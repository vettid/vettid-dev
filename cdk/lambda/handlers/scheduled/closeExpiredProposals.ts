import { DynamoDBClient, ScanCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { publishVoteResults } from '../../common/publishResults';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const PUBLISHED_VOTES_BUCKET = process.env.PUBLISHED_VOTES_BUCKET!;

/**
 * Count eligible voters (members with active subscriptions)
 */
async function countEligibleVoters(): Promise<number> {
  const result = await ddb.send(new ScanCommand({
    TableName: TABLE_SUBSCRIPTIONS,
    FilterExpression: '#status = :status',
    ExpressionAttributeNames: { '#status': 'status' },
    ExpressionAttributeValues: marshall({ ':status': 'active' }),
    Select: 'COUNT'
  }));
  return result.Count || 0;
}

/**
 * Tally votes for a proposal across whatever choice IDs the proposal
 * defines (or yes/no/abstain by default). The previous implementation
 * counted only the literal strings yes/no/abstain — custom choice IDs
 * never showed up in the tally.
 */
async function getVoteCounts(proposalId: string): Promise<{
  yes: number; no: number; abstain: number;
  total: number; counts: Record<string, number>;
}> {
  const result = await ddb.send(new QueryCommand({
    TableName: TABLE_VOTES,
    IndexName: 'proposal-vote-index',
    KeyConditionExpression: 'proposal_id = :pid',
    ExpressionAttributeValues: marshall({ ':pid': proposalId })
  }));

  const votes = (result.Items || []).map(item => unmarshall(item));
  const counts: Record<string, number> = {};
  for (const vote of votes) {
    const choice = String(vote.vote || '');
    if (!choice) continue;
    counts[choice] = (counts[choice] || 0) + 1;
  }

  // Keep the historical fields populated so existing readers (e.g. the
  // proposals row's final_yes/final_no/final_abstain) keep working.
  return {
    yes: counts.yes || 0,
    no: counts.no || 0,
    abstain: counts.abstain || 0,
    total: votes.length,
    counts,
  };
}

/**
 * Check if quorum is met based on proposal settings
 */
function checkQuorumMet(
  quorumType: string,
  quorumValue: number,
  totalVotes: number,
  eligibleVoters: number
): boolean {
  if (quorumType === 'none' || !quorumType) {
    return true; // No quorum requirement
  }

  if (quorumType === 'percentage') {
    if (eligibleVoters === 0) return false;
    const participationRate = (totalVotes / eligibleVoters) * 100;
    return participationRate >= quorumValue;
  }

  if (quorumType === 'count') {
    return totalVotes >= quorumValue;
  }

  return true;
}

/**
 * Build Merkle artifacts and publish vote results to S3 immediately after
 * a proposal closes. Logs but doesn't throw on failure — the proposal is
 * already marked closed; results can be republished by the admin endpoint.
 */
async function autoPublishResults(proposalId: string): Promise<void> {
  if (!PUBLISHED_VOTES_BUCKET) {
    console.warn('PUBLISHED_VOTES_BUCKET not set; skipping auto-publish');
    return;
  }
  const result = await publishVoteResults(
    proposalId,
    TABLE_PROPOSALS,
    TABLE_VOTES,
    PUBLISHED_VOTES_BUCKET,
    'scheduler:closeExpiredProposals'
  );
  if (!result.success) {
    console.error(`Auto-publish failed for ${proposalId}:`, result.error);
    return;
  }
  console.log(`Auto-published results for ${proposalId}: merkle_root=${result.merkle_root}`);
}

/**
 * Scheduled Lambda to manage proposal lifecycle transitions
 * - Activates "upcoming" proposals when opens_at is reached
 * - Closes "active" proposals when closes_at is reached
 * - Auto-publishes Merkle tree + anonymized vote list to S3 on close
 * Triggered by EventBridge scheduled rule
 */
export const handler = async (): Promise<void> => {
  console.log('Starting proposal lifecycle job');

  try {
    const now = new Date();

    // First, activate any upcoming proposals that should now be active
    await activateUpcomingProposals(now);

    // Then close any active proposals that have expired
    await closeActiveProposals(now);

  } catch (error: any) {
    console.error('Error in proposal lifecycle job:', error);
    throw error;
  }
};

/**
 * Activate proposals that are "upcoming" but opens_at has passed
 */
async function activateUpcomingProposals(now: Date): Promise<void> {
  const scanResult = await ddb.send(new ScanCommand({
    TableName: TABLE_PROPOSALS,
    FilterExpression: '#status = :status',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: marshall({
      ':status': 'upcoming',
    }),
  }));

  if (!scanResult.Items || scanResult.Items.length === 0) {
    console.log('No upcoming proposals found');
    return;
  }

  const proposals = scanResult.Items.map(item => unmarshall(item));
  console.log(`Found ${proposals.length} upcoming proposals`);

  let activatedCount = 0;
  let closedDirectlyCount = 0;

  for (const proposal of proposals) {
    const opensAt = new Date(proposal.opens_at);
    const closesAt = new Date(proposal.closes_at);

    if (now >= opensAt && now < closesAt) {
      // Proposal should be active
      console.log(`Activating proposal: ${proposal.proposal_id} (${proposal.proposal_title})`);

      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_PROPOSALS,
        Key: marshall({ proposal_id: proposal.proposal_id }),
        UpdateExpression: 'SET #status = :active, activated_at = :activated_at',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':active': 'active',
          ':activated_at': now.toISOString(),
        }),
      }));

      activatedCount++;
    } else if (now >= closesAt) {
      // Proposal was never activated but has already closed
      // This handles the edge case where the scheduler was delayed
      console.log(`Closing directly (missed activation window): ${proposal.proposal_id}`);

      const eligibleVoters = await countEligibleVoters();
      const voteCounts = await getVoteCounts(proposal.proposal_id);
      const quorumMet = checkQuorumMet(
        proposal.quorum_type || 'none',
        proposal.quorum_value || 0,
        voteCounts.total,
        eligibleVoters
      );
      const passed = quorumMet && voteCounts.yes > voteCounts.no;

      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_PROPOSALS,
        Key: marshall({ proposal_id: proposal.proposal_id }),
        UpdateExpression: 'SET #status = :closed, closed_at = :closed_at, quorum_met = :quorum_met, eligible_voters = :eligible, final_yes = :yes, final_no = :no, final_abstain = :abstain, final_total = :total, passed = :passed',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':closed': 'closed',
          ':closed_at': now.toISOString(),
          ':quorum_met': quorumMet,
          ':eligible': eligibleVoters,
          ':yes': voteCounts.yes,
          ':no': voteCounts.no,
          ':abstain': voteCounts.abstain,
          ':total': voteCounts.total,
          ':passed': passed,
        }),
      }));

      await autoPublishResults(proposal.proposal_id);
      closedDirectlyCount++;
    }
  }

  console.log(`Activated ${activatedCount} proposals, closed ${closedDirectlyCount} directly`);
}

/**
 * Close proposals that are "active" but closes_at has passed
 */
async function closeActiveProposals(now: Date): Promise<void> {
  const scanResult = await ddb.send(new ScanCommand({
    TableName: TABLE_PROPOSALS,
    FilterExpression: '#status = :status',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: marshall({
      ':status': 'active',
    }),
  }));

  if (!scanResult.Items || scanResult.Items.length === 0) {
    console.log('No active proposals found');
    return;
  }

  const proposals = scanResult.Items.map(item => unmarshall(item));
  console.log(`Found ${proposals.length} active proposals`);

  let closedCount = 0;

  // Get eligible voter count once (shared across all proposals closing now)
  const eligibleVoters = await countEligibleVoters();
  console.log(`Eligible voters: ${eligibleVoters}`);

  // Update proposals that have expired
  for (const proposal of proposals) {
    const closesAt = new Date(proposal.closes_at);

    if (now > closesAt) {
      console.log(`Closing expired proposal: ${proposal.proposal_id} (${proposal.proposal_title})`);

      // Get vote counts and calculate quorum
      const voteCounts = await getVoteCounts(proposal.proposal_id);
      const quorumMet = checkQuorumMet(
        proposal.quorum_type || 'none',
        proposal.quorum_value || 0,
        voteCounts.total,
        eligibleVoters
      );

      // Determine if proposal passed (yes > no, and quorum met)
      const passed = quorumMet && voteCounts.yes > voteCounts.no;

      console.log(`Proposal ${proposal.proposal_id}: votes=${voteCounts.total}, quorum_met=${quorumMet}, passed=${passed}`);

      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_PROPOSALS,
        Key: marshall({
          proposal_id: proposal.proposal_id,
        }),
        UpdateExpression: 'SET #status = :closed, closed_at = :closed_at, quorum_met = :quorum_met, eligible_voters = :eligible, final_yes = :yes, final_no = :no, final_abstain = :abstain, final_total = :total, passed = :passed',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':closed': 'closed',
          ':closed_at': now.toISOString(),
          ':quorum_met': quorumMet,
          ':eligible': eligibleVoters,
          ':yes': voteCounts.yes,
          ':no': voteCounts.no,
          ':abstain': voteCounts.abstain,
          ':total': voteCounts.total,
          ':passed': passed,
        }),
      }));

      await autoPublishResults(proposal.proposal_id);
      closedCount++;
    }
  }

  console.log(`Closed ${closedCount} active proposals`);
}
