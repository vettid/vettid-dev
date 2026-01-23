import { DynamoDBClient, ScanCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { SESClient, SendTemplatedEmailCommand } from '@aws-sdk/client-ses';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const SES_FROM = process.env.SES_FROM!;

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

/**
 * Check if user has system emails enabled
 */
async function checkSystemEmailsEnabled(userGuid: string): Promise<boolean> {
  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_AUDIT,
      Key: marshall({ id: `email-prefs:${userGuid}` })
    }));

    if (!result.Item) {
      return true; // Default to enabled
    }

    const prefs = unmarshall(result.Item);
    return prefs.system_emails !== false;
  } catch (error) {
    console.error(`Error checking email preferences for ${userGuid}:`, error);
    return true;
  }
}

/**
 * Get user details from registrations
 */
async function getUserDetails(userGuid: string): Promise<{ email: string; first_name: string } | null> {
  try {
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({ ':guid': userGuid })
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    const registration = unmarshall(result.Items[0]);
    return {
      email: registration.email,
      first_name: registration.first_name || 'Member'
    };
  } catch (error) {
    console.error(`Error getting user details for ${userGuid}:`, error);
    return null;
  }
}

/**
 * Get all user_guids who have voted on a proposal
 */
async function getVoterGuids(proposalId: string): Promise<Set<string>> {
  const result = await ddb.send(new QueryCommand({
    TableName: TABLE_VOTES,
    IndexName: 'proposal-vote-index',
    KeyConditionExpression: 'proposal_id = :pid',
    ExpressionAttributeValues: marshall({ ':pid': proposalId }),
    ProjectionExpression: 'user_guid'
  }));

  const voterGuids = new Set<string>();
  for (const item of result.Items || []) {
    const vote = unmarshall(item);
    if (vote.user_guid) {
      voterGuids.add(vote.user_guid);
    }
  }
  return voterGuids;
}

/**
 * Get all active subscription holders (eligible voters)
 */
async function getActiveSubscribers(): Promise<Array<{ user_guid: string }>> {
  const result = await ddb.send(new ScanCommand({
    TableName: TABLE_SUBSCRIPTIONS,
    FilterExpression: '#status = :status',
    ExpressionAttributeNames: { '#status': 'status' },
    ExpressionAttributeValues: marshall({ ':status': 'active' }),
    ProjectionExpression: 'user_guid'
  }));

  return (result.Items || []).map(item => unmarshall(item) as { user_guid: string });
}

/**
 * Scheduled Lambda to send reminder emails for proposals closing soon
 * Triggered by EventBridge scheduled rule (runs every 6 hours)
 */
export const handler = async (): Promise<void> => {
  console.log('Starting proposal reminder job');

  try {
    const now = new Date();
    const reminderWindowStart = new Date(now.getTime() + (20 * 60 * 60 * 1000)); // 20 hours from now
    const reminderWindowEnd = new Date(now.getTime() + (28 * 60 * 60 * 1000)); // 28 hours from now

    // Find active proposals closing within the reminder window (20-28 hours)
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_PROPOSALS,
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({ ':status': 'active' })
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('No active proposals found');
      return;
    }

    const proposals = scanResult.Items.map(item => unmarshall(item));

    // Filter to proposals closing within the reminder window
    const proposalsClosingSoon = proposals.filter(p => {
      const closesAt = new Date(p.closes_at);
      return closesAt >= reminderWindowStart && closesAt <= reminderWindowEnd;
    });

    if (proposalsClosingSoon.length === 0) {
      console.log('No proposals closing in the reminder window');
      return;
    }

    console.log(`Found ${proposalsClosingSoon.length} proposals closing soon`);

    // Get all active subscribers once
    const subscribers = await getActiveSubscribers();
    console.log(`Found ${subscribers.length} active subscribers`);

    let remindersSent = 0;
    let remindersSkipped = 0;

    for (const proposal of proposalsClosingSoon) {
      console.log(`Processing reminders for proposal ${proposal.proposal_id} (${proposal.proposal_title})`);

      // Get voters for this proposal
      const voterGuids = await getVoterGuids(proposal.proposal_id);
      console.log(`${voterGuids.size} members have already voted`);

      // Find non-voters
      const nonVoters = subscribers.filter(s => !voterGuids.has(s.user_guid));
      console.log(`${nonVoters.length} members have not voted yet`);

      for (const subscriber of nonVoters) {
        try {
          // Check email preferences
          const hasEmailsEnabled = await checkSystemEmailsEnabled(subscriber.user_guid);
          if (!hasEmailsEnabled) {
            remindersSkipped++;
            continue;
          }

          // Get user details
          const userDetails = await getUserDetails(subscriber.user_guid);
          if (!userDetails) {
            remindersSkipped++;
            continue;
          }

          // Calculate hours remaining
          const closesAt = new Date(proposal.closes_at);
          const hoursRemaining = Math.round((closesAt.getTime() - now.getTime()) / (1000 * 60 * 60));

          // Send reminder email
          await ses.send(new SendTemplatedEmailCommand({
            Source: SES_FROM,
            Destination: { ToAddresses: [userDetails.email] },
            Template: 'ProposalVoteReminder',
            TemplateData: JSON.stringify({
              first_name: userDetails.first_name,
              proposal_number: proposal.proposal_number || '',
              proposal_title: proposal.proposal_title || 'Untitled Proposal',
              hours_remaining: String(hoursRemaining),
              vote_link: 'https://vettid.dev/account'
            })
          }));

          remindersSent++;
          console.log(`Sent reminder to ${hashForLog(userDetails.email)} for proposal ${proposal.proposal_id}`);

        } catch (error) {
          console.error(`Error sending reminder to ${subscriber.user_guid}:`, error);
          remindersSkipped++;
        }
      }
    }

    console.log(`Reminder job complete. Sent: ${remindersSent}, Skipped: ${remindersSkipped}`);

  } catch (error: any) {
    console.error('Error in proposal reminder job:', error);
    throw error;
  }
};
