/**
 * Shared module for publishing vote results with Merkle tree verification
 * Used by both admin API endpoint and stream processor (auto-publish)
 */

import { DynamoDBClient, GetItemCommand, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

/**
 * Anonymized vote record for public publishing
 */
export interface AnonymizedVote {
  voting_public_key: string;
  vote: string;
  vote_signature: string;
  signed_payload: string;
}

/**
 * Vote counts structure
 */
export interface VoteCounts {
  yes: number;
  no: number;
  abstain: number;
  total: number;
  web_votes: number;
}

/**
 * Result of publishing vote results
 */
export interface PublishResult {
  success: boolean;
  proposal_id: string;
  merkle_root?: string;
  published_at?: string;
  vote_counts?: VoteCounts;
  error?: string;
  already_published?: boolean;
  not_closed?: boolean;
}

/**
 * Calculate SHA-256 hash of a string
 */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Create a leaf hash from an anonymized vote
 * Format: SHA256(voting_public_key|vote|vote_signature)
 */
function createLeafHash(vote: AnonymizedVote): string {
  const leafData = `${vote.voting_public_key}|${vote.vote}|${vote.vote_signature}`;
  return sha256(leafData);
}

/**
 * Build a Merkle tree from a list of votes
 * Returns the root hash and tree structure for proofs
 */
function buildMerkleTree(votes: AnonymizedVote[]): {
  root: string;
  leaves: string[];
  tree: string[][];
} {
  if (votes.length === 0) {
    return { root: sha256('EMPTY'), leaves: [], tree: [[sha256('EMPTY')]] };
  }

  // Create leaf hashes
  const leaves = votes.map(createLeafHash);

  // Build tree bottom-up
  const tree: string[][] = [leaves];
  let currentLevel = leaves;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      // If odd number of nodes, duplicate the last one
      const right = currentLevel[i + 1] || currentLevel[i];
      const parent = sha256(left + right);
      nextLevel.push(parent);
    }

    tree.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    root: currentLevel[0],
    leaves,
    tree,
  };
}

/**
 * Publish vote results for a proposal
 *
 * This function:
 * 1. Verifies the proposal is closed and not already published
 * 2. Retrieves all vault-signed votes
 * 3. Creates anonymized vote list
 * 4. Builds Merkle tree for verification
 * 5. Stores results to S3
 * 6. Updates proposal with merkle_root
 *
 * @param proposalId - The proposal ID to publish results for
 * @param tableProposals - DynamoDB proposals table name
 * @param tableVotes - DynamoDB votes table name
 * @param publishedVotesBucket - S3 bucket for published votes
 * @param triggeredBy - Who/what triggered the publish (for logging)
 */
export async function publishVoteResults(
  proposalId: string,
  tableProposals: string,
  tableVotes: string,
  publishedVotesBucket: string,
  triggeredBy: string = 'system'
): Promise<PublishResult> {
  try {
    // Get proposal
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: tableProposals,
      Key: marshall({ proposal_id: proposalId }),
    }));

    if (!proposalResult.Item) {
      return {
        success: false,
        proposal_id: proposalId,
        error: 'Proposal not found',
      };
    }

    const proposal = unmarshall(proposalResult.Item);

    // Verify proposal is closed
    if (proposal.status !== 'closed') {
      return {
        success: false,
        proposal_id: proposalId,
        error: 'Proposal is not closed',
        not_closed: true,
      };
    }

    // Check if already published
    if (proposal.results_published_at) {
      return {
        success: false,
        proposal_id: proposalId,
        error: 'Results already published',
        already_published: true,
        merkle_root: proposal.merkle_root,
        published_at: proposal.results_published_at,
      };
    }

    // Query all votes for this proposal using the GSI
    const allVotes: any[] = [];
    let lastEvaluatedKey: any = undefined;

    do {
      const votesResult: any = await ddb.send(new QueryCommand({
        TableName: tableVotes,
        IndexName: 'proposal-index',
        KeyConditionExpression: 'proposal_id = :pid',
        ExpressionAttributeValues: marshall({ ':pid': proposalId }),
        ExclusiveStartKey: lastEvaluatedKey,
      }));

      const items = (votesResult.Items || []).map((item: any) => unmarshall(item));
      allVotes.push(...items);
      lastEvaluatedKey = votesResult.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    // Filter to only vault-signed votes and create anonymized list
    const vaultVotes = allVotes.filter(v =>
      v.vote_source === 'vault' &&
      v.voting_public_key &&
      v.vote_signature &&
      v.signed_payload
    );

    const anonymizedVotes: AnonymizedVote[] = vaultVotes.map(v => ({
      voting_public_key: v.voting_public_key,
      vote: v.vote,
      vote_signature: v.vote_signature,
      signed_payload: v.signed_payload,
    }));

    // Sort by voting_public_key for deterministic ordering
    anonymizedVotes.sort((a, b) => a.voting_public_key.localeCompare(b.voting_public_key));

    // Build Merkle tree
    const merkleResult = buildMerkleTree(anonymizedVotes);

    // Calculate vote counts
    const voteCounts: VoteCounts = {
      yes: anonymizedVotes.filter(v => v.vote === 'yes').length,
      no: anonymizedVotes.filter(v => v.vote === 'no').length,
      abstain: anonymizedVotes.filter(v => v.vote === 'abstain').length,
      total: anonymizedVotes.length,
      web_votes: allVotes.filter(v => v.vote_source !== 'vault').length,
    };

    // Prepare S3 objects
    const publishedAt = new Date().toISOString();

    const votesJson = {
      proposal_id: proposalId,
      published_at: publishedAt,
      triggered_by: triggeredBy,
      merkle_root: merkleResult.root,
      vote_counts: voteCounts,
      votes: anonymizedVotes,
    };

    const merkleJson = {
      proposal_id: proposalId,
      published_at: publishedAt,
      merkle_root: merkleResult.root,
      tree_depth: merkleResult.tree.length,
      leaves: merkleResult.leaves,
      tree: merkleResult.tree,
    };

    // Upload to S3
    await Promise.all([
      s3.send(new PutObjectCommand({
        Bucket: publishedVotesBucket,
        Key: `${proposalId}/votes.json`,
        Body: JSON.stringify(votesJson, null, 2),
        ContentType: 'application/json',
      })),
      s3.send(new PutObjectCommand({
        Bucket: publishedVotesBucket,
        Key: `${proposalId}/merkle.json`,
        Body: JSON.stringify(merkleJson, null, 2),
        ContentType: 'application/json',
      })),
    ]);

    // Update proposal with merkle_root and publication timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: tableProposals,
      Key: marshall({ proposal_id: proposalId }),
      UpdateExpression: 'SET merkle_root = :root, results_published_at = :published, vote_counts = :counts',
      ExpressionAttributeValues: marshall({
        ':root': merkleResult.root,
        ':published': publishedAt,
        ':counts': voteCounts,
      }),
    }));

    console.log(`Published vote results for proposal ${proposalId}: merkle_root=${merkleResult.root}, votes=${voteCounts.total}`);

    return {
      success: true,
      proposal_id: proposalId,
      merkle_root: merkleResult.root,
      published_at: publishedAt,
      vote_counts: voteCounts,
    };
  } catch (error: any) {
    console.error(`Error publishing vote results for ${proposalId}:`, error);
    return {
      success: false,
      proposal_id: proposalId,
      error: error.message || 'Unknown error',
    };
  }
}
