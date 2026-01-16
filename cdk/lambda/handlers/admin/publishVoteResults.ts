import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';
import { createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const PUBLISHED_VOTES_BUCKET = process.env.PUBLISHED_VOTES_BUCKET!;

/**
 * Anonymized vote record for public publishing
 */
interface AnonymizedVote {
  voting_public_key: string;
  vote: string;
  vote_signature: string;
  signed_payload: string;
}

/**
 * Merkle tree node
 */
interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: string; // Leaf node data (vote hash)
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
 * Returns the root node and a flat structure for proofs
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
 * Generate a Merkle proof for a specific leaf index
 */
function generateMerkleProof(tree: string[][], leafIndex: number): {
  leaf: string;
  proof: { hash: string; direction: 'left' | 'right' }[];
} {
  const proof: { hash: string; direction: 'left' | 'right' }[] = [];
  let currentIndex = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    const currentLevel = tree[level];
    const isLeftNode = currentIndex % 2 === 0;
    const siblingIndex = isLeftNode ? currentIndex + 1 : currentIndex - 1;

    // Handle case where sibling doesn't exist (odd number of nodes)
    const sibling = siblingIndex < currentLevel.length
      ? currentLevel[siblingIndex]
      : currentLevel[currentIndex];

    proof.push({
      hash: sibling,
      direction: isLeftNode ? 'right' : 'left',
    });

    // Move to parent index
    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leaf: tree[0][leafIndex],
    proof,
  };
}

/**
 * Publish vote results for a closed proposal
 * POST /admin/proposals/{proposal_id}/publish-results
 *
 * This endpoint:
 * 1. Retrieves all votes for the proposal
 * 2. Creates an anonymized vote list (only vault-signed votes are included)
 * 3. Builds a Merkle tree for verification
 * 4. Stores results to S3
 * 5. Updates the proposal with merkle_root
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    // Get admin email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const adminEmail = claims?.email;

    // Get proposal_id from path
    const proposalId = event.pathParameters?.proposal_id;
    if (!proposalId) {
      return badRequest('Missing proposal_id in path');
    }

    // Get proposal
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposalId }),
    }));

    if (!proposalResult.Item) {
      return notFound('Proposal not found');
    }

    const proposal = unmarshall(proposalResult.Item);

    // Verify proposal is closed
    if (proposal.status !== 'closed') {
      return badRequest('Results can only be published for closed proposals');
    }

    // Check if already published
    if (proposal.results_published_at) {
      return badRequest('Results have already been published for this proposal');
    }

    // Query all votes for this proposal
    const allVotes: any[] = [];
    let lastEvaluatedKey: any = undefined;

    do {
      const votesResult: any = await ddb.send(new QueryCommand({
        TableName: TABLE_VOTES,
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
    const voteCounts = {
      yes: anonymizedVotes.filter(v => v.vote === 'yes').length,
      no: anonymizedVotes.filter(v => v.vote === 'no').length,
      abstain: anonymizedVotes.filter(v => v.vote === 'abstain').length,
      total: anonymizedVotes.length,
      // Include web votes in separate count (if any)
      web_votes: allVotes.filter(v => v.vote_source !== 'vault').length,
    };

    // Prepare S3 objects
    const publishedAt = new Date().toISOString();

    const votesJson = {
      proposal_id: proposalId,
      published_at: publishedAt,
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
        Bucket: PUBLISHED_VOTES_BUCKET,
        Key: `${proposalId}/votes.json`,
        Body: JSON.stringify(votesJson, null, 2),
        ContentType: 'application/json',
      })),
      s3.send(new PutObjectCommand({
        Bucket: PUBLISHED_VOTES_BUCKET,
        Key: `${proposalId}/merkle.json`,
        Body: JSON.stringify(merkleJson, null, 2),
        ContentType: 'application/json',
      })),
    ]);

    // Update proposal with merkle_root and publication timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposalId }),
      UpdateExpression: 'SET merkle_root = :root, results_published_at = :published, vote_counts = :counts',
      ExpressionAttributeValues: marshall({
        ':root': merkleResult.root,
        ':published': publishedAt,
        ':counts': voteCounts,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'proposal_results_published',
      email: adminEmail,
      proposal_id: proposalId,
      merkle_root: merkleResult.root,
      vote_counts: voteCounts,
    }, requestId);

    return ok({
      message: 'Vote results published successfully',
      results: {
        proposal_id: proposalId,
        merkle_root: merkleResult.root,
        published_at: publishedAt,
        vote_counts: voteCounts,
        s3_keys: [
          `${proposalId}/votes.json`,
          `${proposalId}/merkle.json`,
        ],
      },
    });
  } catch (error: any) {
    console.error('Error publishing vote results:', error);
    return internalError('Failed to publish vote results');
  }
};
