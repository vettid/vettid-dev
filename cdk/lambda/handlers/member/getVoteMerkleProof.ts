import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims
} from '../../common/util';
import { createHash } from 'crypto';
import { Readable } from 'stream';

const s3 = new S3Client({});
const ddb = new DynamoDBClient({});
const PUBLISHED_VOTES_BUCKET = process.env.PUBLISHED_VOTES_BUCKET!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Helper to convert stream to string
 */
async function streamToString(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

/**
 * Calculate SHA-256 hash
 */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Generate Merkle proof for a specific leaf
 */
function generateProof(
  tree: string[][],
  leafIndex: number
): { hash: string; direction: 'left' | 'right' }[] {
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

    currentIndex = Math.floor(currentIndex / 2);
  }

  return proof;
}

/**
 * Verify a Merkle proof
 */
function verifyProof(
  leafHash: string,
  proof: { hash: string; direction: 'left' | 'right' }[],
  expectedRoot: string
): boolean {
  let currentHash = leafHash;

  for (const step of proof) {
    if (step.direction === 'left') {
      currentHash = sha256(step.hash + currentHash);
    } else {
      currentHash = sha256(currentHash + step.hash);
    }
  }

  return currentHash === expectedRoot;
}

/**
 * Get Merkle proof for a member's vote
 * GET /member/votes/{proposal_id}/proof
 *
 * Query parameters:
 * - voting_public_key: The voting public key used to cast the vote (base64)
 *
 * The member must provide their voting_public_key to get their proof.
 * This key is derived from their identity key, so only they can know it.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Require authenticated member
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;

    // Get proposal_id from path
    const proposalId = event.pathParameters?.proposal_id;
    if (!proposalId) {
      return badRequest('Missing proposal_id in path');
    }

    // Get voting_public_key from query parameters
    const votingPublicKey = event.queryStringParameters?.voting_public_key;
    if (!votingPublicKey) {
      return badRequest('Missing voting_public_key query parameter');
    }

    // Validate voting_public_key is base64
    try {
      const decoded = Buffer.from(votingPublicKey, 'base64');
      if (decoded.length !== 32) {
        return badRequest('Invalid voting_public_key: must be 32 bytes when decoded');
      }
    } catch {
      return badRequest('Invalid voting_public_key: must be valid base64');
    }

    // Check if proposal exists and has published results
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposalId }),
      ProjectionExpression: 'proposal_id, merkle_root, results_published_at, status',
    }));

    if (!proposalResult.Item) {
      return notFound('Proposal not found');
    }

    const proposal = unmarshall(proposalResult.Item);

    if (!proposal.results_published_at) {
      return badRequest('Results have not been published for this proposal yet');
    }

    // Fetch the published votes and Merkle tree from S3
    let votesData: any;
    let merkleData: any;

    try {
      const [votesObject, merkleObject] = await Promise.all([
        s3.send(new GetObjectCommand({
          Bucket: PUBLISHED_VOTES_BUCKET,
          Key: `${proposalId}/votes.json`,
        })),
        s3.send(new GetObjectCommand({
          Bucket: PUBLISHED_VOTES_BUCKET,
          Key: `${proposalId}/merkle.json`,
        })),
      ]);

      votesData = JSON.parse(await streamToString(votesObject.Body as Readable));
      merkleData = JSON.parse(await streamToString(merkleObject.Body as Readable));
    } catch (error: any) {
      if (error.name === 'NoSuchKey') {
        return notFound('Published vote data not found');
      }
      throw error;
    }

    // Find the vote with matching voting_public_key
    const voteIndex = votesData.votes.findIndex(
      (v: any) => v.voting_public_key === votingPublicKey
    );

    if (voteIndex === -1) {
      return notFound('No vote found with the provided voting_public_key');
    }

    const vote = votesData.votes[voteIndex];

    // Calculate the leaf hash
    const leafData = `${vote.voting_public_key}|${vote.vote}|${vote.vote_signature}`;
    const leafHash = sha256(leafData);

    // Verify leaf hash matches the stored one
    if (merkleData.leaves[voteIndex] !== leafHash) {
      console.error('Leaf hash mismatch:', {
        calculated: leafHash,
        stored: merkleData.leaves[voteIndex],
      });
      return internalError('Vote data integrity error');
    }

    // Generate the Merkle proof
    const proof = generateProof(merkleData.tree, voteIndex);

    // Verify the proof locally (sanity check)
    const isValid = verifyProof(leafHash, proof, proposal.merkle_root);

    return ok({
      proposal_id: proposalId,
      merkle_root: proposal.merkle_root,
      vote: {
        voting_public_key: vote.voting_public_key,
        vote: vote.vote,
        vote_signature: vote.vote_signature,
        signed_payload: vote.signed_payload,
      },
      proof: {
        leaf_hash: leafHash,
        leaf_index: voteIndex,
        proof_path: proof,
        verification_passed: isValid,
      },
      instructions: {
        message: 'To verify your vote was included:',
        steps: [
          '1. Compute leaf_hash = SHA256(voting_public_key|vote|vote_signature)',
          '2. Starting with leaf_hash, for each step in proof_path:',
          '   - If direction is "left", hash = SHA256(step.hash + current_hash)',
          '   - If direction is "right", hash = SHA256(current_hash + step.hash)',
          '3. The final hash should equal merkle_root',
        ],
      },
    });
  } catch (error: any) {
    console.error('Error getting Merkle proof:', error);
    return internalError('Failed to retrieve Merkle proof');
  }
};
