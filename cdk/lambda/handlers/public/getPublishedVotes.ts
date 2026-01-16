import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { S3Client, GetObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { Readable } from 'stream';

const s3 = new S3Client({});
const ddb = new DynamoDBClient({});
const PUBLISHED_VOTES_BUCKET = process.env.PUBLISHED_VOTES_BUCKET!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * CORS headers for public endpoint
 */
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

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
 * Get published vote results for a proposal
 * GET /votes/{proposal_id}/published
 *
 * Public endpoint - no authentication required for transparency
 *
 * Query parameters:
 * - include_votes: 'true' to include full vote list (default: false, only summary)
 * - include_merkle: 'true' to include Merkle tree structure (default: false)
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Handle CORS preflight
  if (event.requestContext.http.method === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: '',
    };
  }

  try {
    // Get proposal_id from path
    const proposalId = event.pathParameters?.proposal_id;
    if (!proposalId) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Missing proposal_id in path' }),
      };
    }

    // Validate proposal_id format (UUID)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(proposalId)) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid proposal_id format' }),
      };
    }

    // Get query parameters
    const includeVotes = event.queryStringParameters?.include_votes === 'true';
    const includeMerkle = event.queryStringParameters?.include_merkle === 'true';

    // First, check if the proposal exists and has published results
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposalId }),
      ProjectionExpression: 'proposal_id, proposal_title, proposal_number, status, merkle_root, results_published_at, vote_counts, opens_at, closes_at',
    }));

    if (!proposalResult.Item) {
      return {
        statusCode: 404,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Proposal not found' }),
      };
    }

    const proposal = unmarshall(proposalResult.Item);

    if (!proposal.results_published_at) {
      return {
        statusCode: 404,
        headers: corsHeaders,
        body: JSON.stringify({
          error: 'Results have not been published for this proposal',
          proposal_status: proposal.status,
        }),
      };
    }

    // Build response with basic proposal info
    const response: any = {
      proposal_id: proposalId,
      proposal_number: proposal.proposal_number,
      proposal_title: proposal.proposal_title,
      status: proposal.status,
      opens_at: proposal.opens_at,
      closes_at: proposal.closes_at,
      results_published_at: proposal.results_published_at,
      merkle_root: proposal.merkle_root,
      vote_counts: proposal.vote_counts,
    };

    // Optionally include full vote list
    if (includeVotes) {
      try {
        const votesObject = await s3.send(new GetObjectCommand({
          Bucket: PUBLISHED_VOTES_BUCKET,
          Key: `${proposalId}/votes.json`,
        }));

        if (votesObject.Body) {
          const votesData = JSON.parse(await streamToString(votesObject.Body as Readable));
          response.votes = votesData.votes;
        }
      } catch (error: any) {
        if (error.name === 'NoSuchKey') {
          response.votes_error = 'Vote list not found in storage';
        } else {
          console.error('Error fetching votes:', error);
          response.votes_error = 'Failed to retrieve vote list';
        }
      }
    }

    // Optionally include Merkle tree
    if (includeMerkle) {
      try {
        const merkleObject = await s3.send(new GetObjectCommand({
          Bucket: PUBLISHED_VOTES_BUCKET,
          Key: `${proposalId}/merkle.json`,
        }));

        if (merkleObject.Body) {
          const merkleData = JSON.parse(await streamToString(merkleObject.Body as Readable));
          response.merkle_tree = {
            tree_depth: merkleData.tree_depth,
            leaves: merkleData.leaves,
            tree: merkleData.tree,
          };
        }
      } catch (error: any) {
        if (error.name === 'NoSuchKey') {
          response.merkle_error = 'Merkle tree not found in storage';
        } else {
          console.error('Error fetching merkle tree:', error);
          response.merkle_error = 'Failed to retrieve Merkle tree';
        }
      }
    }

    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        'Cache-Control': 'public, max-age=300', // Cache for 5 minutes
      },
      body: JSON.stringify(response),
    };
  } catch (error: any) {
    console.error('Error retrieving published votes:', error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};
