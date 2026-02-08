import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
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
 * List all proposals with published results
 * GET /votes
 *
 * Public endpoint - no authentication required for transparency
 * Returns proposals sorted by results_published_at (newest first)
 *
 * Query parameters:
 * - limit: max results to return (default: 50, max: 100)
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
    // Get query parameters
    const requestedLimit = parseInt(event.queryStringParameters?.limit || '50', 10);
    const limit = Math.min(Math.max(1, requestedLimit), 100);

    // Scan for proposals with published results
    // Note: In production with many proposals, consider using a GSI on results_published_at
    // Note: 'status' is a DynamoDB reserved keyword, so we use ExpressionAttributeNames
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_PROPOSALS,
      FilterExpression: 'attribute_exists(results_published_at) AND attribute_exists(merkle_root)',
      ProjectionExpression: 'proposal_id, proposal_number, proposal_title, proposal_description, #s, opens_at, closes_at, results_published_at, merkle_root, vote_counts',
      ExpressionAttributeNames: {
        '#s': 'status',
      },
    }));

    if (!result.Items || result.Items.length === 0) {
      return {
        statusCode: 200,
        headers: {
          ...corsHeaders,
          'Cache-Control': 'public, max-age=60', // Cache for 1 minute
        },
        body: JSON.stringify({
          proposals: [],
          total: 0,
        }),
      };
    }

    // Unmarshall and sort by results_published_at (newest first)
    const proposals = result.Items
      .map(item => unmarshall(item))
      .sort((a, b) => {
        const dateA = new Date(a.results_published_at || 0).getTime();
        const dateB = new Date(b.results_published_at || 0).getTime();
        return dateB - dateA;
      })
      .slice(0, limit)
      .map(p => ({
        proposal_id: p.proposal_id,
        proposal_number: p.proposal_number,
        proposal_title: p.proposal_title,
        proposal_description: p.proposal_description ?
          (p.proposal_description.length > 200 ? p.proposal_description.substring(0, 200) + '...' : p.proposal_description) :
          null,
        status: p.status,
        opens_at: p.opens_at,
        closes_at: p.closes_at,
        results_published_at: p.results_published_at,
        merkle_root: p.merkle_root,
        vote_counts: p.vote_counts,
        total_votes: p.vote_counts?.total ??
          (p.vote_counts?.counts
            ? Object.values(p.vote_counts.counts as Record<string, number>).reduce((a: number, b: number) => a + b, 0)
            : 0),
      }));

    return {
      statusCode: 200,
      headers: {
        ...corsHeaders,
        'Cache-Control': 'public, max-age=60', // Cache for 1 minute
      },
      body: JSON.stringify({
        proposals,
        total: proposals.length,
      }),
    };
  } catch (error: any) {
    console.error('Error listing published proposals:', error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};
