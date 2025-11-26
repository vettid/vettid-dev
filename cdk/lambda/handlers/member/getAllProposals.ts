import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  internalError,
  getRequestId
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get all proposals categorized by status (active, upcoming, closed)
 * GET /proposals
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Query proposals with status='active' using GSI
    const activeProposalsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_PROPOSALS,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'active',
      }),
      ScanIndexForward: true, // Sort by opens_at ascending
    }));

    const activeProposals = activeProposalsResult.Items
      ? activeProposalsResult.Items.map((item) => unmarshall(item))
      : [];

    // Query proposals with status='closed' using GSI
    const closedProposalsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_PROPOSALS,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'closed',
      }),
      ScanIndexForward: false, // Sort by closes_at descending (most recent first)
    }));

    const closedProposals = closedProposalsResult.Items
      ? closedProposalsResult.Items.map((item) => unmarshall(item))
      : [];

    // Categorize active proposals by time
    const now = new Date();
    const active: any[] = [];
    const upcoming: any[] = [];

    activeProposals.forEach(proposal => {
      const opensAt = new Date(proposal.opens_at);
      const closesAt = new Date(proposal.closes_at);

      if (now >= opensAt && now <= closesAt) {
        // Currently open for voting
        active.push(proposal);
      } else if (now < opensAt) {
        // Not yet open for voting
        upcoming.push(proposal);
      }
    });

    return ok({
      active,
      upcoming,
      closed: closedProposals,
    });
  } catch (error: any) {
    console.error('Error getting all proposals:', error);
    return internalError(error.message || 'Failed to get proposals');
  }
};
