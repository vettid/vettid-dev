import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  internalError
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get all active proposals
 * GET /proposals/active
 */
export const handler = async (_event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Query proposals with status='active' using GSI
    const proposalsResult = await ddb.send(new QueryCommand({
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

    const allProposals = proposalsResult.Items
      ? proposalsResult.Items.map((item) => unmarshall(item))
      : [];

    // Filter to only proposals that are currently open for voting
    const now = new Date();
    const proposals = allProposals.filter(proposal => {
      const opensAt = new Date(proposal.opens_at);
      const closesAt = new Date(proposal.closes_at);
      return now >= opensAt && now <= closesAt;
    });

    return ok({ proposals });
  } catch (error: any) {
    console.error('Error getting active proposals:', error);
    return internalError(error.message || 'Failed to get active proposals');
  }
};
