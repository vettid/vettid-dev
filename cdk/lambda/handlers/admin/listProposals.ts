import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * List proposals with optional status filter
 * GET /admin/proposals?status=active|upcoming|closed
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    const statusFilter = event.queryStringParameters?.status;
    const now = new Date();

    // Scan all proposals
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_PROPOSALS,
    }));

    if (!result.Items) {
      return ok([]);
    }

    let proposals = result.Items.map(item => unmarshall(item));

    // Update statuses based on current time (except suspended)
    proposals = proposals.map(p => {
      if (p.status === 'suspended') {
        return p; // Don't auto-update suspended proposals
      }

      const opensDate = new Date(p.opens_at);
      const closesDate = new Date(p.closes_at);

      if (now >= closesDate) {
        p.status = 'closed';
      } else if (now >= opensDate && now < closesDate) {
        p.status = 'active';
      } else {
        p.status = 'upcoming';
      }

      return p;
    });

    // Filter by status if requested
    if (statusFilter) {
      proposals = proposals.filter(p => p.status === statusFilter);
    }

    // Sort by opens_at descending (newest first)
    proposals.sort((a, b) => new Date(b.opens_at).getTime() - new Date(a.opens_at).getTime());

    return ok(proposals);
  } catch (error: any) {
    console.error('Error listing proposals:', error);
    return internalError(error.message || 'Failed to list proposals');
  }
};
