import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup, sanitizeErrorForClient } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_HELP_REQUESTS = process.env.TABLE_HELP_REQUESTS!;

// Pagination limits
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20;

// Valid status values for filtering
const VALID_STATUSES = ['new', 'contacted', 'in_progress', 'archived'];

/**
 * List help requests (admin only)
 * GET /admin/help-requests?status=new&limit=20&cursor=xxx
 *
 * Query params:
 * - status: Filter by status (new, contacted, in_progress, archived)
 * - limit: Max items to return (default 20, max 100)
 * - cursor: Pagination cursor from previous response
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
    const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);
    const cursor = event.queryStringParameters?.cursor;
    const statusFilter = event.queryStringParameters?.status;

    // Validate status filter if provided
    if (statusFilter && !VALID_STATUSES.includes(statusFilter)) {
      return ok({
        help_requests: [],
        count: 0,
        limit,
        error: `Invalid status. Valid values: ${VALID_STATUSES.join(', ')}`
      });
    }

    // Decode pagination cursor if provided
    let exclusiveStartKey: Record<string, any> | undefined;
    if (cursor) {
      try {
        exclusiveStartKey = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
      } catch {
        // Invalid cursor, ignore
      }
    }

    let result;

    if (statusFilter) {
      // Use GSI to query by status
      result = await ddb.send(new QueryCommand({
        TableName: TABLE_HELP_REQUESTS,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :status',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':status': statusFilter,
        }),
        Limit: limit,
        ExclusiveStartKey: exclusiveStartKey,
        ScanIndexForward: false, // Newest first (descending by created_at)
      }));
    } else {
      // Scan all items (no filter)
      result = await ddb.send(new ScanCommand({
        TableName: TABLE_HELP_REQUESTS,
        Limit: limit,
        ExclusiveStartKey: exclusiveStartKey,
      }));
    }

    if (!result.Items || result.Items.length === 0) {
      return ok({ help_requests: [], count: 0, limit });
    }

    let helpRequests = result.Items.map(item => unmarshall(item));

    // If no status filter (scan), sort by created_at descending
    if (!statusFilter) {
      helpRequests.sort((a, b) => {
        const dateA = new Date(a.created_at).getTime();
        const dateB = new Date(b.created_at).getTime();
        return dateB - dateA;
      });
    }

    // Build response with pagination
    const response: any = {
      help_requests: helpRequests,
      count: helpRequests.length,
      limit,
    };

    // Include next cursor if there are more results
    if (result.LastEvaluatedKey) {
      response.nextCursor = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64');
    }

    return ok(response);
  } catch (error: any) {
    console.error('Error listing help requests:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to list help requests'));
  }
};
