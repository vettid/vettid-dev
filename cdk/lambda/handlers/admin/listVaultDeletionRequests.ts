import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;

/**
 * List vault deletion requests
 *
 * Query params:
 * - status: Filter by status (pending, ready, confirmed, cancelled, completed) - default all
 * - limit: Maximum number of results (default 50, max 100)
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  try {
    const statusFilter = event.queryStringParameters?.status;
    const limitParam = parseInt(event.queryStringParameters?.limit || '50', 10);
    const limit = Math.min(Math.max(1, limitParam), 100);

    let requests: Record<string, unknown>[] = [];

    if (statusFilter) {
      // Use scan with filter
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_VAULT_DELETION_REQUESTS,
        FilterExpression: '#s = :status',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({ ':status': statusFilter }),
        Limit: limit * 2,
      }));

      requests = (result.Items || []).map(item => unmarshall(item));
    } else {
      // Scan all requests
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_VAULT_DELETION_REQUESTS,
        Limit: limit * 2,
      }));

      requests = (result.Items || []).map(item => unmarshall(item));
    }

    // Sort by requested_at descending and apply limit
    requests.sort((a, b) => {
      const aTime = new Date(a.requested_at as string || 0).getTime();
      const bTime = new Date(b.requested_at as string || 0).getTime();
      return bTime - aTime;
    });

    requests = requests.slice(0, limit);

    // Format response with time remaining for pending requests
    const now = Date.now();
    const formattedRequests = requests.map(r => {
      const requestedAt = new Date(r.requested_at as string).getTime();
      const eligibleAt = requestedAt + 24 * 60 * 60 * 1000; // 24 hours
      const timeRemaining = r.status === 'pending' ? Math.max(0, eligibleAt - now) : 0;

      return {
        request_id: r.request_id,
        member_guid: r.member_guid,
        member_email: r.member_email,
        status: r.status,
        reason: r.reason,
        requested_at: r.requested_at,
        eligible_at: new Date(eligibleAt).toISOString(),
        time_remaining_ms: timeRemaining,
        time_remaining_readable: formatTimeRemaining(timeRemaining),
        cancelled_at: r.cancelled_at,
        cancelled_by: r.cancelled_by,
        confirmed_at: r.confirmed_at,
        completed_at: r.completed_at,
      };
    });

    return ok({
      requests: formattedRequests,
      count: formattedRequests.length,
      status_filter: statusFilter || 'all',
    });
  } catch (error) {
    console.error('Error listing vault deletion requests:', error);

    await putAudit({
      type: 'admin_list_vault_deletion_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to list vault deletion requests');
  }
};

/**
 * Format milliseconds to human-readable time remaining
 */
function formatTimeRemaining(ms: number): string {
  if (ms <= 0) return 'Ready';

  const hours = Math.floor(ms / (60 * 60 * 1000));
  const minutes = Math.floor((ms % (60 * 60 * 1000)) / (60 * 1000));

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}
