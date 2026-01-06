import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  internalError,
  getRequestId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;

/**
 * GET /vault/delete/status
 *
 * Get the status of any pending vault deletion request.
 *
 * Requires member JWT authentication.
 *
 * Returns:
 * - has_pending_request: boolean
 * - request_id: ID of pending request (if any)
 * - status: 'pending' | 'ready' | null
 * - ready_at: ISO timestamp when deletion can be confirmed (if pending)
 * - is_ready: boolean indicating if deletion can be confirmed now
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const memberGuid = claims.user_guid;

    // Find pending deletion request for this member
    const existingRequest = await ddb.send(new QueryCommand({
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid AND #status = :pending',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending': 'pending',
      }),
      Limit: 1,
    }));

    if (!existingRequest.Items || existingRequest.Items.length === 0) {
      return ok({
        has_pending_request: false,
        request_id: null,
        status: null,
        ready_at: null,
        is_ready: false,
      }, origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();
    const readyAt = new Date(request.ready_at);
    const isReady = now >= readyAt;

    // Calculate time remaining
    let timeRemainingMs = 0;
    let timeRemainingDisplay = '';
    if (!isReady) {
      timeRemainingMs = readyAt.getTime() - now.getTime();
      const hours = Math.floor(timeRemainingMs / (60 * 60 * 1000));
      const minutes = Math.floor((timeRemainingMs % (60 * 60 * 1000)) / (60 * 1000));
      timeRemainingDisplay = hours > 0
        ? `${hours} hour${hours !== 1 ? 's' : ''} ${minutes} minute${minutes !== 1 ? 's' : ''}`
        : `${minutes} minute${minutes !== 1 ? 's' : ''}`;
    }

    return ok({
      has_pending_request: true,
      request_id: request.request_id,
      status: isReady ? 'ready' : 'pending',
      requested_at: request.requested_at,
      ready_at: request.ready_at,
      is_ready: isReady,
      time_remaining_ms: timeRemainingMs,
      time_remaining_display: timeRemainingDisplay,
    }, origin);

  } catch (error: any) {
    console.error('Get vault deletion status error:', error);
    return internalError('Failed to get vault deletion status', origin);
  }
};
