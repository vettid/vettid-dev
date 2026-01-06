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

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;

/**
 * GET /vault/credentials/restore/status
 *
 * Get the status of any pending credential restore request.
 *
 * Requires member JWT authentication.
 *
 * Returns:
 * - has_pending_request: boolean
 * - recovery_id: ID of pending request (if any)
 * - status: 'pending_timer' | 'pending_approval' | 'ready' | 'approved' | null
 * - lost_device: boolean
 * - ready_at: ISO timestamp when recovery can be confirmed (if pending_timer)
 * - is_ready: boolean indicating if recovery can be confirmed now
 * - cancelled_reason: string (if cancelled)
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

    // Find any active restore request for this member
    const existingRequest = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid',
      FilterExpression: '#status IN (:pending_timer, :pending_approval, :ready, :approved)',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending_timer': 'pending_timer',
        ':pending_approval': 'pending_approval',
        ':ready': 'ready',
        ':approved': 'approved',
      }),
      ScanIndexForward: false,
      Limit: 1,
    }));

    if (!existingRequest.Items || existingRequest.Items.length === 0) {
      // Check for recently cancelled requests (to show reason)
      const cancelledRequest = await ddb.send(new QueryCommand({
        TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
        IndexName: 'member-status-index',
        KeyConditionExpression: 'member_guid = :guid',
        FilterExpression: '#status IN (:cancelled, :denied) AND cancelled_at > :recentTime',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':guid': memberGuid,
          ':cancelled': 'cancelled',
          ':denied': 'denied',
          ':recentTime': new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Last 24 hours
        }),
        ScanIndexForward: false,
        Limit: 1,
      }));

      if (cancelledRequest.Items && cancelledRequest.Items.length > 0) {
        const cancelled = unmarshall(cancelledRequest.Items[0]);
        return ok({
          has_pending_request: false,
          recovery_id: cancelled.recovery_id,
          status: cancelled.status,
          cancelled_at: cancelled.cancelled_at,
          cancelled_reason: cancelled.cancelled_reason || null,
          is_ready: false,
        }, origin);
      }

      return ok({
        has_pending_request: false,
        recovery_id: null,
        status: null,
        is_ready: false,
      }, origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();

    // Calculate readiness based on status
    let isReady = false;
    let timeRemainingMs = 0;
    let timeRemainingDisplay = '';

    if (request.status === 'pending_timer' && request.ready_at) {
      const readyAt = new Date(request.ready_at);
      isReady = now >= readyAt;
      if (!isReady) {
        timeRemainingMs = readyAt.getTime() - now.getTime();
        const hours = Math.floor(timeRemainingMs / (60 * 60 * 1000));
        const minutes = Math.floor((timeRemainingMs % (60 * 60 * 1000)) / (60 * 1000));
        timeRemainingDisplay = hours > 0
          ? `${hours} hour${hours !== 1 ? 's' : ''} ${minutes} minute${minutes !== 1 ? 's' : ''}`
          : `${minutes} minute${minutes !== 1 ? 's' : ''}`;
      }
    } else if (request.status === 'ready' || request.status === 'approved') {
      isReady = true;
    }

    const response: Record<string, any> = {
      has_pending_request: true,
      recovery_id: request.recovery_id,
      status: request.status,
      lost_device: request.lost_device || false,
      requested_at: request.requested_at,
      is_ready: isReady,
    };

    if (request.ready_at) {
      response.ready_at = request.ready_at;
    }

    if (timeRemainingMs > 0) {
      response.time_remaining_ms = timeRemainingMs;
      response.time_remaining_display = timeRemainingDisplay;
    }

    if (request.status === 'pending_approval') {
      response.waiting_for_approval = true;
      response.message = 'Waiting for approval from your current device.';
    } else if (request.status === 'approved') {
      response.message = 'Transfer approved. You can now complete the restore.';
    } else if (isReady) {
      response.message = 'Recovery is ready. You can now complete the restore.';
    } else {
      response.message = `Please wait ${timeRemainingDisplay} before completing recovery.`;
    }

    return ok(response, origin);

  } catch (error: any) {
    console.error('Get credential restore status error:', error);
    return internalError('Failed to get credential restore status', origin);
  }
};
