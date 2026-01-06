import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  notFound,
  internalError,
  getRequestId,
  putAudit,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;

/**
 * POST /vault/credentials/restore/cancel
 *
 * Cancel a pending credential restore request.
 * Can be called from the web UI at any time before the restore is completed.
 *
 * Requires member JWT authentication.
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
      FilterExpression: '#status IN (:pending_timer, :pending_approval, :ready)',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending_timer': 'pending_timer',
        ':pending_approval': 'pending_approval',
        ':ready': 'ready',
      }),
      Limit: 1,
    }));

    if (!existingRequest.Items || existingRequest.Items.length === 0) {
      return notFound('No pending restore request found', origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();

    // Cancel the request
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: request.recovery_id }),
      UpdateExpression: 'SET #status = :cancelled, cancelled_at = :now, cancelled_reason = :reason',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':cancelled': 'cancelled',
        ':now': now.toISOString(),
        ':reason': 'user_cancelled',
      }),
    }));

    // Audit log
    await putAudit({
      type: 'credential_restore_cancelled',
      member_guid: memberGuid,
      recovery_id: request.recovery_id,
      previous_status: request.status,
    }, requestId);

    return ok({
      success: true,
      recovery_id: request.recovery_id,
      message: 'Restore request has been cancelled.',
    }, origin);

  } catch (error: any) {
    console.error('Cancel credential restore error:', error);
    return internalError('Failed to cancel credential restore', origin);
  }
};
