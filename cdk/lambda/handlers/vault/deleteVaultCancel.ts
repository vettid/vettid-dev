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

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;

/**
 * POST /vault/delete/cancel
 *
 * Cancel a pending vault deletion request.
 * Can be called at any time before confirmation (even after the 24-hour waiting period).
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

    // Find pending or ready deletion request for this member
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
      return notFound('No pending deletion request found', origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();

    // Cancel the request
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      Key: marshall({ request_id: request.request_id }),
      UpdateExpression: 'SET #status = :cancelled, cancelled_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':cancelled': 'cancelled',
        ':now': now.toISOString(),
      }),
    }));

    // Audit log
    await putAudit({
      type: 'vault_deletion_cancelled',
      member_guid: memberGuid,
      request_id: request.request_id,
    }, requestId);

    return ok({
      success: true,
      request_id: request.request_id,
      message: 'Vault deletion request has been cancelled.',
    }, origin);

  } catch (error: any) {
    console.error('Cancel vault deletion error:', error);
    return internalError('Failed to cancel vault deletion', origin);
  }
};
