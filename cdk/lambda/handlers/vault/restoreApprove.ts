import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

interface ApproveRequestBody {
  recovery_id: string;
}

/**
 * POST /vault/credentials/restore/approve
 *
 * Approve a credential transfer request from the active device.
 * This endpoint is called by the mobile app when the user approves the transfer notification.
 *
 * After approval, the old credential is immediately invalidated and the new device
 * can complete the credential setup.
 *
 * This endpoint uses the enrollment JWT authorizer (called from mobile device).
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Get user_guid from authorizer context (from enrollment JWT)
    const authContext = (event.requestContext as any)?.authorizer?.lambda as {
      userGuid?: string;
    } | undefined;

    if (!authContext?.userGuid) {
      return badRequest('Authentication required', origin);
    }
    const memberGuid = authContext.userGuid;

    // Parse request body
    let body: ApproveRequestBody;
    if (!event.body) {
      return badRequest('Request body is required', origin);
    }
    try {
      body = JSON.parse(event.body) as ApproveRequestBody;
    } catch {
      return badRequest('Invalid JSON in request body', origin);
    }

    if (!body.recovery_id) {
      return badRequest('recovery_id is required', origin);
    }

    // Get the recovery request
    const requestResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: body.recovery_id }),
    }));

    if (!requestResult.Item) {
      return notFound('Recovery request not found', origin);
    }

    const request = unmarshall(requestResult.Item);

    // Verify this request belongs to the authenticated user
    if (request.member_guid !== memberGuid) {
      return badRequest('Request does not belong to authenticated user', origin);
    }

    // Verify the request is in pending_approval status
    if (request.status !== 'pending_approval') {
      return conflict(`Request is not pending approval (status: ${request.status})`, origin);
    }

    // Verify this is a transfer request, not a recovery
    if (request.lost_device) {
      return conflict('Cannot approve a lost device recovery request', origin);
    }

    const now = new Date();

    // Approve the request - mark as ready for immediate transfer
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: body.recovery_id }),
      UpdateExpression: 'SET #status = :approved, approved_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':approved': 'approved',
        ':now': now.toISOString(),
      }),
    }));

    // Mark NATS account as transferring (vault-manager will handle credential transfer)
    // The new device will complete the transfer via vault-manager
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Key: marshall({ user_guid: memberGuid }),
        UpdateExpression: 'SET transfer_approved_at = :now, transfer_status = :status',
        ExpressionAttributeValues: marshall({
          ':now': now.toISOString(),
          ':status': 'approved',
        }),
      }));
    } catch (err) {
      console.log('NATS account not found or already updated');
    }

    // Audit log
    await putAudit({
      type: 'credential_transfer_approved',
      member_guid: memberGuid,
      recovery_id: body.recovery_id,
      nats_account_public_key: request.nats_account_public_key,
    }, requestId);

    return ok({
      success: true,
      recovery_id: body.recovery_id,
      message: 'Transfer approved. Your credential has been transferred to the new device.',
    }, origin);

  } catch (error: any) {
    console.error('Approve credential transfer error:', error);
    return internalError('Failed to approve credential transfer', origin);
  }
};
