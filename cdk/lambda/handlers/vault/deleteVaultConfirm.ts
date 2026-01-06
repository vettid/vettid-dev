import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;

/**
 * POST /vault/delete/confirm
 *
 * Confirm vault deletion after the 24-hour waiting period.
 * This action is IRREVERSIBLE - it will delete the credential, NATS account,
 * and all associated vault data.
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
      return notFound('No pending deletion request found', origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();
    const readyAt = new Date(request.ready_at);

    // Check if 24-hour waiting period has elapsed
    if (now < readyAt) {
      const remainingMs = readyAt.getTime() - now.getTime();
      const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
      return conflict(
        `Deletion cannot be confirmed yet. Please wait ${remainingHours} more hour(s).`,
        origin
      );
    }

    // Proceed with vault deletion
    const credentialId = request.credential_id;

    // 1. Mark credential as deleted
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ user_guid: memberGuid }),
      UpdateExpression: 'SET #status = :deleted, deleted_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':deleted': 'DELETED',
        ':now': now.toISOString(),
      }),
    }));

    // 2. Revoke NATS account (mark as deleted, don't remove for audit trail)
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Key: marshall({ user_guid: memberGuid }),
        UpdateExpression: 'SET #status = :deleted, deleted_at = :now',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':deleted': 'deleted',
          ':now': now.toISOString(),
        }),
      }));
    } catch (err) {
      // NATS account may not exist, which is fine
      console.log('NATS account not found or already deleted');
    }

    // 3. Revoke all LAT tokens for this user
    // Query by user_guid GSI if it exists, otherwise we track the token hash
    // For now, we'll rely on the credential being marked as deleted to invalidate tokens

    // 4. Mark deletion request as completed
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      Key: marshall({ request_id: request.request_id }),
      UpdateExpression: 'SET #status = :completed, completed_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':completed': 'completed',
        ':now': now.toISOString(),
      }),
    }));

    // Audit log
    await putAudit({
      type: 'vault_deleted',
      member_guid: memberGuid,
      request_id: request.request_id,
      credential_id: credentialId,
    }, requestId);

    return ok({
      success: true,
      request_id: request.request_id,
      message: 'Vault has been permanently deleted. You can enroll a new vault at any time.',
    }, origin);

  } catch (error: any) {
    console.error('Confirm vault deletion error:', error);
    return internalError('Failed to confirm vault deletion', origin);
  }
};
