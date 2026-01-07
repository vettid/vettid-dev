import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  generateSecureId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

// 24 hours in milliseconds
const DELETION_DELAY_MS = 24 * 60 * 60 * 1000;
// TTL: 7 days after ready_at (for completed/cancelled requests)
const TTL_DAYS = 7;

/**
 * POST /vault/delete/request
 *
 * Request vault deletion. Initiates a 24-hour waiting period before deletion can be confirmed.
 * This delay protects against account takeover by giving legitimate users time to cancel.
 *
 * Requires member JWT authentication.
 *
 * Returns:
 * - request_id: ID for tracking the deletion request
 * - status: 'pending'
 * - ready_at: ISO timestamp when deletion can be confirmed
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

    // Check if user has an active NATS account (vault)
    // In the Nitro model, having an active NATS account means the user has a vault
    const natsAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: memberGuid }),
    }));

    if (!natsAccountResult.Item) {
      return badRequest('No active vault found', origin);
    }

    const natsAccount = unmarshall(natsAccountResult.Item);
    if (natsAccount.status !== 'active') {
      return badRequest('No active vault found', origin);
    }

    // Check for existing pending deletion request
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

    if (existingRequest.Items && existingRequest.Items.length > 0) {
      const existing = unmarshall(existingRequest.Items[0]);
      return conflict('A deletion request is already pending', origin);
    }

    // Create the deletion request
    const now = new Date();
    const readyAt = new Date(now.getTime() + DELETION_DELAY_MS);
    const ttl = Math.floor(readyAt.getTime() / 1000) + (TTL_DAYS * 24 * 60 * 60);
    const deletionRequestId = generateSecureId('del', 16);

    await ddb.send(new PutItemCommand({
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      Item: marshall({
        request_id: deletionRequestId,
        member_guid: memberGuid,
        nats_account_public_key: natsAccount.account_public_key,
        status: 'pending',
        requested_at: now.toISOString(),
        ready_at: readyAt.toISOString(),
        ttl,
      }, { removeUndefinedValues: true }),
    }));

    // Audit log
    await putAudit({
      type: 'vault_deletion_requested',
      member_guid: memberGuid,
      request_id: deletionRequestId,
      nats_account_public_key: natsAccount.account_public_key,
      ready_at: readyAt.toISOString(),
    }, requestId);

    return ok({
      request_id: deletionRequestId,
      status: 'pending',
      requested_at: now.toISOString(),
      ready_at: readyAt.toISOString(),
      message: 'Vault deletion requested. You can confirm deletion after the 24-hour waiting period.',
    }, origin);

  } catch (error: any) {
    console.error('Vault deletion request error:', error);
    return internalError('Failed to request vault deletion', origin);
  }
};
