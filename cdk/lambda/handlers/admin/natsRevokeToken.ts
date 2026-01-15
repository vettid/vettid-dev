/**
 * NATS Token Revocation Handler
 *
 * Revokes a user's NATS token by:
 * 1. Marking the token as revoked in NatsTokens table
 * 2. Adding the user's public key to the account's revocation list
 * 3. Regenerating the account JWT with updated revocations
 * 4. The NATS server will enforce the revocation on next connection attempt
 *
 * POST /admin/nats/revoke-token
 * Body: { user_guid: string, token_id?: string, reason: string }
 *
 * If token_id is not provided, all active tokens for the user are revoked.
 */

import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand, QueryCommand, BatchWriteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  requireAdminGroup,
  getAdminEmail,
  nowIso,
} from '../../common/util';
import { regenerateAccountJwtWithRevocations } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;

interface RevokeRequest {
  user_guid: string;
  token_id?: string;  // Optional - if not provided, revoke all tokens
  reason: string;
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath,
    });
    return authError;
  }

  const adminEmail = getAdminEmail(event);
  const now = nowIso();

  try {
    // Parse request body
    if (!event.body) {
      return badRequest('Request body required');
    }

    let body: RevokeRequest;
    try {
      body = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON in request body');
    }

    const { user_guid, token_id, reason } = body;

    if (!user_guid) {
      return badRequest('user_guid is required');
    }

    if (!reason || reason.trim().length < 3) {
      return badRequest('reason is required (min 3 characters)');
    }

    // Get the user's NATS account
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid }),
    }));

    if (!accountResult.Item) {
      return notFound('NATS account not found for user');
    }

    const account = unmarshall(accountResult.Item);

    // Get tokens to revoke
    let tokensToRevoke: any[] = [];

    if (token_id) {
      // Revoke specific token
      const tokenResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_NATS_TOKENS,
        Key: marshall({ token_id }),
      }));

      if (!tokenResult.Item) {
        return notFound('Token not found');
      }

      const token = unmarshall(tokenResult.Item);

      if (token.user_guid !== user_guid) {
        return badRequest('Token does not belong to specified user');
      }

      if (token.status === 'revoked') {
        return badRequest('Token is already revoked');
      }

      tokensToRevoke.push(token);
    } else {
      // Revoke all active tokens for user
      // Query by user_guid using GSI (assuming there's a user-index)
      // If no GSI, we'll need to scan with filter
      const queryResult = await ddb.send(new QueryCommand({
        TableName: TABLE_NATS_TOKENS,
        IndexName: 'user-index',
        KeyConditionExpression: 'user_guid = :guid',
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':guid': user_guid,
          ':active': 'active',
        }),
      }));

      tokensToRevoke = (queryResult.Items || []).map(item => unmarshall(item));

      if (tokensToRevoke.length === 0) {
        return ok({
          message: 'No active tokens found for user',
          revoked_count: 0,
        });
      }
    }

    // Build revocations map
    // NATS uses Unix timestamp - any JWT issued BEFORE this timestamp is revoked
    const revocationTimestamp = Math.floor(Date.now() / 1000) + 1; // +1 to ensure current tokens are revoked
    const existingRevocations = account.revocations || {};
    const newRevocations: { [key: string]: number } = { ...existingRevocations };

    for (const token of tokensToRevoke) {
      if (token.user_public_key) {
        newRevocations[token.user_public_key] = revocationTimestamp;
      }
    }

    // Regenerate account JWT with updated revocations
    const accountName = `account-${user_guid.substring(0, 8)}`;
    const newAccountJwt = await regenerateAccountJwtWithRevocations(
      accountName,
      account.account_public_key,
      newRevocations
    );

    // Update tokens to revoked status
    for (const token of tokensToRevoke) {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_NATS_TOKENS,
        Key: marshall({ token_id: token.token_id }),
        UpdateExpression: 'SET #status = :revoked, revoked_at = :now, revoked_by = :by, revocation_reason = :reason',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':revoked': 'revoked',
          ':now': now,
          ':by': adminEmail,
          ':reason': reason,
        }),
      }));
    }

    // Update account with new JWT and revocations
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid }),
      UpdateExpression: 'SET account_jwt = :jwt, revocations = :revocations, updated_at = :now',
      ExpressionAttributeValues: marshall({
        ':jwt': newAccountJwt,
        ':revocations': newRevocations,
        ':now': now,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'nats_token_revoked',
      user_guid,
      revoked_tokens: tokensToRevoke.map(t => t.token_id),
      revoked_count: tokensToRevoke.length,
      reason,
      revoked_by: adminEmail,
    });

    return ok({
      message: `Successfully revoked ${tokensToRevoke.length} token(s)`,
      user_guid,
      revoked_count: tokensToRevoke.length,
      revoked_tokens: tokensToRevoke.map(t => ({
        token_id: t.token_id,
        client_type: t.client_type,
        device_id: t.device_id,
      })),
    });

  } catch (error: any) {
    console.error('NATS token revocation error:', error);

    await putAudit({
      type: 'nats_token_revocation_error',
      error: error.message,
    });

    return internalError('Failed to revoke NATS token');
  }
};
