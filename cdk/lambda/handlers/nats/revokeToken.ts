/**
 * Revoke NATS Token
 *
 * Revokes a previously issued NATS token. The token will no longer be valid
 * for authentication to the NATS cluster.
 *
 * POST /vault/nats/token/revoke
 *
 * Request body:
 * {
 *   "token_id": "string"  // The token ID to revoke
 * }
 *
 * Requires: Member JWT token (can only revoke own tokens)
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  requireUserClaims,
  putAudit,
  getRequestId,
  nowIso,
  parseJsonBody,
  ValidationError,
} from '../../common/util';
import { regenerateAccountJwtWithRevocations } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});

const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

interface RevokeTokenRequest {
  token_id: string;
}

interface RevokeTokenResponse {
  token_id: string;
  status: 'revoked';
  revoked_at: string;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Require authenticated member
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    if (!userGuid) {
      return badRequest('Missing user_guid in token', origin);
    }

    // Parse request body
    let body: RevokeTokenRequest;
    try {
      body = parseJsonBody<RevokeTokenRequest>(event);
    } catch (e) {
      if (e instanceof ValidationError) {
        return badRequest(e.message, origin);
      }
      throw e;
    }

    if (!body.token_id) {
      return badRequest('Missing token_id', origin);
    }

    // Get the token
    const tokenResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_TOKENS,
      Key: marshall({ token_id: body.token_id }),
    }));

    if (!tokenResult.Item) {
      return notFound('Token not found', origin);
    }

    const token = unmarshall(tokenResult.Item);

    // Verify ownership
    if (token.user_guid !== userGuid) {
      return forbidden('Cannot revoke tokens belonging to other users', origin);
    }

    // Check if already revoked
    if (token.status === 'revoked') {
      return ok({
        token_id: body.token_id,
        status: 'revoked',
        revoked_at: token.revoked_at,
        message: 'Token was already revoked',
      }, origin);
    }

    const now = nowIso();
    const nowTimestamp = Math.floor(Date.now() / 1000);

    // SECURITY: Get user public key for NATS-level revocation enforcement
    const userPublicKey = token.user_public_key;
    if (!userPublicKey) {
      // Legacy token without public key - mark as revoked but can't enforce at NATS level
      console.warn(`Token ${body.token_id} missing user_public_key - NATS-level revocation not possible`);
    }

    // Revoke the token in DynamoDB
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_NATS_TOKENS,
      Key: marshall({ token_id: body.token_id }),
      UpdateExpression: 'SET #status = :revoked, revoked_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':revoked': 'revoked',
        ':now': now,
      }),
    }));

    // SECURITY: Enforce revocation at NATS level by updating account JWT
    let natsRevocationEnforced = false;
    if (userPublicKey) {
      try {
        // Get the user's account
        const accountResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_NATS_ACCOUNTS,
          Key: marshall({ user_guid: userGuid }),
        }));

        if (accountResult.Item) {
          const account = unmarshall(accountResult.Item);

          // Build revocations map: user public key -> revocation timestamp
          // The timestamp means any JWT issued BEFORE this time is revoked
          const existingRevocations = account.revocations || {};

          // Add the new revocation (use current timestamp so all existing JWTs are revoked)
          const updatedRevocations: { [key: string]: number } = {
            ...existingRevocations,
            [userPublicKey]: nowTimestamp,
          };

          // Regenerate account JWT with updated revocations
          const accountName = `account-${userGuid.substring(0, 8)}`;
          const newAccountJwt = await regenerateAccountJwtWithRevocations(
            accountName,
            account.account_public_key,
            updatedRevocations
          );

          // Update the account with new JWT and revocations
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_NATS_ACCOUNTS,
            Key: marshall({ user_guid: userGuid }),
            UpdateExpression: 'SET account_jwt = :jwt, revocations = :revocations, updated_at = :now',
            ExpressionAttributeValues: marshall({
              ':jwt': newAccountJwt,
              ':revocations': updatedRevocations,
              ':now': now,
            }),
          }));

          natsRevocationEnforced = true;
          console.info(`SECURITY: Revoked user key ${userPublicKey.substring(0, 12)}... in account JWT`);
        }
      } catch (revocationError: any) {
        // Log but don't fail - token is still marked revoked in DynamoDB
        console.error('Failed to enforce NATS-level revocation:', revocationError.message);
      }
    }

    // Audit log
    await putAudit({
      event: 'nats_token_revoked',
      user_guid: userGuid,
      token_id: body.token_id,
      client_type: token.client_type,
      user_public_key: userPublicKey,
      nats_revocation_enforced: natsRevocationEnforced,
      revoked_at: now,
    }, requestId);

    const response: RevokeTokenResponse = {
      token_id: body.token_id,
      status: 'revoked',
      revoked_at: now,
    };

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error revoking NATS token:', error);
    return internalError('Failed to revoke NATS token', origin);
  }
};
