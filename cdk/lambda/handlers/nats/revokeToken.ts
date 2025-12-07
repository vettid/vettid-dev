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
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
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

const ddb = new DynamoDBClient({});

const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;

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

    // Revoke the token
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

    // Audit log
    await putAudit({
      event: 'nats_token_revoked',
      user_guid: userGuid,
      token_id: body.token_id,
      client_type: token.client_type,
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
