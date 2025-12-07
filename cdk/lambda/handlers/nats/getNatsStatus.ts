/**
 * Get NATS Account Status
 *
 * Returns the status of a member's NATS account and active tokens.
 *
 * GET /vault/nats/status
 *
 * Requires: Member JWT token
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  getRequestId,
  nowIso,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';

interface NatsStatusResponse {
  has_account: boolean;
  account?: {
    owner_space_id: string;
    message_space_id: string;
    status: string;
    created_at: string;
  };
  active_tokens: Array<{
    token_id: string;
    client_type: 'app' | 'vault';
    device_id?: string;
    issued_at: string;
    expires_at: string;
    last_used_at?: string;
  }>;
  nats_endpoint: string;
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

    // Get account
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    const response: NatsStatusResponse = {
      has_account: false,
      active_tokens: [],
      nats_endpoint: `nats://${NATS_DOMAIN}:4222`,
    };

    if (accountResult.Item) {
      const account = unmarshall(accountResult.Item);
      response.has_account = true;
      response.account = {
        owner_space_id: account.owner_space_id,
        message_space_id: account.message_space_id,
        status: account.status,
        created_at: account.created_at,
      };

      // Get active tokens for this user
      // Query using GSI on user_guid
      const tokensResult = await ddb.send(new QueryCommand({
        TableName: TABLE_NATS_TOKENS,
        IndexName: 'user-index',
        KeyConditionExpression: 'user_guid = :user_guid',
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':user_guid': userGuid,
          ':active': 'active',
        }),
      }));

      const now = new Date();
      if (tokensResult.Items) {
        response.active_tokens = tokensResult.Items
          .map(item => unmarshall(item))
          .filter(token => new Date(token.expires_at) > now) // Filter out expired tokens
          .map(token => ({
            token_id: token.token_id,
            client_type: token.client_type,
            device_id: token.device_id,
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
          }));
      }
    }

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error getting NATS status:', error);
    return internalError('Failed to get NATS status', origin);
  }
};
