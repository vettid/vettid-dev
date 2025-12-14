/**
 * Generate NATS Member JWT
 *
 * Generates a scoped JWT token for a member to connect to their NATS namespace.
 * The JWT grants access to:
 * - OwnerSpace.{member_guid}.* (publish/subscribe)
 * - MessageSpace.{member_guid}.* (publish/subscribe)
 *
 * POST /vault/nats/token
 *
 * Request body:
 * {
 *   "client_type": "app" | "vault",  // Type of client requesting token
 *   "device_id": "string"            // Optional device identifier
 * }
 *
 * Requires: Member JWT token
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
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
  addMinutesIso,
  parseJsonBody,
  ValidationError,
} from '../../common/util';
import { generateUserCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';

// Token validity periods
const APP_TOKEN_VALIDITY_MINUTES = 60 * 24; // 24 hours for mobile apps
const VAULT_TOKEN_VALIDITY_MINUTES = 60 * 24 * 7; // 7 days for vault instances

interface GenerateTokenRequest {
  client_type: 'app' | 'vault';
  device_id?: string;
}

interface NatsTokenRecord {
  token_id: string;
  user_guid: string;
  client_type: 'app' | 'vault';
  device_id?: string;
  issued_at: string;
  expires_at: string;
  status: 'active' | 'revoked';
  last_used_at?: string;
}

interface GenerateTokenResponse {
  token_id: string;
  nats_jwt: string;
  nats_seed: string;
  nats_creds: string;  // Full creds file content for easy use
  nats_endpoint: string;
  expires_at: string;
  permissions: {
    publish: string[];
    subscribe: string[];
  };
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
    let body: GenerateTokenRequest;
    try {
      body = parseJsonBody<GenerateTokenRequest>(event);
    } catch (e) {
      if (e instanceof ValidationError) {
        return badRequest(e.message, origin);
      }
      throw e;
    }

    // Validate client_type
    if (!body.client_type || !['app', 'vault'].includes(body.client_type)) {
      return badRequest('Invalid client_type. Must be "app" or "vault"', origin);
    }

    // Verify NATS account exists and is active
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!accountResult.Item) {
      return notFound('NATS account not found. Create account first via POST /vault/nats/account', origin);
    }

    const account = unmarshall(accountResult.Item);
    if (account.status !== 'active') {
      return forbidden('NATS account is not active', origin);
    }

    // Calculate token validity
    const validityMinutes = body.client_type === 'vault'
      ? VAULT_TOKEN_VALIDITY_MINUTES
      : APP_TOKEN_VALIDITY_MINUTES;

    const now = nowIso();
    const expiresAt = addMinutesIso(validityMinutes);
    const tokenId = `nats_${randomUUID()}`;

    // Get account details for credential generation
    const ownerSpace = account.owner_space_id;
    const messageSpace = account.message_space_id;
    const accountSeed = account.account_seed;

    if (!accountSeed) {
      return internalError('NATS account missing signing key. Please recreate account.', origin);
    }

    // Define permissions based on client type
    let publishPerms: string[];
    let subscribePerms: string[];

    if (body.client_type === 'app') {
      // Mobile app permissions
      publishPerms = [
        `${ownerSpace}.forVault.>`,   // App sends to vault
      ];
      subscribePerms = [
        `${ownerSpace}.forApp.>`,     // App receives from vault
        `${ownerSpace}.eventTypes`,   // App can read handler definitions
      ];
    } else {
      // Vault instance permissions
      publishPerms = [
        `${ownerSpace}.forApp.>`,     // Vault sends to app
        `${messageSpace}.forOwner.>`, // Vault sends to connections
        `${messageSpace}.ownerProfile`, // Vault can publish profile
        `${messageSpace}.call.>`,     // Vault can send call signals to peers
      ];
      subscribePerms = [
        `${ownerSpace}.forVault.>`,   // Vault receives from app
        `${ownerSpace}.control`,      // Vault receives system commands
        `${ownerSpace}.eventTypes`,   // Vault can read handler definitions
        `${messageSpace}.forOwner.>`, // Vault receives from connections
        `${messageSpace}.call.>`,     // Vault receives call signals from peers
      ];
    }

    // Generate real NATS user credentials using nkeys
    const expiresAtDate = new Date(expiresAt);
    const credentials = await generateUserCredentials(
      userGuid,
      accountSeed,
      body.client_type,
      ownerSpace,
      messageSpace,
      expiresAtDate
    );

    const jwt = credentials.jwt;
    const seed = credentials.seed;

    // Store token record
    const tokenRecord: NatsTokenRecord = {
      token_id: tokenId,
      user_guid: userGuid,
      client_type: body.client_type,
      device_id: body.device_id,
      issued_at: now,
      expires_at: expiresAt,
      status: 'active',
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_NATS_TOKENS,
      Item: marshall(tokenRecord),
    }));

    // Audit log
    await putAudit({
      event: 'nats_token_generated',
      user_guid: userGuid,
      token_id: tokenId,
      client_type: body.client_type,
      device_id: body.device_id,
      expires_at: expiresAt,
    }, requestId);

    const response: GenerateTokenResponse = {
      token_id: tokenId,
      nats_jwt: jwt,
      nats_seed: seed,
      nats_creds: formatCredsFile(jwt, seed),
      nats_endpoint: `nats://${NATS_DOMAIN}:4222`,
      expires_at: expiresAt,
      permissions: {
        publish: publishPerms,
        subscribe: subscribePerms,
      },
    };

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error generating NATS token:', error);
    return internalError('Failed to generate NATS token', origin);
  }
};
