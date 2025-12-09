/**
 * Generate NATS Control Token
 *
 * Generates a privileged JWT token for Vault Services to communicate with vault instances
 * via the control topic. This token has write access to the control topic for sending
 * system commands (shutdown, backup, update, etc.).
 *
 * POST /admin/nats/control-token
 *
 * Request body:
 * {
 *   "user_guid": "string",  // Target member's user_guid
 *   "purpose": "string"     // Purpose of the token (for audit)
 * }
 *
 * Requires: Admin JWT token
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
  requireAdminGroup,
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

// Control tokens are short-lived for security
const CONTROL_TOKEN_VALIDITY_MINUTES = 60; // 1 hour

interface GenerateControlTokenRequest {
  user_guid: string;
  purpose: string;
}

interface ControlTokenResponse {
  token_id: string;
  nats_jwt: string;
  nats_seed: string;
  nats_creds: string;  // Full creds file content
  nats_endpoint: string;
  expires_at: string;
  target_user_guid: string;
  control_topic: string;
  permissions: {
    publish: string[];
    subscribe: string[];
  };
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  // Require admin authentication
  const adminError = requireAdminGroup(event, origin);
  if (adminError) {
    return adminError;
  }

  try {
    // Parse request body
    let body: GenerateControlTokenRequest;
    try {
      body = parseJsonBody<GenerateControlTokenRequest>(event);
    } catch (e) {
      if (e instanceof ValidationError) {
        return badRequest(e.message, origin);
      }
      throw e;
    }

    if (!body.user_guid) {
      return badRequest('Missing user_guid', origin);
    }

    if (!body.purpose) {
      return badRequest('Missing purpose (required for audit)', origin);
    }

    // Verify target user has NATS account
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: body.user_guid }),
    }));

    if (!accountResult.Item) {
      return notFound('NATS account not found for target user', origin);
    }

    const account = unmarshall(accountResult.Item);
    if (account.status !== 'active') {
      return forbidden('Target user NATS account is not active', origin);
    }

    const now = nowIso();
    const expiresAt = addMinutesIso(CONTROL_TOKEN_VALIDITY_MINUTES);
    const tokenId = `nats_ctrl_${randomUUID()}`;

    // Control token permissions - can only write to control topic
    const ownerSpace = account.owner_space_id;
    const messageSpace = account.message_space_id || `MessageSpace.${body.user_guid}`;
    const controlTopic = `${ownerSpace}.control`;
    const accountSeed = account.account_seed;

    if (!accountSeed) {
      return internalError('NATS account missing signing key. Please recreate account.', origin);
    }

    const publishPerms = [controlTopic];
    const subscribePerms: string[] = []; // Control tokens don't need to subscribe

    // Generate real NATS user credentials
    const expiresAtDate = new Date(expiresAt);
    const credentials = await generateUserCredentials(
      `control-${body.user_guid.substring(0, 8)}`,
      accountSeed,
      'control',
      ownerSpace,
      messageSpace,
      expiresAtDate
    );

    const jwt = credentials.jwt;
    const seed = credentials.seed;

    // Store token record
    const tokenRecord = {
      token_id: tokenId,
      user_guid: 'SYSTEM', // Control tokens are system-issued
      target_user_guid: body.user_guid,
      client_type: 'control',
      purpose: body.purpose,
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
      event: 'nats_control_token_generated',
      target_user_guid: body.user_guid,
      token_id: tokenId,
      purpose: body.purpose,
      expires_at: expiresAt,
      control_topic: controlTopic,
    }, requestId);

    const response: ControlTokenResponse = {
      token_id: tokenId,
      nats_jwt: jwt,
      nats_seed: seed,
      nats_creds: formatCredsFile(jwt, seed),
      nats_endpoint: `nats://${NATS_DOMAIN}:4222`,
      expires_at: expiresAt,
      target_user_guid: body.user_guid,
      control_topic: controlTopic,
      permissions: {
        publish: publishPerms,
        subscribe: subscribePerms,
      },
    };

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error generating NATS control token:', error);
    return internalError('Failed to generate NATS control token', origin);
  }
};
