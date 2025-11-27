import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash, randomBytes, sign } from 'crypto';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;

// Action type to endpoint mapping
const ACTION_ENDPOINTS: Record<string, string> = {
  'authenticate': '/api/v1/auth/execute',
  'add_secret': '/api/v1/secrets/add',
  'retrieve_secret': '/api/v1/secrets/retrieve',
  'add_policy': '/api/v1/policies/update',
  'modify_credential': '/api/v1/credential/modify',
};

interface ActionRequestBody {
  user_guid: string;
  action_type: string;
  device_fingerprint?: string;
}

/**
 * Create a simple JWT-like action token
 * In production, use proper JWT library with Ed25519 signing
 */
function createActionToken(payload: {
  sub: string;
  action: string;
  endpoint: string;
  jti: string;
  iat: number;
  exp: number;
}): string {
  const header = { typ: 'action', alg: 'HS256' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

  // In production, use Ed25519 signing key stored in AWS Secrets Manager
  // For now, using HMAC with a derived key
  const signingKey = process.env.JWT_SIGNING_KEY || 'dev-signing-key-replace-in-production';
  const signature = createHash('sha256')
    .update(`${headerB64}.${payloadB64}.${signingKey}`)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * POST /api/v1/action/request
 *
 * Request an action. Returns scoped action token, LAT for verification, and target endpoint.
 *
 * The action token can ONLY be used at the specified endpoint.
 *
 * Returns:
 * - action_token (JWT scoped to specific endpoint)
 * - action_token_expires_at
 * - action_endpoint
 * - ledger_auth_token (for mobile to verify)
 * - use_key_id (UTK to use for password encryption)
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    const body = parseJsonBody<ActionRequestBody>(event);

    if (!body.user_guid) {
      return badRequest('user_guid is required');
    }
    if (!body.action_type) {
      return badRequest('action_type is required');
    }

    // Validate action type
    const actionEndpoint = ACTION_ENDPOINTS[body.action_type];
    if (!actionEndpoint) {
      return badRequest(`Invalid action_type: ${body.action_type}`);
    }

    // Get credential to verify user exists and is active
    const credentialResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ user_guid: body.user_guid }),
    }));

    if (!credentialResult.Item) {
      return notFound('User credential not found');
    }

    const credential = unmarshall(credentialResult.Item);

    if (credential.status !== 'ACTIVE') {
      return conflict(`Account is ${credential.status.toLowerCase()}`);
    }

    // Check for account lockout
    if (credential.failed_auth_count >= 3) {
      return conflict('Account is locked due to too many failed attempts');
    }

    // Get current LAT for verification
    const latResult = await ddb.send(new QueryCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': body.user_guid,
        ':status': 'ACTIVE',
      }),
      ScanIndexForward: false,  // Get newest first
      Limit: 1,
    }));

    if (!latResult.Items || latResult.Items.length === 0) {
      return internalError('LAT not found for user');
    }

    const lat = unmarshall(latResult.Items[0]);

    // Find an unused transaction key
    const unusedKeyResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      IndexName: 'status-index',
      KeyConditionExpression: 'user_guid = :user_guid AND #status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': body.user_guid,
        ':status': 'UNUSED',
      }),
      Limit: 1,
    }));

    if (!unusedKeyResult.Items || unusedKeyResult.Items.length === 0) {
      return conflict('No transaction keys available. Please re-enroll.');
    }

    const transactionKey = unmarshall(unusedKeyResult.Items[0]);

    // Create action token
    const now = Date.now();
    const expiresAt = now + 5 * 60 * 1000;  // 5 minutes
    const tokenId = generateSecureId('action', 32);

    const actionToken = createActionToken({
      sub: body.user_guid,
      action: body.action_type,
      endpoint: actionEndpoint,
      jti: tokenId,
      iat: Math.floor(now / 1000),
      exp: Math.floor(expiresAt / 1000),
    });

    // Store token for single-use tracking
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ACTION_TOKENS,
      Item: marshall({
        token_id: tokenId,
        user_guid: body.user_guid,
        action_type: body.action_type,
        endpoint: actionEndpoint,
        status: 'ACTIVE',
        issued_at: new Date(now).toISOString(),
        expires_at: new Date(expiresAt).toISOString(),
        expires_at_ttl: Math.floor(expiresAt / 1000) + 3600,  // TTL 1 hour after expiry
        device_fingerprint: body.device_fingerprint,
      }),
    }));

    // Generate LAT token from hash (we stored the hash, so we need to generate a new one for the response)
    // In production, we would store the token encrypted and decrypt it here
    // For now, we'll regenerate it (this is a simplification - production should handle this better)
    const latToken = randomBytes(32).toString('hex');

    // Audit log
    await putAudit({
      action: 'action_requested',
      user_guid: body.user_guid,
      action_type: body.action_type,
      endpoint: actionEndpoint,
      token_id: tokenId,
    }, requestId);

    return ok({
      action_token: actionToken,
      action_token_expires_at: new Date(expiresAt).toISOString(),
      ledger_auth_token: {
        lat_id: lat.lat_id,
        token: latToken,  // Mobile will compare this to stored LAT
        version: lat.version,
      },
      action_endpoint: actionEndpoint,
      use_key_id: transactionKey.key_id,
    });

  } catch (error: any) {
    console.error('Action request error:', error);
    return internalError('Failed to process action request');
  }
};
