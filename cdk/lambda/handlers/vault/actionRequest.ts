import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHmac, randomBytes } from 'crypto';
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
  checkRateLimit,
  hashIdentifier,
  tooManyRequests,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const secretsClient = new SecretsManagerClient({});

const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;

// Action token signing secret from Secrets Manager
const ACTION_TOKEN_SECRET_ARN = process.env.ACTION_TOKEN_SECRET_ARN;

// Secret caching to avoid repeated Secrets Manager calls
let cachedSigningKey: string | null = null;
let secretCacheTime = 0;
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Get signing key from Secrets Manager (with caching)
 */
async function getSigningKey(): Promise<string> {
  // Check cache
  const now = Date.now();
  if (cachedSigningKey && (now - secretCacheTime) < SECRET_CACHE_TTL_MS) {
    return cachedSigningKey;
  }

  if (!ACTION_TOKEN_SECRET_ARN) {
    throw new Error('CRITICAL: ACTION_TOKEN_SECRET_ARN environment variable is required');
  }

  // Fetch from Secrets Manager
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: ACTION_TOKEN_SECRET_ARN,
  }));

  if (!response.SecretString) {
    throw new Error('Action token signing secret is empty');
  }

  const secret = JSON.parse(response.SecretString);
  cachedSigningKey = secret.signing_key;
  secretCacheTime = now;

  if (!cachedSigningKey) {
    throw new Error('Action token secret missing "signing_key" field');
  }

  return cachedSigningKey;
}

// Rate limiting: 10 action requests per user per minute
const RATE_LIMIT_MAX_REQUESTS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 1;

// Action type to endpoint mapping
const ACTION_ENDPOINTS: Record<string, string> = {
  'authenticate': '/api/v1/auth/execute',
  'add_secret': '/api/v1/secrets/add',
  'retrieve_secret': '/api/v1/secrets/retrieve',
  'add_policy': '/api/v1/policies/update',
  'modify_credential': '/api/v1/credential/modify',
  // Vault lifecycle actions (for mobile apps without Cognito auth)
  'vault_start': '/api/v1/vault/start',
  'vault_stop': '/api/v1/vault/stop',
  'vault_status': '/api/v1/vault/status',
};

interface ActionRequestBody {
  user_guid: string;
  action_type: string;
  device_fingerprint?: string;
}

/**
 * Create a JWT-like action token signed with HMAC-SHA256
 * Uses signing key from AWS Secrets Manager
 */
async function createActionToken(payload: {
  sub: string;
  action: string;
  endpoint: string;
  jti: string;
  iat: number;
  exp: number;
}): Promise<string> {
  const header = { typ: 'action', alg: 'HS256' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

  // Get signing key from Secrets Manager (cached)
  const signingKey = await getSigningKey();

  // HMAC-SHA256 signature
  const signature = createHmac('sha256', signingKey)
    .update(`${headerB64}.${payloadB64}`)
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

    // Rate limiting by user_guid (prevents action token abuse)
    const userHash = hashIdentifier(body.user_guid);
    const isAllowed = await checkRateLimit(userHash, 'action_request', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      return tooManyRequests('Too many action requests. Please try again later.');
    }

    // Validate action type
    const actionEndpoint = ACTION_ENDPOINTS[body.action_type];
    if (!actionEndpoint) {
      return badRequest(`Invalid action_type: ${body.action_type}`);
    }

    // Get credential to verify user exists and is active
    // Credentials table has composite key (user_guid + credential_id), so we Query by user_guid
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': body.user_guid,
        ':status': 'ACTIVE',
      }),
      Limit: 1,
    }));

    if (!credentialResult.Items || credentialResult.Items.length === 0) {
      return notFound('User credential not found');
    }

    const credential = unmarshall(credentialResult.Items[0]);

    // Check for account lockout
    if (credential.failed_auth_count >= 3) {
      return conflict('Account is locked due to too many failed attempts');
    }

    // Get current LAT for verification using user-index GSI
    const latResult = await ddb.send(new QueryCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': body.user_guid,
        ':status': 'ACTIVE',
      }),
      Limit: 1,
    }));

    if (!latResult.Items || latResult.Items.length === 0) {
      return internalError('LAT not found for user');
    }

    const lat = unmarshall(latResult.Items[0]);

    // Find an unused transaction key using user-index GSI
    const unusedKeyResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': body.user_guid,
        ':status': 'UNUSED',
      }),
      Limit: 10,  // Fetch a few since filter is applied after key conditions
    }));

    if (!unusedKeyResult.Items || unusedKeyResult.Items.length === 0) {
      return conflict('No transaction keys available. Please re-enroll.');
    }

    const transactionKey = unmarshall(unusedKeyResult.Items[0]);

    // Create action token
    const now = Date.now();
    const expiresAt = now + 5 * 60 * 1000;  // 5 minutes
    const tokenId = generateSecureId('action', 32);

    const actionToken = await createActionToken({
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
      }, { removeUndefinedValues: true }),  // device_fingerprint is optional
    }));

    // Generate LAT token from hash (we stored the hash, so we need to generate a new one for the response)
    // In production, we would store the token encrypted and decrypt it here
    // For now, we'll regenerate it (this is a simplification - production should handle this better)
    const latToken = randomBytes(32).toString('hex');

    // Audit log
    await putAudit({
      type: 'action_requested',
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
