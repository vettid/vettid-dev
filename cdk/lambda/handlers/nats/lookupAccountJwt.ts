/**
 * NATS Account JWT Lookup
 *
 * This endpoint is called by the NATS server's URL resolver to fetch account JWTs.
 * When a user connects with credentials, NATS needs to verify their account exists.
 *
 * GET /nats/jwt/v1/accounts/{account_public_key}
 *
 * Returns: Raw account JWT (text/plain) or 404 if not found
 *
 * Security:
 * - This endpoint is called by NATS servers only (no user auth required)
 * - The JWT itself is cryptographically signed by the operator
 * - Input validation ensures only valid nkey format is accepted
 * - Rate limiting prevents enumeration and DoS attacks
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand, UpdateItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { createHash, randomUUID } from 'crypto';

const ddb = new DynamoDBClient({});
const secretsClient = new SecretsManagerClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const NATS_OPERATOR_SECRET_ARN = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';

// SECURITY: Async audit logging to avoid blocking the request path
// We write audit logs for security-relevant events but don't await them
async function auditSecurityEvent(event: Record<string, unknown>): Promise<void> {
  try {
    await ddb.send(new PutItemCommand({
      TableName: TABLE_AUDIT,
      Item: marshall({
        id: `audit_${randomUUID()}`,
        timestamp: new Date().toISOString(),
        ...event,
      }),
    }));
  } catch (err) {
    // Log but don't fail the request
    console.error('Failed to write security audit:', err);
  }
}

// SECURITY: Rate limiting configuration
// Account public keys are 56 characters, base32 encoded
const NATS_ACCOUNT_PUBLIC_KEY_REGEX = /^A[A-Z0-9]{55}$/;

// SECURITY: In-memory rate limit cache (per Lambda instance)
// This provides basic protection; for production, consider DynamoDB-based rate limiting
interface RateLimitEntry {
  count: number;
  windowStart: number;
}
const rateLimitCache = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute window
const RATE_LIMIT_MAX_REQUESTS = 100; // Max requests per IP per window
const RATE_LIMIT_CLEANUP_INTERVAL = 5 * 60 * 1000; // Cleanup old entries every 5 minutes
let lastCleanup = Date.now();

/**
 * SECURITY: Check rate limit for source IP
 * Returns true if request should be allowed, false if rate limited
 */
function checkRateLimit(sourceIp: string): boolean {
  const now = Date.now();

  // Periodic cleanup of old entries to prevent memory leak
  if (now - lastCleanup > RATE_LIMIT_CLEANUP_INTERVAL) {
    const cutoff = now - RATE_LIMIT_WINDOW_MS;
    for (const [key, entry] of rateLimitCache.entries()) {
      if (entry.windowStart < cutoff) {
        rateLimitCache.delete(key);
      }
    }
    lastCleanup = now;
  }

  const entry = rateLimitCache.get(sourceIp);

  if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
    // New window
    rateLimitCache.set(sourceIp, { count: 1, windowStart: now });
    return true;
  }

  if (entry.count >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }

  entry.count++;
  return true;
}

/**
 * SECURITY: Validate NATS account public key format
 * NATS account public keys start with 'A' and are 56 chars of base32
 */
function isValidAccountPublicKey(key: string): boolean {
  return NATS_ACCOUNT_PUBLIC_KEY_REGEX.test(key);
}

// Cache for special accounts (system and backend) from Secrets Manager
interface SpecialAccount {
  publicKey: string;
  jwt: string;
}

interface SpecialAccountsCache {
  system: SpecialAccount | null;
  backend: SpecialAccount | null;
  timestamp: number;
}

let accountsCache: SpecialAccountsCache = { system: null, backend: null, timestamp: 0 };
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function getSpecialAccounts(): Promise<SpecialAccountsCache> {
  const now = Date.now();
  if (accountsCache.system && (now - accountsCache.timestamp) < CACHE_TTL_MS) {
    return accountsCache;
  }

  try {
    const response = await secretsClient.send(new GetSecretValueCommand({
      SecretId: NATS_OPERATOR_SECRET_ARN,
    }));

    if (!response.SecretString) {
      return accountsCache;
    }

    const secret = JSON.parse(response.SecretString);

    // Cache system account
    if (secret.system_account_public_key && secret.system_account_jwt) {
      accountsCache.system = {
        publicKey: secret.system_account_public_key,
        jwt: secret.system_account_jwt,
      };
    }

    // Cache backend account (for Lambda JetStream operations)
    if (secret.backend_account_public_key && secret.backend_account_jwt) {
      accountsCache.backend = {
        publicKey: secret.backend_account_public_key,
        jwt: secret.backend_account_jwt,
      };
    }

    accountsCache.timestamp = now;
  } catch (error) {
    console.error('Error fetching special accounts from Secrets Manager:', error);
  }

  return accountsCache;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // SECURITY: Rate limit by source IP
    const sourceIp = event.requestContext.http?.sourceIp || 'unknown';
    if (!checkRateLimit(sourceIp)) {
      console.warn(`SECURITY: Rate limit exceeded for IP ${sourceIp}`);
      // SECURITY: Audit rate limit violations (fire-and-forget to avoid blocking)
      auditSecurityEvent({
        event: 'nats_jwt_rate_limit_exceeded',
        source_ip: sourceIp,
        severity: 'warning',
      });
      return {
        statusCode: 429,
        headers: {
          'Content-Type': 'text/plain',
          'Retry-After': '60',
        },
        body: 'Too many requests',
      };
    }

    // Extract account public key from path
    // Path format: /nats/jwt/v1/accounts/{account_public_key}
    const accountPublicKey = event.pathParameters?.account_public_key;

    // Handle base URL request (NATS server validation on startup)
    // When no account key is provided, return 200 OK to indicate the resolver is operational
    if (!accountPublicKey) {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'text/plain' },
        body: 'ok',
      };
    }

    // SECURITY: Validate public key format before database lookup
    // This prevents invalid input from reaching the database
    if (!isValidAccountPublicKey(accountPublicKey)) {
      // Return 404 to avoid revealing validation logic
      // (attacker shouldn't know if key format was wrong vs not found)
      console.warn(`SECURITY: Invalid account key format from IP ${sourceIp}: ${accountPublicKey.substring(0, 10)}...`);
      // SECURITY: Audit invalid key format (potential enumeration attempt)
      auditSecurityEvent({
        event: 'nats_jwt_invalid_key_format',
        source_ip: sourceIp,
        key_prefix: accountPublicKey.substring(0, 8),
        severity: 'warning',
      });
      return {
        statusCode: 404,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Account not found',
      };
    }

    // Check if this is a request for special accounts (stored in Secrets Manager)
    const specialAccounts = await getSpecialAccounts();

    // Check system account
    if (specialAccounts.system && accountPublicKey === specialAccounts.system.publicKey) {
      console.log('Returning system account JWT');
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'text/plain',
          'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        },
        body: specialAccounts.system.jwt,
      };
    }

    // Check backend account (for Lambda JetStream operations)
    if (specialAccounts.backend && accountPublicKey === specialAccounts.backend.publicKey) {
      console.log('Returning backend account JWT');
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'text/plain',
          'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        },
        body: specialAccounts.backend.jwt,
      };
    }

    // Query by account public key using GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      IndexName: 'account-key-index',
      KeyConditionExpression: 'account_public_key = :pk',
      ExpressionAttributeValues: {
        ':pk': { S: accountPublicKey },
      },
      Limit: 1,
    }));

    if (!result.Items || result.Items.length === 0) {
      console.log(`Account not found: ${accountPublicKey.substring(0, 10)}...`);
      return {
        statusCode: 404,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Account not found',
      };
    }

    const account = unmarshall(result.Items[0]);

    // Check account status
    if (account.status !== 'active') {
      console.log(`Account ${accountPublicKey.substring(0, 10)}... is ${account.status}`);
      // SECURITY: Audit access to non-active accounts
      auditSecurityEvent({
        event: 'nats_jwt_account_not_active',
        source_ip: sourceIp,
        account_key_prefix: accountPublicKey.substring(0, 12),
        account_status: account.status,
        severity: 'info',
      });
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'text/plain' },
        body: 'Account is not active',
      };
    }

    // Return the raw JWT
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
      },
      body: account.account_jwt,
    };
  } catch (error: any) {
    console.error('Error looking up account JWT:', error);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'text/plain' },
      body: 'Internal server error',
    };
  }
};
