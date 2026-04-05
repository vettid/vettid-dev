/**
 * NATS Credential Reissue
 *
 * Reissues NATS credentials for enrolled users whose credentials have expired.
 * This is a public endpoint (no Cognito auth) since the user's NATS connection
 * is down and they can't authenticate via NATS.
 *
 * POST /vault/nats/reissue
 *
 * Security model:
 * - Requires user_guid of an enrolled user (account status = 'active')
 * - Credentials are scoped to the user's OwnerSpace (can only talk to their own vault)
 * - Vault still requires PIN verification before granting access
 * - Rate limited: 3 requests per user per 15 minutes
 * - Full audit logging
 *
 * This endpoint is called by the mobile app when stored NATS credentials have
 * expired (user offline > 7 days). It replaces the need to re-enroll.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import {
  ok,
  badRequest,
  unauthorized,
  notFound,
  internalError,
  tooManyRequests,
  getRequestId,
  putAudit,
  nowIso,
  addMinutesIso,
  checkRateLimit,
  hashIdentifier,
} from '../../common/util';
import { generateUserCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const kms = new KMSClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';
const NATS_SEED_KMS_KEY_ARN = process.env.NATS_SEED_KMS_KEY_ARN!;

// Credential validity: 7 days
const CREDENTIAL_VALIDITY_MINUTES = 60 * 24 * 7;

// Rate limiting: 3 reissues per user per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 15;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Parse request body
    if (!event.body) {
      return badRequest('Request body required', origin);
    }

    let body: { user_guid?: string };
    try {
      body = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    const userGuid = body.user_guid;
    if (!userGuid || typeof userGuid !== 'string' || userGuid.length < 10) {
      return badRequest('Valid user_guid required', origin);
    }

    // Rate limiting by user_guid
    const userHash = hashIdentifier(userGuid);
    const isAllowed = await checkRateLimit(userHash, 'nats_reissue', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      await putAudit({
        type: 'nats_credential_reissue_rate_limited',
        user_guid: userGuid,
      }, requestId);
      return tooManyRequests('Too many credential reissue requests. Try again later.', origin);
    }

    // Look up NATS account — must be 'active' (enrollment completed)
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!accountResult.Item) {
      await putAudit({
        type: 'nats_credential_reissue_failed',
        reason: 'account_not_found',
        user_guid: userGuid,
      }, requestId);
      return notFound('No NATS account found for this user', origin);
    }

    const account = unmarshall(accountResult.Item);

    if (account.status !== 'active') {
      await putAudit({
        type: 'nats_credential_reissue_failed',
        reason: 'account_not_active',
        user_guid: userGuid,
        account_status: account.status,
      }, requestId);
      return unauthorized('Account is not active. Please re-enroll.', origin);
    }

    // Decrypt account seed with KMS
    const accountSeed = await decryptAccountSeed(account, userGuid);

    // Generate fresh credentials (7-day TTL)
    const now = nowIso();
    const credExpiresAt = addMinutesIso(CREDENTIAL_VALIDITY_MINUTES);
    const tokenId = `nats_reissue_${randomUUID()}`;
    const ownerSpace = account.owner_space_id;
    const messageSpace = account.message_space_id;

    const credentials = await generateUserCredentials(
      userGuid,
      accountSeed,
      'app',
      ownerSpace,
      messageSpace,
      new Date(credExpiresAt)
    );

    // Store token record for audit trail
    await ddb.send(new PutItemCommand({
      TableName: TABLE_NATS_TOKENS,
      Item: marshall({
        token_id: tokenId,
        user_guid: userGuid,
        client_type: 'app',
        device_id: 'reissue',
        user_public_key: credentials.publicKey,
        issued_at: now,
        expires_at: credExpiresAt,
        status: 'active',
        source: 'credential_reissue',
      }),
    }));

    // Audit log
    await putAudit({
      type: 'nats_credential_reissue_success',
      user_guid: userGuid,
      token_id: tokenId,
      owner_space: ownerSpace,
    }, requestId);

    const ttlSeconds = Math.floor(CREDENTIAL_VALIDITY_MINUTES * 60);

    return ok({
      nats_endpoint: `tls://${NATS_DOMAIN}:443`,
      nats_creds: formatCredsFile(credentials.jwt, credentials.seed),
      owner_space: ownerSpace,
      message_space: messageSpace,
      expires_at: credExpiresAt,
      ttl_seconds: ttlSeconds,
      token_id: tokenId,
    }, origin);

  } catch (error: any) {
    console.error('NATS credential reissue error:', error);
    return internalError('Failed to reissue NATS credentials', origin);
  }
};

/**
 * Decrypt account seed from KMS
 */
async function decryptAccountSeed(account: any, userGuid: string): Promise<string> {
  const encryptedSeed = account.account_seed_encrypted;

  if (!encryptedSeed) {
    throw new Error('NATS account missing encrypted signing key');
  }

  const decryptResult = await kms.send(new DecryptCommand({
    KeyId: NATS_SEED_KMS_KEY_ARN,
    CiphertextBlob: Buffer.from(encryptedSeed, 'base64'),
    EncryptionContext: {
      user_guid: userGuid,
      purpose: 'nats_account_seed',
    },
  }));

  if (!decryptResult.Plaintext) {
    throw new Error('KMS decryption failed');
  }

  return Buffer.from(decryptResult.Plaintext).toString('utf-8');
}
