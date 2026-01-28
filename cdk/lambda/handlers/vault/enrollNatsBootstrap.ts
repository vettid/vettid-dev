/**
 * Enrollment NATS Bootstrap
 *
 * Provides NATS credentials during enrollment flow. This endpoint bridges the gap
 * between authentication (session_token validated) and NATS connection.
 *
 * POST /vault/enroll/nats-bootstrap
 *
 * Security controls:
 * - Requires valid enrollment_token (signed JWT with device binding)
 * - Verifies session is in AUTHENTICATED state
 * - Creates NATS account if needed (scoped to user's namespace)
 * - Issues short-lived credentials (24h for app)
 * - Rate limited per session_id
 * - Full audit logging
 *
 * This endpoint does NOT update session status - the app should call
 * /vault/enroll/status with phase=NATS_CONNECTED after successfully connecting.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import {
  ok,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  conflict,
  internalError,
  tooManyRequests,
  getRequestId,
  putAudit,
  nowIso,
  addMinutesIso,
  checkRateLimit,
  hashIdentifier,
} from '../../common/util';
import { verifyEnrollmentToken, extractTokenFromHeader } from '../../common/enrollment-jwt';
import { generateAccountCredentials, generateUserCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const kms = new KMSClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS || 'vettid-registrations';
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';
const NATS_SEED_KMS_KEY_ARN = process.env.NATS_SEED_KMS_KEY_ARN!;

// SECURITY: Require device attestation before NATS bootstrap
// Set to 'true' in production to enforce hardware-backed attestation
const REQUIRE_DEVICE_ATTESTATION = process.env.REQUIRE_DEVICE_ATTESTATION === 'true';

// Token validity for enrollment bootstrap (24 hours)
const ENROLLMENT_TOKEN_VALIDITY_MINUTES = 60 * 24;

// Rate limiting: 3 bootstrap attempts per session per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 15;

interface RegistrationProfile {
  first_name: string;
  last_name: string;
  email: string;
}

interface NatsBootstrapResponse {
  nats_endpoint: string;
  nats_jwt: string;
  nats_seed: string;
  nats_creds: string;
  owner_space: string;
  message_space: string;
  user_guid: string;
  token_id: string;
  expires_at: string;
  registration_profile?: RegistrationProfile;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // SECURITY: Validate enrollment JWT
    const authHeader = event.headers?.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      return unauthorized('Missing or invalid authorization header', origin);
    }

    const payload = await verifyEnrollmentToken(token);
    if (!payload) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_failed',
        reason: 'invalid_token',
      }, requestId);
      return unauthorized('Invalid or expired enrollment token', origin);
    }

    const sessionId = payload.session_id;
    const userGuid = payload.sub;
    const deviceId = payload.device_id;
    const deviceType = payload.device_type;

    // SECURITY: Rate limiting per session (prevents credential stuffing)
    const sessionHash = hashIdentifier(sessionId);
    const isAllowed = await checkRateLimit(sessionHash, 'nats_bootstrap', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_rate_limited',
        session_id: sessionId,
        user_guid: userGuid,
      }, requestId);
      return tooManyRequests('Too many bootstrap attempts. Please try again later.', origin);
    }

    // SECURITY: Verify session exists and is in AUTHENTICATED state
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
    }));

    if (!sessionResult.Item) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_failed',
        reason: 'session_not_found',
        session_id: sessionId,
      }, requestId);
      return notFound('Enrollment session not found', origin);
    }

    const session = unmarshall(sessionResult.Item);

    // Verify session belongs to this user
    if (session.user_guid !== userGuid) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_failed',
        reason: 'session_user_mismatch',
        session_id: sessionId,
        token_user: userGuid,
        session_user: session.user_guid,
      }, requestId);
      return forbidden('Session does not belong to this user', origin);
    }

    // SECURITY: Only allow NATS bootstrap when session is in correct state
    // This prevents replay attacks and ensures proper flow
    const allowedStates = ['AUTHENTICATED', 'DEVICE_ATTESTED', 'NATS_CONNECTED'];
    if (!allowedStates.includes(session.status)) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_failed',
        reason: 'invalid_session_state',
        session_id: sessionId,
        status: session.status,
      }, requestId);

      if (session.status === 'WEB_INITIATED' || session.status === 'PENDING') {
        return conflict('Session not yet authenticated. Complete authentication first.', origin);
      }
      if (session.status === 'COMPLETED') {
        return conflict('Enrollment already completed', origin);
      }
      return conflict(`Invalid session state for NATS bootstrap: ${session.status}`, origin);
    }

    // SECURITY: If device attestation is required, verify it was completed
    if (REQUIRE_DEVICE_ATTESTATION) {
      if (!session.device_attestation_verified) {
        await putAudit({
          type: 'enrollment_nats_bootstrap_failed',
          reason: 'device_attestation_required',
          session_id: sessionId,
          user_guid: userGuid,
        }, requestId);
        return conflict('Device attestation required before NATS bootstrap. Call /vault/enroll/device-attestation first.', origin);
      }
    }

    // Check session expiry
    const expiresAt = typeof session.expires_at === 'number'
      ? session.expires_at
      : new Date(session.expires_at).getTime();

    if (expiresAt < Date.now()) {
      await putAudit({
        type: 'enrollment_nats_bootstrap_failed',
        reason: 'session_expired',
        session_id: sessionId,
      }, requestId);
      return badRequest('Enrollment session has expired', origin);
    }

    // Check if NATS account exists, create if not
    let accountRecord = await getOrCreateNatsAccount(userGuid, requestId);

    // Generate user credentials for the app
    const now = nowIso();
    const credExpiresAt = addMinutesIso(ENROLLMENT_TOKEN_VALIDITY_MINUTES);
    const tokenId = `nats_enroll_${randomUUID()}`;

    // Decrypt account seed
    const accountSeed = await decryptAccountSeed(accountRecord, userGuid);

    // Define app permissions
    const ownerSpace = accountRecord.owner_space_id;
    const messageSpace = accountRecord.message_space_id;

    const publishPerms = [
      `${ownerSpace}.forVault.>`,
    ];
    const subscribePerms = [
      `${ownerSpace}.forApp.>`,
      `${ownerSpace}.eventTypes`,
    ];

    // Generate NATS user credentials
    const credentials = await generateUserCredentials(
      userGuid,
      accountSeed,
      'app',
      ownerSpace,
      messageSpace,
      new Date(credExpiresAt)
    );

    // Store token record
    await ddb.send(new PutItemCommand({
      TableName: TABLE_NATS_TOKENS,
      Item: marshall({
        token_id: tokenId,
        user_guid: userGuid,
        client_type: 'app',
        device_id: deviceId,
        user_public_key: credentials.publicKey,
        issued_at: now,
        expires_at: credExpiresAt,
        status: 'active',
        enrollment_session_id: sessionId,
      }),
    }));

    // Audit log success
    await putAudit({
      type: 'enrollment_nats_bootstrap_success',
      user_guid: userGuid,
      session_id: sessionId,
      token_id: tokenId,
      device_type: deviceType,
      owner_space: ownerSpace,
    }, requestId);

    // Fetch registration profile for the user (using GSI on user_guid)
    let registrationProfile: RegistrationProfile | undefined;
    try {
      const registrationResult = await ddb.send(new QueryCommand({
        TableName: TABLE_REGISTRATIONS,
        IndexName: 'user-guid-index',
        KeyConditionExpression: 'user_guid = :guid',
        ExpressionAttributeValues: marshall({ ':guid': userGuid }),
        ProjectionExpression: 'first_name, last_name, email',
        Limit: 1,
      }));

      if (registrationResult.Items && registrationResult.Items.length > 0) {
        const reg = unmarshall(registrationResult.Items[0]);
        if (reg.first_name && reg.last_name && reg.email) {
          registrationProfile = {
            first_name: reg.first_name,
            last_name: reg.last_name,
            email: reg.email,
          };
          console.log('Found registration profile:', { firstName: reg.first_name, lastName: reg.last_name, email: reg.email });
        }
      } else {
        console.warn('No registration found for user_guid:', userGuid);
      }
    } catch (error) {
      // Log but don't fail - profile is optional
      console.warn('Failed to fetch registration profile:', error);
    }

    const response: NatsBootstrapResponse = {
      nats_endpoint: `tls://${NATS_DOMAIN}:443`,
      nats_jwt: credentials.jwt,
      nats_seed: credentials.seed,
      nats_creds: formatCredsFile(credentials.jwt, credentials.seed),
      owner_space: ownerSpace,
      message_space: messageSpace,
      user_guid: userGuid,
      token_id: tokenId,
      expires_at: credExpiresAt,
      registration_profile: registrationProfile,
    };

    return ok(response, origin);

  } catch (error: any) {
    console.error('Enrollment NATS bootstrap error:', error);
    return internalError('Failed to generate NATS credentials', origin);
  }
};

// Enrollment TTL: 1 hour for incomplete enrollments to be cleaned up
const ENROLLMENT_TTL_SECONDS = 60 * 60;

/**
 * Get existing NATS account or create new one for enrollment.
 *
 * SECURITY: New accounts are created with status='enrolling' (not 'active').
 * This prevents:
 * - Account page showing "enrolled" before enrollment completes
 * - Vault operations being allowed before enrollment completes
 * - Leaked enrollment credentials being usable for real operations
 *
 * The account transitions to 'active' only in enrollFinalize after
 * the full enrollment flow completes successfully.
 *
 * Accounts stuck in 'enrolling' status have a TTL and will be automatically
 * deleted after 1 hour.
 */
async function getOrCreateNatsAccount(userGuid: string, requestId: string): Promise<any> {
  // Check if account exists
  const existingAccount = await ddb.send(new GetItemCommand({
    TableName: TABLE_NATS_ACCOUNTS,
    Key: marshall({ user_guid: userGuid }),
  }));

  if (existingAccount.Item) {
    const account = unmarshall(existingAccount.Item);

    // If account is active, user is already enrolled
    if (account.status === 'active') {
      return account;
    }

    // If account is in 'enrolling' status, allow re-enrollment
    // This handles the case where a previous enrollment attempt failed
    if (account.status === 'enrolling') {
      console.log(`Re-using existing enrolling account for user ${userGuid}`);
      return account;
    }

    // Any other status is an error
    throw new Error(`NATS account exists with unexpected status: ${account.status}`);
  }

  // Create new account with 'enrolling' status
  const ownerSpaceId = `OwnerSpace.${userGuid}`;
  const messageSpaceId = `MessageSpace.${userGuid}`;

  const accountCredentials = await generateAccountCredentials(userGuid);

  // Encrypt seed with KMS
  const encryptResult = await kms.send(new EncryptCommand({
    KeyId: NATS_SEED_KMS_KEY_ARN,
    Plaintext: Buffer.from(accountCredentials.seed, 'utf-8'),
    EncryptionContext: {
      user_guid: userGuid,
      purpose: 'nats_account_seed',
    },
  }));

  if (!encryptResult.CiphertextBlob) {
    throw new Error('KMS encryption failed');
  }

  const encryptedSeedBase64 = Buffer.from(encryptResult.CiphertextBlob).toString('base64');
  const now = nowIso();

  // TTL for automatic cleanup of incomplete enrollments (1 hour from now)
  const enrollmentTtl = Math.floor(Date.now() / 1000) + ENROLLMENT_TTL_SECONDS;

  const accountRecord = {
    user_guid: userGuid,
    owner_space_id: ownerSpaceId,
    message_space_id: messageSpaceId,
    account_public_key: accountCredentials.publicKey,
    account_seed_encrypted: encryptedSeedBase64,
    account_jwt: accountCredentials.accountJwt,
    status: 'enrolling',  // SECURITY: Not 'active' until enrollment completes
    enrollment_ttl: enrollmentTtl,  // Auto-delete if enrollment doesn't complete
    created_at: now,
    updated_at: now,
  };

  await ddb.send(new PutItemCommand({
    TableName: TABLE_NATS_ACCOUNTS,
    Item: marshall(accountRecord),
    ConditionExpression: 'attribute_not_exists(user_guid)',
  }));

  await putAudit({
    type: 'nats_account_created_for_enrollment',
    user_guid: userGuid,
    owner_space_id: ownerSpaceId,
    message_space_id: messageSpaceId,
    status: 'enrolling',
  }, requestId);

  return accountRecord;
}

/**
 * Decrypt account seed from KMS
 *
 * SECURITY: Only KMS-encrypted seeds are supported. Legacy unencrypted seeds
 * (starting with 'SA') are no longer accepted - users must re-enroll.
 */
async function decryptAccountSeed(account: any, userGuid: string): Promise<string> {
  const encryptedSeed = account.account_seed_encrypted;

  if (!encryptedSeed) {
    // Legacy unencrypted seeds are no longer supported
    if (account.account_seed?.startsWith('SA')) {
      throw new Error('Legacy unencrypted NATS seed detected. User must re-enroll.');
    }
    throw new Error('NATS account missing encrypted signing key');
  }

  // Decrypt with KMS
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
