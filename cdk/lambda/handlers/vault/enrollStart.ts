import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand, BatchWriteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
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
  getClientIp,
} from '../../common/util';
import { generateX25519KeyPair } from '../../common/crypto-keys';
import { generateAttestationChallenge } from '../../common/attestation';
import { generateEnrollmentToken } from '../../common/enrollment-jwt';
import { requestEnclaveAttestation } from '../../common/enclave-client';
import { generateAttestationNonce, getCurrentPCRs } from '../../common/nitro-attestation';

const ddb = new DynamoDBClient({});

// Table names from environment
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

// Number of transaction keys to generate per enrollment
const INITIAL_TRANSACTION_KEY_COUNT = 20;

// Feature flag: require device attestation (Android Play Integrity / iOS App Attest)
// Set to 'false' to skip attestation verification (faster enrollment, less security)
const REQUIRE_ATTESTATION = process.env.REQUIRE_ATTESTATION !== 'false';

// Rate limiting: 10 enrollment attempts per IP per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 10;
const RATE_LIMIT_WINDOW_MINUTES = 15;

/**
 * Clean up old transaction keys for a user before starting new enrollment.
 * This prevents accumulation of keys from failed/abandoned enrollment attempts.
 */
async function cleanupOldTransactionKeys(userGuid: string): Promise<number> {
  let deletedCount = 0;
  let lastEvaluatedKey: any = undefined;

  do {
    // Query all transaction keys for this user using GSI
    const queryResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
      }),
      ExclusiveStartKey: lastEvaluatedKey,
    }));

    if (queryResult.Items && queryResult.Items.length > 0) {
      // Delete in batches of 25 (DynamoDB BatchWriteItem limit)
      const items = queryResult.Items.map(item => unmarshall(item));

      for (let i = 0; i < items.length; i += 25) {
        const batch = items.slice(i, i + 25);
        const deleteRequests = batch.map(item => ({
          DeleteRequest: {
            Key: marshall({ transaction_id: item.transaction_id }),
          },
        }));

        await ddb.send(new BatchWriteItemCommand({
          RequestItems: {
            [TABLE_TRANSACTION_KEYS]: deleteRequests,
          },
        }));

        deletedCount += batch.length;
      }
    }

    lastEvaluatedKey = queryResult.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return deletedCount;
}

interface EnrollStartRequest {
  // For invitation code flow (legacy)
  invitation_code?: string;
  device_id?: string;
  device_type?: 'android' | 'ios';
  skip_attestation?: boolean;
}

/**
 * POST /vault/enroll/start
 *
 * Start enrollment process. Supports two flows:
 *
 * 1. QR Code Flow (web-initiated):
 *    - User scans QR code with mobile app
 *    - Mobile calls /vault/enroll/authenticate with session_token
 *    - Mobile receives enrollment JWT and calls this endpoint
 *    - user_guid, session_id, device_id, device_type come from JWT (authorizer context)
 *
 * 2. Invitation Code Flow (direct):
 *    - User receives invitation code
 *    - Mobile calls this endpoint with invitation_code in body
 *    - New user_guid and session_id are generated
 *
 * Returns:
 * - enrollment_session_id
 * - user_guid
 * - attestation_challenge (for device attestation, if required)
 * - transaction_keys (UTKs - public keys only)
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Rate limiting by IP address
    const clientIp = getClientIp(event);
    const ipHash = hashIdentifier(clientIp);
    const isAllowed = await checkRateLimit(ipHash, 'enroll_start', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      return tooManyRequests('Too many enrollment attempts. Please try again later.', origin);
    }

    // Check for authorizer context (QR code flow)
    // The authorizer property exists but isn't in the base type definition
    const authContext = (event.requestContext as any)?.authorizer?.lambda as {
      userGuid?: string;
      sessionId?: string;
      deviceId?: string;
      deviceType?: string;
    } | undefined;

    // Parse request body
    const body = parseJsonBody<EnrollStartRequest>(event);

    let userGuid: string;
    let sessionId: string;
    let deviceId: string;
    let deviceType: 'android' | 'ios';
    let invitationCode: string | undefined;

    if (authContext?.userGuid && authContext?.sessionId) {
      // QR Code Flow: Use values from authorizer context
      userGuid = authContext.userGuid;
      sessionId = authContext.sessionId;
      deviceId = authContext.deviceId || body.device_id || '';
      deviceType = (authContext.deviceType || body.device_type) as 'android' | 'ios';

      if (!deviceType || !['android', 'ios'].includes(deviceType)) {
        return badRequest('device_type must be android or ios', origin);
      }

      // Verify the session exists and is in correct state
      const sessionResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        Key: marshall({ session_id: sessionId }),
      }));

      if (!sessionResult.Item) {
        return notFound('Enrollment session not found', origin);
      }

      const session = unmarshall(sessionResult.Item);

      if (session.status !== 'AUTHENTICATED' && session.status !== 'WEB_INITIATED') {
        return conflict('Enrollment session is not in valid state', origin);
      }

      // Check expiration
      const now = Date.now();
      const expiresAt = typeof session.expires_at === 'number'
        ? session.expires_at
        : new Date(session.expires_at).getTime();

      if (expiresAt < now) {
        return badRequest('Enrollment session has expired', origin);
      }

    } else if (body.invitation_code) {
      // Invitation Code Flow: Validate invitation and generate new IDs
      if (!body.device_id) {
        return badRequest('device_id is required', origin);
      }
      if (!body.device_type || !['android', 'ios'].includes(body.device_type)) {
        return badRequest('device_type must be android or ios', origin);
      }

      deviceId = body.device_id;
      deviceType = body.device_type;
      invitationCode = body.invitation_code;

      // Validate invitation code
      const inviteResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_INVITES,
        Key: marshall({ code: invitationCode }),
      }));

      if (!inviteResult.Item) {
        return notFound('Invalid invitation code', origin);
      }

      const invite = unmarshall(inviteResult.Item);

      if (invite.status === 'used') {
        return conflict('This invitation code has already been used', origin);
      }

      if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
        return badRequest('This invitation code has expired', origin);
      }

      // Use user_guid from invitation if present (for vault reuse), otherwise generate new
      // This enables test scenarios where user_guid is reused for existing vaults
      userGuid = invite.user_guid || generateSecureId('user', 32);
      sessionId = generateSecureId('enroll', 32);

    } else {
      return badRequest('Either enrollment JWT (via Authorization header) or invitation_code is required', origin);
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes

    // Determine if attestation is required
    const skipAttestation = !REQUIRE_ATTESTATION || body.skip_attestation === true;

    // Generate attestation challenge (even if skipping, for optional future use)
    const attestationChallenge = skipAttestation ? null : generateAttestationChallenge(deviceType);

    // Clean up any old transaction keys from previous enrollment attempts
    const deletedKeysCount = await cleanupOldTransactionKeys(userGuid);
    if (deletedKeysCount > 0) {
      console.log(`Cleaned up ${deletedKeysCount} old transaction keys for user ${userGuid}`);
    }

    // Generate transaction keys (LTK/UTK pairs)
    const transactionKeys: Array<{
      key_id: string;
      public_key: string;
      algorithm: string;
    }> = [];

    for (let i = 0; i < INITIAL_TRANSACTION_KEY_COUNT; i++) {
      const keyPair = generateX25519KeyPair();
      const keyId = generateSecureId('tk', 16);

      const publicKeyB64 = keyPair.publicKey.toString('base64');
      const privateKeyB64 = keyPair.privateKey.toString('base64');

      // Store the full key pair
      // Note: table uses transaction_id as PK, but we also store key_id for API compatibility
      await ddb.send(new PutItemCommand({
        TableName: TABLE_TRANSACTION_KEYS,
        Item: marshall({
          transaction_id: keyId,  // Primary key
          user_guid: userGuid,
          key_id: keyId,  // Kept for API response compatibility
          public_key: publicKeyB64,
          private_key: privateKeyB64,
          algorithm: 'X25519',
          status: 'UNUSED',
          key_index: i,
          created_at: Date.now(),  // GSI sort key expects number
        }),
      }));

      transactionKeys.push({
        key_id: keyId,
        public_key: publicKeyB64,
        algorithm: 'X25519',
      });
    }

    const passwordKeyId = transactionKeys[0].key_id;
    const nextStep = skipAttestation ? 'set_password' : 'attestation_required';

    // ============================================
    // REQUEST NITRO ENCLAVE ATTESTATION
    // ============================================
    // The enclave provides a hardware-attested document proving it's running
    // genuine VettID code. Mobile will verify PCRs before encrypting auth data.

    // Generate nonce for attestation freshness
    const nonce = generateAttestationNonce();

    // Request attestation from enclave via NATS
    const attestationResponse = await requestEnclaveAttestation(nonce);

    // Get current expected PCR values for mobile to verify
    const expectedPCRs = await getCurrentPCRs();

    const enclaveAttestation = {
      attestation_document: attestationResponse.attestation,
      enclave_public_key: attestationResponse.public_key,
      nonce: nonce.toString('base64'),
      expected_pcrs: expectedPCRs.map(p => ({
        pcr0: p.pcr0,
        pcr1: p.pcr1,
        pcr2: p.pcr2,
      })),
    };

    console.log(`Obtained enclave attestation for enrollment ${sessionId}`);

    // Update or create enrollment session
    const sessionItem: Record<string, any> = {
      session_id: sessionId,
      user_guid: userGuid,
      device_id: deviceId,
      device_type: deviceType,
      attestation_skipped: skipAttestation,
      status: 'STARTED',
      step: nextStep,
      password_key_id: passwordKeyId,
      started_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      expires_at_ttl: Math.floor(expiresAt.getTime() / 1000),
    };

    if (invitationCode) {
      sessionItem.invitation_code = invitationCode;
      sessionItem.created_at = now.getTime();  // GSI sort key expects number (Unix timestamp in ms)
    }

    if (attestationChallenge) {
      sessionItem.attestation_challenge = attestationChallenge.challenge;
      sessionItem.attestation_challenge_expires = attestationChallenge.expiresAt;
    }

    // Store enclave attestation data in session (always required)
    sessionItem.enclave_nonce = enclaveAttestation.nonce;
    sessionItem.enclave_public_key = enclaveAttestation.enclave_public_key;
    sessionItem.use_enclave = true;

    // For QR code flow, update existing session; for invitation flow, create new
    if (authContext?.sessionId) {
      // Update existing session
      let updateExpression = 'SET #status = :status, step = :step, password_key_id = :pwkey, started_at = :started, attestation_skipped = :skip, enclave_nonce = :enc_nonce, enclave_public_key = :enc_pubkey, use_enclave = :use_enc';
      if (attestationChallenge) {
        updateExpression += ', attestation_challenge = :challenge, attestation_challenge_expires = :challenge_exp';
      }

      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        Key: marshall({ session_id: sessionId }),
        UpdateExpression: updateExpression,
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':status': 'STARTED',
          ':step': nextStep,
          ':pwkey': passwordKeyId,
          ':started': now.toISOString(),
          ':skip': skipAttestation,
          ':enc_nonce': enclaveAttestation.nonce,
          ':enc_pubkey': enclaveAttestation.enclave_public_key,
          ':use_enc': true,
          ...(attestationChallenge ? {
            ':challenge': attestationChallenge.challenge,
            ':challenge_exp': attestationChallenge.expiresAt,
          } : {}),
        }),
      }));
    } else {
      // Create new session for invitation code flow
      await ddb.send(new PutItemCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        Item: marshall(sessionItem),
      }));

      // Mark invitation as pending
      if (invitationCode) {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_INVITES,
          Key: marshall({ code: invitationCode }),
          UpdateExpression: 'SET #status = :status, enrollment_session_id = :session_id, enrollment_started_at = :started_at',
          ExpressionAttributeNames: {
            '#status': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':status': 'pending',
            ':session_id': sessionId,
            ':started_at': now.toISOString(),
          }),
        }));
      }
    }

    // Audit log
    await putAudit({
      type: 'enrollment_started',
      user_guid: userGuid,
      session_id: sessionId,
      flow: authContext?.sessionId ? 'qr_code' : 'invitation_code',
      device_id: deviceId.substring(0, 8) + '...',
    }, requestId);

    // Build response
    const response: Record<string, any> = {
      enrollment_session_id: sessionId,
      user_guid: userGuid,
      transaction_keys: transactionKeys,
      password_key_id: passwordKeyId,  // The key_id to use for password encryption
      next_step: nextStep,
      attestation_required: !skipAttestation,
    };

    // For invitation_code flow (direct enrollment), generate a JWT
    // This allows subsequent steps (set-password, finalize) to work with the enrollmentAuthorizer
    if (!authContext?.sessionId && invitationCode) {
      const enrollmentToken = await generateEnrollmentToken(
        userGuid,
        sessionId,
        {
          deviceId,
          deviceType,
          expiresInSeconds: 600, // 10 minutes
        }
      );
      response.enrollment_token = enrollmentToken;
    }

    if (attestationChallenge) {
      response.attestation_challenge = attestationChallenge.challenge;
      response.attestation_endpoint = deviceType === 'android'
        ? '/vault/enroll/attestation/android'
        : '/vault/enroll/attestation/ios';
    }

    // Include enclave attestation (always required)
    // Mobile must verify the attestation document and PCR values before
    // encrypting auth data to the enclave's public key
    response.enclave_attestation = {
      attestation_document: enclaveAttestation.attestation_document,
      enclave_public_key: enclaveAttestation.enclave_public_key,
      nonce: enclaveAttestation.nonce,
      expected_pcrs: enclaveAttestation.expected_pcrs,
    };

    return ok(response, origin);

  } catch (error: any) {
    console.error('Enrollment start error:', error);
    return internalError('Failed to start enrollment', origin);
  }
};
