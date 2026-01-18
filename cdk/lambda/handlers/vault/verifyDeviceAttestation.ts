/**
 * Device Attestation Verification Handler
 *
 * POST /vault/enroll/device-attestation
 *
 * SECURITY: Verifies hardware-backed device attestation before allowing
 * NATS bootstrap. This prevents:
 * - Enrollment token exfiltration to different devices
 * - Enrollment on rooted/jailbroken devices
 * - Emulator/simulator-based attacks
 *
 * Flow:
 * 1. App generates device attestation (Play Integrity / App Attest)
 * 2. App calls this endpoint with attestation + enrollment token
 * 3. Backend verifies attestation and stores binding in session
 * 4. App can now call NATS bootstrap (which checks attestation binding)
 *
 * Supported platforms:
 * - Android: Play Integrity API token
 * - iOS: App Attest attestation object
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  internalError,
  tooManyRequests,
  getRequestId,
  putAudit,
  checkRateLimit,
  hashIdentifier,
  ValidationError,
} from '../../common/util';
import { verifyEnrollmentToken, extractTokenFromHeader } from '../../common/enrollment-jwt';
import {
  verifyAndroidHardwareAttestation,
  verifyiOSAppAttest,
  generateDeviceAttestationToken,
  DeviceAttestationResult,
} from '../../common/device-attestation';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const DEVICE_ATTESTATION_SECRET = process.env.DEVICE_ATTESTATION_SECRET || 'dev-attestation-secret';

// Rate limiting: 5 attestation attempts per session per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 15;

interface AndroidAttestationRequest {
  device_type: 'android';
  certificate_chain: string[];  // Base64-encoded DER certificates from Android Keystore
  challenge: string;            // Challenge/nonce used when generating the key
}

interface iOSAttestationRequest {
  device_type: 'ios';
  attestation: string;      // Base64-encoded attestation object
  key_id: string;           // Key identifier from generateKey()
  challenge: string;        // Challenge used for attestation
}

type DeviceAttestationRequest = AndroidAttestationRequest | iOSAttestationRequest;

interface DeviceAttestationResponse {
  verified: boolean;
  device_type: 'android' | 'ios';
  attestation_token?: string;  // Token for binding verification in NATS bootstrap
  device_integrity?: {
    meets_basic_integrity?: boolean;
    meets_device_integrity?: boolean;
    meets_strong_integrity?: boolean;
  };
  error?: string;
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
        type: 'device_attestation_failed',
        reason: 'invalid_enrollment_token',
      }, requestId);
      return unauthorized('Invalid or expired enrollment token', origin);
    }

    const sessionId = payload.session_id;
    const userGuid = payload.sub;
    const tokenDeviceType = payload.device_type;

    // SECURITY: Rate limiting per session
    const sessionHash = hashIdentifier(sessionId);
    const isAllowed = await checkRateLimit(sessionHash, 'device_attestation', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      await putAudit({
        type: 'device_attestation_rate_limited',
        session_id: sessionId,
        user_guid: userGuid,
      }, requestId);
      return tooManyRequests('Too many attestation attempts. Please try again later.', origin);
    }

    // Parse request body
    let body: DeviceAttestationRequest;
    try {
      body = JSON.parse(event.body || '{}');
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Validate device_type matches enrollment token
    if (body.device_type !== tokenDeviceType) {
      await putAudit({
        type: 'device_attestation_failed',
        reason: 'device_type_mismatch',
        session_id: sessionId,
        expected: tokenDeviceType,
        received: body.device_type,
      }, requestId);
      return badRequest(`Device type mismatch: expected ${tokenDeviceType}, got ${body.device_type}`, origin);
    }

    // Verify session exists and is in correct state
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
    }));

    if (!sessionResult.Item) {
      await putAudit({
        type: 'device_attestation_failed',
        reason: 'session_not_found',
        session_id: sessionId,
      }, requestId);
      return notFound('Enrollment session not found', origin);
    }

    const session = unmarshall(sessionResult.Item);

    // Verify session belongs to this user
    if (session.user_guid !== userGuid) {
      await putAudit({
        type: 'device_attestation_failed',
        reason: 'session_user_mismatch',
        session_id: sessionId,
      }, requestId);
      return forbidden('Session does not belong to this user', origin);
    }

    // SECURITY: Only allow attestation when session is in AUTHENTICATED state
    const allowedStates = ['AUTHENTICATED', 'DEVICE_ATTESTED'];
    if (!allowedStates.includes(session.status)) {
      await putAudit({
        type: 'device_attestation_failed',
        reason: 'invalid_session_state',
        session_id: sessionId,
        status: session.status,
      }, requestId);
      return badRequest(`Invalid session state for device attestation: ${session.status}`, origin);
    }

    // Verify device attestation based on platform
    let attestationResult: DeviceAttestationResult;

    if (body.device_type === 'android') {
      const androidRequest = body as AndroidAttestationRequest;

      if (!androidRequest.certificate_chain || androidRequest.certificate_chain.length === 0) {
        return badRequest('Android attestation requires certificate_chain (Base64-encoded DER certs from Keystore)', origin);
      }
      if (!androidRequest.challenge) {
        return badRequest('Android attestation requires challenge', origin);
      }

      attestationResult = await verifyAndroidHardwareAttestation(
        androidRequest.certificate_chain,
        androidRequest.challenge
      );

    } else if (body.device_type === 'ios') {
      const iosRequest = body as iOSAttestationRequest;

      if (!iosRequest.attestation || !iosRequest.key_id || !iosRequest.challenge) {
        return badRequest('iOS attestation requires attestation, key_id, and challenge', origin);
      }

      attestationResult = await verifyiOSAppAttest(
        iosRequest.attestation,
        iosRequest.key_id,
        iosRequest.challenge
      );

    } else {
      return badRequest('Invalid device_type: must be android or ios', origin);
    }

    // Handle verification failure
    if (!attestationResult.valid) {
      await putAudit({
        type: 'device_attestation_failed',
        reason: 'verification_failed',
        session_id: sessionId,
        user_guid: userGuid,
        device_type: body.device_type,
        error: attestationResult.error,
      }, requestId);

      const response: DeviceAttestationResponse = {
        verified: false,
        device_type: body.device_type,
        error: attestationResult.error,
      };

      return ok(response, origin);
    }

    // Generate attestation binding token
    const attestationToken = generateDeviceAttestationToken(
      sessionId,
      attestationResult.attestation_hash!,
      DEVICE_ATTESTATION_SECRET
    );

    // Update session with attestation binding
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
      UpdateExpression: `
        SET #status = :status,
            device_attestation_verified = :verified,
            device_attestation_time = :time,
            device_attestation_hash = :hash,
            device_attestation_type = :type
      `,
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'DEVICE_ATTESTED',
        ':verified': true,
        ':time': new Date().toISOString(),
        ':hash': attestationResult.attestation_hash,
        ':type': body.device_type,
      }),
    }));

    // Audit log success
    await putAudit({
      type: 'device_attestation_verified',
      user_guid: userGuid,
      session_id: sessionId,
      device_type: body.device_type,
      device_integrity: attestationResult.device_integrity,
    }, requestId);

    const response: DeviceAttestationResponse = {
      verified: true,
      device_type: body.device_type,
      attestation_token: attestationToken,
      device_integrity: attestationResult.device_integrity,
    };

    return ok(response, origin);

  } catch (error: any) {
    console.error('Device attestation error:', error);
    return internalError('Failed to verify device attestation', origin);
  }
};
