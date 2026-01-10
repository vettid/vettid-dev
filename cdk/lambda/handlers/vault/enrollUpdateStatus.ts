import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
} from '../../common/util';
import { verifyEnrollmentToken, extractTokenFromHeader } from '../../common/enrollment-jwt';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

/**
 * Valid enrollment phases in order.
 * The app reports these as it progresses through NATS-based enrollment.
 *
 * IMPORTANT: Sensitive operations (attestation verification, PIN setup, password setup)
 * happen directly between app and enclave via NATS. Lambda NEVER sees the actual
 * PIN or password - only receives status updates for tracking purposes.
 */
const ENROLLMENT_PHASES = [
  'AUTHENTICATED',        // App authenticated with QR code
  'NATS_CONNECTED',       // App connected to NATS with bootstrap credentials
  'ATTESTATION_VERIFIED', // App verified enclave attestation
  'PIN_SET',              // Supervisor confirmed PIN/DEK creation
  'PASSWORD_SET',         // Vault-manager confirmed password/credential creation
  'COMPLETED',            // First operation succeeded (set by enrollFinalize)
] as const;

type EnrollmentPhase = typeof ENROLLMENT_PHASES[number];

interface UpdateStatusRequest {
  phase: EnrollmentPhase;
  // Optional metadata (non-sensitive) for audit purposes
  metadata?: {
    nats_connected_at?: string;
    attestation_verified_at?: string;
    pin_set_at?: string;
    password_set_at?: string;
  };
}

/**
 * POST /vault/enroll/status
 *
 * Update enrollment session status as the app progresses through NATS-based phases.
 *
 * This endpoint is called by the mobile app to report progress. The actual sensitive
 * operations (attestation, PIN, password) happen via NATS directly to the enclave.
 * Lambda only tracks status for:
 * 1. Account Portal UI updates (show user enrollment progress)
 * 2. Audit trail
 * 3. Session timeout management
 *
 * Requires enrollment JWT from /vault/enroll/authenticate.
 *
 * Security: This endpoint NEVER receives sensitive data. It only receives
 * phase completion notifications. PIN and password go directly to enclave via NATS.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate enrollment JWT
    const authHeader = event.headers?.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      return unauthorized('Missing or invalid authorization header', origin);
    }

    const payload = await verifyEnrollmentToken(token);
    if (!payload) {
      return unauthorized('Invalid or expired enrollment token', origin);
    }

    const sessionId = payload.session_id;
    const userGuid = payload.sub;

    // Parse request body
    const body = parseJsonBody<UpdateStatusRequest>(event);

    if (!body.phase) {
      return badRequest('phase is required', origin);
    }

    if (!ENROLLMENT_PHASES.includes(body.phase)) {
      return badRequest(`Invalid phase. Must be one of: ${ENROLLMENT_PHASES.join(', ')}`, origin);
    }

    // Get current session
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
    }));

    if (!sessionResult.Item) {
      return notFound('Enrollment session not found', origin);
    }

    const session = unmarshall(sessionResult.Item);

    // Verify session belongs to this user
    if (session.user_guid !== userGuid) {
      return unauthorized('Session does not belong to this user', origin);
    }

    // Check session expiry
    const expiresAt = typeof session.expires_at === 'number'
      ? session.expires_at
      : new Date(session.expires_at).getTime();

    if (expiresAt < Date.now()) {
      return badRequest('Enrollment session has expired', origin);
    }

    // Validate phase transition
    const currentPhaseIndex = ENROLLMENT_PHASES.indexOf(session.status as EnrollmentPhase);
    const newPhaseIndex = ENROLLMENT_PHASES.indexOf(body.phase);

    // Don't allow going backwards (except for retries of the same phase)
    if (newPhaseIndex < currentPhaseIndex) {
      return conflict(
        `Cannot transition from ${session.status} to ${body.phase}. Phase already completed.`,
        origin
      );
    }

    // Don't allow skipping phases (must progress sequentially)
    if (newPhaseIndex > currentPhaseIndex + 1) {
      const expectedPhase = ENROLLMENT_PHASES[currentPhaseIndex + 1];
      return conflict(
        `Cannot skip to ${body.phase}. Expected next phase: ${expectedPhase}`,
        origin
      );
    }

    // If same phase, it's a retry - just return success
    if (newPhaseIndex === currentPhaseIndex) {
      return ok({
        status: session.status,
        phase: body.phase,
        message: 'Phase already recorded',
      }, origin);
    }

    // Update session with new phase
    const now = Date.now();
    const phaseTimestamp = new Date(now).toISOString();
    const phaseField = `${body.phase.toLowerCase()}_at`;

    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
      UpdateExpression: `SET #status = :status, ${phaseField} = :timestamp, updated_at = :timestamp`,
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': body.phase,
        ':timestamp': phaseTimestamp,
      }),
    }));

    // Audit log (no sensitive data)
    await putAudit({
      type: 'enrollment_phase_updated',
      user_guid: userGuid,
      session_id: sessionId,
      previous_phase: session.status,
      new_phase: body.phase,
      device_type: payload.device_type,
    }, requestId);

    return ok({
      status: body.phase,
      phase: body.phase,
      previous_phase: session.status,
      updated_at: phaseTimestamp,
      message: `Enrollment progressed to ${body.phase}`,
    }, origin);

  } catch (error: any) {
    console.error('Update enrollment status error:', error);
    return internalError('Failed to update enrollment status', origin);
  }
};
