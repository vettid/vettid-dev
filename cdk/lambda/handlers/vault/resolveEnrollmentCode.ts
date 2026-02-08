import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  validateDeviceId,
  validateDeviceType,
  ValidationError,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

// Enrollment code format: XXXX-XXXX (uppercase alphanumeric, no ambiguous chars)
const ENROLLMENT_CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

interface ResolveCodeRequest {
  enrollment_code: string;
  device_id: string;
  device_type: 'android' | 'ios';
}

/**
 * POST /vault/enroll/resolve-code
 *
 * Public endpoint (no JWT required) that resolves a short enrollment code
 * to the full enrollment data (equivalent to scanning the QR code).
 *
 * This does NOT authenticate — it just returns the QR-equivalent data.
 * The app then calls /vault/enroll/authenticate with the session_token as usual.
 *
 * Flow:
 * 1. Web user creates enrollment session → gets QR code + enrollment code
 * 2. Mobile user enters enrollment code → calls this endpoint
 * 3. This endpoint resolves code → returns session_token, api_url, user_guid
 * 4. Mobile proceeds with normal authentication flow
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Parse request body
    const body = parseJsonBody<ResolveCodeRequest>(event);

    // Validate enrollment code format
    const enrollmentCode = body.enrollment_code?.trim()?.toUpperCase();
    if (!enrollmentCode || !ENROLLMENT_CODE_PATTERN.test(enrollmentCode)) {
      return badRequest('Invalid enrollment code format. Expected XXXX-XXXX.', origin);
    }

    // SECURITY: Validate device fields
    let deviceId: string;
    let deviceType: 'android' | 'ios';

    try {
      deviceId = validateDeviceId(body.device_id);
      deviceType = validateDeviceType(body.device_type);
    } catch (err) {
      if (err instanceof ValidationError) {
        return badRequest(err.message, origin);
      }
      throw err;
    }

    // Look up session by enrollment code using GSI
    const sessionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'code-index',
      KeyConditionExpression: 'enrollment_code = :code',
      ExpressionAttributeValues: marshall({
        ':code': enrollmentCode,
      }),
      Limit: 1,
    }));

    if (!sessionResult.Items || sessionResult.Items.length === 0) {
      // Log failed attempt for security monitoring
      await putAudit({
        type: 'enrollment_code_resolve_failed',
        reason: 'invalid_code',
        device_id: deviceId.substring(0, 8) + '...',
        device_type: deviceType,
      }, requestId);

      return unauthorized('Invalid or expired enrollment code', origin);
    }

    const session = unmarshall(sessionResult.Items[0]);

    // Validate session status
    if (session.status !== 'WEB_INITIATED') {
      await putAudit({
        type: 'enrollment_code_resolve_failed',
        reason: 'invalid_session_status',
        session_id: session.session_id,
        status: session.status,
      }, requestId);

      return unauthorized('Enrollment session is no longer available', origin);
    }

    // Check expiration
    const now = Date.now();
    const expiresAt = typeof session.expires_at === 'number'
      ? session.expires_at
      : new Date(session.expires_at).getTime();

    if (expiresAt < now) {
      await putAudit({
        type: 'enrollment_code_resolve_failed',
        reason: 'session_expired',
        session_id: session.session_id,
      }, requestId);

      return unauthorized('Enrollment code has expired. Please request a new one from the web portal.', origin);
    }

    // Audit log the successful resolve
    await putAudit({
      type: 'enrollment_code_resolved',
      user_guid: session.user_guid,
      session_id: session.session_id,
      device_id: deviceId.substring(0, 8) + '...',
      device_type: deviceType,
    }, requestId);

    // Return QR-equivalent data
    return ok({
      type: 'vettid_enrollment',
      version: 1,
      api_url: process.env.API_URL || 'https://api.vettid.dev',
      session_token: session.session_token,
      user_guid: session.user_guid,
    }, origin);

  } catch (error: any) {
    console.error('Resolve enrollment code error:', error);
    return internalError('Failed to resolve enrollment code', origin);
  }
};
