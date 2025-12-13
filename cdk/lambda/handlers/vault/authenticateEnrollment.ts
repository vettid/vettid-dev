import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
} from '../../common/util';
import { generateEnrollmentToken } from '../../common/enrollment-jwt';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

interface AuthenticateRequest {
  session_token: string;
  device_id: string;
  device_type: 'android' | 'ios';
}

/**
 * POST /vault/enroll/authenticate
 *
 * Public endpoint (no JWT required) that validates a session_token from the QR code
 * and returns a short-lived enrollment JWT for use with subsequent enrollment endpoints.
 *
 * This is the bridge between the web-initiated QR code flow and the mobile enrollment process.
 *
 * Flow:
 * 1. Web user creates enrollment session (authenticated) → gets QR code with session_token
 * 2. Mobile scans QR code → calls this endpoint with session_token
 * 3. This endpoint validates session_token → returns enrollment JWT
 * 4. Mobile uses enrollment JWT for /vault/enroll/start, /set-password, /finalize
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Parse request body
    const body = parseJsonBody<AuthenticateRequest>(event);

    if (!body.session_token) {
      return badRequest('session_token is required', origin);
    }
    if (!body.device_id) {
      return badRequest('device_id is required', origin);
    }
    if (!body.device_type || !['android', 'ios'].includes(body.device_type)) {
      return badRequest('device_type must be android or ios', origin);
    }

    // Look up session by session_token using GSI
    // Note: session_token is indexed via token-index GSI
    const sessionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'token-index',
      KeyConditionExpression: 'session_token = :token',
      ExpressionAttributeValues: marshall({
        ':token': body.session_token,
      }),
      Limit: 1,
    }));

    if (!sessionResult.Items || sessionResult.Items.length === 0) {
      // Log failed attempt for security monitoring
      await putAudit({
        type: 'enrollment_auth_failed',
        reason: 'invalid_session_token',
        device_id: body.device_id.substring(0, 8) + '...',
        device_type: body.device_type,
      }, requestId);

      return unauthorized('Invalid or expired session token', origin);
    }

    const session = unmarshall(sessionResult.Items[0]);

    // Validate session status
    if (session.status !== 'WEB_INITIATED' && session.status !== 'PENDING') {
      await putAudit({
        type: 'enrollment_auth_failed',
        reason: 'invalid_session_status',
        session_id: session.session_id,
        status: session.status,
      }, requestId);

      return unauthorized('Session is not in a valid state for authentication', origin);
    }

    // Check expiration
    const now = Date.now();
    const expiresAt = typeof session.expires_at === 'number'
      ? session.expires_at
      : new Date(session.expires_at).getTime();

    if (expiresAt < now) {
      await putAudit({
        type: 'enrollment_auth_failed',
        reason: 'session_expired',
        session_id: session.session_id,
      }, requestId);

      return unauthorized('Session has expired', origin);
    }

    // Update session with device info and status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: session.session_id }),
      UpdateExpression: 'SET #status = :status, device_id = :device_id, device_type = :device_type, authenticated_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'AUTHENTICATED',
        ':device_id': body.device_id,
        ':device_type': body.device_type,
        ':now': now,
      }),
    }));

    // Generate enrollment JWT
    // Token expires in 10 minutes (enough time for the enrollment process)
    const enrollmentToken = generateEnrollmentToken(
      session.user_guid,
      session.session_id,
      {
        deviceId: body.device_id,
        deviceType: body.device_type,
        expiresInSeconds: 600, // 10 minutes
      }
    );

    // Calculate token expiration for response
    const tokenExpiresAt = new Date(now + 600 * 1000).toISOString();

    // Audit log
    await putAudit({
      type: 'enrollment_authenticated',
      user_guid: session.user_guid,
      session_id: session.session_id,
      device_id: body.device_id.substring(0, 8) + '...',
      device_type: body.device_type,
    }, requestId);

    return ok({
      enrollment_token: enrollmentToken,
      token_type: 'Bearer',
      expires_in: 600,
      expires_at: tokenExpiresAt,
      enrollment_session_id: session.session_id,
      user_guid: session.user_guid,
    }, origin);

  } catch (error: any) {
    console.error('Enrollment authentication error:', error);
    return internalError('Failed to authenticate enrollment session', origin);
  }
};
