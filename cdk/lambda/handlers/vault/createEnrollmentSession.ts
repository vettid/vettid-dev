import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { randomBytes } from 'crypto';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  generateSecureId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const DEEP_LINK_BASE_URL = 'https://vettid.dev/enroll';

/**
 * Generate a deep link URL for enrollment.
 * The QR data is base64 URL-safe encoded and passed as a query parameter.
 */
function generateDeepLinkUrl(qrData: object): string {
  const jsonString = JSON.stringify(qrData);
  const base64Encoded = Buffer.from(jsonString, 'utf-8').toString('base64url');
  return `${DEEP_LINK_BASE_URL}?data=${base64Encoded}`;
}

/**
 * Generate a short enrollment code for manual entry (8 chars, formatted XXXX-XXXX).
 * Uses uppercase alphanumeric excluding ambiguous chars (0/O, 1/I/L).
 */
function generateEnrollmentCode(): string {
  const SAFE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const codeChars = Array.from(randomBytes(8), (b) => SAFE_CHARS[b % SAFE_CHARS.length]);
  return codeChars.slice(0, 4).join('') + '-' + codeChars.slice(4).join('');
}

/**
 * POST /vault/enroll/session
 *
 * Create a web-initiated enrollment session for the authenticated member.
 * Returns a session token and QR code data for the mobile app to scan.
 *
 * This allows members to start vault enrollment from the web portal
 * and complete it on their mobile device.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    const userGuid = claims.user_guid;
    const userEmail = claims.email;

    // Check if user already has an active NATS account (vault is enrolled)
    // In the Nitro model, having a NATS account means the user has a vault
    const natsAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (natsAccountResult.Item) {
      const natsAccount = unmarshall(natsAccountResult.Item);
      if (natsAccount.status === 'active') {
        return conflict('Vault is already enrolled. Terminate existing vault before re-enrolling.', origin);
      }
    }

    // Check for existing pending session (using user-index GSI)
    const existingSession = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#status = :pending AND expires_at > :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':pending': 'WEB_INITIATED',
        ':now': Date.now(), // Unix timestamp in milliseconds
      }),
      ScanIndexForward: false, // Most recent first
      Limit: 1,
    }));

    // Return existing session if still valid
    if (existingSession.Items && existingSession.Items.length > 0) {
      const session = unmarshall(existingSession.Items[0]);
      const qrData = {
        type: 'vettid_enrollment',
        version: 1,
        api_url: process.env.API_URL || 'https://api.vettid.dev',
        session_token: session.session_token,
        user_guid: userGuid,
      };
      return ok({
        session_id: session.session_id,
        session_token: session.session_token,
        enrollment_code: session.enrollment_code,
        expires_at: session.expires_at,
        qr_data: qrData,
        deep_link_url: generateDeepLinkUrl(qrData),
      }, origin);
    }

    // Generate new enrollment session
    const sessionId = generateSecureId('enroll', 32);
    const sessionToken = generateSecureId('est', 48); // Enrollment Session Token
    const enrollmentCode = generateEnrollmentCode(); // Short code for manual entry (XXXX-XXXX)
    const nowMs = Date.now();
    const expiresAtMs = nowMs + 5 * 60 * 1000; // 5 minutes

    // Create web-initiated enrollment session
    // Note: created_at and expires_at stored as numbers (Unix timestamps in ms) for GSI compatibility
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Item: marshall({
        session_id: sessionId,
        session_token: sessionToken,
        enrollment_code: enrollmentCode,
        user_guid: userGuid,
        user_email: userEmail,
        status: 'WEB_INITIATED',
        step: 'awaiting_mobile',
        created_at: nowMs,
        created_at_iso: new Date(nowMs).toISOString(), // Human-readable version
        expires_at: expiresAtMs,
        expires_at_iso: new Date(expiresAtMs).toISOString(), // Human-readable version
        ttl: Math.floor(expiresAtMs / 1000), // TTL in seconds for DynamoDB auto-deletion
      }),
    }));

    // Audit log
    await putAudit({
      type: 'enrollment_session_created',
      user_guid: userGuid,
      session_id: sessionId,
      initiated_from: 'web',
    }, requestId);

    const qrData = {
      type: 'vettid_enrollment',
      version: 1,
      api_url: process.env.API_URL || 'https://api.vettid.dev',
      session_token: sessionToken,
      user_guid: userGuid,
    };

    return ok({
      session_id: sessionId,
      session_token: sessionToken,
      enrollment_code: enrollmentCode,
      expires_at: new Date(expiresAtMs).toISOString(),
      qr_data: qrData,
      deep_link_url: generateDeepLinkUrl(qrData),
    }, origin);

  } catch (error: any) {
    console.error('Create enrollment session error:', error);
    return internalError('Failed to create enrollment session', origin);
  }
};
