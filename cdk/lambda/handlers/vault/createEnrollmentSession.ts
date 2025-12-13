import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
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
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;

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

    // Check if user already has an active credential (user_guid is the partition key)
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
      }),
      Limit: 1,
    }));

    if (credentialResult.Items && credentialResult.Items.length > 0) {
      const credential = unmarshall(credentialResult.Items[0]);
      if (credential.status === 'ACTIVE') {
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
      return ok({
        session_id: session.session_id,
        session_token: session.session_token,
        expires_at: session.expires_at,
        qr_data: {
          type: 'vettid_enrollment',
          version: 1,
          api_url: process.env.API_URL || 'https://api.vettid.dev',
          session_token: session.session_token,
          user_guid: userGuid,
        },
      }, origin);
    }

    // Generate new enrollment session
    const sessionId = generateSecureId('enroll', 32);
    const sessionToken = generateSecureId('est', 48); // Enrollment Session Token
    const nowMs = Date.now();
    const expiresAtMs = nowMs + 5 * 60 * 1000; // 5 minutes

    // Create web-initiated enrollment session
    // Note: created_at and expires_at stored as numbers (Unix timestamps in ms) for GSI compatibility
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Item: marshall({
        session_id: sessionId,
        session_token: sessionToken,
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

    return ok({
      session_id: sessionId,
      session_token: sessionToken,
      expires_at: new Date(expiresAtMs).toISOString(),
      qr_data: {
        type: 'vettid_enrollment',
        version: 1,
        api_url: process.env.API_URL || 'https://api.vettid.dev',
        session_token: sessionToken,
        user_guid: userGuid,
      },
    }, origin);

  } catch (error: any) {
    console.error('Create enrollment session error:', error);
    return internalError('Failed to create enrollment session', origin);
  }
};
