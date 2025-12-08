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

    // Check if user already has an active credential
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      IndexName: 'user-guid-index',
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

    // Check for existing pending session
    const existingSession = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'user-guid-index',
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#status = :pending AND expires_at > :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':pending': 'WEB_INITIATED',
        ':now': new Date().toISOString(),
      }),
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
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 minutes

    // Create web-initiated enrollment session
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Item: marshall({
        session_id: sessionId,
        session_token: sessionToken,
        user_guid: userGuid,
        user_email: userEmail,
        status: 'WEB_INITIATED',
        step: 'awaiting_mobile',
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        expires_at_ttl: Math.floor(expiresAt.getTime() / 1000),
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
      expires_at: expiresAt.toISOString(),
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
