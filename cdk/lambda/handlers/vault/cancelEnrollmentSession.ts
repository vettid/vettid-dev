import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  notFound,
  internalError,
  getRequestId,
  putAudit,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;

/**
 * POST /vault/enroll/cancel
 *
 * Cancel an active enrollment session for the authenticated member.
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

    // Find active enrollment session for this user
    // Sessions can be in various states: WEB_INITIATED, PENDING, AUTHENTICATED, STARTED
    const existingSession = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#status IN (:web, :pending, :auth, :started) AND expires_at > :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':web': 'WEB_INITIATED',
        ':pending': 'PENDING',
        ':auth': 'AUTHENTICATED',
        ':started': 'STARTED',
        ':now': Date.now(),
      }),
      ScanIndexForward: false,
      Limit: 1,
    }));

    if (!existingSession.Items || existingSession.Items.length === 0) {
      return notFound('No active enrollment session found', origin);
    }

    const session = unmarshall(existingSession.Items[0]);

    // Cancel the session
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: session.session_id }),
      UpdateExpression: 'SET #status = :cancelled, cancelled_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':cancelled': 'CANCELLED',
        ':now': Date.now(),
      }),
    }));

    // Audit log
    await putAudit({
      type: 'enrollment_session_cancelled',
      user_guid: userGuid,
      session_id: session.session_id,
    }, requestId);

    return ok({
      success: true,
      session_id: session.session_id,
      message: 'Enrollment session cancelled',
    }, origin);

  } catch (error: any) {
    console.error('Cancel enrollment session error:', error);
    return internalError('Failed to cancel enrollment session', origin);
  }
};
