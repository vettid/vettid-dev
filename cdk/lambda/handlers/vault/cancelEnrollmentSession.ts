import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand, DeleteItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
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
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

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

    let sessionCancelled = false;
    let sessionId: string | null = null;

    // Cancel the session if one exists
    if (existingSession.Items && existingSession.Items.length > 0) {
      const session = unmarshall(existingSession.Items[0]);
      sessionId = session.session_id;

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
      sessionCancelled = true;
    }

    // Also clean up any NATS account that's still in 'enrolling' status
    // This allows the user to start fresh enrollment even if session expired
    let natsAccountDeleted = false;
    try {
      const natsAccountResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_NATS_ACCOUNTS,
        Key: marshall({ user_guid: userGuid }),
      }));

      if (natsAccountResult.Item) {
        const natsAccount = unmarshall(natsAccountResult.Item);
        // Only delete if still in 'enrolling' status - never delete 'active' accounts
        if (natsAccount.status === 'enrolling') {
          await ddb.send(new DeleteItemCommand({
            TableName: TABLE_NATS_ACCOUNTS,
            Key: marshall({ user_guid: userGuid }),
            // Safety: only delete if still enrolling (prevent race condition)
            ConditionExpression: '#status = :enrolling',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: marshall({ ':enrolling': 'enrolling' }),
          }));
          natsAccountDeleted = true;
          console.log(`Deleted enrolling NATS account for user ${userGuid}`);
        }
      }
    } catch (natsError: any) {
      // Log but don't fail - the session cancellation is the primary action
      if (natsError.name !== 'ConditionalCheckFailedException') {
        console.warn('Failed to clean up NATS account:', natsError);
      }
    }

    // If nothing was cancelled or cleaned up, return not found
    if (!sessionCancelled && !natsAccountDeleted) {
      return notFound('No active enrollment session or pending vault found', origin);
    }

    // Audit log
    await putAudit({
      type: 'enrollment_cancelled',
      user_guid: userGuid,
      session_id: sessionId,
      session_cancelled: sessionCancelled,
      nats_account_deleted: natsAccountDeleted,
    }, requestId);

    return ok({
      success: true,
      session_id: sessionId,
      session_cancelled: sessionCancelled,
      nats_account_cleaned_up: natsAccountDeleted,
      message: sessionCancelled && natsAccountDeleted
        ? 'Enrollment session and pending vault cancelled'
        : sessionCancelled
          ? 'Enrollment session cancelled'
          : 'Pending vault enrollment cancelled',
    }, origin);

  } catch (error: any) {
    console.error('Cancel enrollment session error:', error);
    return internalError('Failed to cancel enrollment session', origin);
  }
};
