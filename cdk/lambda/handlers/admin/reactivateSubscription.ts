import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  putAudit,
  requireAdminGroup,
  sanitizeErrorForClient
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

/**
 * Reactivate a cancelled subscription
 * POST /admin/subscriptions/{user_guid}/reactivate
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    // Get admin email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const email = claims?.email;

    if (!email) {
      return badRequest('Email not found in token');
    }

    // Get user GUID from path
    const userGuid = event.pathParameters?.user_guid;
    if (!userGuid) {
      return badRequest('User GUID is required');
    }

    // Get current subscription
    const getResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!getResult.Item) {
      return badRequest('Subscription not found');
    }

    const subscription = unmarshall(getResult.Item);

    if (subscription.status !== 'cancelled') {
      return badRequest('Only cancelled subscriptions can be reactivated');
    }

    const now = new Date();
    const expiresDate = new Date(subscription.expires_at);

    // Determine new status based on expiration date
    const newStatus = expiresDate > now ? 'active' : 'expired';

    // Update subscription status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET #status = :status, reactivated_at = :reactivated_at, reactivated_by = :reactivated_by REMOVE cancelled_at, cancelled_by',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': newStatus,
        ':reactivated_at': now.toISOString(),
        ':reactivated_by': email,
      }),
    }));

    // Log to audit
    await putAudit({
      type: 'subscription_reactivated',
      email: email,
      user_guid: userGuid,
      new_status: newStatus,
      reactivated_at: now.toISOString(),
    }, requestId);

    return ok({
      message: 'Subscription reactivated successfully',
      new_status: newStatus,
    });
  } catch (error: any) {
    console.error('Error reactivating subscription:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to reactivate subscription'));
  }
};
