import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  putAudit,
  validateOrigin,
  requireUserClaims
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

/**
 * Cancel a subscription for the authenticated user
 * POST /account/subscriptions/cancel
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  try {
    // Get user claims from JWT token
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;
    const { user_guid: userGuid, email } = claimsResult.claims;

    // Get current subscription
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!result.Item) {
      return badRequest('No active subscription found');
    }

    const subscription = unmarshall(result.Item);

    // Check if subscription is already cancelled or expired
    if (subscription.status === 'cancelled' || subscription.status === 'expired') {
      return badRequest('Subscription is already cancelled or expired');
    }

    // Update subscription status to cancelled
    const now = new Date();
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET #status = :status, cancelled_at = :cancelled_at, auto_renew = :auto_renew, updated_at = :updated_at',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'cancelled',
        ':cancelled_at': now.toISOString(),
        ':auto_renew': false,
        ':updated_at': now.toISOString(),
      }),
    }));

    // Log to audit
    await putAudit({
      type: 'subscription_cancelled',
      user_guid: userGuid,
      email: email,
      subscription_type_id: subscription.subscription_type_id,
      subscription_type_name: subscription.subscription_type_name,
    }, requestId);

    return ok({
      message: 'Subscription cancelled successfully. You will retain access until the end of your billing period.',
      subscription: {
        status: 'cancelled',
        expires_at: subscription.expires_at,
      },
    });
  } catch (error: any) {
    console.error('Error cancelling subscription:', error);
    return internalError(error.message || 'Failed to cancel subscription');
  }
};
