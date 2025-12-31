import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  internalError,
  requireUserClaims,
  sanitizeErrorForClient
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

/**
 * Get subscription status for the authenticated user
 * GET /subscriptions/status
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Get user claims from JWT token
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;
    const { user_guid: userGuid } = claimsResult.claims;

    // Get subscription from DynamoDB
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!result.Item) {
      return ok({
        has_subscription: false,
        is_active: false,
        plan: null,
        expires_at: null,
      });
    }

    const subscription = unmarshall(result.Item);

    // Check if subscription has expired
    const now = new Date();
    const expiresAt = new Date(subscription.expires_at);
    const isActive = subscription.status === 'active' && expiresAt > now;

    // If expired, update status to expired
    if (!isActive && subscription.status === 'active') {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_SUBSCRIPTIONS,
        Key: marshall({ user_guid: userGuid }),
        UpdateExpression: 'SET #status = :status, updated_at = :updated_at',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':status': 'expired',
          ':updated_at': now.toISOString(),
        }),
      }));

      subscription.status = 'expired';
    }

    return ok({
      has_subscription: true,
      is_active: isActive,
      plan: subscription.subscription_type_name,
      status: subscription.status,
      created_at: subscription.created_at,
      expires_at: subscription.expires_at,
      amount: subscription.amount || 0,
      currency: subscription.currency || 'USD',
      has_used_trial: subscription.has_used_trial || false,
    });
  } catch (error: any) {
    console.error('Error getting subscription status:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to get subscription status'));
  }
};
