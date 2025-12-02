import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireUserClaims } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTION_TYPES = process.env.TABLE_SUBSCRIPTION_TYPES!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

/**
 * List enabled subscription types (public endpoint for members to view available subscriptions)
 * GET /account/subscription-types
 * Filters out one-time offers that have already been used by the current user
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Get user claims from JWT token
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;
    const { user_guid: userGuid } = claimsResult.claims;

    // Scan all subscription types
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTION_TYPES,
    }));

    if (!result.Items || result.Items.length === 0) {
      return ok({ subscription_types: [] });
    }

    const subscriptionTypes = result.Items.map(item => unmarshall(item))
      .filter(st => st.is_enabled === true); // Only return enabled types

    // Get user's subscription history from audit table
    const auditResult = await ddb.send(new ScanCommand({
      TableName: TABLE_AUDIT,
      FilterExpression: '#act = :action AND user_guid = :uguid',
      ExpressionAttributeNames: {
        '#act': 'action',
      },
      ExpressionAttributeValues: {
        ':action': { S: 'subscription_created' },
        ':uguid': { S: userGuid },
      },
    }));

    // Extract unique subscription_type_ids the user has already used
    const usedSubscriptionTypeIds = new Set<string>();
    if (auditResult.Items && auditResult.Items.length > 0) {
      auditResult.Items.forEach(item => {
        const record = unmarshall(item);
        if (record.subscription_type_id) {
          usedSubscriptionTypeIds.add(record.subscription_type_id);
        }
      });
    }

    // Filter out one-time offers that have already been used
    const availableSubscriptionTypes = subscriptionTypes.filter(st => {
      // If it's a one-time offer and the user has already used it, exclude it
      if (st.is_one_time_offer === true && usedSubscriptionTypeIds.has(st.subscription_type_id)) {
        return false;
      }
      return true;
    });

    // Sort by created_at descending (newest first)
    availableSubscriptionTypes.sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateB - dateA;
    });

    return ok({ subscription_types: availableSubscriptionTypes });
  } catch (error: any) {
    console.error('Error listing enabled subscription types:', error);
    return internalError(error.message || 'Failed to list subscription types');
  }
};
