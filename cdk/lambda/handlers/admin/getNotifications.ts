import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { ok, badRequest, internalError, requireAdminGroup } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_NOTIFICATION_PREFERENCES = process.env.TABLE_NOTIFICATION_PREFERENCES!;

const VALID_NOTIFICATION_TYPES = ['waitlist', 'user', 'vote', 'help_offer', 'system_health'];

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // Get notification type from path parameters
  const notificationType = event.pathParameters?.type;

  if (!notificationType) {
    return badRequest('Notification type is required', requestOrigin);
  }

  if (!VALID_NOTIFICATION_TYPES.includes(notificationType)) {
    return badRequest(`Invalid notification type. Must be one of: ${VALID_NOTIFICATION_TYPES.join(', ')}`, requestOrigin);
  }

  try {
    // Query DynamoDB for all admins assigned to this notification type
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_NOTIFICATION_PREFERENCES,
      KeyConditionExpression: 'notification_type = :type',
      ExpressionAttributeValues: {
        ':type': { S: notificationType }
      }
    }));

    // Extract admin emails from the results
    const admins = (result.Items || []).map(item => {
      const unmarshalled = unmarshall(item);
      return unmarshalled.admin_email;
    });

    return ok({ admins }, requestOrigin);
  } catch (error) {
    console.error('Error fetching notification preferences:', error);
    return internalError('Failed to fetch notification preferences', requestOrigin);
  }
};
