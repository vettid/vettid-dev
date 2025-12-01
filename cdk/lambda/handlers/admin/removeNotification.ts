import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { DynamoDBClient, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { ok, badRequest, internalError, requireAdminGroup } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_NOTIFICATION_PREFERENCES = process.env.TABLE_NOTIFICATION_PREFERENCES!;

const VALID_NOTIFICATION_TYPES = ['waitlist', 'user', 'vote', 'system_health'];

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // Get notification type and email from path parameters
  const notificationType = event.pathParameters?.type;
  const adminEmail = event.pathParameters?.email;

  if (!notificationType) {
    return badRequest('Notification type is required', requestOrigin);
  }

  if (!adminEmail) {
    return badRequest('Admin email is required', requestOrigin);
  }

  if (!VALID_NOTIFICATION_TYPES.includes(notificationType)) {
    return badRequest(`Invalid notification type. Must be one of: ${VALID_NOTIFICATION_TYPES.join(', ')}`, requestOrigin);
  }

  try {
    // Delete the notification preference from DynamoDB
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_NOTIFICATION_PREFERENCES,
      Key: marshall({
        notification_type: notificationType,
        admin_email: decodeURIComponent(adminEmail)
      })
    }));

    return ok({ message: 'Notification preference removed successfully' }, requestOrigin);
  } catch (error) {
    console.error('Error removing notification preference:', error);
    return internalError('Failed to remove notification preference', requestOrigin);
  }
};
