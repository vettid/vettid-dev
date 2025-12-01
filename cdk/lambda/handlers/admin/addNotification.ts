import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { ok, badRequest, internalError, requireAdminGroup } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_NOTIFICATION_PREFERENCES = process.env.TABLE_NOTIFICATION_PREFERENCES!;

const VALID_NOTIFICATION_TYPES = ['waitlist', 'user', 'vote', 'system_health'];

// Email validation regex
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

  // Parse request body
  let body: any;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (error) {
    return badRequest('Invalid JSON body', requestOrigin);
  }

  const adminEmail = body.admin_email;

  if (!adminEmail) {
    return badRequest('admin_email is required', requestOrigin);
  }

  // Validate email format
  if (!EMAIL_REGEX.test(adminEmail)) {
    return badRequest('Invalid email format', requestOrigin);
  }

  try {
    // Add the notification preference to DynamoDB
    await ddb.send(new PutItemCommand({
      TableName: TABLE_NOTIFICATION_PREFERENCES,
      Item: marshall({
        notification_type: notificationType,
        admin_email: adminEmail,
        created_at: new Date().toISOString()
      })
    }));

    return ok({ message: 'Notification preference added successfully' }, requestOrigin);
  } catch (error) {
    console.error('Error adding notification preference:', error);
    return internalError('Failed to add notification preference', requestOrigin);
  }
};
