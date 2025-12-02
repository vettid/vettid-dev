import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  internalError,
  requireRegisteredOrMemberGroup
} from "../../common/util";
import { QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

  try {
    // Get user's email from JWT claims
    const userEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    // Find the user's registration by email using GSI (efficient query instead of scan)
    const queryResult = await ddb.send(new QueryCommand({
      TableName: TABLES.registrations,
      IndexName: 'email-index',
      KeyConditionExpression: "email = :email",
      FilterExpression: "#s = :approved",
      ExpressionAttributeNames: {
        "#s": "status"
      },
      ExpressionAttributeValues: marshall({
        ":email": userEmail,
        ":approved": "approved"
      })
    }));

    // If no registration found, return default disabled state (valid for new users)
    if (!queryResult.Items || queryResult.Items.length === 0) {
      return ok({
        pin_enabled: false,
        pin_updated_at: null
      });
    }

    const reg = unmarshall(queryResult.Items[0]) as any;

    return ok({
      pin_enabled: reg.pin_enabled === true,
      pin_updated_at: reg.pin_updated_at || null
    });
  } catch (error) {
    console.error('Failed to get PIN status:', error);
    return internalError("Failed to get PIN status");
  }
};
