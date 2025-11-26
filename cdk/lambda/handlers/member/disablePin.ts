import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  requireRegisteredOrMemberGroup,
  getRequestId
} from "../../common/util";
import { UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    // Get user's email from JWT claims
    const userEmail = (event.requestContext as any)?.authorizer?.jwt?.claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    // Find the user's registration by email using GSI
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
      }),
      Limit: 1
    }));

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return notFound("No active registration found for your account");
    }

    const reg = unmarshall(queryResult.Items[0]) as any;
    const now = new Date().toISOString();

    // Disable PIN (remove hash and set enabled to false)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: reg.registration_id }),
      UpdateExpression: "REMOVE pin_hash SET pin_enabled = :enabled, pin_updated_at = :now",
      ExpressionAttributeValues: marshall({
        ":enabled": false,
        ":now": now
      })
    }));

    await putAudit({
      type: "pin_disabled",
      registration_id: reg.registration_id,
      email: userEmail,
      disabled_at: now
    }, requestId);

    return ok({
      message: "PIN disabled successfully"
    });
  } catch (error) {
    console.error('Failed to disable PIN:', error);
    return internalError("Failed to disable PIN");
  }
};
