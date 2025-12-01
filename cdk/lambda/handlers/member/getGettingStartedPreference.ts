import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest } from "../../common/util";
import { GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Get user email from JWT claims
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  const email = claims?.email;

  if (!email) {
    return badRequest('Unable to identify user from authentication token');
  }

  try {
    // Get getting started preference from DynamoDB
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLES.audit, // Using audit table for user preferences
      Key: marshall({ id: `getting_started_${email}` })
    }));

    if (!result.Item) {
      // Default: getting started not completed
      return ok({
        email,
        getting_started_complete: false,
        completed_at: null
      });
    }

    const pref = unmarshall(result.Item);
    return ok({
      email,
      getting_started_complete: pref.getting_started_complete ?? false,
      completed_at: pref.completed_at || null
    });
  } catch (error: any) {
    console.error('Error getting getting started preference:', error);
    throw error;
  }
};
