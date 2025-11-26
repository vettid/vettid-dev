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
    // Get email preferences from DynamoDB
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLES.audit, // Using audit table for user preferences
      Key: marshall({ id: `email_pref_${email}` })
    }));

    if (!result.Item) {
      // Default: emails enabled
      return ok({
        email,
        system_emails_enabled: true,
        opted_in_at: null
      });
    }

    const pref = unmarshall(result.Item);
    return ok({
      email,
      system_emails_enabled: pref.system_emails_enabled ?? true,
      opted_in_at: pref.opted_in_at || null,
      opted_out_at: pref.opted_out_at || null
    });
  } catch (error: any) {
    console.error('Error getting email preferences:', error);
    throw error;
  }
};
