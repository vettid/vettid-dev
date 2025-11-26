import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, badRequest, validateOrigin } from "../../common/util";
import { PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Get user email from JWT claims
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  const email = claims?.email;

  if (!email) {
    return badRequest('Unable to identify user from authentication token');
  }

  let systemEmailsEnabled: boolean;

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    systemEmailsEnabled = body.system_emails_enabled;

    if (typeof systemEmailsEnabled !== 'boolean') {
      return badRequest('system_emails_enabled must be a boolean');
    }
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input');
  }

  try {
    const now = new Date().toISOString();

    // Store email preference in DynamoDB (using audit table for simplicity)
    await ddb.send(new PutItemCommand({
      TableName: TABLES.audit,
      Item: marshall({
        id: `email_pref_${email}`,
        email,
        system_emails_enabled: systemEmailsEnabled,
        ...(systemEmailsEnabled ? { opted_in_at: now } : { opted_out_at: now }),
        updated_at: now
      })
    }));

    return ok({
      message: systemEmailsEnabled
        ? "System emails enabled successfully"
        : "System emails disabled successfully",
      email,
      system_emails_enabled: systemEmailsEnabled
    });
  } catch (error: any) {
    console.error('Error updating email preferences:', error);
    throw error;
  }
};
