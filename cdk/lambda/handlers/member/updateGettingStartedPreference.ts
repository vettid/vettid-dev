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

  let gettingStartedComplete: boolean;

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    gettingStartedComplete = body.getting_started_complete;

    if (typeof gettingStartedComplete !== 'boolean') {
      return badRequest('getting_started_complete must be a boolean');
    }
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input');
  }

  try {
    const now = new Date().toISOString();

    // Store getting started preference in DynamoDB (using audit table for simplicity)
    await ddb.send(new PutItemCommand({
      TableName: TABLES.audit,
      Item: marshall({
        id: `getting_started_${email}`,
        email,
        getting_started_complete: gettingStartedComplete,
        completed_at: gettingStartedComplete ? now : null,
        updated_at: now
      })
    }));

    return ok({
      message: gettingStartedComplete
        ? "Getting started marked as complete"
        : "Getting started marked as incomplete",
      email,
      getting_started_complete: gettingStartedComplete
    });
  } catch (error: any) {
    console.error('Error updating getting started preference:', error);
    throw error;
  }
};
