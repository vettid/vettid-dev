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
  getRequestId,
  parseJsonBody
} from "../../common/util";
import { UpdateItemCommand, QueryCommand, ScanCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { createHash } from "crypto";

/**
 * Hash PIN using SHA-256
 */
function hashPin(pin: string): string {
  return createHash('sha256').update(pin).digest('hex');
}

/**
 * Validate PIN format (4-6 digits)
 */
function isValidPin(pin: string): boolean {
  return /^\d{4,6}$/.test(pin);
}

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

    // Parse request body to get current PIN
    const body = parseJsonBody(event);
    const currentPin = body.currentPin;

    if (!currentPin || typeof currentPin !== 'string') {
      return badRequest("Current PIN is required");
    }

    if (!isValidPin(currentPin)) {
      return badRequest("Current PIN must be 4-6 digits");
    }

    // Find the user's registration by email using Scan
    const queryResult = await ddb.send(new ScanCommand({
      TableName: TABLES.registrations,
      FilterExpression: "email = :email AND #s = :approved",
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

    // Check if PIN is enabled
    if (!reg.pin_enabled) {
      return badRequest("PIN is not enabled");
    }

    // Verify current PIN matches stored hash
    const currentPinHash = hashPin(currentPin);
    if (currentPinHash !== reg.pin_hash) {
      // SECURITY: Log failed PIN verification attempts for security monitoring
      await putAudit({
        type: "pin_verification_failed_on_disable",
        registration_id: reg.registration_id,
        email: userEmail,
        failed_at: new Date().toISOString()
      }, requestId);
      return badRequest("Current PIN is incorrect");
    }

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
