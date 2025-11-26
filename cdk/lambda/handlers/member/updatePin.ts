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
  parseJsonBody,
  ValidationError
} from "../../common/util";
import { UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
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

    const body = parseJsonBody(event);
    const currentPin = body.currentPin;
    const newPin = body.newPin;

    if (!currentPin || typeof currentPin !== 'string') {
      return badRequest("Current PIN is required");
    }

    if (!isValidPin(currentPin)) {
      return badRequest("Current PIN must be 4-6 digits");
    }

    if (!newPin || typeof newPin !== 'string') {
      return badRequest("New PIN is required");
    }

    if (!isValidPin(newPin)) {
      return badRequest("New PIN must be 4-6 digits");
    }

    if (currentPin === newPin) {
      return badRequest("New PIN must be different from current PIN");
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

    // Check if PIN is enabled
    if (!reg.pin_enabled) {
      return badRequest("PIN is not enabled. Please enable PIN first.");
    }

    // Verify current PIN matches stored hash
    const currentPinHash = hashPin(currentPin);
    if (currentPinHash !== reg.pin_hash) {
      // SECURITY: Log failed PIN verification attempts for security monitoring
      await putAudit({
        type: "pin_verification_failed",
        registration_id: reg.registration_id,
        email: userEmail,
        failed_at: new Date().toISOString()
      }, requestId);
      return badRequest("Current PIN is incorrect");
    }

    const now = new Date().toISOString();

    // Hash the new PIN and update it
    const pinHash = hashPin(newPin);

    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: reg.registration_id }),
      UpdateExpression: "SET pin_hash = :pin_hash, pin_updated_at = :now",
      ExpressionAttributeValues: marshall({
        ":pin_hash": pinHash,
        ":now": now
      })
    }));

    await putAudit({
      type: "pin_updated",
      registration_id: reg.registration_id,
      email: userEmail,
      updated_at: now
    }, requestId);

    return ok({
      message: "PIN updated successfully"
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    console.error('Failed to update PIN:', error);
    return internalError("Failed to update PIN");
  }
};
