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
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const userEmail = claims?.email;
    if (!userEmail) {
      return badRequest("Unable to identify user");
    }

    const body = parseJsonBody(event);
    const pin = body.pin;

    if (!pin || typeof pin !== 'string') {
      return badRequest("PIN is required");
    }

    if (!isValidPin(pin)) {
      return badRequest("PIN must be 4-6 digits");
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

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return notFound("No active registration found for your account");
    }

    const reg = unmarshall(queryResult.Items[0]) as any;
    const now = new Date().toISOString();

    // Hash the PIN and store it
    const pinHash = hashPin(pin);

    await ddb.send(new UpdateItemCommand({
      TableName: TABLES.registrations,
      Key: marshall({ registration_id: reg.registration_id }),
      UpdateExpression: "SET pin_hash = :pin_hash, pin_enabled = :enabled, pin_updated_at = :now",
      ExpressionAttributeValues: marshall({
        ":pin_hash": pinHash,
        ":enabled": true,
        ":now": now
      })
    }));

    await putAudit({
      type: "pin_enabled",
      registration_id: reg.registration_id,
      email: userEmail,
      enabled_at: now
    }, requestId);

    return ok({
      message: "PIN enabled successfully"
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    console.error('Failed to enable PIN:', error);
    return internalError("Failed to enable PIN");
  }
};
