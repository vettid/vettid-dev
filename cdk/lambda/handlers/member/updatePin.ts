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
  ValidationError,
  isWeakPin,
  secureCompare
} from "../../common/util";
import {
  isBlockedByBruteForce,
  recordFailedAttempt,
  clearFailedAttempts,
  PIN_BRUTE_FORCE_CONFIG
} from "../../common/rateLimit";
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

    // SECURITY: Check if user is blocked due to too many failed PIN attempts
    const isBlocked = await isBlockedByBruteForce(userEmail, "pin_update", PIN_BRUTE_FORCE_CONFIG);
    if (isBlocked) {
      await putAudit({
        type: "pin_update_blocked",
        email: userEmail,
        reason: "brute_force_protection",
        blocked_at: new Date().toISOString()
      }, requestId);

      return {
        statusCode: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(PIN_BRUTE_FORCE_CONFIG.blockDurationSeconds),
        },
        body: JSON.stringify({
          message: "Too many failed PIN attempts. Please try again later.",
          retryAfter: PIN_BRUTE_FORCE_CONFIG.blockDurationSeconds
        })
      };
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

    // SECURITY: Reject weak PINs
    if (isWeakPin(newPin)) {
      return badRequest("New PIN is too weak. Avoid sequential digits (1234), repeated digits (1111), or common patterns.");
    }

    if (currentPin === newPin) {
      return badRequest("New PIN must be different from current PIN");
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

    // Check if PIN is enabled
    if (!reg.pin_enabled) {
      return badRequest("PIN is not enabled. Please enable PIN first.");
    }

    // SECURITY: Verify current PIN matches stored hash using timing-safe comparison
    // This prevents timing attacks that could leak information about the correct PIN
    const currentPinHash = hashPin(currentPin);
    if (!secureCompare(currentPinHash, reg.pin_hash)) {
      // SECURITY: Record failed attempt for brute force detection
      const bruteForceResult = await recordFailedAttempt(
        userEmail,
        "pin_update",
        PIN_BRUTE_FORCE_CONFIG
      );

      // SECURITY: Log failed PIN verification attempts for security monitoring
      await putAudit({
        type: "pin_verification_failed",
        registration_id: reg.registration_id,
        email: userEmail,
        failed_at: new Date().toISOString(),
        attempts_remaining: bruteForceResult.attemptsRemaining,
        now_blocked: bruteForceResult.blocked
      }, requestId);

      // If this attempt caused a block, return 429
      if (bruteForceResult.blocked) {
        return {
          statusCode: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(PIN_BRUTE_FORCE_CONFIG.blockDurationSeconds),
          },
          body: JSON.stringify({
            message: "Too many failed PIN attempts. Account temporarily locked.",
            retryAfter: PIN_BRUTE_FORCE_CONFIG.blockDurationSeconds
          })
        };
      }

      return badRequest(`Current PIN is incorrect. ${bruteForceResult.attemptsRemaining} attempts remaining.`);
    }

    // PIN verified successfully - clear any failed attempt tracking
    await clearFailedAttempts(userEmail, "pin_update");

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
    if (error instanceof ValidationError || (error as any)?.name === 'ValidationError') {
      return badRequest((error as Error).message);
    }
    console.error('Failed to update PIN:', error);
    return internalError("Failed to update PIN");
  }
};
