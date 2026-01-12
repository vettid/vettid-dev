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
    const isBlocked = await isBlockedByBruteForce(userEmail, "pin_disable", PIN_BRUTE_FORCE_CONFIG);
    if (isBlocked) {
      await putAudit({
        type: "pin_disable_blocked",
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

    // Parse request body to get current PIN
    const body = parseJsonBody(event);
    const currentPin = body.currentPin;

    if (!currentPin || typeof currentPin !== 'string') {
      return badRequest("Current PIN is required");
    }

    if (!isValidPin(currentPin)) {
      return badRequest("Current PIN must be 4-6 digits");
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
      return badRequest("PIN is not enabled");
    }

    // SECURITY: Verify current PIN matches stored hash using timing-safe comparison
    // This prevents timing attacks that could leak information about the correct PIN
    const currentPinHash = hashPin(currentPin);
    if (!secureCompare(currentPinHash, reg.pin_hash)) {
      // SECURITY: Record failed attempt for brute force detection
      const bruteForceResult = await recordFailedAttempt(
        userEmail,
        "pin_disable",
        PIN_BRUTE_FORCE_CONFIG
      );

      // SECURITY: Log failed PIN verification attempts for security monitoring
      await putAudit({
        type: "pin_verification_failed_on_disable",
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
    await clearFailedAttempts(userEmail, "pin_disable");

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
    if (error instanceof ValidationError || (error as any)?.name === 'ValidationError') {
      return badRequest((error as Error).message);
    }
    console.error('Failed to disable PIN:', error);
    return internalError("Failed to disable PIN");
  }
};
