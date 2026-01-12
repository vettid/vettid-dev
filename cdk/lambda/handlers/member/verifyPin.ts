import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import {
  ddb,
  TABLES,
  ok,
  badRequest,
  notFound,
  internalError,
  tooManyRequests,
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
  PIN_BRUTE_FORCE_CONFIG,
  getRateLimitHeaders
} from "../../common/rateLimit";
import { QueryCommand } from "@aws-sdk/client-dynamodb";
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
    const isBlocked = await isBlockedByBruteForce(userEmail, "pin_verify", PIN_BRUTE_FORCE_CONFIG);
    if (isBlocked) {
      await putAudit({
        type: "pin_verification_blocked",
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

    // Check if PIN is enabled
    if (!reg.pin_enabled) {
      // PIN not enabled - return success (no verification needed)
      return ok({
        verified: true,
        pin_enabled: false,
        message: "PIN is not enabled"
      });
    }

    // Verify PIN matches stored hash using timing-safe comparison
    const pinHash = hashPin(pin);
    if (!secureCompare(pinHash, reg.pin_hash)) {
      // SECURITY: Record failed attempt for brute force detection
      const bruteForceResult = await recordFailedAttempt(
        userEmail,
        "pin_verify",
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
            verified: false,
            message: "Too many failed PIN attempts. Account temporarily locked.",
            retryAfter: PIN_BRUTE_FORCE_CONFIG.blockDurationSeconds
          })
        };
      }

      return ok({
        verified: false,
        pin_enabled: true,
        message: "Incorrect PIN",
        attemptsRemaining: bruteForceResult.attemptsRemaining
      });
    }

    // PIN verified successfully - clear any failed attempt tracking
    await clearFailedAttempts(userEmail, "pin_verify");

    await putAudit({
      type: "pin_verification_success",
      registration_id: reg.registration_id,
      email: userEmail,
      verified_at: new Date().toISOString()
    }, requestId);

    return ok({
      verified: true,
      pin_enabled: true,
      message: "PIN verified successfully"
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return badRequest(error.message);
    }
    console.error('Failed to verify PIN:', error);
    return internalError("Failed to verify PIN");
  }
};
