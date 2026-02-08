/**
 * Rate Limiting Module - Phase 9 Security Hardening
 *
 * Provides comprehensive rate limiting with:
 * - Per-endpoint rate limits
 * - Per-user rate limits
 * - IP-based rate limits
 * - Sliding window algorithm
 * - Distributed rate limiting via DynamoDB
 * - Brute force detection
 */

import { DynamoDBClient, UpdateItemCommand, GetItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { APIGatewayProxyEventV2 } from "aws-lambda";
import { createHash } from "crypto";
import { logSecurityEvent, SecurityEventType, SecuritySeverity, extractSecurityContext } from "./security";

const ddb = new DynamoDBClient({});
const TABLE_RATE_LIMITS = process.env.TABLE_RATE_LIMITS || process.env.TABLE_AUDIT;

/**
 * Rate limit configuration for an endpoint
 */
export interface RateLimitConfig {
  // Maximum requests allowed in the window
  maxRequests: number;
  // Window size in seconds
  windowSeconds: number;
  // Optional: Per-user limit (if different from general limit)
  perUserLimit?: number;
  // Optional: Per-IP limit (if different from general limit)
  perIpLimit?: number;
  // Optional: Burst allowance (extra requests allowed in short bursts)
  burstAllowance?: number;
  // Optional: Cost multiplier for this endpoint (for weighted rate limiting)
  costMultiplier?: number;
  // Optional: Skip rate limiting for authenticated users
  skipForAuthenticated?: boolean;
  // Optional: Skip rate limiting for admin users
  skipForAdmin?: boolean;
}

/**
 * Predefined rate limit configurations for common endpoints
 */
export const RATE_LIMIT_CONFIGS: Record<string, RateLimitConfig> = {
  // Authentication endpoints (strict limits to prevent brute force)
  "auth:login": {
    maxRequests: 5,
    windowSeconds: 60,
    perIpLimit: 10,
    burstAllowance: 2,
  },

  // PIN verification endpoints (very strict - prevent brute force)
  "pin:verify": {
    maxRequests: 5,
    windowSeconds: 300, // 5 minutes
    perIpLimit: 10,
    perUserLimit: 5,
  },
  "pin:update": {
    maxRequests: 3,
    windowSeconds: 300, // 5 minutes
    perIpLimit: 5,
    perUserLimit: 3,
  },
  "pin:disable": {
    maxRequests: 3,
    windowSeconds: 300, // 5 minutes
    perIpLimit: 5,
    perUserLimit: 3,
  },
  "auth:password_reset": {
    maxRequests: 3,
    windowSeconds: 300, // 5 minutes
    perIpLimit: 5,
  },
  "auth:verify": {
    maxRequests: 10,
    windowSeconds: 60,
  },

  // Registration endpoints
  "register:submit": {
    maxRequests: 3,
    windowSeconds: 3600, // 1 hour
    perIpLimit: 10,
  },
  "register:waitlist": {
    maxRequests: 5,
    windowSeconds: 3600,
    perIpLimit: 20,
  },

  // Vault endpoints (moderate limits)
  "vault:enrollment": {
    maxRequests: 10,
    windowSeconds: 60,
    perUserLimit: 20,
    skipForAuthenticated: true,
  },
  "vault:auth": {
    maxRequests: 10,
    windowSeconds: 60,
    perUserLimit: 20,
  },
  "vault:backup": {
    maxRequests: 5,
    windowSeconds: 60,
    perUserLimit: 10,
  },

  // API endpoints (standard limits)
  "api:read": {
    maxRequests: 100,
    windowSeconds: 60,
    perUserLimit: 200,
    skipForAdmin: true,
  },
  "api:write": {
    maxRequests: 30,
    windowSeconds: 60,
    perUserLimit: 60,
    skipForAdmin: true,
  },

  // Admin endpoints (higher limits for admin users)
  "admin:read": {
    maxRequests: 200,
    windowSeconds: 60,
    skipForAdmin: true,
  },
  "admin:write": {
    maxRequests: 50,
    windowSeconds: 60,
    skipForAdmin: true,
  },

  // Public endpoints (moderate limits)
  "public:default": {
    maxRequests: 60,
    windowSeconds: 60,
    perIpLimit: 120,
  },

  // Agent connector shortlink resolution (strict - prevent brute force code guessing)
  "agent:resolve_shortlink": {
    maxRequests: 5,
    windowSeconds: 30,
    perIpLimit: 5,
  },

  // Default fallback
  "default": {
    maxRequests: 100,
    windowSeconds: 60,
    perIpLimit: 200,
  },
};

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  limitType?: "user" | "ip" | "endpoint";
}

/**
 * Hash an identifier for privacy-safe rate limit keys
 */
function hashIdentifier(value: string): string {
  return createHash("sha256").update(value.toLowerCase().trim()).digest("hex");
}

/**
 * Get client IP from API Gateway event
 */
function getClientIp(event: APIGatewayProxyEventV2): string {
  return event.requestContext.http?.sourceIp ||
    event.headers?.["x-forwarded-for"]?.split(",")[0]?.trim() ||
    "unknown";
}

/**
 * Get user identifier from event (if authenticated)
 */
function getUserId(event: APIGatewayProxyEventV2): string | undefined {
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  return claims?.["custom:user_guid"] || claims?.sub;
}

/**
 * Check if user is admin
 */
function isAdminUser(event: APIGatewayProxyEventV2): boolean {
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  const groups = claims?.["cognito:groups"];

  if (!groups) return false;

  if (Array.isArray(groups)) {
    return groups.includes("admin");
  }

  if (typeof groups === "string") {
    return groups.includes("admin");
  }

  return false;
}

/**
 * Atomic rate limit check and increment using DynamoDB
 * Uses sliding window algorithm for accurate rate limiting
 */
async function atomicRateLimitCheck(
  key: string,
  config: RateLimitConfig,
  costMultiplier: number = 1
): Promise<RateLimitResult> {
  if (!TABLE_RATE_LIMITS) {
    console.warn("TABLE_RATE_LIMITS not configured, rate limiting disabled");
    return { allowed: true, remaining: config.maxRequests, resetAt: 0 };
  }

  const now = Date.now();
  const windowMs = config.windowSeconds * 1000;
  const windowStart = now - windowMs;
  const ttl = Math.floor((now + windowMs * 2) / 1000); // Keep data for 2x window

  // Calculate effective limit (with burst allowance)
  const effectiveLimit = config.maxRequests + (config.burstAllowance || 0);
  const requestCost = Math.ceil(costMultiplier);

  try {
    // Atomic increment with condition
    const result = await ddb.send(new UpdateItemCommand({
      TableName: TABLE_RATE_LIMITS,
      Key: marshall({ id: key }),
      UpdateExpression: `
        SET #count = if_not_exists(#count, :zero) + :cost,
            #windowStart = if_not_exists(#windowStart, :now),
            #ttl = :ttl,
            #ts = :ts
      `,
      ConditionExpression: `
        attribute_not_exists(#count) OR
        #windowStart < :windowStart OR
        #count < :maxRequests
      `,
      ExpressionAttributeNames: {
        "#count": "request_count",
        "#windowStart": "window_start",
        "#ttl": "ttl",
        "#ts": "updated_at",
      },
      ExpressionAttributeValues: marshall({
        ":zero": 0,
        ":cost": requestCost,
        ":now": now,
        ":windowStart": windowStart,
        ":maxRequests": effectiveLimit,
        ":ttl": ttl,
        ":ts": new Date().toISOString(),
      }),
      ReturnValues: "ALL_NEW",
    }));

    const item = result.Attributes ? unmarshall(result.Attributes) : {};
    const currentCount = item.request_count || requestCost;
    const remaining = Math.max(0, effectiveLimit - currentCount);
    const resetAt = Math.floor((item.window_start || now) / 1000) + config.windowSeconds;

    return {
      allowed: true,
      remaining,
      resetAt,
    };
  } catch (error: any) {
    if (error.name === "ConditionalCheckFailedException") {
      // Rate limit exceeded
      // Get current state for accurate remaining/reset info
      try {
        const getResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_RATE_LIMITS,
          Key: marshall({ id: key }),
        }));

        const item = getResult.Item ? unmarshall(getResult.Item) : {};
        const windowStart = item.window_start || now;
        const resetAt = Math.floor(windowStart / 1000) + config.windowSeconds;
        const retryAfter = Math.max(0, resetAt - Math.floor(now / 1000));

        return {
          allowed: false,
          remaining: 0,
          resetAt,
          retryAfter,
        };
      } catch {
        // Fallback if we can't get current state
        return {
          allowed: false,
          remaining: 0,
          resetAt: Math.floor(now / 1000) + config.windowSeconds,
          retryAfter: config.windowSeconds,
        };
      }
    }

    // On other errors, allow the request (fail open for availability)
    console.warn("Rate limit check failed:", error);
    return { allowed: true, remaining: config.maxRequests, resetAt: 0 };
  }
}

/**
 * Main rate limiting function
 *
 * Checks multiple rate limit dimensions:
 * 1. Per-endpoint limit
 * 2. Per-user limit (if authenticated)
 * 3. Per-IP limit
 *
 * Returns the most restrictive result.
 */
export async function checkRateLimit(
  event: APIGatewayProxyEventV2,
  endpointKey: string,
  customConfig?: Partial<RateLimitConfig>
): Promise<RateLimitResult> {
  // Get configuration
  const baseConfig = RATE_LIMIT_CONFIGS[endpointKey] || RATE_LIMIT_CONFIGS["default"];
  const config: RateLimitConfig = { ...baseConfig, ...customConfig };

  // Check if rate limiting should be skipped
  const userId = getUserId(event);
  const isAdmin = isAdminUser(event);

  if (config.skipForAdmin && isAdmin) {
    return { allowed: true, remaining: config.maxRequests, resetAt: 0 };
  }

  if (config.skipForAuthenticated && userId) {
    return { allowed: true, remaining: config.maxRequests, resetAt: 0 };
  }

  const clientIp = getClientIp(event);
  const results: RateLimitResult[] = [];

  // Check per-endpoint limit
  const endpointHash = hashIdentifier(endpointKey);
  const endpointResult = await atomicRateLimitCheck(
    `RL#EP#${endpointHash}`,
    config,
    config.costMultiplier
  );
  results.push({ ...endpointResult, limitType: "endpoint" });

  // Check per-IP limit
  if (config.perIpLimit) {
    const ipHash = hashIdentifier(clientIp);
    const ipConfig = { ...config, maxRequests: config.perIpLimit };
    const ipResult = await atomicRateLimitCheck(
      `RL#IP#${ipHash}#${endpointHash}`,
      ipConfig,
      config.costMultiplier
    );
    results.push({ ...ipResult, limitType: "ip" });
  }

  // Check per-user limit (if authenticated)
  if (userId && config.perUserLimit) {
    const userHash = hashIdentifier(userId);
    const userConfig = { ...config, maxRequests: config.perUserLimit };
    const userResult = await atomicRateLimitCheck(
      `RL#USER#${userHash}#${endpointHash}`,
      userConfig,
      config.costMultiplier
    );
    results.push({ ...userResult, limitType: "user" });
  }

  // Return the most restrictive result
  const deniedResult = results.find(r => !r.allowed);
  if (deniedResult) {
    // Log rate limit exceeded
    const context = extractSecurityContext(event);
    await logSecurityEvent({
      type: SecurityEventType.RATE_LIMIT_EXCEEDED,
      severity: SecuritySeverity.MEDIUM,
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      sourceIp: context.sourceIp,
      userAgent: context.userAgent,
      userId: userId,
      endpoint: context.endpoint,
      method: context.method,
      message: `Rate limit exceeded for ${endpointKey} (${deniedResult.limitType} limit)`,
      details: {
        endpointKey,
        limitType: deniedResult.limitType,
        retryAfter: deniedResult.retryAfter,
      },
      blocked: true,
    });

    return deniedResult;
  }

  // Return result with lowest remaining count
  return results.reduce((min, curr) => curr.remaining < min.remaining ? curr : min);
}

/**
 * Brute force detection - tracks failed attempts and blocks after threshold
 */
export interface BruteForceConfig {
  maxFailedAttempts: number;
  windowSeconds: number;
  blockDurationSeconds: number;
}

const DEFAULT_BRUTE_FORCE_CONFIG: BruteForceConfig = {
  maxFailedAttempts: 5,
  windowSeconds: 300, // 5 minutes
  blockDurationSeconds: 900, // 15 minutes
};

/**
 * Stricter brute force config for PIN verification
 * PINs are 4-6 digits (10,000 to 1,000,000 combinations)
 * We must be extra strict to prevent enumeration
 */
export const PIN_BRUTE_FORCE_CONFIG: BruteForceConfig = {
  maxFailedAttempts: 5,
  windowSeconds: 300, // 5 minutes
  blockDurationSeconds: 1800, // 30 minutes - longer block for PIN attempts
};

/**
 * Record a failed attempt for brute force detection
 */
export async function recordFailedAttempt(
  identifier: string,
  attemptType: string,
  config: BruteForceConfig = DEFAULT_BRUTE_FORCE_CONFIG
): Promise<{ blocked: boolean; attemptsRemaining: number }> {
  if (!TABLE_RATE_LIMITS) {
    return { blocked: false, attemptsRemaining: config.maxFailedAttempts };
  }

  const key = `BF#${attemptType}#${hashIdentifier(identifier)}`;
  const now = Date.now();
  const ttl = Math.floor((now + config.blockDurationSeconds * 1000) / 1000);

  try {
    const result = await ddb.send(new UpdateItemCommand({
      TableName: TABLE_RATE_LIMITS,
      Key: marshall({ id: key }),
      UpdateExpression: `
        SET #count = if_not_exists(#count, :zero) + :one,
            #firstAttempt = if_not_exists(#firstAttempt, :now),
            #lastAttempt = :now,
            #ttl = :ttl
      `,
      ExpressionAttributeNames: {
        "#count": "failed_count",
        "#firstAttempt": "first_attempt",
        "#lastAttempt": "last_attempt",
        "#ttl": "ttl",
      },
      ExpressionAttributeValues: marshall({
        ":zero": 0,
        ":one": 1,
        ":now": now,
        ":ttl": ttl,
      }),
      ReturnValues: "ALL_NEW",
    }));

    const item = result.Attributes ? unmarshall(result.Attributes) : {};
    const failedCount = item.failed_count || 1;
    const firstAttempt = item.first_attempt || now;

    // Check if within window
    const windowExpired = (now - firstAttempt) > config.windowSeconds * 1000;
    if (windowExpired) {
      // Reset the counter
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_RATE_LIMITS,
        Key: marshall({ id: key }),
        UpdateExpression: "SET #count = :one, #firstAttempt = :now",
        ExpressionAttributeNames: {
          "#count": "failed_count",
          "#firstAttempt": "first_attempt",
        },
        ExpressionAttributeValues: marshall({
          ":one": 1,
          ":now": now,
        }),
      }));
      return { blocked: false, attemptsRemaining: config.maxFailedAttempts - 1 };
    }

    const blocked = failedCount >= config.maxFailedAttempts;
    const attemptsRemaining = Math.max(0, config.maxFailedAttempts - failedCount);

    return { blocked, attemptsRemaining };
  } catch (error) {
    console.warn("Failed to record brute force attempt:", error);
    return { blocked: false, attemptsRemaining: config.maxFailedAttempts };
  }
}

/**
 * Check if identifier is currently blocked due to brute force
 */
export async function isBlockedByBruteForce(
  identifier: string,
  attemptType: string,
  config: BruteForceConfig = DEFAULT_BRUTE_FORCE_CONFIG
): Promise<boolean> {
  if (!TABLE_RATE_LIMITS) {
    return false;
  }

  const key = `BF#${attemptType}#${hashIdentifier(identifier)}`;

  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_RATE_LIMITS,
      Key: marshall({ id: key }),
    }));

    if (!result.Item) {
      return false;
    }

    const item = unmarshall(result.Item);
    const failedCount = item.failed_count || 0;
    const firstAttempt = item.first_attempt || 0;
    const now = Date.now();

    // Check if within window and over threshold
    const windowExpired = (now - firstAttempt) > config.windowSeconds * 1000;
    if (windowExpired) {
      return false;
    }

    return failedCount >= config.maxFailedAttempts;
  } catch (error) {
    console.warn("Failed to check brute force block:", error);
    return false;
  }
}

/**
 * Clear failed attempts (e.g., after successful login)
 */
export async function clearFailedAttempts(
  identifier: string,
  attemptType: string
): Promise<void> {
  if (!TABLE_RATE_LIMITS) {
    return;
  }

  const key = `BF#${attemptType}#${hashIdentifier(identifier)}`;

  try {
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_RATE_LIMITS,
      Key: marshall({ id: key }),
      UpdateExpression: "SET #count = :zero",
      ExpressionAttributeNames: {
        "#count": "failed_count",
      },
      ExpressionAttributeValues: marshall({
        ":zero": 0,
      }),
    }));
  } catch (error) {
    console.warn("Failed to clear brute force attempts:", error);
  }
}

/**
 * Get rate limit headers for response
 */
export function getRateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    "X-RateLimit-Remaining": String(result.remaining),
    "X-RateLimit-Reset": String(result.resetAt),
  };

  if (!result.allowed && result.retryAfter) {
    headers["Retry-After"] = String(result.retryAfter);
  }

  return headers;
}
