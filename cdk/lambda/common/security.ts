/**
 * Security Module - Phase 9 Security Hardening
 *
 * This module provides security primitives for:
 * - Request signing validation
 * - Replay attack prevention
 * - Enhanced security headers
 * - Security event audit logging
 * - Input sanitization enhancements
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { createHmac, createHash, timingSafeEqual, randomBytes } from "crypto";
import { DynamoDBClient, PutItemCommand, GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

// Environment configuration
const REQUEST_SIGNING_SECRET = process.env.REQUEST_SIGNING_SECRET;
const TABLE_SECURITY_EVENTS = process.env.TABLE_SECURITY_EVENTS || process.env.TABLE_AUDIT;
const TABLE_NONCES = process.env.TABLE_NONCES || process.env.TABLE_AUDIT;

// Security configuration constants
const NONCE_EXPIRY_SECONDS = 300; // 5 minutes
const REQUEST_TIMESTAMP_TOLERANCE_SECONDS = 300; // 5 minutes
const MAX_REQUEST_BODY_SIZE = 1024 * 1024; // 1MB

/**
 * Security event types for audit logging
 */
export enum SecurityEventType {
  // Authentication events
  AUTH_SUCCESS = "AUTH_SUCCESS",
  AUTH_FAILURE = "AUTH_FAILURE",
  TOKEN_INVALID = "TOKEN_INVALID",
  TOKEN_EXPIRED = "TOKEN_EXPIRED",
  TOKEN_REPLAY = "TOKEN_REPLAY",

  // Authorization events
  AUTHZ_DENIED = "AUTHZ_DENIED",
  PRIVILEGE_ESCALATION_ATTEMPT = "PRIVILEGE_ESCALATION_ATTEMPT",
  IDOR_ATTEMPT = "IDOR_ATTEMPT",

  // Rate limiting events
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
  BRUTE_FORCE_DETECTED = "BRUTE_FORCE_DETECTED",

  // Input validation events
  INJECTION_ATTEMPT = "INJECTION_ATTEMPT",
  XSS_ATTEMPT = "XSS_ATTEMPT",
  PATH_TRAVERSAL_ATTEMPT = "PATH_TRAVERSAL_ATTEMPT",
  MALFORMED_INPUT = "MALFORMED_INPUT",
  OVERSIZED_REQUEST = "OVERSIZED_REQUEST",

  // Request integrity events
  SIGNATURE_INVALID = "SIGNATURE_INVALID",
  SIGNATURE_MISSING = "SIGNATURE_MISSING",
  NONCE_REUSED = "NONCE_REUSED",
  TIMESTAMP_INVALID = "TIMESTAMP_INVALID",
  REPLAY_ATTACK = "REPLAY_ATTACK",

  // Cryptographic events
  CRYPTO_FAILURE = "CRYPTO_FAILURE",
  KEY_DERIVATION_FAILURE = "KEY_DERIVATION_FAILURE",

  // Session events
  SESSION_HIJACK_ATTEMPT = "SESSION_HIJACK_ATTEMPT",
  CONCURRENT_SESSION_VIOLATION = "CONCURRENT_SESSION_VIOLATION",

  // Network security events
  CORS_VIOLATION = "CORS_VIOLATION",
  ORIGIN_MISMATCH = "ORIGIN_MISMATCH",
  SUSPICIOUS_USER_AGENT = "SUSPICIOUS_USER_AGENT",

  // Data protection events
  PII_ACCESS = "PII_ACCESS",
  SENSITIVE_DATA_EXPORT = "SENSITIVE_DATA_EXPORT",
  BACKUP_ACCESS = "BACKUP_ACCESS",

  // General security events
  SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
  SECURITY_CONFIG_ERROR = "SECURITY_CONFIG_ERROR",
}

/**
 * Severity levels for security events
 */
export enum SecuritySeverity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

/**
 * Security event interface for audit logging
 */
export interface SecurityEvent {
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: string;
  requestId: string;
  sourceIp: string;
  userAgent?: string;
  userId?: string;
  email?: string;
  endpoint?: string;
  method?: string;
  message: string;
  details?: Record<string, any>;
  blocked: boolean;
}

/**
 * Log a security event to the audit table
 */
export async function logSecurityEvent(event: SecurityEvent): Promise<void> {
  if (!TABLE_SECURITY_EVENTS) {
    console.warn("TABLE_SECURITY_EVENTS not configured, logging to console only");
    console.log("SECURITY_EVENT:", JSON.stringify(event));
    return;
  }

  try {
    const item = {
      id: `SEC#${event.requestId}#${Date.now()}`,
      type: "SECURITY_EVENT",
      event_type: event.type,
      severity: event.severity,
      ts: event.timestamp,
      request_id: event.requestId,
      source_ip: event.sourceIp,
      user_agent: event.userAgent || "unknown",
      user_id: event.userId || "anonymous",
      email_hash: event.email ? createHash("sha256").update(event.email.toLowerCase()).digest("hex").substring(0, 12) : undefined,
      endpoint: event.endpoint,
      method: event.method,
      message: event.message,
      details: event.details,
      blocked: event.blocked,
      ttl: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60, // 90 days retention
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SECURITY_EVENTS,
      Item: marshall(item, { removeUndefinedValues: true }),
    }));

    // Also log to CloudWatch for real-time alerting
    if (event.severity === SecuritySeverity.HIGH || event.severity === SecuritySeverity.CRITICAL) {
      console.error("SECURITY_ALERT:", JSON.stringify(event));
    } else {
      console.log("SECURITY_EVENT:", JSON.stringify({
        type: event.type,
        severity: event.severity,
        message: event.message,
        blocked: event.blocked,
      }));
    }
  } catch (error) {
    console.error("Failed to log security event:", error);
    // Don't throw - security logging should not break the main flow
  }
}

/**
 * Extract security context from API Gateway event
 */
export function extractSecurityContext(event: APIGatewayProxyEventV2): {
  requestId: string;
  sourceIp: string;
  userAgent: string;
  endpoint: string;
  method: string;
  origin?: string;
} {
  return {
    requestId: event.requestContext.requestId,
    sourceIp: event.requestContext.http?.sourceIp || event.headers?.["x-forwarded-for"]?.split(",")[0]?.trim() || "unknown",
    userAgent: event.headers?.["user-agent"] || "unknown",
    endpoint: event.rawPath || event.requestContext.http?.path || "unknown",
    method: event.requestContext.http?.method || "unknown",
    origin: event.headers?.origin || event.headers?.Origin,
  };
}

/**
 * Request signature validation for replay attack prevention
 *
 * Expected headers:
 * - X-Request-Signature: HMAC-SHA256 signature of the request
 * - X-Request-Timestamp: Unix timestamp (seconds) when request was created
 * - X-Request-Nonce: Unique nonce for this request
 *
 * Signature = HMAC-SHA256(secret, timestamp + nonce + method + path + bodyHash)
 */
export interface SignatureValidationResult {
  valid: boolean;
  error?: string;
  eventType?: SecurityEventType;
}

/**
 * Validate request signature for replay attack prevention
 */
export async function validateRequestSignature(
  event: APIGatewayProxyEventV2
): Promise<SignatureValidationResult> {
  // Skip validation if signing is not configured
  if (!REQUEST_SIGNING_SECRET) {
    return { valid: true };
  }

  const signature = event.headers?.["x-request-signature"];
  const timestamp = event.headers?.["x-request-timestamp"];
  const nonce = event.headers?.["x-request-nonce"];

  // Check for required headers
  if (!signature) {
    return {
      valid: false,
      error: "Missing request signature",
      eventType: SecurityEventType.SIGNATURE_MISSING,
    };
  }

  if (!timestamp || !nonce) {
    return {
      valid: false,
      error: "Missing timestamp or nonce",
      eventType: SecurityEventType.SIGNATURE_INVALID,
    };
  }

  // Validate timestamp is within tolerance
  const requestTime = parseInt(timestamp, 10);
  const currentTime = Math.floor(Date.now() / 1000);
  const timeDiff = Math.abs(currentTime - requestTime);

  if (isNaN(requestTime) || timeDiff > REQUEST_TIMESTAMP_TOLERANCE_SECONDS) {
    return {
      valid: false,
      error: "Request timestamp out of range",
      eventType: SecurityEventType.TIMESTAMP_INVALID,
    };
  }

  // Check nonce hasn't been used (replay attack prevention)
  const nonceUsed = await checkAndStoreNonce(nonce, requestTime);
  if (nonceUsed) {
    return {
      valid: false,
      error: "Nonce already used (potential replay attack)",
      eventType: SecurityEventType.NONCE_REUSED,
    };
  }

  // Calculate expected signature
  const method = event.requestContext.http?.method || "GET";
  const path = event.rawPath || "/";
  const bodyHash = event.body
    ? createHash("sha256").update(event.body).digest("hex")
    : createHash("sha256").update("").digest("hex");

  const signaturePayload = `${timestamp}${nonce}${method}${path}${bodyHash}`;
  const expectedSignature = createHmac("sha256", REQUEST_SIGNING_SECRET)
    .update(signaturePayload)
    .digest("hex");

  // Timing-safe comparison
  const signatureBuffer = Buffer.from(signature, "hex");
  const expectedBuffer = Buffer.from(expectedSignature, "hex");

  if (signatureBuffer.length !== expectedBuffer.length) {
    return {
      valid: false,
      error: "Invalid signature",
      eventType: SecurityEventType.SIGNATURE_INVALID,
    };
  }

  if (!timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return {
      valid: false,
      error: "Invalid signature",
      eventType: SecurityEventType.SIGNATURE_INVALID,
    };
  }

  return { valid: true };
}

/**
 * Check if nonce was already used and store it if not
 * Returns true if nonce was already used (replay attack)
 */
async function checkAndStoreNonce(nonce: string, timestamp: number): Promise<boolean> {
  if (!TABLE_NONCES) {
    // If table not configured, skip nonce checking (less secure)
    console.warn("TABLE_NONCES not configured, skipping nonce validation");
    return false;
  }

  const nonceKey = `NONCE#${nonce}`;
  const ttl = timestamp + NONCE_EXPIRY_SECONDS;

  try {
    // Try to write the nonce with a condition that it doesn't exist
    await ddb.send(new PutItemCommand({
      TableName: TABLE_NONCES,
      Item: marshall({
        id: nonceKey,
        type: "NONCE",
        ts: new Date().toISOString(),
        ttl,
      }),
      ConditionExpression: "attribute_not_exists(id)",
    }));

    return false; // Nonce is new
  } catch (error: any) {
    if (error.name === "ConditionalCheckFailedException") {
      return true; // Nonce was already used
    }
    // On other errors, log and allow (fail open for availability)
    console.warn("Nonce check failed:", error);
    return false;
  }
}

/**
 * Generate a cryptographically secure nonce for request signing
 */
export function generateNonce(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Generate a request signature for client-side use
 */
export function generateRequestSignature(
  secret: string,
  timestamp: number,
  nonce: string,
  method: string,
  path: string,
  body?: string
): string {
  const bodyHash = body
    ? createHash("sha256").update(body).digest("hex")
    : createHash("sha256").update("").digest("hex");

  const signaturePayload = `${timestamp}${nonce}${method}${path}${bodyHash}`;
  return createHmac("sha256", secret).update(signaturePayload).digest("hex");
}

/**
 * Validate request body size
 */
export function validateRequestSize(event: APIGatewayProxyEventV2): SignatureValidationResult {
  const contentLength = parseInt(event.headers?.["content-length"] || "0", 10);
  const bodyLength = event.body?.length || 0;
  const actualLength = Math.max(contentLength, bodyLength);

  if (actualLength > MAX_REQUEST_BODY_SIZE) {
    return {
      valid: false,
      error: `Request body too large (${actualLength} bytes, max ${MAX_REQUEST_BODY_SIZE})`,
      eventType: SecurityEventType.OVERSIZED_REQUEST,
    };
  }

  return { valid: true };
}

/**
 * Detect common injection patterns in input
 */
export function detectInjectionPatterns(input: string): {
  detected: boolean;
  type?: string;
  pattern?: string;
} {
  if (!input || typeof input !== "string") {
    return { detected: false };
  }

  const patterns: { type: string; regex: RegExp }[] = [
    // SQL injection patterns
    { type: "SQL_INJECTION", regex: /('|"|;|--|\/\*|\*\/|xp_|sp_|0x|union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set)/i },
    // NoSQL injection patterns (MongoDB/DynamoDB)
    { type: "NOSQL_INJECTION", regex: /(\$where|\$ne|\$gt|\$lt|\$regex|\$in|\$nin|\$or|\$and|{\s*"\$)/i },
    // Command injection patterns
    { type: "COMMAND_INJECTION", regex: /(;|\||`|\$\(|&&|\|\||>|<|eval\(|exec\(|system\()/i },
    // LDAP injection patterns
    { type: "LDAP_INJECTION", regex: /([)(|*\\]|\x00|\x0a|\x0d)/i },
    // XPath injection patterns
    { type: "XPATH_INJECTION", regex: /(\/\/|\.\.\/|\[.*=.*\]|ancestor::|child::|parent::)/i },
    // Template injection patterns
    { type: "TEMPLATE_INJECTION", regex: /(\{\{|\}\}|\$\{|<%|%>|\[\[|\]\])/i },
  ];

  for (const { type, regex } of patterns) {
    if (regex.test(input)) {
      return {
        detected: true,
        type,
        pattern: regex.source,
      };
    }
  }

  return { detected: false };
}

/**
 * Detect XSS patterns in input
 */
export function detectXSSPatterns(input: string): {
  detected: boolean;
  pattern?: string;
} {
  if (!input || typeof input !== "string") {
    return { detected: false };
  }

  const patterns: RegExp[] = [
    // Script tags
    /<script[\s\S]*?>/i,
    /<\/script>/i,
    // Event handlers
    /\bon\w+\s*=/i,
    // javascript: protocol
    /javascript:/i,
    // data: protocol (for HTML)
    /data:text\/html/i,
    // vbscript: protocol
    /vbscript:/i,
    // Expression (IE)
    /expression\s*\(/i,
    // SVG vectors
    /<svg[\s\S]*?onload/i,
    // Object/embed tags
    /<(object|embed|applet|iframe|frame|frameset|layer|ilayer|bgsound|link|meta|style|base|body|xml|import)/i,
    // HTML encoded variants
    /&#x?[0-9a-f]+;/i,
    // Base64 encoded data URIs
    /data:[^,]*;base64,/i,
  ];

  for (const regex of patterns) {
    if (regex.test(input)) {
      return {
        detected: true,
        pattern: regex.source,
      };
    }
  }

  return { detected: false };
}

/**
 * Detect path traversal attempts
 */
export function detectPathTraversal(input: string): {
  detected: boolean;
  pattern?: string;
} {
  if (!input || typeof input !== "string") {
    return { detected: false };
  }

  const patterns: RegExp[] = [
    // Standard path traversal
    /\.\.\//,
    /\.\.\\/,
    // URL encoded variants
    /%2e%2e%2f/i,
    /%2e%2e\//i,
    /%2e%2e%5c/i,
    // Double URL encoded
    /%252e%252e%252f/i,
    // Unicode variants
    /\.\.%c0%af/i,
    /\.\.%c1%9c/i,
    // Null byte injection
    /%00/,
  ];

  for (const regex of patterns) {
    if (regex.test(input)) {
      return {
        detected: true,
        pattern: regex.source,
      };
    }
  }

  return { detected: false };
}

/**
 * Comprehensive input security validation
 * Returns security event if malicious input detected
 */
export function validateInputSecurity(
  input: string,
  fieldName: string
): { safe: boolean; event?: Partial<SecurityEvent> } {
  // Check for injection patterns
  const injection = detectInjectionPatterns(input);
  if (injection.detected) {
    return {
      safe: false,
      event: {
        type: SecurityEventType.INJECTION_ATTEMPT,
        severity: SecuritySeverity.HIGH,
        message: `Injection attempt detected in ${fieldName}`,
        details: { field: fieldName, injectionType: injection.type, pattern: injection.pattern },
        blocked: true,
      },
    };
  }

  // Check for XSS patterns
  const xss = detectXSSPatterns(input);
  if (xss.detected) {
    return {
      safe: false,
      event: {
        type: SecurityEventType.XSS_ATTEMPT,
        severity: SecuritySeverity.HIGH,
        message: `XSS attempt detected in ${fieldName}`,
        details: { field: fieldName, pattern: xss.pattern },
        blocked: true,
      },
    };
  }

  // Check for path traversal
  const traversal = detectPathTraversal(input);
  if (traversal.detected) {
    return {
      safe: false,
      event: {
        type: SecurityEventType.PATH_TRAVERSAL_ATTEMPT,
        severity: SecuritySeverity.HIGH,
        message: `Path traversal attempt detected in ${fieldName}`,
        details: { field: fieldName, pattern: traversal.pattern },
        blocked: true,
      },
    };
  }

  return { safe: true };
}

/**
 * Enhanced security headers for API responses
 */
export function getSecurityHeaders(requestOrigin?: string): Record<string, string> {
  // Determine allowed origin
  const allowedOrigins = (process.env.CORS_ORIGIN || "https://vettid.dev").split(",").map(o => o.trim());
  const allowOrigin = requestOrigin && allowedOrigins.includes(requestOrigin)
    ? requestOrigin
    : allowedOrigins[0];

  return {
    // CORS headers
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Request-Signature,X-Request-Timestamp,X-Request-Nonce",
    "Access-Control-Allow-Methods": "OPTIONS,GET,POST,PUT,DELETE",
    "Access-Control-Max-Age": "86400", // 24 hours preflight cache

    // Security headers
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",

    // Cache control for sensitive data
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Expires": "0",

    // Content type
    "Content-Type": "application/json",
  };
}

/**
 * Security-aware error response
 */
export function securityError(
  statusCode: number,
  message: string,
  requestOrigin?: string
): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: getSecurityHeaders(requestOrigin),
    body: JSON.stringify({ error: message }),
  };
}

/**
 * Middleware-style security validation for handlers
 * Call at the beginning of each handler for comprehensive security checks
 */
export async function validateRequestSecurity(
  event: APIGatewayProxyEventV2
): Promise<{ passed: boolean; response?: APIGatewayProxyResultV2 }> {
  const context = extractSecurityContext(event);
  const origin = event.headers?.origin || event.headers?.Origin;

  // Validate request size
  const sizeValidation = validateRequestSize(event);
  if (!sizeValidation.valid) {
    await logSecurityEvent({
      type: sizeValidation.eventType!,
      severity: SecuritySeverity.MEDIUM,
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      sourceIp: context.sourceIp,
      userAgent: context.userAgent,
      endpoint: context.endpoint,
      method: context.method,
      message: sizeValidation.error!,
      blocked: true,
    });

    return {
      passed: false,
      response: securityError(413, "Request too large", origin),
    };
  }

  // Validate request signature (if configured)
  const signatureValidation = await validateRequestSignature(event);
  if (!signatureValidation.valid) {
    await logSecurityEvent({
      type: signatureValidation.eventType!,
      severity: SecuritySeverity.HIGH,
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      sourceIp: context.sourceIp,
      userAgent: context.userAgent,
      endpoint: context.endpoint,
      method: context.method,
      message: signatureValidation.error!,
      blocked: true,
    });

    return {
      passed: false,
      response: securityError(401, "Invalid request signature", origin),
    };
  }

  // Validate body content if present
  if (event.body) {
    const bodyValidation = validateInputSecurity(event.body, "request_body");
    if (!bodyValidation.safe && bodyValidation.event) {
      await logSecurityEvent({
        ...bodyValidation.event,
        timestamp: new Date().toISOString(),
        requestId: context.requestId,
        sourceIp: context.sourceIp,
        userAgent: context.userAgent,
        endpoint: context.endpoint,
        method: context.method,
      } as SecurityEvent);

      return {
        passed: false,
        response: securityError(400, "Invalid request content", origin),
      };
    }
  }

  return { passed: true };
}
