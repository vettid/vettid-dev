import { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { SESClient, SendTemplatedEmailCommand } from "@aws-sdk/client-ses";
import { CognitoIdentityProviderClient, AdminGetUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { randomUUID, createHash, timingSafeEqual } from "crypto";

export const ddb = new DynamoDBClient({});
export const ses = new SESClient({});
export const cognito = new CognitoIdentityProviderClient({});

export const TABLES = {
  invites: process.env.TABLE_INVITES!,
  registrations: process.env.TABLE_REGISTRATIONS!,
  audit: process.env.TABLE_AUDIT!,
};

export const USER_POOL_ID = process.env.USER_POOL_ID!;

/**
 * Custom error classes
 */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/**
 * Timing-safe string comparison to prevent timing attacks
 * SECURITY: Always use this for comparing tokens, secrets, and user-provided values
 * against stored values to prevent attackers from inferring information via response times.
 * @param a First string
 * @param b Second string
 * @returns true if strings are equal, false otherwise
 */
export function secureCompare(a: string, b: string): boolean {
  // Convert strings to Buffers for timingSafeEqual
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // If lengths differ, we still need to do a constant-time operation
  // to avoid leaking length information
  if (bufA.length !== bufB.length) {
    // Compare against itself to maintain timing, then return false
    timingSafeEqual(bufA, bufA);
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Generate cryptographically secure IDs (replaces Math.random())
 * @param prefix Optional prefix to prepend to the ID
 * @param length Length of random portion (default 16 for high entropy)
 */
export function generateSecureId(prefix?: string, length: number = 16): string {
  const id = randomUUID().replace(/-/g, '').substring(0, Math.min(length, 32)).toUpperCase();
  return prefix ? `${prefix}-${id}` : id;
}

/**
 * Audit logging with secure ID generation and request correlation
 */
export async function putAudit(entry: Record<string, any>, requestId?: string): Promise<void> {
  entry.id = generateSecureId('AUDIT');
  entry.ts = new Date().toISOString();
  if (requestId) {
    entry.request_id = requestId;
  }
  try {
    await ddb.send(new PutItemCommand({ TableName: TABLES.audit, Item: marshall(entry) }));
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

/**
 * Extract request ID from API Gateway event for tracing
 */
export function getRequestId(event: APIGatewayProxyEventV2): string {
  return event.requestContext.requestId;
}

/**
 * Send templated email with error handling
 */
export async function sendTemplateEmail(to: string, template: string, data: any): Promise<boolean> {
  try {
    await ses.send(new SendTemplatedEmailCommand({
      Source: process.env.SES_FROM!,
      Destination: { ToAddresses: [to] },
      Template: template,
      TemplateData: JSON.stringify(data),
    }));
    return true;
  } catch (error) {
    console.error(`Failed to send email to ${to}:`, error);
    return false;
  }
}

/**
 * HTTP Response helpers
 * Note: These helpers don't accept requestOrigin parameter because
 * the CORS headers are set by API Gateway. These are for Lambda responses.
 */
export function ok(body: any): APIGatewayProxyResultV2 {
  return { statusCode: 200, headers: cors(), body: JSON.stringify(body) };
}

export function created(body: any): APIGatewayProxyResultV2 {
  return { statusCode: 201, headers: cors(), body: JSON.stringify(body) };
}

export function badRequest(message: string): APIGatewayProxyResultV2 {
  return { statusCode: 400, headers: cors(), body: JSON.stringify({ message }) };
}

export function unauthorized(message: string = "Unauthorized"): APIGatewayProxyResultV2 {
  return { statusCode: 401, headers: cors(), body: JSON.stringify({ message }) };
}

export function forbidden(message: string = "Forbidden"): APIGatewayProxyResultV2 {
  return { statusCode: 403, headers: cors(), body: JSON.stringify({ message }) };
}

export function notFound(message: string = "Not found"): APIGatewayProxyResultV2 {
  return { statusCode: 404, headers: cors(), body: JSON.stringify({ message }) };
}

export function conflict(message: string): APIGatewayProxyResultV2 {
  return { statusCode: 409, headers: cors(), body: JSON.stringify({ message }) };
}

export function internalError(message: string = "Internal server error"): APIGatewayProxyResultV2 {
  return { statusCode: 500, headers: cors(), body: JSON.stringify({ message }) };
}

export function tooManyRequests(message: string = "Too many requests. Please try again later."): APIGatewayProxyResultV2 {
  return { statusCode: 429, headers: cors(), body: JSON.stringify({ message }) };
}

/**
 * Test email domain patterns that bypass rate limiting
 * SECURITY: Only use for automated testing domains that you control
 * These emails should NOT be used for production user accounts
 */
const RATE_LIMIT_BYPASS_DOMAINS = [
  '@test.vettid.dev',  // Automated test emails
];

/**
 * Check if an email should bypass rate limiting (for testing)
 * @param email Email address to check
 * @returns true if email should bypass rate limits
 */
export function shouldBypassRateLimit(email: string): boolean {
  if (!email) return false;
  const lowerEmail = email.toLowerCase().trim();
  return RATE_LIMIT_BYPASS_DOMAINS.some(domain => lowerEmail.endsWith(domain));
}

/**
 * Rate limiting using DynamoDB atomic counters
 * Uses conditional writes to prevent race conditions (TOCTOU attacks)
 * Each window gets its own counter that atomically increments
 * @param identifier Unique identifier (e.g., hashed email, IP address)
 * @param action The action being rate limited (e.g., 'register', 'waitlist')
 * @param maxRequests Maximum requests allowed in the window
 * @param windowMinutes Time window in minutes
 * @param bypassEmail Optional email to check for rate limit bypass (test emails)
 * @returns true if request is allowed, false if rate limited
 */
export async function checkRateLimit(
  identifier: string,
  action: string,
  maxRequests: number = 5,
  windowMinutes: number = 60,
  bypassEmail?: string
): Promise<boolean> {
  // Allow test emails to bypass rate limiting
  if (bypassEmail && shouldBypassRateLimit(bypassEmail)) {
    return true;
  }
  const now = Date.now();
  // Use fixed time windows (e.g., every 60 minutes from epoch)
  const windowId = Math.floor(now / (windowMinutes * 60 * 1000));
  const rateLimitKey = `RATELIMIT#${action}#${identifier}#${windowId}`;
  const ttl = Math.floor((now + windowMinutes * 60 * 1000 * 2) / 1000); // TTL for cleanup (2x window)

  try {
    // Atomic increment with conditional check
    // This prevents race conditions by checking and incrementing in a single operation
    const result = await ddb.send(new UpdateItemCommand({
      TableName: TABLES.audit,
      Key: marshall({ id: rateLimitKey }),
      UpdateExpression: 'SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl, #ts = :ts, #action = :action',
      ConditionExpression: 'attribute_not_exists(#count) OR #count < :maxRequests',
      ExpressionAttributeNames: {
        '#count': 'request_count',
        '#ttl': 'ttl',
        '#ts': 'ts',
        '#action': 'action'
      },
      ExpressionAttributeValues: marshall({
        ':zero': 0,
        ':one': 1,
        ':maxRequests': maxRequests,
        ':ttl': ttl,
        ':ts': new Date().toISOString(),
        ':action': action
      }),
      ReturnValues: 'ALL_NEW'
    }));

    const newCount = unmarshall(result.Attributes!).request_count;
    return true; // Request allowed (increment succeeded)
  } catch (error: any) {
    if (error.name === 'ConditionalCheckFailedException') {
      // Rate limit exceeded (atomic check failed)
      console.log(`Rate limit exceeded for ${action}:${identifier.substring(0, 8)}... - ${maxRequests}/${maxRequests} in ${windowMinutes} minutes`);
      return false;
    }
    // On other errors, allow the request (fail open for availability)
    console.warn('Rate limit check failed, allowing request:', error);
    return true;
  }
}

/**
 * Hash an identifier for privacy (e.g., email address)
 * SECURITY: Use full SHA-256 hash (64 chars) to prevent collision attacks
 * Truncating to 16 chars only provides 2^64 collision resistance, full hash provides 2^256
 */
export function hashIdentifier(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex');
}

/**
 * Parse JSON body from API Gateway event (throws ValidationError on failure)
 * Use this when you want validation errors to propagate
 */
export function parseJsonBody<T = any>(event: APIGatewayProxyEventV2): T {
  if (!event.body) throw new ValidationError("Missing request body");
  try {
    return JSON.parse(event.body) as T;
  } catch {
    throw new ValidationError("Invalid JSON in request body");
  }
}

/**
 * Safely parse JSON body string, returns null if parsing fails
 * Use this when you want to handle parsing errors yourself
 */
export function safeParseJsonBody<T = any>(body: string | undefined | null): T | null {
  if (!body) return null;
  try {
    return JSON.parse(body) as T;
  } catch {
    return null;
  }
}

/**
 * Safely parse JSON body with default value
 */
export function safeParseJsonBodyOrDefault<T = any>(body: string | undefined | null, defaultValue: T): T {
  const parsed = safeParseJsonBody<T>(body);
  return parsed !== null ? parsed : defaultValue;
}

/**
 * Get client IP from API Gateway event
 */
export function getClientIp(event: APIGatewayProxyEventV2): string {
  return event.requestContext.http?.sourceIp ||
         event.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
         'unknown';
}

/**
 * ALLOWED_ORIGINS for CORS - explicitly define allowed origins
 * Never allow wildcard (*) in production for security
 */
const ALLOWED_ORIGINS = [
  'https://register.vettid.dev',
  'https://account.vettid.dev',
  'https://admin.vettid.dev',
  'https://vettid.dev',
  'https://www.vettid.dev',
  // Development origins (should be removed in production)
  'http://localhost:3000',
  'http://localhost:5173',
];

/**
 * Get CORS headers with strict origin validation
 * SECURITY: Only allows explicitly listed origins - no wildcards
 * @param requestOrigin The origin from the request header
 * @param methods Allowed HTTP methods
 */
export function cors(requestOrigin?: string, methods: string = "OPTIONS,GET,POST,PUT,DELETE"): Record<string, string> {
  // Use env var if set, otherwise use default allowed origins
  const envOrigins = process.env.CORS_ORIGIN;
  const allowedOrigins = envOrigins && envOrigins !== '*'
    ? envOrigins.split(',').map(o => o.trim())
    : ALLOWED_ORIGINS;

  // SECURITY: Only return the origin if it's in the allowed list
  // Never fallback to wildcard
  let allowOrigin: string;
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    allowOrigin = requestOrigin;
  } else if (allowedOrigins.length === 1 && allowedOrigins[0] !== '*') {
    // Single specific origin configured - use it
    allowOrigin = allowedOrigins[0];
  } else {
    // Use the first non-wildcard origin as default
    // This will cause CORS errors for unknown origins (which is the desired behavior)
    allowOrigin = allowedOrigins.find(o => o !== '*') || 'https://vettid.dev';
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": methods,
    // SECURITY: Additional headers to prevent MIME type sniffing and other attacks
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Language": "en",
  };
}

/**
 * Extract admin email from API Gateway event
 */
export function getAdminEmail(event: APIGatewayProxyEventV2): string {
  return (event.requestContext as any)?.authorizer?.jwt?.claims?.email || "unknown@vettid.dev";
}

/**
 * Validate that the user has the required Cognito group membership
 * @param event API Gateway event with JWT claims
 * @param requiredGroup The group name required (e.g., 'admin', 'member')
 * @returns true if user has the group, false otherwise
 */
export function hasRequiredGroup(event: APIGatewayProxyEventV2, requiredGroup: string): boolean {
  const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
  let groups = claims?.['cognito:groups'];

  if (!groups) {
    return false;
  }

  // If already an array, use it directly
  if (Array.isArray(groups)) {
    return groups.includes(requiredGroup);
  }

  // Handle various string encodings of the groups array
  if (typeof groups === 'string') {
    // Try JSON parse first (for proper JSON arrays)
    try {
      const parsed = JSON.parse(groups);
      if (Array.isArray(parsed)) {
        groups = parsed;
      }
    } catch {
      // Not valid JSON, try other formats

      // Format: "[admin member]" or "[admin,member]" or "[admin, member]" (brackets without quotes)
      // API Gateway sends Cognito groups as: "[member registered]" (space-separated!)
      if (groups.startsWith('[') && groups.endsWith(']')) {
        const groupsContent = groups.slice(1, -1).trim();
        if (groupsContent) {
          // Check if it's comma-separated or space-separated
          if (groupsContent.includes(',')) {
            groups = groupsContent.split(',').map((g: string) => g.trim());
          } else {
            // Space-separated (this is what API Gateway sends for Cognito groups)
            groups = groupsContent.split(/\s+/).filter((g: string) => g.trim());
          }
        } else {
          return false;
        }
      }
      // Format: "admin member" (space-separated)
      else if (groups.includes(' ')) {
        groups = groups.split(' ').filter((g: string) => g.trim());
      }
      // Format: "admin,member" (comma-separated)
      else if (groups.includes(',')) {
        groups = groups.split(',').map((g: string) => g.trim());
      }
      // Plain single group string
      else {
        return groups === requiredGroup;
      }
    }
  }

  // After parsing, check if required group is in the array
  if (Array.isArray(groups)) {
    return groups.includes(requiredGroup);
  }

  return false;
}

/**
 * Require admin group membership or return 403
 * Call this at the start of admin handlers
 */
export function requireAdminGroup(event: APIGatewayProxyEventV2): APIGatewayProxyResultV2 | null {
  if (!hasRequiredGroup(event, 'admin')) {
    return forbidden("Admin group membership required");
  }
  return null;
}

/**
 * Require member group membership or return 403
 * Call this at the start of member handlers
 */
export function requireMemberGroup(event: APIGatewayProxyEventV2): APIGatewayProxyResultV2 | null {
  if (!hasRequiredGroup(event, 'member')) {
    return forbidden("Member group membership required");
  }
  return null;
}

/**
 * Require registered OR member group membership or return 403
 * Call this at the start of handlers that allow both registered users and members
 */
export function requireRegisteredOrMemberGroup(event: APIGatewayProxyEventV2): APIGatewayProxyResultV2 | null {
  if (!hasRequiredGroup(event, 'registered') && !hasRequiredGroup(event, 'member')) {
    return forbidden("Registered or member group membership required");
  }
  return null;
}

/**
 * CSRF Protection: Validate Origin/Referer header for state-changing operations
 * Since we use JWT in Authorization headers (not cookies), we have inherent CSRF protection.
 * This adds an additional layer by validating the request origin.
 *
 * @param event API Gateway event
 * @param allowedOrigins List of allowed origins (e.g., ['https://admin.vettid.dev', 'https://vettid.dev'])
 * @returns forbidden response if origin check fails, null if valid
 */
export function validateOrigin(event: APIGatewayProxyEventV2, allowedOrigins?: string[]): APIGatewayProxyResultV2 | null {
  // Get allowed origins from environment or parameter
  const origins = allowedOrigins || (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);

  // SECURITY: Wildcard origins are not allowed - must explicitly configure allowed origins
  if (origins.includes('*')) {
    console.error('SECURITY: Wildcard (*) in ALLOWED_ORIGINS is not permitted');
    return forbidden("Invalid CORS configuration");
  }

  // SECURITY: Require origins to be configured - no default allow-all
  if (origins.length === 0) {
    console.error('SECURITY: ALLOWED_ORIGINS environment variable not configured');
    return forbidden("CSRF protection not configured");
  }

  // Get Origin or Referer header
  const origin = event.headers?.origin || event.headers?.Origin;
  const referer = event.headers?.referer || event.headers?.Referer;

  // Extract origin from referer if origin header not present
  let requestOrigin = origin;
  if (!requestOrigin && referer) {
    try {
      const refererUrl = new URL(referer);
      requestOrigin = refererUrl.origin;
    } catch {
      // Invalid referer URL
      return forbidden("Invalid request origin");
    }
  }

  // No origin/referer header present
  if (!requestOrigin) {
    return forbidden("Missing origin header");
  }

  // Check if origin is in allowed list
  if (!origins.includes(requestOrigin)) {
    console.warn(`CSRF protection: Blocked request from origin ${requestOrigin}. Allowed: ${origins.join(', ')}`);
    return forbidden("Request origin not allowed");
  }

  return null;
}

/**
 * DynamoDB helpers
 */
export async function getRegistration(registrationId: string): Promise<any> {
  const res = await ddb.send(new GetItemCommand({
    TableName: TABLES.registrations,
    Key: marshall({ registration_id: registrationId })
  }));
  if (!res.Item) throw new NotFoundError("Registration not found");
  return unmarshall(res.Item);
}

export async function getInvite(code: string): Promise<any> {
  const res = await ddb.send(new GetItemCommand({
    TableName: TABLES.invites,
    Key: marshall({ code }),
    ConsistentRead: true
  }));
  if (!res.Item) throw new NotFoundError("Invite not found");
  return unmarshall(res.Item);
}

/**
 * Cognito helpers
 * SECURITY: Uses timing-safe comparison to prevent email enumeration attacks
 * The function always takes roughly the same time regardless of whether user exists
 */
export async function userExistsInCognito(email: string): Promise<boolean> {
  const startTime = Date.now();
  const minDuration = 50; // Minimum execution time in ms to prevent timing attacks

  try {
    await cognito.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email
    }));

    // Ensure consistent timing
    const elapsed = Date.now() - startTime;
    if (elapsed < minDuration) {
      await new Promise(resolve => setTimeout(resolve, minDuration - elapsed));
    }
    return true;
  } catch {
    // Ensure consistent timing even on failure
    const elapsed = Date.now() - startTime;
    if (elapsed < minDuration) {
      await new Promise(resolve => setTimeout(resolve, minDuration - elapsed));
    }
    return false;
  }
}

/**
 * Sanitize user input to prevent XSS attacks
 * Removes potentially dangerous characters while preserving legitimate text
 * @param input The user-provided string to sanitize
 * @returns Sanitized string safe for storage and display
 */
export function sanitizeInput(input: string, maxLength: number = 500): string {
  if (!input || typeof input !== 'string') return '';

  let sanitized = input.trim();

  // Decode HTML entities to prevent encoded XSS attacks
  sanitized = sanitized
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#x2F;/gi, '/')
    .replace(/&amp;/gi, '&');

  // Remove dangerous patterns
  sanitized = sanitized
    // Remove null bytes
    .replace(/\0/g, '')
    // Remove control characters (except newlines and tabs)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Remove HTML/XML tags
    .replace(/<[^>]*>/g, '')
    // Remove javascript: protocol
    .replace(/javascript:/gi, '')
    // Remove data: protocol (can be used for XSS)
    .replace(/data:text\/html/gi, '')
    // Remove on* event handlers
    .replace(/on\w+\s*=/gi, '')
    // Remove script tags even if obfuscated
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    // Remove style tags
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    // Limit length to prevent storage abuse
    .substring(0, maxLength);

  return sanitized;
}

/**
 * Validate and sanitize email address
 * @param email Email address to validate
 * @returns Sanitized email or throws ValidationError
 */
export function validateEmail(email: string): string {
  if (!email || typeof email !== 'string') {
    throw new ValidationError("Email is required");
  }

  const sanitized = email.trim().toLowerCase();

  // Comprehensive email regex (RFC 5322 simplified)
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  if (!emailRegex.test(sanitized)) {
    throw new ValidationError("Invalid email format");
  }

  if (sanitized.length > 254) {
    throw new ValidationError("Email too long (max 254 characters)");
  }

  return sanitized;
}

/**
 * Validate invite code format
 * @param code Invite code to validate
 * @returns Sanitized code or throws ValidationError
 */
export function validateInviteCode(code: string): string {
  if (!code || typeof code !== 'string') {
    throw new ValidationError("Invite code is required");
  }

  const sanitized = code.trim();

  // Strict alphanumeric validation with optional hyphen/dash (case-insensitive)
  if (!/^[a-zA-Z0-9\-]+$/.test(sanitized)) {
    throw new ValidationError("Please check your invite code. Only letters, numbers, and dashes are allowed.");
  }

  if (sanitized.length < 3 || sanitized.length > 50) {
    throw new ValidationError("Invite code must be between 3-50 characters");
  }

  return sanitized;
}

/**
 * Validate person name (first/last name)
 * @param name Name to validate
 * @param fieldName Field name for error messages
 * @returns Sanitized name or throws ValidationError
 */
export function validateName(name: string, fieldName: string = "Name"): string {
  if (!name || typeof name !== 'string') {
    throw new ValidationError(`${fieldName} is required`);
  }

  const sanitized = name.trim();

  // Allow letters, spaces, hyphens, apostrophes, and common diacritics
  if (!/^[a-zA-Z\u00C0-\u017F\s'-]+$/.test(sanitized)) {
    throw new ValidationError(`${fieldName} contains invalid characters`);
  }

  if (sanitized.length < 1 || sanitized.length > 100) {
    throw new ValidationError(`${fieldName} must be between 1-100 characters`);
  }

  return sanitized;
}

/**
 * Validate string input with configurable constraints
 * SECURITY: Prevents oversized inputs that could cause DoS or buffer issues
 * @param value The value to validate
 * @param fieldName Field name for error messages
 * @param minLength Minimum length (default 1)
 * @param maxLength Maximum length (default 1000)
 * @returns Sanitized string or throws ValidationError
 */
export function validateStringInput(
  value: string,
  fieldName: string,
  minLength: number = 1,
  maxLength: number = 1000
): string {
  if (value === undefined || value === null) {
    throw new ValidationError(`${fieldName} is required`);
  }

  if (typeof value !== 'string') {
    throw new ValidationError(`${fieldName} must be a string`);
  }

  const trimmed = value.trim();

  if (trimmed.length < minLength) {
    throw new ValidationError(`${fieldName} must be at least ${minLength} characters`);
  }

  if (trimmed.length > maxLength) {
    throw new ValidationError(`${fieldName} must be at most ${maxLength} characters`);
  }

  return trimmed;
}

/**
 * Validate UUID format (v4)
 * @param value The UUID to validate
 * @param fieldName Field name for error messages
 * @returns The UUID or throws ValidationError
 */
export function validateUUID(value: string, fieldName: string = "ID"): string {
  if (!value || typeof value !== 'string') {
    throw new ValidationError(`${fieldName} is required`);
  }

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(value)) {
    throw new ValidationError(`${fieldName} has invalid format`);
  }

  return value.toLowerCase();
}

/**
 * Validate path parameter format (alphanumeric with hyphens/underscores)
 * SECURITY: Prevents path traversal and injection attacks
 */
export function validatePathParam(value: string | undefined, fieldName: string = "Parameter"): string {
  if (!value || typeof value !== 'string') {
    throw new ValidationError(`${fieldName} is required`);
  }

  const trimmed = value.trim();

  // Only allow safe characters in path parameters
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    throw new ValidationError(`${fieldName} contains invalid characters`);
  }

  if (trimmed.length > 128) {
    throw new ValidationError(`${fieldName} is too long (max 128 characters)`);
  }

  return trimmed;
}

/**
 * Sanitize error for client response
 * SECURITY: Removes stack traces and internal details from error messages
 * @param error The error to sanitize
 * @param genericMessage Fallback message if error cannot be safely exposed
 * @returns Safe error message for client
 */
export function sanitizeErrorForClient(error: any, genericMessage: string = "An error occurred"): string {
  // Known safe error types that can be exposed
  if (error instanceof ValidationError) {
    return error.message;
  }

  if (error instanceof NotFoundError) {
    return error.message;
  }

  // For other errors, check if the message is safe to expose
  const message = error?.message || '';

  // List of patterns that indicate internal/sensitive information
  const sensitivePatterns = [
    /stack/i,
    /at\s+\w+\s+\(/,  // Stack trace line
    /\.ts:\d+/,        // TypeScript file reference
    /\.js:\d+/,        // JavaScript file reference
    /node_modules/,
    /internal\//,
    /aws-sdk/i,
    /dynamodb/i,
    /cognito/i,
    /lambda/i,
    /arn:/i,
    /access.*denied/i,
    /credential/i,
    /secret/i,
    /key/i,
    /token/i,
  ];

  for (const pattern of sensitivePatterns) {
    if (pattern.test(message)) {
      // Log the full error internally but return generic message
      console.error('Sanitized error (internal):', error);
      return genericMessage;
    }
  }

  // If message is short and doesn't match sensitive patterns, it's likely safe
  if (message.length > 0 && message.length < 200) {
    return message;
  }

  return genericMessage;
}

