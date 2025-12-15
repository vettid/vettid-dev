/**
 * Enrollment JWT utilities
 *
 * Generates and validates short-lived JWTs for mobile device enrollment.
 * These tokens are issued after validating a session_token from the QR code
 * and allow the mobile app to access enrollment endpoints.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

// Secrets Manager client and cache
const secretsClient = new SecretsManagerClient({});
let cachedJwtSecret: string | null = null;
let secretCacheTime = 0;
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const JWT_SECRET_ARN = process.env.ENROLLMENT_JWT_SECRET_ARN;

// For backwards compatibility, also check ENROLLMENT_JWT_SECRET env var
const STATIC_JWT_SECRET = process.env.ENROLLMENT_JWT_SECRET;

if (!JWT_SECRET_ARN && !STATIC_JWT_SECRET) {
  throw new Error('CRITICAL: Either ENROLLMENT_JWT_SECRET_ARN or ENROLLMENT_JWT_SECRET environment variable is required');
}

/**
 * Get JWT secret - either from Secrets Manager or environment variable
 */
async function getJwtSecret(): Promise<string> {
  // Use static secret if available (for backwards compatibility)
  if (STATIC_JWT_SECRET) {
    return STATIC_JWT_SECRET;
  }

  // Check cache
  const now = Date.now();
  if (cachedJwtSecret && (now - secretCacheTime) < SECRET_CACHE_TTL_MS) {
    return cachedJwtSecret;
  }

  // Fetch from Secrets Manager
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: JWT_SECRET_ARN,
  }));

  if (!response.SecretString) {
    throw new Error('Enrollment JWT secret is empty');
  }

  const secret = JSON.parse(response.SecretString);
  cachedJwtSecret = secret.secret;
  secretCacheTime = now;

  if (!cachedJwtSecret) {
    throw new Error('Enrollment JWT secret missing "secret" field');
  }

  return cachedJwtSecret;
}

export interface EnrollmentTokenPayload {
  // Standard JWT claims
  iss: string;           // Issuer: 'vettid-enrollment'
  sub: string;           // Subject: user_guid
  aud: string;           // Audience: 'vettid-mobile'
  exp: number;           // Expiration time (Unix timestamp)
  iat: number;           // Issued at (Unix timestamp)
  jti: string;           // JWT ID (unique identifier)

  // Custom claims
  session_id: string;    // Enrollment session ID
  scope: 'enrollment';   // Token scope (limited to enrollment)
  device_id?: string;    // Device identifier
  device_type?: 'android' | 'ios';
}

/**
 * Base64url encode (URL-safe base64 without padding)
 */
function base64urlEncode(data: string | Buffer): string {
  const base64 = Buffer.isBuffer(data)
    ? data.toString('base64')
    : Buffer.from(data).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64url decode
 */
function base64urlDecode(str: string): string {
  // Add padding back
  const padding = 4 - (str.length % 4);
  const padded = padding < 4 ? str + '='.repeat(padding) : str;
  // Convert URL-safe chars back
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Create HMAC-SHA256 signature
 */
function sign(data: string, secret: string): string {
  return base64urlEncode(
    createHmac('sha256', secret).update(data).digest()
  );
}

/**
 * Generate an enrollment JWT
 *
 * @param userGuid User's GUID from the enrollment session
 * @param sessionId Enrollment session ID
 * @param options Additional options
 * @returns Signed JWT string
 */
export async function generateEnrollmentToken(
  userGuid: string,
  sessionId: string,
  options: {
    deviceId?: string;
    deviceType?: 'android' | 'ios';
    expiresInSeconds?: number;
  } = {}
): Promise<string> {
  const jwtSecret = await getJwtSecret();
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = options.expiresInSeconds || 600; // Default 10 minutes

  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const payload: EnrollmentTokenPayload = {
    iss: 'vettid-enrollment',
    sub: userGuid,
    aud: 'vettid-mobile',
    exp: now + expiresIn,
    iat: now,
    jti: randomBytes(16).toString('hex'),
    session_id: sessionId,
    scope: 'enrollment',
    device_id: options.deviceId,
    device_type: options.deviceType,
  };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signature = sign(`${headerB64}.${payloadB64}`, jwtSecret);

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Verify and decode an enrollment JWT
 *
 * @param token JWT string
 * @returns Decoded payload if valid, null if invalid
 */
export async function verifyEnrollmentToken(token: string): Promise<EnrollmentTokenPayload | null> {
  try {
    const jwtSecret = await getJwtSecret();
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Verify signature
    const expectedSignature = sign(`${headerB64}.${payloadB64}`, jwtSecret);

    // Timing-safe comparison
    const sigBuffer = Buffer.from(signatureB64);
    const expectedBuffer = Buffer.from(expectedSignature);

    if (sigBuffer.length !== expectedBuffer.length) {
      return null;
    }

    if (!timingSafeEqual(sigBuffer, expectedBuffer)) {
      return null;
    }

    // Decode and parse payload
    const payload: EnrollmentTokenPayload = JSON.parse(base64urlDecode(payloadB64));

    // Verify claims
    const now = Math.floor(Date.now() / 1000);

    // Check expiration
    if (payload.exp < now) {
      return null;
    }

    // Check issuer
    if (payload.iss !== 'vettid-enrollment') {
      return null;
    }

    // Check audience
    if (payload.aud !== 'vettid-mobile') {
      return null;
    }

    // Check scope
    if (payload.scope !== 'enrollment') {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

/**
 * Extract enrollment token from Authorization header
 *
 * @param authHeader Authorization header value (e.g., "Bearer <token>")
 * @returns Token string or null if not found/invalid format
 */
export function extractTokenFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}
