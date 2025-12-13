/**
 * Enrollment JWT utilities
 *
 * Generates and validates short-lived JWTs for mobile device enrollment.
 * These tokens are issued after validating a session_token from the QR code
 * and allow the mobile app to access enrollment endpoints.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

// JWT secret - in production this should come from AWS Secrets Manager
// For now, we use an environment variable
const JWT_SECRET = process.env.ENROLLMENT_JWT_SECRET || 'vettid-enrollment-secret-change-in-production';

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
export function generateEnrollmentToken(
  userGuid: string,
  sessionId: string,
  options: {
    deviceId?: string;
    deviceType?: 'android' | 'ios';
    expiresInSeconds?: number;
  } = {}
): string {
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
  const signature = sign(`${headerB64}.${payloadB64}`, JWT_SECRET);

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Verify and decode an enrollment JWT
 *
 * @param token JWT string
 * @returns Decoded payload if valid, null if invalid
 */
export function verifyEnrollmentToken(token: string): EnrollmentTokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Verify signature
    const expectedSignature = sign(`${headerB64}.${payloadB64}`, JWT_SECRET);

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
