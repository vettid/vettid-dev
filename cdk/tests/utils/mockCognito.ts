/**
 * Mock Cognito token utilities
 * Generates valid JWT tokens for testing
 */

import * as crypto from 'crypto';

export interface TokenClaims {
  sub: string;
  email?: string;
  'cognito:username'?: string;
  'cognito:groups'?: string[];
  'custom:user_guid'?: string;
  'custom:admin_type'?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  [key: string]: any;
}

export interface MockTokenOptions {
  userGuid?: string;
  email?: string;
  groups?: string[];
  adminType?: string;
  expiresIn?: number; // seconds
  issuer?: string;
  audience?: string;
}

/**
 * Base64URL encode
 */
function base64UrlEncode(data: string | Buffer): string {
  const base64 = Buffer.isBuffer(data)
    ? data.toString('base64')
    : Buffer.from(data).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a mock JWT token
 * Note: This is NOT cryptographically signed - for testing only
 */
export function generateMockToken(options: MockTokenOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const userGuid = options.userGuid || crypto.randomUUID();

  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: 'test-key-id'
  };

  const payload: TokenClaims = {
    sub: userGuid,
    email: options.email || `test-${userGuid.slice(0, 8)}@example.com`,
    'cognito:username': options.email || `test-${userGuid.slice(0, 8)}@example.com`,
    'cognito:groups': options.groups || [],
    'custom:user_guid': userGuid,
    iss: options.issuer || 'https://cognito-idp.us-east-1.amazonaws.com/test-pool',
    aud: options.audience || 'test-client-id',
    iat: now,
    exp: now + (options.expiresIn || 3600),
    token_use: 'id'
  };

  if (options.adminType) {
    payload['custom:admin_type'] = options.adminType;
  }

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));

  // Generate a fake signature (not valid, but matches JWT format)
  const signature = base64UrlEncode(
    crypto.createHash('sha256').update(`${headerB64}.${payloadB64}`).digest()
  );

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Generate a member JWT token
 */
export function generateMemberToken(options: Omit<MockTokenOptions, 'groups'> = {}): string {
  return generateMockToken({
    ...options,
    groups: ['member']
  });
}

/**
 * Generate an admin JWT token
 */
export function generateAdminToken(
  options: Omit<MockTokenOptions, 'groups'> & { adminType?: string } = {}
): string {
  return generateMockToken({
    ...options,
    groups: ['admin'],
    adminType: options.adminType || 'full'
  });
}

/**
 * Generate an expired token
 */
export function generateExpiredToken(options: MockTokenOptions = {}): string {
  return generateMockToken({
    ...options,
    expiresIn: -3600 // Expired 1 hour ago
  });
}

/**
 * Parse a JWT token (without verification)
 */
export function parseToken(token: string): TokenClaims {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const payload = Buffer.from(parts[1], 'base64url').toString();
  return JSON.parse(payload);
}

/**
 * Check if token claims include a specific group
 */
export function hasGroup(claims: TokenClaims, group: string): boolean {
  const groups = claims['cognito:groups'] || [];
  return groups.includes(group);
}

/**
 * Extract user GUID from token claims
 */
export function getUserGuid(claims: TokenClaims): string | undefined {
  return claims['custom:user_guid'] || claims.sub;
}

/**
 * Mock API Gateway event authorizer context
 */
export function createAuthorizerContext(token: string): Record<string, any> {
  const claims = parseToken(token);
  return {
    claims,
    principalId: claims.sub
  };
}

/**
 * Create mock API Gateway event with authorization
 */
export function createAuthorizedEvent(
  token: string,
  body?: any,
  pathParameters?: Record<string, string>,
  queryStringParameters?: Record<string, string>
): any {
  const claims = parseToken(token);

  return {
    body: body ? JSON.stringify(body) : null,
    pathParameters: pathParameters || null,
    queryStringParameters: queryStringParameters || null,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    requestContext: {
      authorizer: {
        jwt: {
          claims
        }
      }
    }
  };
}
