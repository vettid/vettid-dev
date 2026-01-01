/**
 * Authentication and authorization helpers
 */

import type { APIGatewayProxyEvent } from 'aws-lambda';

export interface UserClaims {
  sub: string;
  email?: string;
  'cognito:username'?: string;
  'cognito:groups'?: string[];
}

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Extract user claims from a Cognito-authorized API Gateway event
 */
export function getUserClaims(event: APIGatewayProxyEvent): UserClaims | null {
  const claims = event.requestContext?.authorizer?.claims;
  if (!claims) {
    return null;
  }
  return claims as UserClaims;
}

/**
 * Require valid user claims or throw AuthError
 */
export function requireUserClaims(event: APIGatewayProxyEvent): UserClaims {
  const claims = getUserClaims(event);
  if (!claims || !claims.sub) {
    throw new AuthError('User claims not found');
  }
  return claims;
}

/**
 * Check if user belongs to a specific Cognito group
 */
export function isInGroup(claims: UserClaims, group: string): boolean {
  const groups = claims['cognito:groups'];
  return Array.isArray(groups) && groups.includes(group);
}

/**
 * Require user to be in admin group or throw AuthError
 */
export function requireAdminGroup(claims: UserClaims): void {
  if (!isInGroup(claims, 'admin')) {
    throw new AuthError('Admin access required');
  }
}

/**
 * Get user GUID from claims (sub field)
 */
export function getUserGuid(claims: UserClaims): string {
  return claims.sub;
}
