/**
 * Verify Password Handler
 *
 * POST /vault/auth/verify-password
 *
 * Verifies a user's password against the stored Argon2id hash.
 * This is the primary authentication mechanism for vault access.
 *
 * Security features:
 * - Argon2id password hashing (memory-hard, timing-resistant)
 * - Account lockout after 5 failed attempts
 * - Automatic hash upgrade from legacy PBKDF2 to Argon2id
 * - Audit logging of all attempts
 *
 * Flow:
 * 1. Validate JWT authentication (proves user owns the account)
 * 2. Check if account is locked
 * 3. Retrieve stored password hash
 * 4. Verify password using Argon2id
 * 5. On success: reset failed attempts, optionally generate session
 * 6. On failure: increment failed attempts, check for lockout
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  ok,
  badRequest,
  forbidden,
  internalError,
  getRequestId,
  requireUserClaims,
} from '../../common/util';
import {
  verifyPassword as verifyPasswordHash,
  needsRehash,
  hashPassword,
} from '../../common/crypto';
import {
  query,
  transaction,
  getPasswordHash,
  recordFailedAttempt,
  resetFailedAttempts,
  storePasswordHash,
  claimSession,
  logSecurityEvent,
} from '../../common/ledger-db';
import { randomUUID } from 'crypto';

interface VerifyPasswordRequest {
  password: string;           // Plain text password
  create_session?: boolean;   // Whether to create a new session
  force_session?: boolean;    // Force new session even if one exists
}

interface VerifyPasswordResponse {
  verified: boolean;
  session_id?: string;
  failed_attempts?: number;
  locked_until?: string;
  rehashed?: boolean;         // True if password was rehashed to Argon2id
}

// Lockout configuration
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 30;

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;
  const clientIp = event.headers?.['x-forwarded-for']?.split(',')[0];

  try {
    // Validate JWT authentication
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Parse request body
    if (!event.body) {
      return badRequest('Request body required', origin);
    }

    let request: VerifyPasswordRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Validate password is provided
    if (!request.password || typeof request.password !== 'string') {
      return badRequest('password is required', origin);
    }

    // Get stored password hash
    const storedHash = await getPasswordHash(userGuid);

    if (!storedHash) {
      // No password set - user needs to complete enrollment
      await logSecurityEvent(
        'password_verify_no_hash',
        userGuid,
        undefined,
        { reason: 'no_password_hash' },
        'warning',
        clientIp
      );

      return ok({
        verified: false,
        failed_attempts: 0,
      }, origin);
    }

    // Check if account is locked
    if (storedHash.locked_until && new Date(storedHash.locked_until) > new Date()) {
      await logSecurityEvent(
        'password_verify_locked',
        userGuid,
        undefined,
        { locked_until: storedHash.locked_until },
        'warning',
        clientIp
      );

      return ok({
        verified: false,
        locked_until: storedHash.locked_until.toISOString(),
        failed_attempts: storedHash.failed_attempts,
      }, origin);
    }

    // Verify the password
    let isValid: boolean;
    try {
      isValid = await verifyPasswordHash(storedHash.password_hash, request.password);
    } catch (error) {
      console.error('[VERIFY-PASSWORD] Hash verification error:', error);
      isValid = false;
    }

    if (!isValid) {
      // Record failed attempt
      const lockDuration = storedHash.failed_attempts + 1 >= MAX_FAILED_ATTEMPTS
        ? LOCKOUT_DURATION_MINUTES
        : undefined;

      const attemptResult = await recordFailedAttempt(storedHash.hash_id, lockDuration);

      await logSecurityEvent(
        'password_verify_failed',
        userGuid,
        undefined,
        {
          failed_attempts: attemptResult.failed_attempts,
          locked: !!attemptResult.locked_until,
        },
        'warning',
        clientIp
      );

      return ok({
        verified: false,
        failed_attempts: attemptResult.failed_attempts,
        locked_until: attemptResult.locked_until?.toISOString(),
      }, origin);
    }

    // Password is valid!

    // Reset failed attempts
    await resetFailedAttempts(storedHash.hash_id);

    // Check if we need to upgrade the hash algorithm
    let rehashed = false;
    if (needsRehash(storedHash.password_hash)) {
      // Upgrade to Argon2id
      const newHash = await hashPassword(request.password);
      await storePasswordHash(userGuid, newHash);
      rehashed = true;

      await logSecurityEvent(
        'password_hash_upgraded',
        userGuid,
        undefined,
        { from: 'pbkdf2', to: 'argon2id' },
        'info',
        clientIp
      );
    }

    // Create session if requested
    let sessionId: string | undefined;
    if (request.create_session) {
      sessionId = randomUUID();
      const claimed = await claimSession(userGuid, sessionId, request.force_session);

      if (!claimed) {
        // Another session is already active
        sessionId = undefined;

        await logSecurityEvent(
          'session_claim_failed',
          userGuid,
          undefined,
          { reason: 'existing_session' },
          'info',
          clientIp
        );
      }
    }

    await logSecurityEvent(
      'password_verified',
      userGuid,
      sessionId,
      { session_created: !!sessionId, rehashed },
      'info',
      clientIp
    );

    const response: VerifyPasswordResponse = {
      verified: true,
      session_id: sessionId,
      rehashed,
    };

    return ok(response, origin);
  } catch (error) {
    console.error('[VERIFY-PASSWORD] Error:', error);
    return internalError('Failed to verify password', origin);
  }
};
