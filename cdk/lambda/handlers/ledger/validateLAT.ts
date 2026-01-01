/**
 * Validate LAT Handler
 *
 * POST /vault/auth/validate-lat
 *
 * Validates a Ledger Authentication Token (LAT) for mutual authentication.
 * LATs provide mutual authentication between the user's app and the Ledger:
 * - App proves it has the correct LAT
 * - Ledger proves it knows the LAT by returning a new rotated token
 *
 * This is NOT for user authentication - it's for app-to-ledger authentication
 * after the user has already authenticated with their password.
 *
 * Flow:
 * 1. App sends current LAT
 * 2. Ledger verifies LAT hash matches stored hash
 * 3. Ledger marks old LAT as used (prevents replay)
 * 4. Ledger generates new LAT
 * 5. Ledger returns new LAT to app
 * 6. App stores new LAT for next request
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
  hashLATToken,
  verifyLATToken,
  generateLAT,
} from '../../common/crypto-keys';
import {
  verifyAndRotateLAT,
  logSecurityEvent,
} from '../../common/ledger-db';

interface ValidateLATRequest {
  lat_token: string;  // Current LAT token (64 hex characters)
}

interface ValidateLATResponse {
  valid: boolean;
  new_lat?: {
    token: string;    // New LAT token
    version: number;
  };
  session_id?: string;
}

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate authentication (JWT from Cognito)
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

    let request: ValidateLATRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Validate LAT token format
    if (!request.lat_token || !/^[a-f0-9]{64}$/i.test(request.lat_token)) {
      return badRequest('Invalid lat_token format (must be 64 hex characters)', origin);
    }

    // Hash the provided token for comparison
    const tokenHash = Buffer.from(hashLATToken(request.lat_token), 'hex');

    // Generate new LAT upfront (version will be incremented in the transaction)
    // We need to prepare this before the transaction so it can be stored atomically
    const newLat = generateLAT(1); // Version will be set by the transaction
    const newTokenHash = Buffer.from(hashLATToken(newLat.token), 'hex');

    // Calculate expiry (30 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    // SECURITY: Verify and rotate the LAT in a single atomic transaction
    // This prevents race conditions where old token is invalidated but new token isn't created
    // Also uses SELECT FOR UPDATE to prevent concurrent rotation attacks
    const rotationResult = await verifyAndRotateLAT(
      userGuid,
      tokenHash,
      newTokenHash,
      expiresAt
    );

    if (!rotationResult) {
      // Log failed validation attempt
      await logSecurityEvent(
        'lat_validation_failed',
        userGuid,
        undefined,
        { reason: 'invalid_or_expired_token' },
        'warning',
        event.headers?.['x-forwarded-for']?.split(',')[0]
      );

      // Don't reveal whether the token was invalid or expired
      return ok({
        valid: false,
      }, origin);
    }

    // Update the LAT with the correct version from the transaction
    newLat.version = rotationResult.version;

    // Log successful validation
    await logSecurityEvent(
      'lat_validated',
      userGuid,
      undefined,
      {
        old_version: rotationResult.version - 1,
        new_version: rotationResult.version,
      },
      'info'
    );

    const response: ValidateLATResponse = {
      valid: true,
      new_lat: {
        token: newLat.token,
        version: rotationResult.version,
      },
    };

    return ok(response, origin);
  } catch (error) {
    console.error('[VALIDATE-LAT] Error:', error);
    return internalError('Failed to validate LAT', origin);
  }
};
