/**
 * Replenish Transaction Keys Handler
 *
 * POST /vault/transaction-keys/replenish
 *
 * Generates a new batch of transaction keys for the user.
 * This should be called when the available key pool is running low.
 *
 * Transaction keys are used for:
 * - Encrypting password during verification
 * - Encrypting credential updates
 * - Secure session key exchange
 *
 * Each key can only be used once, so a pool is maintained.
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
import { generateTransactionKeyPool } from '../../common/crypto';
import {
  query,
  storeTransactionKeys,
  logSecurityEvent,
} from '../../common/ledger-db';

interface ReplenishRequest {
  count?: number;  // Number of keys to generate (default: 20, max: 100)
}

interface ReplenishResponse {
  new_keys: Array<{
    key_id: string;
    public_key: string;  // UTK - Base64 encoded
    expires_at: string;
  }>;
  total_available: number;
}

const DEFAULT_KEY_COUNT = 20;
const MAX_KEY_COUNT = 100;
const MAX_TOTAL_KEYS = 200; // Maximum unused keys per user

export const handler = async (
  event: APIGatewayProxyEventV2
): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate authentication
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Parse request body
    let count = DEFAULT_KEY_COUNT;
    if (event.body) {
      try {
        const request: ReplenishRequest = JSON.parse(event.body);
        if (request.count !== undefined) {
          count = Math.min(Math.max(1, request.count), MAX_KEY_COUNT);
        }
      } catch {
        return badRequest('Invalid JSON body', origin);
      }
    }

    // Check current key count
    const currentCount = await query<{ count: string }>(
      `SELECT COUNT(*) as count
       FROM transaction_keys
       WHERE user_guid = $1
         AND status = 'unused'
         AND expires_at > NOW()`,
      [userGuid]
    );

    const existingCount = parseInt(currentCount.rows[0].count, 10);

    // Limit total keys to prevent abuse
    if (existingCount >= MAX_TOTAL_KEYS) {
      return badRequest(
        `Maximum of ${MAX_TOTAL_KEYS} unused transaction keys allowed. Current: ${existingCount}`,
        origin
      );
    }

    // Adjust count if it would exceed the limit
    const actualCount = Math.min(count, MAX_TOTAL_KEYS - existingCount);

    if (actualCount <= 0) {
      return ok({
        new_keys: [],
        total_available: existingCount,
      }, origin);
    }

    // Generate new keys
    const keyPairs = generateTransactionKeyPool(actualCount);

    // Keys expire in 24 hours
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    // Store the keys
    const keyIds = await storeTransactionKeys(
      userGuid,
      keyPairs.map((kp) => ({
        publicKey: kp.publicKey,
        privateKey: kp.privateKey,
      })),
      expiresAt
    );

    // Clear private keys from memory
    keyPairs.forEach((kp) => kp.privateKey.fill(0));

    // Log the replenishment
    await logSecurityEvent(
      'transaction_keys_replenished',
      userGuid,
      undefined,
      { count: actualCount, total: existingCount + actualCount },
      'info'
    );

    // Build response
    const newKeys = keyIds.map((keyId, index) => ({
      key_id: keyId,
      public_key: keyPairs[index].publicKey.toString('base64'),
      expires_at: expiresAt.toISOString(),
    }));

    const response: ReplenishResponse = {
      new_keys: newKeys,
      total_available: existingCount + actualCount,
    };

    return ok(response, origin);
  } catch (error) {
    console.error('[REPLENISH-TRANSACTION-KEYS] Error:', error);
    return internalError('Failed to replenish transaction keys', origin);
  }
};
