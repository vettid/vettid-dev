/**
 * Get Transaction Keys Handler
 *
 * GET /vault/transaction-keys
 *
 * Returns the user's available transaction keys (UTKs - User Transaction Keys).
 * These are the public keys from the transaction key pairs.
 * The corresponding private keys (LTKs - Ledger Transaction Keys) are stored
 * in the Ledger and never sent to the client.
 *
 * Transaction keys are one-time-use keys for encrypting session data.
 * When the client uses a UTK to encrypt data, the Ledger can decrypt it
 * with the corresponding LTK.
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
import { query } from '../../common/ledger-db';

interface TransactionKey {
  key_id: string;
  public_key: string;  // UTK - Base64 encoded
  expires_at: string;
}

interface GetTransactionKeysResponse {
  keys: TransactionKey[];
  total_available: number;
  next_expiry?: string;
}

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

    // Get pagination parameters
    const limit = Math.min(
      parseInt(event.queryStringParameters?.limit || '20', 10),
      100
    );

    // Get unused transaction keys
    const result = await query<{
      key_id: string;
      public_key: Buffer;
      expires_at: Date;
    }>(
      `SELECT key_id, public_key, expires_at
       FROM transaction_keys
       WHERE user_guid = $1
         AND status = 'unused'
         AND expires_at > NOW()
       ORDER BY created_at ASC
       LIMIT $2`,
      [userGuid, limit]
    );

    // Get total count
    const countResult = await query<{ count: string }>(
      `SELECT COUNT(*) as count
       FROM transaction_keys
       WHERE user_guid = $1
         AND status = 'unused'
         AND expires_at > NOW()`,
      [userGuid]
    );

    const totalAvailable = parseInt(countResult.rows[0].count, 10);

    // Format response
    const keys: TransactionKey[] = result.rows.map((row) => ({
      key_id: row.key_id,
      public_key: row.public_key.toString('base64'),
      expires_at: row.expires_at.toISOString(),
    }));

    // Find earliest expiry
    let nextExpiry: string | undefined;
    if (keys.length > 0) {
      const expiryResult = await query<{ min_expiry: Date }>(
        `SELECT MIN(expires_at) as min_expiry
         FROM transaction_keys
         WHERE user_guid = $1
           AND status = 'unused'
           AND expires_at > NOW()`,
        [userGuid]
      );
      if (expiryResult.rows[0]?.min_expiry) {
        nextExpiry = expiryResult.rows[0].min_expiry.toISOString();
      }
    }

    const response: GetTransactionKeysResponse = {
      keys,
      total_available: totalAvailable,
      next_expiry: nextExpiry,
    };

    return ok(response, origin);
  } catch (error) {
    console.error('[GET-TRANSACTION-KEYS] Error:', error);
    return internalError('Failed to get transaction keys', origin);
  }
};
