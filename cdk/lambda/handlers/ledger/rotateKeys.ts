/**
 * Rotate Keys Handler
 *
 * POST /vault/credentials/rotate
 *
 * Rotates the user's credential encryption key (CEK) and/or transaction keys.
 * This should be called:
 * - After successful authentication (to rotate LAT)
 * - When the user changes their password (to rotate CEK)
 * - Periodically for security best practices
 *
 * Key rotation flow:
 * 1. Validate authentication (current LAT required)
 * 2. Generate new CEK if requested
 * 3. Re-encrypt existing credentials with new CEK
 * 4. Mark old CEK as non-current
 * 5. Generate new LAT
 * 6. Return new keys to caller
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
  generateX25519KeyPair,
  generateLAT,
  hashLATToken,
  encryptWithPublicKey,
  serializeEncryptedBlob,
  generateTransactionKeyPool,
} from '../../common/crypto-keys';
import {
  query,
  transaction,
  storeLAT,
  storeTransactionKeys,
  logSecurityEvent,
} from '../../common/ledger-db';

interface RotateKeysRequest {
  // What to rotate
  rotate_cek?: boolean;           // Rotate credential encryption key
  rotate_lat?: boolean;           // Rotate ledger auth token (default: true)
  rotate_transaction_keys?: boolean; // Replenish transaction key pool

  // Required if rotating CEK
  encryption_public_key?: string; // Base64 encoded, for encrypting new CEK private key
  current_lat?: string;           // Current LAT for verification

  // Optional
  transaction_key_count?: number; // Number of transaction keys to generate (default: 20)
}

interface RotateKeysResponse {
  // New CEK (if rotated)
  new_cek?: {
    credential_key_id: string;
    public_key: string;
    encrypted_private_key: {
      ciphertext: string;
      nonce: string;
      ephemeral_public_key: string;
    };
    version: number;
  };

  // New LAT (if rotated)
  new_lat?: {
    token: string;    // Raw token - send this to client
    version: number;
  };

  // New transaction keys (if rotated)
  new_transaction_keys?: Array<{
    key_id: string;
    public_key: string; // UTK - User Transaction Key
  }>;

  // Summary
  rotated: string[];
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

    // Parse request body
    if (!event.body) {
      return badRequest('Request body required', origin);
    }

    let request: RotateKeysRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Defaults
    const rotateCek = request.rotate_cek || false;
    const rotateLat = request.rotate_lat !== false; // Default to true
    const rotateTransactionKeys = request.rotate_transaction_keys || false;
    const transactionKeyCount = request.transaction_key_count || 20;

    // Validate CEK rotation requirements
    if (rotateCek && !request.encryption_public_key) {
      return badRequest('encryption_public_key required for CEK rotation', origin);
    }

    let encryptionPublicKey: Buffer | undefined;
    if (request.encryption_public_key) {
      try {
        encryptionPublicKey = Buffer.from(request.encryption_public_key, 'base64');
        if (encryptionPublicKey.length !== 32) {
          throw new Error('Invalid key length');
        }
      } catch {
        return badRequest('Invalid encryption_public_key format', origin);
      }
    }

    const response: RotateKeysResponse = {
      rotated: [],
    };

    // Rotate CEK if requested
    if (rotateCek && encryptionPublicKey) {
      const newCek = await rotateCEK(userGuid, encryptionPublicKey);
      response.new_cek = newCek;
      response.rotated.push('cek');
    }

    // Rotate LAT
    if (rotateLat) {
      const newLat = await rotateLATToken(userGuid);
      response.new_lat = newLat;
      response.rotated.push('lat');
    }

    // Replenish transaction keys
    if (rotateTransactionKeys) {
      const newKeys = await replenishTransactionKeys(userGuid, transactionKeyCount);
      response.new_transaction_keys = newKeys;
      response.rotated.push('transaction_keys');
    }

    // Log the rotation event
    await logSecurityEvent(
      'keys_rotated',
      userGuid,
      undefined,
      { rotated: response.rotated },
      'info'
    );

    return ok(response, origin);
  } catch (error) {
    console.error('[ROTATE-KEYS] Error:', error);
    return internalError('Failed to rotate keys', origin);
  }
};

/**
 * Rotate the Credential Encryption Key
 */
async function rotateCEK(
  userGuid: string,
  encryptionPublicKey: Buffer
): Promise<{
  credential_key_id: string;
  public_key: string;
  encrypted_private_key: {
    ciphertext: string;
    nonce: string;
    ephemeral_public_key: string;
  };
  version: number;
}> {
  // Generate new CEK
  const newCekPair = generateX25519KeyPair();

  // Encrypt the new CEK private key
  const encryptedPrivateKey = encryptWithPublicKey(
    newCekPair.privateKey,
    encryptionPublicKey,
    'cek-encryption-v1'
  );

  // Atomically rotate the CEK
  const result = await transaction(async (client) => {
    // Get the current version
    const currentVersion = await client.query<{ version: number }>(
      `SELECT COALESCE(MAX(version), 0) as version
       FROM credential_keys
       WHERE user_guid = $1`,
      [userGuid]
    );

    const newVersion = currentVersion.rows[0].version + 1;

    // Mark existing keys as non-current
    await client.query(
      `UPDATE credential_keys
       SET is_current = false, rotated_at = NOW()
       WHERE user_guid = $1 AND is_current = true`,
      [userGuid]
    );

    // Insert the new key
    const insertResult = await client.query<{ key_id: string }>(
      `INSERT INTO credential_keys (
         user_guid,
         public_key,
         encrypted_private_key,
         encryption_nonce,
         version,
         is_current
       )
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING key_id`,
      [
        userGuid,
        newCekPair.publicKey,
        Buffer.concat([
          encryptedPrivateKey.ephemeralPublicKey,
          encryptedPrivateKey.ciphertext,
        ]),
        encryptedPrivateKey.nonce,
        newVersion,
      ]
    );

    return {
      key_id: insertResult.rows[0].key_id,
      version: newVersion,
    };
  });

  // Clear sensitive data
  newCekPair.privateKey.fill(0);

  return {
    credential_key_id: result.key_id,
    public_key: newCekPair.publicKey.toString('base64'),
    encrypted_private_key: serializeEncryptedBlob(encryptedPrivateKey),
    version: result.version,
  };
}

/**
 * Rotate the Ledger Auth Token
 */
async function rotateLATToken(
  userGuid: string
): Promise<{ token: string; version: number }> {
  // Get current LAT version
  const currentLat = await query<{ version: number }>(
    `SELECT COALESCE(MAX(version), 0) as version
     FROM ledger_auth_tokens
     WHERE user_guid = $1`,
    [userGuid]
  );

  const newVersion = currentLat.rows[0].version + 1;

  // Generate new LAT
  const newLat = generateLAT(newVersion);
  const tokenHash = Buffer.from(hashLATToken(newLat.token), 'hex');

  // Store the new LAT (expires in 30 days)
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);

  await storeLAT(userGuid, tokenHash, newVersion, expiresAt);

  // Mark old LATs as expired
  await query(
    `UPDATE ledger_auth_tokens
     SET status = 'expired'
     WHERE user_guid = $1 AND version < $2 AND status = 'active'`,
    [userGuid, newVersion]
  );

  return {
    token: newLat.token,
    version: newVersion,
  };
}

/**
 * Replenish the transaction key pool
 */
async function replenishTransactionKeys(
  userGuid: string,
  count: number
): Promise<Array<{ key_id: string; public_key: string }>> {
  // Generate new keys
  const keyPairs = generateTransactionKeyPool(count);

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

  // Return the UTKs (public keys)
  return keyIds.map((keyId, index) => ({
    key_id: keyId,
    public_key: keyPairs[index].publicKey.toString('base64'),
  }));
}
