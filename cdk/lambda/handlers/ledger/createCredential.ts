/**
 * Create Credential Handler
 *
 * POST /vault/credentials/create
 *
 * Creates a new credential encryption key (CEK) for a user.
 * This is called during initial enrollment to set up the user's credential storage.
 *
 * The CEK is an X25519 key pair where:
 * - Public key is stored unencrypted (used to encrypt credential blobs)
 * - Private key is encrypted with a key derived from the user's password
 *
 * Flow:
 * 1. Validate user authentication (LAT or session)
 * 2. Generate X25519 CEK key pair
 * 3. Encrypt private key with password-derived key
 * 4. Store in credential_keys table
 * 5. Return public key to caller
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
  encryptWithPublicKey,
  serializeEncryptedBlob,
} from '../../common/crypto';
import {
  query,
  transaction,
  getOrCreateUser,
  logSecurityEvent,
} from '../../common/ledger-db';

interface CreateCredentialRequest {
  // Public key for encrypting the CEK private key
  // This is derived from the user's password on the client side
  encryption_public_key: string; // Base64 encoded 32-byte X25519 public key
}

interface CreateCredentialResponse {
  credential_key_id: string;
  public_key: string;         // Base64 encoded 32-byte X25519 public key
  encrypted_private_key: {    // Encrypted CEK private key
    ciphertext: string;
    nonce: string;
    ephemeral_public_key: string;
  };
  version: number;
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

    let request: CreateCredentialRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Validate encryption public key
    if (!request.encryption_public_key) {
      return badRequest('encryption_public_key is required', origin);
    }

    let encryptionPublicKey: Buffer;
    try {
      encryptionPublicKey = Buffer.from(request.encryption_public_key, 'base64');
      if (encryptionPublicKey.length !== 32) {
        throw new Error('Invalid key length');
      }
    } catch {
      return badRequest('Invalid encryption_public_key format (must be 32-byte base64)', origin);
    }

    // Ensure user exists in Ledger
    await getOrCreateUser(userGuid);

    // Check if user already has a current CEK
    const existingKey = await query<{ key_id: string }>(
      `SELECT key_id FROM credential_keys
       WHERE user_guid = $1 AND is_current = true`,
      [userGuid]
    );

    if (existingKey.rows.length > 0) {
      return badRequest(
        'User already has a credential key. Use /vault/credentials/rotate to create a new one.',
        origin
      );
    }

    // Generate new CEK key pair
    const cekKeyPair = generateX25519KeyPair();

    // Encrypt the CEK private key with the user's encryption key
    const encryptedPrivateKey = encryptWithPublicKey(
      cekKeyPair.privateKey,
      encryptionPublicKey,
      'cek-encryption-v1'
    );

    // Store the CEK in the database
    const result = await transaction(async (client) => {
      const insertResult = await client.query<{
        key_id: string;
        version: number;
      }>(
        `INSERT INTO credential_keys (
           user_guid,
           public_key,
           encrypted_private_key,
           encryption_nonce,
           version,
           is_current
         )
         VALUES ($1, $2, $3, $4, 1, true)
         RETURNING key_id, version`,
        [
          userGuid,
          cekKeyPair.publicKey,
          Buffer.concat([
            encryptedPrivateKey.ephemeralPublicKey,
            encryptedPrivateKey.ciphertext,
          ]),
          encryptedPrivateKey.nonce,
        ]
      );

      return insertResult.rows[0];
    });

    // Log the security event
    await logSecurityEvent(
      'credential_key_created',
      userGuid,
      undefined,
      { key_id: result.key_id, version: result.version },
      'info'
    );

    // Clear sensitive data
    cekKeyPair.privateKey.fill(0);

    // Build response
    const response: CreateCredentialResponse = {
      credential_key_id: result.key_id,
      public_key: cekKeyPair.publicKey.toString('base64'),
      encrypted_private_key: serializeEncryptedBlob(encryptedPrivateKey),
      version: result.version,
    };

    return ok(response, origin);
  } catch (error) {
    console.error('[CREATE-CREDENTIAL] Error:', error);
    return internalError('Failed to create credential key', origin);
  }
};
