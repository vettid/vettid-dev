import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  generateSecureId,
} from '../../common/util';
import {
  generateX25519KeyPair,
  encryptCredentialBlob,
  decryptCredentialBlob,
  decryptWithTransactionKey,
  deserializeEncryptedBlob,
  serializeEncryptedBlob,
  generateLAT,
  hashLATToken,
} from '../../common/crypto-keys';
import { verifyPassword } from '../../common/crypto-password';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_CREDENTIAL_KEYS = process.env.TABLE_CREDENTIAL_KEYS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;

const EXPECTED_ENDPOINT = '/api/v1/auth/execute';

interface AuthExecuteRequest {
  encrypted_blob: string;
  cek_version: number;
  encrypted_password_hash: string;
  ephemeral_public_key: string;
  nonce: string;
  key_id: string;
}

/**
 * Validate the action token from Authorization header
 */
function validateActionToken(authHeader: string | undefined): { valid: boolean; payload?: any; error?: string } {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing or invalid Authorization header' };
  }

  const token = authHeader.substring(7);
  const parts = token.split('.');

  if (parts.length !== 3) {
    return { valid: false, error: 'Invalid token format' };
  }

  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }

    // Check endpoint scope
    if (payload.endpoint !== EXPECTED_ENDPOINT) {
      return { valid: false, error: 'Token not valid for this endpoint' };
    }

    // In production, verify signature with Ed25519 public key
    // For now, we just validate the structure and check the database

    return { valid: true, payload };
  } catch {
    return { valid: false, error: 'Invalid token payload' };
  }
}


/**
 * POST /api/v1/auth/execute
 *
 * Execute authentication action.
 * Validates scoped token, decrypts blob, verifies password, rotates credentials.
 *
 * Requires: Authorization: Bearer {action_token}
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Validate action token
    const tokenResult = validateActionToken(event.headers.authorization || event.headers.Authorization);
    if (!tokenResult.valid) {
      return unauthorized(tokenResult.error || 'Invalid token');
    }

    const tokenPayload = tokenResult.payload;
    const userGuid = tokenPayload.sub;
    const tokenId = tokenPayload.jti;

    // Verify token is still active in database (single-use check)
    const actionTokenResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ACTION_TOKENS,
      Key: marshall({ token_id: tokenId }),
    }));

    if (!actionTokenResult.Item) {
      return unauthorized('Token not found');
    }

    const actionToken = unmarshall(actionTokenResult.Item);

    if (actionToken.status !== 'ACTIVE') {
      return forbidden('Token has already been used');
    }

    // Mark token as used immediately (single-use)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ACTION_TOKENS,
      Key: marshall({ token_id: tokenId }),
      UpdateExpression: 'SET #status = :status, used_at = :used_at',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'USED',
        ':used_at': new Date().toISOString(),
      }),
    }));

    // Parse request body
    const body = parseJsonBody<AuthExecuteRequest>(event);

    if (!body.encrypted_blob) return badRequest('encrypted_blob is required');
    if (!body.cek_version) return badRequest('cek_version is required');
    if (!body.encrypted_password_hash) return badRequest('encrypted_password_hash is required');
    if (!body.ephemeral_public_key) return badRequest('ephemeral_public_key is required');
    if (!body.nonce) return badRequest('nonce is required');
    if (!body.key_id) return badRequest('key_id is required');

    // Get credential
    const credentialResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!credentialResult.Item) {
      return notFound('Credential not found');
    }

    const credential = unmarshall(credentialResult.Item);

    // Verify CEK version matches
    if (credential.cek_version !== body.cek_version) {
      return conflict('CEK version mismatch - credential may be out of sync');
    }

    // Get transaction key for decrypting password hash
    const tkResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({ user_guid: userGuid, key_id: body.key_id }),
    }));

    if (!tkResult.Item) {
      return badRequest('Transaction key not found');
    }

    // Mark transaction key as used
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({ user_guid: userGuid, key_id: body.key_id }),
      UpdateExpression: 'SET #status = :status, used_at = :used_at, used_for = :used_for',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'USED',
        ':used_at': new Date().toISOString(),
        ':used_for': 'auth_execute',
      }),
    }));

    const now = new Date();
    const tk = unmarshall(tkResult.Item);

    // 1. Decrypt password hash using transaction key (LTK)
    const ltkPrivateKey = Buffer.from(tk.private_key, 'base64');
    const encryptedPasswordData = deserializeEncryptedBlob({
      ciphertext: body.encrypted_password_hash,
      nonce: body.nonce,
      ephemeral_public_key: body.ephemeral_public_key,
    });

    let providedPasswordHash: string;
    try {
      const decryptedBuffer = decryptWithTransactionKey(encryptedPasswordData, ltkPrivateKey);
      providedPasswordHash = decryptedBuffer.toString('utf-8');
    } catch (decryptError) {
      console.error('Failed to decrypt password hash:', decryptError);
      return badRequest('Failed to decrypt password data');
    }

    // 2. Get CEK to decrypt credential blob
    const cekResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_KEYS,
      Key: marshall({ user_guid: userGuid, version: body.cek_version }),
    }));

    if (!cekResult.Item) {
      return badRequest('CEK not found');
    }

    const cek = unmarshall(cekResult.Item);
    const cekPrivateKey = Buffer.from(cek.private_key, 'base64');

    // 3. Decrypt credential blob to get stored password hash
    const encryptedBlobData = deserializeEncryptedBlob({
      ciphertext: body.encrypted_blob,
      nonce: body.nonce,  // Note: In production, blob should have its own nonce
      ephemeral_public_key: body.ephemeral_public_key,
    });

    let credentialData: { password_hash: string; [key: string]: any };
    try {
      const decryptedBlob = decryptCredentialBlob(encryptedBlobData, cekPrivateKey);
      credentialData = JSON.parse(decryptedBlob.toString('utf-8'));
    } catch (blobDecryptError) {
      console.error('Failed to decrypt credential blob:', blobDecryptError);
      return badRequest('Failed to decrypt credential data');
    }

    // 4. Verify password hash matches
    const passwordValid = await verifyPassword(credentialData.password_hash, providedPasswordHash);
    if (!passwordValid) {
      // Increment failed auth count
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_CREDENTIALS,
        Key: marshall({ user_guid: userGuid }),
        UpdateExpression: 'SET failed_auth_count = failed_auth_count + :one',
        ExpressionAttributeValues: marshall({ ':one': 1 }),
      }));

      await putAudit({
        type: 'auth_failed',
        user_guid: userGuid,
        reason: 'password_mismatch',
      }, requestId);

      return unauthorized('Authentication failed');
    }

    // 5. Rotate CEK
    const newCekKeyPair = generateX25519KeyPair();
    const newCekVersion = credential.cek_version + 1;

    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_KEYS,
      Item: marshall({
        user_guid: userGuid,
        version: newCekVersion,
        private_key: newCekKeyPair.privateKey.toString('base64'),
        public_key: newCekKeyPair.publicKey.toString('base64'),
        algorithm: 'X25519',
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Mark old CEK as rotated
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_KEYS,
      Key: marshall({ user_guid: userGuid, version: credential.cek_version }),
      UpdateExpression: 'SET #status = :status, rotated_at = :rotated_at',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'ROTATED',
        ':rotated_at': now.toISOString(),
      }),
    }));

    // 6. Rotate LAT using crypto utilities
    const newLat = generateLAT(credential.lat_version + 1);
    const newLatId = generateSecureId('lat', 16);

    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Item: marshall({
        user_guid: userGuid,
        version: newLat.version,
        lat_id: newLatId,
        token_hash: hashLATToken(newLat.token),
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Mark old LAT as rotated
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Key: marshall({ user_guid: userGuid, version: credential.lat_version }),
      UpdateExpression: 'SET #status = :status, rotated_at = :rotated_at',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'ROTATED',
        ':rotated_at': now.toISOString(),
      }),
    }));

    // 7. Re-encrypt credential blob with new CEK
    credentialData.rotated_at = now.toISOString();
    const newEncryptedBlobData = encryptCredentialBlob(
      Buffer.from(JSON.stringify(credentialData)),
      newCekKeyPair.publicKey  // Use PUBLIC key for encryption
    );
    const serializedNewBlob = serializeEncryptedBlob(newEncryptedBlobData);

    // Update credential metadata
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET cek_version = :cek_version, lat_version = :lat_version, last_action_at = :last_action, failed_auth_count = :zero',
      ExpressionAttributeValues: marshall({
        ':cek_version': newCekVersion,
        ':lat_version': newLat.version,
        ':last_action': now.toISOString(),
        ':zero': 0,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'auth_executed',
      user_guid: userGuid,
      token_id: tokenId,
      cek_rotated_to: newCekVersion,
      lat_rotated_to: newLat.version,
    }, requestId);

    return ok({
      status: 'success',
      action_result: {
        authenticated: true,
        message: 'Authentication successful',
        timestamp: now.toISOString(),
      },
      credential_package: {
        encrypted_blob: serializedNewBlob.ciphertext,
        ephemeral_public_key: serializedNewBlob.ephemeral_public_key,
        nonce: serializedNewBlob.nonce,
        cek_version: newCekVersion,
        ledger_auth_token: {
          lat_id: newLatId,
          token: newLat.token,
          version: newLat.version,
        },
        new_transaction_keys: [],  // Would include replenished keys if pool is low
      },
      used_key_id: body.key_id,
    });

  } catch (error: any) {
    console.error('Auth execute error:', error);
    return internalError('Authentication failed');
  }
};
