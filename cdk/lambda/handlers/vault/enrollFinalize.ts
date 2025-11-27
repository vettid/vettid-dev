import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { randomBytes, generateKeyPairSync, createCipheriv, createHash } from 'crypto';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_CREDENTIAL_KEYS = process.env.TABLE_CREDENTIAL_KEYS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

interface FinalizeRequest {
  enrollment_session_id: string;
}

/**
 * Generate an X25519 key pair for CEK (Credential Encryption Key)
 */
function generateX25519KeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const keyPair = generateKeyPairSync('x25519');
  const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKey = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

  // Extract raw key bytes
  const rawPublic = publicKey.slice(12);
  const rawPrivate = privateKey.slice(16);

  return {
    publicKey: rawPublic,
    privateKey: rawPrivate,
  };
}

/**
 * Generate a secure LAT token
 */
function generateLatToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Encrypt the credential blob
 * In production, this would use ChaCha20-Poly1305 with proper key derivation
 * For now, using AES-256-GCM as a placeholder
 */
function encryptCredentialBlob(data: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', createHash('sha256').update(key).digest(), iv);

  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { ciphertext, iv, tag };
}

/**
 * POST /api/v1/enroll/finalize
 *
 * Finalize enrollment and create the credential.
 * Generates CEK, encrypts credential blob, creates LAT.
 *
 * Returns:
 * - status: 'enrolled'
 * - credential_package with encrypted_blob, cek_version, lat, and remaining transaction_keys
 * - vault_status
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    const body = parseJsonBody<FinalizeRequest>(event);

    if (!body.enrollment_session_id) {
      return badRequest('enrollment_session_id is required');
    }

    // Get enrollment session
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: body.enrollment_session_id }),
    }));

    if (!sessionResult.Item) {
      return notFound('Enrollment session not found');
    }

    const session = unmarshall(sessionResult.Item);

    // Validate session state
    if (session.status !== 'STARTED') {
      return conflict(`Invalid session status: ${session.status}`);
    }

    if (session.step !== 'password_set') {
      return conflict('Password must be set before finalizing enrollment');
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired');
    }

    const now = new Date();
    const userGuid = session.user_guid;

    // Generate CEK (Credential Encryption Key)
    const cekKeyPair = generateX25519KeyPair();
    const cekVersion = 1;

    // Store CEK private key (encrypted at rest by DynamoDB)
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_KEYS,
      Item: marshall({
        user_guid: userGuid,
        version: cekVersion,
        private_key: cekKeyPair.privateKey.toString('base64'),
        public_key: cekKeyPair.publicKey.toString('base64'),
        algorithm: 'X25519',
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Generate LAT (Ledger Auth Token)
    const latToken = generateLatToken();
    const latId = generateSecureId('lat', 16);
    const latVersion = 1;

    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Item: marshall({
        user_guid: userGuid,
        version: latVersion,
        lat_id: latId,
        token_hash: createHash('sha256').update(latToken).digest('hex'),  // Store hash, not raw token
        status: 'ACTIVE',
        created_at: now.toISOString(),
      }),
    }));

    // Create credential data structure
    const credentialData = {
      guid: userGuid,
      version: 1,
      created_at: now.toISOString(),
      password_hash: session.encrypted_password_hash,  // Store the encrypted hash from enrollment
      password_nonce: session.password_nonce,
      policies: {
        cache_period: 3600,
        require_biometric: false,
        max_attempts: 3,
      },
      secrets: {},
    };

    // Encrypt credential blob with CEK
    const credentialJson = JSON.stringify(credentialData);
    const { ciphertext, iv, tag } = encryptCredentialBlob(
      Buffer.from(credentialJson, 'utf-8'),
      cekKeyPair.privateKey
    );

    // Combine into encrypted blob format: iv || tag || ciphertext
    const encryptedBlob = Buffer.concat([iv, tag, ciphertext]).toString('base64');

    // Store credential metadata
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIALS,
      Item: marshall({
        user_guid: userGuid,
        status: 'ACTIVE',
        cek_version: cekVersion,
        lat_version: latVersion,
        device_id: session.device_id,
        invitation_code: session.invitation_code,
        created_at: now.toISOString(),
        last_action_at: now.toISOString(),
        failed_auth_count: 0,
      }),
    }));

    // Get remaining unused transaction keys
    const unusedKeysResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      KeyConditionExpression: 'user_guid = :user_guid',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':user_guid': userGuid,
        ':status': 'UNUSED',
      }),
    }));

    const remainingKeys = (unusedKeysResult.Items || []).map(item => {
      const key = unmarshall(item);
      return {
        key_id: key.key_id,
        public_key: key.public_key,
        algorithm: key.algorithm,
      };
    });

    // Mark session as completed
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: body.enrollment_session_id }),
      UpdateExpression: 'SET #status = :status, completed_at = :completed_at',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'COMPLETED',
        ':completed_at': now.toISOString(),
      }),
    }));

    // Mark invitation as used
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_INVITES,
      Key: marshall({ code: session.invitation_code }),
      UpdateExpression: 'SET #status = :status, used_at = :used_at, used_by_guid = :user_guid',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'used',
        ':used_at': now.toISOString(),
        ':user_guid': userGuid,
      }),
    }));

    // Audit log
    await putAudit({
      action: 'enrollment_completed',
      user_guid: userGuid,
      session_id: body.enrollment_session_id,
      cek_version: cekVersion,
      lat_version: latVersion,
      transaction_keys_remaining: remainingKeys.length,
    }, requestId);

    return ok({
      status: 'enrolled',
      credential_package: {
        user_guid: userGuid,
        encrypted_blob: encryptedBlob,
        cek_version: cekVersion,
        ledger_auth_token: {
          lat_id: latId,
          token: latToken,  // Send raw token to mobile (will be stored for verification)
          version: latVersion,
        },
        transaction_keys: remainingKeys,
      },
      vault_status: 'PROVISIONING',
    });

  } catch (error: any) {
    console.error('Finalize enrollment error:', error);
    return internalError('Failed to finalize enrollment');
  }
};
