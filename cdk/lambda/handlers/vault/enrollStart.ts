import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { generateKeyPairSync } from 'crypto';
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

// Table names from environment
const TABLE_INVITES = process.env.TABLE_INVITES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

// Number of transaction keys to generate per enrollment
const INITIAL_TRANSACTION_KEY_COUNT = 20;

interface EnrollStartRequest {
  invitation_code: string;
  device_id: string;
  attestation_data: string;
}

/**
 * Generate an X25519 key pair for transaction keys
 * Returns base64-encoded public and private keys
 */
function generateX25519KeyPair(): { publicKey: string; privateKey: string } {
  const keyPair = generateKeyPairSync('x25519');
  const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const privateKey = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });

  // Extract raw key bytes (skip DER header)
  // X25519 public key in SPKI format has 12-byte header
  // X25519 private key in PKCS8 format has 16-byte header
  const rawPublic = publicKey.slice(12);
  const rawPrivate = privateKey.slice(16);

  return {
    publicKey: rawPublic.toString('base64'),
    privateKey: rawPrivate.toString('base64'),
  };
}

/**
 * POST /api/v1/enroll/start
 *
 * Start enrollment with invitation code.
 * Validates the invitation, creates enrollment session, generates transaction keys.
 *
 * Returns:
 * - enrollment_session_id
 * - user_guid
 * - transaction_keys (UTKs - public keys only)
 * - password_prompt with key_id to use
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Parse request body
    const body = parseJsonBody<EnrollStartRequest>(event);

    if (!body.invitation_code) {
      return badRequest('invitation_code is required');
    }
    if (!body.device_id) {
      return badRequest('device_id is required');
    }
    if (!body.attestation_data) {
      return badRequest('attestation_data is required');
    }

    // Validate invitation code exists and is valid
    const inviteResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_INVITES,
      Key: marshall({ code: body.invitation_code }),
    }));

    if (!inviteResult.Item) {
      return notFound('Invalid invitation code');
    }

    const invite = unmarshall(inviteResult.Item);

    // Check if invitation is already used
    if (invite.status === 'used') {
      return conflict('This invitation code has already been used');
    }

    // Check if invitation is expired
    if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
      return badRequest('This invitation code has expired');
    }

    // TODO: Validate attestation_data based on platform
    // For now, we just verify it's present and base64 encoded
    try {
      Buffer.from(body.attestation_data, 'base64');
    } catch {
      return badRequest('Invalid attestation_data format');
    }

    // Generate user GUID for this enrollment
    const userGuid = generateSecureId('user', 32);

    // Generate enrollment session
    const sessionId = generateSecureId('enroll', 32);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes

    // Generate transaction keys (LTK/UTK pairs)
    const transactionKeys: Array<{
      key_id: string;
      public_key: string;
      algorithm: string;
    }> = [];

    for (let i = 0; i < INITIAL_TRANSACTION_KEY_COUNT; i++) {
      const keyPair = generateX25519KeyPair();
      const keyId = generateSecureId('tk', 16);

      // Store the full key pair (LTK is private, UTK is public)
      await ddb.send(new PutItemCommand({
        TableName: TABLE_TRANSACTION_KEYS,
        Item: marshall({
          user_guid: userGuid,
          key_id: keyId,
          public_key: keyPair.publicKey,      // UTK - sent to mobile
          private_key: keyPair.privateKey,    // LTK - stays on ledger (encrypted at rest by DynamoDB)
          algorithm: 'X25519',
          status: 'UNUSED',
          key_index: i,
          created_at: now.toISOString(),
        }),
      }));

      // Only include public key in response (UTK)
      transactionKeys.push({
        key_id: keyId,
        public_key: keyPair.publicKey,
        algorithm: 'X25519',
      });
    }

    // Select the first key for password encryption
    const passwordKeyId = transactionKeys[0].key_id;

    // Create enrollment session
    await ddb.send(new PutItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Item: marshall({
        session_id: sessionId,
        user_guid: userGuid,
        invitation_code: body.invitation_code,
        device_id: body.device_id,
        attestation_data: body.attestation_data,
        status: 'STARTED',
        step: 'password_required',
        password_key_id: passwordKeyId,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        expires_at_ttl: Math.floor(expiresAt.getTime() / 1000),
      }),
    }));

    // Mark invitation as pending (not fully used until enrollment completes)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_INVITES,
      Key: marshall({ code: body.invitation_code }),
      UpdateExpression: 'SET #status = :status, enrollment_session_id = :session_id, enrollment_started_at = :started_at',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'pending',
        ':session_id': sessionId,
        ':started_at': now.toISOString(),
      }),
    }));

    // Audit log
    await putAudit({
      type: 'enrollment_started',
      user_guid: userGuid,
      session_id: sessionId,
      invitation_code: body.invitation_code.substring(0, 8) + '...',  // Partial for privacy
      device_id: body.device_id.substring(0, 8) + '...',  // Partial for privacy
    }, requestId);

    return ok({
      enrollment_session_id: sessionId,
      user_guid: userGuid,
      transaction_keys: transactionKeys,
      password_prompt: {
        use_key_id: passwordKeyId,
        message: 'Please create a secure password for your credential.',
      },
    });

  } catch (error: any) {
    console.error('Enrollment start error:', error);
    return internalError('Failed to start enrollment');
  }
};
