import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  checkRateLimit,
  hashIdentifier,
  tooManyRequests,
  getClientIp,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

// Rate limiting: 5 password set attempts per session per 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 15;

interface SetPasswordRequest {
  enrollment_session_id?: string;  // Optional if using authorizer context
  encrypted_password_hash: string;
  key_id: string;
  nonce: string;
  ephemeral_public_key: string;  // Mobile's ephemeral X25519 public key for ECDH
}

/**
 * POST /vault/enroll/set-password
 *
 * Set password during enrollment.
 * The password hash is encrypted with the specified UTK before sending.
 * Ledger stores the encrypted hash for later verification.
 *
 * Supports two flows:
 * 1. QR Code Flow: session_id comes from enrollment JWT (authorizer context)
 * 2. Direct Flow: enrollment_session_id in request body
 *
 * Returns:
 * - status: 'password_set'
 * - next_step: 'set_policies' | 'finalize'
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Check for authorizer context (QR code flow)
    // The authorizer property exists but isn't in the base type definition
    const authContext = (event.requestContext as any)?.authorizer?.lambda as {
      userGuid?: string;
      sessionId?: string;
    } | undefined;

    const body = parseJsonBody<SetPasswordRequest>(event);

    // Get session_id from authorizer context or request body
    const sessionId = authContext?.sessionId || body.enrollment_session_id;

    if (!sessionId) {
      return badRequest('enrollment_session_id is required', origin);
    }

    // Rate limiting by session ID (prevents brute-force password attempts)
    const sessionHash = hashIdentifier(sessionId);
    const isAllowed = await checkRateLimit(sessionHash, 'enroll_set_password', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MINUTES);
    if (!isAllowed) {
      return tooManyRequests('Too many password attempts. Please try again later.', origin);
    }

    if (!body.encrypted_password_hash) {
      return badRequest('encrypted_password_hash is required', origin);
    }
    if (!body.key_id) {
      return badRequest('key_id is required', origin);
    }
    if (!body.nonce) {
      return badRequest('nonce is required', origin);
    }
    if (!body.ephemeral_public_key) {
      return badRequest('ephemeral_public_key is required', origin);
    }

    // Get enrollment session
    const sessionResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
    }));

    if (!sessionResult.Item) {
      return notFound('Enrollment session not found', origin);
    }

    const session = unmarshall(sessionResult.Item);

    // If using authorizer context, verify user_guid matches
    if (authContext?.userGuid && session.user_guid !== authContext.userGuid) {
      return badRequest('Session does not belong to authenticated user', origin);
    }

    // Validate session state
    if (session.status !== 'STARTED') {
      return conflict(`Invalid session status: ${session.status}`, origin);
    }

    if (session.step !== 'set_password' && session.step !== 'password_required') {
      return conflict(`Invalid session step: ${session.step}`, origin);
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired', origin);
    }

    // Validate the key_id matches the expected one
    if (body.key_id !== session.password_key_id) {
      return badRequest('Invalid key_id for password encryption', origin);
    }

    // Verify the transaction key exists and is unused
    // Note: table uses transaction_id as PK (same value as key_id)
    const keyResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({
        transaction_id: body.key_id,
      }),
    }));

    if (!keyResult.Item) {
      return notFound('Transaction key not found', origin);
    }

    const transactionKey = unmarshall(keyResult.Item);

    // Verify the key belongs to this user
    if (transactionKey.user_guid !== session.user_guid) {
      return badRequest('Transaction key does not belong to this user', origin);
    }

    if (transactionKey.status !== 'UNUSED') {
      return conflict('Transaction key has already been used', origin);
    }

    // Mark the transaction key as used
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({
        transaction_id: body.key_id,
      }),
      UpdateExpression: 'SET #status = :status, used_at = :used_at, used_for = :used_for',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'USED',
        ':used_at': new Date().toISOString(),
        ':used_for': 'enrollment_password',
      }),
    }));

    // Update session with encrypted password hash and ephemeral key
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: sessionId }),
      UpdateExpression: 'SET #step = :step, encrypted_password_hash = :hash, password_nonce = :nonce, password_ephemeral_key = :ephemeral, password_set_at = :set_at',
      ExpressionAttributeNames: {
        '#step': 'step',
      },
      ExpressionAttributeValues: marshall({
        ':step': 'password_set',
        ':hash': body.encrypted_password_hash,
        ':nonce': body.nonce,
        ':ephemeral': body.ephemeral_public_key,
        ':set_at': new Date().toISOString(),
      }),
    }));

    // Audit log (don't include the actual hash)
    await putAudit({
      type: 'enrollment_password_set',
      user_guid: session.user_guid,
      session_id: sessionId,
      key_id: body.key_id,
    }, requestId);

    return ok({
      status: 'password_set',
      next_step: 'finalize',
    }, origin);

  } catch (error: any) {
    console.error('Set password error:', error);
    return internalError('Failed to set password', origin);
  }
};
