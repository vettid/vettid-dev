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
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

interface SetPasswordRequest {
  enrollment_session_id: string;
  encrypted_password_hash: string;
  key_id: string;
  nonce: string;
}

/**
 * POST /api/v1/enroll/set-password
 *
 * Set password during enrollment.
 * The password hash is encrypted with the specified UTK before sending.
 * Ledger stores the encrypted hash for later verification.
 *
 * Returns:
 * - status: 'password_set'
 * - next_step: 'set_policies' | 'finalize'
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    const body = parseJsonBody<SetPasswordRequest>(event);

    if (!body.enrollment_session_id) {
      return badRequest('enrollment_session_id is required');
    }
    if (!body.encrypted_password_hash) {
      return badRequest('encrypted_password_hash is required');
    }
    if (!body.key_id) {
      return badRequest('key_id is required');
    }
    if (!body.nonce) {
      return badRequest('nonce is required');
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

    if (session.step !== 'password_required') {
      return conflict(`Invalid session step: ${session.step}`);
    }

    // Check session expiry
    if (new Date(session.expires_at) < new Date()) {
      return badRequest('Enrollment session has expired');
    }

    // Validate the key_id matches the expected one
    if (body.key_id !== session.password_key_id) {
      return badRequest('Invalid key_id for password encryption');
    }

    // Verify the transaction key exists and is unused
    const keyResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({
        user_guid: session.user_guid,
        key_id: body.key_id,
      }),
    }));

    if (!keyResult.Item) {
      return notFound('Transaction key not found');
    }

    const transactionKey = unmarshall(keyResult.Item);

    if (transactionKey.status !== 'UNUSED') {
      return conflict('Transaction key has already been used');
    }

    // Mark the transaction key as used
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      Key: marshall({
        user_guid: session.user_guid,
        key_id: body.key_id,
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

    // Update session with encrypted password hash
    // Note: The encrypted hash will be decrypted and re-encrypted with the credential when finalizing
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      Key: marshall({ session_id: body.enrollment_session_id }),
      UpdateExpression: 'SET #step = :step, encrypted_password_hash = :hash, password_nonce = :nonce, password_set_at = :set_at',
      ExpressionAttributeNames: {
        '#step': 'step',
      },
      ExpressionAttributeValues: marshall({
        ':step': 'password_set',
        ':hash': body.encrypted_password_hash,
        ':nonce': body.nonce,
        ':set_at': new Date().toISOString(),
      }),
    }));

    // Audit log (don't include the actual hash)
    await putAudit({
      action: 'enrollment_password_set',
      user_guid: session.user_guid,
      session_id: body.enrollment_session_id,
      key_id: body.key_id,
    }, requestId);

    return ok({
      status: 'password_set',
      next_step: 'finalize',  // Skip policies for now, can add later
      // Optional: include policy_options if we want to support set_policies step
    });

  } catch (error: any) {
    console.error('Set password error:', error);
    return internalError('Failed to set password');
  }
};
