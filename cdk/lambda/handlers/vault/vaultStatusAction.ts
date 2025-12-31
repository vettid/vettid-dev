import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  unauthorized,
  forbidden,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;
const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

const EXPECTED_ENDPOINT = '/api/v1/vault/status';

/**
 * Vault status response structure
 */
interface VaultStatusResponse {
  // Enrollment status
  enrollment_status: 'not_enrolled' | 'pending' | 'enrolled' | 'active' | 'error';
  user_guid?: string;
  enrolled_at?: string;
  last_auth_at?: string;
  last_sync_at?: string;
  device_type?: 'android' | 'ios';
  security_level?: string;
  transaction_keys_remaining?: number;
  credential_version?: number;

  // Instance status (if vault exists)
  instance_status?: 'running' | 'stopped' | 'stopping' | 'starting' | 'pending' | 'terminated' | 'provisioning' | 'initializing';
  instance_id?: string;
  instance_ip?: string;
  nats_endpoint?: string;

  error_message?: string;
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

    return { valid: true, payload };
  } catch {
    return { valid: false, error: 'Invalid token payload' };
  }
}

/**
 * GET /api/v1/vault/status
 *
 * Get the current vault status using action token authentication.
 * Returns enrollment state, device info, key status, and instance status.
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

    // Build response
    let response: VaultStatusResponse = {
      enrollment_status: 'not_enrolled',
    };

    // Look up credential by user_guid
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
      }),
      Limit: 1,
    }));

    if (credentialResult.Items && credentialResult.Items.length > 0) {
      const credential = unmarshall(credentialResult.Items[0]);

      // Get transaction key count using user-index GSI
      const tkResult = await ddb.send(new QueryCommand({
        TableName: TABLE_TRANSACTION_KEYS,
        IndexName: 'user-index',
        KeyConditionExpression: 'user_guid = :guid',
        FilterExpression: '#status = :unused',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: marshall({
          ':guid': credential.user_guid,
          ':unused': 'UNUSED',
        }),
        Select: 'COUNT',
      }));

      response = {
        enrollment_status: credential.status === 'ACTIVE' ? 'active' : 'enrolled',
        user_guid: credential.user_guid,
        enrolled_at: credential.created_at,
        last_auth_at: credential.last_auth_at,
        last_sync_at: credential.last_sync_at,
        device_type: credential.device_type,
        security_level: credential.security_level,
        transaction_keys_remaining: tkResult.Count || 0,
        credential_version: credential.version || 1,
      };
    } else {
      // Check for pending enrollment session (using user-index GSI)
      const sessionResult = await ddb.send(new QueryCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        IndexName: 'user-index',
        KeyConditionExpression: 'user_guid = :guid',
        ExpressionAttributeValues: marshall({
          ':guid': userGuid,
        }),
        ScanIndexForward: false, // Get most recent first
        Limit: 1,
      }));

      if (sessionResult.Items && sessionResult.Items.length > 0) {
        const session = unmarshall(sessionResult.Items[0]);

        // Check if session is expired
        if (new Date(session.expires_at) >= new Date()) {
          response = {
            enrollment_status: 'pending',
            user_guid: session.user_guid,
            device_type: session.device_type,
          };
        }
      }
    }

    // Get vault instance status if enrolled
    if (response.enrollment_status !== 'not_enrolled') {
      const instanceResult = await ddb.send(new GetItemCommand({
        TableName: TABLE_VAULT_INSTANCES,
        Key: marshall({ user_guid: userGuid }),
      }));

      if (instanceResult.Item) {
        const instance = unmarshall(instanceResult.Item);
        response.instance_status = instance.status;
        response.instance_id = instance.instance_id;

        // Only include IP and NATS endpoint if vault is running
        if (instance.status === 'running') {
          response.instance_ip = instance.public_ip;
          response.nats_endpoint = instance.nats_endpoint;
        }
      }
    }

    // Audit log
    await putAudit({
      type: 'vault_status_queried_via_action',
      user_guid: userGuid,
      token_id: tokenId,
      enrollment_status: response.enrollment_status,
      instance_status: response.instance_status,
    }, requestId);

    return ok(response);

  } catch (error: any) {
    console.error('Get vault status action error:', error);
    return internalError('Failed to get vault status');
  }
};
