import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, unauthorized, getRequestId, getUserGuid } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

/**
 * GET /vault/status
 *
 * Returns the vault enrollment status for the authenticated user.
 *
 * Statuses:
 * - not_enrolled: No vault or enrollment session exists
 * - pending: Enrollment session created, waiting for mobile app
 * - enrolled: NATS account exists, vault is ready for use
 * - active: Vault is actively connected and in use
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Get user GUID from JWT claims
    const userGuid = getUserGuid(event);
    if (!userGuid) {
      return unauthorized('Authentication required', origin);
    }

    // Check VaultInstances table for enrolled/active vaults
    const vaultResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (vaultResult.Item) {
      const vault = unmarshall(vaultResult.Item);

      // Determine status based on vault instance status
      let status: 'enrolled' | 'active' = 'enrolled';
      if (vault.status === 'active' || vault.status === 'connected') {
        status = 'active';
      }

      return ok({
        status,
        enrolled_at: vault.created_at,
        last_sync_at: vault.last_seen_at,
        device_type: vault.device_type,
        instance_id: vault.instance_id,
        // Include attestation info if available
        attestation_time: vault.attestation_time,
        pcr_hash: vault.pcr_hash,
        // Transaction keys status
        transaction_keys_remaining: vault.transaction_keys_remaining,
      }, origin);
    }

    // Check NATS accounts table - if account exists but no vault instance,
    // user is enrolled but hasn't initialized the vault yet
    const natsResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (natsResult.Item) {
      const natsAccount = unmarshall(natsResult.Item);
      return ok({
        status: 'enrolled',
        enrolled_at: natsAccount.created_at,
        storage_type: natsAccount.storage_type || 'enclave',
      }, origin);
    }

    // Check for pending enrollment sessions (exclude expired ones)
    const sessionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_ENROLLMENT_SESSIONS,
      IndexName: 'user-index',
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#s IN (:web_initiated, :authenticated, :started) AND expires_at > :now',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':web_initiated': 'WEB_INITIATED',
        ':authenticated': 'AUTHENTICATED',
        ':started': 'STARTED',
        ':now': Date.now(),
      }),
      Limit: 1,
      ScanIndexForward: false, // Most recent first
    }));

    if (sessionResult.Items && sessionResult.Items.length > 0) {
      const session = unmarshall(sessionResult.Items[0]);
      return ok({
        status: 'pending',
        started_at: session.created_at,
        session_status: session.status,
        expires_at: session.expires_at,
      }, origin);
    }

    // No vault, no NATS account, no pending session
    return ok({
      status: 'not_enrolled',
    }, origin);

  } catch (error: any) {
    console.error('Error getting vault status:', error);
    return internalError('Failed to get vault status', origin);
  }
};
