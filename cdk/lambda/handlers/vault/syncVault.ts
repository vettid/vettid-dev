import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, UpdateItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  requireUserClaims,
  generateSecureId,
} from '../../common/util';
import { generateX25519KeyPair } from '../../common/crypto';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

// Minimum transaction keys to maintain
const MIN_TRANSACTION_KEYS = 10;
// Number of keys to generate when replenishing
const REPLENISH_KEY_COUNT = 20;

/**
 * Sync response structure
 */
interface SyncResponse {
  status: 'synced' | 'keys_replenished' | 'error';
  last_sync_at: string;
  transaction_keys_remaining: number;
  new_transaction_keys?: Array<{
    key_id: string;
    public_key: string;
    algorithm: string;
  }>;
  credential_version: number;
}

/**
 * POST /vault/sync
 *
 * Sync vault state and replenish transaction keys if needed.
 * Called periodically by mobile apps to maintain key pool.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Look up credential by user_guid (user_guid is the partition key)
    const credentialResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIALS,
      KeyConditionExpression: 'user_guid = :guid',
      ExpressionAttributeValues: marshall({
        ':guid': claims.user_guid,
      }),
      Limit: 1,
    }));

    if (!credentialResult.Items || credentialResult.Items.length === 0) {
      return notFound('No enrolled vault found');
    }

    const credential = unmarshall(credentialResult.Items[0]);
    const userGuid = credential.user_guid;
    const now = new Date();

    // Count remaining unused transaction keys
    const tkCountResult = await ddb.send(new QueryCommand({
      TableName: TABLE_TRANSACTION_KEYS,
      KeyConditionExpression: 'user_guid = :guid',
      FilterExpression: '#status = :unused',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':unused': 'UNUSED',
      }),
      Select: 'COUNT',
    }));

    const remainingKeys = tkCountResult.Count || 0;
    let newTransactionKeys: Array<{ key_id: string; public_key: string; algorithm: string }> = [];
    let syncStatus: 'synced' | 'keys_replenished' = 'synced';

    // Replenish transaction keys if below minimum
    if (remainingKeys < MIN_TRANSACTION_KEYS) {
      // Get current max key index
      const existingKeysResult = await ddb.send(new QueryCommand({
        TableName: TABLE_TRANSACTION_KEYS,
        KeyConditionExpression: 'user_guid = :guid',
        ExpressionAttributeValues: marshall({
          ':guid': userGuid,
        }),
        ProjectionExpression: 'key_index',
        ScanIndexForward: false,
        Limit: 1,
      }));

      let startIndex = 0;
      if (existingKeysResult.Items && existingKeysResult.Items.length > 0) {
        const lastKey = unmarshall(existingKeysResult.Items[0]);
        startIndex = (lastKey.key_index || 0) + 1;
      }

      // Generate new transaction keys
      for (let i = 0; i < REPLENISH_KEY_COUNT; i++) {
        const keyPair = generateX25519KeyPair();
        const keyId = generateSecureId('tk', 16);

        const publicKeyB64 = keyPair.publicKey.toString('base64');
        const privateKeyB64 = keyPair.privateKey.toString('base64');

        await ddb.send(new PutItemCommand({
          TableName: TABLE_TRANSACTION_KEYS,
          Item: marshall({
            user_guid: userGuid,
            key_id: keyId,
            public_key: publicKeyB64,
            private_key: privateKeyB64,
            algorithm: 'X25519',
            status: 'UNUSED',
            key_index: startIndex + i,
            created_at: now.toISOString(),
          }),
        }));

        // Only include public key in response
        newTransactionKeys.push({
          key_id: keyId,
          public_key: publicKeyB64,
          algorithm: 'X25519',
        });
      }

      syncStatus = 'keys_replenished';
    }

    // Update last sync timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ credential_id: credential.credential_id }),
      UpdateExpression: 'SET last_sync_at = :sync_at',
      ExpressionAttributeValues: marshall({
        ':sync_at': now.toISOString(),
      }),
    }));

    const response: SyncResponse = {
      status: syncStatus,
      last_sync_at: now.toISOString(),
      transaction_keys_remaining: remainingKeys + newTransactionKeys.length,
      credential_version: credential.version || 1,
    };

    if (newTransactionKeys.length > 0) {
      response.new_transaction_keys = newTransactionKeys;
    }

    return ok(response);

  } catch (error: any) {
    console.error('Vault sync error:', error);
    return internalError('Failed to sync vault');
  }
};
