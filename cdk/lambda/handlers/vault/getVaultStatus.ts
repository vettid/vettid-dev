import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_TRANSACTION_KEYS = process.env.TABLE_TRANSACTION_KEYS!;

/**
 * Vault status response structure
 */
interface VaultStatusResponse {
  status: 'not_enrolled' | 'pending' | 'enrolled' | 'active' | 'error';
  user_guid?: string;
  enrolled_at?: string;
  last_auth_at?: string;
  last_sync_at?: string;
  device_type?: 'android' | 'ios';
  security_level?: string;
  transaction_keys_remaining?: number;
  credential_version?: number;
  error_message?: string;
}

/**
 * GET /vault/status
 *
 * Get the current vault status for the authenticated member.
 * Returns enrollment state, device info, and key status.
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

    // Use user_guid from claims (which maps to Cognito sub)
    const userGuid = claims.user_guid;

    // Look up credential by user_guid (user_guid is the partition key)
    // First, check if there's a completed enrollment
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

      const response: VaultStatusResponse = {
        status: credential.status === 'ACTIVE' ? 'active' : 'enrolled',
        user_guid: credential.user_guid,
        enrolled_at: credential.created_at,
        last_auth_at: credential.last_auth_at,
        last_sync_at: credential.last_sync_at,
        device_type: credential.device_type,
        security_level: credential.security_level,
        transaction_keys_remaining: tkResult.Count || 0,
        credential_version: credential.version || 1,
      };

      return ok(response);
    }

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
      if (new Date(session.expires_at) < new Date()) {
        const response: VaultStatusResponse = {
          status: 'not_enrolled',
        };
        return ok(response);
      }

      const response: VaultStatusResponse = {
        status: 'pending',
        user_guid: session.user_guid,
        device_type: session.device_type,
      };

      return ok(response);
    }

    // No enrollment found
    const response: VaultStatusResponse = {
      status: 'not_enrolled',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Get vault status error:', error);
    return internalError('Failed to get vault status');
  }
};
