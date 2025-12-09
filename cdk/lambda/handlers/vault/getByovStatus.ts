import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * BYOV Status Response
 */
interface ByovStatusResponse {
  has_vault: boolean;
  vault_id?: string;
  vault_name?: string;
  vault_url?: string;
  type?: string;
  status?: string;
  health_status?: string;
  last_health_check?: string;
  created_at?: string;
  api_key_set?: boolean;
  verify_ssl?: boolean;
}

/**
 * GET /vault/byov/status
 *
 * Get the status of the user's BYOV vault registration.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Get vault instance for user
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!result.Item) {
      const response: ByovStatusResponse = {
        has_vault: false,
      };
      return ok(response, origin);
    }

    const vault = unmarshall(result.Item);

    // Only return BYOV vaults in this endpoint
    if (vault.type !== 'BYOV') {
      const response: ByovStatusResponse = {
        has_vault: false,
      };
      return ok(response, origin);
    }

    const response: ByovStatusResponse = {
      has_vault: true,
      vault_id: vault.vault_id,
      vault_name: vault.vault_name,
      vault_url: vault.vault_url,
      type: vault.type,
      status: vault.status,
      health_status: vault.health_status,
      last_health_check: vault.last_health_check,
      created_at: vault.created_at,
      api_key_set: vault.api_key_set || false,
      verify_ssl: vault.verify_ssl !== false,
    };

    return ok(response, origin);

  } catch (error: any) {
    console.error('Get BYOV status error:', error);
    return internalError('Failed to get vault status', origin);
  }
};
