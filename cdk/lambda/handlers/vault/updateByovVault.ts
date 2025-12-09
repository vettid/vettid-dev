import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  requireUserClaims,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * BYOV Update Request
 */
interface ByovUpdateRequest {
  vault_name?: string;
  vault_url?: string;
  api_key?: string;
  verify_ssl?: boolean;
  clear_api_key?: boolean;
}

/**
 * PATCH /vault/byov
 *
 * Update BYOV vault settings.
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

    // Parse request body
    if (!event.body) {
      return badRequest('Request body required', origin);
    }

    let request: ByovUpdateRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Get existing vault
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!result.Item) {
      return notFound('No vault registered', origin);
    }

    const vault = unmarshall(result.Item);

    if (vault.type !== 'BYOV') {
      return badRequest('This endpoint is only for BYOV vaults', origin);
    }

    // Build update expression
    const updateParts: string[] = ['updated_at = :now'];
    const expressionValues: Record<string, any> = {
      ':now': new Date().toISOString(),
    };

    if (request.vault_name !== undefined) {
      updateParts.push('vault_name = :name');
      expressionValues[':name'] = request.vault_name;
    }

    if (request.vault_url !== undefined) {
      // Validate URL format
      let vaultUrl: URL;
      try {
        vaultUrl = new URL(request.vault_url);
        if (vaultUrl.protocol !== 'https:') {
          return badRequest('vault_url must use HTTPS', origin);
        }
      } catch {
        return badRequest('Invalid vault_url format', origin);
      }
      updateParts.push('vault_url = :url');
      expressionValues[':url'] = vaultUrl.toString();
      // Reset verification status when URL changes
      updateParts.push('#status = :status');
      expressionValues[':status'] = 'PENDING_VERIFICATION';
      updateParts.push('health_status = :health');
      expressionValues[':health'] = 'UNKNOWN';
    }

    if (request.verify_ssl !== undefined) {
      updateParts.push('verify_ssl = :ssl');
      expressionValues[':ssl'] = request.verify_ssl;
    }

    if (request.clear_api_key) {
      updateParts.push('api_key_set = :keySet');
      updateParts.push('api_key_hash = :keyHash');
      expressionValues[':keySet'] = false;
      expressionValues[':keyHash'] = null;
    } else if (request.api_key !== undefined) {
      updateParts.push('api_key_set = :keySet');
      updateParts.push('api_key_hash = :keyHash');
      expressionValues[':keySet'] = true;
      expressionValues[':keyHash'] = await hashApiKey(request.api_key);
    }

    // Execute update
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET ' + updateParts.join(', '),
      ExpressionAttributeNames: request.vault_url ? { '#status': 'status' } : undefined,
      ExpressionAttributeValues: marshall(expressionValues),
    }));

    // Audit log
    await putAudit({
      type: 'byov_vault_updated',
      user_guid: userGuid,
      vault_id: vault.vault_id,
      fields_updated: Object.keys(request).filter(k => request[k as keyof ByovUpdateRequest] !== undefined),
    }, requestId);

    return ok({
      vault_id: vault.vault_id,
      message: 'Vault settings updated',
      requires_verification: !!request.vault_url,
    }, origin);

  } catch (error: any) {
    console.error('Update BYOV vault error:', error);
    return internalError('Failed to update vault', origin);
  }
};

/**
 * Hash API key for storage
 */
async function hashApiKey(apiKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
