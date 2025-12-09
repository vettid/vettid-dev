import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  getRequestId,
  requireUserClaims,
  putAudit,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * BYOV Registration Request
 */
interface ByovRegistrationRequest {
  vault_url: string;           // HTTPS URL to the vault endpoint
  vault_name?: string;         // Optional friendly name
  api_key?: string;            // Optional API key for authentication
  verify_ssl?: boolean;        // Whether to verify SSL (default true)
}

/**
 * POST /vault/byov/register
 *
 * Register a self-hosted vault (Bring Your Own Vault).
 * The vault must be accessible via HTTPS and respond to health checks.
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

    let request: ByovRegistrationRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest('Invalid JSON body', origin);
    }

    // Validate vault URL
    if (!request.vault_url) {
      return badRequest('vault_url is required', origin);
    }

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

    // Check if user already has a vault registered
    const existingVault = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (existingVault.Item) {
      const existing = unmarshall(existingVault.Item);
      if (existing.status === 'ACTIVE' || existing.status === 'PENDING') {
        return conflict('You already have a vault registered. Terminate it first to register a new one.', origin);
      }
    }

    const now = new Date().toISOString();
    const vaultId = generateSecureId('byov', 16);

    // Create vault instance record
    const vaultRecord = {
      user_guid: userGuid,
      vault_id: vaultId,
      instance_id: `byov-${vaultId}`, // For GSI compatibility
      type: 'BYOV',
      vault_url: vaultUrl.toString(),
      vault_name: request.vault_name || 'My Vault',
      api_key_set: !!request.api_key,
      verify_ssl: request.verify_ssl !== false,
      status: 'PENDING_VERIFICATION',
      created_at: now,
      updated_at: now,
      last_health_check: null,
      health_status: 'UNKNOWN',
    };

    // Store API key separately if provided (would use Secrets Manager in production)
    if (request.api_key) {
      (vaultRecord as any).api_key_hash = await hashApiKey(request.api_key);
    }

    await ddb.send(new PutItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Item: marshall(vaultRecord),
    }));

    // Audit log
    await putAudit({
      type: 'byov_vault_registered',
      user_guid: userGuid,
      vault_id: vaultId,
      vault_url: vaultUrl.host, // Log host only, not full URL
    }, requestId);

    return ok({
      vault_id: vaultId,
      vault_name: vaultRecord.vault_name,
      vault_url: vaultUrl.toString(),
      status: 'PENDING_VERIFICATION',
      message: 'Vault registered. Verification will begin shortly.',
    }, origin);

  } catch (error: any) {
    console.error('Register BYOV vault error:', error);
    return internalError('Failed to register vault', origin);
  }
};

/**
 * Hash API key for storage (simple hash - use proper KMS in production)
 */
async function hashApiKey(apiKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
