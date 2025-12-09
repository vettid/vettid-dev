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
 * POST /vault/byov/verify
 *
 * Verify connectivity to a registered BYOV vault.
 * Performs a health check and updates the vault status.
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
      return notFound('No vault registered', origin);
    }

    const vault = unmarshall(result.Item);

    if (vault.type !== 'BYOV') {
      return badRequest('This endpoint is only for BYOV vaults', origin);
    }

    const now = new Date().toISOString();
    let healthStatus = 'UNKNOWN';
    let healthMessage = '';
    let newStatus = vault.status;

    // Perform health check
    try {
      const healthUrl = new URL('/api/health', vault.vault_url).toString();

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(healthUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'VettID-BYOV-Checker/1.0',
        },
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        healthStatus = 'HEALTHY';
        healthMessage = 'Vault is reachable and responding';
        newStatus = 'ACTIVE';
      } else if (response.status === 401 || response.status === 403) {
        healthStatus = 'AUTH_REQUIRED';
        healthMessage = 'Vault requires authentication. Please provide an API key.';
        newStatus = 'PENDING_AUTH';
      } else {
        healthStatus = 'UNHEALTHY';
        healthMessage = `Vault returned status ${response.status}`;
        newStatus = 'ERROR';
      }
    } catch (fetchError: any) {
      if (fetchError.name === 'AbortError') {
        healthStatus = 'TIMEOUT';
        healthMessage = 'Connection timed out after 10 seconds';
      } else if (fetchError.cause?.code === 'ENOTFOUND') {
        healthStatus = 'DNS_ERROR';
        healthMessage = 'Could not resolve vault hostname';
      } else if (fetchError.cause?.code === 'ECONNREFUSED') {
        healthStatus = 'CONNECTION_REFUSED';
        healthMessage = 'Connection refused. Is the vault running?';
      } else if (fetchError.message?.includes('certificate')) {
        healthStatus = 'SSL_ERROR';
        healthMessage = 'SSL certificate error. Check your certificate configuration.';
      } else {
        healthStatus = 'UNREACHABLE';
        healthMessage = fetchError.message || 'Could not reach vault';
      }
      newStatus = 'ERROR';
    }

    // Update vault record
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET health_status = :health, last_health_check = :now, #status = :status, health_message = :msg, updated_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':health': healthStatus,
        ':now': now,
        ':status': newStatus,
        ':msg': healthMessage,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'byov_vault_verified',
      user_guid: userGuid,
      vault_id: vault.vault_id,
      health_status: healthStatus,
      new_status: newStatus,
    }, requestId);

    return ok({
      vault_id: vault.vault_id,
      health_status: healthStatus,
      health_message: healthMessage,
      status: newStatus,
      last_health_check: now,
    }, origin);

  } catch (error: any) {
    console.error('Verify BYOV vault error:', error);
    return internalError('Failed to verify vault', origin);
  }
};
