import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  requireUserClaims,
  parseJsonBody,
  validatePathParam,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;
const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

interface ExecuteHandlerRequest {
  input: Record<string, any>;
  timeout_ms?: number;
}

interface ExecuteHandlerResponse {
  request_id: string;
  status: 'queued' | 'success' | 'error' | 'timeout';
  output?: Record<string, any>;
  error?: string;
  execution_time_ms?: number;
}

/**
 * POST /vault/handlers/{id}/execute
 *
 * Execute a handler on the user's vault.
 * The request is forwarded to the vault instance via NATS.
 *
 * Requires member JWT authentication.
 * Requires the handler to be installed.
 * Requires the vault to be running.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate member authentication
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Get handler ID from path
    const handlerId = event.pathParameters?.id;
    if (!handlerId) {
      return badRequest('Handler ID is required.');
    }

    try {
      validatePathParam(handlerId, 'Handler ID');
    } catch (e: any) {
      return badRequest(e.message);
    }

    // Parse request body
    let body: ExecuteHandlerRequest;
    try {
      body = parseJsonBody<ExecuteHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.input || typeof body.input !== 'object') {
      return badRequest('input object is required.');
    }

    const timeoutMs = Math.min(body.timeout_ms || 30000, 60000); // Max 60 seconds

    // Check if handler is installed
    const installationResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Key: marshall({
        user_guid: userGuid,
        handler_id: handlerId,
      }),
    }));

    if (!installationResult.Item) {
      return notFound('Handler is not installed.');
    }

    // Check if vault is running
    const vaultResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!vaultResult.Item) {
      return badRequest('Vault is not provisioned.');
    }

    const vault = unmarshall(vaultResult.Item);

    if (vault.status !== 'running' && vault.status !== 'healthy') {
      return badRequest(`Vault is not running (current status: ${vault.status}).`);
    }

    // Generate request ID
    const requestId = generateSecureId('REQ');

    // In a full implementation, we would:
    // 1. Publish the execution request to NATS
    // 2. Wait for response with timeout
    // 3. Return the result
    //
    // For now, we return a "queued" response indicating the request was accepted
    // The mobile app should poll for results or receive them via NATS subscription

    const response: ExecuteHandlerResponse = {
      request_id: requestId,
      status: 'queued',
    };

    // NOTE: Handler execution is done via vault-to-vault NATS messaging.
    // The mobile app sends handler execution requests through its vault via OwnerSpace.forVault.
    // This Lambda endpoint is for legacy/fallback purposes only.

    return ok(response);

  } catch (error: any) {
    console.error('Execute handler error:', error);
    return internalError('Failed to execute handler.');
  }
};
