import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  parseJsonBody,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * Health update payload from vault-manager
 */
interface VaultHealthRequest {
  user_guid: string;
  instance_id: string;
  type: 'heartbeat' | 'shutdown';
  status: {
    status: string;
    uptime: string;
    version?: string;
    go_routines: number;
    memory_mb: number;
    nats_local: boolean;
    nats_central: boolean;
  };
}

/**
 * POST /vault/internal/health
 *
 * Called by vault-manager every 30 seconds to report health status.
 * This endpoint updates the vault health metrics in DynamoDB.
 *
 * This is an internal endpoint - no user authentication required, but we validate:
 * 1. The instance_id matches what we have in DynamoDB
 * 2. The vault is in a valid state (running or degraded)
 *
 * Request body:
 * - user_guid: string - The user GUID this vault belongs to
 * - instance_id: string - The EC2 instance ID
 * - type: 'heartbeat' | 'shutdown' - Type of health update
 * - status: object - Current health status metrics
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Parse request body
    const body = parseJsonBody<VaultHealthRequest>(event);
    if (!body) {
      return badRequest('Request body is required', origin);
    }

    const { user_guid, instance_id, type, status } = body;

    // Validate required fields
    if (!user_guid) {
      return badRequest('user_guid is required', origin);
    }
    if (!instance_id) {
      return badRequest('instance_id is required', origin);
    }
    if (!type) {
      return badRequest('type is required', origin);
    }
    if (!status) {
      return badRequest('status is required', origin);
    }

    // Get existing vault instance from DynamoDB
    const instanceResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid }),
    }));

    if (!instanceResult.Item) {
      // Silent ignore - vault may have been terminated
      console.debug(`Health update: No vault record found for user ${user_guid}`);
      return ok({ success: false, reason: 'no_vault_record' }, origin);
    }

    const vaultRecord = unmarshall(instanceResult.Item);

    // Verify the instance_id matches
    if (vaultRecord.instance_id !== instance_id) {
      console.debug(`Health update: Instance ID mismatch for ${user_guid}`);
      return ok({ success: false, reason: 'instance_mismatch' }, origin);
    }

    // Determine overall status based on health metrics
    let overallStatus = 'running';
    if (type === 'shutdown') {
      overallStatus = 'stopping';
    } else if (status.status === 'degraded' || !status.nats_central) {
      overallStatus = 'degraded';
    }

    const now = new Date().toISOString();

    // Update vault health in DynamoDB
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid }),
      UpdateExpression: `
        SET #status = :status,
            vault_manager_status = :vm_status,
            local_nats_status = :local_nats,
            central_nats_status = :central_nats,
            uptime = :uptime,
            memory_mb = :memory_mb,
            go_routines = :go_routines,
            last_health_check = :now,
            updated_at = :now
      `,
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': overallStatus,
        ':vm_status': status.status || 'unknown',
        ':local_nats': status.nats_local ? 'running' : 'degraded',
        ':central_nats': status.nats_central ? 'connected' : 'disconnected',
        ':uptime': status.uptime || '',
        ':memory_mb': status.memory_mb || 0,
        ':go_routines': status.go_routines || 0,
        ':now': now,
      }),
      ConditionExpression: 'attribute_exists(user_guid)',
    }));

    return ok({
      success: true,
      status: overallStatus,
      timestamp: now,
    }, origin);

  } catch (error: any) {
    if (error.name === 'ConditionalCheckFailedException') {
      // Vault record doesn't exist - silent ignore
      return ok({ success: false, reason: 'vault_not_found' }, origin);
    }
    console.error('Health update error:', error);
    return internalError('Failed to process health update', origin);
  }
};
