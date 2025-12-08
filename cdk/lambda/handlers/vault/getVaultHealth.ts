import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, DescribeInstancesCommand, DescribeInstanceStatusCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  notFound,
  internalError,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

interface NatsHealth {
  status: string;
  connections: number;
}

interface CentralNatsHealth {
  status: string;
  latency_ms: number;
}

interface VaultManagerHealth {
  status: string;
  memory_mb: number;
  cpu_percent: number;
  handlers_loaded: number;
}

interface VaultHealthResponse {
  status: 'healthy' | 'unhealthy' | 'degraded' | 'stopped' | 'terminated' | 'provisioning';
  uptime_seconds: number;
  local_nats: NatsHealth;
  central_nats: CentralNatsHealth;
  vault_manager: VaultManagerHealth;
  last_event_at: string | null;
  instance_id: string;
  private_ip: string | null;
}

/**
 * GET /vault/health
 *
 * Get the health status of the vault instance.
 * Returns detailed health information about vault components.
 *
 * Requires member JWT authentication.
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

    // Get vault instance
    const instanceResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (!instanceResult.Item) {
      return notFound('No vault instance found. Use POST /vault/provision first.');
    }

    const instance = unmarshall(instanceResult.Item);

    // Handle non-running states
    if (instance.status === 'terminated') {
      return ok({
        status: 'terminated',
        uptime_seconds: 0,
        local_nats: { status: 'stopped', connections: 0 },
        central_nats: { status: 'disconnected', latency_ms: 0 },
        vault_manager: { status: 'stopped', memory_mb: 0, cpu_percent: 0, handlers_loaded: 0 },
        last_event_at: instance.last_event_at || null,
        instance_id: instance.instance_id,
        private_ip: null,
      } as VaultHealthResponse);
    }

    if (instance.status === 'stopped' || instance.status === 'stopping') {
      return ok({
        status: 'stopped',
        uptime_seconds: 0,
        local_nats: { status: 'stopped', connections: 0 },
        central_nats: { status: 'disconnected', latency_ms: 0 },
        vault_manager: { status: 'stopped', memory_mb: 0, cpu_percent: 0, handlers_loaded: 0 },
        last_event_at: instance.last_event_at || null,
        instance_id: instance.instance_id,
        private_ip: instance.private_ip || null,
      } as VaultHealthResponse);
    }

    if (instance.status === 'provisioning' || instance.status === 'initializing') {
      return ok({
        status: 'provisioning',
        uptime_seconds: 0,
        local_nats: { status: 'starting', connections: 0 },
        central_nats: { status: 'connecting', latency_ms: 0 },
        vault_manager: { status: 'starting', memory_mb: 0, cpu_percent: 0, handlers_loaded: 0 },
        last_event_at: null,
        instance_id: instance.instance_id,
        private_ip: instance.private_ip || null,
      } as VaultHealthResponse);
    }

    // For running instances, check EC2 status
    let ec2Status = 'running';
    let systemStatus = 'ok';
    let instanceStatus = 'ok';

    try {
      const ec2Result = await ec2.send(new DescribeInstancesCommand({
        InstanceIds: [instance.instance_id],
      }));

      const ec2Instance = ec2Result.Reservations?.[0]?.Instances?.[0];
      if (ec2Instance) {
        ec2Status = ec2Instance.State?.Name || 'unknown';

        // Update private IP if changed
        if (ec2Instance.PrivateIpAddress && ec2Instance.PrivateIpAddress !== instance.private_ip) {
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_VAULT_INSTANCES,
            Key: marshall({ user_guid: userGuid }),
            UpdateExpression: 'SET private_ip = :ip, updated_at = :now',
            ExpressionAttributeValues: marshall({
              ':ip': ec2Instance.PrivateIpAddress,
              ':now': new Date().toISOString(),
            }),
          }));
          instance.private_ip = ec2Instance.PrivateIpAddress;
        }
      }

      // Get instance status checks
      const statusResult = await ec2.send(new DescribeInstanceStatusCommand({
        InstanceIds: [instance.instance_id],
      }));

      const status = statusResult.InstanceStatuses?.[0];
      if (status) {
        systemStatus = status.SystemStatus?.Status || 'unknown';
        instanceStatus = status.InstanceStatus?.Status || 'unknown';
      }
    } catch (ec2Error: any) {
      console.error('EC2 status check error:', ec2Error);
      // If instance not found, mark as terminated
      if (ec2Error.name === 'InvalidInstanceID.NotFound') {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_VAULT_INSTANCES,
          Key: marshall({ user_guid: userGuid }),
          UpdateExpression: 'SET #status = :status, updated_at = :now',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({
            ':status': 'terminated',
            ':now': new Date().toISOString(),
          }),
        }));

        return ok({
          status: 'terminated',
          uptime_seconds: 0,
          local_nats: { status: 'stopped', connections: 0 },
          central_nats: { status: 'disconnected', latency_ms: 0 },
          vault_manager: { status: 'stopped', memory_mb: 0, cpu_percent: 0, handlers_loaded: 0 },
          last_event_at: instance.last_event_at || null,
          instance_id: instance.instance_id,
          private_ip: null,
        } as VaultHealthResponse);
      }
    }

    // Calculate uptime
    const initializedAt = instance.initialized_at ? new Date(instance.initialized_at).getTime() : Date.now();
    const uptimeSeconds = Math.floor((Date.now() - initializedAt) / 1000);

    // Determine overall health status
    let overallStatus: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';

    if (ec2Status !== 'running') {
      overallStatus = 'unhealthy';
    } else if (systemStatus !== 'ok' || instanceStatus !== 'ok') {
      overallStatus = 'degraded';
    } else if (instance.local_nats_status !== 'running' || instance.central_nats_status !== 'connected') {
      overallStatus = 'degraded';
    }

    // In production, this would query the vault instance directly for real metrics
    // For now, we simulate based on stored state
    const response: VaultHealthResponse = {
      status: overallStatus,
      uptime_seconds: uptimeSeconds,
      local_nats: {
        status: instance.local_nats_status || 'unknown',
        connections: instance.local_nats_status === 'running' ? 2 : 0, // App + Vault Manager
      },
      central_nats: {
        status: instance.central_nats_status || 'unknown',
        latency_ms: instance.central_nats_status === 'connected' ? 15 : 0,
      },
      vault_manager: {
        status: instance.vault_manager_status || 'unknown',
        memory_mb: instance.vault_manager_status === 'running' ? 128 : 0,
        cpu_percent: instance.vault_manager_status === 'running' ? 5.2 : 0,
        handlers_loaded: instance.vault_manager_status === 'running' ? 3 : 0,
      },
      last_event_at: instance.last_event_at || null,
      instance_id: instance.instance_id,
      private_ip: instance.private_ip || null,
    };

    // Update last health check timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: 'SET last_health_check = :now',
      ExpressionAttributeValues: marshall({
        ':now': new Date().toISOString(),
      }),
    }));

    return ok(response);

  } catch (error: any) {
    console.error('Get vault health error:', error);
    return internalError('Failed to get vault health.');
  }
};
