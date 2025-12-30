import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
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
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

/**
 * Request payload from vault-manager when it's ready
 */
interface VaultReadyRequest {
  user_guid: string;
  instance_id: string;
  private_ip?: string;
  status: {
    vault_manager: 'running' | 'starting';
    local_nats: 'running' | 'starting' | 'degraded';
    central_nats: 'connected' | 'connecting';
  };
}

/**
 * POST /vault/internal/ready
 *
 * Called by vault-manager when it has successfully started and connected to NATS.
 * This endpoint updates the vault instance status from "provisioning" to "running".
 *
 * This is an internal endpoint - no user authentication required, but we validate:
 * 1. The instance_id matches what we have in DynamoDB
 * 2. The EC2 instance actually exists and is running
 * 3. The instance has the correct VettID:UserGuid tag
 *
 * Request body:
 * - user_guid: string - The user GUID this vault belongs to
 * - instance_id: string - The EC2 instance ID
 * - private_ip: string (optional) - The private IP address
 * - status: object - Initial health status
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Parse request body
    const body = parseJsonBody<VaultReadyRequest>(event);
    if (!body) {
      return badRequest('Request body is required', origin);
    }

    const { user_guid, instance_id, private_ip, status } = body;

    // Validate required fields
    if (!user_guid) {
      return badRequest('user_guid is required', origin);
    }
    if (!instance_id) {
      return badRequest('instance_id is required', origin);
    }
    if (!status) {
      return badRequest('status is required', origin);
    }

    console.log(`Vault ready signal: user=${user_guid}, instance=${instance_id}`);

    // Get existing vault instance from DynamoDB
    const instanceResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid }),
    }));

    if (!instanceResult.Item) {
      console.warn(`Vault ready: No vault record found for user ${user_guid}`);
      return notFound('No vault instance found for this user', origin);
    }

    const vaultRecord = unmarshall(instanceResult.Item);

    // Verify the instance_id matches
    if (vaultRecord.instance_id !== instance_id) {
      console.warn(`Vault ready: Instance ID mismatch. Expected ${vaultRecord.instance_id}, got ${instance_id}`);
      return forbidden('Instance ID does not match vault record', origin);
    }

    // Verify the EC2 instance exists and has correct tags
    let ec2PrivateIp: string | null = null;
    try {
      const ec2Result = await ec2.send(new DescribeInstancesCommand({
        InstanceIds: [instance_id],
      }));

      const ec2Instance = ec2Result.Reservations?.[0]?.Instances?.[0];
      if (!ec2Instance) {
        console.warn(`Vault ready: EC2 instance ${instance_id} not found`);
        return badRequest('EC2 instance not found', origin);
      }

      // Verify the instance is running
      if (ec2Instance.State?.Name !== 'running') {
        console.warn(`Vault ready: EC2 instance ${instance_id} is not running (state: ${ec2Instance.State?.Name})`);
        return badRequest(`EC2 instance is not running (state: ${ec2Instance.State?.Name})`, origin);
      }

      // Verify the UserGuid tag matches
      const userGuidTag = ec2Instance.Tags?.find(t => t.Key === 'VettID:UserGuid');
      if (!userGuidTag || userGuidTag.Value !== user_guid) {
        console.warn(`Vault ready: UserGuid tag mismatch for instance ${instance_id}`);
        return forbidden('Instance UserGuid tag does not match', origin);
      }

      ec2PrivateIp = ec2Instance.PrivateIpAddress || null;
    } catch (ec2Error: any) {
      if (ec2Error.name === 'InvalidInstanceID.NotFound') {
        return badRequest('EC2 instance not found', origin);
      }
      console.error('EC2 verification error:', ec2Error);
      return internalError('Failed to verify EC2 instance', origin);
    }

    // All validations passed - update the vault record
    const now = new Date().toISOString();

    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid }),
      UpdateExpression: `
        SET #status = :status,
            vault_manager_status = :vm_status,
            local_nats_status = :local_nats,
            central_nats_status = :central_nats,
            initialized_at = :now,
            updated_at = :now,
            private_ip = :private_ip,
            last_health_check = :now
      `,
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'running',
        ':vm_status': status.vault_manager || 'running',
        ':local_nats': status.local_nats || 'running',
        ':central_nats': status.central_nats || 'connected',
        ':now': now,
        ':private_ip': private_ip || ec2PrivateIp || vaultRecord.private_ip,
      }),
      ConditionExpression: 'attribute_exists(user_guid)',
    }));

    console.log(`Vault ready: Successfully marked vault as running for user ${user_guid}`);

    return ok({
      success: true,
      user_guid,
      instance_id,
      status: 'running',
      initialized_at: now,
    }, origin);

  } catch (error: any) {
    console.error('Vault ready error:', error);
    return internalError('Failed to process vault ready signal', origin);
  }
};
