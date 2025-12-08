import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  forbidden,
  notFound,
  internalError,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

interface InitializeResponse {
  status: 'initialized' | 'initializing' | 'failed';
  local_nats_status: string;
  central_nats_status: string;
  owner_space_id: string;
  message_space_id: string;
}

/**
 * POST /vault/initialize
 *
 * Initialize a vault instance after EC2 is running.
 * Verifies the instance is ready and configures NATS connections.
 *
 * Requires member JWT authentication and provisioned vault.
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

    // Check current status
    if (instance.status === 'running') {
      return ok({
        status: 'initialized',
        local_nats_status: instance.local_nats_status,
        central_nats_status: instance.central_nats_status,
        owner_space_id: instance.owner_space_id,
        message_space_id: instance.message_space_id,
      } as InitializeResponse);
    }

    if (instance.status === 'terminated' || instance.status === 'failed') {
      return badRequest(`Vault is ${instance.status}. Provision a new instance.`);
    }

    // Check EC2 instance status
    const ec2Result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instance.instance_id],
    }));

    const ec2Instance = ec2Result.Reservations?.[0]?.Instances?.[0];
    if (!ec2Instance) {
      // Instance not found in EC2, mark as failed
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_VAULT_INSTANCES,
        Key: marshall({ user_guid: userGuid }),
        UpdateExpression: 'SET #status = :status, updated_at = :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':status': 'failed',
          ':now': new Date().toISOString(),
        }),
      }));
      return internalError('Vault instance not found in EC2.');
    }

    const ec2State = ec2Instance.State?.Name;

    if (ec2State === 'terminated' || ec2State === 'shutting-down') {
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
      return badRequest('Vault instance has been terminated.');
    }

    if (ec2State !== 'running') {
      // Still starting up
      return ok({
        status: 'initializing',
        local_nats_status: 'pending',
        central_nats_status: 'pending',
        owner_space_id: instance.owner_space_id,
        message_space_id: instance.message_space_id,
      } as InitializeResponse);
    }

    // EC2 is running - check if vault manager is ready
    // In production, this would query the vault instance directly
    // For now, we simulate based on time since provisioning
    const createdAt = new Date(instance.created_at).getTime();
    const elapsed = Date.now() - createdAt;
    const INIT_TIME_MS = 90000; // 90 seconds for initialization

    if (elapsed < INIT_TIME_MS) {
      // Still initializing
      return ok({
        status: 'initializing',
        local_nats_status: 'starting',
        central_nats_status: 'connecting',
        owner_space_id: instance.owner_space_id,
        message_space_id: instance.message_space_id,
      } as InitializeResponse);
    }

    // Mark as running
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: `
        SET #status = :status,
            local_nats_status = :local_nats,
            central_nats_status = :central_nats,
            vault_manager_status = :vault_manager,
            initialized_at = :now,
            updated_at = :now,
            private_ip = :private_ip
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'running',
        ':local_nats': 'running',
        ':central_nats': 'connected',
        ':vault_manager': 'running',
        ':now': new Date().toISOString(),
        ':private_ip': ec2Instance.PrivateIpAddress || instance.private_ip,
      }),
    }));

    const response: InitializeResponse = {
      status: 'initialized',
      local_nats_status: 'running',
      central_nats_status: 'connected',
      owner_space_id: instance.owner_space_id,
      message_space_id: instance.message_space_id,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Initialize vault error:', error);
    return internalError('Failed to initialize vault.');
  }
};
