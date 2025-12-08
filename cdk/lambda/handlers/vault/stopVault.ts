import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, StopInstancesCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;

interface StopResponse {
  status: 'stopping' | 'stopped';
  instance_id: string;
  message: string;
}

/**
 * POST /vault/stop
 *
 * Stop the vault EC2 instance, preserving its state.
 * The vault can be restarted later without losing data.
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
      return notFound('No vault instance found.');
    }

    const instance = unmarshall(instanceResult.Item);

    // Check current status
    if (instance.status === 'stopped') {
      return ok({
        status: 'stopped',
        instance_id: instance.instance_id,
        message: 'Vault is already stopped.',
      } as StopResponse);
    }

    if (instance.status === 'stopping') {
      return ok({
        status: 'stopping',
        instance_id: instance.instance_id,
        message: 'Vault is currently stopping.',
      } as StopResponse);
    }

    if (instance.status === 'terminated') {
      return badRequest('Vault has been terminated. Provision a new instance.');
    }

    if (!['running', 'provisioning', 'initializing'].includes(instance.status)) {
      return badRequest(`Cannot stop vault in ${instance.status} state.`);
    }

    // Stop the EC2 instance
    try {
      await ec2.send(new StopInstancesCommand({
        InstanceIds: [instance.instance_id],
      }));
    } catch (ec2Error: any) {
      // If instance not found, it may have been terminated externally
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
        return badRequest('Vault instance not found. It may have been terminated.');
      }
      throw ec2Error;
    }

    // Update vault status
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_INSTANCES,
      Key: marshall({ user_guid: userGuid }),
      UpdateExpression: `
        SET #status = :status,
            local_nats_status = :stopped,
            central_nats_status = :disconnected,
            vault_manager_status = :stopped,
            stopped_at = :now,
            updated_at = :now
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'stopping',
        ':stopped': 'stopped',
        ':disconnected': 'disconnected',
        ':now': new Date().toISOString(),
      }),
    }));

    const response: StopResponse = {
      status: 'stopping',
      instance_id: instance.instance_id,
      message: 'Vault is stopping. State will be preserved.',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Stop vault error:', error);
    return internalError('Failed to stop vault.');
  }
};
