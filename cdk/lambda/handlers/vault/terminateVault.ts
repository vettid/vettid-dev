import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, TerminateInstancesCommand } from '@aws-sdk/client-ec2';
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

interface TerminateResponse {
  status: 'terminating' | 'terminated';
  instance_id: string;
  message: string;
}

/**
 * POST /vault/terminate
 *
 * Terminate the vault EC2 instance and cleanup resources.
 * WARNING: This is a destructive operation. All vault data will be lost.
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
    if (instance.status === 'terminated') {
      return ok({
        status: 'terminated',
        instance_id: instance.instance_id,
        message: 'Vault is already terminated.',
      } as TerminateResponse);
    }

    if (instance.status === 'terminating') {
      return ok({
        status: 'terminating',
        instance_id: instance.instance_id,
        message: 'Vault termination in progress.',
      } as TerminateResponse);
    }

    // Terminate the EC2 instance
    try {
      await ec2.send(new TerminateInstancesCommand({
        InstanceIds: [instance.instance_id],
      }));
    } catch (ec2Error: any) {
      // If instance not found, it's already gone
      if (ec2Error.name === 'InvalidInstanceID.NotFound') {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_VAULT_INSTANCES,
          Key: marshall({ user_guid: userGuid }),
          UpdateExpression: `
            SET #status = :status,
                local_nats_status = :stopped,
                central_nats_status = :disconnected,
                vault_manager_status = :stopped,
                terminated_at = :now,
                updated_at = :now
          `,
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({
            ':status': 'terminated',
            ':stopped': 'stopped',
            ':disconnected': 'disconnected',
            ':now': new Date().toISOString(),
          }),
        }));

        return ok({
          status: 'terminated',
          instance_id: instance.instance_id,
          message: 'Vault instance already terminated.',
        } as TerminateResponse);
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
            terminated_at = :now,
            updated_at = :now
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'terminating',
        ':stopped': 'stopped',
        ':disconnected': 'disconnected',
        ':now': new Date().toISOString(),
      }),
    }));

    const response: TerminateResponse = {
      status: 'terminating',
      instance_id: instance.instance_id,
      message: 'Vault is terminating. All data will be deleted.',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Terminate vault error:', error);
    return internalError('Failed to terminate vault.');
  }
};
