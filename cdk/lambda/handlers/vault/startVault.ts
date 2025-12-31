import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, StartInstancesCommand } from '@aws-sdk/client-ec2';
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

interface StartResponse {
  status: 'starting' | 'running' | 'pending';
  instance_id: string;
  message: string;
}

/**
 * POST /vault/start
 *
 * Start a stopped vault EC2 instance.
 * The vault will resume with its preserved state.
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
    if (instance.status === 'running') {
      return ok({
        status: 'running',
        instance_id: instance.instance_id,
        message: 'Vault is already running.',
      } as StartResponse);
    }

    if (instance.status === 'starting' || instance.status === 'pending') {
      return ok({
        status: 'starting',
        instance_id: instance.instance_id,
        message: 'Vault is currently starting.',
      } as StartResponse);
    }

    if (instance.status === 'terminated') {
      return badRequest('Vault has been terminated. Provision a new instance.');
    }

    if (!['stopped', 'stopping'].includes(instance.status)) {
      return badRequest(`Cannot start vault in ${instance.status} state.`);
    }

    // Start the EC2 instance
    try {
      await ec2.send(new StartInstancesCommand({
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
            started_at = :now,
            updated_at = :now
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'starting',
        ':now': new Date().toISOString(),
      }),
    }));

    const response: StartResponse = {
      status: 'starting',
      instance_id: instance.instance_id,
      message: 'Vault is starting. Please wait for initialization to complete.',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Start vault error:', error);
    return internalError('Failed to start vault.');
  }
};
