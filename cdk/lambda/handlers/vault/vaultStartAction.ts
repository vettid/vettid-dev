import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EC2Client, StartInstancesCommand } from '@aws-sdk/client-ec2';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_ACTION_TOKENS = process.env.TABLE_ACTION_TOKENS!;

const EXPECTED_ENDPOINT = '/api/v1/vault/start';

interface StartResponse {
  status: 'starting' | 'running' | 'pending';
  instance_id: string;
  message: string;
}

/**
 * Validate the action token from Authorization header
 */
function validateActionToken(authHeader: string | undefined): { valid: boolean; payload?: any; error?: string } {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing or invalid Authorization header' };
  }

  const token = authHeader.substring(7);
  const parts = token.split('.');

  if (parts.length !== 3) {
    return { valid: false, error: 'Invalid token format' };
  }

  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }

    // Check endpoint scope
    if (payload.endpoint !== EXPECTED_ENDPOINT) {
      return { valid: false, error: 'Token not valid for this endpoint' };
    }

    return { valid: true, payload };
  } catch {
    return { valid: false, error: 'Invalid token payload' };
  }
}

/**
 * POST /api/v1/vault/start
 *
 * Start a stopped vault EC2 instance using action token authentication.
 * For mobile apps without Cognito JWT.
 *
 * Requires: Authorization: Bearer {action_token}
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Validate action token
    const tokenResult = validateActionToken(event.headers.authorization || event.headers.Authorization);
    if (!tokenResult.valid) {
      return unauthorized(tokenResult.error || 'Invalid token');
    }

    const tokenPayload = tokenResult.payload;
    const userGuid = tokenPayload.sub;
    const tokenId = tokenPayload.jti;

    // Verify token is still active in database (single-use check)
    const actionTokenResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_ACTION_TOKENS,
      Key: marshall({ token_id: tokenId }),
    }));

    if (!actionTokenResult.Item) {
      return unauthorized('Token not found');
    }

    const actionToken = unmarshall(actionTokenResult.Item);

    if (actionToken.status !== 'ACTIVE') {
      return forbidden('Token has already been used');
    }

    // Mark token as used immediately (single-use)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_ACTION_TOKENS,
      Key: marshall({ token_id: tokenId }),
      UpdateExpression: 'SET #status = :status, used_at = :used_at',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': 'USED',
        ':used_at': new Date().toISOString(),
      }),
    }));

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

    // Audit log
    await putAudit({
      type: 'vault_started_via_action',
      user_guid: userGuid,
      token_id: tokenId,
      instance_id: instance.instance_id,
    }, requestId);

    const response: StartResponse = {
      status: 'starting',
      instance_id: instance.instance_id,
      message: 'Vault is starting. Please wait for initialization to complete.',
    };

    return ok(response);

  } catch (error: any) {
    console.error('Start vault action error:', error);
    return internalError('Failed to start vault.');
  }
};
