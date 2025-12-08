import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  requireUserClaims,
  parseJsonBody,
  ValidationError,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;

interface InstallHandlerRequest {
  handler_id: string;
  version?: string; // Optional, defaults to current version
}

interface InstallHandlerResponse {
  status: 'installed' | 'updated' | 'failed';
  handler_id: string;
  version: string;
  installed_at: string;
}

/**
 * POST /vault/handlers/install
 *
 * Install a handler from the registry to the user's vault.
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

    // Parse request body
    let body: InstallHandlerRequest;
    try {
      body = parseJsonBody<InstallHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.handler_id) {
      return badRequest('handler_id is required.');
    }

    // Get handler from registry
    const handlerResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    if (!handlerResult.Item) {
      return notFound('Handler not found.');
    }

    const handlerData = unmarshall(handlerResult.Item);

    // Check if handler is active
    if (handlerData.status !== 'active') {
      return notFound('Handler not found or is no longer available.');
    }

    // Determine version to install
    const version = body.version || handlerData.current_version;

    // Verify the version exists
    if (!handlerData.versions?.includes(version)) {
      return badRequest(`Version ${version} is not available for this handler.`);
    }

    // Check if already installed
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Key: marshall({
        user_guid: userGuid,
        handler_id: body.handler_id,
      }),
    }));

    const now = new Date().toISOString();
    const isUpdate = !!existingResult.Item;

    // Create or update installation record
    await ddb.send(new PutItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Item: marshall({
        user_guid: userGuid,
        handler_id: body.handler_id,
        installed_version: version,
        handler_name: handlerData.name,
        installed_at: isUpdate ? unmarshall(existingResult.Item!).installed_at : now,
        updated_at: now,
        status: 'installed',
      }),
    }));

    // Increment handler install count
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
      UpdateExpression: 'SET install_count = if_not_exists(install_count, :zero) + :one',
      ExpressionAttributeValues: marshall({
        ':zero': 0,
        ':one': 1,
      }),
    }));

    const response: InstallHandlerResponse = {
      status: isUpdate ? 'updated' : 'installed',
      handler_id: body.handler_id,
      version,
      installed_at: now,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Install handler error:', error);
    return internalError('Failed to install handler.');
  }
};
