import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  parseJsonBody,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;

interface UninstallHandlerRequest {
  handler_id: string;
}

interface UninstallHandlerResponse {
  status: 'uninstalled';
  handler_id: string;
  uninstalled_at: string;
}

/**
 * POST /vault/handlers/uninstall
 *
 * Uninstall a handler from the user's vault.
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
    let body: UninstallHandlerRequest;
    try {
      body = parseJsonBody<UninstallHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.handler_id) {
      return badRequest('handler_id is required.');
    }

    // Check if handler is installed
    const installationResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Key: marshall({
        user_guid: userGuid,
        handler_id: body.handler_id,
      }),
    }));

    if (!installationResult.Item) {
      return notFound('Handler is not installed.');
    }

    // Delete installation record
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Key: marshall({
        user_guid: userGuid,
        handler_id: body.handler_id,
      }),
    }));

    // Decrement handler install count (don't go below 0)
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_HANDLERS,
        Key: marshall({ handler_id: body.handler_id }),
        UpdateExpression: 'SET install_count = install_count - :one',
        ConditionExpression: 'install_count > :zero',
        ExpressionAttributeValues: marshall({
          ':zero': 0,
          ':one': 1,
        }),
      }));
    } catch (e: any) {
      // Ignore if handler doesn't exist or count is already 0
      if (e.name !== 'ConditionalCheckFailedException') {
        console.warn('Failed to decrement install count:', e);
      }
    }

    const response: UninstallHandlerResponse = {
      status: 'uninstalled',
      handler_id: body.handler_id,
      uninstalled_at: new Date().toISOString(),
    };

    return ok(response);

  } catch (error: any) {
    console.error('Uninstall handler error:', error);
    return internalError('Failed to uninstall handler.');
  }
};
