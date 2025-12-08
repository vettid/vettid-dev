import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, BatchGetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireUserClaims } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;

interface InstalledHandler {
  id: string;
  name: string;
  description: string;
  installed_version: string;
  current_version: string;
  category: string;
  icon_url: string | null;
  installed_at: string;
  update_available: boolean;
}

interface ListInstalledHandlersResponse {
  handlers: InstalledHandler[];
  total: number;
}

/**
 * GET /vault/handlers
 *
 * List handlers installed on the user's vault.
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

    // Get user's installed handlers
    const installationsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      KeyConditionExpression: 'user_guid = :userGuid',
      ExpressionAttributeValues: marshall({ ':userGuid': userGuid }),
    }));

    const installations = installationsResult.Items?.map(item => unmarshall(item)) || [];

    if (installations.length === 0) {
      return ok({
        handlers: [],
        total: 0,
      } as ListInstalledHandlersResponse);
    }

    // Batch get handler details
    const handlerIds = installations.map(i => i.handler_id);
    const batchResult = await ddb.send(new BatchGetItemCommand({
      RequestItems: {
        [TABLE_HANDLERS]: {
          Keys: handlerIds.map(id => marshall({ handler_id: id })),
        },
      },
    }));

    const handlers = new Map<string, any>();
    batchResult.Responses?.[TABLE_HANDLERS]?.forEach(item => {
      const h = unmarshall(item);
      handlers.set(h.handler_id, h);
    });

    // Build response
    const installedHandlers: InstalledHandler[] = installations
      .map(installation => {
        const handler = handlers.get(installation.handler_id);
        if (!handler) return null;

        return {
          id: handler.handler_id,
          name: handler.name,
          description: handler.description,
          installed_version: installation.installed_version,
          current_version: handler.current_version,
          category: handler.category,
          icon_url: handler.icon_url || null,
          installed_at: installation.installed_at,
          update_available: installation.installed_version !== handler.current_version,
        };
      })
      .filter((h): h is InstalledHandler => h !== null);

    // Sort by name
    installedHandlers.sort((a, b) => a.name.localeCompare(b.name));

    const response: ListInstalledHandlersResponse = {
      handlers: installedHandlers,
      total: installedHandlers.length,
    };

    return ok(response);

  } catch (error: any) {
    console.error('List installed handlers error:', error);
    return internalError('Failed to list installed handlers.');
  }
};
