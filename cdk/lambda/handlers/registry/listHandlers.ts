import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, badRequest, internalError, requireUserClaims } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;

interface HandlerSummary {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  icon_url: string | null;
  publisher: string;
  installed: boolean;
  installed_version: string | null;
}

interface ListHandlersResponse {
  handlers: HandlerSummary[];
  total: number;
  page: number;
  has_more: boolean;
}

/**
 * GET /registry/handlers
 *
 * List available handlers from the registry.
 * Supports filtering by category and pagination.
 *
 * Query parameters:
 * - category: Filter by handler category
 * - page: Page number (default 1)
 * - limit: Items per page (default 20, max 100)
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

    // Parse query parameters
    const category = event.queryStringParameters?.category;
    const page = Math.max(1, parseInt(event.queryStringParameters?.page || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(event.queryStringParameters?.limit || '20', 10)));

    // Get handlers from registry
    let handlers: any[] = [];
    let lastEvaluatedKey: any;
    let totalScanned = 0;
    const startIndex = (page - 1) * limit;

    if (category) {
      // Query by category using GSI
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_HANDLERS,
        IndexName: 'category-index',
        KeyConditionExpression: 'category = :category',
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':category': category,
          ':active': 'active',
        }),
      }));
      handlers = result.Items?.map(item => unmarshall(item)) || [];
    } else {
      // Scan all active handlers
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_HANDLERS,
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({ ':active': 'active' }),
      }));
      handlers = result.Items?.map(item => unmarshall(item)) || [];
    }

    // Get user's installed handlers
    const installationsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      KeyConditionExpression: 'user_guid = :userGuid',
      ExpressionAttributeValues: marshall({ ':userGuid': userGuid }),
    }));
    const installations = new Map<string, string>();
    installationsResult.Items?.forEach(item => {
      const installation = unmarshall(item);
      installations.set(installation.handler_id, installation.installed_version);
    });

    // Sort handlers by name
    handlers.sort((a, b) => a.name.localeCompare(b.name));

    // Paginate
    const total = handlers.length;
    const paginatedHandlers = handlers.slice(startIndex, startIndex + limit);

    // Map to response format
    const handlerSummaries: HandlerSummary[] = paginatedHandlers.map(h => ({
      id: h.handler_id,
      name: h.name,
      description: h.description,
      version: h.current_version,
      category: h.category,
      icon_url: h.icon_url || null,
      publisher: h.publisher,
      installed: installations.has(h.handler_id),
      installed_version: installations.get(h.handler_id) || null,
    }));

    const response: ListHandlersResponse = {
      handlers: handlerSummaries,
      total,
      page,
      has_more: startIndex + limit < total,
    };

    return ok(response);

  } catch (error: any) {
    console.error('List handlers error:', error);
    return internalError('Failed to list handlers.');
  }
};
