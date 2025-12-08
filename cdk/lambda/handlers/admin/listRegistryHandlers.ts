import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;

interface AdminHandlerSummary {
  handler_id: string;
  name: string;
  description: string;
  current_version: string;
  versions: string[];
  category: string;
  publisher: string;
  status: string;
  install_count: number;
  created_at: string;
  created_by: string;
  signed_at?: string;
  signed_by?: string;
  revoked_at?: string;
  revoked_by?: string;
  revocation_reason?: string;
}

interface ListRegistryHandlersResponse {
  handlers: AdminHandlerSummary[];
  total: number;
}

/**
 * GET /admin/registry/handlers
 *
 * List all handlers in the registry (including pending and revoked).
 *
 * Requires admin JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate admin authentication
    const adminCheck = requireAdminGroup(event);
    if (adminCheck) return adminCheck;

    // Query parameters for filtering
    const status = event.queryStringParameters?.status;
    const category = event.queryStringParameters?.category;

    // Scan all handlers (admin view includes all statuses)
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_HANDLERS,
    }));

    let handlers = result.Items?.map(item => unmarshall(item)) || [];

    // Apply filters
    if (status) {
      handlers = handlers.filter(h => h.status === status);
    }
    if (category) {
      handlers = handlers.filter(h => h.category === category);
    }

    // Sort by created_at descending (newest first)
    handlers.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    // Map to response format
    const handlerSummaries: AdminHandlerSummary[] = handlers.map(h => ({
      handler_id: h.handler_id,
      name: h.name,
      description: h.description,
      current_version: h.current_version,
      versions: h.versions || [],
      category: h.category,
      publisher: h.publisher,
      status: h.status,
      install_count: h.install_count || 0,
      created_at: h.created_at,
      created_by: h.created_by,
      signed_at: h.signed_at,
      signed_by: h.signed_by,
      revoked_at: h.revoked_at,
      revoked_by: h.revoked_by,
      revocation_reason: h.revocation_reason,
    }));

    const response: ListRegistryHandlersResponse = {
      handlers: handlerSummaries,
      total: handlerSummaries.length,
    };

    return ok(response);

  } catch (error: any) {
    console.error('List registry handlers error:', error);
    return internalError('Failed to list handlers.');
  }
};
