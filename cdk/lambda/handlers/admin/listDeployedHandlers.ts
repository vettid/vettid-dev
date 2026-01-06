import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

// Use the existing handlers registry table (not submissions)
const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;

/**
 * List deployed handlers from the registry
 *
 * Returns handlers with status 'signed' (production-ready handlers)
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  try {
    // Query the handlers registry for signed (deployed) handlers
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_HANDLERS,
      FilterExpression: '#s = :signed',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':signed': { S: 'signed' }
      }
    }));

    const handlers = (result.Items || []).map(item => {
      const h = unmarshall(item);
      return {
        handler_id: h.handler_id,
        name: h.name,
        version: h.current_version,
        description: h.description,
        category: h.category,
        publisher: h.publisher,
        status: h.status,
        install_count: h.install_count || 0,
        signed_at: h.signed_at,
        signed_by: h.signed_by,
        created_at: h.created_at
      };
    });

    // Sort by signed_at descending (most recently deployed first)
    handlers.sort((a, b) => {
      const aTime = new Date(a.signed_at || a.created_at || 0).getTime();
      const bTime = new Date(b.signed_at || b.created_at || 0).getTime();
      return bTime - aTime;
    });

    return ok({
      handlers,
      count: handlers.length
    });
  } catch (error) {
    console.error('Error listing deployed handlers:', error);

    await putAudit({
      type: 'admin_list_deployed_handlers_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to list deployed handlers');
  }
};
