import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_HANDLER_SUBMISSIONS = process.env.TABLE_HANDLER_SUBMISSIONS!;

/**
 * List deployed handlers from the registry
 *
 * Returns handlers with status 'deployed'
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
    // Query for deployed handlers
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_HANDLER_SUBMISSIONS,
      FilterExpression: '#s = :deployed',
      ExpressionAttributeNames: { '#s': 'status', '#n': 'name' },
      ExpressionAttributeValues: {
        ':deployed': { S: 'deployed' }
      },
      ProjectionExpression: 'submission_id, handler_id, #n, version, description, wasm_hash, deployed_at, deployed_by'
    }));

    const handlers = (result.Items || []).map(item => {
      const h = unmarshall(item);
      return {
        submission_id: h.submission_id,
        handler_id: h.handler_id,
        name: h.name,
        version: h.version,
        description: h.description,
        wasm_hash: h.wasm_hash,
        deployed_at: h.deployed_at,
        deployed_by: h.deployed_by
      };
    });

    // Sort by deployed_at descending
    handlers.sort((a, b) => {
      const aTime = new Date(a.deployed_at || 0).getTime();
      const bTime = new Date(b.deployed_at || 0).getTime();
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
