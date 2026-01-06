import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_BROADCASTS = process.env.TABLE_VAULT_BROADCASTS!;

/**
 * List vault broadcast history
 *
 * Query params:
 * - type: Filter by broadcast type (system_announcement, security_alert, admin_message)
 * - limit: Maximum number of results (default 50, max 100)
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
    const typeFilter = event.queryStringParameters?.type;
    const limitParam = parseInt(event.queryStringParameters?.limit || '50', 10);
    const limit = Math.min(Math.max(1, limitParam), 100);

    let broadcasts: Record<string, unknown>[] = [];

    if (typeFilter) {
      // Use type-sent-index GSI to filter by type
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_VAULT_BROADCASTS,
        IndexName: 'type-sent-index',
        KeyConditionExpression: '#t = :type',
        ExpressionAttributeNames: { '#t': 'type' },
        ExpressionAttributeValues: marshall({ ':type': typeFilter }),
        ScanIndexForward: false, // Most recent first
        Limit: limit,
      }));

      broadcasts = (result.Items || []).map(item => unmarshall(item));
    } else {
      // Scan all broadcasts and sort by sent_at
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_VAULT_BROADCASTS,
        Limit: limit * 2, // Fetch more to allow for sorting
      }));

      broadcasts = (result.Items || []).map(item => unmarshall(item));

      // Sort by sent_at descending
      broadcasts.sort((a, b) => {
        const aTime = new Date(a.sent_at as string || 0).getTime();
        const bTime = new Date(b.sent_at as string || 0).getTime();
        return bTime - aTime;
      });

      // Apply limit after sorting
      broadcasts = broadcasts.slice(0, limit);
    }

    // Format response
    const formattedBroadcasts = broadcasts.map(b => ({
      broadcast_id: b.broadcast_id,
      type: b.type,
      priority: b.priority,
      title: b.title,
      message: b.message,
      nats_subject: b.nats_subject,
      sent_at: b.sent_at,
      sent_by: b.sent_by,
      delivery_status: b.delivery_status,
      delivery_count: b.delivery_count,
    }));

    return ok({
      broadcasts: formattedBroadcasts,
      count: formattedBroadcasts.length,
      type_filter: typeFilter || null,
    });
  } catch (error) {
    console.error('Error listing vault broadcasts:', error);

    await putAudit({
      type: 'admin_list_vault_broadcasts_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to list vault broadcasts');
  }
};
