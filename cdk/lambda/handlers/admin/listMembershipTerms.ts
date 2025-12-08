import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, ok, requireAdminGroup } from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const DEFAULT_PAGE_SIZE = 20;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Parse pagination parameters
    const limit = Math.min(
      parseInt(event.queryStringParameters?.limit || String(DEFAULT_PAGE_SIZE), 10),
      100 // Max page size
    );
    const lastEvaluatedKey = event.queryStringParameters?.cursor
      ? JSON.parse(Buffer.from(event.queryStringParameters.cursor, 'base64').toString())
      : undefined;

    // Scan terms with pagination
    const res = await ddb.send(new ScanCommand({
      TableName: TABLE_MEMBERSHIP_TERMS,
      Limit: limit + 50, // Fetch extra to ensure we have enough after sorting
      ExclusiveStartKey: lastEvaluatedKey
    }));

    const items = (res.Items || []).map((i) => unmarshall(i as any));

    // Sort by created_at descending (newest first)
    items.sort((a: any, b: any) => {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

    // Separate current from previous
    const current = items.find((item: any) => item.is_current === 'true');
    const previous = items.filter((item: any) => item.is_current !== 'true');

    // Apply pagination to previous versions only (current always shown)
    const paginatedPrevious = previous.slice(0, limit);

    // Map items without presigned URLs (lazy loading)
    const mappedCurrent = current ? {
      version_id: current.version_id,
      created_at: current.created_at,
      created_by: current.created_by,
      is_current: true
    } : null;

    const mappedPrevious = paginatedPrevious.map((item: any) => ({
      version_id: item.version_id,
      created_at: item.created_at,
      created_by: item.created_by,
      is_current: false
    }));

    // Calculate next cursor
    const hasMore = previous.length > limit || !!res.LastEvaluatedKey;
    const nextCursor = hasMore && res.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(res.LastEvaluatedKey)).toString('base64')
      : null;

    return ok({
      current: mappedCurrent,
      previous: mappedPrevious,
      pagination: {
        has_more: hasMore,
        next_cursor: nextCursor,
        total_previous: previous.length
      }
    });
  } catch (error) {
    console.error('Failed to list membership terms:', error);
    return ok({
      current: null,
      previous: [],
      pagination: { has_more: false, next_cursor: null, total_previous: 0 }
    });
  }
};
