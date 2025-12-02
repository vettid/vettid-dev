import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ddb, TABLES, ok, requireAdminGroup } from "../../common/util";
import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

// SECURITY: Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const status = event.queryStringParameters?.status;
  // SECURITY: Enforce reasonable limits to prevent abuse
  const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
  const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);
  const cursor = event.queryStringParameters?.cursor;

  // Decode pagination cursor if provided
  let exclusiveStartKey: Record<string, any> | undefined;
  if (cursor) {
    try {
      exclusiveStartKey = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
    } catch {
      // Invalid cursor, ignore
    }
  }

  const params: any = {
    TableName: TABLES.invites,
    Limit: limit,
    ExclusiveStartKey: exclusiveStartKey
  };

  // If status filter is provided, add FilterExpression
  if (status) {
    params.FilterExpression = "#s = :status";
    params.ExpressionAttributeNames = { "#s": "status" };
    params.ExpressionAttributeValues = { ":status": { S: status } };
  }

  const res = await ddb.send(new ScanCommand(params));
  const items = (res.Items || []).map((i) => unmarshall(i as any));

  // Sort by created_at descending
  items.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));

  // Build response with pagination
  const response: any = {
    items,
    count: items.length,
    limit
  };

  // Include next cursor if there are more results
  if (res.LastEvaluatedKey) {
    response.nextCursor = Buffer.from(JSON.stringify(res.LastEvaluatedKey)).toString('base64');
  }

  return ok(response);
};
