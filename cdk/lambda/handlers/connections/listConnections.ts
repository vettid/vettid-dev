import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;

interface ConnectionResponse {
  connection_id: string;
  peer_guid: string;
  peer_display_name: string;
  peer_avatar_url: string | null;
  status: string;
  created_at: string;
  last_message_at: string | null;
  unread_count: number;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Parse query parameters
    const status = event.queryStringParameters?.status || "active";
    const limit = Math.min(parseInt(event.queryStringParameters?.limit || "50", 10), 100);
    const lastKey = event.queryStringParameters?.last_key;

    // Validate status parameter
    const validStatuses = ["active", "revoked", "all"];
    if (!validStatuses.includes(status)) {
      return badRequest(`status must be one of: ${validStatuses.join(", ")}`, origin);
    }

    // Build query
    let filterExpression: string | undefined;
    let expressionAttributeValues: Record<string, any> = {
      ":owner": claims.user_guid,
    };

    if (status !== "all") {
      filterExpression = "#status = :status";
      expressionAttributeValues[":status"] = status;
    }

    const queryParams: any = {
      TableName: TABLE_CONNECTIONS,
      KeyConditionExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall(expressionAttributeValues),
      Limit: limit,
    };

    if (filterExpression) {
      queryParams.FilterExpression = filterExpression;
      queryParams.ExpressionAttributeNames = { "#status": "status" };
    }

    if (lastKey) {
      try {
        queryParams.ExclusiveStartKey = JSON.parse(Buffer.from(lastKey, "base64").toString());
      } catch {
        return badRequest("Invalid last_key format", origin);
      }
    }

    const result = await ddb.send(new QueryCommand(queryParams));

    const connections: ConnectionResponse[] = (result.Items || []).map(item => {
      const conn = unmarshall(item);
      return {
        connection_id: conn.connection_id,
        peer_guid: conn.peer_guid,
        peer_display_name: conn.peer_display_name,
        peer_avatar_url: conn.peer_avatar_url || null,
        status: conn.status,
        created_at: conn.created_at,
        last_message_at: conn.last_message_at || null,
        unread_count: conn.unread_count || 0,
      };
    });

    // Sort by last_message_at (most recent first), then by created_at
    connections.sort((a, b) => {
      const aTime = a.last_message_at || a.created_at;
      const bTime = b.last_message_at || b.created_at;
      return bTime.localeCompare(aTime);
    });

    const response: any = {
      connections,
      count: connections.length,
    };

    if (result.LastEvaluatedKey) {
      response.last_key = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64");
    }

    return ok(response, origin);

  } catch (error) {
    console.error("Error listing connections:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to list connections", origin);
  }
};
