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

interface UnreadCountResponse {
  total_unread: number;
  by_connection: Record<string, number>;
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

    // Get all active connections for user
    const connectionsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      KeyConditionExpression: "owner_guid = :owner",
      FilterExpression: "#status = :active",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":owner": claims.user_guid,
        ":active": "active",
      }),
      ProjectionExpression: "connection_id, unread_count",
    }));

    const connections = connectionsResult.Items?.map(item => unmarshall(item)) || [];

    // Build response
    let totalUnread = 0;
    const byConnection: Record<string, number> = {};

    for (const conn of connections) {
      const unread = conn.unread_count || 0;
      if (unread > 0) {
        byConnection[conn.connection_id] = unread;
        totalUnread += unread;
      }
    }

    const response: UnreadCountResponse = {
      total_unread: totalUnread,
      by_connection: byConnection,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error getting unread count:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get unread count", origin);
  }
};
