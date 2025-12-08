import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  ValidationError,
  validatePathParam,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get connection ID from path
    const connectionId = validatePathParam(event.pathParameters?.connectionId, "Connection ID");

    // Query for connection by ID where user is owner
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      IndexName: "connection-id-index",
      KeyConditionExpression: "connection_id = :connId",
      FilterExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall({
        ":connId": connectionId,
        ":owner": claims.user_guid,
      }),
    }));

    if (!result.Items || result.Items.length === 0) {
      return notFound("Connection not found", origin);
    }

    const connection = unmarshall(result.Items[0]);

    return ok({
      connection_id: connection.connection_id,
      peer_guid: connection.peer_guid,
      peer_display_name: connection.peer_display_name,
      peer_avatar_url: connection.peer_avatar_url || null,
      status: connection.status,
      created_at: connection.created_at,
      last_message_at: connection.last_message_at || null,
      unread_count: connection.unread_count || 0,
      revoked_at: connection.revoked_at || null,
      revoked_by: connection.revoked_by || null,
    }, origin);

  } catch (error) {
    console.error("Error getting connection:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get connection", origin);
  }
};
