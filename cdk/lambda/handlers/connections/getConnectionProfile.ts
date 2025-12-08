import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  requireUserClaims,
  ValidationError,
  validatePathParam,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;

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

    // Verify connection exists and user owns it
    const connectionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      IndexName: "connection-id-index",
      KeyConditionExpression: "connection_id = :connId",
      FilterExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall({
        ":connId": connectionId,
        ":owner": claims.user_guid,
      }),
    }));

    if (!connectionResult.Items || connectionResult.Items.length === 0) {
      return notFound("Connection not found", origin);
    }

    const connection = unmarshall(connectionResult.Items[0]);

    // Check connection status
    if (connection.status !== "active") {
      return forbidden("Cannot view profile for revoked connection", origin);
    }

    // Get peer's profile
    const profileResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROFILES,
      Key: marshall({ user_guid: connection.peer_guid }),
    }));

    if (!profileResult.Item) {
      // Return minimal profile from connection data if no profile exists
      return ok({
        guid: connection.peer_guid,
        display_name: connection.peer_display_name,
        avatar_url: connection.peer_avatar_url || null,
        bio: null,
        location: null,
        last_updated: connection.created_at,
      }, origin);
    }

    const profile = unmarshall(profileResult.Item);

    return ok({
      guid: profile.user_guid,
      display_name: profile.display_name,
      avatar_url: profile.avatar_url || null,
      bio: profile.bio || null,
      location: profile.location || null,
      last_updated: profile.updated_at || profile.created_at,
    }, origin);

  } catch (error) {
    console.error("Error getting connection profile:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get connection profile", origin);
  }
};
