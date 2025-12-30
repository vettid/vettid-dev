import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, QueryCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
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

    // Get user's profile
    const profileResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROFILES,
      Key: marshall({ user_guid: claims.user_guid }),
    }));

    if (!profileResult.Item) {
      return notFound("Profile not found. Please create a profile first.", origin);
    }

    const profile = unmarshall(profileResult.Item);

    // Get all active connections where this user is the peer
    // (i.e., connections from others to this user)
    const connectionsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      IndexName: "peer-guid-index",
      KeyConditionExpression: "peer_guid = :peerGuid",
      FilterExpression: "#status = :active",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":peerGuid": claims.user_guid,
        ":active": "active",
      }),
    }));

    const connections = connectionsResult.Items?.map(item => unmarshall(item)) || [];
    const now = nowIso();

    // Update profile info in each connection
    let updatedCount = 0;
    const errors: string[] = [];

    for (const conn of connections) {
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_CONNECTIONS,
          Key: marshall({
            owner_guid: conn.owner_guid,
            peer_guid: claims.user_guid,
          }),
          UpdateExpression: "SET peer_display_name = :name, peer_avatar_url = :avatar, profile_updated_at = :now",
          ExpressionAttributeValues: marshall({
            ":name": profile.display_name,
            ":avatar": profile.avatar_url || null,
            ":now": now,
          }),
        }));
        updatedCount++;
      } catch (error) {
        console.error(`Failed to update connection for owner ${conn.owner_guid}:`, error);
        errors.push(conn.owner_guid);
      }
    }

    // NOTE: Profile updates are broadcast vault-to-vault via NATS MessageSpace.
    // The mobile app triggers profile.broadcast through its vault, which notifies all connected peer vaults.

    return ok({
      published: true,
      connections_updated: updatedCount,
      total_connections: connections.length,
      failed_connections: errors.length,
      published_at: now,
    }, origin);

  } catch (error) {
    console.error("Error publishing profile:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to publish profile", origin);
  }
};
