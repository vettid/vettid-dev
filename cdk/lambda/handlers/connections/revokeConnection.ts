import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
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

    // Find the connection owned by this user
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

    // Verify ownership
    if (connection.owner_guid !== claims.user_guid) {
      return forbidden("You can only revoke your own connections", origin);
    }

    // Check if already revoked
    if (connection.status === "revoked") {
      return badRequest("Connection has already been revoked", origin);
    }

    const now = nowIso();

    // Update both sides of the connection to revoked status
    // First, update the owner's connection record
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: claims.user_guid,
        peer_guid: connection.peer_guid,
      }),
      UpdateExpression: "SET #status = :revoked, revoked_at = :now, revoked_by = :revoker",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":revoked": "revoked",
        ":now": now,
        ":revoker": claims.user_guid,
      }),
    }));

    // Update the peer's connection record
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: connection.peer_guid,
        peer_guid: claims.user_guid,
      }),
      UpdateExpression: "SET #status = :revoked, revoked_at = :now, revoked_by = :revoker",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":revoked": "revoked",
        ":now": now,
        ":revoker": claims.user_guid,
      }),
    }));

    // NOTE: Revocation notifications are sent vault-to-vault via NATS MessageSpace.
    // The mobile app triggers connection.notify-revoke through its vault, which notifies the peer's vault.
    // Shared encryption keys should be deleted from the vault's local storage.

    return ok({
      connection_id: connectionId,
      status: "revoked",
      revoked_at: now,
    }, origin);

  } catch (error) {
    console.error("Error revoking connection:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to revoke connection", origin);
  }
};
