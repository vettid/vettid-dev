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
const TABLE_MESSAGES = process.env.TABLE_MESSAGES!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get message ID from path
    const messageId = validatePathParam(event.pathParameters?.messageId, "Message ID");

    // Get the message
    const messageResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_MESSAGES,
      Key: marshall({ message_id: messageId }),
    }));

    if (!messageResult.Item) {
      return notFound("Message not found", origin);
    }

    const message = unmarshall(messageResult.Item);

    // Verify user is the recipient of this message
    if (message.recipient_guid !== claims.user_guid) {
      return forbidden("You can only mark your own messages as read", origin);
    }

    // Check if already read
    if (message.read_at) {
      return ok({
        message_id: messageId,
        read_at: message.read_at,
        already_read: true,
      }, origin);
    }

    const now = nowIso();

    // Mark message as read
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_MESSAGES,
      Key: marshall({ message_id: messageId }),
      UpdateExpression: "SET read_at = :now, #status = :read",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: marshall({
        ":now": now,
        ":read": "read",
      }),
    }));

    // Find the connection and decrement unread count
    const connectionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      IndexName: "connection-id-index",
      KeyConditionExpression: "connection_id = :connId",
      FilterExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall({
        ":connId": message.connection_id,
        ":owner": claims.user_guid,
      }),
    }));

    if (connectionResult.Items && connectionResult.Items.length > 0) {
      const connection = unmarshall(connectionResult.Items[0]);

      // Decrement unread count (but don't go below 0)
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_CONNECTIONS,
        Key: marshall({
          owner_guid: claims.user_guid,
          peer_guid: connection.peer_guid,
        }),
        UpdateExpression: "SET unread_count = if_not_exists(unread_count, :one) - :one",
        ConditionExpression: "unread_count > :zero",
        ExpressionAttributeValues: marshall({
          ":one": 1,
          ":zero": 0,
        }),
      })).catch(() => {
        // Ignore if unread_count was already 0
      });
    }

    // NOTE: Read receipts are sent vault-to-vault via NATS MessageSpace.
    // The mobile app triggers message.read-receipt through its vault, which forwards to the sender's vault.

    return ok({
      message_id: messageId,
      read_at: now,
      already_read: false,
    }, origin);

  } catch (error) {
    console.error("Error marking message as read:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to mark message as read", origin);
  }
};
