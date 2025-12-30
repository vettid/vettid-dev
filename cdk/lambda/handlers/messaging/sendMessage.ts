import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
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
  generateSecureId,
  parseJsonBody,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_MESSAGES = process.env.TABLE_MESSAGES!;

const MAX_MESSAGE_SIZE = 64 * 1024; // 64KB max for encrypted content

interface SendMessageRequest {
  connection_id: string;
  encrypted_content: string; // Base64-encoded encrypted message
  nonce: string; // Base64-encoded nonce
  content_type?: string; // "text", "image", "file"
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

    // Parse request body
    const body = parseJsonBody<SendMessageRequest>(event);

    if (!body.connection_id || typeof body.connection_id !== "string") {
      return badRequest("connection_id is required", origin);
    }

    if (!body.encrypted_content || typeof body.encrypted_content !== "string") {
      return badRequest("encrypted_content is required", origin);
    }

    if (!body.nonce || typeof body.nonce !== "string") {
      return badRequest("nonce is required", origin);
    }

    // Validate encrypted content size
    try {
      const contentBuffer = Buffer.from(body.encrypted_content, "base64");
      if (contentBuffer.length > MAX_MESSAGE_SIZE) {
        return badRequest(`Message too large. Maximum size is ${MAX_MESSAGE_SIZE} bytes.`, origin);
      }
    } catch {
      return badRequest("encrypted_content must be valid Base64", origin);
    }

    // Validate nonce (24 bytes for XChaCha20-Poly1305)
    try {
      const nonceBuffer = Buffer.from(body.nonce, "base64");
      if (nonceBuffer.length !== 24) {
        return badRequest("nonce must be 24 bytes (XChaCha20-Poly1305)", origin);
      }
    } catch {
      return badRequest("nonce must be valid Base64", origin);
    }

    const contentType = body.content_type || "text";
    if (!["text", "image", "file"].includes(contentType)) {
      return badRequest("content_type must be text, image, or file", origin);
    }

    // Verify connection exists and is active
    const connectionResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      IndexName: "connection-id-index",
      KeyConditionExpression: "connection_id = :connId",
      FilterExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall({
        ":connId": body.connection_id,
        ":owner": claims.user_guid,
      }),
    }));

    if (!connectionResult.Items || connectionResult.Items.length === 0) {
      return notFound("Connection not found", origin);
    }

    const connection = unmarshall(connectionResult.Items[0]);

    if (connection.status !== "active") {
      return forbidden("Cannot send messages to a revoked connection", origin);
    }

    // Create message
    const messageId = generateSecureId("MSG");
    const now = nowIso();

    const message = {
      message_id: messageId,
      connection_id: body.connection_id,
      sender_guid: claims.user_guid,
      recipient_guid: connection.peer_guid,
      encrypted_content: body.encrypted_content,
      nonce: body.nonce,
      content_type: contentType,
      sent_at: now,
      status: "sent",
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_MESSAGES,
      Item: marshall(message),
    }));

    // Update sender's connection with last message time
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: claims.user_guid,
        peer_guid: connection.peer_guid,
      }),
      UpdateExpression: "SET last_message_at = :now",
      ExpressionAttributeValues: marshall({ ":now": now }),
    }));

    // Update recipient's connection with last message time and increment unread count
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CONNECTIONS,
      Key: marshall({
        owner_guid: connection.peer_guid,
        peer_guid: claims.user_guid,
      }),
      UpdateExpression: "SET last_message_at = :now, unread_count = if_not_exists(unread_count, :zero) + :one",
      ExpressionAttributeValues: marshall({
        ":now": now,
        ":zero": 0,
        ":one": 1,
      }),
    }));

    // NOTE: Real-time delivery is handled vault-to-vault via NATS MessageSpace.
    // This Lambda stores messages in DynamoDB for backup/history.
    // The mobile app sends messages through its vault, which forwards to the recipient's vault.

    return ok({
      message_id: messageId,
      connection_id: body.connection_id,
      sender_guid: claims.user_guid,
      content_type: contentType,
      sent_at: now,
      status: "sent",
    }, origin);

  } catch (error) {
    console.error("Error sending message:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to send message", origin);
  }
};
