import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
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
const TABLE_MESSAGES = process.env.TABLE_MESSAGES!;

interface MessageResponse {
  message_id: string;
  connection_id: string;
  sender_guid: string;
  encrypted_content: string;
  nonce: string;
  content_type: string;
  sent_at: string;
  received_at: string | null;
  read_at: string | null;
  status: string;
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

    // Get connection ID from path
    const connectionId = validatePathParam(event.pathParameters?.connectionId, "Connection ID");

    // Parse query parameters
    const limit = Math.min(parseInt(event.queryStringParameters?.limit || "50", 10), 100);
    const before = event.queryStringParameters?.before; // ISO timestamp
    const lastKey = event.queryStringParameters?.last_key;

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

    // Build query for messages
    const queryParams: any = {
      TableName: TABLE_MESSAGES,
      IndexName: "connection-sent-index",
      KeyConditionExpression: "connection_id = :connId",
      ExpressionAttributeValues: marshall({
        ":connId": connectionId,
      }),
      Limit: limit,
      ScanIndexForward: false, // Most recent first
    };

    // Add before filter if specified
    if (before) {
      queryParams.KeyConditionExpression += " AND sent_at < :before";
      queryParams.ExpressionAttributeValues = marshall({
        ...unmarshall(queryParams.ExpressionAttributeValues),
        ":before": before,
      });
    }

    // Add pagination key if specified
    if (lastKey) {
      try {
        queryParams.ExclusiveStartKey = JSON.parse(Buffer.from(lastKey, "base64").toString());
      } catch {
        return badRequest("Invalid last_key format", origin);
      }
    }

    const result = await ddb.send(new QueryCommand(queryParams));

    const messages: MessageResponse[] = (result.Items || []).map(item => {
      const msg = unmarshall(item);
      return {
        message_id: msg.message_id,
        connection_id: msg.connection_id,
        sender_guid: msg.sender_guid,
        encrypted_content: msg.encrypted_content,
        nonce: msg.nonce,
        content_type: msg.content_type,
        sent_at: msg.sent_at,
        received_at: msg.received_at || null,
        read_at: msg.read_at || null,
        status: msg.status,
      };
    });

    const response: any = {
      messages,
      count: messages.length,
      connection_id: connectionId,
    };

    if (result.LastEvaluatedKey) {
      response.last_key = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64");
    }

    return ok(response, origin);

  } catch (error) {
    console.error("Error getting message history:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get message history", origin);
  }
};
