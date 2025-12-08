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
const TABLE_BACKUPS = process.env.TABLE_BACKUPS!;

interface BackupResponse {
  backup_id: string;
  created_at: string;
  type: "manual" | "auto";
  status: string;
  size_bytes: number;
  encryption_method: string;
  contents: {
    connections_count: number;
    messages_count: number;
    handlers_count: number;
    profile_included: boolean;
  };
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
    const limit = Math.min(parseInt(event.queryStringParameters?.limit || "50", 10), 100);
    const lastKey = event.queryStringParameters?.last_key;

    // Query backups for this member
    const queryParams: any = {
      TableName: TABLE_BACKUPS,
      IndexName: "member-created-index",
      KeyConditionExpression: "member_guid = :member",
      ExpressionAttributeValues: marshall({
        ":member": claims.user_guid,
      }),
      ScanIndexForward: false, // Most recent first
      Limit: limit,
    };

    // Add pagination key if specified
    if (lastKey) {
      try {
        queryParams.ExclusiveStartKey = JSON.parse(Buffer.from(lastKey, "base64").toString());
      } catch {
        return badRequest("Invalid last_key format", origin);
      }
    }

    const result = await ddb.send(new QueryCommand(queryParams));

    const backups: BackupResponse[] = (result.Items || []).map(item => {
      const backup = unmarshall(item);
      return {
        backup_id: backup.backup_id,
        created_at: backup.created_at,
        type: backup.type,
        status: backup.status,
        size_bytes: backup.size_bytes,
        encryption_method: backup.encryption_method,
        contents: backup.contents || {
          connections_count: 0,
          messages_count: 0,
          handlers_count: 0,
          profile_included: false,
        },
      };
    });

    const response: any = {
      backups,
      count: backups.length,
    };

    if (result.LastEvaluatedKey) {
      response.last_key = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64");
    }

    return ok(response, origin);

  } catch (error) {
    console.error("Error listing backups:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to list backups", origin);
  }
};
