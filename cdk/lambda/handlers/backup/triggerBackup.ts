import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomUUID } from "crypto";
import {
  ok,
  badRequest,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});
const TABLE_BACKUPS = process.env.TABLE_BACKUPS!;
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const TABLE_MESSAGES = process.env.TABLE_MESSAGES!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

interface BackupRequest {
  type?: "manual" | "auto";
  include_messages?: boolean;
}

interface BackupContents {
  connections_count: number;
  messages_count: number;
  handlers_count: number;
  profile_included: boolean;
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
    let request: BackupRequest = {};
    if (event.body) {
      try {
        request = JSON.parse(event.body);
      } catch {
        return badRequest("Invalid JSON body", origin);
      }
    }

    const backupType = request.type || "manual";
    const includeMessages = request.include_messages !== false;

    // Check for recent backup (within last hour for auto backups)
    if (backupType === "auto") {
      const recentCheck = await ddb.send(new QueryCommand({
        TableName: TABLE_BACKUPS,
        IndexName: "member-created-index",
        KeyConditionExpression: "member_guid = :member",
        ExpressionAttributeValues: marshall({
          ":member": claims.user_guid,
        }),
        ScanIndexForward: false,
        Limit: 1,
      }));

      if (recentCheck.Items && recentCheck.Items.length > 0) {
        const lastBackup = unmarshall(recentCheck.Items[0]);
        const lastBackupTime = new Date(lastBackup.created_at).getTime();
        const oneHourAgo = Date.now() - 60 * 60 * 1000;

        if (lastBackupTime > oneHourAgo) {
          return ok({
            skipped: true,
            reason: "Recent backup exists",
            last_backup_id: lastBackup.backup_id,
            last_backup_at: lastBackup.created_at,
          }, origin);
        }
      }
    }

    const backupId = randomUUID();
    const now = nowIso();

    // Gather backup data
    const backupData: any = {
      version: 1,
      created_at: now,
      member_guid: claims.user_guid,
    };

    // Get connections
    const connectionsResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CONNECTIONS,
      KeyConditionExpression: "owner_guid = :owner",
      ExpressionAttributeValues: marshall({
        ":owner": claims.user_guid,
      }),
    }));
    const connections = connectionsResult.Items?.map(item => unmarshall(item)) || [];
    backupData.connections = connections;

    // Get profile
    const profileResult = await ddb.send(new QueryCommand({
      TableName: TABLE_PROFILES,
      KeyConditionExpression: "user_guid = :user",
      ExpressionAttributeValues: marshall({
        ":user": claims.user_guid,
      }),
      Limit: 1,
    }));
    if (profileResult.Items && profileResult.Items.length > 0) {
      backupData.profile = unmarshall(profileResult.Items[0]);
    }

    // Get messages if requested
    let messagesCount = 0;
    if (includeMessages) {
      const connectionIds = connections.map(c => c.connection_id);
      const allMessages: any[] = [];

      for (const connId of connectionIds) {
        const messagesResult = await ddb.send(new QueryCommand({
          TableName: TABLE_MESSAGES,
          IndexName: "connection-sent-index",
          KeyConditionExpression: "connection_id = :connId",
          ExpressionAttributeValues: marshall({
            ":connId": connId,
          }),
        }));
        if (messagesResult.Items) {
          allMessages.push(...messagesResult.Items.map(item => unmarshall(item)));
        }
      }
      backupData.messages = allMessages;
      messagesCount = allMessages.length;
    }

    // Serialize and calculate size
    const backupJson = JSON.stringify(backupData);
    const backupBuffer = Buffer.from(backupJson, "utf-8");
    const sizeBytes = backupBuffer.length;

    // Upload to S3
    const s3Key = `${claims.user_guid}/vault/${backupId}.json`;
    await s3.send(new PutObjectCommand({
      Bucket: BACKUP_BUCKET,
      Key: s3Key,
      Body: backupBuffer,
      ContentType: "application/json",
      ServerSideEncryption: "AES256",
      Metadata: {
        "member-guid": claims.user_guid,
        "backup-type": backupType,
        "created-at": now,
      },
    }));

    // Create backup metadata record
    const contents: BackupContents = {
      connections_count: connections.length,
      messages_count: messagesCount,
      handlers_count: 0, // TODO: Add handler config backup
      profile_included: !!backupData.profile,
    };

    const backupRecord = {
      backup_id: backupId,
      member_guid: claims.user_guid,
      created_at: now,
      type: backupType,
      status: "complete",
      size_bytes: sizeBytes,
      s3_key: s3Key,
      encryption_method: "AES256", // S3 SSE
      contents,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_BACKUPS,
      Item: marshall(backupRecord),
    }));

    return ok({
      backup_id: backupId,
      created_at: now,
      type: backupType,
      status: "complete",
      size_bytes: sizeBytes,
      contents,
    }, origin);

  } catch (error) {
    console.error("Error triggering backup:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to create backup", origin);
  }
};
