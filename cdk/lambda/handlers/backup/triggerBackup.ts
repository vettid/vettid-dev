import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, QueryCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
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
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

// NOTE: Connections and messages are vault-managed (stored in JetStream KV).
// This Lambda only backs up profile data from DynamoDB.
// Vault data backups are handled by the vault itself via NATS commands.

interface BackupRequest {
  type?: "manual" | "auto";
}

interface BackupContents {
  profile_included: boolean;
  // Legacy fields kept for compatibility
  connections_count: number;
  messages_count: number;
  handlers_count: number;
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

    // Gather backup data (profile only - connections/messages are vault-managed)
    const backupData: any = {
      version: 2, // v2: profile only, connections/messages in vault
      created_at: now,
      member_guid: claims.user_guid,
    };

    // Get profile
    const profileResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROFILES,
      Key: marshall({ user_guid: claims.user_guid }),
    }));
    if (profileResult.Item) {
      backupData.profile = unmarshall(profileResult.Item);
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
    // NOTE: connections_count and messages_count are 0 since those are vault-managed
    const contents: BackupContents = {
      profile_included: !!backupData.profile,
      connections_count: 0, // Vault-managed
      messages_count: 0, // Vault-managed
      handlers_count: 0, // TODO: Add handler config backup
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
