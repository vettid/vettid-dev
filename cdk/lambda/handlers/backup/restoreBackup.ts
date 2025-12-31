import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
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
} from "../../common/util";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});
const TABLE_BACKUPS = process.env.TABLE_BACKUPS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

// NOTE: Connections and messages are vault-managed (stored in JetStream KV).
// This Lambda only restores profile data from DynamoDB backups.
// Vault data restoration is handled by the vault itself via NATS commands.

interface RestoreRequest {
  backup_id: string;
  mode?: "overwrite" | "merge";
  restore_profile?: boolean;
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
    if (!event.body) {
      return badRequest("Request body required", origin);
    }

    let request: RestoreRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest("Invalid JSON body", origin);
    }

    if (!request.backup_id) {
      return badRequest("backup_id is required", origin);
    }

    const mode = request.mode || "overwrite";
    const restoreProfile = request.restore_profile !== false;

    // Get backup metadata
    const backupResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_BACKUPS,
      Key: marshall({ backup_id: request.backup_id }),
    }));

    if (!backupResult.Item) {
      return notFound("Backup not found", origin);
    }

    const backup = unmarshall(backupResult.Item);

    // Verify ownership
    if (backup.member_guid !== claims.user_guid) {
      return forbidden("You can only restore your own backups", origin);
    }

    // Verify backup status
    if (backup.status !== "complete") {
      return badRequest("Cannot restore incomplete backup", origin);
    }

    // Download backup from S3
    let backupData: any;
    try {
      const s3Result = await s3.send(new GetObjectCommand({
        Bucket: BACKUP_BUCKET,
        Key: backup.s3_key,
      }));
      const bodyString = await s3Result.Body?.transformToString();
      if (!bodyString) {
        return internalError("Backup file is empty", origin);
      }
      backupData = JSON.parse(bodyString);
    } catch (error) {
      console.error("Error downloading backup:", error);
      return internalError("Failed to download backup", origin);
    }

    // Verify backup integrity
    if (backupData.member_guid !== claims.user_guid) {
      return forbidden("Backup data does not match current user", origin);
    }

    const restored = {
      profile: false,
      // Legacy fields for compatibility
      connections: 0,
      messages: 0,
    };
    const conflicts: string[] = [];

    // Restore profile
    if (restoreProfile && backupData.profile) {
      try {
        if (mode === "overwrite") {
          await ddb.send(new PutItemCommand({
            TableName: TABLE_PROFILES,
            Item: marshall({
              ...backupData.profile,
              restored_at: nowIso(),
            }),
          }));
          restored.profile = true;
        } else {
          // Merge mode - only update if not exists
          await ddb.send(new PutItemCommand({
            TableName: TABLE_PROFILES,
            Item: marshall({
              ...backupData.profile,
              restored_at: nowIso(),
            }),
            ConditionExpression: "attribute_not_exists(user_guid)",
          }));
          restored.profile = true;
        }
      } catch (error: any) {
        if (error.name === "ConditionalCheckFailedException") {
          conflicts.push("Profile already exists");
        } else {
          throw error;
        }
      }
    }

    // NOTE: Connections and messages from old backups (version 1) are ignored.
    // Those are now vault-managed and restored via vault-to-vault NATS commands.

    // Update backup record with restore timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_BACKUPS,
      Key: marshall({ backup_id: request.backup_id }),
      UpdateExpression: "SET last_restored_at = :now",
      ExpressionAttributeValues: marshall({
        ":now": nowIso(),
      }),
    }));

    return ok({
      success: true,
      backup_id: request.backup_id,
      mode,
      restored_items: restored.profile ? 1 : 0,
      restored: {
        profile: restored.profile,
        connections: restored.connections,
        messages: restored.messages,
      },
      conflicts,
      requires_reauth: false,
    }, origin);

  } catch (error) {
    console.error("Error restoring backup:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to restore backup", origin);
  }
};
