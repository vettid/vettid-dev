import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand, DeleteItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
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
const TABLE_CONNECTIONS = process.env.TABLE_CONNECTIONS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const TABLE_MESSAGES = process.env.TABLE_MESSAGES!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

interface RestoreRequest {
  backup_id: string;
  mode?: "overwrite" | "merge";
  restore_connections?: boolean;
  restore_messages?: boolean;
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
    const restoreConnections = request.restore_connections !== false;
    const restoreMessages = request.restore_messages !== false;
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
      connections: 0,
      messages: 0,
      profile: false,
    };
    const conflicts: string[] = [];

    // Restore connections
    if (restoreConnections && backupData.connections) {
      if (mode === "overwrite") {
        // Delete existing connections first
        const existingConnections = await ddb.send(new QueryCommand({
          TableName: TABLE_CONNECTIONS,
          KeyConditionExpression: "owner_guid = :owner",
          ExpressionAttributeValues: marshall({
            ":owner": claims.user_guid,
          }),
        }));

        for (const item of existingConnections.Items || []) {
          const conn = unmarshall(item);
          await ddb.send(new DeleteItemCommand({
            TableName: TABLE_CONNECTIONS,
            Key: marshall({
              owner_guid: conn.owner_guid,
              peer_guid: conn.peer_guid,
            }),
          }));
        }
      }

      // Restore connections from backup
      for (const conn of backupData.connections) {
        try {
          await ddb.send(new PutItemCommand({
            TableName: TABLE_CONNECTIONS,
            Item: marshall({
              ...conn,
              restored_at: nowIso(),
            }),
            ConditionExpression: mode === "merge" ? "attribute_not_exists(owner_guid)" : undefined,
          }));
          restored.connections++;
        } catch (error: any) {
          if (error.name === "ConditionalCheckFailedException") {
            conflicts.push(`Connection with ${conn.peer_guid} already exists`);
          } else {
            throw error;
          }
        }
      }
    }

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

    // Restore messages
    if (restoreMessages && backupData.messages) {
      for (const msg of backupData.messages) {
        try {
          await ddb.send(new PutItemCommand({
            TableName: TABLE_MESSAGES,
            Item: marshall({
              ...msg,
              restored_at: nowIso(),
            }),
            ConditionExpression: mode === "merge" ? "attribute_not_exists(message_id)" : undefined,
          }));
          restored.messages++;
        } catch (error: any) {
          if (error.name !== "ConditionalCheckFailedException") {
            throw error;
          }
          // Silently skip duplicate messages in merge mode
        }
      }
    }

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
      restored_items: restored.connections + restored.messages + (restored.profile ? 1 : 0),
      restored: {
        connections: restored.connections,
        messages: restored.messages,
        profile: restored.profile,
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
