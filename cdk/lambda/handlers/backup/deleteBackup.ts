import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, DeleteItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";
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
const s3 = new S3Client({});
const TABLE_BACKUPS = process.env.TABLE_BACKUPS!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get backup ID from path
    const backupId = validatePathParam(event.pathParameters?.backupId, "Backup ID");

    // Get backup metadata
    const backupResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_BACKUPS,
      Key: marshall({ backup_id: backupId }),
    }));

    if (!backupResult.Item) {
      return notFound("Backup not found", origin);
    }

    const backup = unmarshall(backupResult.Item);

    // Verify ownership
    if (backup.member_guid !== claims.user_guid) {
      return forbidden("You can only delete your own backups", origin);
    }

    // Check if this is the only backup
    const backupCount = await ddb.send(new QueryCommand({
      TableName: TABLE_BACKUPS,
      IndexName: "member-created-index",
      KeyConditionExpression: "member_guid = :member",
      ExpressionAttributeValues: marshall({
        ":member": claims.user_guid,
      }),
      Select: "COUNT",
    }));

    if (backupCount.Count === 1) {
      return badRequest("Cannot delete the only backup. Create a new backup first.", origin);
    }

    // Delete from S3
    try {
      await s3.send(new DeleteObjectCommand({
        Bucket: BACKUP_BUCKET,
        Key: backup.s3_key,
      }));
    } catch (error) {
      console.error("Error deleting backup from S3:", error);
      // Continue to delete metadata even if S3 delete fails
    }

    // Delete metadata from DynamoDB
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_BACKUPS,
      Key: marshall({ backup_id: backupId }),
    }));

    return ok({
      deleted: true,
      backup_id: backupId,
    }, origin);

  } catch (error) {
    console.error("Error deleting backup:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to delete backup", origin);
  }
};
