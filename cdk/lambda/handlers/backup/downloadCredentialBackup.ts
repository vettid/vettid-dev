import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
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

    // Get credential backup metadata
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    if (!result.Item) {
      return notFound("No credential backup found", origin);
    }

    const backup = unmarshall(result.Item);

    // Download encrypted blob from S3
    let encryptedBlob: string;
    try {
      const s3Result = await s3.send(new GetObjectCommand({
        Bucket: BACKUP_BUCKET,
        Key: backup.s3_key,
      }));
      const bodyBytes = await s3Result.Body?.transformToByteArray();
      if (!bodyBytes) {
        return internalError("Backup file is empty", origin);
      }
      encryptedBlob = Buffer.from(bodyBytes).toString("base64");
    } catch (error) {
      console.error("Error downloading credential backup:", error);
      return internalError("Failed to download credential backup", origin);
    }

    // Update last accessed timestamp
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
      UpdateExpression: "SET last_accessed_at = :now",
      ExpressionAttributeValues: marshall({
        ":now": nowIso(),
      }),
    }));

    return ok({
      encrypted_blob: encryptedBlob,
      salt: backup.salt,
      nonce: backup.nonce,
      created_at: backup.created_at,
      encryption_method: backup.encryption_method,
      key_derivation: backup.key_derivation,
    }, origin);

  } catch (error) {
    console.error("Error downloading credential backup:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to download credential backup", origin);
  }
};
