import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
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
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

interface CredentialBackupRequest {
  encrypted_blob: string;  // Base64-encoded encrypted credential blob
  salt: string;            // Base64-encoded salt used for key derivation
  nonce: string;           // Base64-encoded nonce used for encryption
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

    let request: CredentialBackupRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return badRequest("Invalid JSON body", origin);
    }

    // Validate required fields
    if (!request.encrypted_blob) {
      return badRequest("encrypted_blob is required", origin);
    }
    if (!request.salt) {
      return badRequest("salt is required", origin);
    }
    if (!request.nonce) {
      return badRequest("nonce is required", origin);
    }

    // Validate Base64 format
    try {
      const blobBuffer = Buffer.from(request.encrypted_blob, "base64");
      const saltBuffer = Buffer.from(request.salt, "base64");
      const nonceBuffer = Buffer.from(request.nonce, "base64");

      if (blobBuffer.length === 0) {
        return badRequest("encrypted_blob cannot be empty", origin);
      }
      if (saltBuffer.length < 16) {
        return badRequest("salt must be at least 16 bytes", origin);
      }
      if (nonceBuffer.length !== 24) {
        return badRequest("nonce must be exactly 24 bytes (XChaCha20)", origin);
      }
    } catch {
      return badRequest("Invalid Base64 encoding", origin);
    }

    const backupId = randomUUID();
    const now = nowIso();

    // Check if credential backup already exists
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    const isUpdate = !!existingResult.Item;

    // Upload encrypted blob to S3
    const s3Key = `${claims.user_guid}/credentials/${backupId}.enc`;
    await s3.send(new PutObjectCommand({
      Bucket: BACKUP_BUCKET,
      Key: s3Key,
      Body: Buffer.from(request.encrypted_blob, "base64"),
      ContentType: "application/octet-stream",
      ServerSideEncryption: "AES256",
      Metadata: {
        "member-guid": claims.user_guid,
        "created-at": now,
        "encryption": "XChaCha20-Poly1305",
      },
    }));

    // Store or update credential backup metadata
    const backupRecord = {
      member_guid: claims.user_guid,
      backup_id: backupId,
      created_at: now,
      updated_at: now,
      s3_key: s3Key,
      salt: request.salt,
      nonce: request.nonce,
      encryption_method: "XChaCha20-Poly1305",
      key_derivation: "Argon2id",
      size_bytes: Buffer.from(request.encrypted_blob, "base64").length,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Item: marshall(backupRecord),
    }));

    return ok({
      success: true,
      backup_id: backupId,
      created_at: now,
      is_update: isUpdate,
    }, origin);

  } catch (error) {
    console.error("Error creating credential backup:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to create credential backup", origin);
  }
};
