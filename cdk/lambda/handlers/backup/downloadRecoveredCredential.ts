/**
 * Download Recovered Credential
 *
 * GET /vault/recovery/download?recovery_id={id}
 *
 * Downloads the recovered credential after the 24-hour delay has passed.
 * This is the final step of the credential recovery process.
 *
 * Security:
 * - Only available after 24-hour delay
 * - Can only be downloaded once (status changes to 'completed')
 * - Requires valid member JWT matching the recovery request owner
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  conflict,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
  putAudit,
  hashIdentifier,
  getClientIp,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

interface RecoveredCredentialResponse {
  recovery_id: string;
  encrypted_blob: string;       // Base64-encoded encrypted credential
  salt: string;                 // Salt for key derivation
  nonce: string;                // Nonce for decryption
  encryption_method: string;    // e.g., "xchacha20-poly1305"
  key_derivation: string;       // e.g., "argon2id"
  created_at: string;           // When backup was created
  recovered_at: string;         // When recovery completed
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;
  const clientIp = getClientIp(event);

  try {
    // Validate user claims
    const claimsResult = requireUserClaims(event, origin);
    if ("error" in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;

    // Get recovery_id from query parameters
    const recoveryId = event.queryStringParameters?.recovery_id;
    if (!recoveryId) {
      return badRequest("recovery_id query parameter is required", origin);
    }

    // Validate recovery_id format
    if (!recoveryId.startsWith('recovery-') || recoveryId.length < 20) {
      return badRequest("Invalid recovery_id format", origin);
    }

    // Get recovery request
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: recoveryId }),
    }));

    if (!result.Item) {
      return notFound("Recovery request not found", origin);
    }

    const request = unmarshall(result.Item);

    // Verify ownership
    if (request.member_guid !== claims.user_guid) {
      return forbidden("You do not have permission to download this credential", origin);
    }

    // Check status
    if (request.status === 'cancelled') {
      return conflict(JSON.stringify({
        error: "This recovery request was cancelled",
        cancelled_at: request.cancelled_at,
      }), origin);
    }

    if (request.status === 'completed') {
      return conflict(JSON.stringify({
        error: "This credential has already been downloaded",
        completed_at: request.completed_at,
        message: "For security, each recovery can only be downloaded once. Please create a new recovery request if needed.",
      }), origin);
    }

    if (request.status === 'expired') {
      return conflict(JSON.stringify({
        error: "This recovery request has expired",
        expires_at: request.expires_at,
        message: "Please create a new recovery request.",
      }), origin);
    }

    // Check if delay has passed
    const now = new Date();
    const availableAt = new Date(request.available_at);
    const expiresAt = new Date(request.expires_at);

    if (now < availableAt) {
      const remainingMs = availableAt.getTime() - now.getTime();
      const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));

      return conflict(JSON.stringify({
        error: "Recovery not yet available",
        available_at: request.available_at,
        remaining_hours: remainingHours,
        message: `Your credential will be available in approximately ${remainingHours} hour${remainingHours === 1 ? '' : 's'}.`,
      }), origin);
    }

    if (now >= expiresAt) {
      // Update status to expired
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_RECOVERY_REQUESTS,
        Key: marshall({ recovery_id: recoveryId }),
        UpdateExpression: 'SET #status = :expired',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({ ':expired': 'expired' }),
      })).catch(() => { /* ignore */ });

      return conflict(JSON.stringify({
        error: "This recovery request has expired",
        expires_at: request.expires_at,
        message: "Please create a new recovery request.",
      }), origin);
    }

    // Get credential backup
    const backupResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    if (!backupResult.Item) {
      return internalError("Credential backup not found. This should not happen.", origin);
    }

    const backup = unmarshall(backupResult.Item);

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
      return internalError("Failed to download credential", origin);
    }

    // Mark recovery as completed (atomic update to prevent replay)
    const completedAt = nowIso();
    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_RECOVERY_REQUESTS,
        Key: marshall({ recovery_id: recoveryId }),
        UpdateExpression: 'SET #status = :completed, completed_at = :now, download_ip_hash = :ip',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':completed': 'completed',
          ':now': completedAt,
          ':ip': hashIdentifier(clientIp),
          ':ready': 'ready',
          ':pending': 'pending',
        }),
        ConditionExpression: '#status IN (:ready, :pending)',
      }));
    } catch (e: any) {
      if (e.name === 'ConditionalCheckFailedException') {
        return conflict(JSON.stringify({
          error: "Recovery request is no longer valid",
          message: "Please check the recovery status and try again.",
        }), origin);
      }
      throw e;
    }

    // Audit log
    await putAudit({
      action: 'credential_recovery_completed',
      member_guid: claims.user_guid,
      recovery_id: recoveryId,
      client_ip_hash: hashIdentifier(clientIp),
    });

    const response: RecoveredCredentialResponse = {
      recovery_id: recoveryId,
      encrypted_blob: encryptedBlob,
      salt: backup.salt,
      nonce: backup.nonce,
      encryption_method: backup.encryption_method || 'xchacha20-poly1305',
      key_derivation: backup.key_derivation || 'argon2id',
      created_at: backup.created_at,
      recovered_at: completedAt,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error downloading recovered credential:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to download recovered credential", origin);
  }
};
