/**
 * Get Recovery QR Code
 *
 * GET /vault/recovery/qr?recovery_id={id}
 *
 * Generates a QR code payload for credential recovery after the 24-hour delay.
 * The mobile app scans this QR code and exchanges the token directly with
 * the vault via NATS to receive the recovered credential.
 *
 * Security Model (per Architecture v2.0 Section 5.18):
 * - Only returns QR after 24-hour delay has passed
 * - QR contains one-time recovery token
 * - Token is tied to user's vault via NATS topic
 * - App exchanges token with vault-manager via NATS (not Lambda)
 * - Each QR view generates a new token (previous tokens invalidated)
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { randomBytes } from "crypto";
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  conflict,
  internalError,
  requireUserClaims,
  ValidationError,
  generateSecureId,
  putAudit,
  hashIdentifier,
  getClientIp,
} from "../../common/util";

const ddb = new DynamoDBClient({});

const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;
const NATS_ENDPOINT = process.env.NATS_ENDPOINT || "nats.vettid.dev:443";

// Token expires after 10 minutes (must scan QR promptly)
const TOKEN_EXPIRY_SECONDS = 600;

interface RecoveryQRPayload {
  type: "vettid_recovery";
  version: 1;
  token: string;           // One-time recovery token
  vault_topic: string;     // NATS topic for recovery claim
  nats_endpoint: string;   // NATS server endpoint
  nonce: string;           // Random nonce for replay protection
  expires_at: string;      // ISO 8601 expiry timestamp
  recovery_id: string;     // For correlation (short form)
}

interface RecoveryQRResponse {
  qr_payload: RecoveryQRPayload;
  qr_data: string;         // Base64-encoded JSON for QR code
  expires_at: string;
  message: string;
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
      return forbidden("You do not have permission to access this recovery", origin);
    }

    const now = new Date();
    const availableAt = new Date(request.available_at);
    const expiresAt = new Date(request.expires_at);

    // Check status
    if (request.status === 'cancelled') {
      return conflict("This recovery request was cancelled", origin);
    }
    if (request.status === 'completed') {
      return conflict("This recovery has already been completed", origin);
    }
    if (request.status === 'expired' || now >= expiresAt) {
      return conflict("This recovery request has expired. Please create a new request.", origin);
    }
    if (request.status === 'pending' && now < availableAt) {
      const remainingMs = availableAt.getTime() - now.getTime();
      const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
      return conflict(
        `Recovery is not yet available. Please wait ${remainingHours} more hour${remainingHours === 1 ? '' : 's'}.`,
        origin
      );
    }

    // Generate one-time recovery token
    const recoveryToken = generateSecureId();
    const nonce = randomBytes(16).toString('hex');
    const tokenExpiresAt = new Date(now.getTime() + TOKEN_EXPIRY_SECONDS * 1000);

    // Construct the NATS topic for recovery claim
    // Format: OwnerSpace.{user_guid_no_dashes}.forVault.recovery.claim
    const userGuidNoDashes = claims.user_guid.replace(/-/g, '');
    const vaultTopic = `OwnerSpace.${userGuidNoDashes}.forVault.recovery.claim`;

    // Update recovery request with new token (invalidates previous tokens)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: recoveryId }),
      UpdateExpression: `
        SET #status = :ready,
            recovery_token = :token,
            token_nonce = :nonce,
            token_expires_at = :expires,
            last_qr_generated_at = :now
      `,
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':ready': 'ready',
        ':token': recoveryToken,
        ':nonce': nonce,
        ':expires': tokenExpiresAt.toISOString(),
        ':now': now.toISOString(),
      }),
    }));

    // Build QR payload
    const qrPayload: RecoveryQRPayload = {
      type: "vettid_recovery",
      version: 1,
      token: recoveryToken,
      vault_topic: vaultTopic,
      nats_endpoint: `tls://${NATS_ENDPOINT}`,
      nonce,
      expires_at: tokenExpiresAt.toISOString(),
      recovery_id: recoveryId.substring(0, 24),  // Short form for display
    };

    // Encode as base64 for QR code
    const qrData = Buffer.from(JSON.stringify(qrPayload)).toString('base64');

    // Audit log
    await putAudit({
      action: 'recovery_qr_generated',
      member_guid: claims.user_guid,
      recovery_id: recoveryId,
      client_ip_hash: hashIdentifier(clientIp),
      token_expires_at: tokenExpiresAt.toISOString(),
    });

    const response: RecoveryQRResponse = {
      qr_payload: qrPayload,
      qr_data: qrData,
      expires_at: tokenExpiresAt.toISOString(),
      message: `Scan this QR code with your VettID app within ${Math.round(TOKEN_EXPIRY_SECONDS / 60)} minutes to recover your credential.`,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error generating recovery QR:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to generate recovery QR code", origin);
  }
};
