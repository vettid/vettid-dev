/**
 * Request Credential Recovery
 *
 * POST /vault/recovery/request
 *
 * Initiates a 24-hour delayed credential recovery process.
 * The delay provides a security window for the user to cancel
 * if the request was made by an unauthorized party.
 *
 * Security Model:
 * - Anyone with valid member JWT can request recovery
 * - 24-hour delay before recovery is available
 * - Email notification sent when recovery is requested
 * - User can cancel at any time during the delay
 * - Only one active recovery request per user
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { SESClient, SendTemplatedEmailCommand } from "@aws-sdk/client-ses";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  conflict,
  notFound,
  internalError,
  requireUserClaims,
  ValidationError,
  nowIso,
  putAudit,
  generateSecureId,
  hashIdentifier,
  getClientIp,
} from "../../common/util";
import { publishRecoveryRequested } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@vettid.dev";

// 24 hours in milliseconds
const RECOVERY_DELAY_MS = 24 * 60 * 60 * 1000;

// Recovery request expires after 7 days if not claimed
const RECOVERY_EXPIRY_DAYS = 7;

interface RequestRecoveryRequest {
  reason?: string;  // Optional reason for audit trail
}

interface RequestRecoveryResponse {
  recovery_id: string;
  requested_at: string;
  available_at: string;
  status: 'pending' | 'ready' | 'cancelled' | 'expired' | 'completed';
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

    // Parse optional request body
    let body: RequestRecoveryRequest = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body);
      } catch (e) {
        return badRequest("Invalid JSON body", origin);
      }
    }

    // Check if user has a credential backup
    const backupResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      Key: marshall({ member_guid: claims.user_guid }),
    }));

    if (!backupResult.Item) {
      return notFound("No credential backup found. You must create a backup before you can request recovery.", origin);
    }

    // Check for existing active recovery request
    const existingResult = await ddb.send(new QueryCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid AND #status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': claims.user_guid,
        ':status': 'pending',
      }),
      Limit: 1,
    }));

    if (existingResult.Items && existingResult.Items.length > 0) {
      const existing = unmarshall(existingResult.Items[0]);
      return conflict(JSON.stringify({
        error: "Active recovery request already exists",
        recovery_id: existing.recovery_id,
        available_at: existing.available_at,
        message: "You already have a pending recovery request. Cancel it first to create a new one.",
      }), origin);
    }

    // Create new recovery request
    const now = new Date();
    const availableAt = new Date(now.getTime() + RECOVERY_DELAY_MS);
    const expiresAt = new Date(availableAt.getTime() + RECOVERY_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
    const recoveryId = `recovery-${generateSecureId()}`;

    const recoveryRequest = {
      recovery_id: recoveryId,
      member_guid: claims.user_guid,
      email: claims.email,
      status: 'pending',
      reason: body.reason || null,
      requested_at: now.toISOString(),
      available_at: availableAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      ttl: Math.floor(expiresAt.getTime() / 1000),  // DynamoDB TTL
      client_ip_hash: hashIdentifier(clientIp),
      cancelled_at: null,
      completed_at: null,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      Item: marshall(recoveryRequest, { removeUndefinedValues: true }),
      ConditionExpression: 'attribute_not_exists(recovery_id)',
    }));

    // Send notification email
    try {
      await ses.send(new SendTemplatedEmailCommand({
        Source: FROM_EMAIL,
        Destination: {
          ToAddresses: [claims.email],
        },
        Template: 'CredentialRecoveryRequested',
        TemplateData: JSON.stringify({
          email: claims.email,
          recovery_id: recoveryId.substring(0, 16) + '...',
          available_at: availableAt.toISOString(),
          cancel_url: `https://account.vettid.dev/recovery/cancel?id=${recoveryId}`,
        }),
      }));
    } catch (emailError) {
      console.error('Failed to send recovery notification email:', emailError);
      // Don't fail the request if email fails
    }

    // Audit log
    await putAudit({
      action: 'credential_recovery_requested',
      member_guid: claims.user_guid,
      recovery_id: recoveryId,
      client_ip_hash: hashIdentifier(clientIp),
      available_at: availableAt.toISOString(),
    });

    // Publish NATS event to notify user's connected devices
    try {
      await publishRecoveryRequested(
        claims.user_guid,
        recoveryId,
        now.toISOString(),
        availableAt.toISOString()
      );
    } catch (natsError) {
      console.error('Failed to publish recovery requested event:', natsError);
      // Don't fail the request if NATS publish fails
    }

    const response: RequestRecoveryResponse = {
      recovery_id: recoveryId,
      requested_at: now.toISOString(),
      available_at: availableAt.toISOString(),
      status: 'pending',
      message: `Recovery request created. Your credential will be available for download in 24 hours (at ${availableAt.toISOString()}). Check your email for confirmation.`,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error requesting credential recovery:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to request credential recovery", origin);
  }
};
