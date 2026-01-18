/**
 * Cancel Credential Recovery
 *
 * POST /vault/recovery/cancel
 *
 * Cancels an active credential recovery request.
 * This is a critical security feature - if a user notices an
 * unauthorized recovery request, they can cancel it before
 * the 24-hour delay expires.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { SESClient, SendTemplatedEmailCommand } from "@aws-sdk/client-ses";
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
import { publishRecoveryCancelled } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});
const ses = new SESClient({});

const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@vettid.dev";

interface CancelRecoveryRequest {
  recovery_id: string;
  reason?: string;  // Optional reason for audit trail
}

interface CancelRecoveryResponse {
  recovery_id: string;
  status: 'cancelled';
  cancelled_at: string;
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

    // Parse request body
    let body: CancelRecoveryRequest;
    if (!event.body) {
      return badRequest("Missing request body", origin);
    }
    try {
      body = JSON.parse(event.body);
    } catch (e) {
      return badRequest("Invalid JSON body", origin);
    }

    const { recovery_id, reason } = body;

    if (!recovery_id) {
      return badRequest("recovery_id is required", origin);
    }

    // Validate recovery_id format
    if (!recovery_id.startsWith('recovery-') || recovery_id.length < 20) {
      return badRequest("Invalid recovery_id format", origin);
    }

    // Get recovery request
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id }),
    }));

    if (!result.Item) {
      return notFound("Recovery request not found", origin);
    }

    const request = unmarshall(result.Item);

    // Verify ownership
    if (request.member_guid !== claims.user_guid) {
      return forbidden("You do not have permission to cancel this recovery request", origin);
    }

    // Check if cancellable
    if (request.status === 'cancelled') {
      return conflict(JSON.stringify({
        error: "Recovery request already cancelled",
        cancelled_at: request.cancelled_at,
      }), origin);
    }

    if (request.status === 'completed') {
      return conflict(JSON.stringify({
        error: "Recovery has already been completed and cannot be cancelled",
        completed_at: request.completed_at,
      }), origin);
    }

    if (request.status === 'expired') {
      return conflict(JSON.stringify({
        error: "Recovery request has expired",
        expires_at: request.expires_at,
      }), origin);
    }

    // Cancel the request
    const now = nowIso();

    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_RECOVERY_REQUESTS,
        Key: marshall({ recovery_id }),
        UpdateExpression: 'SET #status = :cancelled, cancelled_at = :now, cancel_reason = :reason, cancel_ip_hash = :ip',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':cancelled': 'cancelled',
          ':now': now,
          ':reason': reason || null,
          ':ip': hashIdentifier(clientIp),
          ':pending': 'pending',
          ':ready': 'ready',
        }, { removeUndefinedValues: true }),
        ConditionExpression: '#status IN (:pending, :ready)',
      }));
    } catch (e: any) {
      if (e.name === 'ConditionalCheckFailedException') {
        return conflict(JSON.stringify({
          error: "Recovery request cannot be cancelled in its current state",
          status: request.status,
        }), origin);
      }
      throw e;
    }

    // Send confirmation email
    try {
      await ses.send(new SendTemplatedEmailCommand({
        Source: FROM_EMAIL,
        Destination: {
          ToAddresses: [claims.email],
        },
        Template: 'CredentialRecoveryCancelled',
        TemplateData: JSON.stringify({
          email: claims.email,
          recovery_id: recovery_id.substring(0, 16) + '...',
          cancelled_at: now,
        }),
      }));
    } catch (emailError) {
      console.error('Failed to send cancellation email:', emailError);
      // Don't fail the request if email fails
    }

    // Audit log
    await putAudit({
      action: 'credential_recovery_cancelled',
      member_guid: claims.user_guid,
      recovery_id,
      client_ip_hash: hashIdentifier(clientIp),
      reason: reason || null,
    });

    // Publish NATS event to notify user's connected devices
    try {
      await publishRecoveryCancelled(
        claims.user_guid,
        recovery_id,
        'user_cancelled',
        now
      );
    } catch (natsError) {
      console.error('Failed to publish recovery cancelled event:', natsError);
      // Don't fail the request if NATS publish fails
    }

    const response: CancelRecoveryResponse = {
      recovery_id,
      status: 'cancelled',
      cancelled_at: now,
      message: 'Recovery request has been cancelled successfully.',
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error cancelling credential recovery:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to cancel credential recovery", origin);
  }
};
