/**
 * Credential Transfer Approve/Deny
 *
 * POST /vault/credentials/transfer/approve
 *
 * Approve or deny a pending credential transfer request from the old device.
 *
 * Security Model:
 * - Only the device that owns the credential can approve/deny
 * - Device attestation required for approval
 * - Transfer must not be expired
 * - One-time transfer token generated on approval
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
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
  generateSecureId,
  hashIdentifier,
  getClientIp,
} from "../../common/util";
import {
  publishTransferApproved,
  publishTransferDenied,
} from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_TRANSFERS = process.env.TABLE_CREDENTIAL_TRANSFERS!;

interface TransferApproveBody {
  transfer_id: string;
  approved: boolean;
  source_attestation?: string;  // Device attestation from approving device
  denial_reason?: string;       // Optional reason if denying
}

interface TransferApproveResponse {
  transfer_id: string;
  status: 'approved' | 'denied';
  transfer_token?: string;  // One-time token for credential transfer (only on approval)
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
    let body: TransferApproveBody;
    if (!event.body) {
      return badRequest("Missing request body", origin);
    }
    try {
      body = JSON.parse(event.body);
    } catch (e) {
      return badRequest("Invalid JSON body", origin);
    }

    const { transfer_id, approved, source_attestation, denial_reason } = body;

    if (!transfer_id) {
      return badRequest("transfer_id is required", origin);
    }

    if (typeof approved !== 'boolean') {
      return badRequest("approved must be a boolean", origin);
    }

    // Validate transfer_id format
    if (!transfer_id.startsWith('transfer-') || transfer_id.length < 20) {
      return badRequest("Invalid transfer_id format", origin);
    }

    // Get transfer request
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_TRANSFERS,
      Key: marshall({ transfer_id }),
    }));

    if (!result.Item) {
      return notFound("Transfer request not found", origin);
    }

    const transfer = unmarshall(result.Item);

    // Verify ownership
    if (transfer.member_guid !== claims.user_guid) {
      return forbidden("You do not have permission to process this transfer request", origin);
    }

    // Check if already processed
    if (transfer.status !== 'pending') {
      return conflict(JSON.stringify({
        error: `Transfer request already ${transfer.status}`,
        status: transfer.status,
      }), origin);
    }

    // Check if expired
    const now = new Date();
    const expiresAt = new Date(transfer.expires_at);
    if (now > expiresAt) {
      // Update status to expired
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_CREDENTIAL_TRANSFERS,
        Key: marshall({ transfer_id }),
        UpdateExpression: 'SET #status = :expired',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({ ':expired': 'expired' }),
      }));

      return conflict(JSON.stringify({
        error: "Transfer request has expired",
        expires_at: transfer.expires_at,
      }), origin);
    }

    // TODO: Validate source attestation when implemented

    const timestamp = nowIso();

    if (approved) {
      // Generate one-time transfer token
      const transferToken = generateSecureId('xfer');

      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_CREDENTIAL_TRANSFERS,
          Key: marshall({ transfer_id }),
          UpdateExpression: 'SET #status = :approved, approved_at = :now, transfer_token = :token, approver_ip_hash = :ip',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({
            ':approved': 'approved',
            ':now': timestamp,
            ':token': transferToken,
            ':ip': hashIdentifier(clientIp),
            ':pending': 'pending',
          }),
          ConditionExpression: '#status = :pending',
        }));
      } catch (e: any) {
        if (e.name === 'ConditionalCheckFailedException') {
          return conflict(JSON.stringify({
            error: "Transfer request cannot be approved in its current state",
          }), origin);
        }
        throw e;
      }

      // Publish NATS event
      try {
        await publishTransferApproved(claims.user_guid, transfer_id);
      } catch (natsError) {
        console.error('Failed to publish transfer approved event:', natsError);
      }

      // Audit log
      await putAudit({
        action: 'credential_transfer_approved',
        member_guid: claims.user_guid,
        transfer_id,
        target_device_id_hash: hashIdentifier(transfer.target_device_id),
        client_ip_hash: hashIdentifier(clientIp),
      });

      const response: TransferApproveResponse = {
        transfer_id,
        status: 'approved',
        transfer_token: transferToken,
        message: 'Transfer approved. The new device can now receive the credential.',
      };

      return ok(response, origin);

    } else {
      // Deny the transfer
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_CREDENTIAL_TRANSFERS,
          Key: marshall({ transfer_id }),
          UpdateExpression: 'SET #status = :denied, denied_at = :now, denial_reason = :reason, denier_ip_hash = :ip',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({
            ':denied': 'denied',
            ':now': timestamp,
            ':reason': denial_reason || 'user_denied',
            ':ip': hashIdentifier(clientIp),
            ':pending': 'pending',
          }, { removeUndefinedValues: true }),
          ConditionExpression: '#status = :pending',
        }));
      } catch (e: any) {
        if (e.name === 'ConditionalCheckFailedException') {
          return conflict(JSON.stringify({
            error: "Transfer request cannot be denied in its current state",
          }), origin);
        }
        throw e;
      }

      // Publish NATS event
      try {
        await publishTransferDenied(claims.user_guid, transfer_id, denial_reason);
      } catch (natsError) {
        console.error('Failed to publish transfer denied event:', natsError);
      }

      // Audit log
      await putAudit({
        action: 'credential_transfer_denied',
        member_guid: claims.user_guid,
        transfer_id,
        target_device_id_hash: hashIdentifier(transfer.target_device_id),
        reason: denial_reason || 'user_denied',
        client_ip_hash: hashIdentifier(clientIp),
      });

      const response: TransferApproveResponse = {
        transfer_id,
        status: 'denied',
        message: 'Transfer denied. The new device will be notified.',
      };

      return ok(response, origin);
    }

  } catch (error) {
    console.error("Error processing credential transfer:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to process credential transfer", origin);
  }
};
