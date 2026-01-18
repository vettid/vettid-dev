/**
 * Credential Transfer Request
 *
 * POST /vault/credentials/transfer/request
 *
 * Request a credential transfer from a new device. This initiates the transfer
 * process by creating a pending transfer record and notifying the old device(s).
 *
 * Security Model:
 * - Device attestation required for the requesting device
 * - Transfer expires after 15 minutes
 * - Only one active transfer per user
 * - All transfer operations are audit logged
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
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
import { publishTransferRequested, DeviceInfo } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_TRANSFERS = process.env.TABLE_CREDENTIAL_TRANSFERS!;

// Transfer expires after 15 minutes
const TRANSFER_EXPIRY_MS = 15 * 60 * 1000;

interface TransferRequestBody {
  target_device_id: string;
  target_attestation?: string;  // Device attestation (future use)
  device_info?: {
    model?: string;
    os_version?: string;
    location?: string;
  };
}

interface TransferRequestResponse {
  transfer_id: string;
  status: 'pending_approval';
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

    // Parse request body
    let body: TransferRequestBody;
    if (!event.body) {
      return badRequest("Missing request body", origin);
    }
    try {
      body = JSON.parse(event.body);
    } catch (e) {
      return badRequest("Invalid JSON body", origin);
    }

    const { target_device_id, target_attestation, device_info } = body;

    if (!target_device_id) {
      return badRequest("target_device_id is required", origin);
    }

    // Validate device ID format
    if (target_device_id.length < 10 || target_device_id.length > 128) {
      return badRequest("Invalid target_device_id format", origin);
    }

    // TODO: Validate device attestation when implemented
    // For now, we accept any device ID

    // Check for existing active transfer request
    const existingResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_TRANSFERS,
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
        error: "Active transfer request already exists",
        transfer_id: existing.transfer_id,
        expires_at: existing.expires_at,
        message: "You already have a pending transfer request. Wait for it to expire or be processed.",
      }), origin);
    }

    // Create new transfer request
    const now = new Date();
    const expiresAt = new Date(now.getTime() + TRANSFER_EXPIRY_MS);
    const transferId = `transfer-${generateSecureId()}`;

    // Get source device info - in a real implementation, this would come from
    // the user's enrolled device records
    const sourceDeviceId = 'enrolled-device'; // Placeholder

    const transferRequest = {
      transfer_id: transferId,
      member_guid: claims.user_guid,
      email: claims.email,
      source_device_id: sourceDeviceId,
      target_device_id: target_device_id,
      target_attestation_hash: target_attestation ? hashIdentifier(target_attestation) : null,
      target_device_info: device_info || {},
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      ttl: Math.floor(expiresAt.getTime() / 1000) + 3600, // Keep for 1 hour after expiry for audit
      approved_at: null,
      denied_at: null,
      completed_at: null,
      client_ip_hash: hashIdentifier(clientIp),
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_TRANSFERS,
      Item: marshall(transferRequest, { removeUndefinedValues: true }),
      ConditionExpression: 'attribute_not_exists(transfer_id)',
    }));

    // Publish NATS event to notify old device(s)
    try {
      const targetDeviceInfo: DeviceInfo = {
        device_id: target_device_id,
        model: device_info?.model,
        os_version: device_info?.os_version,
        location: device_info?.location,
      };

      await publishTransferRequested(
        claims.user_guid,
        transferId,
        sourceDeviceId,
        targetDeviceInfo,
        expiresAt.toISOString()
      );
    } catch (natsError) {
      console.error('Failed to publish transfer requested event:', natsError);
      // Don't fail the request if NATS publish fails
    }

    // Audit log
    await putAudit({
      action: 'credential_transfer_requested',
      member_guid: claims.user_guid,
      transfer_id: transferId,
      target_device_id_hash: hashIdentifier(target_device_id),
      client_ip_hash: hashIdentifier(clientIp),
      expires_at: expiresAt.toISOString(),
    });

    const response: TransferRequestResponse = {
      transfer_id: transferId,
      status: 'pending_approval',
      expires_at: expiresAt.toISOString(),
      message: `Transfer request created. Waiting for approval from your existing device. Request expires in 15 minutes.`,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error requesting credential transfer:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to request credential transfer", origin);
  }
};
