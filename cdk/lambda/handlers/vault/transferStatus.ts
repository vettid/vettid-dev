/**
 * Credential Transfer Status
 *
 * GET /vault/credentials/transfer/status?transfer_id=xxx
 *
 * Get the status of a credential transfer request.
 * Used by the new device to poll for approval.
 *
 * Security Model:
 * - Only the user who owns the transfer can check status
 * - Transfer token only returned once (on first approved status check)
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import {
  ok,
  badRequest,
  notFound,
  forbidden,
  internalError,
  requireUserClaims,
  ValidationError,
} from "../../common/util";
import { publishTransferExpired } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_TRANSFERS = process.env.TABLE_CREDENTIAL_TRANSFERS!;

interface TransferStatusResponse {
  transfer_id: string;
  status: 'pending' | 'approved' | 'denied' | 'completed' | 'expired';
  created_at: string;
  expires_at: string;
  transfer_token?: string;  // Only included once on approved status
  remaining_seconds?: number;  // For pending status
  denial_reason?: string;  // For denied status
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

    // Get transfer_id from query parameters
    const transferId = event.queryStringParameters?.transfer_id;

    if (!transferId) {
      return badRequest("transfer_id query parameter is required", origin);
    }

    // Validate transfer_id format
    if (!transferId.startsWith('transfer-') || transferId.length < 20) {
      return badRequest("Invalid transfer_id format", origin);
    }

    // Get transfer request
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_TRANSFERS,
      Key: marshall({ transfer_id: transferId }),
    }));

    if (!result.Item) {
      return notFound("Transfer request not found", origin);
    }

    const transfer = unmarshall(result.Item);

    // Verify ownership
    if (transfer.member_guid !== claims.user_guid) {
      return forbidden("You do not have permission to view this transfer request", origin);
    }

    // Check if expired (and update status if needed)
    const now = new Date();
    const expiresAt = new Date(transfer.expires_at);
    let status = transfer.status;

    if (status === 'pending' && now > expiresAt) {
      // Update status to expired
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_CREDENTIAL_TRANSFERS,
        Key: marshall({ transfer_id: transferId }),
        UpdateExpression: 'SET #status = :expired',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({ ':expired': 'expired' }),
      }));
      status = 'expired';

      // Publish expired event
      try {
        await publishTransferExpired(claims.user_guid, transferId);
      } catch (natsError) {
        console.error('Failed to publish transfer expired event:', natsError);
      }
    }

    // Build response
    const response: TransferStatusResponse = {
      transfer_id: transferId,
      status,
      created_at: transfer.created_at,
      expires_at: transfer.expires_at,
    };

    // Include remaining seconds for pending status
    if (status === 'pending') {
      const remainingMs = expiresAt.getTime() - now.getTime();
      response.remaining_seconds = Math.max(0, Math.floor(remainingMs / 1000));
    }

    // Include transfer token for approved status (only once)
    // The new device uses this token to receive the credential via NATS
    if (status === 'approved' && transfer.transfer_token) {
      response.transfer_token = transfer.transfer_token;

      // Mark token as claimed so it's not returned again
      // (Security: prevents replay if response is intercepted)
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_CREDENTIAL_TRANSFERS,
        Key: marshall({ transfer_id: transferId }),
        UpdateExpression: 'SET token_claimed = :true, token_claimed_at = :now',
        ExpressionAttributeValues: marshall({
          ':true': true,
          ':now': now.toISOString(),
        }),
      }));
    }

    // Include denial reason for denied status
    if (status === 'denied' && transfer.denial_reason) {
      response.denial_reason = transfer.denial_reason;
    }

    return ok(response, origin);

  } catch (error) {
    console.error("Error getting transfer status:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get transfer status", origin);
  }
};
