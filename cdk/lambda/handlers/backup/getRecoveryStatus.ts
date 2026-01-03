/**
 * Get Credential Recovery Status
 *
 * GET /vault/recovery/status?recovery_id={id}
 *
 * Returns the current status of a credential recovery request.
 * Used by mobile apps to poll for when recovery becomes available.
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
  nowIso,
} from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;

interface RecoveryStatusResponse {
  recovery_id: string;
  status: 'pending' | 'ready' | 'cancelled' | 'expired' | 'completed';
  requested_at: string;
  available_at: string;
  expires_at: string;
  remaining_seconds?: number;  // Seconds until available (if pending)
  message: string;
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
      return forbidden("You do not have permission to view this recovery request", origin);
    }

    const now = new Date();
    const availableAt = new Date(request.available_at);
    const expiresAt = new Date(request.expires_at);

    // Determine current status
    let status = request.status;
    let message = '';

    if (status === 'pending') {
      if (now >= availableAt) {
        // Update status to ready
        status = 'ready';
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_RECOVERY_REQUESTS,
          Key: marshall({ recovery_id: recoveryId }),
          UpdateExpression: 'SET #status = :ready',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({ ':ready': 'ready' }),
          ConditionExpression: '#status = :pending',
        })).catch(() => {
          // Ignore race condition
        });
        message = 'Your credential is now available for download.';
      } else {
        const remainingMs = availableAt.getTime() - now.getTime();
        const remainingSeconds = Math.ceil(remainingMs / 1000);
        const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));

        message = `Your credential will be available in approximately ${remainingHours} hour${remainingHours === 1 ? '' : 's'}.`;

        const response: RecoveryStatusResponse = {
          recovery_id: recoveryId,
          status: 'pending',
          requested_at: request.requested_at,
          available_at: request.available_at,
          expires_at: request.expires_at,
          remaining_seconds: remainingSeconds,
          message,
        };

        return ok(response, origin);
      }
    } else if (status === 'ready') {
      if (now >= expiresAt) {
        // Update status to expired
        status = 'expired';
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_RECOVERY_REQUESTS,
          Key: marshall({ recovery_id: recoveryId }),
          UpdateExpression: 'SET #status = :expired',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: marshall({ ':expired': 'expired' }),
          ConditionExpression: '#status = :ready',
        })).catch(() => {
          // Ignore race condition
        });
        message = 'This recovery request has expired. Please create a new request.';
      } else {
        message = 'Your credential is ready for download.';
      }
    } else if (status === 'cancelled') {
      message = 'This recovery request was cancelled.';
    } else if (status === 'expired') {
      message = 'This recovery request has expired. Please create a new request.';
    } else if (status === 'completed') {
      message = 'This recovery has already been completed.';
    }

    const response: RecoveryStatusResponse = {
      recovery_id: recoveryId,
      status,
      requested_at: request.requested_at,
      available_at: request.available_at,
      expires_at: request.expires_at,
      message,
    };

    return ok(response, origin);

  } catch (error) {
    console.error("Error getting recovery status:", error);
    if (error instanceof ValidationError) {
      return badRequest(error.message, origin);
    }
    return internalError("Failed to get recovery status", origin);
  }
};
