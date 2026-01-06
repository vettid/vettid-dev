import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;

/**
 * Cancel a pending credential recovery request
 *
 * Path params:
 * - recovery_id: The recovery request ID to cancel
 *
 * Body (optional):
 * - reason: Reason for cancellation
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  try {
    const recoveryId = event.pathParameters?.recovery_id;
    if (!recoveryId) {
      return badRequest('recovery_id is required');
    }

    const adminEmail = getAdminEmail(event);
    let reason = 'Cancelled by admin';

    if (event.body) {
      try {
        const body = JSON.parse(event.body);
        if (body.reason) {
          reason = body.reason;
        }
      } catch {
        // Ignore parse errors for optional body
      }
    }

    // Get the current request
    const getResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: recoveryId }),
    }));

    if (!getResult.Item) {
      return notFound('Recovery request not found');
    }

    const request = unmarshall(getResult.Item);

    // Only allow cancellation of pending requests
    if (request.status !== 'pending') {
      return badRequest(`Cannot cancel request with status '${request.status}'. Only pending requests can be cancelled.`);
    }

    // Update the request status
    const now = new Date().toISOString();
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: recoveryId }),
      UpdateExpression: 'SET #s = :cancelled, cancelled_at = :now, cancelled_by = :admin, cancellation_reason = :reason',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: marshall({
        ':cancelled': 'cancelled',
        ':now': now,
        ':admin': adminEmail,
        ':reason': reason,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'admin_credential_recovery_cancelled',
      details: {
        recovery_id: recoveryId,
        member_guid: request.member_guid,
        member_email: request.member_email,
        cancelled_by: adminEmail,
        reason,
      }
    });

    return ok({
      recovery_id: recoveryId,
      status: 'cancelled',
      cancelled_at: now,
      cancelled_by: adminEmail,
      reason,
      message: 'Recovery request cancelled successfully',
    });
  } catch (error) {
    console.error('Error cancelling recovery request:', error);

    await putAudit({
      type: 'admin_cancel_recovery_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to cancel recovery request');
  }
};
