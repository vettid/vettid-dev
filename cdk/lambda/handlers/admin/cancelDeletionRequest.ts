import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, notFound, internalError, requireAdminGroup, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;

/**
 * Cancel a pending vault deletion request
 *
 * Path params:
 * - request_id: The deletion request ID to cancel
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
    const requestId = event.pathParameters?.request_id;
    if (!requestId) {
      return badRequest('request_id is required');
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
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      Key: marshall({ request_id: requestId }),
    }));

    if (!getResult.Item) {
      return notFound('Deletion request not found');
    }

    const request = unmarshall(getResult.Item);

    // Only allow cancellation of pending or ready requests
    if (!['pending', 'ready'].includes(request.status)) {
      return badRequest(`Cannot cancel request with status '${request.status}'. Only pending or ready requests can be cancelled.`);
    }

    // Update the request status
    const now = new Date().toISOString();
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_DELETION_REQUESTS,
      Key: marshall({ request_id: requestId }),
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
      type: 'admin_vault_deletion_cancelled',
      details: {
        request_id: requestId,
        member_guid: request.member_guid,
        member_email: request.member_email,
        cancelled_by: adminEmail,
        reason,
      }
    });

    return ok({
      request_id: requestId,
      status: 'cancelled',
      cancelled_at: now,
      cancelled_by: adminEmail,
      reason,
      message: 'Deletion request cancelled successfully',
    });
  } catch (error) {
    console.error('Error cancelling deletion request:', error);

    await putAudit({
      type: 'admin_cancel_deletion_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to cancel deletion request');
  }
};
