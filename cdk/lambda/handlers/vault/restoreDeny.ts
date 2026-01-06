import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;

interface DenyRequestBody {
  recovery_id: string;
  report_suspicious?: boolean;
}

/**
 * POST /vault/credentials/restore/deny
 *
 * Deny a credential transfer request from the active device.
 * This endpoint is called by the mobile app when the user denies the transfer notification.
 *
 * If report_suspicious is true, the system will log a security event and may
 * trigger additional security measures.
 *
 * This endpoint uses the enrollment JWT authorizer (called from mobile device).
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Get user_guid from authorizer context (from enrollment JWT)
    const authContext = (event.requestContext as any)?.authorizer?.lambda as {
      userGuid?: string;
    } | undefined;

    if (!authContext?.userGuid) {
      return badRequest('Authentication required', origin);
    }
    const memberGuid = authContext.userGuid;

    // Parse request body
    let body: DenyRequestBody;
    if (!event.body) {
      return badRequest('Request body is required', origin);
    }
    try {
      body = JSON.parse(event.body) as DenyRequestBody;
    } catch {
      return badRequest('Invalid JSON in request body', origin);
    }

    if (!body.recovery_id) {
      return badRequest('recovery_id is required', origin);
    }

    // Get the recovery request
    const requestResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: body.recovery_id }),
    }));

    if (!requestResult.Item) {
      return notFound('Recovery request not found', origin);
    }

    const request = unmarshall(requestResult.Item);

    // Verify this request belongs to the authenticated user
    if (request.member_guid !== memberGuid) {
      return badRequest('Request does not belong to authenticated user', origin);
    }

    // Verify the request is in pending_approval status
    if (request.status !== 'pending_approval') {
      return conflict(`Request is not pending approval (status: ${request.status})`, origin);
    }

    const now = new Date();

    // Deny the request
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: body.recovery_id }),
      UpdateExpression: 'SET #status = :denied, denied_at = :now, report_suspicious = :suspicious, cancelled_reason = :reason',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':denied': 'denied',
        ':now': now.toISOString(),
        ':suspicious': body.report_suspicious === true,
        ':reason': 'denied_by_device',
      }),
    }));

    // Audit log
    await putAudit({
      type: body.report_suspicious ? 'credential_transfer_denied_suspicious' : 'credential_transfer_denied',
      member_guid: memberGuid,
      recovery_id: body.recovery_id,
      credential_id: request.credential_id,
      report_suspicious: body.report_suspicious === true,
    }, requestId);

    // TODO: If report_suspicious, trigger security measures (email notification, etc.)
    if (body.report_suspicious) {
      console.log(`SECURITY: Suspicious transfer attempt reported for member ${memberGuid}`);
    }

    return ok({
      success: true,
      recovery_id: body.recovery_id,
      message: 'Transfer request denied.',
    }, origin);

  } catch (error: any) {
    console.error('Deny credential transfer error:', error);
    return internalError('Failed to deny credential transfer', origin);
  }
};
