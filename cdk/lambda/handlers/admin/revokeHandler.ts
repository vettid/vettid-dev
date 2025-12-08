import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireAdminGroup,
  getAdminEmail,
  parseJsonBody,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;

interface RevokeHandlerRequest {
  handler_id: string;
  reason: string;
}

interface RevokeHandlerResponse {
  handler_id: string;
  status: 'revoked';
  revoked_at: string;
  revoked_by: string;
  reason: string;
}

/**
 * POST /admin/registry/handlers/revoke
 *
 * Revoke a handler, making it unavailable for new installations.
 * Existing installations remain but users will be notified of revocation.
 *
 * Requires admin JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate admin authentication
    const adminCheck = requireAdminGroup(event);
    if (adminCheck) return adminCheck;

    const adminEmail = getAdminEmail(event);

    // Parse request body
    let body: RevokeHandlerRequest;
    try {
      body = parseJsonBody<RevokeHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.handler_id) {
      return badRequest('handler_id is required.');
    }

    if (!body.reason || body.reason.trim().length < 10) {
      return badRequest('reason is required and must be at least 10 characters.');
    }

    // Get handler from registry
    const handlerResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    if (!handlerResult.Item) {
      return notFound('Handler not found.');
    }

    const handlerData = unmarshall(handlerResult.Item);

    // Check if already revoked
    if (handlerData.status === 'revoked') {
      return badRequest('Handler is already revoked.');
    }

    const now = new Date().toISOString();

    // Update handler status to revoked
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
      UpdateExpression: `
        SET #status = :revoked,
            revoked_at = :now,
            revoked_by = :admin,
            revocation_reason = :reason,
            updated_at = :now,
            updated_by = :admin
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':revoked': 'revoked',
        ':now': now,
        ':admin': adminEmail,
        ':reason': body.reason.trim(),
      }),
    }));

    const response: RevokeHandlerResponse = {
      handler_id: body.handler_id,
      status: 'revoked',
      revoked_at: now,
      revoked_by: adminEmail,
      reason: body.reason.trim(),
    };

    return ok(response);

  } catch (error: any) {
    console.error('Revoke handler error:', error);
    return internalError('Failed to revoke handler.');
  }
};
