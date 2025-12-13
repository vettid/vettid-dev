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

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;

interface ToggleStatusRequest {
  service_id: string;
  status: 'active' | 'deprecated' | 'coming-soon';
}

/**
 * POST /admin/services/status
 *
 * Toggle the status of a supported service.
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
    let body: ToggleStatusRequest;
    try {
      body = parseJsonBody<ToggleStatusRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.service_id) {
      return badRequest('service_id is required.');
    }

    const validStatuses = ['active', 'deprecated', 'coming-soon'];
    if (!body.status || !validStatuses.includes(body.status)) {
      return badRequest(`status must be one of: ${validStatuses.join(', ')}`);
    }

    // Check if service exists
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    if (!existingResult.Item) {
      return notFound('Service not found.');
    }

    const now = new Date().toISOString();

    // Update status
    const updateResult = await ddb.send(new UpdateItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
      UpdateExpression: 'SET #status = :status, updated_at = :now, updated_by = :admin',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':status': body.status,
        ':now': now,
        ':admin': adminEmail,
      }),
      ReturnValues: 'ALL_NEW',
    }));

    return ok(unmarshall(updateResult.Attributes!));

  } catch (error: any) {
    console.error('Toggle service status error:', error);
    return internalError('Failed to update service status.');
  }
};
