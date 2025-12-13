import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
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

interface DeleteServiceRequest {
  service_id: string;
}

/**
 * POST /admin/services/delete
 *
 * Permanently delete a supported service listing.
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
    let body: DeleteServiceRequest;
    try {
      body = parseJsonBody<DeleteServiceRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.service_id) {
      return badRequest('service_id is required.');
    }

    // Check if service exists
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    if (!existingResult.Item) {
      return notFound('Service not found.');
    }

    // Delete the service
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    const now = new Date().toISOString();

    return ok({
      service_id: body.service_id,
      deleted: true,
      deleted_at: now,
      deleted_by: adminEmail,
    });

  } catch (error: any) {
    console.error('Delete service error:', error);
    return internalError('Failed to delete service.');
  }
};
