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

interface UpdateServiceRequest {
  service_id: string;
  name?: string;
  description?: string;
  service_type?: string;
  logo_url?: string | null;
  website_url?: string;
  connect_url?: string | null;
  documentation_url?: string | null;
  status?: 'active' | 'deprecated' | 'coming-soon';
  required_user_data?: string[];
  featured?: boolean;
  sort_order?: number;
}

/**
 * PUT /admin/services
 *
 * Update an existing supported service listing.
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
    let body: UpdateServiceRequest;
    try {
      body = parseJsonBody<UpdateServiceRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.service_id) {
      return badRequest('service_id is required.');
    }

    // Validate service_type if provided
    if (body.service_type) {
      const validServiceTypes = [
        'banking', 'messaging', 'crypto', 'authentication', 'payments',
        'storage', 'analytics', 'identity', 'social', 'productivity', 'other'
      ];
      if (!validServiceTypes.includes(body.service_type)) {
        return badRequest(`service_type must be one of: ${validServiceTypes.join(', ')}`);
      }
    }

    // Validate status if provided
    if (body.status) {
      const validStatuses = ['active', 'deprecated', 'coming-soon'];
      if (!validStatuses.includes(body.status)) {
        return badRequest(`status must be one of: ${validStatuses.join(', ')}`);
      }
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

    // Build update expression dynamically
    const updateFields: string[] = [];
    const expressionAttributeNames: { [key: string]: string } = {};
    const expressionAttributeValues: { [key: string]: any } = {};

    const fieldMappings: { [key: string]: string } = {
      name: '#name',
      description: 'description',
      service_type: 'service_type',
      logo_url: 'logo_url',
      website_url: 'website_url',
      connect_url: 'connect_url',
      documentation_url: 'documentation_url',
      status: '#status',
      required_user_data: 'required_user_data',
      featured: 'featured',
      sort_order: 'sort_order',
    };

    for (const [field, dbField] of Object.entries(fieldMappings)) {
      if (field in body && body[field as keyof UpdateServiceRequest] !== undefined) {
        const placeholder = `:${field}`;
        if (dbField.startsWith('#')) {
          expressionAttributeNames[dbField] = field;
          updateFields.push(`${dbField} = ${placeholder}`);
        } else {
          updateFields.push(`${dbField} = ${placeholder}`);
        }
        expressionAttributeValues[placeholder] = body[field as keyof UpdateServiceRequest];
      }
    }

    // Always update audit fields
    updateFields.push('updated_at = :updatedAt');
    updateFields.push('updated_by = :updatedBy');
    expressionAttributeValues[':updatedAt'] = now;
    expressionAttributeValues[':updatedBy'] = adminEmail;

    const updateExpression = `SET ${updateFields.join(', ')}`;

    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 ? expressionAttributeNames : undefined,
      ExpressionAttributeValues: marshall(expressionAttributeValues),
      ReturnValues: 'ALL_NEW',
    }));

    // Get updated item
    const updatedResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    return ok(unmarshall(updatedResult.Item!));

  } catch (error: any) {
    console.error('Update service error:', error);
    return internalError('Failed to update service.');
  }
};
