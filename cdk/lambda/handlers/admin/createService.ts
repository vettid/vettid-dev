import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  created,
  badRequest,
  conflict,
  internalError,
  requireAdminGroup,
  getAdminEmail,
  parseJsonBody,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;

interface CreateServiceRequest {
  service_id: string;
  name: string;
  description: string;
  service_type: string;
  logo_url?: string;
  website_url: string;
  connect_url?: string;
  documentation_url?: string;
  status?: 'active' | 'deprecated' | 'coming-soon';
  required_user_data?: string[];
  featured?: boolean;
  sort_order?: number;
}

/**
 * POST /admin/services
 *
 * Create a new supported service listing.
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
    let body: CreateServiceRequest;
    try {
      body = parseJsonBody<CreateServiceRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    // Validate required fields
    if (!body.service_id || !body.name || !body.description || !body.service_type || !body.website_url) {
      return badRequest('service_id, name, description, service_type, and website_url are required.');
    }

    // Validate service_id format (lowercase alphanumeric with hyphens)
    if (!/^[a-z0-9-]+$/.test(body.service_id)) {
      return badRequest('service_id must be lowercase alphanumeric with hyphens only.');
    }

    // Valid service types
    const validServiceTypes = [
      'banking', 'messaging', 'crypto', 'authentication', 'payments',
      'storage', 'analytics', 'identity', 'social', 'productivity', 'other'
    ];
    if (!validServiceTypes.includes(body.service_type)) {
      return badRequest(`service_type must be one of: ${validServiceTypes.join(', ')}`);
    }

    // Valid statuses
    const validStatuses = ['active', 'deprecated', 'coming-soon'];
    if (body.status && !validStatuses.includes(body.status)) {
      return badRequest(`status must be one of: ${validStatuses.join(', ')}`);
    }

    // Check if service already exists
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Key: marshall({ service_id: body.service_id }),
    }));

    if (existingResult.Item) {
      return conflict(`Service with ID '${body.service_id}' already exists.`);
    }

    const now = new Date().toISOString();

    // Create service entry
    const serviceItem = {
      service_id: body.service_id,
      name: body.name,
      description: body.description,
      service_type: body.service_type,
      logo_url: body.logo_url || null,
      website_url: body.website_url,
      connect_url: body.connect_url || null,
      documentation_url: body.documentation_url || null,
      status: body.status || 'active',
      required_user_data: body.required_user_data || [],
      featured: body.featured || false,
      sort_order: body.sort_order ?? 100,
      connect_count: 0,
      created_at: now,
      created_by: adminEmail,
      updated_at: now,
      updated_by: adminEmail,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      Item: marshall(serviceItem, { removeUndefinedValues: true }),
    }));

    return created(serviceItem);

  } catch (error: any) {
    console.error('Create service error:', error);
    return internalError('Failed to create service.');
  }
};
