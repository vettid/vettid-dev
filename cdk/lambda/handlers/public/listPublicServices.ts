import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;

/**
 * Public service information for mobile app display
 */
interface PublicService {
  service_id: string;
  name: string;
  description: string;
  service_type: string;
  logo_url?: string;
  website_url: string;
  connect_url?: string;
  featured: boolean;
}

/**
 * GET /services
 *
 * Public endpoint to list active supported services.
 * No authentication required - designed for mobile app consumption.
 *
 * Returns only active services with fields needed for display.
 * Sorted by featured (first), then sort_order, then name.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Query only active services using GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':status': { S: 'active' } },
    }));

    const items = (result.Items || []).map(item => unmarshall(item));

    // Sort: featured first, then by sort_order, then by name
    items.sort((a, b) => {
      // Featured services first
      if (a.featured && !b.featured) return -1;
      if (!a.featured && b.featured) return 1;

      // Then by sort_order
      const orderDiff = (a.sort_order ?? 100) - (b.sort_order ?? 100);
      if (orderDiff !== 0) return orderDiff;

      // Then alphabetically by name
      return (a.name || '').localeCompare(b.name || '');
    });

    // Map to public-facing fields only
    const services: PublicService[] = items.map(item => ({
      service_id: item.service_id,
      name: item.name,
      description: item.description,
      service_type: item.service_type,
      logo_url: item.logo_url || undefined,
      website_url: item.website_url,
      connect_url: item.connect_url || undefined,
      featured: item.featured === true,
    }));

    return ok({
      services,
      count: services.length,
    }, origin);

  } catch (error: any) {
    console.error('List public services error:', error);
    return internalError('Failed to list services.', origin);
  }
};
