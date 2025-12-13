import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  internalError,
  requireAdminGroup,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;

/**
 * GET /admin/services
 *
 * List all supported services with optional filtering.
 *
 * Query parameters:
 * - status: Filter by status (active, deprecated, coming-soon)
 * - service_type: Filter by service type
 *
 * Requires admin JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate admin authentication
    const adminCheck = requireAdminGroup(event);
    if (adminCheck) return adminCheck;

    const status = event.queryStringParameters?.status;
    const serviceType = event.queryStringParameters?.service_type;

    let items: any[] = [];

    if (status) {
      // Query by status using GSI
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_SUPPORTED_SERVICES,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :status',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':status': { S: status } },
      }));
      items = (result.Items || []).map(item => unmarshall(item));
    } else if (serviceType) {
      // Query by service type using GSI
      const result = await ddb.send(new QueryCommand({
        TableName: TABLE_SUPPORTED_SERVICES,
        IndexName: 'service-type-index',
        KeyConditionExpression: 'service_type = :type',
        ExpressionAttributeValues: { ':type': { S: serviceType } },
      }));
      items = (result.Items || []).map(item => unmarshall(item));
    } else {
      // Scan all services
      const result = await ddb.send(new ScanCommand({
        TableName: TABLE_SUPPORTED_SERVICES,
      }));
      items = (result.Items || []).map(item => unmarshall(item));
    }

    // Sort by sort_order (ascending), then by name
    items.sort((a, b) => {
      const orderDiff = (a.sort_order ?? 100) - (b.sort_order ?? 100);
      if (orderDiff !== 0) return orderDiff;
      return (a.name || '').localeCompare(b.name || '');
    });

    return ok({
      services: items,
      count: items.length,
    });

  } catch (error: any) {
    console.error('List services error:', error);
    return internalError('Failed to list services.');
  }
};
