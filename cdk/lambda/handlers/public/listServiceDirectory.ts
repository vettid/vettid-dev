import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, BatchGetItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError } from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_SUPPORTED_SERVICES = process.env.TABLE_SUPPORTED_SERVICES!;
const TABLE_SERVICE_REGISTRY = process.env.TABLE_SERVICE_REGISTRY!;

/**
 * Public service directory entry
 * Combines supportedServices metadata with serviceRegistry connection status
 */
interface ServiceDirectoryEntry {
  service_id: string;
  name: string;
  description: string;
  service_type: string;
  logo_url?: string;
  website_url: string;
  connect_url?: string;
  documentation_url?: string;
  featured: boolean;
  // Connection capability info
  can_connect: boolean;           // True if service has active NATS credentials
  connection_domain?: string;     // Verified domain for connection
  capabilities?: string[];        // Available capabilities: auth, authz, data, etc.
}

/**
 * GET /services/directory
 *
 * Public endpoint listing services with their connection capabilities.
 * Joins supportedServices (metadata) with serviceRegistry (NATS credentials).
 *
 * This tells mobile apps which services can actually establish vault connections
 * vs services that are just listed for informational purposes.
 *
 * No authentication required.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const origin = event.headers?.origin;

  try {
    // Query active supported services
    const servicesResult = await ddb.send(new QueryCommand({
      TableName: TABLE_SUPPORTED_SERVICES,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':status': { S: 'active' } },
    }));

    const supportedServices = (servicesResult.Items || []).map(item => unmarshall(item));

    if (supportedServices.length === 0) {
      return ok({
        services: [],
        count: 0,
        connectable_count: 0,
      }, origin);
    }

    // Query active service registry entries
    const registryResult = await ddb.send(new QueryCommand({
      TableName: TABLE_SERVICE_REGISTRY,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':status': { S: 'active' } },
    }));

    // Build lookup map of active registry entries
    const registryMap = new Map<string, any>();
    for (const item of registryResult.Items || []) {
      const registry = unmarshall(item);
      registryMap.set(registry.service_id, registry);
    }

    // Combine data
    const directory: ServiceDirectoryEntry[] = supportedServices.map(service => {
      const registry = registryMap.get(service.service_id);

      const entry: ServiceDirectoryEntry = {
        service_id: service.service_id,
        name: service.name,
        description: service.description,
        service_type: service.service_type,
        logo_url: service.logo_url || undefined,
        website_url: service.website_url,
        connect_url: service.connect_url || undefined,
        documentation_url: service.documentation_url || undefined,
        featured: service.featured === true,
        can_connect: !!registry,
      };

      if (registry) {
        entry.connection_domain = registry.domain;
        // Default capabilities for connected services
        // In the future, this could be customized per-service
        entry.capabilities = ['auth', 'authz', 'notify'];
      }

      return entry;
    });

    // Sort: connectable first, then featured, then by name
    directory.sort((a, b) => {
      // Connectable services first
      if (a.can_connect && !b.can_connect) return -1;
      if (!a.can_connect && b.can_connect) return 1;

      // Then featured
      if (a.featured && !b.featured) return -1;
      if (!a.featured && b.featured) return 1;

      // Then alphabetically
      return a.name.localeCompare(b.name);
    });

    const connectableCount = directory.filter(s => s.can_connect).length;

    return ok({
      services: directory,
      count: directory.length,
      connectable_count: connectableCount,
    }, origin);

  } catch (error: any) {
    console.error('List service directory error:', error);
    return internalError('Failed to list service directory.', origin);
  }
};
