import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  created,
  badRequest,
  conflict,
  internalError,
  requireAdminGroup,
  getAdminEmail,
  parseJsonBody,
  generateSecureId,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const BUCKET_HANDLERS = process.env.BUCKET_HANDLERS!;

interface UploadHandlerRequest {
  handler_id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  publisher: string;
  icon_url?: string;
  permissions: Array<{
    type: string;
    scope: string;
    description: string;
  }>;
  input_schema: Record<string, any>;
  output_schema: Record<string, any>;
  changelog?: string;
  size_bytes: number;
}

interface UploadHandlerResponse {
  handler_id: string;
  version: string;
  upload_url: string;
  upload_expires_at: string;
}

/**
 * POST /admin/registry/handlers
 *
 * Create a new handler entry or add a new version.
 * Returns a pre-signed URL for uploading the WASM package.
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
    let body: UploadHandlerRequest;
    try {
      body = parseJsonBody<UploadHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    // Validate required fields
    if (!body.handler_id || !body.name || !body.version || !body.category || !body.publisher) {
      return badRequest('handler_id, name, version, category, and publisher are required.');
    }

    // Validate handler_id format (alphanumeric with hyphens)
    if (!/^[a-z0-9-]+$/.test(body.handler_id)) {
      return badRequest('handler_id must be lowercase alphanumeric with hyphens only.');
    }

    // Validate version format (semver-like)
    if (!/^\d+\.\d+\.\d+$/.test(body.version)) {
      return badRequest('version must be in format X.Y.Z (e.g., 1.0.0).');
    }

    // Valid categories
    const validCategories = ['messaging', 'social', 'productivity', 'utilities', 'finance', 'health', 'profile', 'connections', 'other'];
    if (!validCategories.includes(body.category)) {
      return badRequest(`category must be one of: ${validCategories.join(', ')}`);
    }

    const now = new Date().toISOString();

    // Check if handler already exists
    const existingResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    if (existingResult.Item) {
      // Handler exists - add new version
      const existing = unmarshall(existingResult.Item);

      // Check if version already exists
      if (existing.versions?.includes(body.version)) {
        return conflict(`Version ${body.version} already exists for this handler.`);
      }

      // Update handler with new version
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_HANDLERS,
        Key: marshall({ handler_id: body.handler_id }),
        UpdateExpression: `
          SET current_version = :version,
              versions = list_append(if_not_exists(versions, :empty), :newVersion),
              #name = :name,
              description = :description,
              category = :category,
              publisher = :publisher,
              icon_url = :iconUrl,
              permissions = :permissions,
              input_schema = :inputSchema,
              output_schema = :outputSchema,
              changelog = :changelog,
              size_bytes = :sizeBytes,
              updated_at = :now,
              updated_by = :admin
        `,
        ExpressionAttributeNames: { '#name': 'name' },
        ExpressionAttributeValues: marshall({
          ':version': body.version,
          ':empty': [],
          ':newVersion': [body.version],
          ':name': body.name,
          ':description': body.description,
          ':category': body.category,
          ':publisher': body.publisher,
          ':iconUrl': body.icon_url || null,
          ':permissions': body.permissions || [],
          ':inputSchema': body.input_schema || {},
          ':outputSchema': body.output_schema || {},
          ':changelog': body.changelog || null,
          ':sizeBytes': body.size_bytes || 0,
          ':now': now,
          ':admin': adminEmail,
        }),
      }));
    } else {
      // Create new handler
      await ddb.send(new PutItemCommand({
        TableName: TABLE_HANDLERS,
        Item: marshall({
          handler_id: body.handler_id,
          name: body.name,
          description: body.description,
          current_version: body.version,
          versions: [body.version],
          category: body.category,
          publisher: body.publisher,
          icon_url: body.icon_url || null,
          permissions: body.permissions || [],
          input_schema: body.input_schema || {},
          output_schema: body.output_schema || {},
          changelog: body.changelog || null,
          size_bytes: body.size_bytes || 0,
          status: 'pending', // Pending until signed
          install_count: 0,
          published_at: now,
          created_at: now,
          created_by: adminEmail,
          updated_at: now,
          updated_by: adminEmail,
        }),
      }));
    }

    // Generate pre-signed URL for upload
    const s3Key = `handlers/${body.handler_id}/${body.version}/handler.wasm`;
    const expiresIn = 3600; // 1 hour
    const uploadUrl = await getSignedUrl(
      s3,
      new PutObjectCommand({
        Bucket: BUCKET_HANDLERS,
        Key: s3Key,
        ContentType: 'application/wasm',
      }),
      { expiresIn }
    );

    const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();

    const response: UploadHandlerResponse = {
      handler_id: body.handler_id,
      version: body.version,
      upload_url: uploadUrl,
      upload_expires_at: expiresAt,
    };

    return created(response);

  } catch (error: any) {
    console.error('Upload handler error:', error);
    return internalError('Failed to create handler entry.');
  }
};
