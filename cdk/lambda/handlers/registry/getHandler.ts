import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireUserClaims,
  validatePathParam,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const TABLE_HANDLER_INSTALLATIONS = process.env.TABLE_HANDLER_INSTALLATIONS!;
const BUCKET_HANDLERS = process.env.BUCKET_HANDLERS!;

interface HandlerPermission {
  type: string;
  scope: string;
  description: string;
}

interface HandlerDetailResponse {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  icon_url: string | null;
  publisher: string;
  published_at: string;
  size_bytes: number;
  permissions: HandlerPermission[];
  input_schema: Record<string, any>;
  output_schema: Record<string, any>;
  changelog: string | null;
  installed: boolean;
  installed_version: string | null;
  download_url: string;
}

/**
 * GET /registry/handlers/{id}
 *
 * Get detailed information about a specific handler.
 * Returns handler metadata, permissions, schemas, and a pre-signed download URL.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate member authentication
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    // Get handler ID from path
    const handlerId = event.pathParameters?.id;
    if (!handlerId) {
      return badRequest('Handler ID is required.');
    }

    try {
      validatePathParam(handlerId, 'Handler ID');
    } catch (e: any) {
      return badRequest(e.message);
    }

    // Get handler from registry
    const handlerResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: handlerId }),
    }));

    if (!handlerResult.Item) {
      return notFound('Handler not found.');
    }

    const handlerData = unmarshall(handlerResult.Item);

    // Check if handler is active
    if (handlerData.status !== 'active') {
      return notFound('Handler not found.');
    }

    // Check if user has this handler installed
    const installationResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLER_INSTALLATIONS,
      Key: marshall({
        user_guid: userGuid,
        handler_id: handlerId,
      }),
    }));

    const installation = installationResult.Item ? unmarshall(installationResult.Item) : null;

    // Generate pre-signed URL for handler download
    const s3Key = `handlers/${handlerId}/${handlerData.current_version}/handler.wasm`;
    const downloadUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: BUCKET_HANDLERS,
        Key: s3Key,
      }),
      { expiresIn: 3600 } // 1 hour
    );

    const response: HandlerDetailResponse = {
      id: handlerData.handler_id,
      name: handlerData.name,
      description: handlerData.description,
      version: handlerData.current_version,
      category: handlerData.category,
      icon_url: handlerData.icon_url || null,
      publisher: handlerData.publisher,
      published_at: handlerData.published_at,
      size_bytes: handlerData.size_bytes || 0,
      permissions: handlerData.permissions || [],
      input_schema: handlerData.input_schema || {},
      output_schema: handlerData.output_schema || {},
      changelog: handlerData.changelog || null,
      installed: !!installation,
      installed_version: installation?.installed_version || null,
      download_url: downloadUrl,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Get handler error:', error);
    return internalError('Failed to get handler details.');
  }
};
