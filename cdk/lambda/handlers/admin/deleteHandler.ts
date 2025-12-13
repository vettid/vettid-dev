import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, DeleteObjectsCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
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
const s3 = new S3Client({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const BUCKET_HANDLERS = process.env.BUCKET_HANDLERS!;

interface DeleteHandlerRequest {
  handler_id: string;
}

interface DeleteHandlerResponse {
  handler_id: string;
  deleted: true;
  deleted_at: string;
  deleted_by: string;
  versions_deleted: number;
}

/**
 * POST /admin/registry/handlers/delete
 *
 * Permanently delete a handler and all its versions from the registry.
 * This removes the handler from DynamoDB and deletes all WASM packages from S3.
 *
 * WARNING: This action is irreversible.
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
    let body: DeleteHandlerRequest;
    try {
      body = parseJsonBody<DeleteHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.handler_id) {
      return badRequest('handler_id is required.');
    }

    // Get handler from registry to verify it exists
    const handlerResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    if (!handlerResult.Item) {
      return notFound('Handler not found.');
    }

    const handlerData = unmarshall(handlerResult.Item);
    const versions = handlerData.versions || [];

    // Delete all versions from S3
    let versionsDeleted = 0;
    if (versions.length > 0) {
      // List all objects under the handler's S3 prefix
      const s3Prefix = `handlers/${body.handler_id}/`;
      const listResult = await s3.send(new ListObjectsV2Command({
        Bucket: BUCKET_HANDLERS,
        Prefix: s3Prefix,
      }));

      if (listResult.Contents && listResult.Contents.length > 0) {
        const objectsToDelete = listResult.Contents.map(obj => ({ Key: obj.Key! }));

        await s3.send(new DeleteObjectsCommand({
          Bucket: BUCKET_HANDLERS,
          Delete: {
            Objects: objectsToDelete,
            Quiet: true,
          },
        }));

        versionsDeleted = objectsToDelete.length;
      }
    }

    // Delete handler from DynamoDB
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    const now = new Date().toISOString();

    const response: DeleteHandlerResponse = {
      handler_id: body.handler_id,
      deleted: true,
      deleted_at: now,
      deleted_by: adminEmail,
      versions_deleted: versionsDeleted,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Delete handler error:', error);
    return internalError('Failed to delete handler.');
  }
};
