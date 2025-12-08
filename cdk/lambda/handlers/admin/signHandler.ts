import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, HeadObjectCommand } from '@aws-sdk/client-s3';
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
import { createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_HANDLERS = process.env.TABLE_HANDLERS!;
const BUCKET_HANDLERS = process.env.BUCKET_HANDLERS!;

interface SignHandlerRequest {
  handler_id: string;
  version: string;
}

interface SignHandlerResponse {
  handler_id: string;
  version: string;
  status: 'active';
  signed_at: string;
  signed_by: string;
}

/**
 * POST /admin/registry/handlers/sign
 *
 * Sign and activate a handler version.
 * This marks the handler as verified and available for installation.
 *
 * Requires admin JWT authentication.
 * Requires the WASM package to be uploaded first.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  try {
    // Validate admin authentication
    const adminCheck = requireAdminGroup(event);
    if (adminCheck) return adminCheck;

    const adminEmail = getAdminEmail(event);

    // Parse request body
    let body: SignHandlerRequest;
    try {
      body = parseJsonBody<SignHandlerRequest>(event);
    } catch (e: any) {
      return badRequest(e.message);
    }

    if (!body.handler_id || !body.version) {
      return badRequest('handler_id and version are required.');
    }

    // Get handler from registry
    const handlerResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
    }));

    if (!handlerResult.Item) {
      return notFound('Handler not found.');
    }

    const handlerData = unmarshall(handlerResult.Item);

    // Check if version exists
    if (!handlerData.versions?.includes(body.version)) {
      return notFound(`Version ${body.version} not found for this handler.`);
    }

    // Check if WASM package exists in S3
    const s3Key = `handlers/${body.handler_id}/${body.version}/handler.wasm`;
    try {
      await s3.send(new HeadObjectCommand({
        Bucket: BUCKET_HANDLERS,
        Key: s3Key,
      }));
    } catch (e: any) {
      if (e.name === 'NotFound' || e.$metadata?.httpStatusCode === 404) {
        return badRequest('WASM package has not been uploaded yet.');
      }
      throw e;
    }

    const now = new Date().toISOString();

    // Update handler status to active
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HANDLERS,
      Key: marshall({ handler_id: body.handler_id }),
      UpdateExpression: `
        SET #status = :active,
            signed_at = :now,
            signed_by = :admin,
            updated_at = :now,
            updated_by = :admin
      `,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: marshall({
        ':active': 'active',
        ':now': now,
        ':admin': adminEmail,
      }),
    }));

    const response: SignHandlerResponse = {
      handler_id: body.handler_id,
      version: body.version,
      status: 'active',
      signed_at: now,
      signed_by: adminEmail,
    };

    return ok(response);

  } catch (error: any) {
    console.error('Sign handler error:', error);
    return internalError('Failed to sign handler.');
  }
};
