import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup, sanitizeErrorForClient } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;

// SECURITY: Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20; // SECURITY: Reduced from 50 for better performance

/**
 * List all waitlist entries (admin only)
 * GET /admin/waitlist?limit=50&cursor=xxx
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership (using standardized check)
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // SECURITY: Enforce reasonable limits to prevent abuse
    const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
    const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);
    const cursor = event.queryStringParameters?.cursor;

    // Decode pagination cursor if provided
    let exclusiveStartKey: Record<string, any> | undefined;
    if (cursor) {
      try {
        exclusiveStartKey = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
      } catch {
        // Invalid cursor, ignore
      }
    }

    // Scan waitlist table with pagination
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_WAITLIST,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey
    }));

    if (!result.Items || result.Items.length === 0) {
      return ok({ waitlist: [], count: 0, limit });
    }

    const waitlist = result.Items.map(item => unmarshall(item));

    // Sort by created_at descending (newest first)
    waitlist.sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateB - dateA;
    });

    // Build response with pagination
    const response: any = {
      waitlist,
      count: waitlist.length,
      limit
    };

    // Include next cursor if there are more results
    if (result.LastEvaluatedKey) {
      response.nextCursor = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64');
    }

    return ok(response);
  } catch (error: any) {
    console.error('Error listing waitlist:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to list waitlist'));
  }
};
