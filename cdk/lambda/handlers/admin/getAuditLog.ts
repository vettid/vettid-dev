import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall, marshall } from "@aws-sdk/util-dynamodb";
import { ok, badRequest, internalError, requireAdminGroup } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

// Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

/**
 * Get audit log entries for a specific email
 * GET /admin/audit?email=user@example.com
 *
 * Uses the email-timestamp-index GSI to query audit entries.
 * Note: Only entries with createdAtTimestamp field will appear (new entries).
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  const email = event.queryStringParameters?.email;
  if (!email) {
    return badRequest('Email parameter is required', requestOrigin);
  }

  // Parse limit parameter with security bounds
  const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
  const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);

  try {
    // Query audit table using email-timestamp-index GSI
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_AUDIT,
      IndexName: 'email-timestamp-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: marshall({
        ':email': email,
      }),
      ScanIndexForward: false, // Most recent first
      Limit: limit,
    }));

    const items = (result.Items || []).map((item) => unmarshall(item));

    return ok(items, requestOrigin);
  } catch (error) {
    console.error('Error fetching audit log:', error);
    return internalError('Failed to fetch audit log', requestOrigin);
  }
};
