import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall, marshall } from "@aws-sdk/util-dynamodb";
import { ok, badRequest, internalError, forbidden, requireAdminGroup, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail, putAudit } from "../../common/util";

const ddb = new DynamoDBClient({});
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

// Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20; // SECURITY: Reduced from 50 for better performance

/**
 * Get audit log entries for a specific email
 * GET /admin/audit?email=user@example.com
 *
 * Uses the email-timestamp-index GSI to query audit entries.
 * Note: Only entries with createdAtTimestamp field will appear (new entries).
 *
 * SECURITY: Restricted to admin_type='admin' only. Rate limited to 30 req/min.
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // SECURITY: Restrict to full admins only (admin_type='admin')
  const adminType = (event.requestContext as any)?.authorizer?.jwt?.claims?.['custom:admin_type'];
  if (adminType !== 'admin') {
    await putAudit({
      type: 'unauthorized_audit_log_access_attempt',
      admin_type: adminType,
      path: event.rawPath
    });
    return forbidden('Insufficient privileges to access audit logs', requestOrigin);
  }

  // Rate limiting: 30 requests per admin per minute
  const callerEmail = getAdminEmail(event);
  const callerHash = hashIdentifier(callerEmail);
  const isAllowed = await checkRateLimit(callerHash, 'audit_log_query', 30, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many audit log requests. Please try again later.", requestOrigin);
  }

  const email = event.queryStringParameters?.email;
  if (!email) {
    return badRequest('Email parameter is required', requestOrigin);
  }

  // Parse limit parameter with security bounds
  const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
  const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);

  try {
    // Query audit table using actor-email-index GSI (for admin activity)
    // This finds all audit entries where this admin performed the action
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_AUDIT,
      IndexName: 'actor-email-index',
      KeyConditionExpression: 'actor_email = :email',
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
