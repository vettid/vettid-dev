import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;

/**
 * Extend subscription(s) by specified days
 * POST /admin/subscriptions/bulk-extend
 * Body: { user_guids: string[], days: number }
 * OR
 * POST /admin/subscriptions/{user_guid}/extend
 * Body: { days: number }
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    // Get admin email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const email = claims?.email;

    if (!email) {
      return badRequest('Email not found in token');
    }

    // Parse request body
    const body = parseJsonBody(event);

    // SECURITY: Validate and constrain days parameter
    const rawDays = Number(body.days) || 7;
    if (!Number.isInteger(rawDays) || rawDays < 1 || rawDays > 3650) {
      return badRequest('Days must be an integer between 1 and 3650 (10 years max)');
    }
    const days = rawDays;

    // Determine if single or bulk operation
    let userGuids: string[] = [];
    if (body.user_guids && Array.isArray(body.user_guids)) {
      // Bulk operation
      userGuids = body.user_guids;
    } else {
      // Single operation from path parameter
      const userGuid = event.pathParameters?.user_guid;
      if (!userGuid) {
        return badRequest('User GUID is required');
      }
      userGuids = [userGuid];
    }

    if (userGuids.length === 0) {
      return badRequest('At least one user GUID is required');
    }

    const now = new Date();
    const results = [];

    // Process each subscription
    for (const userGuid of userGuids) {
      try {
        // Get current subscription
        const getResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_SUBSCRIPTIONS,
          Key: marshall({ user_guid: userGuid }),
        }));

        if (!getResult.Item) {
          results.push({ user_guid: userGuid, success: false, error: 'Subscription not found' });
          continue;
        }

        const subscription = unmarshall(getResult.Item);
        const currentExpires = new Date(subscription.expires_at);

        // If already expired, extend from now, otherwise extend from current expiry
        const baseDate = currentExpires < now ? now : currentExpires;
        const newExpires = new Date(baseDate.getTime() + (days * 24 * 60 * 60 * 1000));

        // Update subscription
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_SUBSCRIPTIONS,
          Key: marshall({ user_guid: userGuid }),
          UpdateExpression: 'SET expires_at = :expires_at, #status = :status, extended_at = :extended_at, extended_by = :extended_by',
          ExpressionAttributeNames: {
            '#status': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':expires_at': newExpires.toISOString(),
            ':status': 'active',
            ':extended_at': now.toISOString(),
            ':extended_by': email,
          }),
        }));

        // Log to audit
        await putAudit({
          type: 'subscription_extended',
          email: email,
          user_guid: userGuid,
          days_added: days,
          new_expires_at: newExpires.toISOString(),
        }, requestId);

        results.push({ user_guid: userGuid, success: true, new_expires_at: newExpires.toISOString() });
      } catch (error: any) {
        console.error(`Error extending subscription for ${userGuid}:`, error);
        results.push({ user_guid: userGuid, success: false, error: error.message });
      }
    }

    const successCount = results.filter(r => r.success).length;

    return ok({
      message: `Extended ${successCount} of ${userGuids.length} subscription(s)`,
      results,
    });
  } catch (error: any) {
    console.error('Error extending subscriptions:', error);
    // SECURITY: Don't expose error.message
    return internalError('Failed to extend subscriptions');
  }
};
