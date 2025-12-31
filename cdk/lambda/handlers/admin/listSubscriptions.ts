import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, BatchGetItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

// SECURITY: Maximum items to return per request
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20; // SECURITY: Reduced from 50 for better performance

/**
 * List subscriptions with optional status filter
 * GET /admin/subscriptions?status=active|cancelled|expired&limit=50&cursor=xxx
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    const statusFilter = event.queryStringParameters?.status;
    const now = new Date();

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

    // Fetch subscriptions with pagination
    const subscriptionsResult = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey
    }));

    if (!subscriptionsResult.Items) {
      return ok({ subscriptions: [], count: 0, limit });
    }

    let subscriptions = subscriptionsResult.Items.map(item => unmarshall(item));

    // OPTIMIZED: Get unique user_guids first, then fetch only needed registrations
    const uniqueUserGuids = [...new Set(subscriptions.map(s => s.user_guid).filter(Boolean))];

    // Fetch only registrations for subscribed users
    const registrationsMap = new Map();
    if (uniqueUserGuids.length > 0) {
      const registrationsResult = await ddb.send(new ScanCommand({
        TableName: TABLE_REGISTRATIONS,
        FilterExpression: `user_guid IN (${uniqueUserGuids.map((_, i) => `:guid${i}`).join(', ')})`,
        ExpressionAttributeValues: marshall(
          Object.fromEntries(uniqueUserGuids.map((guid, i) => [`:guid${i}`, guid]))
        ),
      }));

      if (registrationsResult.Items) {
        registrationsResult.Items.forEach(item => {
          const reg = unmarshall(item);
          registrationsMap.set(reg.user_guid, reg);
        });
      }
    }

    // Collect all email addresses for batch email preference lookup
    const emails = subscriptions
      .map(s => {
        const registration = registrationsMap.get(s.user_guid);
        return registration?.email || s.email || '';
      })
      .filter(Boolean);

    // OPTIMIZED: Batch get email preferences (fixes N+1 query)
    const emailPrefsMap = new Map();
    if (emails.length > 0) {
      // DynamoDB BatchGetItem supports up to 100 items at once
      const batches = [];
      for (let i = 0; i < emails.length; i += 100) {
        batches.push(emails.slice(i, i + 100));
      }

      for (const batch of batches) {
        try {
          const batchResult = await ddb.send(new BatchGetItemCommand({
            RequestItems: {
              [TABLE_AUDIT]: {
                Keys: batch.map(email => marshall({ id: `email_pref_${email}` })),
              },
            },
          }));

          if (batchResult.Responses?.[TABLE_AUDIT]) {
            batchResult.Responses[TABLE_AUDIT].forEach(item => {
              const pref = unmarshall(item);
              // Extract email from id (format: email_pref_EMAIL)
              const email = pref.id.replace('email_pref_', '');
              emailPrefsMap.set(email, pref);
            });
          }
        } catch (error) {
          console.error('Error batch fetching email preferences:', error);
        }
      }
    }

    // Enrich subscriptions with user data (now all data is pre-fetched)
    const enrichedSubscriptions = subscriptions.map((sub) => {
      const registration = registrationsMap.get(sub.user_guid);
      const expiresDate = new Date(sub.expires_at);
      const email = registration?.email || sub.email || '';

      // Calculate dynamic status if not cancelled
      let status = sub.status;
      if (status !== 'cancelled') {
        if (now >= expiresDate) {
          status = 'expired';
        } else {
          status = 'active';
        }
      }

      // Get PIN status from registration
      const pinEnabled = registration?.pin_enabled === true;

      // Get email preferences from pre-fetched map
      const emailPref = emailPrefsMap.get(email);
      const systemEmailsEnabled = emailPref?.system_emails_enabled === true;

      return {
        ...sub,
        status,
        plan: sub.subscription_type_name || sub.plan || 'Unknown',
        first_name: registration?.first_name || '',
        last_name: registration?.last_name || '',
        email,
        pin_enabled: pinEnabled,
        system_emails_enabled: systemEmailsEnabled,
      };
    });

    subscriptions = enrichedSubscriptions;

    // Filter by status if requested
    if (statusFilter) {
      subscriptions = subscriptions.filter(s => s.status === statusFilter);
    }

    // Build response with pagination
    const response: any = {
      subscriptions,
      count: subscriptions.length,
      limit
    };

    // Include next cursor if there are more results
    if (subscriptionsResult.LastEvaluatedKey) {
      response.nextCursor = Buffer.from(JSON.stringify(subscriptionsResult.LastEvaluatedKey)).toString('base64');
    }

    return ok(response);
  } catch (error: any) {
    console.error('Error listing subscriptions:', error);
    return internalError(error.message || 'Failed to list subscriptions');
  }
};
