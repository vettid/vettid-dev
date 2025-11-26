import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';
import { createHash } from 'crypto';

/**
 * Hash identifier for safe logging (no PII in logs)
 */
function hashForLog(value: string): string {
  return createHash('sha256').update(value.toLowerCase().trim()).digest('hex').substring(0, 12);
}

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

/**
 * List subscriptions with optional status filter
 * GET /admin/subscriptions?status=active|cancelled|expired
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    const statusFilter = event.queryStringParameters?.status;
    const now = new Date();

    // Fetch all subscriptions
    const subscriptionsResult = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTIONS,
    }));

    if (!subscriptionsResult.Items) {
      return ok({ subscriptions: [] });
    }

    let subscriptions = subscriptionsResult.Items.map(item => unmarshall(item));

    // Fetch all registrations to join user data
    const registrationsResult = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
    }));

    const registrationsMap = new Map();
    if (registrationsResult.Items) {
      registrationsResult.Items.forEach(item => {
        const reg = unmarshall(item);
        registrationsMap.set(reg.user_guid, reg);
      });
    }

    // Enrich subscriptions with user data and calculate dynamic status
    const enrichedSubscriptions = await Promise.all(subscriptions.map(async (sub) => {
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

      // Get email preferences from audit table
      let systemEmailsEnabled = false;
      if (email) {
        try {
          const emailPrefResult = await ddb.send(new GetItemCommand({
            TableName: TABLE_AUDIT,
            Key: marshall({ id: `email_pref_${email}` }),
          }));

          if (emailPrefResult.Item) {
            const emailPref = unmarshall(emailPrefResult.Item);
            systemEmailsEnabled = emailPref.system_emails_enabled === true;
          }
        } catch (error) {
          console.error(`Error fetching email preferences for user ${hashForLog(email)}:`, error);
        }
      }

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
    }));

    subscriptions = enrichedSubscriptions;

    // Filter by status if requested
    if (statusFilter) {
      subscriptions = subscriptions.filter(s => s.status === statusFilter);
    }

    return ok({ subscriptions });
  } catch (error: any) {
    console.error('Error listing subscriptions:', error);
    return internalError(error.message || 'Failed to list subscriptions');
  }
};
