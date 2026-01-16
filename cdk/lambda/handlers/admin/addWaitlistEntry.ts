import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import {
  ok,
  badRequest,
  internalError,
  requireAdminGroup,
  sanitizeErrorForClient,
  validateEmail,
  validateName,
  putAudit,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;

type AddWaitlistRequest = {
  email?: string;
  first_name?: string;
  last_name?: string;
};

/**
 * Add a single entry to the waitlist (admin only)
 * POST /admin/waitlist
 *
 * Used by admin batch import feature to add waitlist entries without
 * sending welcome emails or triggering rate limits.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  if (!event.body) {
    return badRequest('Missing request body');
  }

  let payload: AddWaitlistRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON');
  }

  // Validate inputs
  let email: string;
  let firstName: string;
  let lastName: string;

  try {
    email = validateEmail(payload.email || '');
    firstName = validateName(payload.first_name || '', 'First name');
    lastName = validateName(payload.last_name || '', 'Last name');
  } catch (error: any) {
    return badRequest(error.message || 'Invalid input');
  }

  try {
    // Check for duplicate email
    const existingEntries = await ddb.send(
      new QueryCommand({
        TableName: TABLE_WAITLIST,
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: marshall({
          ':email': email,
        }),
        Limit: 1,
      })
    );

    if (existingEntries.Items && existingEntries.Items.length > 0) {
      return badRequest('This email address is already on the waitlist');
    }

    // Create waitlist entry
    const waitlistId = randomUUID();
    const nowIso = new Date().toISOString();

    const waitlistItem = {
      waitlist_id: waitlistId,
      first_name: firstName,
      last_name: lastName,
      email,
      status: 'pending',
      created_at: nowIso,
      added_by: 'admin_import',
    };

    await ddb.send(
      new PutItemCommand({
        TableName: TABLE_WAITLIST,
        Item: marshall(waitlistItem),
      })
    );

    // Audit log
    await putAudit({
      action: 'waitlist_entry_added',
      admin_email: (event.requestContext as any)?.authorizer?.jwt?.claims?.email || 'unknown',
      target_email: email,
      details: { waitlist_id: waitlistId, source: 'admin_import' },
    });

    return ok({
      message: 'Waitlist entry added successfully',
      waitlist_id: waitlistId,
      email,
    });
  } catch (error: any) {
    console.error('Error adding waitlist entry:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to add waitlist entry'));
  }
};
