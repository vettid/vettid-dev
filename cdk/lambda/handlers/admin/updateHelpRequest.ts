import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  requireAdminGroup,
  validateOrigin,
  validatePathParam,
  validateStringInput,
  sanitizeErrorForClient,
  getAdminEmail,
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_HELP_REQUESTS = process.env.TABLE_HELP_REQUESTS!;

// Valid status transitions
const VALID_STATUSES = ['new', 'contacted', 'in_progress', 'archived'] as const;
type Status = typeof VALID_STATUSES[number];

type UpdateRequest = {
  status?: string;
  admin_notes?: string;
};

/**
 * Update a help request (admin only)
 * PATCH /admin/help-requests/{request_id}
 *
 * Body:
 * - status: new | contacted | in_progress | archived
 * - admin_notes: string (optional notes for tracking)
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Validate request_id path parameter
  let requestId: string;
  try {
    requestId = validatePathParam(event.pathParameters?.request_id, 'request_id');
  } catch (error: any) {
    return badRequest(error.message);
  }

  if (!event.body) {
    return badRequest('Missing request body');
  }

  let payload: UpdateRequest;
  try {
    payload = JSON.parse(event.body);
  } catch {
    return badRequest('Request body must be valid JSON');
  }

  // Must have at least one field to update
  if (!payload.status && payload.admin_notes === undefined) {
    return badRequest('Must provide status or admin_notes to update');
  }

  // Validate status if provided
  if (payload.status && !VALID_STATUSES.includes(payload.status as Status)) {
    return badRequest(`Invalid status. Valid values: ${VALID_STATUSES.join(', ')}`);
  }

  // Validate admin_notes if provided (allow empty string to clear notes)
  let adminNotes: string | null = null;
  if (payload.admin_notes !== undefined) {
    if (payload.admin_notes === '' || payload.admin_notes === null) {
      adminNotes = null;
    } else {
      try {
        adminNotes = validateStringInput(payload.admin_notes, 'admin_notes', 1, 2000);
      } catch (error: any) {
        return badRequest(error.message);
      }
    }
  }

  try {
    // First, verify the help request exists
    const existing = await ddb.send(new GetItemCommand({
      TableName: TABLE_HELP_REQUESTS,
      Key: marshall({ request_id: requestId }),
    }));

    if (!existing.Item) {
      return notFound('Help request not found');
    }

    // Build update expression
    const updateParts: string[] = [];
    const expressionValues: Record<string, any> = {};
    const expressionNames: Record<string, string> = {};

    if (payload.status) {
      updateParts.push('#status = :status');
      expressionNames['#status'] = 'status';
      expressionValues[':status'] = payload.status;
    }

    if (payload.admin_notes !== undefined) {
      updateParts.push('admin_notes = :notes');
      expressionValues[':notes'] = adminNotes;
    }

    // Always update updated_at and updated_by
    updateParts.push('updated_at = :updated_at');
    updateParts.push('updated_by = :updated_by');
    expressionValues[':updated_at'] = new Date().toISOString();
    expressionValues[':updated_by'] = getAdminEmail(event);

    // Execute update
    const result = await ddb.send(new UpdateItemCommand({
      TableName: TABLE_HELP_REQUESTS,
      Key: marshall({ request_id: requestId }),
      UpdateExpression: `SET ${updateParts.join(', ')}`,
      ExpressionAttributeNames: Object.keys(expressionNames).length > 0 ? expressionNames : undefined,
      ExpressionAttributeValues: marshall(expressionValues),
      ReturnValues: 'ALL_NEW',
    }));

    const updated = result.Attributes ? unmarshall(result.Attributes) : null;

    return ok({
      message: 'Help request updated successfully',
      help_request: updated,
    });
  } catch (error: any) {
    console.error('Error updating help request:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to update help request'));
  }
};
