import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  putAudit,
  requireAdminGroup,
  sanitizeErrorForClient
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTION_TYPES = process.env.TABLE_SUBSCRIPTION_TYPES!;

/**
 * Enable a subscription type
 * POST /admin/subscription-types/{id}/enable
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

    const subscriptionTypeId = event.pathParameters?.id;

    if (!subscriptionTypeId) {
      return badRequest('Subscription type ID is required');
    }

    const now = new Date().toISOString();

    // Update the subscription type to enabled
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_SUBSCRIPTION_TYPES,
      Key: marshall({ subscription_type_id: subscriptionTypeId }),
      UpdateExpression: 'SET is_enabled = :enabled, updated_at = :updated_at',
      ExpressionAttributeValues: marshall({
        ':enabled': true,
        ':updated_at': now,
      }),
    }));

    // Log to audit
    await putAudit({
      type: 'subscription_type_enabled',
      email: email,
      subscription_type_id: subscriptionTypeId,
    }, requestId);

    return ok({ message: 'Subscription type enabled successfully' });
  } catch (error: any) {
    console.error('Error enabling subscription type:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to enable subscription type'));
  }
};
