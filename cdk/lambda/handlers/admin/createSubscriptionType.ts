import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';
import { randomUUID } from 'crypto';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTION_TYPES = process.env.TABLE_SUBSCRIPTION_TYPES!;

/**
 * Create a new subscription type
 * POST /admin/subscription-types
 * Body: { name, description, term_value, term_unit, currency, price, is_one_time_offer }
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
    const { name, description, term_value, term_unit, currency, price, is_one_time_offer, enable_immediately } = body;

    if (!name || !description || !term_value || !term_unit || !currency || price === undefined || price === null) {
      return badRequest('Missing required fields: name, description, term_value, term_unit, currency, price');
    }

    // Validate term_unit
    const validTermUnits = ['days', 'months', 'years'];
    if (!validTermUnits.includes(term_unit)) {
      return badRequest('Invalid term_unit. Must be one of: days, months, years');
    }

    // Validate term_value
    if (typeof term_value !== 'number' || term_value < 1) {
      return badRequest('term_value must be a positive number');
    }

    // Validate price
    if (typeof price !== 'number' || price < 0) {
      return badRequest('price must be a non-negative number');
    }

    // Create subscription type record
    const subscriptionTypeId = randomUUID();
    const now = new Date().toISOString();

    const subscriptionType = {
      subscription_type_id: subscriptionTypeId,
      name: name,
      description: description,
      term_value: term_value,
      term_unit: term_unit,
      currency: currency,
      price: price,
      is_one_time_offer: is_one_time_offer || false,
      is_enabled: enable_immediately === true, // Enable if checkbox was checked
      created_by: email,
      created_at: now,
      updated_at: now,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SUBSCRIPTION_TYPES,
      Item: marshall(subscriptionType),
    }));

    // Log to audit
    await putAudit({
      type: 'subscription_type_created',
      email: email,
      subscription_type_id: subscriptionTypeId,
      name: name,
      term: `${term_value} ${term_unit}`,
      price: `${currency} ${price}`,
    }, requestId);

    return ok({
      message: 'Subscription type created successfully',
      subscription_type: {
        subscription_type_id: subscriptionTypeId,
      },
    });
  } catch (error: any) {
    console.error('Error creating subscription type:', error);
    return internalError(error.message || 'Failed to create subscription type');
  }
};
