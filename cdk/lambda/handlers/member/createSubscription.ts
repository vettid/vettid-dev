import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  forbidden
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTIONS = process.env.TABLE_SUBSCRIPTIONS!;
const TABLE_SUBSCRIPTION_TYPES = process.env.TABLE_SUBSCRIPTION_TYPES!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

/**
 * Create or update a subscription for the authenticated user
 * POST /subscriptions
 * Body: { subscription_type_id: string }
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Get user GUID from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const userGuid = claims?.['custom:user_guid'];
    const email = claims?.email;

    if (!userGuid) {
      return badRequest('User GUID not found in token');
    }

    if (!email) {
      return badRequest('Email not found in token');
    }

    // Validate user has accepted membership terms
    // Note: Remove Limit when using FilterExpression - Limit applies BEFORE filtering
    const registrationsResult = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'email = :email',
      ExpressionAttributeValues: marshall({
        ':email': email,
      }),
    }));

    if (!registrationsResult.Items || registrationsResult.Items.length === 0) {
      return forbidden('No registration found. Please contact support.');
    }

    const registration = unmarshall(registrationsResult.Items[0]);

    // Only allow subscriptions for approved members
    if (registration.membership_status !== 'approved') {
      return forbidden('You must accept the membership terms before creating a subscription.');
    }

    // Parse request body
    const body = parseJsonBody(event);
    const { subscription_type_id } = body;

    if (!subscription_type_id) {
      return badRequest('Subscription type ID is required');
    }

    // Fetch subscription type from database
    const subscriptionTypeResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_SUBSCRIPTION_TYPES,
      Key: marshall({ subscription_type_id }),
    }));

    if (!subscriptionTypeResult.Item) {
      return badRequest('Invalid subscription type');
    }

    const subscriptionType = unmarshall(subscriptionTypeResult.Item);

    // Check if subscription type is enabled
    if (!subscriptionType.is_enabled) {
      return badRequest('This subscription type is not currently available');
    }

    // Calculate expiration date based on subscription type
    const now = new Date();
    const expiresAt = new Date(now);

    // Add the term to the current date
    switch (subscriptionType.term_unit) {
      case 'day':
      case 'days':
        expiresAt.setDate(expiresAt.getDate() + subscriptionType.term_value);
        break;
      case 'month':
      case 'months':
        expiresAt.setMonth(expiresAt.getMonth() + subscriptionType.term_value);
        break;
      case 'year':
      case 'years':
        expiresAt.setFullYear(expiresAt.getFullYear() + subscriptionType.term_value);
        break;
      default:
        return badRequest('Invalid term unit in subscription type');
    }

    // Create subscription record
    const subscription = {
      user_guid: userGuid,
      email: email,
      subscription_type_id: subscription_type_id,
      subscription_type_name: subscriptionType.name,
      status: 'active',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      amount: subscriptionType.price || 0,
      currency: subscriptionType.currency || 'USD',
      auto_renew: false, // Placeholder for future payment integration
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_SUBSCRIPTIONS,
      Item: marshall(subscription),
    }));

    // Log to audit
    await putAudit({
      action: 'subscription_created',
      user_guid: userGuid,
      email: email,
      subscription_type_id: subscription_type_id,
      subscription_type_name: subscriptionType.name,
      expires_at: expiresAt.toISOString(),
    }, requestId);

    return ok({
      message: `Subscription activated successfully`,
      subscription: {
        subscription_type_id: subscription_type_id,
        subscription_type_name: subscriptionType.name,
        status: 'active',
        expires_at: expiresAt.toISOString(),
      },
    });
  } catch (error: any) {
    console.error('Error creating subscription:', error);
    return internalError(error.message || 'Failed to create subscription');
  }
};
