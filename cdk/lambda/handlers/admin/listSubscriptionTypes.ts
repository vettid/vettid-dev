import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SUBSCRIPTION_TYPES = process.env.TABLE_SUBSCRIPTION_TYPES!;

/**
 * List all subscription types
 * GET /admin/subscription-types
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Scan all subscription types
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_SUBSCRIPTION_TYPES,
    }));

    if (!result.Items || result.Items.length === 0) {
      return ok({ subscription_types: [] });
    }

    const subscriptionTypes = result.Items.map(item => unmarshall(item));

    // Sort by created_at descending (newest first)
    subscriptionTypes.sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateB - dateA;
    });

    return ok({ subscription_types: subscriptionTypes });
  } catch (error: any) {
    console.error('Error listing subscription types:', error);
    return internalError(error.message || 'Failed to list subscription types');
  }
};
