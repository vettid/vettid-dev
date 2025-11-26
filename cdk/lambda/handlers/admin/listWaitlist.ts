import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, forbidden, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_WAITLIST = process.env.TABLE_WAITLIST!;

/**
 * List all waitlist entries (admin only)
 * GET /admin/waitlist
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership (using standardized check)
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Scan waitlist table
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_WAITLIST,
    }));

    if (!result.Items || result.Items.length === 0) {
      return ok({ waitlist: [] });
    }

    const waitlist = result.Items.map(item => unmarshall(item));

    // Sort by created_at descending (newest first)
    waitlist.sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateB - dateA;
    });

    return ok({ waitlist });
  } catch (error: any) {
    console.error('Error listing waitlist:', error);
    return internalError(error.message || 'Failed to list waitlist');
  }
};
