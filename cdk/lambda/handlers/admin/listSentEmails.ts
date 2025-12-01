import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { ok, internalError, requireAdminGroup } from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_SENT_EMAILS = process.env.TABLE_SENT_EMAILS!;

/**
 * List all sent bulk emails (admin only)
 * GET /admin/sent-emails
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  try {
    // Scan sent emails table
    const result = await ddb.send(new ScanCommand({
      TableName: TABLE_SENT_EMAILS,
    }));

    if (!result.Items || result.Items.length === 0) {
      return ok([]);
    }

    const sentEmails = result.Items.map(item => unmarshall(item));

    // Sort by sent_at descending (newest first)
    sentEmails.sort((a, b) => {
      const dateA = new Date(a.sent_at).getTime();
      const dateB = new Date(b.sent_at).getTime();
      return dateB - dateA;
    });

    return ok(sentEmails);
  } catch (error: any) {
    console.error('Error listing sent emails:', error);
    return internalError(error.message || 'Failed to list sent emails');
  }
};
