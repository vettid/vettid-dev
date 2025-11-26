import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Suspend an active proposal
 * POST /admin/proposals/{proposal_id}/suspend
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

    // Get proposal ID from path
    const proposalId = event.pathParameters?.proposal_id;
    if (!proposalId) {
      return badRequest('Proposal ID is required');
    }

    const now = new Date();

    // Update proposal status to suspended
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposalId }),
      UpdateExpression: 'SET #status = :status, suspended_at = :suspended_at, suspended_by = :suspended_by',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'suspended',
        ':suspended_at': now.toISOString(),
        ':suspended_by': email,
      }),
    }));

    // Log to audit
    await putAudit({
      action: 'proposal_suspended',
      email: email,
      proposal_id: proposalId,
      suspended_at: now.toISOString(),
    }, requestId);

    return ok({
      message: 'Proposal suspended successfully',
    });
  } catch (error: any) {
    console.error('Error suspending proposal:', error);
    return internalError(error.message || 'Failed to suspend proposal');
  }
};
