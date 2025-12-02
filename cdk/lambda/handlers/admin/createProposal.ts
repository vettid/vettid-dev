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
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Create a new voting proposal
 * POST /admin/proposals
 * Body: { proposal_text: string, opens_at: ISO date, closes_at: ISO date }
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
    const { proposal_title, proposal_text, opens_at, closes_at } = body;

    if (!proposal_text || !opens_at || !closes_at) {
      return badRequest('Missing required fields: proposal_text, opens_at, closes_at');
    }

    // Validate dates
    const opensDate = new Date(opens_at);
    const closesDate = new Date(closes_at);
    const now = new Date();

    if (isNaN(opensDate.getTime()) || isNaN(closesDate.getTime())) {
      return badRequest('Invalid date format');
    }

    if (closesDate <= opensDate) {
      return badRequest('Closing date must be after opening date');
    }

    // Determine initial status
    let status = 'upcoming';
    if (now >= opensDate && now < closesDate) {
      status = 'active';
    } else if (now >= closesDate) {
      status = 'closed';
    }

    // Create proposal record
    const proposalId = randomUUID();
    const proposal: any = {
      proposal_id: proposalId,
      proposal_text: proposal_text,
      opens_at: opensDate.toISOString(),
      closes_at: closesDate.toISOString(),
      status: status,
      created_by: email,
      created_at: now.toISOString(),
    };

    // Add optional title if provided
    if (proposal_title) {
      proposal.proposal_title = proposal_title;
    }

    await ddb.send(new PutItemCommand({
      TableName: TABLE_PROPOSALS,
      Item: marshall(proposal),
    }));

    // Log to audit
    const auditEntry: any = {
      type: 'proposal_created',
      email: email,
      proposal_id: proposalId,
      proposal_text: proposal_text,
      opens_at: opensDate.toISOString(),
      closes_at: closesDate.toISOString(),
    };
    if (proposal_title) {
      auditEntry.proposal_title = proposal_title;
    }
    await putAudit(auditEntry, requestId);

    return ok({
      message: 'Proposal created successfully',
      proposal: {
        proposal_id: proposalId,
        status: status,
      },
    });
  } catch (error: any) {
    console.error('Error creating proposal:', error);
    return internalError(error.message || 'Failed to create proposal');
  }
};
