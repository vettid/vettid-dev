import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Submit a vote on a proposal
 * POST /votes
 * Body: { proposal_id: string, vote: 'yes' | 'no' | 'abstain' }
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Get user_guid and email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const email = claims?.email;
    const user_guid = claims?.['custom:user_guid'];

    if (!email) {
      return badRequest('Email not found in token');
    }

    if (!user_guid) {
      return badRequest('User GUID not found in token');
    }

    // Parse request body
    const body = parseJsonBody(event);
    const { proposal_id, vote } = body;

    if (!proposal_id || !vote) {
      return badRequest('Missing required fields: proposal_id, vote');
    }

    if (!['yes', 'no', 'abstain'].includes(vote)) {
      return badRequest('Vote must be "yes", "no", or "abstain"');
    }

    // Check if proposal exists and is active
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposal_id }),
    }));

    if (!proposalResult.Item) {
      return badRequest('Proposal not found');
    }

    const proposal = unmarshall(proposalResult.Item);

    if (proposal.status !== 'active') {
      return badRequest('Proposal is not active for voting');
    }

    // Check if voting period is valid
    const now = new Date();
    const opensAt = new Date(proposal.opens_at);
    const closesAt = new Date(proposal.closes_at);

    if (now < opensAt) {
      return badRequest('Voting has not yet opened for this proposal');
    }

    if (now > closesAt) {
      return badRequest('Voting has closed for this proposal');
    }

    // Check if user has already voted
    const existingVoteResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_VOTES,
      Key: marshall({
        proposal_id: proposal_id,
        user_guid: user_guid,
      }),
    }));

    if (existingVoteResult.Item) {
      return badRequest('You have already voted on this proposal');
    }

    // Create vote record
    const voteRecord = {
      proposal_id: proposal_id,
      user_guid: user_guid,
      vote: vote,
      voted_at: now.toISOString(),
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_VOTES,
      Item: marshall(voteRecord),
    }));

    // Log to audit
    await putAudit({
      action: 'vote_submitted',
      email: email,
      user_guid: user_guid,
      proposal_id: proposal_id,
      vote: vote,
    }, requestId);

    return ok({
      message: 'Vote recorded successfully',
      vote: {
        proposal_id: proposal_id,
        vote: vote,
        voted_at: voteRecord.voted_at,
      },
    });
  } catch (error: any) {
    console.error('Error submitting vote:', error);
    return internalError(error.message || 'Failed to submit vote');
  }
};
