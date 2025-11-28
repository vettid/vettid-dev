import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId,
  requireAdminGroup
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get vote counts for a proposal (admin only)
 * GET /admin/proposals/{proposal_id}/votes
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    const proposal_id = event.pathParameters?.proposal_id;

    if (!proposal_id) {
      return badRequest('Proposal ID is required');
    }

    // Get proposal details
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposal_id }),
    }));

    if (!proposalResult.Item) {
      return badRequest('Proposal not found');
    }

    const proposal = unmarshall(proposalResult.Item);

    // Scan all votes for this proposal
    const votesResult = await ddb.send(new ScanCommand({
      TableName: TABLE_VOTES,
      FilterExpression: 'proposal_id = :proposal_id',
      ExpressionAttributeValues: marshall({
        ':proposal_id': proposal_id,
      }),
    }));

    // Aggregate vote counts
    const results = {
      yes: 0,
      no: 0,
      abstain: 0,
    };

    if (votesResult.Items) {
      votesResult.Items.forEach((item) => {
        const vote = unmarshall(item);
        if (vote.vote === 'yes') results.yes++;
        else if (vote.vote === 'no') results.no++;
        else if (vote.vote === 'abstain') results.abstain++;
      });
    }

    const totalVotes = results.yes + results.no + results.abstain;

    // Calculate hours until close for active proposals
    let hoursUntilClose = null;
    if (proposal.status === 'active') {
      const now = new Date();
      const closesAt = new Date(proposal.closes_at);
      const msUntilClose = closesAt.getTime() - now.getTime();
      hoursUntilClose = Math.max(0, Math.round(msUntilClose / (1000 * 60 * 60)));
    }

    return ok({
      proposal: {
        proposal_id: proposal.proposal_id,
        proposal_title: proposal.proposal_title || null,
        proposal_text: proposal.proposal_text,
        status: proposal.status,
        opens_at: proposal.opens_at,
        closes_at: proposal.closes_at,
      },
      totalVotes,
      results,
      hoursUntilClose,
    });
  } catch (error: any) {
    console.error('Error getting proposal vote counts:', error);
    return internalError(error.message || 'Failed to get proposal vote counts');
  }
};
