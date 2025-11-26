import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  getRequestId
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get vote counts for a proposal (member accessible)
 * GET /proposals/{proposal_id}/vote-counts
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
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

    // Query all votes for this proposal using GSI
    const votesResult = await ddb.send(new QueryCommand({
      TableName: TABLE_VOTES,
      IndexName: 'proposal-votes-index',
      KeyConditionExpression: 'proposal_id = :proposal_id',
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
      yes: results.yes,
      no: results.no,
      abstain: results.abstain,
      totalVotes,
    });
  } catch (error: any) {
    console.error('Error getting proposal vote counts:', error);
    return internalError(error.message || 'Failed to get proposal vote counts');
  }
};
