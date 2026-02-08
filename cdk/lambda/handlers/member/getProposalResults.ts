import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  requireRegisteredOrMemberGroup
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get results for a specific proposal
 * GET /proposals/{proposal_id}/results
 *
 * SECURITY: Requires member or registered group membership
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Validate registered or member group membership
  const authError = requireRegisteredOrMemberGroup(event);
  if (authError) return authError;

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

    // Only show results for closed proposals
    if (proposal.status !== 'closed') {
      return badRequest('Results are only available for closed proposals');
    }

    // Query all votes for this proposal using GSI
    const votesResult = await ddb.send(new QueryCommand({
      TableName: TABLE_VOTES,
      IndexName: 'proposal-vote-index',
      KeyConditionExpression: 'proposal_id = :proposal_id',
      ExpressionAttributeValues: marshall({
        ':proposal_id': proposal_id,
      }),
    }));

    // Extract choices from proposal (fall back to default yes/no/abstain)
    const defaultChoices = [
      { id: 'yes', label: 'Yes' },
      { id: 'no', label: 'No' },
      { id: 'abstain', label: 'Abstain' },
    ];
    const choices: Array<{ id: string; label: string }> = Array.isArray(proposal.choices) && proposal.choices.length >= 2
      ? proposal.choices
      : defaultChoices;

    // Aggregate vote counts dynamically from choices
    const validChoiceIds = new Set(choices.map(c => c.id));
    const results: Record<string, number> = {};
    for (const choice of choices) {
      results[choice.id] = 0;
    }

    if (votesResult.Items) {
      votesResult.Items.forEach((item) => {
        const vote = unmarshall(item);
        if (validChoiceIds.has(vote.vote)) {
          results[vote.vote]++;
        }
      });
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
      results,
      choices,
    });
  } catch (error: any) {
    console.error('Error getting proposal results:', error);
    // SECURITY: Don't expose error.message to prevent information disclosure
    return internalError('Failed to get proposal results');
  }
};
