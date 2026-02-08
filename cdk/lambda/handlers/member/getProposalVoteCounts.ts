import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  sanitizeErrorForClient
} from '../../common/util';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Get vote counts for a proposal (member accessible)
 * GET /proposals/{id}/vote-counts
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  try {
    const proposal_id = event.pathParameters?.proposal_id;

    if (!proposal_id) {
      return badRequest('Proposal ID is required', requestOrigin);
    }

    // Get proposal details
    const proposalResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_PROPOSALS,
      Key: marshall({ proposal_id: proposal_id }),
    }));

    if (!proposalResult.Item) {
      return badRequest('Proposal not found', requestOrigin);
    }

    const proposal = unmarshall(proposalResult.Item);

    // Extract choices from proposal (fall back to default yes/no/abstain)
    const defaultChoices = [
      { id: 'yes', label: 'Yes' },
      { id: 'no', label: 'No' },
      { id: 'abstain', label: 'Abstain' },
    ];
    const choices: Array<{ id: string; label: string }> = Array.isArray(proposal.choices) && proposal.choices.length >= 2
      ? proposal.choices
      : defaultChoices;

    // Scan all votes for this proposal
    const votesResult = await ddb.send(new ScanCommand({
      TableName: TABLE_VOTES,
      FilterExpression: 'proposal_id = :proposal_id',
      ExpressionAttributeValues: marshall({
        ':proposal_id': proposal_id,
      }),
    }));

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

    const totalVotes = Object.values(results).reduce((sum, count) => sum + count, 0);

    return ok({
      results,
      choices,
      totalVotes,
    }, requestOrigin);
  } catch (error: any) {
    console.error('Error getting proposal vote counts:', error);
    return internalError(sanitizeErrorForClient(error, 'Failed to get proposal vote counts'), requestOrigin);
  }
};
