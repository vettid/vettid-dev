import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
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
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

/**
 * Get voting history for the authenticated user
 * GET /votes/history
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Get email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const email = claims?.email;

    if (!email) {
      return badRequest('Email not found in token');
    }

    // Get user_guid from registrations table using Scan
    const registrationsResult = await ddb.send(new ScanCommand({
      TableName: TABLE_REGISTRATIONS,
      FilterExpression: 'email = :email',
      ExpressionAttributeValues: marshall({
        ':email': email,
      }),
      Limit: 1,
    }));

    if (!registrationsResult.Items || registrationsResult.Items.length === 0) {
      return badRequest('User registration not found');
    }

    const registration = unmarshall(registrationsResult.Items[0]);
    const user_guid = registration.user_guid;

    if (!user_guid) {
      return badRequest('User GUID not found');
    }

    // Scan votes by user_guid
    const votesResult = await ddb.send(new ScanCommand({
      TableName: TABLE_VOTES,
      FilterExpression: 'user_guid = :user_guid',
      ExpressionAttributeValues: marshall({
        ':user_guid': user_guid,
      }),
    }));

    if (!votesResult.Items || votesResult.Items.length === 0) {
      return ok({ votes: [] });
    }

    // Enrich votes with proposal data
    const votes = await Promise.all(
      votesResult.Items.map(async (item) => {
        const vote = unmarshall(item);

        // Fetch proposal details
        const proposalResult = await ddb.send(new GetItemCommand({
          TableName: TABLE_PROPOSALS,
          Key: marshall({ proposal_id: vote.proposal_id }),
        }));

        if (proposalResult.Item) {
          const proposal = unmarshall(proposalResult.Item);
          return {
            ...vote,
            proposal_title: proposal.proposal_title || null,
            proposal_text: proposal.proposal_text,
            proposal_status: proposal.status,
            proposal_opens_at: proposal.opens_at,
            proposal_closes_at: proposal.closes_at,
          };
        }

        return vote;
      })
    );

    // Sort by voted_at descending (most recent first)
    votes.sort((a, b) => {
      const dateA = new Date(a.voted_at || 0).getTime();
      const dateB = new Date(b.voted_at || 0).getTime();
      return dateB - dateA;
    });

    return ok({ votes });
  } catch (error: any) {
    console.error('Error getting voting history:', error);
    return internalError(error.message || 'Failed to get voting history');
  }
};
