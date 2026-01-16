import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';
import { publishVoteResults } from '../../common/publishResults';

const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_VOTES = process.env.TABLE_VOTES!;
const PUBLISHED_VOTES_BUCKET = process.env.PUBLISHED_VOTES_BUCKET!;

/**
 * Publish vote results for a closed proposal
 * POST /admin/proposals/{proposal_id}/publish-results
 *
 * This endpoint:
 * 1. Retrieves all votes for the proposal
 * 2. Creates an anonymized vote list (only vault-signed votes are included)
 * 3. Builds a Merkle tree for verification
 * 4. Stores results to S3
 * 5. Updates the proposal with merkle_root
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  // Require admin group membership
  const authError = requireAdminGroup(event);
  if (authError) return authError;

  const requestId = getRequestId(event);

  try {
    // Get admin email from JWT claims
    const claims = (event.requestContext as any)?.authorizer?.jwt?.claims;
    const adminEmail = claims?.email;

    // Get proposal_id from path
    const proposalId = event.pathParameters?.proposal_id;
    if (!proposalId) {
      return badRequest('Missing proposal_id in path');
    }

    // Publish vote results using shared module
    const result = await publishVoteResults(
      proposalId,
      TABLE_PROPOSALS,
      TABLE_VOTES,
      PUBLISHED_VOTES_BUCKET,
      `admin:${adminEmail || 'unknown'}`
    );

    if (!result.success) {
      if (result.error === 'Proposal not found') {
        return notFound('Proposal not found');
      }
      if (result.not_closed) {
        return badRequest('Results can only be published for closed proposals');
      }
      if (result.already_published) {
        return badRequest('Results have already been published for this proposal');
      }
      return internalError(result.error || 'Failed to publish vote results');
    }

    // Audit log
    await putAudit({
      type: 'proposal_results_published',
      email: adminEmail,
      proposal_id: proposalId,
      merkle_root: result.merkle_root,
      vote_counts: result.vote_counts,
    }, requestId);

    return ok({
      message: 'Vote results published successfully',
      results: {
        proposal_id: proposalId,
        merkle_root: result.merkle_root,
        published_at: result.published_at,
        vote_counts: result.vote_counts,
        s3_keys: [
          `${proposalId}/votes.json`,
          `${proposalId}/merkle.json`,
        ],
      },
    });
  } catch (error: any) {
    console.error('Error publishing vote results:', error);
    return internalError('Failed to publish vote results');
  }
};
