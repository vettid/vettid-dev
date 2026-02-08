import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, GetItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  requireUserClaims
} from '../../common/util';
import { createVerify, createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const TABLE_VOTES = process.env.TABLE_VOTES!;
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;

/**
 * Verify an Ed25519 signature
 * @param publicKey - Base64-encoded Ed25519 public key
 * @param signature - Base64-encoded signature
 * @param message - The message that was signed
 * @returns true if signature is valid
 */
function verifyEd25519Signature(publicKey: string, signature: string, message: string): boolean {
  try {
    // Convert base64 public key to DER format for Node.js crypto
    const pubKeyBuffer = Buffer.from(publicKey, 'base64');

    // Ed25519 public keys are 32 bytes raw
    if (pubKeyBuffer.length !== 32) {
      console.error('Invalid public key length:', pubKeyBuffer.length);
      return false;
    }

    // Create DER-encoded public key for Ed25519
    // DER header for Ed25519: 302a300506032b6570032100 (12 bytes) + 32 byte key
    const derPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const derPublicKey = Buffer.concat([derPrefix, pubKeyBuffer]);

    const verify = createVerify('ed25519');
    verify.update(message);

    const signatureBuffer = Buffer.from(signature, 'base64');
    return verify.verify(
      { key: derPublicKey, format: 'der', type: 'spki' },
      signatureBuffer
    );
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Receive a vault-signed vote
 * POST /member/votes/signed
 * Body: {
 *   proposal_id: string,
 *   vote: string (choice ID matching proposal's choices),
 *   voting_public_key: string (base64),
 *   vote_signature: string (base64),
 *   signed_payload: string
 * }
 *
 * The signed_payload should be: proposal_id|vote|timestamp
 * The signature is created by the user's vault using a derived voting keypair.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);

  try {
    // Require authenticated member (to prevent spam)
    // Note: We don't use the user_guid for vote storage - voting_public_key provides anonymity
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) return claimsResult.error;

    // Parse request body
    const body = parseJsonBody(event);
    const { proposal_id, vote, voting_public_key, vote_signature, signed_payload } = body;

    // Validate required fields
    if (!proposal_id || !vote || !voting_public_key || !vote_signature || !signed_payload) {
      return badRequest('Missing required fields: proposal_id, vote, voting_public_key, vote_signature, signed_payload');
    }

    // Vote value is validated after proposal fetch (dynamic choices)

    // Validate signed_payload format: proposal_id|vote|timestamp
    const payloadParts = signed_payload.split('|');
    if (payloadParts.length !== 3) {
      return badRequest('Invalid signed_payload format');
    }

    const [payloadProposalId, payloadVote, payloadTimestamp] = payloadParts;

    // Verify payload matches request
    if (payloadProposalId !== proposal_id) {
      return badRequest('Signed payload proposal_id does not match request');
    }

    if (payloadVote !== vote) {
      return badRequest('Signed payload vote does not match request');
    }

    // Verify timestamp is recent (within 5 minutes)
    const signedTime = new Date(payloadTimestamp);
    const now = new Date();
    const timeDiff = Math.abs(now.getTime() - signedTime.getTime());
    const fiveMinutes = 5 * 60 * 1000;

    if (isNaN(signedTime.getTime()) || timeDiff > fiveMinutes) {
      return badRequest('Vote signature has expired or timestamp is invalid');
    }

    // Verify Ed25519 signature
    const isValidSignature = verifyEd25519Signature(voting_public_key, vote_signature, signed_payload);
    if (!isValidSignature) {
      // Log failed signature attempt for security monitoring
      await putAudit({
        type: 'vault_vote_signature_invalid',
        proposal_id: proposal_id,
        voting_public_key_prefix: voting_public_key.substring(0, 16) + '...',
      }, requestId);
      return badRequest('Invalid vote signature');
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

    // Validate vote value against proposal's choices
    const validChoiceIds: string[] = proposal.choices
      ? proposal.choices.map((c: any) => c.id)
      : ['yes', 'no', 'abstain'];
    if (!validChoiceIds.includes(vote)) {
      return badRequest(`Vote must be one of: ${validChoiceIds.join(', ')}`);
    }

    if (proposal.status !== 'active') {
      return badRequest('Proposal is not active for voting');
    }

    // Check if voting period is valid
    const opensAt = new Date(proposal.opens_at);
    const closesAt = new Date(proposal.closes_at);

    if (now < opensAt) {
      return badRequest('Voting has not yet opened for this proposal');
    }

    if (now > closesAt) {
      return badRequest('Voting has closed for this proposal');
    }

    // Create vote record with idempotency via conditional expression
    // Use voting_public_key as the sort key for vault-signed votes
    // This prevents the same derived key from voting twice while preserving anonymity
    const voteRecord = {
      proposal_id: proposal_id,
      user_guid: `VAULT:${voting_public_key}`, // Prefixed to distinguish from web votes
      vote: vote,
      voted_at: now.toISOString(),
      // Vault-signed vote fields
      voting_public_key: voting_public_key,
      vote_signature: vote_signature,
      signed_payload: signed_payload,
      vote_source: 'vault',
    };

    try {
      await ddb.send(new PutItemCommand({
        TableName: TABLE_VOTES,
        Item: marshall(voteRecord),
        // IDEMPOTENCY: Only create if this vote doesn't already exist
        ConditionExpression: 'attribute_not_exists(proposal_id) AND attribute_not_exists(user_guid)',
      }));
    } catch (error: any) {
      if (error.name === 'ConditionalCheckFailedException') {
        return badRequest('This voting key has already been used to vote on this proposal');
      }
      throw error;
    }

    // Log to audit (without revealing identity)
    await putAudit({
      type: 'vault_vote_submitted',
      proposal_id: proposal_id,
      voting_public_key_prefix: voting_public_key.substring(0, 16) + '...',
      vote_source: 'vault',
    }, requestId);

    return ok({
      message: 'Vault-signed vote recorded successfully',
      vote: {
        proposal_id: proposal_id,
        vote: vote,
        voted_at: voteRecord.voted_at,
        voting_public_key_prefix: voting_public_key.substring(0, 16) + '...',
      },
    });
  } catch (error: any) {
    console.error('Error submitting vault-signed vote:', error);
    // SECURITY: Don't expose error.message
    return internalError('Failed to submit vote');
  }
};
