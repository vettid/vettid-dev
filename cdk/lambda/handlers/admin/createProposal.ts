import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  internalError,
  parseJsonBody,
  getRequestId,
  putAudit,
  requireAdminGroup
} from '../../common/util';
import { randomUUID, createHash } from 'crypto';

const ddb = new DynamoDBClient({});
const kms = new KMSClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;
const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const VOTING_KEY_ID = process.env.VOTING_KEY_ID!;

/**
 * Get the next proposal number atomically
 * Uses DynamoDB atomic counter pattern to ensure unique sequential numbers
 */
async function getNextProposalNumber(): Promise<string> {
  const result = await ddb.send(new UpdateItemCommand({
    TableName: TABLE_AUDIT,
    Key: marshall({ id: 'COUNTER#proposals' }),
    UpdateExpression: 'ADD #count :inc',
    ExpressionAttributeNames: { '#count': 'count' },
    ExpressionAttributeValues: marshall({ ':inc': 1 }),
    ReturnValues: 'UPDATED_NEW'
  }));

  const updated = result.Attributes ? unmarshall(result.Attributes) : { count: 1 };
  const nextNumber = updated.count || 1;
  return `P${String(nextNumber).padStart(7, '0')}`;
}

/**
 * A proposal choice with an ID and display label.
 */
interface ProposalChoice {
  id: string;
  label: string;
  description?: string;
}

/** Default choices when none are specified */
const DEFAULT_CHOICES: ProposalChoice[] = [
  { id: 'yes', label: 'Yes' },
  { id: 'no', label: 'No' },
  { id: 'abstain', label: 'Abstain' },
];

/**
 * Create a canonical signing payload for a proposal
 * Format: proposal_id|proposal_title|opens_at|closes_at|choiceId1,choiceId2,...
 * This payload is signed by VettID's KMS key to prove proposal authenticity
 */
function createSigningPayload(
  proposalId: string,
  proposalTitle: string | undefined,
  opensAt: string,
  closesAt: string,
  choices: ProposalChoice[]
): string {
  // Use empty string for title if not provided (consistent with verification)
  const title = proposalTitle || '';
  // Sort choice IDs for deterministic signing
  const sortedChoiceIds = choices.map(c => c.id).sort().join(',');
  return `${proposalId}|${title}|${opensAt}|${closesAt}|${sortedChoiceIds}`;
}

/**
 * Sign a proposal using KMS ECDSA-SHA256
 * Returns the signature as base64 and the signing payload
 */
async function signProposal(
  proposalId: string,
  proposalTitle: string | undefined,
  opensAt: string,
  closesAt: string,
  choices: ProposalChoice[]
): Promise<{ signature: string; signingPayload: string }> {
  const signingPayload = createSigningPayload(proposalId, proposalTitle, opensAt, closesAt, choices);

  // Hash the payload with SHA-256 (KMS ECDSA_SHA_256 expects pre-hashed message)
  const messageHash = createHash('sha256').update(signingPayload).digest();

  // Sign with KMS
  const signResult = await kms.send(new SignCommand({
    KeyId: VOTING_KEY_ID,
    Message: messageHash,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'ECDSA_SHA_256',
  }));

  if (!signResult.Signature) {
    throw new Error('KMS signing failed: no signature returned');
  }

  // Return signature as base64
  const signature = Buffer.from(signResult.Signature).toString('base64');
  return { signature, signingPayload };
}

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
    const { proposal_title, proposal_text, opens_at, closes_at, quorum_type, quorum_value, category, choices: rawChoices } = body;

    if (!proposal_text || !opens_at || !closes_at) {
      return badRequest('Missing required fields: proposal_text, opens_at, closes_at');
    }

    // Validate and normalize choices
    let effectiveChoices: ProposalChoice[] = DEFAULT_CHOICES;
    if (rawChoices !== undefined && rawChoices !== null) {
      if (!Array.isArray(rawChoices)) {
        return badRequest('choices must be an array');
      }
      if (rawChoices.length < 2) {
        return badRequest('choices must have at least 2 options');
      }
      if (rawChoices.length > 20) {
        return badRequest('choices must not exceed 20 options');
      }
      // Validate each choice
      const choiceIds = new Set<string>();
      const choiceIdPattern = /^[a-zA-Z0-9_-]{1,50}$/;
      for (const choice of rawChoices) {
        if (!choice.id || typeof choice.id !== 'string' || !choice.label || typeof choice.label !== 'string') {
          return badRequest('Each choice must have an id (string) and label (string)');
        }
        if (!choiceIdPattern.test(choice.id)) {
          return badRequest(`Choice id "${choice.id}" must be alphanumeric/hyphens/underscores, max 50 chars`);
        }
        if (choice.label.length > 200) {
          return badRequest('Choice label must not exceed 200 characters');
        }
        if (choiceIds.has(choice.id)) {
          return badRequest(`Duplicate choice id: ${choice.id}`);
        }
        choiceIds.add(choice.id);
      }
      effectiveChoices = rawChoices.map((c: any) => ({
        id: c.id,
        label: c.label,
        ...(c.description ? { description: c.description } : {}),
      }));
    }

    // Validate quorum settings
    const validQuorumTypes = ['none', 'percentage', 'count'];
    const effectiveQuorumType = quorum_type || 'none';
    if (!validQuorumTypes.includes(effectiveQuorumType)) {
      return badRequest('Invalid quorum_type. Must be: none, percentage, or count');
    }
    let effectiveQuorumValue = 0;
    if (effectiveQuorumType !== 'none') {
      if (typeof quorum_value !== 'number' || quorum_value <= 0) {
        return badRequest('quorum_value must be a positive number when quorum_type is set');
      }
      if (effectiveQuorumType === 'percentage' && (quorum_value < 1 || quorum_value > 100)) {
        return badRequest('quorum_value for percentage must be between 1 and 100');
      }
      effectiveQuorumValue = quorum_value;
    }

    // Validate category
    const validCategories = ['governance', 'policy', 'budget', 'operational', 'other'];
    const effectiveCategory = category || 'other';
    if (!validCategories.includes(effectiveCategory)) {
      return badRequest('Invalid category. Must be: governance, policy, budget, operational, or other');
    }

    // SECURITY: Validate proposal text length
    if (typeof proposal_text !== 'string' || proposal_text.trim().length < 10) {
      return badRequest('Proposal text must be at least 10 characters');
    }
    if (proposal_text.length > 10000) {
      return badRequest('Proposal text must not exceed 10,000 characters');
    }

    // Validate optional title length
    if (proposal_title && (typeof proposal_title !== 'string' || proposal_title.length > 200)) {
      return badRequest('Proposal title must not exceed 200 characters');
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

    // Validate that opening date is in the future
    if (opensDate < now) {
      return badRequest('Opening date must be in the future');
    }

    // Determine initial status
    let status = 'upcoming';
    if (now >= opensDate && now < closesDate) {
      status = 'active';
    } else if (now >= closesDate) {
      status = 'closed';
    }

    // Get next proposal number atomically
    const proposalNumber = await getNextProposalNumber();

    // Create proposal record
    const proposalId = randomUUID();
    const opensAtIso = opensDate.toISOString();
    const closesAtIso = closesDate.toISOString();

    // Sign the proposal with VettID's KMS key for authenticity
    // This signature proves the proposal was created by VettID (not forged)
    // Vaults verify this signature before allowing users to vote
    const { signature: kmsSignature, signingPayload } = await signProposal(
      proposalId,
      proposal_title,
      opensAtIso,
      closesAtIso,
      effectiveChoices
    );

    const proposal: any = {
      proposal_id: proposalId,
      proposal_number: proposalNumber,
      proposal_text: proposal_text,
      opens_at: opensAtIso,
      closes_at: closesAtIso,
      status: status,
      created_by: email,
      created_at: now.toISOString(),
      quorum_type: effectiveQuorumType,
      quorum_value: effectiveQuorumValue,
      category: effectiveCategory,
      choices: effectiveChoices,
      // Vault-based voting fields
      kms_signature: kmsSignature,
      kms_key_id: VOTING_KEY_ID,
      signing_payload: signingPayload,
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
      proposal_number: proposalNumber,
      proposal_text: proposal_text,
      opens_at: opensAtIso,
      closes_at: closesAtIso,
      quorum_type: effectiveQuorumType,
      quorum_value: effectiveQuorumValue,
      category: effectiveCategory,
      choices_count: effectiveChoices.length,
      kms_signed: true,
    };
    if (proposal_title) {
      auditEntry.proposal_title = proposal_title;
    }
    await putAudit(auditEntry, requestId);

    return ok({
      message: 'Proposal created successfully',
      proposal: {
        proposal_id: proposalId,
        proposal_number: proposalNumber,
        status: status,
        kms_signature: kmsSignature,
        kms_key_id: VOTING_KEY_ID,
      },
    });
  } catch (error: any) {
    console.error('Error creating proposal:', error);
    // SECURITY: Don't expose error.message
    return internalError('Failed to create proposal');
  }
};
