/**
 * Create NATS Member Account
 *
 * Creates a NATS account (namespace) for a member. This includes:
 * - OwnerSpace.{member_guid} - For vault communication (forVault, forApp, eventTypes, control)
 * - MessageSpace.{member_guid} - For external connections (forOwner, ownerProfile)
 *
 * POST /vault/nats/account
 *
 * Requires: Member JWT token
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { createHash } from 'crypto';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  requireUserClaims,
  putAudit,
  getRequestId,
  nowIso,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';

interface NatsAccountRecord {
  user_guid: string;
  owner_space_id: string;
  message_space_id: string;
  account_public_key: string;
  status: 'active' | 'suspended' | 'revoked';
  created_at: string;
  updated_at: string;
}

interface CreateAccountResponse {
  owner_space_id: string;
  message_space_id: string;
  nats_endpoint: string;
  status: string;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Require authenticated member
    const claimsResult = requireUserClaims(event, origin);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const userGuid = claims.user_guid;

    if (!userGuid) {
      return badRequest('Missing user_guid in token', origin);
    }

    // Check if account already exists
    const existingAccount = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    if (existingAccount.Item) {
      const account = unmarshall(existingAccount.Item) as NatsAccountRecord;
      if (account.status === 'active') {
        return conflict('NATS account already exists for this member', origin);
      }
      // If suspended/revoked, could reactivate - but for now, return conflict
      return conflict('NATS account exists but is not active. Contact support.', origin);
    }

    // Generate unique account IDs
    const ownerSpaceId = `OwnerSpace.${userGuid}`;
    const messageSpaceId = `MessageSpace.${userGuid}`;

    // Generate account signing key (in production, this would use nkeys library)
    // For now, we create a placeholder that will be populated by the NATS operator
    const accountPublicKey = generateAccountPlaceholder(userGuid);

    const now = nowIso();

    // Create account record
    const accountRecord: NatsAccountRecord = {
      user_guid: userGuid,
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      account_public_key: accountPublicKey,
      status: 'active',
      created_at: now,
      updated_at: now,
    };

    await ddb.send(new PutItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Item: marshall(accountRecord),
      ConditionExpression: 'attribute_not_exists(user_guid)',
    }));

    // Audit log
    await putAudit({
      event: 'nats_account_created',
      user_guid: userGuid,
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
    }, requestId);

    const response: CreateAccountResponse = {
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      nats_endpoint: `nats://${NATS_DOMAIN}:4222`,
      status: 'active',
    };

    return ok(response, origin);
  } catch (error: any) {
    console.error('Error creating NATS account:', error);

    if (error.name === 'ConditionalCheckFailedException') {
      return conflict('NATS account already exists', origin);
    }

    return internalError('Failed to create NATS account', origin);
  }
};

/**
 * Generate a placeholder account key identifier
 * In production, this would use the nkeys library to generate proper NATS account keys
 */
function generateAccountPlaceholder(userGuid: string): string {
  const hash = createHash('sha256').update(userGuid).digest('hex').substring(0, 32);
  return `A${hash.toUpperCase()}`;
}
