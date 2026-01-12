/**
 * Create NATS Member Account
 *
 * Creates a NATS account (namespace) for a member. This includes:
 * - OwnerSpace.{member_guid} - For vault communication (forVault, forApp, eventTypes, control)
 * - MessageSpace.{member_guid} - For external connections (forOwner, ownerProfile)
 *
 * The response includes KV bucket configuration for the vault to provision:
 * - {user_guid}_calls - Call history and state (30-day TTL)
 * - {user_guid}_connections - Peer connection data
 * - {user_guid}_messages - Chat message history (90-day TTL)
 * - {user_guid}_profile - User profile data
 *
 * Note: KV buckets are provisioned by the vault on first connection using JetStream.
 * This Lambda only creates the NATS account credentials.
 *
 * POST /vault/nats/account
 *
 * Requires: Member JWT token
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { KMSClient, EncryptCommand } from '@aws-sdk/client-kms';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
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
import { generateAccountCredentials } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const kms = new KMSClient({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';
// SECURITY: KMS key for envelope encryption of account seeds (Ed25519 private keys)
const NATS_SEED_KMS_KEY_ARN = process.env.NATS_SEED_KMS_KEY_ARN!;

interface NatsAccountRecord {
  user_guid: string;
  owner_space_id: string;
  message_space_id: string;
  account_public_key: string;
  // SECURITY: account_seed is envelope-encrypted with KMS before storage
  // Format: base64-encoded KMS ciphertext blob
  account_seed_encrypted: string;
  account_jwt: string;   // Account JWT signed by operator
  status: 'active' | 'suspended' | 'revoked';
  created_at: string;
  updated_at: string;
}

interface KVBucketConfig {
  name: string;
  ttl_seconds?: number;
  max_bytes: number;
  description: string;
}

interface CreateAccountResponse {
  owner_space_id: string;
  message_space_id: string;
  nats_endpoint: string;
  status: string;
  kv_buckets: KVBucketConfig[];
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

    // Generate account credentials using nkeys
    const accountCredentials = await generateAccountCredentials(userGuid);

    // SECURITY: Encrypt the account seed with KMS before storing
    // This provides envelope encryption - even if DynamoDB is compromised,
    // the seed cannot be decrypted without KMS access
    const encryptResult = await kms.send(new EncryptCommand({
      KeyId: NATS_SEED_KMS_KEY_ARN,
      Plaintext: Buffer.from(accountCredentials.seed, 'utf-8'),
      EncryptionContext: {
        // SECURITY: Bind ciphertext to this specific user to prevent copy attacks
        user_guid: userGuid,
        purpose: 'nats_account_seed',
      },
    }));

    if (!encryptResult.CiphertextBlob) {
      console.error('KMS encryption failed - no ciphertext returned');
      return internalError('Failed to secure account credentials', origin);
    }

    const encryptedSeedBase64 = Buffer.from(encryptResult.CiphertextBlob).toString('base64');

    const now = nowIso();

    // Create account record with encrypted seed
    const accountRecord: NatsAccountRecord = {
      user_guid: userGuid,
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      account_public_key: accountCredentials.publicKey,
      account_seed_encrypted: encryptedSeedBase64,
      account_jwt: accountCredentials.accountJwt,
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

    // Define KV bucket configuration for the vault to provision
    const kvBuckets: KVBucketConfig[] = [
      {
        name: `${userGuid}_calls`,
        ttl_seconds: 30 * 24 * 60 * 60, // 30 days
        max_bytes: 10 * 1024 * 1024,    // 10MB
        description: 'Call history and state',
      },
      {
        name: `${userGuid}_connections`,
        max_bytes: 1 * 1024 * 1024,     // 1MB
        description: 'Peer connection data',
      },
      {
        name: `${userGuid}_messages`,
        ttl_seconds: 90 * 24 * 60 * 60, // 90 days
        max_bytes: 100 * 1024 * 1024,   // 100MB
        description: 'Chat message history',
      },
      {
        name: `${userGuid}_profile`,
        max_bytes: 100 * 1024,          // 100KB
        description: 'User profile data',
      },
    ];

    const response: CreateAccountResponse = {
      owner_space_id: ownerSpaceId,
      message_space_id: messageSpaceId,
      nats_endpoint: `nats://${NATS_DOMAIN}:4222`,
      status: 'active',
      kv_buckets: kvBuckets,
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
