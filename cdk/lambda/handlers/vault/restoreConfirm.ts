import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  requireUserClaims,
} from '../../common/util';
import { generateBootstrapCredentials, formatCredsFile } from '../../common/nats-jwt';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const CREDENTIAL_BACKUP_BUCKET = process.env.CREDENTIAL_BACKUP_BUCKET!;

/**
 * POST /vault/credentials/restore/confirm
 *
 * Confirm credential restore after the 24-hour waiting period (for lost device recovery)
 * or immediately after approval (for device transfer).
 *
 * Simplified Backup Model:
 * - No recovery phrase required
 * - Lambda fetches encrypted credential backup from S3
 * - Returns credential backup + NATS bootstrap credentials
 * - App connects to vault via NATS and authenticates with credential + password
 * - Vault verifies password against credential to prove identity
 *
 * Security: Even if attacker compromises Cognito account and waits 24 hours,
 * they cannot authenticate to the vault without knowing the user's password.
 *
 * Requires member JWT authentication.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  try {
    // Validate member authentication and get claims
    const claimsResult = requireUserClaims(event);
    if ('error' in claimsResult) {
      return claimsResult.error;
    }
    const { claims } = claimsResult;
    const memberGuid = claims.user_guid;

    // Find eligible restore request for this member
    // Look for: pending_timer (ready after 24hrs), ready, or approved (transfer)
    const existingRequest = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid',
      FilterExpression: '#status IN (:pending_timer, :ready, :approved)',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending_timer': 'pending_timer',
        ':ready': 'ready',
        ':approved': 'approved',
      }),
      Limit: 1,
    }));

    if (!existingRequest.Items || existingRequest.Items.length === 0) {
      return notFound('No eligible restore request found', origin);
    }

    const request = unmarshall(existingRequest.Items[0]);
    const now = new Date();

    // For lost device recovery, check if 24-hour waiting period has elapsed
    if (request.lost_device && request.status === 'pending_timer') {
      const readyAt = new Date(request.ready_at);
      if (now < readyAt) {
        const remainingMs = readyAt.getTime() - now.getTime();
        const remainingHours = Math.ceil(remainingMs / (60 * 60 * 1000));
        return conflict(
          `Recovery cannot be confirmed yet. Please wait ${remainingHours} more hour(s).`,
          origin
        );
      }
    }

    // Find the most recent active backup for this user
    const backupResult = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_BACKUPS,
      IndexName: 'member-index',
      KeyConditionExpression: 'member_guid = :guid',
      FilterExpression: '#status = :active',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':active': 'ACTIVE',
      }),
      ScanIndexForward: false, // Most recent first
      Limit: 1,
    }));

    if (!backupResult.Items || backupResult.Items.length === 0) {
      return badRequest('No backup found. Backups must be enabled before device loss.', origin);
    }

    const backup = unmarshall(backupResult.Items[0]);

    // Fetch the encrypted credential from S3
    let credentialBlob: string;
    try {
      const s3Response = await s3.send(new GetObjectCommand({
        Bucket: CREDENTIAL_BACKUP_BUCKET,
        Key: backup.s3_key,
      }));

      if (!s3Response.Body) {
        throw new Error('Empty S3 response');
      }

      credentialBlob = await s3Response.Body.transformToString('base64');
    } catch (s3Error: any) {
      console.error('Failed to fetch credential backup from S3:', s3Error);
      return internalError('Failed to retrieve credential backup', origin);
    }

    // Get the NATS account for this user
    const natsAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: memberGuid }),
    }));

    if (!natsAccountResult.Item) {
      return badRequest('No vault account found', origin);
    }

    const natsAccount = unmarshall(natsAccountResult.Item);

    // Generate bootstrap credentials for the new device to connect to vault
    const ownerSpaceId = natsAccount.owner_space_id || `OwnerSpace.${memberGuid.replace(/-/g, '')}`;
    const messageSpaceId = natsAccount.message_space_id || `MessageSpace.${memberGuid.replace(/-/g, '')}`;

    const bootstrapCreds = await generateBootstrapCredentials(
      memberGuid,
      natsAccount.account_seed,
      ownerSpaceId
    );

    const bootstrapCredentials = formatCredsFile(bootstrapCreds.jwt, bootstrapCreds.seed);

    // Update NATS account status to indicate restore in progress
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: memberGuid }),
      UpdateExpression: 'SET #status = :restoring, restore_confirmed_at = :now, transfer_status = :pending',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':restoring': 'restoring',
        ':now': now.toISOString(),
        ':pending': 'pending_authentication',
      }),
    }));

    // Mark restore request as pending authentication
    // Will be marked completed when vault confirms successful authentication
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: request.recovery_id }),
      UpdateExpression: 'SET #status = :status, confirm_requested_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'pending_authentication',
        ':now': now.toISOString(),
      }),
    }));

    // Audit log
    await putAudit({
      type: 'credential_restore_confirm',
      member_guid: memberGuid,
      recovery_id: request.recovery_id,
      lost_device: request.lost_device,
      backup_id: backup.backup_id,
      backup_created_at: backup.created_at,
    }, requestId);

    return ok({
      success: true,
      status: 'pending_authentication',
      message: 'Credential backup retrieved. Connect to your vault and authenticate with your password.',
      // Encrypted credential blob - app stores this and sends to vault for authentication
      credential_backup: {
        encrypted_credential: credentialBlob,
        backup_id: backup.backup_id,
        created_at: backup.created_at,
        key_id: backup.key_id, // Key ID used to encrypt the credential
      },
      // Vault bootstrap info - app uses these credentials to connect to vault
      vault_bootstrap: {
        credentials: bootstrapCredentials,
        owner_space: ownerSpaceId,
        message_space: messageSpaceId,
        nats_endpoint: `tls://${process.env.NATS_ENDPOINT || 'nats.vettid.dev:443'}`,
        auth_topic: `${ownerSpaceId}.forVault.app.authenticate`,
        response_topic: `${ownerSpaceId}.forApp.app.authenticate.>`,
        credentials_ttl_seconds: 3600,
      },
    }, origin);

  } catch (error: any) {
    console.error('Confirm credential restore error:', error);
    return internalError('Failed to confirm credential restore', origin);
  }
};
