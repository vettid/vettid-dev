/**
 * Vault Decommission Handler
 *
 * Completely removes a user's vault and all related NATS data.
 * This is used for:
 * - Testing: Reset a user's vault state for re-enrollment
 * - User deletion: Clean up vault data when permanently deleting a user
 * - Security incidents: Emergency revocation of vault access
 *
 * DELETE /admin/vault/{user_guid}/decommission
 *
 * Deletes:
 * - DynamoDB: NatsAccounts, NatsTokens, EnrollmentSessions, CredentialBackups, Profiles
 * - S3: Credential backup blobs in backup bucket
 * - NATS: Revokes account JWT (user can no longer connect)
 *
 * Note: JetStream data in the enclave will be orphaned but inaccessible
 * once the account JWT is revoked. It will be cleaned up during enclave
 * maintenance or rebuild.
 */

import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import {
  DynamoDBClient,
  GetItemCommand,
  DeleteItemCommand,
  QueryCommand,
  BatchWriteItemCommand,
  ScanCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import {
  S3Client,
  ListObjectsV2Command,
  DeleteObjectsCommand,
} from '@aws-sdk/client-s3';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  internalError,
  putAudit,
  requireAdminGroup,
  getAdminEmail,
  nowIso,
  validateOrigin,
} from '../../common/util';
import { publishToNats } from '../../common/nats-publisher';

const ddb = new DynamoDBClient({});
const s3 = new S3Client({});

const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;
const TABLE_NATS_TOKENS = process.env.TABLE_NATS_TOKENS!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;
const TABLE_PROFILES = process.env.TABLE_PROFILES!;
const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;
const BACKUP_BUCKET = process.env.BACKUP_BUCKET!;

interface DecommissionResult {
  nats_account_deleted: boolean;
  nats_tokens_deleted: number;
  enrollment_sessions_deleted: number;
  credential_backups_deleted: number;
  profiles_deleted: number;
  vault_instance_deleted: boolean;
  registration_reset: boolean;
  s3_objects_deleted: number;
  enclave_credential_deleted: boolean;
  errors: string[];
}

/**
 * Delete all items matching a filter from a table
 * Returns count of deleted items
 */
async function deleteItemsByUserGuid(
  tableName: string,
  userGuid: string,
  keyAttribute: string,
  useIndex: boolean = false
): Promise<{ count: number; error?: string }> {
  try {
    let items: any[] = [];

    if (useIndex) {
      // Use GSI for tables with user-index
      const result = await ddb.send(new QueryCommand({
        TableName: tableName,
        IndexName: 'user-index',
        KeyConditionExpression: 'user_guid = :guid',
        ExpressionAttributeValues: marshall({ ':guid': userGuid }),
      }));
      items = result.Items || [];
    } else {
      // Scan with filter for tables without index
      const result = await ddb.send(new ScanCommand({
        TableName: tableName,
        FilterExpression: 'user_guid = :guid',
        ExpressionAttributeValues: marshall({ ':guid': userGuid }),
      }));
      items = result.Items || [];
    }

    if (items.length === 0) {
      return { count: 0 };
    }

    // Delete in batches of 25 (DynamoDB limit)
    const batchSize = 25;
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const deleteRequests = batch.map(item => {
        const unmarshalled = unmarshall(item);
        return {
          DeleteRequest: {
            Key: marshall({ [keyAttribute]: unmarshalled[keyAttribute] }),
          },
        };
      });

      await ddb.send(new BatchWriteItemCommand({
        RequestItems: {
          [tableName]: deleteRequests,
        },
      }));
    }

    return { count: items.length };
  } catch (error: any) {
    console.error(`Error deleting from ${tableName}:`, error);
    return { count: 0, error: error.message };
  }
}

/**
 * Delete all S3 objects for a user
 */
async function deleteS3Objects(bucket: string, prefix: string): Promise<{ count: number; error?: string }> {
  try {
    // List all objects with the prefix
    const listResult = await s3.send(new ListObjectsV2Command({
      Bucket: bucket,
      Prefix: prefix,
    }));

    if (!listResult.Contents || listResult.Contents.length === 0) {
      return { count: 0 };
    }

    // Delete all objects
    const deleteResult = await s3.send(new DeleteObjectsCommand({
      Bucket: bucket,
      Delete: {
        Objects: listResult.Contents.map(obj => ({ Key: obj.Key! })),
      },
    }));

    return { count: deleteResult.Deleted?.length || 0 };
  } catch (error: any) {
    console.error(`Error deleting S3 objects from ${bucket}/${prefix}:`, error);
    return { count: 0, error: error.message };
  }
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath,
    });
    return authError;
  }

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  const adminEmail = getAdminEmail(event);
  const now = nowIso();

  // Get user_guid from path
  const userGuid = event.pathParameters?.user_guid;
  if (!userGuid) {
    return badRequest('user_guid is required in path');
  }

  // Validate UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userGuid)) {
    return badRequest('Invalid user_guid format');
  }

  const result: DecommissionResult = {
    nats_account_deleted: false,
    nats_tokens_deleted: 0,
    enrollment_sessions_deleted: 0,
    credential_backups_deleted: 0,
    profiles_deleted: 0,
    vault_instance_deleted: false,
    registration_reset: false,
    s3_objects_deleted: 0,
    enclave_credential_deleted: false,
    errors: [],
  };

  try {
    console.log(`Starting vault decommission for user: ${userGuid}`);

    // 1. Check if NATS account exists (to verify user has vault data)
    const accountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: userGuid }),
    }));

    const hasNatsAccount = !!accountResult.Item;
    if (hasNatsAccount) {
      const account = unmarshall(accountResult.Item!);
      console.log(`Found NATS account with status: ${account.status}`);
    }

    // 2. Delete NATS tokens (do this first to prevent new connections)
    const tokensResult = await deleteItemsByUserGuid(
      TABLE_NATS_TOKENS,
      userGuid,
      'token_id',
      true // use user-index
    );
    result.nats_tokens_deleted = tokensResult.count;
    if (tokensResult.error) {
      result.errors.push(`NatsTokens: ${tokensResult.error}`);
    }
    console.log(`Deleted ${tokensResult.count} NATS tokens`);

    // 3. Delete NATS account
    if (hasNatsAccount) {
      try {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_NATS_ACCOUNTS,
          Key: marshall({ user_guid: userGuid }),
        }));
        result.nats_account_deleted = true;
        console.log('Deleted NATS account');
      } catch (error: any) {
        result.errors.push(`NatsAccounts: ${error.message}`);
      }
    }

    // 4. Delete enrollment sessions
    const sessionsResult = await deleteItemsByUserGuid(
      TABLE_ENROLLMENT_SESSIONS,
      userGuid,
      'session_id',
      false // no index, need to scan
    );
    result.enrollment_sessions_deleted = sessionsResult.count;
    if (sessionsResult.error) {
      result.errors.push(`EnrollmentSessions: ${sessionsResult.error}`);
    }
    console.log(`Deleted ${sessionsResult.count} enrollment sessions`);

    // 5. Delete credential backup metadata
    // CredentialBackups uses member_guid as partition key (same as user_guid)
    if (TABLE_CREDENTIAL_BACKUPS) {
      try {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_CREDENTIAL_BACKUPS,
          Key: marshall({ member_guid: userGuid }),
        }));
        result.credential_backups_deleted = 1;
        console.log('Deleted credential backup record');
      } catch (error: any) {
        // Ignore if not found
        if (error.name !== 'ResourceNotFoundException') {
          result.errors.push(`CredentialBackups: ${error.message}`);
        }
      }
    }

    // 6. Delete profiles
    if (TABLE_PROFILES) {
      const profilesResult = await deleteItemsByUserGuid(
        TABLE_PROFILES,
        userGuid,
        'profile_id',
        false // no index
      );
      result.profiles_deleted = profilesResult.count;
      if (profilesResult.error) {
        result.errors.push(`Profiles: ${profilesResult.error}`);
      }
      console.log(`Deleted ${profilesResult.count} profiles`);
    }

    // 7. Delete VaultInstances record (this is what the portal checks)
    if (TABLE_VAULT_INSTANCES) {
      try {
        await ddb.send(new DeleteItemCommand({
          TableName: TABLE_VAULT_INSTANCES,
          Key: marshall({ user_guid: userGuid }),
        }));
        result.vault_instance_deleted = true;
        console.log('Deleted VaultInstances record');
      } catch (error: any) {
        // Ignore if not found
        if (error.name !== 'ResourceNotFoundException' && !error.message?.includes('does not exist')) {
          result.errors.push(`VaultInstances: ${error.message}`);
        }
      }
    }

    // 8. Reset registration status to allow re-enrollment
    if (TABLE_REGISTRATIONS) {
      try {
        // Find registration by user_guid (uses scan since registration_id is the key)
        const regResult = await ddb.send(new ScanCommand({
          TableName: TABLE_REGISTRATIONS,
          FilterExpression: 'user_guid = :guid',
          ExpressionAttributeValues: marshall({ ':guid': userGuid }),
          Limit: 1,
        }));

        if (regResult.Items && regResult.Items.length > 0) {
          const reg = unmarshall(regResult.Items[0]);
          // Reset enrollment_status to pending and remove vault-related fields
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_REGISTRATIONS,
            Key: marshall({ registration_id: reg.registration_id }),
            UpdateExpression: 'SET enrollment_status = :pending REMOVE vault_instance_id, vault_deployed_at',
            ExpressionAttributeValues: marshall({ ':pending': 'pending' }),
          }));
          result.registration_reset = true;
          console.log('Reset registration status to pending');
        }
      } catch (error: any) {
        result.errors.push(`Registrations: ${error.message}`);
      }
    }

    // 9. Delete S3 backup blobs
    if (BACKUP_BUCKET) {
      const s3Result = await deleteS3Objects(BACKUP_BUCKET, `${userGuid}/`);
      result.s3_objects_deleted = s3Result.count;
      if (s3Result.error) {
        result.errors.push(`S3: ${s3Result.error}`);
      }
      console.log(`Deleted ${s3Result.count} S3 objects`);
    }

    // 10. Delete credential from enclave via vault reset
    // This clears the credential from the enclave's SQLite storage
    try {
      const natsResult = await publishToNats('enclave.vault.reset', {
        user_guid: userGuid,
      });
      if (natsResult.success) {
        result.enclave_credential_deleted = true;
        console.log(`Sent vault reset to enclave for user: ${userGuid}`);
      } else {
        result.errors.push(`Enclave: ${natsResult.error || 'Failed to send vault reset'}`);
        console.error('Failed to send vault reset:', natsResult.error);
      }
    } catch (error: any) {
      result.errors.push(`Enclave: ${error.message}`);
      console.error('Error sending vault reset:', error);
    }

    // Audit log
    await putAudit({
      type: 'vault_decommissioned',
      user_guid: userGuid,
      decommissioned_by: adminEmail,
      result: {
        nats_account_deleted: result.nats_account_deleted,
        nats_tokens_deleted: result.nats_tokens_deleted,
        enrollment_sessions_deleted: result.enrollment_sessions_deleted,
        credential_backups_deleted: result.credential_backups_deleted,
        profiles_deleted: result.profiles_deleted,
        vault_instance_deleted: result.vault_instance_deleted,
        registration_reset: result.registration_reset,
        s3_objects_deleted: result.s3_objects_deleted,
        enclave_credential_deleted: result.enclave_credential_deleted,
      },
      errors: result.errors,
    });

    const hasErrors = result.errors.length > 0;
    const totalDeleted =
      (result.nats_account_deleted ? 1 : 0) +
      result.nats_tokens_deleted +
      result.enrollment_sessions_deleted +
      result.credential_backups_deleted +
      result.profiles_deleted +
      (result.vault_instance_deleted ? 1 : 0) +
      (result.registration_reset ? 1 : 0) +
      result.s3_objects_deleted +
      (result.enclave_credential_deleted ? 1 : 0);

    return ok({
      message: hasErrors
        ? `Vault decommissioned with ${result.errors.length} error(s)`
        : 'Vault successfully decommissioned',
      user_guid: userGuid,
      total_items_deleted: totalDeleted,
      details: result,
      warning: hasErrors ? 'Some operations failed - see errors' : undefined,
    });

  } catch (error: any) {
    console.error('Vault decommission error:', error);

    await putAudit({
      type: 'vault_decommission_error',
      user_guid: userGuid,
      error: error.message,
      decommissioned_by: adminEmail,
    });

    return internalError('Failed to decommission vault');
  }
};
