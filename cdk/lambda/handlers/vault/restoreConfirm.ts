import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, UpdateItemCommand, QueryCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  notFound,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  generateSecureId,
  requireUserClaims,
} from '../../common/util';
import { generateLAT, hashLATToken } from '../../common/crypto-keys';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;
const TABLE_CREDENTIALS = process.env.TABLE_CREDENTIALS!;
const TABLE_LEDGER_AUTH_TOKENS = process.env.TABLE_LEDGER_AUTH_TOKENS!;
const TABLE_CREDENTIAL_BACKUPS = process.env.TABLE_CREDENTIAL_BACKUPS!;

interface ConfirmRequestBody {
  recovery_phrase?: string;
}

/**
 * POST /vault/credentials/restore/confirm
 *
 * Confirm credential restore after the 24-hour waiting period (for lost device recovery)
 * or immediately after approval (for device transfer).
 *
 * For lost device recovery: requires recovery_phrase
 * For device transfer: recovery_phrase is optional (approved by old device)
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

    // Parse request body
    let body: ConfirmRequestBody = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body) as ConfirmRequestBody;
      } catch {
        return badRequest('Invalid JSON in request body', origin);
      }
    }

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

    // For lost device recovery, require recovery phrase
    if (request.lost_device) {
      if (!body.recovery_phrase) {
        return badRequest('recovery_phrase is required for lost device recovery', origin);
      }

      // TODO: Verify recovery phrase against stored backup
      // For now, we'll check if a backup exists
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
        Limit: 1,
      }));

      if (!backupResult.Items || backupResult.Items.length === 0) {
        return badRequest('No backup found. Please contact support for recovery options.', origin);
      }

      // TODO: Verify recovery phrase cryptographically
      // This would involve decrypting the backup with the recovery phrase
    }

    // Create new credential
    const newCredentialId = generateSecureId('cred', 16);
    const lat = generateLAT(1);
    const latTokenHash = hashLATToken(lat.token);

    // Store new LAT
    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEDGER_AUTH_TOKENS,
      Item: marshall({
        token: latTokenHash,
        user_guid: memberGuid,
        version: lat.version,
        status: 'ACTIVE',
        created_at: now.toISOString(),
        source: 'restore',
      }, { removeUndefinedValues: true }),
    }));

    // Create new credential (will need enclave integration for full restore)
    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIALS,
      Item: marshall({
        user_guid: memberGuid,
        credential_id: newCredentialId,
        status: 'ACTIVE',
        storage_type: 'enclave',
        lat_version: lat.version,
        created_at: now.toISOString(),
        last_action_at: now.toISOString(),
        failed_auth_count: 0,
        restored_from: request.credential_id,
      }, { removeUndefinedValues: true }),
    }));

    // Mark old credential as superseded (if not already transferred)
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIALS,
      Key: marshall({ user_guid: memberGuid }),
      UpdateExpression: 'SET #status = :superseded WHERE credential_id = :oldCred',
      ConditionExpression: 'credential_id = :oldCred',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':superseded': 'SUPERSEDED',
        ':oldCred': request.credential_id,
      }),
    })).catch(() => {
      // Old credential may already be transferred/deleted
      console.log('Old credential already updated or not found');
    });

    // Mark restore request as completed
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Key: marshall({ recovery_id: request.recovery_id }),
      UpdateExpression: 'SET #status = :completed, completed_at = :now, new_credential_id = :newCred',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':completed': 'completed',
        ':now': now.toISOString(),
        ':newCred': newCredentialId,
      }),
    }));

    // Audit log
    await putAudit({
      type: 'credential_restored',
      member_guid: memberGuid,
      recovery_id: request.recovery_id,
      old_credential_id: request.credential_id,
      new_credential_id: newCredentialId,
      lost_device: request.lost_device,
    }, requestId);

    return ok({
      success: true,
      status: 'restored',
      new_credential_id: newCredentialId,
      ledger_auth_token: {
        token: lat.token,
        version: lat.version,
      },
      message: 'Credential has been restored successfully.',
    }, origin);

  } catch (error: any) {
    console.error('Confirm credential restore error:', error);
    return internalError('Failed to confirm credential restore', origin);
  }
};
