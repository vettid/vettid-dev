import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand, QueryCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import {
  ok,
  badRequest,
  conflict,
  internalError,
  getRequestId,
  putAudit,
  generateSecureId,
  requireUserClaims,
} from '../../common/util';

const ddb = new DynamoDBClient({});

const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;
const TABLE_NATS_ACCOUNTS = process.env.TABLE_NATS_ACCOUNTS!;

// 24 hours in milliseconds
const RECOVERY_DELAY_MS = 24 * 60 * 60 * 1000;
// TTL: 7 days after ready_at
const TTL_DAYS = 7;

interface RestoreRequestBody {
  lost_device?: boolean;
}

/**
 * POST /vault/credentials/restore/request
 *
 * Request credential restore. Two flows:
 * 1. Transfer (lost_device=false): Sends push notification to active device for approval
 * 2. Recovery (lost_device=true): Starts 24-hour waiting period
 *
 * If the credential is used during a recovery waiting period, the request is auto-cancelled.
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
    let body: RestoreRequestBody = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body) as RestoreRequestBody;
      } catch {
        return badRequest('Invalid JSON in request body', origin);
      }
    }

    const lostDevice = body.lost_device === true;

    // Check if user has a NATS account (vault)
    // In the Nitro model, having a NATS account means the user has a vault
    const natsAccountResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_NATS_ACCOUNTS,
      Key: marshall({ user_guid: memberGuid }),
    }));

    if (!natsAccountResult.Item) {
      return badRequest('No vault found. Please enroll first.', origin);
    }

    const natsAccount = unmarshall(natsAccountResult.Item);

    // Check for existing pending restore request
    const existingRequest = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid AND #status = :pending',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending': lostDevice ? 'pending_timer' : 'pending_approval',
      }),
      Limit: 1,
    }));

    if (existingRequest.Items && existingRequest.Items.length > 0) {
      return conflict('A restore request is already pending', origin);
    }

    // Also check for any other pending state
    const anyPendingRequest = await ddb.send(new QueryCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid',
      FilterExpression: '#status IN (:pending_timer, :pending_approval, :ready)',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': memberGuid,
        ':pending_timer': 'pending_timer',
        ':pending_approval': 'pending_approval',
        ':ready': 'ready',
      }),
      Limit: 1,
    }));

    if (anyPendingRequest.Items && anyPendingRequest.Items.length > 0) {
      return conflict('A restore request is already pending', origin);
    }

    // Create the restore request
    const now = new Date();
    const recoveryId = generateSecureId('rcv', 16);

    let status: string;
    let readyAt: Date | null = null;
    let ttl: number;

    if (lostDevice) {
      // Recovery flow: 24-hour waiting period
      status = 'pending_timer';
      readyAt = new Date(now.getTime() + RECOVERY_DELAY_MS);
      ttl = Math.floor(readyAt.getTime() / 1000) + (TTL_DAYS * 24 * 60 * 60);
    } else {
      // Transfer flow: waiting for device approval
      status = 'pending_approval';
      // TTL: 24 hours from now (approval window)
      ttl = Math.floor(now.getTime() / 1000) + (24 * 60 * 60) + (TTL_DAYS * 24 * 60 * 60);
    }

    const item: Record<string, any> = {
      recovery_id: recoveryId,
      member_guid: memberGuid,
      nats_account_public_key: natsAccount.account_public_key,
      status,
      lost_device: lostDevice,
      requested_at: now.toISOString(),
      ttl,
    };

    if (readyAt) {
      item.ready_at = readyAt.toISOString();
    }

    await ddb.send(new PutItemCommand({
      TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
      Item: marshall(item, { removeUndefinedValues: true }),
    }));

    // If transfer flow, send push notification to device via NATS
    // TODO: Implement NATS push notification
    if (!lostDevice) {
      console.log(`TODO: Send push notification to device for member ${memberGuid}`);
    }

    // Audit log
    await putAudit({
      type: 'credential_restore_requested',
      member_guid: memberGuid,
      recovery_id: recoveryId,
      lost_device: lostDevice,
      nats_account_public_key: natsAccount.account_public_key,
    }, requestId);

    const response: Record<string, any> = {
      recovery_id: recoveryId,
      status,
      requested_at: now.toISOString(),
      lost_device: lostDevice,
    };

    if (lostDevice) {
      response.ready_at = readyAt!.toISOString();
      response.message = 'Recovery request created. You can complete recovery after the 24-hour security delay.';
    } else {
      response.message = 'Transfer request sent. Please approve on your current device.';
      response.waiting_for_approval = true;
    }

    return ok(response, origin);

  } catch (error: any) {
    console.error('Credential restore request error:', error);
    return internalError('Failed to request credential restore', origin);
  }
};
