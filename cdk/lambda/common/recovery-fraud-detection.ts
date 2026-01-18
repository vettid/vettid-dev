/**
 * Recovery Fraud Detection
 *
 * Automatically cancels pending credential recovery requests if the original
 * credential is used during the 24-hour waiting period. This provides strong
 * protection against unauthorized recovery attempts.
 *
 * Detection Logic:
 * 1. On every credential usage (auth, vault operation), check for pending recovery
 * 2. Skip if same device (user testing their credential)
 * 3. Skip during 5-minute grace period (user may be testing after initiating)
 * 4. Auto-cancel recovery and notify user
 *
 * Integration:
 * - Call checkRecoveryFraud() from auth handlers after successful authentication
 * - Call from vault operation handlers after credential verification
 */

import { DynamoDBClient, QueryCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { publishRecoveryCancelled, publishRecoveryFraudDetected } from "./nats-publisher";
import { putAudit, nowIso } from "./util";

const ddb = new DynamoDBClient({});

const TABLE_RECOVERY_REQUESTS = process.env.TABLE_RECOVERY_REQUESTS!;

// Grace period: 5 minutes after recovery request
// Allows user to test if their credential still works after initiating recovery
const GRACE_PERIOD_MS = 5 * 60 * 1000;

/**
 * Result of fraud detection check
 */
export interface FraudCheckResult {
  fraudDetected: boolean;
  recoveryId?: string;
  reason?: string;
}

/**
 * Check for recovery fraud when a credential is used.
 *
 * Call this function after successful credential verification in:
 * - Authentication handlers
 * - Vault operation handlers
 * - Any credential-using endpoint
 *
 * @param userGuid - The user's GUID
 * @param deviceId - The device ID making the request (optional, for same-device check)
 * @returns FraudCheckResult indicating if fraud was detected and recovery cancelled
 */
export async function checkRecoveryFraud(
  userGuid: string,
  deviceId?: string
): Promise<FraudCheckResult> {
  try {
    // Query for pending recovery requests for this user
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid AND #status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':status': 'pending',
      }),
      Limit: 1,
    }));

    // No pending recovery - nothing to do
    if (!result.Items || result.Items.length === 0) {
      return { fraudDetected: false };
    }

    const recovery = unmarshall(result.Items[0]);
    const recoveryId = recovery.recovery_id;
    const requestedAt = new Date(recovery.requested_at).getTime();
    const now = Date.now();

    // Check grace period (5 minutes after request)
    // During grace period, don't cancel - user might be testing their credential
    if (now - requestedAt < GRACE_PERIOD_MS) {
      console.log(`Recovery ${recoveryId} within grace period, skipping fraud check`);
      return { fraudDetected: false };
    }

    // Same device check - don't cancel if same device that requested recovery
    // This allows the user to continue using their credential while waiting
    // (The recovery request device is tracked separately if available)
    if (deviceId && recovery.device_id === deviceId) {
      console.log(`Recovery ${recoveryId} same device, skipping fraud check`);
      return { fraudDetected: false };
    }

    // Fraud detected! Cancel the recovery
    const cancelledAt = nowIso();

    try {
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_RECOVERY_REQUESTS,
        Key: marshall({ recovery_id: recoveryId }),
        UpdateExpression: 'SET #status = :cancelled, cancelled_at = :now, cancellation_reason = :reason',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: marshall({
          ':cancelled': 'cancelled',
          ':now': cancelledAt,
          ':reason': 'credential_used_during_recovery',
          ':pending': 'pending',
        }),
        ConditionExpression: '#status = :pending',
      }));
    } catch (e: any) {
      if (e.name === 'ConditionalCheckFailedException') {
        // Recovery status already changed - not fraud
        return { fraudDetected: false };
      }
      throw e;
    }

    // Publish NATS events
    try {
      // Notify about cancellation
      await publishRecoveryCancelled(
        userGuid,
        recoveryId,
        'credential_used_during_recovery',
        cancelledAt
      );

      // Publish specific fraud detection alert
      await publishRecoveryFraudDetected(
        userGuid,
        recoveryId,
        'credential_used_during_recovery',
        cancelledAt
      );
    } catch (natsError) {
      console.error('Failed to publish fraud detection events:', natsError);
      // Continue even if NATS fails - the recovery is already cancelled
    }

    // Audit log
    await putAudit({
      action: 'recovery_fraud_detected',
      member_guid: userGuid,
      recovery_id: recoveryId,
      trigger_device_id: deviceId || 'unknown',
      reason: 'credential_used_during_recovery',
      cancelled_at: cancelledAt,
    });

    console.log(`SECURITY: Recovery fraud detected for user ${userGuid.substring(0, 8)}..., recovery ${recoveryId} cancelled`);

    return {
      fraudDetected: true,
      recoveryId,
      reason: 'credential_used_during_recovery',
    };

  } catch (error) {
    console.error('Error checking recovery fraud:', error);
    // Don't throw - fraud detection failure shouldn't block the operation
    return { fraudDetected: false };
  }
}

/**
 * Get pending recovery for a user (if any)
 *
 * Utility function for checking if user has active recovery without fraud detection
 *
 * @param userGuid - The user's GUID
 * @returns The pending recovery request or null
 */
export async function getPendingRecovery(userGuid: string): Promise<{
  recovery_id: string;
  requested_at: string;
  available_at: string;
  status: string;
} | null> {
  try {
    const result = await ddb.send(new QueryCommand({
      TableName: TABLE_RECOVERY_REQUESTS,
      IndexName: 'member-status-index',
      KeyConditionExpression: 'member_guid = :guid AND #status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':guid': userGuid,
        ':status': 'pending',
      }),
      Limit: 1,
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    const recovery = unmarshall(result.Items[0]);
    return {
      recovery_id: recovery.recovery_id,
      requested_at: recovery.requested_at,
      available_at: recovery.available_at,
      status: recovery.status,
    };
  } catch (error) {
    console.error('Error getting pending recovery:', error);
    return null;
  }
}
