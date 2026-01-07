import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, internalError, requireAdminGroup, validateOrigin, putAudit, getAdminEmail } from "../../common/util";
import { DynamoDBClient, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { randomUUID } from "crypto";
import { publishVaultBroadcast } from "../../common/nats-publisher";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_BROADCASTS = process.env.TABLE_VAULT_BROADCASTS!;

// Broadcast types and their NATS subjects
const BROADCAST_TYPES = {
  system_announcement: 'Broadcast.system.announcement',
  security_alert: 'Broadcast.security.alert',
  admin_message: 'Broadcast.admin.message',
} as const;

type BroadcastType = keyof typeof BROADCAST_TYPES;

// Priority levels
const PRIORITIES = ['normal', 'high', 'critical'] as const;
type Priority = typeof PRIORITIES[number];

/**
 * Send a broadcast message to all active vaults
 *
 * Body:
 * - type: 'system_announcement' | 'security_alert' | 'admin_message'
 * - priority: 'normal' | 'high' | 'critical'
 * - title: Short title for the broadcast
 * - message: Full message content
 *
 * Priority levels:
 * - normal: Standard notification, shown when convenient
 * - high: Important notification, requires acknowledgment
 * - critical: Urgent notification, interrupts user flow
 */
export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  // Validate admin group membership
  const authError = requireAdminGroup(event);
  if (authError) {
    await putAudit({
      type: 'auth_failure_admin_access_denied',
      reason: 'insufficient_group_membership',
      path: event.rawPath
    });
    return authError;
  }

  // CSRF protection: Validate request origin
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  try {
    if (!event.body) {
      return badRequest('Request body is required');
    }

    const body = JSON.parse(event.body);
    const { type, priority, title, message } = body;
    const adminEmail = getAdminEmail(event);

    // Validate type
    if (!type || !Object.keys(BROADCAST_TYPES).includes(type)) {
      return badRequest(`Invalid type. Must be one of: ${Object.keys(BROADCAST_TYPES).join(', ')}`);
    }

    // Validate priority
    if (!priority || !PRIORITIES.includes(priority)) {
      return badRequest(`Invalid priority. Must be one of: ${PRIORITIES.join(', ')}`);
    }

    // Validate title
    if (!title || typeof title !== 'string' || title.trim().length < 3) {
      return badRequest('title is required and must be at least 3 characters');
    }

    if (title.length > 100) {
      return badRequest('title must be 100 characters or less');
    }

    // Validate message
    if (!message || typeof message !== 'string' || message.trim().length < 10) {
      return badRequest('message is required and must be at least 10 characters');
    }

    if (message.length > 2000) {
      return badRequest('message must be 2000 characters or less');
    }

    const broadcastId = `bcast-${randomUUID()}`;
    const natsSubject = BROADCAST_TYPES[type as BroadcastType];
    const now = new Date().toISOString();

    // Build the NATS message payload
    const natsPayload = {
      broadcast_id: broadcastId,
      type,
      priority,
      title: title.trim(),
      message: message.trim(),
      sent_at: now,
      sent_by: adminEmail,
    };

    // Record the broadcast in DynamoDB (initially queued)
    await ddb.send(new PutItemCommand({
      TableName: TABLE_VAULT_BROADCASTS,
      Item: marshall({
        broadcast_id: broadcastId,
        type,
        priority,
        title: title.trim(),
        message: message.trim(),
        nats_subject: natsSubject,
        sent_at: now,
        sent_by: adminEmail,
        delivery_status: 'sending',
        delivery_count: 0,
      })
    }));

    // Publish to NATS
    const publishResult = await publishVaultBroadcast(type, natsPayload);

    // Update delivery status based on publish result
    const deliveryStatus = publishResult.success ? 'delivered' : 'failed';
    const deliveredAt = publishResult.success ? new Date().toISOString() : undefined;

    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_VAULT_BROADCASTS,
      Key: marshall({ broadcast_id: broadcastId }),
      UpdateExpression: deliveredAt
        ? 'SET delivery_status = :status, delivered_at = :delivered_at'
        : 'SET delivery_status = :status, delivery_error = :error',
      ExpressionAttributeValues: marshall(
        deliveredAt
          ? { ':status': deliveryStatus, ':delivered_at': deliveredAt }
          : { ':status': deliveryStatus, ':error': publishResult.error || 'Unknown error' }
      ),
    }));

    // Audit log
    await putAudit({
      type: 'admin_vault_broadcast_sent',
      details: {
        broadcast_id: broadcastId,
        broadcast_type: type,
        priority,
        title: title.trim(),
        nats_subject: natsSubject,
        sent_by: adminEmail,
        delivery_status: deliveryStatus,
        nats_publish_success: publishResult.success,
        nats_error: publishResult.error,
      }
    });

    if (!publishResult.success) {
      // Return success but indicate delivery failed
      // This lets the admin know the broadcast was recorded but NATS publishing failed
      return ok({
        broadcast_id: broadcastId,
        type,
        priority,
        title: title.trim(),
        nats_subject: natsSubject,
        sent_at: now,
        sent_by: adminEmail,
        status: 'failed',
        error: publishResult.error,
        message: 'Broadcast recorded but NATS delivery failed. Will be retried.',
      });
    }

    return ok({
      broadcast_id: broadcastId,
      type,
      priority,
      title: title.trim(),
      nats_subject: natsSubject,
      sent_at: now,
      sent_by: adminEmail,
      status: 'delivered',
      message: 'Broadcast delivered to active vaults'
    });
  } catch (error) {
    console.error('Error sending vault broadcast:', error);

    await putAudit({
      type: 'admin_vault_broadcast_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to send vault broadcast');
  }
};
