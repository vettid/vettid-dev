import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_AUDIT = process.env.TABLE_AUDIT!;
const TABLE_CREDENTIAL_RECOVERY_REQUESTS = process.env.TABLE_CREDENTIAL_RECOVERY_REQUESTS!;
const TABLE_VAULT_DELETION_REQUESTS = process.env.TABLE_VAULT_DELETION_REQUESTS!;

// Security event types to filter for
const SECURITY_EVENT_TYPES = [
  'auth_failure_admin_access_denied',
  'auth_failure_invalid_token',
  'auth_failure_expired_token',
  'pin_failed',
  'pin_lockout',
  'login_failed',
  'password_reset_requested',
  'suspicious_activity',
  'rate_limit_exceeded',
  'invalid_invite_attempt',
  'registration_rejected',
  'user_disabled',
  'user_delete_failed',
  'enrollment_failed',
  'vault_auth_failed',
  'credential_recovery_requested',
  'credential_recovery_cancelled',
  'vault_deletion_requested',
  'vault_deletion_cancelled',
];

// Severity mapping for event types
const SEVERITY_MAP: Record<string, string> = {
  auth_failure_admin_access_denied: 'high',
  auth_failure_invalid_token: 'high',
  auth_failure_expired_token: 'medium',
  pin_failed: 'medium',
  pin_lockout: 'high',
  login_failed: 'low',
  password_reset_requested: 'low',
  suspicious_activity: 'critical',
  rate_limit_exceeded: 'medium',
  invalid_invite_attempt: 'medium',
  registration_rejected: 'low',
  user_disabled: 'high',
  user_delete_failed: 'medium',
  enrollment_failed: 'medium',
  vault_auth_failed: 'high',
  credential_recovery_requested: 'medium',
  credential_recovery_cancelled: 'low',
  vault_deletion_requested: 'high',
  vault_deletion_cancelled: 'medium',
};

/**
 * Get security events from audit log with metrics summary
 *
 * Query params:
 * - range: Time range filter (24h, 7d, 30d) - default 24h
 * - severity: Filter by severity (all, critical, high, medium, low) - default all
 * - limit: Maximum number of events to return (default 50, max 200)
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

  try {
    const range = event.queryStringParameters?.range || '24h';
    const severity = event.queryStringParameters?.severity || 'all';
    const limitParam = parseInt(event.queryStringParameters?.limit || '50', 10);
    const limit = Math.min(Math.max(1, limitParam), 200);

    // Calculate time range
    const now = Date.now();
    let startTime: number;
    switch (range) {
      case '7d':
        startTime = now - 7 * 24 * 60 * 60 * 1000;
        break;
      case '30d':
        startTime = now - 30 * 24 * 60 * 60 * 1000;
        break;
      case '24h':
      default:
        startTime = now - 24 * 60 * 60 * 1000;
        break;
    }

    // Filter event types by severity if specified
    let eventTypes = SECURITY_EVENT_TYPES;
    if (severity !== 'all') {
      eventTypes = SECURITY_EVENT_TYPES.filter(type => SEVERITY_MAP[type] === severity);
    }

    // Scan audit table and filter for security events
    // Note: In production, consider adding a GSI on type+timestamp for better performance
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_AUDIT,
      FilterExpression: 'createdAtTimestamp >= :startTime',
      ExpressionAttributeValues: marshall({ ':startTime': startTime }),
    }));

    // Filter and process events
    let events = (scanResult.Items || [])
      .map(item => unmarshall(item))
      .filter(item => eventTypes.includes(item.type))
      .sort((a, b) => (b.createdAtTimestamp || 0) - (a.createdAtTimestamp || 0))
      .slice(0, limit)
      .map(item => ({
        id: item.id,
        type: item.type,
        severity: SEVERITY_MAP[item.type] || 'low',
        timestamp: item.ts,
        email: item.email ? maskEmail(item.email) : null,
        path: item.path,
        reason: item.reason,
        details: item.details,
      }));

    // Calculate metrics summary
    const allEvents = (scanResult.Items || [])
      .map(item => unmarshall(item))
      .filter(item => SECURITY_EVENT_TYPES.includes(item.type));

    const metrics = {
      total_events: allEvents.length,
      critical: allEvents.filter(e => SEVERITY_MAP[e.type] === 'critical').length,
      high: allEvents.filter(e => SEVERITY_MAP[e.type] === 'high').length,
      medium: allEvents.filter(e => SEVERITY_MAP[e.type] === 'medium').length,
      low: allEvents.filter(e => SEVERITY_MAP[e.type] === 'low').length,
      auth_failures: allEvents.filter(e => e.type.startsWith('auth_failure')).length,
    };

    // Get pending counts from recovery and deletion tables
    const [recoveryResult, deletionResult] = await Promise.all([
      ddb.send(new ScanCommand({
        TableName: TABLE_CREDENTIAL_RECOVERY_REQUESTS,
        FilterExpression: '#s = :pending',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({ ':pending': 'pending' }),
        Select: 'COUNT',
      })),
      ddb.send(new ScanCommand({
        TableName: TABLE_VAULT_DELETION_REQUESTS,
        FilterExpression: '#s = :pending',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({ ':pending': 'pending' }),
        Select: 'COUNT',
      })),
    ]);

    return ok({
      events,
      count: events.length,
      metrics: {
        ...metrics,
        pending_recovery_requests: recoveryResult.Count || 0,
        pending_deletion_requests: deletionResult.Count || 0,
      },
      range,
      severity_filter: severity,
    });
  } catch (error) {
    console.error('Error fetching security events:', error);

    await putAudit({
      type: 'admin_get_security_events_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to fetch security events');
  }
};

/**
 * Mask email for privacy in logs (show first 2 chars and domain)
 */
function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  const masked = local.length > 2 ? local.substring(0, 2) + '***' : '***';
  return `${masked}@${domain}`;
}
