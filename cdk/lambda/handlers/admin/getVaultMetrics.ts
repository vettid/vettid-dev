import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { DynamoDBClient, ScanCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const ddb = new DynamoDBClient({});

const TABLE_VAULT_INSTANCES = process.env.TABLE_VAULT_INSTANCES!;
const TABLE_ENROLLMENT_SESSIONS = process.env.TABLE_ENROLLMENT_SESSIONS!;
const TABLE_REGISTRATIONS = process.env.TABLE_REGISTRATIONS!;

/**
 * Get vault enrollment metrics for admin dashboard
 *
 * Returns:
 * - Total enrolled users
 * - Active vaults (currently connected)
 * - Pending enrollments
 * - Enrollment rate (enrolled / total approved users)
 * - Enrollment outcomes (last 30 days): success, failed, abandoned
 * - Vault status distribution: active, idle, offline, suspended, deleted
 * - Recent enrollments (last 10)
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
    // Calculate date 30 days ago
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const thirtyDaysAgoStr = thirtyDaysAgo.toISOString();

    // Parallel queries for metrics
    const [
      vaultInstancesResult,
      enrollmentSessionsResult,
      approvedUsersResult,
    ] = await Promise.all([
      // Get all vault instances
      ddb.send(new ScanCommand({
        TableName: TABLE_VAULT_INSTANCES,
        ProjectionExpression: 'user_guid, #s, created_at, last_seen_at',
        ExpressionAttributeNames: { '#s': 'status' },
      })),
      // Get enrollment sessions from last 30 days
      ddb.send(new ScanCommand({
        TableName: TABLE_ENROLLMENT_SESSIONS,
        FilterExpression: 'created_at >= :thirtyDaysAgo',
        ExpressionAttributeValues: marshall({
          ':thirtyDaysAgo': thirtyDaysAgo.getTime(),
        }),
        ProjectionExpression: 'session_id, user_guid, #s, created_at, completed_at, email',
        ExpressionAttributeNames: { '#s': 'status' },
      })),
      // Count approved registrations for enrollment rate calculation
      ddb.send(new QueryCommand({
        TableName: TABLE_REGISTRATIONS,
        IndexName: 'status-index',
        KeyConditionExpression: '#s = :approved',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({ ':approved': 'approved' }),
        Select: 'COUNT',
      })),
    ]);

    const vaultInstances = (vaultInstancesResult.Items || []).map(item => unmarshall(item));
    const enrollmentSessions = (enrollmentSessionsResult.Items || []).map(item => unmarshall(item));
    const totalApprovedUsers = approvedUsersResult.Count || 0;

    // Calculate vault status distribution (Nitro model)
    // In Nitro architecture, vaults are stateless enclaves - we track enrollment/account states
    const statusDistribution: Record<string, number> = {
      active: 0,      // Successfully enrolled, operational
      suspended: 0,   // Admin-suspended account
      deleted: 0,     // Vault has been deleted
    };

    for (const vault of vaultInstances) {
      const status = (vault.status as string || '').toLowerCase();
      // Map various status values to our simplified model
      if (status === 'active' || status === 'connected' || status === 'enrolled' || status === 'running' || status === 'healthy') {
        statusDistribution.active++;
      } else if (status === 'suspended' || status === 'disabled') {
        statusDistribution.suspended++;
      } else if (status === 'deleted' || status === 'removed') {
        statusDistribution.deleted++;
      } else {
        // Unknown/other status - count as active (default operational state)
        statusDistribution.active++;
      }
    }

    // Calculate enrollment outcomes (last 30 days)
    const enrollmentOutcomes = {
      success: 0,
      failed: 0,
      abandoned: 0,
      pending: 0,
    };

    for (const session of enrollmentSessions) {
      // Note: Status values are UPPERCASE in the enrollment system
      const status = (session.status as string || '').toUpperCase();
      switch (status) {
        case 'COMPLETED':
        case 'FINALIZED':
          enrollmentOutcomes.success++;
          break;
        case 'FAILED':
        case 'ERROR':
          enrollmentOutcomes.failed++;
          break;
        case 'EXPIRED':
        case 'CANCELLED':
          enrollmentOutcomes.abandoned++;
          break;
        case 'PENDING':
        case 'WEB_INITIATED':
        case 'AUTHENTICATED':
        case 'STARTED':
        case 'PASSWORD_SET':
          enrollmentOutcomes.pending++;
          break;
        default:
          // Unknown status - count as pending if session exists
          if (status) enrollmentOutcomes.pending++;
          break;
      }
    }

    // Get recent enrollments (last 10 completed)
    interface EnrollmentSession {
      session_id?: string;
      user_guid?: string;
      status?: string;
      created_at?: number | string;
      completed_at?: number | string;
      email?: string;
    }

    // Helper to normalize date values to timestamp (handles both ISO strings and numbers)
    const toTimestamp = (val: number | string | undefined): number => {
      if (!val) return 0;
      if (typeof val === 'number') return val;
      return new Date(val).getTime() || 0;
    };

    // Filter for completed enrollments (uppercase status values)
    const recentEnrollments = (enrollmentSessions as EnrollmentSession[])
      .filter((s: EnrollmentSession) => {
        const status = (s.status || '').toUpperCase();
        return status === 'COMPLETED' || status === 'FINALIZED';
      })
      .sort((a: EnrollmentSession, b: EnrollmentSession) => {
        // Sort by completed_at descending (most recent first), fallback to created_at
        const aTime = toTimestamp(a.completed_at) || toTimestamp(a.created_at);
        const bTime = toTimestamp(b.completed_at) || toTimestamp(b.created_at);
        return bTime - aTime;
      })
      .slice(0, 10)
      .map((s: EnrollmentSession) => {
        const completedTs = toTimestamp(s.completed_at);
        const createdTs = toTimestamp(s.created_at);
        return {
          user_guid: s.user_guid || '',
          email: s.email || '',
          completed_at: completedTs ? new Date(completedTs).toISOString() : null,
          created_at: createdTs ? new Date(createdTs).toISOString() : '',
        };
      });

    // Calculate key metrics
    const totalEnrolled = vaultInstances.length;
    const activeVaults = statusDistribution.active;
    const pendingEnrollments = enrollmentOutcomes.pending;
    const enrollmentRate = totalApprovedUsers > 0
      ? ((totalEnrolled / totalApprovedUsers) * 100).toFixed(1)
      : '0.0';

    const response = {
      key_metrics: {
        total_enrolled: totalEnrolled,
        active_vaults: activeVaults,
        pending_enrollments: pendingEnrollments,
        total_approved_users: totalApprovedUsers,
        enrollment_rate_percent: parseFloat(enrollmentRate),
      },
      enrollment_outcomes_30d: enrollmentOutcomes,
      vault_status_distribution: statusDistribution,
      recent_enrollments: recentEnrollments,
      generated_at: new Date().toISOString(),
    };

    // Log metrics query
    await putAudit({
      type: 'admin_vault_metrics_query',
      details: {
        total_enrolled: totalEnrolled,
        active_vaults: activeVaults,
        enrollment_rate: enrollmentRate,
      }
    });

    return ok(response);
  } catch (error) {
    console.error('Error fetching vault metrics:', error);

    await putAudit({
      type: 'admin_vault_metrics_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to fetch vault metrics');
  }
};
