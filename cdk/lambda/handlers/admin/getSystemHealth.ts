import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { SESClient, GetSendQuotaCommand } from "@aws-sdk/client-ses";
import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";

const ses = new SESClient({});
const ddb = new DynamoDBClient({});
const cloudwatch = new CloudWatchClient({});

// Table names from environment variables (set by CDK)
const TABLE_NAMES: Record<string, string | undefined> = {
  'Invites': process.env.TABLE_INVITES,
  'Registrations': process.env.TABLE_REGISTRATIONS,
  'Audit': process.env.TABLE_AUDIT,
  'Waitlist': process.env.TABLE_WAITLIST,
  'MagicLinkTokens': process.env.TABLE_MAGIC_LINK_TOKENS,
  'MembershipTerms': process.env.TABLE_MEMBERSHIP_TERMS,
  'Subscriptions': process.env.TABLE_SUBSCRIPTIONS,
  'SubscriptionTypes': process.env.TABLE_SUBSCRIPTION_TYPES,
  'Proposals': process.env.TABLE_PROPOSALS,
  'Votes': process.env.TABLE_VOTES,
  'SentEmails': process.env.TABLE_SENT_EMAILS,
  'NotificationPreferences': process.env.TABLE_NOTIFICATION_PREFERENCES,
};

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
    // Fetch SES quota
    const sesQuota = await ses.send(new GetSendQuotaCommand({}));

    // Build list of tables to query from environment variables
    const tableEntries = Object.entries(TABLE_NAMES).filter(([_, tableName]) => tableName);

    let totalSize = 0;
    const tableSizes: Record<string, number> = {};
    const tableItemCounts: Record<string, number> = {};

    await Promise.all(tableEntries.map(async ([displayName, tableName]) => {
      try {
        const tableDesc = await ddb.send(new DescribeTableCommand({ TableName: tableName! }));
        const size = tableDesc.Table?.TableSizeBytes || 0;
        const itemCount = tableDesc.Table?.ItemCount || 0;
        tableSizes[displayName] = size;
        tableItemCounts[displayName] = itemCount;
        totalSize += size;
      } catch (error) {
        // Table might not exist, skip
        console.error(`Error describing table ${tableName}:`, error);
        tableSizes[displayName] = 0;
        tableItemCounts[displayName] = 0;
      }
    }));

    // Fetch Lambda errors in last 24 hours
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);

    let lambdaErrors = 0;
    try {
      const errorMetrics = await cloudwatch.send(new GetMetricStatisticsCommand({
        Namespace: 'AWS/Lambda',
        MetricName: 'Errors',
        StartTime: startTime,
        EndTime: endTime,
        Period: 86400, // 24 hours in seconds
        Statistics: ['Sum']
      }));

      if (errorMetrics.Datapoints && errorMetrics.Datapoints.length > 0) {
        lambdaErrors = errorMetrics.Datapoints[0].Sum || 0;
      }
    } catch (error) {
      console.error('Error fetching Lambda metrics:', error);
    }

    // Build response
    const response = {
      ses: {
        sent24h: sesQuota.SentLast24Hours || 0,
        limit: sesQuota.Max24HourSend || 0,
        maxSendRate: sesQuota.MaxSendRate || 0,
        percentUsed: sesQuota.Max24HourSend
          ? ((sesQuota.SentLast24Hours || 0) / sesQuota.Max24HourSend * 100).toFixed(1)
          : 0
      },
      dynamodb: {
        totalSize: totalSize,
        totalItems: Object.values(tableItemCounts).reduce((sum, count) => sum + count, 0),
        tables: tableSizes,
        tableItemCounts: tableItemCounts,
        tableCount: Object.keys(tableSizes).length
      },
      lambda: {
        errors24h: lambdaErrors
      },
      api: {
        status: 'healthy',
        timestamp: new Date().toISOString()
      }
    };

    // Log system health check
    await putAudit({
      type: 'system_health_check',
      details: {
        ses_quota_percent: response.ses.percentUsed,
        total_db_size: totalSize,
        lambda_errors: lambdaErrors
      }
    });

    return ok(response);
  } catch (error) {
    console.error('Error fetching system health:', error);

    await putAudit({
      type: 'system_health_check_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to fetch system health');
  }
};
