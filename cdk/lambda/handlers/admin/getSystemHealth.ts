import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, requireAdminGroup, putAudit } from "../../common/util";
import { SESClient, GetSendQuotaCommand } from "@aws-sdk/client-ses";
import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";

const ses = new SESClient({});
const ddb = new DynamoDBClient({});
const cloudwatch = new CloudWatchClient({});

const TABLE_PREFIX = process.env.TABLE_PREFIX || 'VettIDStack';

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

    // Fetch DynamoDB table sizes
    const tableNames = [
      `${TABLE_PREFIX}-Invites`,
      `${TABLE_PREFIX}-Registrations`,
      `${TABLE_PREFIX}-Audit`,
      `${TABLE_PREFIX}-Users`,
      `${TABLE_PREFIX}-Waitlist`,
      `${TABLE_PREFIX}-MembershipRequests`,
      `${TABLE_PREFIX}-Subscriptions`,
      `${TABLE_PREFIX}-SubscriptionTypes`,
      `${TABLE_PREFIX}-Proposals`,
      `${TABLE_PREFIX}-Votes`,
      `${TABLE_PREFIX}-Terms`,
      `${TABLE_PREFIX}-TermAcceptances`,
      `${TABLE_PREFIX}-RateLimits`,
      `${TABLE_PREFIX}-MagicLinks`,
      `${TABLE_PREFIX}-Exports`,
      `${TABLE_PREFIX}-Notifications`
    ];

    let totalSize = 0;
    const tableSizes: Record<string, number> = {};

    await Promise.all(tableNames.map(async (tableName) => {
      try {
        const tableDesc = await ddb.send(new DescribeTableCommand({ TableName: tableName }));
        const size = tableDesc.Table?.TableSizeBytes || 0;
        tableSizes[tableName] = size;
        totalSize += size;
      } catch (error) {
        // Table might not exist, skip
        tableSizes[tableName] = 0;
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
      dynamo: {
        totalSize: totalSize,
        tables: tableSizes,
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

    return {
      statusCode: 500,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        error: 'Failed to fetch system health',
        message: error instanceof Error ? error.message : String(error)
      })
    };
  }
};
