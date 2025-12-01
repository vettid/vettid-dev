import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, requireAdminGroup, putAudit } from "../../common/util";
import { CloudWatchLogsClient, DescribeLogGroupsCommand, FilterLogEventsCommand, LogGroup } from "@aws-sdk/client-cloudwatch-logs";

const logs = new CloudWatchLogsClient({});

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

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
    const source = event.queryStringParameters?.source || 'all';
    const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
    const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);

    // Get all Lambda log groups
    const logGroupsResult = await logs.send(new DescribeLogGroupsCommand({
      logGroupNamePrefix: '/aws/lambda/'
    }));

    const logGroups = logGroupsResult.logGroups || [];
    const logEntries: any[] = [];

    // Filter log groups based on source parameter
    let targetLogGroups = logGroups;
    if (source === 'lambda') {
      targetLogGroups = logGroups.filter((lg: LogGroup) => lg.logGroupName?.includes('/aws/lambda/'));
    } else if (source === 'api') {
      // API Gateway logs (if configured)
      const apiLogGroups = await logs.send(new DescribeLogGroupsCommand({
        logGroupNamePrefix: '/aws/apigateway/'
      }));
      targetLogGroups = apiLogGroups.logGroups || [];
    }

    // Fetch recent log events from each log group
    const endTime = Date.now();
    const startTime = endTime - (24 * 60 * 60 * 1000); // Last 24 hours

    await Promise.all(
      targetLogGroups.slice(0, 10).map(async (logGroup: LogGroup) => {
        if (!logGroup.logGroupName) return;

        try {
          const filterParams: any = {
            logGroupName: logGroup.logGroupName,
            startTime: startTime,
            endTime: endTime,
            limit: 10
          };

          // Filter for errors if requested
          if (source === 'errors') {
            filterParams.filterPattern = '?ERROR ?Error ?error ?WARN ?Warning';
          }

          const eventsResult = await logs.send(new FilterLogEventsCommand(filterParams));

          if (eventsResult.events) {
            eventsResult.events.forEach((event: any) => {
              logEntries.push({
                timestamp: event.timestamp || 0,
                source: logGroup.logGroupName,
                message: event.message || '',
                logStream: event.logStreamName || ''
              });
            });
          }
        } catch (error) {
          console.error(`Error fetching logs from ${logGroup.logGroupName}:`, error);
        }
      })
    );

    // Sort by timestamp (most recent first) and limit results
    logEntries.sort((a, b) => b.timestamp - a.timestamp);
    const limitedLogs = logEntries.slice(0, limit);

    // Log the system logs access
    await putAudit({
      type: 'system_logs_access',
      details: {
        source: source,
        limit: limit,
        entries_returned: limitedLogs.length
      }
    });

    return ok(limitedLogs);
  } catch (error) {
    console.error('Error fetching system logs:', error);

    await putAudit({
      type: 'system_logs_access_error',
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
        error: 'Failed to fetch system logs',
        message: error instanceof Error ? error.message : String(error)
      })
    };
  }
};
