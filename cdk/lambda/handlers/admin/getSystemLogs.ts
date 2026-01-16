import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, forbidden, requireAdminGroup, putAudit } from "../../common/util";
import { CloudWatchLogsClient, DescribeLogGroupsCommand, FilterLogEventsCommand, LogGroup } from "@aws-sdk/client-cloudwatch-logs";

const logs = new CloudWatchLogsClient({});

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 20; // SECURITY: Reduced from 50 for better performance

// VettID-specific log group prefixes
const VETTID_LOG_PREFIXES = [
  '/aws/lambda/VettID-Admin',
  '/aws/lambda/VettID-Infrastructure',
  '/aws/lambda/VettID-Vault',
  '/aws/lambda/VettIDStack',
];

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

  // SECURITY: Restrict to full admins only (admin_type='admin')
  const adminType = (event.requestContext as any)?.authorizer?.jwt?.claims?.['custom:admin_type'];
  if (adminType !== 'admin') {
    await putAudit({
      type: 'unauthorized_system_logs_access_attempt',
      admin_type: adminType,
      path: event.rawPath
    });
    return forbidden('Insufficient privileges to access system logs');
  }

  try {
    const source = event.queryStringParameters?.source || 'all';
    const requestedLimit = Number(event.queryStringParameters?.limit || DEFAULT_LIMIT);
    const limit = Math.min(Math.max(1, requestedLimit), MAX_LIMIT);

    // Get VettID Lambda log groups - fetch from multiple prefixes
    let allLogGroups: LogGroup[] = [];

    for (const prefix of VETTID_LOG_PREFIXES) {
      const result = await logs.send(new DescribeLogGroupsCommand({
        logGroupNamePrefix: prefix,
        limit: 50  // Get up to 50 log groups per prefix
      }));
      if (result.logGroups) {
        allLogGroups = allLogGroups.concat(result.logGroups);
      }
    }

    const logEntries: any[] = [];

    // Filter log groups based on source parameter
    let targetLogGroups = allLogGroups;
    if (source === 'api') {
      // API Gateway logs (if configured)
      const apiLogGroups = await logs.send(new DescribeLogGroupsCommand({
        logGroupNamePrefix: '/aws/apigateway/'
      }));
      targetLogGroups = apiLogGroups.logGroups || [];
    }

    // Sort log groups by last event time (most recent first) and take top 20
    targetLogGroups.sort((a, b) => (b.creationTime || 0) - (a.creationTime || 0));
    const recentLogGroups = targetLogGroups.slice(0, 20);

    // Fetch recent log events from each log group
    const endTime = Date.now();
    const startTime = endTime - (24 * 60 * 60 * 1000); // Last 24 hours

    await Promise.all(
      recentLogGroups.map(async (logGroup: LogGroup) => {
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

    return ok({ logs: limitedLogs });
  } catch (error) {
    console.error('Error fetching system logs:', error);

    await putAudit({
      type: 'system_logs_access_error',
      error: error instanceof Error ? error.message : String(error)
    });

    return internalError('Failed to fetch system logs');
  }
};
