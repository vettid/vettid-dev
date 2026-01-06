import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, internalError, requireAdminGroup, putAudit } from "../../common/util";
import { SESClient, GetSendQuotaCommand } from "@aws-sdk/client-ses";
import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { CloudWatchClient, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import {
  ElasticLoadBalancingV2Client,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  AutoScalingClient,
  DescribeAutoScalingGroupsCommand,
  DescribeInstanceRefreshesCommand,
} from "@aws-sdk/client-auto-scaling";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const ses = new SESClient({});
const ddb = new DynamoDBClient({});
const cloudwatch = new CloudWatchClient({});
const elbv2 = new ElasticLoadBalancingV2Client({});
const autoscaling = new AutoScalingClient({});
const ssm = new SSMClient({});

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

    // Fetch NATS cluster health
    let natsHealth = {
      status: 'unknown' as 'healthy' | 'degraded' | 'unhealthy' | 'unknown',
      healthyNodes: 0,
      totalNodes: 0,
      nodes: [] as Array<{ id: string; status: string; ip?: string }>,
    };

    try {
      // Find the NATS target group by name pattern (CDK uses VettID-Nats prefix)
      const targetGroupsResult = await elbv2.send(new DescribeTargetGroupsCommand({}));
      const natsTargetGroup = targetGroupsResult.TargetGroups?.find(tg =>
        tg.TargetGroupName?.toLowerCase().includes('nats')
      );

      if (natsTargetGroup?.TargetGroupArn) {
        // Get health of all targets in the group
        const healthResult = await elbv2.send(new DescribeTargetHealthCommand({
          TargetGroupArn: natsTargetGroup.TargetGroupArn,
        }));

        const targets = healthResult.TargetHealthDescriptions || [];
        natsHealth.totalNodes = targets.length;
        natsHealth.healthyNodes = targets.filter(t => t.TargetHealth?.State === 'healthy').length;

        natsHealth.nodes = targets.map(t => ({
          id: t.Target?.Id || 'unknown',
          status: t.TargetHealth?.State || 'unknown',
          ip: t.Target?.Id, // For EC2 targets, Id is the instance ID
        }));

        // Determine overall status
        if (natsHealth.healthyNodes === natsHealth.totalNodes && natsHealth.totalNodes > 0) {
          natsHealth.status = 'healthy';
        } else if (natsHealth.healthyNodes > 0) {
          natsHealth.status = 'degraded';
        } else if (natsHealth.totalNodes > 0) {
          natsHealth.status = 'unhealthy';
        }
      }
    } catch (natsError) {
      console.error('Error fetching NATS health:', natsError);
      // Keep default 'unknown' status
    }

    // Fetch Nitro Enclave ASG health
    let nitroHealth = {
      status: 'unknown' as 'healthy' | 'degraded' | 'unhealthy' | 'unknown',
      desiredCapacity: 0,
      runningInstances: 0,
      healthyInstances: 0,
      currentAmi: '',
      latestAmi: '',
      amiUpToDate: false,
      instanceRefresh: null as null | {
        status: string;
        percentComplete: number;
        startTime?: string;
      },
    };

    try {
      // Find the Nitro enclave ASG by name pattern
      const asgResult = await autoscaling.send(new DescribeAutoScalingGroupsCommand({}));
      const nitroAsg = asgResult.AutoScalingGroups?.find(asg =>
        asg.AutoScalingGroupName?.toLowerCase().includes('nitro') ||
        asg.AutoScalingGroupName?.toLowerCase().includes('enclave') ||
        asg.AutoScalingGroupName?.toLowerCase().includes('vaultinfra')
      );

      if (nitroAsg) {
        nitroHealth.desiredCapacity = nitroAsg.DesiredCapacity || 0;

        // Count instances by health status
        const instances = nitroAsg.Instances || [];
        nitroHealth.runningInstances = instances.filter(i =>
          i.LifecycleState === 'InService' || i.LifecycleState === 'Pending'
        ).length;
        nitroHealth.healthyInstances = instances.filter(i =>
          i.HealthStatus === 'Healthy' && i.LifecycleState === 'InService'
        ).length;

        // Get the current AMI from launch template or launch configuration
        if (nitroAsg.LaunchTemplate?.LaunchTemplateId) {
          // AMI is in launch template - would need additional API call
          // For now, get from first running instance
          const runningInstance = instances.find(i => i.LifecycleState === 'InService');
          if (runningInstance?.InstanceId) {
            // Instance ID available - AMI would need EC2 DescribeInstances call
            // Instead, check SSM parameter for current deployed AMI
            try {
              const currentAmiParam = await ssm.send(new GetParameterCommand({
                Name: '/vettid/nitro-enclave/current-ami',
              }));
              nitroHealth.currentAmi = currentAmiParam.Parameter?.Value || '';
            } catch {
              // Parameter might not exist
            }
          }
        }

        // Get latest available AMI from SSM parameter (set by Packer builds)
        try {
          const latestAmiParam = await ssm.send(new GetParameterCommand({
            Name: '/vettid/nitro-enclave/latest-ami',
          }));
          nitroHealth.latestAmi = latestAmiParam.Parameter?.Value || '';
        } catch {
          // Parameter might not exist
        }

        // Check if current AMI matches latest
        nitroHealth.amiUpToDate = nitroHealth.currentAmi !== '' &&
          nitroHealth.currentAmi === nitroHealth.latestAmi;

        // Check for active instance refresh
        try {
          const refreshResult = await autoscaling.send(new DescribeInstanceRefreshesCommand({
            AutoScalingGroupName: nitroAsg.AutoScalingGroupName,
            MaxRecords: 1,
          }));

          const latestRefresh = refreshResult.InstanceRefreshes?.[0];
          if (latestRefresh) {
            // Only show if in progress or recently completed (within last hour)
            const isRecent = latestRefresh.StartTime &&
              (Date.now() - latestRefresh.StartTime.getTime()) < 60 * 60 * 1000;
            const isActive = latestRefresh.Status === 'InProgress' ||
              latestRefresh.Status === 'Pending';

            if (isActive || isRecent) {
              nitroHealth.instanceRefresh = {
                status: latestRefresh.Status || 'unknown',
                percentComplete: latestRefresh.PercentageComplete || 0,
                startTime: latestRefresh.StartTime?.toISOString(),
              };
            }
          }
        } catch (refreshError) {
          console.error('Error fetching instance refresh:', refreshError);
        }

        // Determine overall status
        if (nitroHealth.healthyInstances >= nitroHealth.desiredCapacity && nitroHealth.desiredCapacity > 0) {
          nitroHealth.status = 'healthy';
        } else if (nitroHealth.healthyInstances > 0) {
          nitroHealth.status = 'degraded';
        } else if (nitroHealth.desiredCapacity > 0) {
          nitroHealth.status = 'unhealthy';
        }
      }
    } catch (nitroError) {
      console.error('Error fetching Nitro ASG health:', nitroError);
      // Keep default 'unknown' status
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
      },
      nats: natsHealth,
      nitro: nitroHealth
    };

    // Log system health check
    await putAudit({
      type: 'system_health_check',
      details: {
        ses_quota_percent: response.ses.percentUsed,
        total_db_size: totalSize,
        lambda_errors: lambdaErrors,
        nats_status: natsHealth.status,
        nats_healthy_nodes: natsHealth.healthyNodes,
        nats_total_nodes: natsHealth.totalNodes,
        nitro_status: nitroHealth.status,
        nitro_healthy_instances: nitroHealth.healthyInstances,
        nitro_desired_capacity: nitroHealth.desiredCapacity,
        nitro_ami_up_to_date: nitroHealth.amiUpToDate,
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
