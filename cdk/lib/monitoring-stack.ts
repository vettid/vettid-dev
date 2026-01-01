/**
 * VettID Monitoring Stack
 *
 * Creates CloudWatch dashboards and alarms for operational visibility:
 * - Lambda error rates and performance
 * - DynamoDB throttling and capacity
 * - NATS cluster health
 * - Vault provisioning status
 */

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';

export interface MonitoringStackProps extends cdk.StackProps {
  /** Email address for alarm notifications */
  alarmEmail?: string;
}

export class MonitoringStack extends cdk.Stack {
  public readonly dashboard: cloudwatch.Dashboard;
  public readonly alarmTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: MonitoringStackProps = {}) {
    super(scope, id, props);

    // SNS topic for alarm notifications
    this.alarmTopic = new sns.Topic(this, 'AlarmTopic', {
      displayName: 'VettID Monitoring Alarms',
    });

    // Add email subscription if provided
    if (props.alarmEmail) {
      this.alarmTopic.addSubscription(
        new subscriptions.EmailSubscription(props.alarmEmail)
      );
    }

    // Create the main dashboard
    this.dashboard = new cloudwatch.Dashboard(this, 'OperationalDashboard', {
      dashboardName: 'VettID-Operations',
    });

    // ===============================
    // Lambda Error Monitoring
    // ===============================
    this.addLambdaMonitoring();

    // ===============================
    // DynamoDB Monitoring
    // ===============================
    this.addDynamoDBMonitoring();

    // ===============================
    // NATS Cluster Monitoring
    // ===============================
    this.addNatsMonitoring();

    // ===============================
    // Vault Provisioning Monitoring
    // ===============================
    this.addVaultMonitoring();
  }

  private addLambdaMonitoring(): void {
    // Lambda error rate widget - shows errors across all VettID functions
    const lambdaErrorWidget = new cloudwatch.GraphWidget({
      title: 'Lambda Errors (All Functions)',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/Lambda,FunctionName} MetricName="Errors"\', \'Sum\', 60)',
          label: 'Errors',
          usingMetrics: {},
        }),
      ],
    });

    // Lambda invocation count widget
    const lambdaInvocationsWidget = new cloudwatch.GraphWidget({
      title: 'Lambda Invocations',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/Lambda,FunctionName} MetricName="Invocations"\', \'Sum\', 60)',
          label: 'Invocations',
          usingMetrics: {},
        }),
      ],
    });

    // Lambda duration widget
    const lambdaDurationWidget = new cloudwatch.GraphWidget({
      title: 'Lambda Duration (p95)',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/Lambda,FunctionName} MetricName="Duration"\', \'p95\', 60)',
          label: 'Duration p95',
          usingMetrics: {},
        }),
      ],
    });

    // Lambda throttles widget
    const lambdaThrottlesWidget = new cloudwatch.GraphWidget({
      title: 'Lambda Throttles',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/Lambda,FunctionName} MetricName="Throttles"\', \'Sum\', 60)',
          label: 'Throttles',
          usingMetrics: {},
        }),
      ],
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Lambda Functions',
        width: 24,
        height: 1,
      })
    );
    this.dashboard.addWidgets(lambdaErrorWidget, lambdaInvocationsWidget);
    this.dashboard.addWidgets(lambdaDurationWidget, lambdaThrottlesWidget);

    // Create alarm for Lambda error rate > 5%
    // This requires creating individual alarms per function, so we'll monitor key functions
    const criticalFunctions = [
      'VettID-Vault-EnrollStartFn',
      'VettID-Vault-EnrollSetPasswordFn',
      'VettID-Vault-EnrollFinalizeFn',
      'VettID-Vault-ActionRequestFn',
      'VettID-Vault-AuthExecuteFn',
    ];

    criticalFunctions.forEach((functionName) => {
      const errorMetric = new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Errors',
        dimensionsMap: { FunctionName: functionName },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      });

      const invocationMetric = new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Invocations',
        dimensionsMap: { FunctionName: functionName },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      });

      const errorRateAlarm = new cloudwatch.Alarm(this, `${functionName}ErrorRate`, {
        metric: new cloudwatch.MathExpression({
          expression: 'IF(invocations > 0, errors / invocations * 100, 0)',
          usingMetrics: {
            errors: errorMetric,
            invocations: invocationMetric,
          },
          period: cdk.Duration.minutes(5),
        }),
        threshold: 5, // 5% error rate
        evaluationPeriods: 2,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        alarmDescription: `Lambda ${functionName} error rate > 5%`,
        alarmName: `VettID-${functionName}-ErrorRate`,
      });

      errorRateAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));
    });
  }

  private addDynamoDBMonitoring(): void {
    // DynamoDB tables to monitor
    const tables = [
      'VettID-Infrastructure-InvitesTable',
      'VettID-Infrastructure-RegistrationsTable',
      'VettID-Infrastructure-AuditTable',
      'VettID-Infrastructure-EnrollmentSessions',
      'VettID-Infrastructure-ActionTokens',
    ];

    // Throttled requests widget
    const throttlesWidget = new cloudwatch.GraphWidget({
      title: 'DynamoDB Throttled Requests',
      width: 12,
      height: 6,
      left: tables.map(
        (table) =>
          new cloudwatch.Metric({
            namespace: 'AWS/DynamoDB',
            metricName: 'ThrottledRequests',
            dimensionsMap: { TableName: table },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          })
      ),
    });

    // Consumed capacity widget
    const capacityWidget = new cloudwatch.GraphWidget({
      title: 'DynamoDB Consumed Read/Write Capacity',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/DynamoDB,TableName} MetricName="ConsumedReadCapacityUnits"\', \'Sum\', 60)',
          label: 'Read Capacity',
          usingMetrics: {},
        }),
      ],
      right: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/DynamoDB,TableName} MetricName="ConsumedWriteCapacityUnits"\', \'Sum\', 60)',
          label: 'Write Capacity',
          usingMetrics: {},
        }),
      ],
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# DynamoDB',
        width: 24,
        height: 1,
      })
    );
    this.dashboard.addWidgets(throttlesWidget, capacityWidget);

    // Create alarm for DynamoDB throttling
    tables.forEach((table) => {
      const throttleAlarm = new cloudwatch.Alarm(this, `${table}Throttle`, {
        metric: new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'ThrottledRequests',
          dimensionsMap: { TableName: table },
          statistic: 'Sum',
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 2,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        alarmDescription: `DynamoDB table ${table} is being throttled`,
        alarmName: `VettID-DynamoDB-${table.split('-').pop()}-Throttle`,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });

      throttleAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));
    });
  }

  private addNatsMonitoring(): void {
    // NATS EC2 instance metrics
    // These metrics come from CloudWatch agent on NATS instances

    const natsStatusWidget = new cloudwatch.GraphWidget({
      title: 'NATS Cluster - Instance Status',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/EC2',
          metricName: 'StatusCheckFailed',
          dimensionsMap: { AutoScalingGroupName: 'VettID-NATS-ASG' },
          statistic: 'Maximum',
          period: cdk.Duration.minutes(1),
        }),
      ],
    });

    const natsCpuWidget = new cloudwatch.GraphWidget({
      title: 'NATS Cluster - CPU Utilization',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-NATS" MetricName="CPUUtilization"\', \'Average\', 60)',
          label: 'CPU %',
          usingMetrics: {},
        }),
      ],
    });

    const natsNetworkWidget = new cloudwatch.GraphWidget({
      title: 'NATS Cluster - Network I/O',
      width: 24,
      height: 6,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-NATS" MetricName="NetworkIn"\', \'Average\', 60)',
          label: 'Network In',
          usingMetrics: {},
        }),
      ],
      right: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-NATS" MetricName="NetworkOut"\', \'Average\', 60)',
          label: 'Network Out',
          usingMetrics: {},
        }),
      ],
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# NATS Messaging Cluster',
        width: 24,
        height: 1,
      })
    );
    this.dashboard.addWidgets(natsStatusWidget, natsCpuWidget);
    this.dashboard.addWidgets(natsNetworkWidget);

    // NATS instance health alarm
    const natsHealthAlarm = new cloudwatch.Alarm(this, 'NatsInstanceHealth', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/AutoScaling',
        metricName: 'GroupInServiceInstances',
        dimensionsMap: { AutoScalingGroupName: 'VettID-NATS-ASG' },
        statistic: 'Minimum',
        period: cdk.Duration.minutes(1),
      }),
      threshold: 1,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      alarmDescription: 'NATS cluster has no healthy instances',
      alarmName: 'VettID-NATS-NoHealthyInstances',
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });

    natsHealthAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));
  }

  private addVaultMonitoring(): void {
    // Vault EC2 instance metrics
    const vaultStatusWidget = new cloudwatch.SingleValueWidget({
      title: 'Active Vault Instances',
      width: 8,
      height: 4,
      metrics: [
        new cloudwatch.Metric({
          namespace: 'AWS/AutoScaling',
          metricName: 'GroupInServiceInstances',
          dimensionsMap: { AutoScalingGroupName: 'VettID-VaultInfra-VaultASG' },
          statistic: 'Average',
          period: cdk.Duration.minutes(1),
        }),
      ],
    });

    const vaultCpuWidget = new cloudwatch.GraphWidget({
      title: 'Vault Instances - CPU Utilization',
      width: 8,
      height: 4,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-VaultInfra-VaultASG" MetricName="CPUUtilization"\', \'Average\', 60)',
          label: 'CPU %',
          usingMetrics: {},
        }),
      ],
    });

    const vaultNetworkWidget = new cloudwatch.GraphWidget({
      title: 'Vault Instances - Network I/O',
      width: 8,
      height: 4,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-VaultInfra-VaultASG" MetricName="NetworkIn"\', \'Sum\', 60)',
          label: 'Network In',
          usingMetrics: {},
        }),
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="VettID-VaultInfra-VaultASG" MetricName="NetworkOut"\', \'Sum\', 60)',
          label: 'Network Out',
          usingMetrics: {},
        }),
      ],
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Vault Instances',
        width: 24,
        height: 1,
      })
    );
    this.dashboard.addWidgets(vaultStatusWidget, vaultCpuWidget, vaultNetworkWidget);

    // Vault provisioning error tracking via Lambda
    // Monitor the provision vault Lambda for failures
    const provisionVaultErrorAlarm = new cloudwatch.Alarm(this, 'VaultProvisioningErrors', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Errors',
        dimensionsMap: { FunctionName: 'VettID-Vault-ProvisionVaultFn' },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 3,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Vault provisioning failures > 3 in 5 minutes',
      alarmName: 'VettID-Vault-ProvisioningFailures',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    provisionVaultErrorAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));
  }
}
