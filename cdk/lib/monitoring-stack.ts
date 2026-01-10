/**
 * VettID Monitoring Stack
 *
 * Creates CloudWatch dashboards and alarms for operational visibility:
 * - Lambda error rates and performance
 * - DynamoDB throttling and capacity
 * - NATS cluster health
 * - Vault provisioning status
 * - API Gateway error rates
 * - Active vault instance count
 */

import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

export interface MonitoringStackProps extends cdk.StackProps {
  /** Email address for alarm notifications */
  alarmEmail?: string;

  /**
   * VaultInstances DynamoDB table for vault count metrics.
   * If provided, enables the Active Vault Count widget.
   */
  vaultInstancesTable?: dynamodb.ITable;

  /**
   * HTTP API for API Gateway metrics.
   * If provided, enables API Gateway error rate monitoring.
   */
  httpApi?: apigatewayv2.IHttpApi;

  /**
   * API Gateway API ID (used when httpApi is not passed directly).
   * Can be retrieved from stack outputs.
   */
  apiGatewayApiId?: string;

  /**
   * NATS Auto Scaling Group name for NATS cluster health.
   * Defaults to 'VettID-NATS-ASG'.
   */
  natsAsgName?: string;

  /**
   * Vault Auto Scaling Group name for vault infrastructure health.
   * Defaults to 'VettID-VaultInfra-VaultASG'.
   */
  vaultAsgName?: string;

  /**
   * List of DynamoDB table names to monitor.
   * If not provided, defaults to standard VettID tables.
   */
  dynamoDbTables?: string[];

  /**
   * List of critical Lambda function names to monitor for error rates.
   * If not provided, defaults to standard VettID functions.
   */
  criticalFunctions?: string[];
}

export class MonitoringStack extends cdk.Stack {
  public readonly dashboard: cloudwatch.Dashboard;
  public readonly alarmTopic: sns.Topic;

  private readonly props: MonitoringStackProps;

  // Default table names if not provided via props
  // Note: Legacy credential tables removed - vault-manager uses SQLite storage
  private readonly defaultTables = [
    'VettID-Infrastructure-VaultInstances',
    'VettID-Infrastructure-EnrollmentSessions',
    'VettID-Infrastructure-ActionTokens',
    'VettID-Infrastructure-NatsAccounts',
    'VettID-Infrastructure-Registrations',
    'VettID-Infrastructure-Invites',
    'VettID-Infrastructure-Audit',
  ];

  // Default critical functions if not provided via props
  private readonly defaultCriticalFunctions = [
    'VettID-Vault-EnrollStartFn',
    'VettID-Vault-EnrollSetPasswordFn',
    'VettID-Vault-EnrollFinalizeFn',
    'VettID-Vault-ActionRequestFn',
    'VettID-Vault-AuthExecuteFn',
    'VettID-Vault-ProvisionVaultFn',
  ];

  constructor(scope: Construct, id: string, props: MonitoringStackProps = {}) {
    super(scope, id, props);
    this.props = props;

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
    // Active Vault Count (from DynamoDB)
    // ===============================
    this.addActiveVaultCountWidget();

    // ===============================
    // API Gateway Monitoring
    // ===============================
    this.addApiGatewayMonitoring();

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

  /**
   * Add widget showing active vault instance count from DynamoDB.
   * Uses a custom metric or query from the VaultInstances table.
   */
  private addActiveVaultCountWidget(): void {
    // Text header for Vault Overview section
    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Vault Overview',
        width: 24,
        height: 1,
      })
    );

    // VaultInstances table item count - uses DynamoDB ItemCount metric
    // Note: ItemCount is updated approximately every 6 hours by DynamoDB
    const vaultTableName = this.props.vaultInstancesTable?.tableName || 'VettID-Infrastructure-VaultInstances';

    // Single value widget showing vault instances table size
    const vaultCountWidget = new cloudwatch.SingleValueWidget({
      title: 'Vault Instances (Table Item Count)',
      width: 8,
      height: 4,
      metrics: [
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'ItemCount',
          dimensionsMap: { TableName: vaultTableName },
          statistic: 'Average',
          period: cdk.Duration.hours(6), // ItemCount updates ~6 hours
        }),
      ],
    });

    // Graph of DynamoDB operations on VaultInstances table (shows activity)
    const vaultTableOpsWidget = new cloudwatch.GraphWidget({
      title: 'VaultInstances Table Operations',
      width: 8,
      height: 4,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'ConsumedReadCapacityUnits',
          dimensionsMap: { TableName: vaultTableName },
          statistic: 'Sum',
          period: cdk.Duration.minutes(5),
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'ConsumedWriteCapacityUnits',
          dimensionsMap: { TableName: vaultTableName },
          statistic: 'Sum',
          period: cdk.Duration.minutes(5),
        }),
      ],
    });

    // Successful put/get operations indicate active vault provisioning
    const vaultOperationsWidget = new cloudwatch.GraphWidget({
      title: 'VaultInstances Successful Operations',
      width: 8,
      height: 4,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'SuccessfulRequestLatency',
          dimensionsMap: { TableName: vaultTableName, Operation: 'GetItem' },
          statistic: 'SampleCount',
          period: cdk.Duration.minutes(5),
          label: 'GetItem Count',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'SuccessfulRequestLatency',
          dimensionsMap: { TableName: vaultTableName, Operation: 'PutItem' },
          statistic: 'SampleCount',
          period: cdk.Duration.minutes(5),
          label: 'PutItem Count',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'SuccessfulRequestLatency',
          dimensionsMap: { TableName: vaultTableName, Operation: 'UpdateItem' },
          statistic: 'SampleCount',
          period: cdk.Duration.minutes(5),
          label: 'UpdateItem Count',
        }),
      ],
    });

    this.dashboard.addWidgets(vaultCountWidget, vaultTableOpsWidget, vaultOperationsWidget);
  }

  /**
   * Add API Gateway monitoring widgets and alarms.
   * Monitors 4xx and 5xx error rates for the HTTP API.
   */
  private addApiGatewayMonitoring(): void {
    // Get API ID from props or use default (from stack outputs)
    const apiId = this.props.httpApi?.apiId || this.props.apiGatewayApiId || 'tiqpij5mue';

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# API Gateway',
        width: 24,
        height: 1,
      })
    );

    // 4xx Client Errors widget
    const api4xxWidget = new cloudwatch.GraphWidget({
      title: 'API Gateway 4xx Errors',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: '4XXError',
          dimensionsMap: { ApiId: apiId },
          statistic: 'Sum',
          period: cdk.Duration.minutes(1),
          label: '4xx Errors',
          color: '#ff7f0e', // Orange
        }),
      ],
    });

    // 5xx Server Errors widget
    const api5xxWidget = new cloudwatch.GraphWidget({
      title: 'API Gateway 5xx Errors',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: '5XXError',
          dimensionsMap: { ApiId: apiId },
          statistic: 'Sum',
          period: cdk.Duration.minutes(1),
          label: '5xx Errors',
          color: '#d62728', // Red
        }),
      ],
    });

    // Request count and latency
    const apiRequestsWidget = new cloudwatch.GraphWidget({
      title: 'API Gateway Requests',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: 'Count',
          dimensionsMap: { ApiId: apiId },
          statistic: 'Sum',
          period: cdk.Duration.minutes(1),
          label: 'Request Count',
        }),
      ],
    });

    const apiLatencyWidget = new cloudwatch.GraphWidget({
      title: 'API Gateway Latency',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: 'Latency',
          dimensionsMap: { ApiId: apiId },
          statistic: 'p50',
          period: cdk.Duration.minutes(1),
          label: 'p50 Latency',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: 'Latency',
          dimensionsMap: { ApiId: apiId },
          statistic: 'p95',
          period: cdk.Duration.minutes(1),
          label: 'p95 Latency',
        }),
        new cloudwatch.Metric({
          namespace: 'AWS/ApiGateway',
          metricName: 'Latency',
          dimensionsMap: { ApiId: apiId },
          statistic: 'p99',
          period: cdk.Duration.minutes(1),
          label: 'p99 Latency',
        }),
      ],
    });

    this.dashboard.addWidgets(api4xxWidget, api5xxWidget);
    this.dashboard.addWidgets(apiRequestsWidget, apiLatencyWidget);

    // ===== API Gateway 5xx Alarm =====
    // Critical alarm: > 10 5xx errors in 5 minutes
    const api5xxAlarm = new cloudwatch.Alarm(this, 'ApiGateway5xxAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway',
        metricName: '5XXError',
        dimensionsMap: { ApiId: apiId },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'API Gateway 5xx errors > 10 in 5 minutes',
      alarmName: 'VettID-ApiGateway-5xxErrors',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    api5xxAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));

    // Warning alarm for 4xx rate (might indicate attack or client issues)
    const api4xxAlarm = new cloudwatch.Alarm(this, 'ApiGateway4xxAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/ApiGateway',
        metricName: '4XXError',
        dimensionsMap: { ApiId: apiId },
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 100,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'API Gateway 4xx errors > 100 in 5 minutes (sustained)',
      alarmName: 'VettID-ApiGateway-4xxErrors',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    api4xxAlarm.addAlarmAction(new actions.SnsAction(this.alarmTopic));
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
    const criticalFunctions = this.props.criticalFunctions || this.defaultCriticalFunctions;

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
    // DynamoDB tables to monitor - use props or defaults
    const tables = this.props.dynamoDbTables || this.defaultTables;

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
    const natsAsgName = this.props.natsAsgName || 'VettID-NATS-NatsAsg';

    const natsStatusWidget = new cloudwatch.GraphWidget({
      title: 'NATS Cluster - Instance Status',
      width: 12,
      height: 6,
      left: [
        new cloudwatch.Metric({
          namespace: 'AWS/EC2',
          metricName: 'StatusCheckFailed',
          dimensionsMap: { AutoScalingGroupName: natsAsgName },
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
          expression: `SEARCH('{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="${natsAsgName}" MetricName="CPUUtilization"', 'Average', 60)`,
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
          expression: `SEARCH('{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="${natsAsgName}" MetricName="NetworkIn"', 'Average', 60)`,
          label: 'Network In',
          usingMetrics: {},
        }),
      ],
      right: [
        new cloudwatch.MathExpression({
          expression: `SEARCH('{AWS/EC2,AutoScalingGroupName} AutoScalingGroupName="${natsAsgName}" MetricName="NetworkOut"', 'Average', 60)`,
          label: 'Network Out',
          usingMetrics: {},
        }),
      ],
    });

    // NATS cluster in-service instances
    const natsInServiceWidget = new cloudwatch.SingleValueWidget({
      title: 'NATS Cluster Health',
      width: 12,
      height: 4,
      metrics: [
        new cloudwatch.Metric({
          namespace: 'AWS/AutoScaling',
          metricName: 'GroupInServiceInstances',
          dimensionsMap: { AutoScalingGroupName: natsAsgName },
          statistic: 'Average',
          period: cdk.Duration.minutes(1),
          label: 'In-Service Instances',
        }),
      ],
    });

    // NATS target health (NLB health checks)
    const natsTargetHealthWidget = new cloudwatch.SingleValueWidget({
      title: 'NATS Target Health',
      width: 12,
      height: 4,
      metrics: [
        new cloudwatch.Metric({
          namespace: 'AWS/AutoScaling',
          metricName: 'GroupDesiredCapacity',
          dimensionsMap: { AutoScalingGroupName: natsAsgName },
          statistic: 'Average',
          period: cdk.Duration.minutes(1),
          label: 'Desired Capacity',
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
    this.dashboard.addWidgets(natsInServiceWidget, natsTargetHealthWidget);
    this.dashboard.addWidgets(natsStatusWidget, natsCpuWidget);
    this.dashboard.addWidgets(natsNetworkWidget);

    // NATS instance health alarm
    const natsHealthAlarm = new cloudwatch.Alarm(this, 'NatsInstanceHealth', {
      metric: new cloudwatch.Metric({
        namespace: 'AWS/AutoScaling',
        metricName: 'GroupInServiceInstances',
        dimensionsMap: { AutoScalingGroupName: natsAsgName },
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
    // Vault EC2 instance metrics (from VaultInfrastructureStack ASG if it exists)
    // Note: Individual vault EC2 instances are NOT managed by an ASG - they are provisioned per-user
    // This section monitors the VaultInstances provisioning Lambda and EC2 tagged instances
    const vaultAsgName = this.props.vaultAsgName || 'VettID-VaultInfra-VaultASG';

    // Search for all vault EC2 instances by Application tag
    const vaultEc2StatusWidget = new cloudwatch.GraphWidget({
      title: 'Vault EC2 Instances - Status Checks',
      width: 12,
      height: 4,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,InstanceId} MetricName="StatusCheckFailed"\', \'Maximum\', 60)',
          label: 'Status Check Failed',
          usingMetrics: {},
        }),
      ],
    });

    const vaultEc2CpuWidget = new cloudwatch.GraphWidget({
      title: 'Vault EC2 Instances - CPU Utilization',
      width: 12,
      height: 4,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,InstanceId} MetricName="CPUUtilization"\', \'Average\', 60)',
          label: 'CPU %',
          usingMetrics: {},
        }),
      ],
    });

    const vaultEc2NetworkWidget = new cloudwatch.GraphWidget({
      title: 'Vault EC2 Instances - Network I/O',
      width: 24,
      height: 4,
      left: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,InstanceId} MetricName="NetworkIn"\', \'Sum\', 60)',
          label: 'Network In',
          usingMetrics: {},
        }),
      ],
      right: [
        new cloudwatch.MathExpression({
          expression: 'SEARCH(\'{AWS/EC2,InstanceId} MetricName="NetworkOut"\', \'Sum\', 60)',
          label: 'Network Out',
          usingMetrics: {},
        }),
      ],
    });

    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# Vault EC2 Instances',
        width: 24,
        height: 1,
      })
    );
    this.dashboard.addWidgets(vaultEc2StatusWidget, vaultEc2CpuWidget);
    this.dashboard.addWidgets(vaultEc2NetworkWidget);

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
