import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_s3 as s3,
  aws_autoscaling as autoscaling,
  aws_cloudwatch as cloudwatch,
  aws_ssm as ssm,
} from 'aws-cdk-lib';

export interface NitroStackProps extends cdk.StackProps {
  /**
   * Optional alarm email for notifications
   */
  alarmEmail?: string;
}

/**
 * VettID Nitro Enclave Stack
 *
 * Creates infrastructure for multi-tenant Nitro Enclave vault architecture:
 * - VPC with public/private subnets (for enclave EC2 instances)
 * - S3 bucket for encrypted vault data
 * - Auto Scaling Group with Nitro-enabled c6a.2xlarge instances
 * - IAM role for enclave instances (S3, CloudWatch, SSM access)
 * - CloudWatch dashboard and alarms
 *
 * This replaces the per-user EC2 vault model (VaultInfrastructureStack)
 * with a shared multi-tenant architecture using Nitro Enclaves.
 *
 * Security Model:
 * - Enclave instances run supervisor + vault-manager processes
 * - All vault data is encrypted before leaving the enclave
 * - Parent process (on EC2 host) only sees encrypted blobs
 * - PCR-based sealing ensures data can only be decrypted by matching enclave code
 */
export class NitroStack extends cdk.Stack {
  // VPC CIDR (explicit to avoid conflicts with NATS VPC 10.10.0.0/16)
  public static readonly VPC_CIDR = '10.20.0.0/16';

  // VPC and networking
  public readonly vpc: ec2.Vpc;
  public readonly enclaveSecurityGroup: ec2.SecurityGroup;
  public readonly lambdaSecurityGroup: ec2.SecurityGroup;
  public readonly privateSubnetIds: string[];

  // S3 bucket for encrypted vault data
  public readonly vaultDataBucket: s3.Bucket;

  // Auto Scaling Group for enclave instances
  public readonly enclaveASG: autoscaling.AutoScalingGroup;

  // IAM for enclave instances
  public readonly enclaveInstanceRole: iam.Role;

  // SSM Parameters
  public readonly enclaveAmiParameter: ssm.StringParameter;

  constructor(scope: Construct, id: string, props?: NitroStackProps) {
    super(scope, id, props);

    // ===== VPC =====
    // Create a VPC for Nitro enclave instances
    // Using 2 AZs for high availability
    // Separate from old vault VPC (10.0.0.0/16) and NATS VPC (10.10.0.0/16)
    this.vpc = new ec2.Vpc(this, 'EnclaveVpc', {
      vpcName: 'vettid-enclave-vpc',
      maxAzs: 2,
      natGateways: 1, // Single NAT Gateway to reduce cost
      ipAddresses: ec2.IpAddresses.cidr(NitroStack.VPC_CIDR),
      subnetConfiguration: [
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
      ],
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    this.privateSubnetIds = this.vpc.privateSubnets.map(s => s.subnetId);

    // ===== S3 BUCKET FOR VAULT DATA =====
    // All vault data is encrypted by the enclave before storage
    // S3 server-side encryption adds additional layer
    this.vaultDataBucket = new s3.Bucket(this, 'VaultDataBucket', {
      bucketName: `vettid-vault-data-${this.account}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          // Delete old versions after 30 days
          noncurrentVersionExpiration: cdk.Duration.days(30),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN, // Keep data on stack deletion
    });

    // ===== SECURITY GROUP =====
    this.enclaveSecurityGroup = new ec2.SecurityGroup(this, 'EnclaveSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: 'vettid-enclave-sg',
      description: 'Security group for VettID Nitro Enclave instances',
      allowAllOutbound: true, // Enclaves need outbound for NATS, S3
    });

    // Allow health check HTTP on port 8080 from ALB/NLB (if needed)
    // Currently using NLB passthrough, so no health check port needed here

    cdk.Tags.of(this.enclaveSecurityGroup).add('Name', 'vettid-enclave-sg');
    cdk.Tags.of(this.enclaveSecurityGroup).add('Purpose', 'VettID Nitro Enclave Instances');

    // Lambda security group for functions that need VPC access (NATS, internal services)
    this.lambdaSecurityGroup = new ec2.SecurityGroup(this, 'LambdaSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: 'vettid-lambda-sg',
      description: 'Security group for VettID Lambda functions requiring VPC access',
      allowAllOutbound: true, // Lambdas need outbound for NATS, DynamoDB, etc.
    });

    cdk.Tags.of(this.lambdaSecurityGroup).add('Name', 'vettid-lambda-sg');
    cdk.Tags.of(this.lambdaSecurityGroup).add('Purpose', 'VettID Lambda Functions');

    // ===== IAM ROLE FOR ENCLAVE INSTANCES =====
    this.enclaveInstanceRole = new iam.Role(this, 'EnclaveInstanceRole', {
      roleName: 'vettid-enclave-instance-role',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'IAM role for VettID Nitro Enclave EC2 instances',
      managedPolicies: [
        // SSM for debugging and management
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        // CloudWatch for logs and metrics
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
      ],
    });

    // S3 access for vault data bucket
    this.vaultDataBucket.grantReadWrite(this.enclaveInstanceRole);

    // KMS access for Nitro attestation (if using KMS for sealing)
    // The enclave uses Nitro's built-in sealing for PCR-based encryption
    // which doesn't require explicit KMS permissions
    // However, if we add KMS-based sealing in the future:
    // kmsKey.grantEncryptDecrypt(this.enclaveInstanceRole);

    // EC2 describe for self-discovery
    this.enclaveInstanceRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeInstances',
        'ec2:DescribeTags',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'ec2:ResourceTag/Application': 'vettid-enclave',
        },
      },
    }));

    // SSM GetParameter for fetching NATS credentials
    this.enclaveInstanceRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'ssm:GetParameter',
        'ssm:GetParameters',
      ],
      resources: [
        `arn:aws:ssm:${this.region}:${this.account}:parameter/vettid/nitro/*`,
      ],
    }));

    // ===== SSM PARAMETER FOR AMI ID =====
    // The enclave AMI ID is stored in SSM for easy updates
    this.enclaveAmiParameter = new ssm.StringParameter(this, 'EnclaveAmiParameter', {
      parameterName: '/vettid/enclave/ami-id',
      description: 'AMI ID for VettID Nitro Enclave instances',
      stringValue: 'ami-030b618202b5577e7', // Built 2025-01-02 via Packer
      tier: ssm.ParameterTier.STANDARD,
    });

    // ===== AUTO SCALING GROUP =====
    // Create launch template with Nitro enclave enabled
    const launchTemplate = new ec2.LaunchTemplate(this, 'EnclaveLaunchTemplate', {
      launchTemplateName: 'vettid-enclave-template',
      // Use the pre-built Nitro Enclave AMI (built via Packer)
      machineImage: ec2.MachineImage.genericLinux({
        'us-east-1': 'ami-030b618202b5577e7', // Built 2025-01-02
      }),
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.C6A,
        ec2.InstanceSize.XLARGE2 // Upgraded for EIF build memory headroom
      ),
      securityGroup: this.enclaveSecurityGroup,
      role: this.enclaveInstanceRole,
      // Enable Nitro Enclaves
      nitroEnclaveEnabled: true,
      // EBS-optimized for better I/O performance
      ebsOptimized: true,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            encrypted: true,
            iops: 3000,
            throughput: 125,
          }),
        },
      ],
      userData: this.createUserData(),
    });

    // Create Auto Scaling Group
    this.enclaveASG = new autoscaling.AutoScalingGroup(this, 'EnclaveASG', {
      vpc: this.vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      launchTemplate,
      minCapacity: 1, // Single instance for dev
      maxCapacity: 3, // Scale up to 3 for production
      desiredCapacity: 1,
      healthCheck: autoscaling.HealthCheck.ec2({
        grace: cdk.Duration.minutes(5),
      }),
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
        maxBatchSize: 1,
        minInstancesInService: 0, // Allow full replacement for dev
        pauseTime: cdk.Duration.minutes(5),
      }),
    });

    // Tags for the ASG instances
    cdk.Tags.of(this.enclaveASG).add('Application', 'vettid-enclave');
    cdk.Tags.of(this.enclaveASG).add('Purpose', 'Nitro Enclave Host');

    // ===== CLOUDWATCH DASHBOARD =====
    const dashboard = new cloudwatch.Dashboard(this, 'EnclaveDashboard', {
      dashboardName: 'VettID-Nitro-Enclave',
    });

    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# VettID Nitro Enclave Monitoring\nMulti-tenant vault infrastructure',
        width: 24,
        height: 1,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Enclave Instance Count',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/AutoScaling',
            metricName: 'GroupInServiceInstances',
            dimensionsMap: {
              AutoScalingGroupName: this.enclaveASG.autoScalingGroupName,
            },
            statistic: 'Average',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'CPU Utilization',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/EC2',
            metricName: 'CPUUtilization',
            dimensionsMap: {
              AutoScalingGroupName: this.enclaveASG.autoScalingGroupName,
            },
            statistic: 'Average',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'S3 Bucket Size',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/S3',
            metricName: 'BucketSizeBytes',
            dimensionsMap: {
              BucketName: this.vaultDataBucket.bucketName,
              StorageType: 'StandardStorage',
            },
            statistic: 'Average',
            period: cdk.Duration.days(1),
          }),
        ],
        width: 8,
        height: 6,
      }),
    );

    // ===== CLOUDWATCH ALARMS =====
    // Alarm if no instances are running
    new cloudwatch.Alarm(this, 'NoInstancesAlarm', {
      alarmName: 'VettID-Enclave-NoInstances',
      alarmDescription: 'No Nitro Enclave instances are running',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/AutoScaling',
        metricName: 'GroupInServiceInstances',
        dimensionsMap: {
          AutoScalingGroupName: this.enclaveASG.autoScalingGroupName,
        },
        statistic: 'Minimum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });

    // High CPU alarm
    new cloudwatch.Alarm(this, 'HighCpuAlarm', {
      alarmName: 'VettID-Enclave-HighCPU',
      alarmDescription: 'Enclave instance CPU utilization is high',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/EC2',
        metricName: 'CPUUtilization',
        dimensionsMap: {
          AutoScalingGroupName: this.enclaveASG.autoScalingGroupName,
        },
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    });

    // ===== OUTPUTS =====
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID for Nitro Enclave instances',
    });

    new cdk.CfnOutput(this, 'VaultDataBucketName', {
      value: this.vaultDataBucket.bucketName,
      description: 'S3 bucket for encrypted vault data',
    });

    new cdk.CfnOutput(this, 'EnclaveASGName', {
      value: this.enclaveASG.autoScalingGroupName,
      description: 'Auto Scaling Group name for Nitro Enclave instances',
    });

    new cdk.CfnOutput(this, 'EnclaveRoleArn', {
      value: this.enclaveInstanceRole.roleArn,
      description: 'IAM role ARN for Nitro Enclave instances',
    });
  }

  /**
   * Creates user data script for enclave instances
   *
   * The AMI already has:
   * - Nitro CLI tools installed
   * - Parent binary at /usr/local/bin/vettid-parent
   * - EIF at /opt/vettid/enclave/vettid-vault-enclave.eif
   * - Systemd services for enclave and parent
   *
   * This user data:
   * - Fetches NATS credentials from SSM
   * - Writes them to /etc/vettid/nats.creds
   * - Starts the enclave and parent services
   */
  private createUserData(): ec2.UserData {
    const userData = ec2.UserData.forLinux();

    userData.addCommands(
      '#!/bin/bash',
      'set -euxo pipefail',
      '',
      '# Log to CloudWatch',
      'exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1',
      '',
      '# Get region from instance metadata',
      'TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'REGION=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      '',
      '# Fetch NATS credentials from SSM and write to file',
      'echo "Fetching NATS credentials from SSM..."',
      'aws ssm get-parameter --name /vettid/nitro/parent-nats-creds --with-decryption --region $REGION --query Parameter.Value --output text > /etc/vettid/nats.creds',
      'chmod 600 /etc/vettid/nats.creds',
      'chown root:root /etc/vettid/nats.creds',
      'echo "NATS credentials written to /etc/vettid/nats.creds"',
      '',
      '# Update parent config to use NATS credentials',
      'cat > /etc/vettid/parent.yaml << EOF',
      '# VettID Nitro Enclave Parent Configuration',
      '',
      'enclave:',
      '  eif_path: /opt/vettid/enclave/vettid-vault-enclave.eif',
      '  memory_mib: 6144',
      '  cpu_count: 2',
      '  cid: 16',
      '  debug_mode: false',
      '',
      'vsock:',
      '  port: 5000',
      '',
      'nats:',
      '  url: nats://nats.internal.vettid.dev:4222',
      '  credentials_file: /etc/vettid/nats.creds',
      '  reconnect_wait: 2000',
      '  max_reconnects: -1',
      '',
      's3:',
      '  bucket: ""',
      '  region: us-east-1',
      '',
      'health:',
      '  port: 8080',
      '  check_interval: 30s',
      '',
      'logging:',
      '  level: info',
      '  format: json',
      'EOF',
      'chmod 644 /etc/vettid/parent.yaml',
      '',
      '# Wait for nitro-enclaves-allocator to be ready',
      'echo "Waiting for nitro-enclaves-allocator..."',
      'for i in {1..30}; do',
      '  if systemctl is-active --quiet nitro-enclaves-allocator; then',
      '    echo "nitro-enclaves-allocator is ready"',
      '    break',
      '  fi',
      '  echo "Waiting... ($i/30)"',
      '  sleep 2',
      'done',
      '',
      '# Start enclave service',
      'echo "Starting enclave service..."',
      'systemctl start vettid-enclave || true',
      'sleep 3',
      '',
      '# Start parent service',
      'echo "Starting parent service..."',
      'systemctl start vettid-parent || true',
      '',
      '# Check status',
      'echo "=== Service Status ==="',
      'systemctl status vettid-enclave --no-pager || true',
      'systemctl status vettid-parent --no-pager || true',
      '',
      '# Signal completion',
      'echo "User data complete"',
    );

    return userData;
  }
}
