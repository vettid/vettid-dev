import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_s3 as s3,
  aws_autoscaling as autoscaling,
  aws_cloudwatch as cloudwatch,
  aws_ssm as ssm,
  custom_resources as cr,
} from 'aws-cdk-lib';

import { InfrastructureStack } from './infrastructure-stack';

export interface NitroStackProps extends cdk.StackProps {
  /**
   * Optional alarm email for notifications
   */
  alarmEmail?: string;

  /**
   * Infrastructure stack for shared resources (DynamoDB tables, S3 buckets)
   */
  infrastructure?: InfrastructureStack;
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

    // ===== KMS KEY FOR NITRO SEALING =====
    // This key is used for envelope encryption of vault credentials
    // The key policy requires attestation for decryption, binding to PCR values
    //
    // SECURITY MODEL:
    // - Encrypt/GenerateDataKey: Allowed without attestation (parent can encrypt)
    // - Decrypt: REQUIRES PCR0 attestation (only correct enclave build can decrypt)
    //
    // This ensures that even if an attacker compromises the EC2 host, they cannot
    // decrypt sealed credentials without running the exact enclave code that was
    // measured into PCR0.
    //
    // PCR0 is updated in SSM during each AMI build. When deploying CDK, the current
    // PCR0 value is read from SSM and embedded in the key policy.
    const pcr0Value = ssm.StringParameter.valueForStringParameter(
      this,
      '/vettid/enclave/pcr/pcr0'
    );

    const sealingKey = new cdk.aws_kms.Key(this, 'EnclaveSealingKey', {
      alias: 'vettid-enclave-sealing',
      description: 'KMS key for VettID Nitro Enclave credential sealing',
      enableKeyRotation: true,
      // Custom key policy is defined below
    });

    // Output the sealing key ARN for configuration
    new cdk.CfnOutput(this, 'EnclaveSealingKeyArn', {
      value: sealingKey.keyArn,
      description: 'KMS key ARN for enclave sealing (configure in parent.yaml)',
    });

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

    // ===== VPC ENDPOINTS FOR SSM (SECURITY HARDENING) =====
    // These endpoints keep SSM traffic within AWS network, avoiding internet exposure.
    // Required for SSM to work in private subnets without NAT gateway for SSM traffic.

    // Security group for VPC endpoints
    const vpcEndpointSg = new ec2.SecurityGroup(this, 'VpcEndpointSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: 'vettid-vpce-sg',
      description: 'Security group for VPC endpoints',
      allowAllOutbound: false,
    });

    // Allow HTTPS from enclave instances
    vpcEndpointSg.addIngressRule(
      this.enclaveSecurityGroup,
      ec2.Port.tcp(443),
      'Allow HTTPS from enclave instances'
    );

    // SSM endpoint - for Systems Manager API calls
    this.vpc.addInterfaceEndpoint('SsmEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM,
      securityGroups: [vpcEndpointSg],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // SSM Messages endpoint - for Session Manager connections
    this.vpc.addInterfaceEndpoint('SsmMessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      securityGroups: [vpcEndpointSg],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // EC2 Messages endpoint - for EC2 Run Command
    this.vpc.addInterfaceEndpoint('Ec2MessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      securityGroups: [vpcEndpointSg],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // S3 Gateway endpoint (for vault data access without internet)
    this.vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    });

    // CloudWatch Logs endpoint (for Session Manager logging)
    this.vpc.addInterfaceEndpoint('CloudWatchLogsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      securityGroups: [vpcEndpointSg],
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // ===== SESSION MANAGER LOGGING =====
    // Create CloudWatch Log Group for Session Manager audit logs
    const ssmLogGroup = new cdk.aws_logs.LogGroup(this, 'SsmSessionLogGroup', {
      logGroupName: '/vettid/ssm-sessions',
      retention: cdk.aws_logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // S3 bucket for Session Manager session logs (long-term retention)
    const ssmSessionLogBucket = new s3.Bucket(this, 'SsmSessionLogBucket', {
      bucketName: `vettid-ssm-session-logs-${this.account}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        { expiration: cdk.Duration.days(365) }, // Keep logs for 1 year
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Configure Session Manager preferences via Custom Resource
    // This sets up CloudWatch and S3 logging for all SSM sessions
    const sessionPreferencesContent = JSON.stringify({
      schemaVersion: '1.0',
      description: 'VettID Session Manager Settings with logging enabled',
      sessionType: 'Standard_Stream',
      inputs: {
        cloudWatchLogGroupName: ssmLogGroup.logGroupName,
        cloudWatchEncryptionEnabled: false,
        cloudWatchStreamingEnabled: true,
        s3BucketName: ssmSessionLogBucket.bucketName,
        s3KeyPrefix: 'sessions',
        s3EncryptionEnabled: false,
        runAsEnabled: false,
        idleSessionTimeout: '20',
      },
    });

    // Custom Resource to create/update the SSM-SessionManagerRunShell document
    const configureSessionManager = new cr.AwsCustomResource(this, 'ConfigureSessionManager', {
      onCreate: {
        service: 'SSM',
        action: 'createDocument',
        parameters: {
          Content: sessionPreferencesContent,
          Name: 'SSM-SessionManagerRunShell',
          DocumentType: 'Session',
          DocumentFormat: 'JSON',
        },
        physicalResourceId: cr.PhysicalResourceId.of('SSM-SessionManagerRunShell'),
        // Ignore if document already exists - we'll update it instead
        ignoreErrorCodesMatching: 'DocumentAlreadyExists',
      },
      onUpdate: {
        service: 'SSM',
        action: 'updateDocument',
        parameters: {
          Content: sessionPreferencesContent,
          Name: 'SSM-SessionManagerRunShell',
          DocumentVersion: '$LATEST',
        },
        physicalResourceId: cr.PhysicalResourceId.of('SSM-SessionManagerRunShell'),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'ssm:CreateDocument',
            'ssm:UpdateDocument',
            'ssm:DescribeDocument',
          ],
          resources: [
            `arn:aws:ssm:${this.region}:${this.account}:document/SSM-SessionManagerRunShell`,
          ],
        }),
      ]),
    });

    // Ensure log group and bucket exist before configuring Session Manager
    configureSessionManager.node.addDependency(ssmLogGroup);
    configureSessionManager.node.addDependency(ssmSessionLogBucket);

    // Grant Session Manager permission to write to CloudWatch Logs
    ssmLogGroup.grantWrite(new iam.ServicePrincipal('ssm.amazonaws.com'));

    // Grant Session Manager permission to write to S3
    ssmSessionLogBucket.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('ssm.amazonaws.com')],
      actions: ['s3:PutObject', 's3:PutObjectAcl'],
      resources: [`${ssmSessionLogBucket.bucketArn}/sessions/*`],
      conditions: {
        StringEquals: {
          'aws:SourceAccount': this.account,
        },
      },
    }));

    // SSM SECURITY RESTRICTIONS:
    // - ssm:SendCommand should only be granted to admin IAM roles
    // - Consider using AWS Organizations SCPs to restrict SSM access
    // - Monitor CloudWatch Logs for unauthorized session attempts

    // ===== PACKER BUILD ROLE =====
    // IAM role for Packer EC2 build instances to write PCR values to SSM
    const packerBuildRole = new iam.Role(this, 'PackerBuildRole', {
      roleName: 'vettid-packer-build-role',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'IAM role for Packer build instances (AMI creation)',
    });

    // Allow packer to write PCR values to SSM
    packerBuildRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ssm:PutParameter'],
      resources: [
        `arn:aws:ssm:${this.region}:${this.account}:parameter/vettid/enclave/pcr/*`,
      ],
    }));

    // Create instance profile for packer
    const packerInstanceProfile = new iam.InstanceProfile(this, 'PackerInstanceProfile', {
      instanceProfileName: 'vettid-packer-build-profile',
      role: packerBuildRole,
    });

    // Output for packer configuration
    new cdk.CfnOutput(this, 'PackerInstanceProfileName', {
      value: packerInstanceProfile.instanceProfileName,
      description: 'Instance profile name for Packer builds',
    });

    new cdk.CfnOutput(this, 'SsmSessionLogGroupName', {
      value: ssmLogGroup.logGroupName,
      description: 'CloudWatch Log Group for SSM Session Manager logs',
    });

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

    // KMS access for Nitro Enclave envelope encryption
    // The parent process (EC2 host) calls KMS on behalf of the enclave:
    // - Encrypt/GenerateDataKey: No attestation needed (parent encrypts DEKs)
    // - Decrypt: REQUIRES PCR0 attestation - KMS validates the attestation document
    //   and only returns CiphertextForRecipient if PCR0 matches
    //
    // Key policy statements (KMS resource-based policy):

    // Statement 1: Allow Encrypt and GenerateDataKey without attestation
    // This lets the parent process seal new credentials
    sealingKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowEnclaveEncrypt',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(this.enclaveInstanceRole.roleArn)],
      actions: ['kms:Encrypt', 'kms:GenerateDataKey'],
      resources: ['*'],
    }));

    // Statement 2: Allow Decrypt ONLY with valid PCR0 attestation
    // This ensures only the exact enclave build can unseal credentials
    sealingKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowEnclaveDecrypt',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(this.enclaveInstanceRole.roleArn)],
      actions: ['kms:Decrypt'],
      resources: ['*'],
      conditions: {
        StringEqualsIgnoreCase: {
          'kms:RecipientAttestation:PCR0': pcr0Value,
        },
      },
    }));

    // Store sealing key ARN in SSM for parent process configuration
    const sealingKeyArnParam = new ssm.StringParameter(this, 'SealingKeyArnParameter', {
      parameterName: '/vettid/nitro/sealing-key-arn',
      description: 'ARN of the KMS key used for Nitro Enclave credential sealing',
      stringValue: sealingKey.keyArn,
      tier: ssm.ParameterTier.STANDARD,
    });

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

    // ===== DYNAMIC HANDLER LOADING PERMISSIONS =====
    // Grant read access to handler manifest table and handlers bucket
    if (props?.infrastructure) {
      // Read handler manifest from DynamoDB (for version lookups)
      props.infrastructure.tables.handlerManifest.grantReadData(this.enclaveInstanceRole);

      // Read handler WASM files from S3
      props.infrastructure.handlersBucket.grantRead(this.enclaveInstanceRole);

      // Read handler signing public key from Secrets Manager
      this.enclaveInstanceRole.addToPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [props.infrastructure.handlerSigningKeySecretArn],
      }));
    }

    // ===== AMI FROM SSM PARAMETER =====
    // The AMI ID is managed externally (set by Packer during AMI builds)
    // CDK reads this at deploy time - no need for hardcoded AMI IDs
    // Workflow: Build AMI → Packer updates SSM → Deploy CDK → Instance Refresh
    const enclaveAmiId = ssm.StringParameter.valueForStringParameter(
      this,
      '/vettid/enclave/ami-id'
    );

    // ===== AUTO SCALING GROUP =====
    // Create launch template with Nitro enclave enabled
    const launchTemplate = new ec2.LaunchTemplate(this, 'EnclaveLaunchTemplate', {
      launchTemplateName: 'vettid-enclave-template',
      // AMI is read from SSM at deploy time - no hardcoding required
      machineImage: ec2.MachineImage.genericLinux({
        'us-east-1': enclaveAmiId,
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
      '# Fetch KMS sealing key ARN from SSM',
      'echo "Fetching KMS sealing key ARN from SSM..."',
      'KMS_SEALING_KEY_ARN=$(aws ssm get-parameter --name /vettid/nitro/sealing-key-arn --region $REGION --query Parameter.Value --output text)',
      'echo "KMS sealing key ARN: $KMS_SEALING_KEY_ARN"',
      '',
      '# Update parent config to use NATS credentials and KMS',
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
      'kms:',
      '  sealing_key_arn: $KMS_SEALING_KEY_ARN',
      '  region: $REGION',
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
