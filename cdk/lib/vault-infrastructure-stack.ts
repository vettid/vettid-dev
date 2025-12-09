import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_ec2 as ec2,
  aws_iam as iam,
} from 'aws-cdk-lib';

/**
 * VettID Vault Infrastructure Stack
 *
 * Contains EC2-related infrastructure for vault instances:
 * - VPC with public/private subnets
 * - Security group for vault instances
 * - IAM role and instance profile for vaults
 * - SSM parameters for configuration
 *
 * This stack is deployed after Infrastructure but before Vault provisioning can work.
 */
export class VaultInfrastructureStack extends cdk.Stack {
  // VPC and networking
  public readonly vpc: ec2.Vpc;
  public readonly vaultSecurityGroup: ec2.SecurityGroup;
  public readonly privateSubnetIds: string[];

  // IAM for vault instances
  public readonly vaultInstanceRole: iam.Role;
  public readonly vaultInstanceProfile: iam.InstanceProfile;

  // Configuration exports for Lambda
  public readonly vaultConfig: {
    securityGroupId: string;
    subnetIds: string;
    iamProfileArn: string;
    iamProfileName: string;
  };

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ===== VPC =====
    // Create a VPC for vault instances
    // Using 2 AZs to reduce cost while maintaining availability
    this.vpc = new ec2.Vpc(this, 'VaultVpc', {
      vpcName: 'vettid-vault-vpc',
      maxAzs: 2,
      natGateways: 1, // Single NAT Gateway to reduce cost
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
      // Enable DNS support for NATS connections
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // Get private subnet IDs for vault placement
    this.privateSubnetIds = this.vpc.privateSubnets.map(s => s.subnetId);

    // ===== SECURITY GROUP =====
    this.vaultSecurityGroup = new ec2.SecurityGroup(this, 'VaultSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: 'vettid-vault-sg',
      description: 'Security group for VettID vault instances',
      allowAllOutbound: true, // Vaults need outbound for NATS, S3, etc.
    });

    // Allow NATS connections (outbound only - vaults connect to central NATS)
    // No inbound rules needed - vaults are completely isolated

    // Allow SSM Session Manager access (for debugging if needed)
    // This uses VPC endpoints or NAT Gateway, no inbound rules needed

    // Tag the security group
    cdk.Tags.of(this.vaultSecurityGroup).add('Name', 'vettid-vault-sg');
    cdk.Tags.of(this.vaultSecurityGroup).add('Purpose', 'VettID Vault Instances');

    // ===== IAM ROLE FOR VAULT INSTANCES =====
    this.vaultInstanceRole = new iam.Role(this, 'VaultInstanceRole', {
      roleName: 'vettid-vault-instance-role',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'IAM role for VettID vault EC2 instances',
      managedPolicies: [
        // SSM for debugging and management
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        // CloudWatch for logs and metrics
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
      ],
    });

    // NATS credentials are passed via user data at launch time and stored locally
    // in the vault's encrypted datastore - no Secrets Manager needed

    // Allow vault instances to report their status via API
    // (They will use instance metadata to get their user_guid and call back)
    this.vaultInstanceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'DescribeSelf',
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeInstances',
        'ec2:DescribeTags',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'ec2:ResourceTag/VettID:Purpose': 'vault',
        },
      },
    }));

    // Allow vault instances to write to their backup bucket prefix
    this.vaultInstanceRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BackupBucketAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:PutObject',
        's3:GetObject',
        's3:DeleteObject',
        's3:ListBucket',
      ],
      resources: [
        `arn:aws:s3:::vettid-vault-backups-${this.account}`,
        `arn:aws:s3:::vettid-vault-backups-${this.account}/*`,
      ],
    }));

    // Create instance profile
    this.vaultInstanceProfile = new iam.InstanceProfile(this, 'VaultInstanceProfile', {
      instanceProfileName: 'vettid-vault-instance-profile',
      role: this.vaultInstanceRole,
    });

    // ===== VPC ENDPOINTS (Optional, reduces NAT costs) =====
    // SSM endpoints for Session Manager without NAT
    this.vpc.addInterfaceEndpoint('SsmEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    this.vpc.addInterfaceEndpoint('SsmMessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    this.vpc.addInterfaceEndpoint('Ec2MessagesEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // S3 Gateway endpoint (free, reduces NAT costs for S3 traffic)
    this.vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    });

    // Note: No Secrets Manager endpoint needed - NATS credentials are passed
    // via EC2 user data at launch time and stored locally in the vault

    // ===== EXPORTS =====
    this.vaultConfig = {
      securityGroupId: this.vaultSecurityGroup.securityGroupId,
      subnetIds: this.privateSubnetIds.join(','),
      iamProfileArn: this.vaultInstanceProfile.instanceProfileArn,
      iamProfileName: this.vaultInstanceProfile.instanceProfileName!,
    };

    // CloudFormation exports for reference
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID for vault instances',
      exportName: 'VettID-Vault-VpcId',
    });

    new cdk.CfnOutput(this, 'SecurityGroupId', {
      value: this.vaultSecurityGroup.securityGroupId,
      description: 'Security group ID for vault instances',
      exportName: 'VettID-Vault-SecurityGroupId',
    });

    new cdk.CfnOutput(this, 'PrivateSubnetIds', {
      value: this.privateSubnetIds.join(','),
      description: 'Private subnet IDs for vault instances',
      exportName: 'VettID-Vault-PrivateSubnetIds',
    });

    new cdk.CfnOutput(this, 'InstanceProfileArn', {
      value: this.vaultInstanceProfile.instanceProfileArn,
      description: 'IAM instance profile ARN for vault instances',
      exportName: 'VettID-Vault-InstanceProfileArn',
    });

    new cdk.CfnOutput(this, 'InstanceProfileName', {
      value: this.vaultInstanceProfile.instanceProfileName!,
      description: 'IAM instance profile name for vault instances',
      exportName: 'VettID-Vault-InstanceProfileName',
    });
  }
}
