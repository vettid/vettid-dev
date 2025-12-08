import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_ec2 as ec2,
  aws_rds as rds,
  aws_secretsmanager as secretsmanager,
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
} from 'aws-cdk-lib';

/**
 * VettID Ledger Stack
 *
 * Contains the Protean Credential System database:
 * - Aurora PostgreSQL Serverless v2 for Ledger database
 * - VPC with private subnets for database isolation
 * - Secrets Manager for database credentials
 * - Lambda functions for Ledger operations
 *
 * Phase 1: Protean Credential System - Core
 *
 * The Ledger manages:
 * - User sessions (atomic session management)
 * - Credential Encryption Keys (CEK)
 * - Transaction Keys (UTK/LTK pairs)
 * - Ledger Authentication Tokens (LAT)
 * - Password hashes (Argon2id)
 */

export interface LedgerStackProps extends cdk.StackProps {
  // Environment configuration
  readonly environment?: 'development' | 'staging' | 'production';
}

export class LedgerStack extends cdk.Stack {
  // VPC resources
  public readonly vpc: ec2.Vpc;
  public readonly databaseSecurityGroup: ec2.SecurityGroup;
  public readonly lambdaSecurityGroup: ec2.SecurityGroup;

  // Database resources
  public readonly cluster: rds.DatabaseCluster;
  public readonly databaseSecret: secretsmanager.ISecret;

  // Database connection info for Lambda handlers
  public readonly databaseEndpoint: string;
  public readonly databaseName: string;

  constructor(scope: Construct, id: string, props?: LedgerStackProps) {
    super(scope, id, props);

    const environment = props?.environment || 'development';
    const isProd = environment === 'production';

    // ============================================
    // VPC Configuration
    // ============================================

    // Create VPC with private subnets for database isolation
    this.vpc = new ec2.Vpc(this, 'LedgerVpc', {
      maxAzs: isProd ? 3 : 2,
      natGateways: 1, // Required for Lambda to access secrets manager
      subnetConfiguration: [
        {
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: 'Isolated',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
    });

    // Security group for database - only allows access from Lambda
    this.databaseSecurityGroup = new ec2.SecurityGroup(this, 'DatabaseSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Ledger Aurora database',
      allowAllOutbound: false,
    });

    // Security group for Lambda functions that access the database
    this.lambdaSecurityGroup = new ec2.SecurityGroup(this, 'LambdaSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Ledger Lambda functions',
      allowAllOutbound: true,
    });

    // Allow Lambda to connect to database on PostgreSQL port
    this.databaseSecurityGroup.addIngressRule(
      this.lambdaSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow Lambda functions to connect to PostgreSQL'
    );

    // ============================================
    // Aurora PostgreSQL Serverless v2
    // ============================================

    this.databaseName = 'ledger';

    // Create Aurora Serverless v2 cluster
    this.cluster = new rds.DatabaseCluster(this, 'LedgerCluster', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.VER_15_4,
      }),
      serverlessV2MinCapacity: 0.5,  // Minimum ACUs (can scale to 0.5 for dev)
      serverlessV2MaxCapacity: isProd ? 16 : 4,  // Maximum ACUs
      writer: rds.ClusterInstance.serverlessV2('Writer', {
        publiclyAccessible: false,
      }),
      readers: isProd
        ? [
            rds.ClusterInstance.serverlessV2('Reader1', {
              scaleWithWriter: true,
            }),
          ]
        : [],
      vpc: this.vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      },
      securityGroups: [this.databaseSecurityGroup],
      defaultDatabaseName: this.databaseName,
      storageEncrypted: true,
      deletionProtection: isProd,
      backup: {
        retention: cdk.Duration.days(isProd ? 35 : 7),
      },
      monitoringInterval: isProd ? cdk.Duration.seconds(60) : undefined,
      cloudwatchLogsExports: isProd ? ['postgresql'] : undefined,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Store the secret reference
    this.databaseSecret = this.cluster.secret!;
    this.databaseEndpoint = this.cluster.clusterEndpoint.hostname;

    // ============================================
    // VPC Endpoints for Lambda Access
    // ============================================

    // Secrets Manager endpoint for Lambda to retrieve credentials
    this.vpc.addInterfaceEndpoint('SecretsManagerEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      subnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
    });

    // RDS Data API endpoint (optional, for simpler queries)
    this.vpc.addInterfaceEndpoint('RdsDataEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.RDS_DATA,
      subnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
    });

    // ============================================
    // Stack Outputs
    // ============================================

    new cdk.CfnOutput(this, 'LedgerVpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID for Ledger infrastructure',
      exportName: 'VettID-Ledger-VpcId',
    });

    new cdk.CfnOutput(this, 'LedgerClusterEndpoint', {
      value: this.cluster.clusterEndpoint.hostname,
      description: 'Aurora cluster endpoint',
      exportName: 'VettID-Ledger-ClusterEndpoint',
    });

    new cdk.CfnOutput(this, 'LedgerClusterPort', {
      value: this.cluster.clusterEndpoint.port.toString(),
      description: 'Aurora cluster port',
      exportName: 'VettID-Ledger-ClusterPort',
    });

    new cdk.CfnOutput(this, 'LedgerSecretArn', {
      value: this.databaseSecret.secretArn,
      description: 'Secrets Manager ARN for database credentials',
      exportName: 'VettID-Ledger-SecretArn',
    });

    new cdk.CfnOutput(this, 'LedgerDatabaseName', {
      value: this.databaseName,
      description: 'Ledger database name',
      exportName: 'VettID-Ledger-DatabaseName',
    });

    new cdk.CfnOutput(this, 'LedgerSecurityGroupId', {
      value: this.lambdaSecurityGroup.securityGroupId,
      description: 'Security group ID for Lambda functions',
      exportName: 'VettID-Ledger-LambdaSecurityGroupId',
    });
  }

  /**
   * Get the environment variables needed for Lambda functions to connect to the database
   */
  public getDatabaseEnv(): { [key: string]: string } {
    return {
      LEDGER_DB_HOST: this.databaseEndpoint,
      LEDGER_DB_PORT: '5432',
      LEDGER_DB_NAME: this.databaseName,
      LEDGER_DB_SECRET_ARN: this.databaseSecret.secretArn,
    };
  }

  /**
   * Get the VPC configuration for Lambda functions
   */
  public getLambdaVpcConfig(): {
    vpc: ec2.IVpc;
    vpcSubnets: ec2.SubnetSelection;
    securityGroups: ec2.ISecurityGroup[];
  } {
    return {
      vpc: this.vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      securityGroups: [this.lambdaSecurityGroup],
    };
  }

  /**
   * Grant a Lambda function permission to access the database
   */
  public grantDatabaseAccess(lambdaFunction: lambda.IFunction): void {
    // Grant permission to read database secret
    this.databaseSecret.grantRead(lambdaFunction);

    // Grant RDS Data API access (if using Data API)
    lambdaFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'rds-data:ExecuteStatement',
          'rds-data:BatchExecuteStatement',
          'rds-data:BeginTransaction',
          'rds-data:CommitTransaction',
          'rds-data:RollbackTransaction',
        ],
        resources: [this.cluster.clusterArn],
      })
    );
  }
}
