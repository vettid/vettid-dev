import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface VaultStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
}

/**
 * VettID Vault Stack
 *
 * Contains vault enrollment and authentication services:
 * - Vault enrollment Lambda functions
 * - Vault authentication Lambda functions
 * - NATS account management Lambda functions
 * - API routes added by VettIDStack after instantiation
 *
 * Depends on: Infrastructure Stack (for tables, user pool)
 */
export class VaultStack extends cdk.Stack {
  // Public Lambda functions to be used by VettIDStack for route creation
  public readonly enrollStart!: lambdaNode.NodejsFunction;
  public readonly enrollSetPassword!: lambdaNode.NodejsFunction;
  public readonly enrollFinalize!: lambdaNode.NodejsFunction;
  public readonly actionRequest!: lambdaNode.NodejsFunction;
  public readonly authExecute!: lambdaNode.NodejsFunction;

  // NATS account management functions
  public readonly natsCreateAccount!: lambdaNode.NodejsFunction;
  public readonly natsGenerateToken!: lambdaNode.NodejsFunction;
  public readonly natsRevokeToken!: lambdaNode.NodejsFunction;
  public readonly natsGetStatus!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: VaultStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const memberUserPool = props.infrastructure.memberUserPool;

    // Default environment variables for vault functions
    const defaultEnv = {
      TABLE_CREDENTIALS: tables.credentials.tableName,
      TABLE_CREDENTIAL_KEYS: tables.credentialKeys.tableName,
      TABLE_TRANSACTION_KEYS: tables.transactionKeys.tableName,
      TABLE_LEDGER_AUTH_TOKENS: tables.ledgerAuthTokens.tableName,
      TABLE_ACTION_TOKENS: tables.actionTokens.tableName,
      TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
    };

    // ===== VAULT ENROLLMENT =====

    this.enrollStart = new lambdaNode.NodejsFunction(this, 'EnrollStartFn', {
      entry: 'lambda/handlers/vault/enrollStart.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.enrollSetPassword = new lambdaNode.NodejsFunction(this, 'EnrollSetPasswordFn', {
      entry: 'lambda/handlers/vault/enrollSetPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.enrollFinalize = new lambdaNode.NodejsFunction(this, 'EnrollFinalizeFn', {
      entry: 'lambda/handlers/vault/enrollFinalize.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== VAULT AUTHENTICATION =====

    this.actionRequest = new lambdaNode.NodejsFunction(this, 'ActionRequestFn', {
      entry: 'lambda/handlers/vault/actionRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.authExecute = new lambdaNode.NodejsFunction(this, 'AuthExecuteFn', {
      entry: 'lambda/handlers/vault/authExecute.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== NATS ACCOUNT MANAGEMENT =====

    const natsEnv = {
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      TABLE_NATS_TOKENS: tables.natsTokens.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      NATS_DOMAIN: 'nats.vettid.dev',
    };

    this.natsCreateAccount = new lambdaNode.NodejsFunction(this, 'NatsCreateAccountFn', {
      entry: 'lambda/handlers/nats/createMemberAccount.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: natsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.natsGenerateToken = new lambdaNode.NodejsFunction(this, 'NatsGenerateTokenFn', {
      entry: 'lambda/handlers/nats/generateMemberJwt.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: natsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.natsRevokeToken = new lambdaNode.NodejsFunction(this, 'NatsRevokeTokenFn', {
      entry: 'lambda/handlers/nats/revokeToken.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: natsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.natsGetStatus = new lambdaNode.NodejsFunction(this, 'NatsGetStatusFn', {
      entry: 'lambda/handlers/nats/getNatsStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: natsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== PERMISSIONS =====

    // Grant table permissions
    tables.enrollmentSessions.grantReadWriteData(this.enrollStart);
    tables.enrollmentSessions.grantReadWriteData(this.enrollSetPassword);
    tables.enrollmentSessions.grantReadWriteData(this.enrollFinalize);

    tables.credentials.grantReadWriteData(this.enrollFinalize);
    tables.credentials.grantReadData(this.actionRequest);
    tables.credentials.grantReadData(this.authExecute);

    tables.credentialKeys.grantReadWriteData(this.enrollFinalize);
    tables.credentialKeys.grantReadData(this.actionRequest);
    tables.credentialKeys.grantReadData(this.authExecute);

    tables.transactionKeys.grantReadWriteData(this.actionRequest);
    tables.transactionKeys.grantReadWriteData(this.authExecute);

    tables.ledgerAuthTokens.grantReadWriteData(this.authExecute);

    tables.actionTokens.grantReadWriteData(this.actionRequest);
    tables.actionTokens.grantReadWriteData(this.authExecute);

    tables.registrations.grantReadData(this.enrollStart);
    tables.registrations.grantReadData(this.enrollFinalize);

    // Grant audit table permissions for all vault functions
    tables.audit.grantReadWriteData(this.enrollStart);
    tables.audit.grantReadWriteData(this.enrollSetPassword);
    tables.audit.grantReadWriteData(this.enrollFinalize);
    tables.audit.grantReadWriteData(this.actionRequest);
    tables.audit.grantReadWriteData(this.authExecute);

    // Grant Cognito permissions for enrollment finalization
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminUpdateUserAttributes',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    // Grant SES permissions for email sending
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/auth.vettid.dev`;
    [this.enrollStart, this.actionRequest].forEach(fn => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ses:SendEmail', 'ses:SendTemplatedEmail'],
        resources: [sesIdentityArn],
      }));
    });

    // ===== NATS PERMISSIONS =====

    // Grant NATS accounts table access
    tables.natsAccounts.grantReadWriteData(this.natsCreateAccount);
    tables.natsAccounts.grantReadData(this.natsGenerateToken);
    tables.natsAccounts.grantReadData(this.natsGetStatus);

    // Grant NATS tokens table access
    tables.natsTokens.grantReadWriteData(this.natsGenerateToken);
    tables.natsTokens.grantReadWriteData(this.natsRevokeToken);
    tables.natsTokens.grantReadData(this.natsGetStatus);

    // Grant audit table access for NATS functions
    tables.audit.grantReadWriteData(this.natsCreateAccount);
    tables.audit.grantReadWriteData(this.natsGenerateToken);
    tables.audit.grantReadWriteData(this.natsRevokeToken);
  }
}
