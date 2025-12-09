import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_authorizers as authorizers,
  aws_apigatewayv2_integrations as integrations,
  custom_resources as cr,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';
import { LedgerStack } from './ledger-stack';
import { VaultInfrastructureStack } from './vault-infrastructure-stack';

export interface VaultStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  memberAuthorizer: apigw.IHttpRouteAuthorizer;
  ledger?: LedgerStack;  // Optional until Ledger is deployed
  vaultInfra?: VaultInfrastructureStack;  // Optional until VaultInfra is deployed
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
  public readonly createEnrollmentSession!: lambdaNode.NodejsFunction;
  public readonly actionRequest!: lambdaNode.NodejsFunction;
  public readonly authExecute!: lambdaNode.NodejsFunction;

  // Device attestation handlers (Phase 2)
  public readonly verifyAndroidAttestation!: lambdaNode.NodejsFunction;
  public readonly verifyIosAttestation!: lambdaNode.NodejsFunction;

  // NATS account management functions
  public readonly natsCreateAccount!: lambdaNode.NodejsFunction;
  public readonly natsGenerateToken!: lambdaNode.NodejsFunction;
  public readonly natsRevokeToken!: lambdaNode.NodejsFunction;
  public readonly natsGetStatus!: lambdaNode.NodejsFunction;

  // Vault lifecycle management functions
  public readonly provisionVault!: lambdaNode.NodejsFunction;
  public readonly initializeVault!: lambdaNode.NodejsFunction;
  public readonly stopVault!: lambdaNode.NodejsFunction;
  public readonly terminateVault!: lambdaNode.NodejsFunction;
  public readonly getVaultStatus!: lambdaNode.NodejsFunction;
  public readonly getVaultHealth!: lambdaNode.NodejsFunction;

  // Handler registry functions (public endpoints)
  public readonly listHandlers!: lambdaNode.NodejsFunction;
  public readonly getHandler!: lambdaNode.NodejsFunction;
  public readonly installHandler!: lambdaNode.NodejsFunction;
  public readonly uninstallHandler!: lambdaNode.NodejsFunction;
  public readonly listInstalledHandlers!: lambdaNode.NodejsFunction;
  public readonly executeHandler!: lambdaNode.NodejsFunction;

  // Phase 7: Connections & Messaging
  public readonly createConnectionInvite!: lambdaNode.NodejsFunction;
  public readonly acceptConnectionInvite!: lambdaNode.NodejsFunction;
  public readonly revokeConnection!: lambdaNode.NodejsFunction;
  public readonly listConnections!: lambdaNode.NodejsFunction;
  public readonly getConnection!: lambdaNode.NodejsFunction;
  public readonly getConnectionProfile!: lambdaNode.NodejsFunction;

  // Profile management
  public readonly getProfile!: lambdaNode.NodejsFunction;
  public readonly updateProfile!: lambdaNode.NodejsFunction;
  public readonly publishProfile!: lambdaNode.NodejsFunction;

  // Messaging
  public readonly sendMessage!: lambdaNode.NodejsFunction;
  public readonly getMessageHistory!: lambdaNode.NodejsFunction;
  public readonly getUnreadCount!: lambdaNode.NodejsFunction;
  public readonly markMessageRead!: lambdaNode.NodejsFunction;

  // Phase 8: Backup System
  public readonly triggerBackup!: lambdaNode.NodejsFunction;
  public readonly listBackups!: lambdaNode.NodejsFunction;
  public readonly restoreBackup!: lambdaNode.NodejsFunction;
  public readonly deleteBackup!: lambdaNode.NodejsFunction;
  public readonly createCredentialBackup!: lambdaNode.NodejsFunction;
  public readonly getCredentialBackupStatus!: lambdaNode.NodejsFunction;
  public readonly downloadCredentialBackup!: lambdaNode.NodejsFunction;
  public readonly getBackupSettings!: lambdaNode.NodejsFunction;
  public readonly updateBackupSettings!: lambdaNode.NodejsFunction;

  // BYOV (Bring Your Own Vault)
  public readonly registerByovVault!: lambdaNode.NodejsFunction;
  public readonly getByovStatus!: lambdaNode.NodejsFunction;
  public readonly verifyByovVault!: lambdaNode.NodejsFunction;
  public readonly updateByovVault!: lambdaNode.NodejsFunction;
  public readonly deleteByovVault!: lambdaNode.NodejsFunction;

  // Ledger (Protean Credential System) - Phase 1
  public readonly ledgerVerifyPassword?: lambdaNode.NodejsFunction;
  public readonly ledgerValidateLAT?: lambdaNode.NodejsFunction;
  public readonly ledgerGetTransactionKeys?: lambdaNode.NodejsFunction;
  public readonly ledgerReplenishTransactionKeys?: lambdaNode.NodejsFunction;
  public readonly ledgerCreateCredential?: lambdaNode.NodejsFunction;
  public readonly ledgerRotateKeys?: lambdaNode.NodejsFunction;

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

    // Web-initiated enrollment session (for QR code flow)
    this.createEnrollmentSession = new lambdaNode.NodejsFunction(this, 'CreateEnrollmentSessionFn', {
      entry: 'lambda/handlers/vault/createEnrollmentSession.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        API_URL: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com',
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== DEVICE ATTESTATION (Phase 2) =====

    this.verifyAndroidAttestation = new lambdaNode.NodejsFunction(this, 'VerifyAndroidAttestationFn', {
      entry: 'lambda/handlers/attestation/verifyAndroidAttestation.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_AUDIT: tables.audit.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.verifyIosAttestation = new lambdaNode.NodejsFunction(this, 'VerifyIosAttestationFn', {
      entry: 'lambda/handlers/attestation/verifyIosAttestation.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_AUDIT: tables.audit.tableName,
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

    // NATS operator secret for signing JWTs
    const natsOperatorSecret = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'NatsOperatorSecret', 'vettid/nats/operator-key'
    );

    const natsEnv = {
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      TABLE_NATS_TOKENS: tables.natsTokens.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      NATS_DOMAIN: 'nats.vettid.dev',
      NATS_OPERATOR_SECRET_ARN: natsOperatorSecret.secretArn,
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

    // ===== VAULT LIFECYCLE MANAGEMENT =====

    // Get vault EC2 configuration from VaultInfrastructureStack if provided
    const vaultConfig = props.vaultInfra?.vaultConfig;

    const vaultLifecycleEnv = {
      TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      TABLE_CREDENTIALS: tables.credentials.tableName,
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      VAULT_AMI_ID: process.env.VAULT_AMI_ID || 'ami-placeholder',
      VAULT_INSTANCE_TYPE: 't4g.nano',
      VAULT_SECURITY_GROUP: vaultConfig?.securityGroupId || '',
      VAULT_SUBNET_IDS: vaultConfig?.subnetIds || '',
      VAULT_IAM_PROFILE: vaultConfig?.iamProfileName || '',
    };

    this.provisionVault = new lambdaNode.NodejsFunction(this, 'ProvisionVaultFn', {
      entry: 'lambda/handlers/vault/provisionVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultLifecycleEnv,
      timeout: cdk.Duration.seconds(60),
    });

    this.initializeVault = new lambdaNode.NodejsFunction(this, 'InitializeVaultFn', {
      entry: 'lambda/handlers/vault/initializeVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.stopVault = new lambdaNode.NodejsFunction(this, 'StopVaultFn', {
      entry: 'lambda/handlers/vault/stopVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.terminateVault = new lambdaNode.NodejsFunction(this, 'TerminateVaultFn', {
      entry: 'lambda/handlers/vault/terminateVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.getVaultHealth = new lambdaNode.NodejsFunction(this, 'GetVaultHealthFn', {
      entry: 'lambda/handlers/vault/getVaultHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.getVaultStatus = new lambdaNode.NodejsFunction(this, 'GetVaultStatusFn', {
      entry: 'lambda/handlers/vault/getVaultStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
        TABLE_CREDENTIALS: tables.credentials.tableName,
        TABLE_TRANSACTION_KEYS: tables.transactionKeys.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== HANDLER REGISTRY =====

    const handlerEnv = {
      TABLE_HANDLERS: tables.handlers.tableName,
      TABLE_HANDLER_INSTALLATIONS: tables.handlerInstallations.tableName,
      TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      BUCKET_HANDLERS: props.infrastructure.handlersBucket.bucketName,
    };

    this.listHandlers = new lambdaNode.NodejsFunction(this, 'ListHandlersFn', {
      entry: 'lambda/handlers/registry/listHandlers.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.getHandler = new lambdaNode.NodejsFunction(this, 'GetHandlerFn', {
      entry: 'lambda/handlers/registry/getHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.installHandler = new lambdaNode.NodejsFunction(this, 'InstallHandlerFn', {
      entry: 'lambda/handlers/registry/installHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.uninstallHandler = new lambdaNode.NodejsFunction(this, 'UninstallHandlerFn', {
      entry: 'lambda/handlers/registry/uninstallHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.listInstalledHandlers = new lambdaNode.NodejsFunction(this, 'ListInstalledHandlersFn', {
      entry: 'lambda/handlers/registry/listInstalledHandlers.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.executeHandler = new lambdaNode.NodejsFunction(this, 'ExecuteHandlerFn', {
      entry: 'lambda/handlers/registry/executeHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(60), // Longer timeout for handler execution
    });

    // ===== PERMISSIONS =====

    // Grant table permissions
    tables.enrollmentSessions.grantReadWriteData(this.enrollStart);
    tables.enrollmentSessions.grantReadWriteData(this.enrollSetPassword);
    tables.enrollmentSessions.grantReadWriteData(this.enrollFinalize);
    tables.enrollmentSessions.grantReadWriteData(this.createEnrollmentSession);
    tables.credentials.grantReadData(this.createEnrollmentSession);
    tables.audit.grantReadWriteData(this.createEnrollmentSession);

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

    // ===== DEVICE ATTESTATION PERMISSIONS (Phase 2) =====
    tables.enrollmentSessions.grantReadWriteData(this.verifyAndroidAttestation);
    tables.enrollmentSessions.grantReadWriteData(this.verifyIosAttestation);
    tables.audit.grantReadWriteData(this.verifyAndroidAttestation);
    tables.audit.grantReadWriteData(this.verifyIosAttestation);

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

    // Grant NATS operator secret access for JWT signing
    natsOperatorSecret.grantRead(this.natsCreateAccount);
    natsOperatorSecret.grantRead(this.natsGenerateToken);

    // ===== VAULT LIFECYCLE PERMISSIONS =====

    // Grant vault instances table access
    tables.vaultInstances.grantReadWriteData(this.provisionVault);
    tables.vaultInstances.grantReadWriteData(this.initializeVault);
    tables.vaultInstances.grantReadWriteData(this.stopVault);
    tables.vaultInstances.grantReadWriteData(this.terminateVault);
    tables.vaultInstances.grantReadWriteData(this.getVaultHealth);

    // Grant getVaultStatus access to enrollment sessions, credentials, and transaction keys
    tables.enrollmentSessions.grantReadData(this.getVaultStatus);
    tables.credentials.grantReadData(this.getVaultStatus);
    tables.transactionKeys.grantReadData(this.getVaultStatus);

    // provisionVault needs to check credentials and NATS accounts
    tables.credentials.grantReadData(this.provisionVault);
    tables.natsAccounts.grantReadData(this.provisionVault);

    // Grant EC2 permissions for vault lifecycle management
    const ec2Policy = new iam.PolicyStatement({
      actions: [
        'ec2:RunInstances',
        'ec2:CreateTags',
        'ec2:DescribeInstances',
        'ec2:DescribeInstanceStatus',
        'ec2:DescribeSubnets',
        'ec2:StopInstances',
        'ec2:StartInstances',
        'ec2:TerminateInstances',
      ],
      resources: ['*'], // EC2 RunInstances requires broad permissions
    });

    this.provisionVault.addToRolePolicy(ec2Policy);
    this.initializeVault.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DescribeInstances'],
      resources: ['*'],
    }));
    this.stopVault.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:StopInstances', 'ec2:DescribeInstances'],
      resources: ['*'],
    }));
    this.terminateVault.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:TerminateInstances', 'ec2:DescribeInstances'],
      resources: ['*'],
    }));
    this.getVaultHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DescribeInstances', 'ec2:DescribeInstanceStatus'],
      resources: ['*'],
    }));

    // Grant IAM pass role permission if using instance profile
    // This will be needed when VAULT_IAM_PROFILE is set
    this.provisionVault.addToRolePolicy(new iam.PolicyStatement({
      actions: ['iam:PassRole'],
      resources: [`arn:aws:iam::${this.account}:role/vettid-vault-*`],
    }));

    // ===== HANDLER REGISTRY PERMISSIONS =====

    // Grant handlers table access
    tables.handlers.grantReadData(this.listHandlers);
    tables.handlers.grantReadData(this.getHandler);
    tables.handlers.grantReadData(this.installHandler);
    tables.handlers.grantReadWriteData(this.installHandler);
    tables.handlers.grantReadWriteData(this.uninstallHandler);
    tables.handlers.grantReadData(this.listInstalledHandlers);

    // Grant handler installations table access
    tables.handlerInstallations.grantReadData(this.listHandlers);
    tables.handlerInstallations.grantReadData(this.getHandler);
    tables.handlerInstallations.grantReadWriteData(this.installHandler);
    tables.handlerInstallations.grantReadWriteData(this.uninstallHandler);
    tables.handlerInstallations.grantReadData(this.listInstalledHandlers);
    tables.handlerInstallations.grantReadData(this.executeHandler);

    // Grant vault instances table access for execute
    tables.vaultInstances.grantReadData(this.executeHandler);

    // Grant S3 access for handler downloads
    props.infrastructure.handlersBucket.grantRead(this.getHandler);

    // ===== PHASE 7: CONNECTIONS & MESSAGING =====

    const connectionsEnv = {
      TABLE_CONNECTIONS: tables.connections.tableName,
      TABLE_INVITATIONS: tables.connectionInvitations.tableName,
      TABLE_PROFILES: tables.profiles.tableName,
      TABLE_MESSAGES: tables.messages.tableName,
    };

    // Connection management functions
    this.createConnectionInvite = new lambdaNode.NodejsFunction(this, 'CreateConnectionInviteFn', {
      entry: 'lambda/handlers/connections/createInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.acceptConnectionInvite = new lambdaNode.NodejsFunction(this, 'AcceptConnectionInviteFn', {
      entry: 'lambda/handlers/connections/acceptInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.revokeConnection = new lambdaNode.NodejsFunction(this, 'RevokeConnectionFn', {
      entry: 'lambda/handlers/connections/revokeConnection.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.listConnections = new lambdaNode.NodejsFunction(this, 'ListConnectionsFn', {
      entry: 'lambda/handlers/connections/listConnections.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.getConnection = new lambdaNode.NodejsFunction(this, 'GetConnectionFn', {
      entry: 'lambda/handlers/connections/getConnection.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.getConnectionProfile = new lambdaNode.NodejsFunction(this, 'GetConnectionProfileFn', {
      entry: 'lambda/handlers/connections/getConnectionProfile.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: connectionsEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Profile management functions
    this.getProfile = new lambdaNode.NodejsFunction(this, 'GetProfileFn', {
      entry: 'lambda/handlers/profile/getProfile.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_PROFILES: tables.profiles.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.updateProfile = new lambdaNode.NodejsFunction(this, 'UpdateProfileFn', {
      entry: 'lambda/handlers/profile/updateProfile.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_PROFILES: tables.profiles.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.publishProfile = new lambdaNode.NodejsFunction(this, 'PublishProfileFn', {
      entry: 'lambda/handlers/profile/publishProfile.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_PROFILES: tables.profiles.tableName,
        TABLE_CONNECTIONS: tables.connections.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Messaging functions
    this.sendMessage = new lambdaNode.NodejsFunction(this, 'SendMessageFn', {
      entry: 'lambda/handlers/messaging/sendMessage.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CONNECTIONS: tables.connections.tableName,
        TABLE_MESSAGES: tables.messages.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.getMessageHistory = new lambdaNode.NodejsFunction(this, 'GetMessageHistoryFn', {
      entry: 'lambda/handlers/messaging/getMessageHistory.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CONNECTIONS: tables.connections.tableName,
        TABLE_MESSAGES: tables.messages.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.getUnreadCount = new lambdaNode.NodejsFunction(this, 'GetUnreadCountFn', {
      entry: 'lambda/handlers/messaging/getUnreadCount.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CONNECTIONS: tables.connections.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.markMessageRead = new lambdaNode.NodejsFunction(this, 'MarkMessageReadFn', {
      entry: 'lambda/handlers/messaging/markAsRead.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CONNECTIONS: tables.connections.tableName,
        TABLE_MESSAGES: tables.messages.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== PHASE 7 PERMISSIONS =====

    // Connection invitations - createConnectionInvite needs read/write
    tables.connectionInvitations.grantReadWriteData(this.createConnectionInvite);
    tables.connectionInvitations.grantReadWriteData(this.acceptConnectionInvite);

    // Connections table permissions
    tables.connections.grantReadWriteData(this.acceptConnectionInvite);
    tables.connections.grantReadWriteData(this.revokeConnection);
    tables.connections.grantReadData(this.listConnections);
    tables.connections.grantReadData(this.getConnection);
    tables.connections.grantReadData(this.getConnectionProfile);
    tables.connections.grantReadWriteData(this.publishProfile);
    tables.connections.grantReadData(this.sendMessage);
    tables.connections.grantReadWriteData(this.sendMessage); // Needs write for unread_count
    tables.connections.grantReadData(this.getMessageHistory);
    tables.connections.grantReadData(this.getUnreadCount);
    tables.connections.grantReadWriteData(this.markMessageRead);

    // Profiles table permissions
    tables.profiles.grantReadWriteData(this.getProfile); // Creates default if missing
    tables.profiles.grantReadWriteData(this.updateProfile);
    tables.profiles.grantReadData(this.publishProfile);
    tables.profiles.grantReadData(this.getConnectionProfile);
    tables.profiles.grantReadData(this.acceptConnectionInvite);

    // Messages table permissions
    tables.messages.grantReadWriteData(this.sendMessage);
    tables.messages.grantReadData(this.getMessageHistory);
    tables.messages.grantReadWriteData(this.markMessageRead);

    // ===== PHASE 8: BACKUP SYSTEM =====

    const backupEnv = {
      TABLE_BACKUPS: tables.backups.tableName,
      TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
      TABLE_CONNECTIONS: tables.connections.tableName,
      TABLE_PROFILES: tables.profiles.tableName,
      TABLE_MESSAGES: tables.messages.tableName,
      BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
    };

    // Vault backup functions
    this.triggerBackup = new lambdaNode.NodejsFunction(this, 'TriggerBackupFn', {
      entry: 'lambda/handlers/backup/triggerBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(60),
      memorySize: 512, // More memory for backup operations
    });

    this.listBackups = new lambdaNode.NodejsFunction(this, 'ListBackupsFn', {
      entry: 'lambda/handlers/backup/listBackups.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_BACKUPS: tables.backups.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreBackup = new lambdaNode.NodejsFunction(this, 'RestoreBackupFn', {
      entry: 'lambda/handlers/backup/restoreBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: backupEnv,
      timeout: cdk.Duration.seconds(120),
      memorySize: 512,
    });

    this.deleteBackup = new lambdaNode.NodejsFunction(this, 'DeleteBackupFn', {
      entry: 'lambda/handlers/backup/deleteBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_BACKUPS: tables.backups.tableName,
        BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Credential backup functions
    this.createCredentialBackup = new lambdaNode.NodejsFunction(this, 'CreateCredentialBackupFn', {
      entry: 'lambda/handlers/backup/createCredentialBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
        BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.getCredentialBackupStatus = new lambdaNode.NodejsFunction(this, 'GetCredentialBackupStatusFn', {
      entry: 'lambda/handlers/backup/getCredentialBackupStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.downloadCredentialBackup = new lambdaNode.NodejsFunction(this, 'DownloadCredentialBackupFn', {
      entry: 'lambda/handlers/backup/downloadCredentialBackup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
        BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Backup settings functions
    this.getBackupSettings = new lambdaNode.NodejsFunction(this, 'GetBackupSettingsFn', {
      entry: 'lambda/handlers/backup/getBackupSettings.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.updateBackupSettings = new lambdaNode.NodejsFunction(this, 'UpdateBackupSettingsFn', {
      entry: 'lambda/handlers/backup/updateBackupSettings.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== BYOV (Bring Your Own Vault) =====

    const byovEnv = {
      TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      TABLE_AUDIT: tables.audit.tableName,
    };

    this.registerByovVault = new lambdaNode.NodejsFunction(this, 'RegisterByovVaultFn', {
      entry: 'lambda/handlers/vault/registerByovVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: byovEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.getByovStatus = new lambdaNode.NodejsFunction(this, 'GetByovStatusFn', {
      entry: 'lambda/handlers/vault/getByovStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.verifyByovVault = new lambdaNode.NodejsFunction(this, 'VerifyByovVaultFn', {
      entry: 'lambda/handlers/vault/verifyByovVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: byovEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.updateByovVault = new lambdaNode.NodejsFunction(this, 'UpdateByovVaultFn', {
      entry: 'lambda/handlers/vault/updateByovVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: byovEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.deleteByovVault = new lambdaNode.NodejsFunction(this, 'DeleteByovVaultFn', {
      entry: 'lambda/handlers/vault/deleteByovVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: byovEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== PHASE 8 PERMISSIONS =====

    // Backups table permissions
    tables.backups.grantReadWriteData(this.triggerBackup);
    tables.backups.grantReadData(this.listBackups);
    tables.backups.grantReadWriteData(this.restoreBackup);
    tables.backups.grantReadWriteData(this.deleteBackup);

    // Credential backups table permissions
    tables.credentialBackups.grantReadWriteData(this.createCredentialBackup);
    tables.credentialBackups.grantReadData(this.getCredentialBackupStatus);
    tables.credentialBackups.grantReadWriteData(this.downloadCredentialBackup);

    // Backup settings table permissions
    tables.backupSettings.grantReadData(this.getBackupSettings);
    tables.backupSettings.grantReadWriteData(this.updateBackupSettings);

    // S3 backup bucket permissions
    props.infrastructure.backupBucket.grantReadWrite(this.triggerBackup);
    props.infrastructure.backupBucket.grantRead(this.restoreBackup);
    props.infrastructure.backupBucket.grantDelete(this.deleteBackup);
    props.infrastructure.backupBucket.grantReadWrite(this.createCredentialBackup);
    props.infrastructure.backupBucket.grantRead(this.downloadCredentialBackup);

    // triggerBackup needs read access to connections, profiles, messages
    tables.connections.grantReadData(this.triggerBackup);
    tables.profiles.grantReadData(this.triggerBackup);
    tables.messages.grantReadData(this.triggerBackup);

    // restoreBackup needs write access to connections, profiles, messages
    tables.connections.grantReadWriteData(this.restoreBackup);
    tables.profiles.grantReadWriteData(this.restoreBackup);
    tables.messages.grantReadWriteData(this.restoreBackup);

    // ===== BYOV PERMISSIONS =====

    // Grant vault instances table access for BYOV functions
    tables.vaultInstances.grantReadWriteData(this.registerByovVault);
    tables.vaultInstances.grantReadData(this.getByovStatus);
    tables.vaultInstances.grantReadWriteData(this.verifyByovVault);
    tables.vaultInstances.grantReadWriteData(this.updateByovVault);
    tables.vaultInstances.grantReadWriteData(this.deleteByovVault);

    // Grant audit table access for BYOV functions
    tables.audit.grantReadWriteData(this.registerByovVault);
    tables.audit.grantReadWriteData(this.verifyByovVault);
    tables.audit.grantReadWriteData(this.updateByovVault);
    tables.audit.grantReadWriteData(this.deleteByovVault);

    // ===== LEDGER (PROTEAN CREDENTIAL SYSTEM) - Phase 1 =====
    // Only created if LedgerStack is provided
    if (props.ledger) {
      const ledgerDbEnv = props.ledger.getDatabaseEnv();
      const ledgerVpcConfig = props.ledger.getLambdaVpcConfig();

      // Password verification
      this.ledgerVerifyPassword = new lambdaNode.NodejsFunction(this, 'LedgerVerifyPasswordFn', {
        entry: 'lambda/handlers/ledger/verifyPassword.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
        memorySize: 256, // Argon2id needs more memory
      });
      props.ledger.grantDatabaseAccess(this.ledgerVerifyPassword);

      // LAT validation and rotation
      this.ledgerValidateLAT = new lambdaNode.NodejsFunction(this, 'LedgerValidateLATFn', {
        entry: 'lambda/handlers/ledger/validateLAT.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
      });
      props.ledger.grantDatabaseAccess(this.ledgerValidateLAT);

      // Get transaction keys
      this.ledgerGetTransactionKeys = new lambdaNode.NodejsFunction(this, 'LedgerGetTransactionKeysFn', {
        entry: 'lambda/handlers/ledger/getTransactionKeys.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
      });
      props.ledger.grantDatabaseAccess(this.ledgerGetTransactionKeys);

      // Replenish transaction keys
      this.ledgerReplenishTransactionKeys = new lambdaNode.NodejsFunction(this, 'LedgerReplenishTransactionKeysFn', {
        entry: 'lambda/handlers/ledger/replenishTransactionKeys.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
      });
      props.ledger.grantDatabaseAccess(this.ledgerReplenishTransactionKeys);

      // Create credential (CEK)
      this.ledgerCreateCredential = new lambdaNode.NodejsFunction(this, 'LedgerCreateCredentialFn', {
        entry: 'lambda/handlers/ledger/createCredential.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
      });
      props.ledger.grantDatabaseAccess(this.ledgerCreateCredential);

      // Rotate keys
      this.ledgerRotateKeys = new lambdaNode.NodejsFunction(this, 'LedgerRotateKeysFn', {
        entry: 'lambda/handlers/ledger/rotateKeys.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.seconds(30),
      });
      props.ledger.grantDatabaseAccess(this.ledgerRotateKeys);

      // Database migration Lambda
      const runMigration = new lambdaNode.NodejsFunction(this, 'LedgerRunMigrationFn', {
        entry: 'lambda/handlers/ledger/runMigration.ts',
        runtime: lambda.Runtime.NODEJS_22_X,
        environment: ledgerDbEnv,
        ...ledgerVpcConfig,
        timeout: cdk.Duration.minutes(5),  // Migrations may take time
        memorySize: 256,
      });
      props.ledger.grantDatabaseAccess(runMigration);

      // Custom resource to run migrations on deploy
      const migrationProvider = new cr.Provider(this, 'MigrationProvider', {
        onEventHandler: runMigration,
      });

      new cdk.CustomResource(this, 'LedgerMigration', {
        serviceToken: migrationProvider.serviceToken,
        properties: {
          // Change this to force migration re-run (e.g., bump version)
          version: '2',  // Bumped from 1 to 2 to re-run after SSL fix
          action: 'run',
        },
      });
    }

    // Add API routes - done here to keep route resources in VaultStack
    this.addRoutes(props.httpApi, props.memberAuthorizer);
  }

  /**
   * Helper to create a route in this stack's scope (avoids cyclic dependency)
   */
  private route(
    id: string,
    httpApi: apigw.HttpApi,
    path: string,
    method: apigw.HttpMethod,
    handler: lambdaNode.NodejsFunction,
    authorizer: apigw.IHttpRouteAuthorizer,
  ): void {
    new apigw.HttpRoute(this, id, {
      httpApi,
      routeKey: apigw.HttpRouteKey.with(path, method),
      integration: new integrations.HttpLambdaIntegration(`${id}Int`, handler),
      authorizer,
    });
  }

  /**
   * Add vault routes to the HTTP API
   * Routes are created in VaultStack to stay under CloudFormation's 500 resource limit
   * Using HttpRoute directly (not httpApi.addRoutes) to avoid cyclic dependencies
   */
  private addRoutes(httpApi: apigw.HttpApi, memberAuthorizer: apigw.IHttpRouteAuthorizer): void {
    // Vault Enrollment
    this.route('CreateEnrollmentSession', httpApi, '/vault/enroll/session', apigw.HttpMethod.POST, this.createEnrollmentSession, memberAuthorizer);
    this.route('EnrollStart', httpApi, '/vault/enroll/start', apigw.HttpMethod.POST, this.enrollStart, memberAuthorizer);
    this.route('EnrollSetPassword', httpApi, '/vault/enroll/set-password', apigw.HttpMethod.POST, this.enrollSetPassword, memberAuthorizer);
    this.route('EnrollFinalize', httpApi, '/vault/enroll/finalize', apigw.HttpMethod.POST, this.enrollFinalize, memberAuthorizer);

    // Device Attestation (Phase 2)
    this.route('VerifyAndroidAttestation', httpApi, '/vault/enroll/attestation/android', apigw.HttpMethod.POST, this.verifyAndroidAttestation, memberAuthorizer);
    this.route('VerifyIosAttestation', httpApi, '/vault/enroll/attestation/ios', apigw.HttpMethod.POST, this.verifyIosAttestation, memberAuthorizer);

    // Vault Authentication
    this.route('ActionRequest', httpApi, '/vault/action/request', apigw.HttpMethod.POST, this.actionRequest, memberAuthorizer);
    this.route('AuthExecute', httpApi, '/vault/auth/execute', apigw.HttpMethod.POST, this.authExecute, memberAuthorizer);

    // NATS Account Management
    this.route('NatsCreateAccount', httpApi, '/vault/nats/account', apigw.HttpMethod.POST, this.natsCreateAccount, memberAuthorizer);
    this.route('NatsGenerateToken', httpApi, '/vault/nats/token', apigw.HttpMethod.POST, this.natsGenerateToken, memberAuthorizer);
    this.route('NatsRevokeToken', httpApi, '/vault/nats/token/revoke', apigw.HttpMethod.POST, this.natsRevokeToken, memberAuthorizer);
    this.route('NatsGetStatus', httpApi, '/vault/nats/status', apigw.HttpMethod.GET, this.natsGetStatus, memberAuthorizer);

    // Vault Lifecycle Management
    this.route('ProvisionVault', httpApi, '/vault/provision', apigw.HttpMethod.POST, this.provisionVault, memberAuthorizer);
    this.route('InitializeVault', httpApi, '/vault/initialize', apigw.HttpMethod.POST, this.initializeVault, memberAuthorizer);
    this.route('StopVault', httpApi, '/vault/stop', apigw.HttpMethod.POST, this.stopVault, memberAuthorizer);
    this.route('TerminateVault', httpApi, '/vault/terminate', apigw.HttpMethod.POST, this.terminateVault, memberAuthorizer);
    this.route('GetVaultHealth', httpApi, '/vault/health', apigw.HttpMethod.GET, this.getVaultHealth, memberAuthorizer);
    this.route('GetVaultStatus', httpApi, '/vault/status', apigw.HttpMethod.GET, this.getVaultStatus, memberAuthorizer);

    // Handler Registry Routes
    this.route('ListHandlers', httpApi, '/registry/handlers', apigw.HttpMethod.GET, this.listHandlers, memberAuthorizer);
    this.route('GetHandler', httpApi, '/registry/handlers/{id}', apigw.HttpMethod.GET, this.getHandler, memberAuthorizer);
    this.route('InstallHandler', httpApi, '/vault/handlers/install', apigw.HttpMethod.POST, this.installHandler, memberAuthorizer);
    this.route('UninstallHandler', httpApi, '/vault/handlers/uninstall', apigw.HttpMethod.POST, this.uninstallHandler, memberAuthorizer);
    this.route('ListInstalledHandlers', httpApi, '/vault/handlers', apigw.HttpMethod.GET, this.listInstalledHandlers, memberAuthorizer);
    this.route('ExecuteHandler', httpApi, '/vault/handlers/{id}/execute', apigw.HttpMethod.POST, this.executeHandler, memberAuthorizer);

    // Connections & Messaging Routes
    this.route('CreateConnectionInvite', httpApi, '/connections/invite', apigw.HttpMethod.POST, this.createConnectionInvite, memberAuthorizer);
    this.route('AcceptConnectionInvite', httpApi, '/connections/accept', apigw.HttpMethod.POST, this.acceptConnectionInvite, memberAuthorizer);
    this.route('RevokeConnection', httpApi, '/connections/{connectionId}/revoke', apigw.HttpMethod.POST, this.revokeConnection, memberAuthorizer);
    this.route('ListConnections', httpApi, '/connections', apigw.HttpMethod.GET, this.listConnections, memberAuthorizer);
    this.route('GetConnection', httpApi, '/connections/{connectionId}', apigw.HttpMethod.GET, this.getConnection, memberAuthorizer);
    this.route('GetConnectionProfile', httpApi, '/connections/{connectionId}/profile', apigw.HttpMethod.GET, this.getConnectionProfile, memberAuthorizer);

    // Profile management
    this.route('GetProfile', httpApi, '/profile', apigw.HttpMethod.GET, this.getProfile, memberAuthorizer);
    this.route('UpdateProfile', httpApi, '/profile', apigw.HttpMethod.PATCH, this.updateProfile, memberAuthorizer);
    this.route('PublishProfile', httpApi, '/profile/publish', apigw.HttpMethod.POST, this.publishProfile, memberAuthorizer);

    // Messaging
    this.route('SendMessage', httpApi, '/messages', apigw.HttpMethod.POST, this.sendMessage, memberAuthorizer);
    this.route('GetMessageHistory', httpApi, '/connections/{connectionId}/messages', apigw.HttpMethod.GET, this.getMessageHistory, memberAuthorizer);
    this.route('GetUnreadCount', httpApi, '/messages/unread', apigw.HttpMethod.GET, this.getUnreadCount, memberAuthorizer);
    this.route('MarkMessageRead', httpApi, '/messages/{messageId}/read', apigw.HttpMethod.POST, this.markMessageRead, memberAuthorizer);

    // Backup System Routes
    this.route('TriggerBackup', httpApi, '/vault/backup', apigw.HttpMethod.POST, this.triggerBackup, memberAuthorizer);
    this.route('ListBackups', httpApi, '/vault/backups', apigw.HttpMethod.GET, this.listBackups, memberAuthorizer);
    this.route('RestoreBackup', httpApi, '/vault/restore', apigw.HttpMethod.POST, this.restoreBackup, memberAuthorizer);
    this.route('DeleteBackup', httpApi, '/vault/backups/{backupId}', apigw.HttpMethod.DELETE, this.deleteBackup, memberAuthorizer);

    // Credential backup
    this.route('CreateCredentialBackup', httpApi, '/vault/credentials/backup', apigw.HttpMethod.POST, this.createCredentialBackup, memberAuthorizer);
    this.route('GetCredentialBackupStatus', httpApi, '/vault/credentials/backup', apigw.HttpMethod.GET, this.getCredentialBackupStatus, memberAuthorizer);
    this.route('DownloadCredentialBackup', httpApi, '/vault/credentials/recover', apigw.HttpMethod.POST, this.downloadCredentialBackup, memberAuthorizer);

    // Backup settings
    this.route('GetBackupSettings', httpApi, '/vault/backup/settings', apigw.HttpMethod.GET, this.getBackupSettings, memberAuthorizer);
    this.route('UpdateBackupSettings', httpApi, '/vault/backup/settings', apigw.HttpMethod.PUT, this.updateBackupSettings, memberAuthorizer);

    // BYOV (Bring Your Own Vault) Routes
    this.route('RegisterByovVault', httpApi, '/vault/byov/register', apigw.HttpMethod.POST, this.registerByovVault, memberAuthorizer);
    this.route('GetByovStatus', httpApi, '/vault/byov/status', apigw.HttpMethod.GET, this.getByovStatus, memberAuthorizer);
    this.route('VerifyByovVault', httpApi, '/vault/byov/verify', apigw.HttpMethod.POST, this.verifyByovVault, memberAuthorizer);
    this.route('UpdateByovVault', httpApi, '/vault/byov', apigw.HttpMethod.PATCH, this.updateByovVault, memberAuthorizer);
    this.route('DeleteByovVault', httpApi, '/vault/byov', apigw.HttpMethod.DELETE, this.deleteByovVault, memberAuthorizer);

    // Ledger (Protean Credential System) Routes - Phase 1
    // Only added if Ledger Lambda functions are created
    if (this.ledgerVerifyPassword) {
      this.route('LedgerVerifyPassword', httpApi, '/vault/auth/verify-password', apigw.HttpMethod.POST, this.ledgerVerifyPassword, memberAuthorizer);
    }
    if (this.ledgerValidateLAT) {
      this.route('LedgerValidateLAT', httpApi, '/vault/auth/validate-lat', apigw.HttpMethod.POST, this.ledgerValidateLAT, memberAuthorizer);
    }
    if (this.ledgerGetTransactionKeys) {
      this.route('LedgerGetTransactionKeys', httpApi, '/vault/transaction-keys', apigw.HttpMethod.GET, this.ledgerGetTransactionKeys, memberAuthorizer);
    }
    if (this.ledgerReplenishTransactionKeys) {
      this.route('LedgerReplenishTransactionKeys', httpApi, '/vault/transaction-keys/replenish', apigw.HttpMethod.POST, this.ledgerReplenishTransactionKeys, memberAuthorizer);
    }
    if (this.ledgerCreateCredential) {
      this.route('LedgerCreateCredential', httpApi, '/vault/credentials/create', apigw.HttpMethod.POST, this.ledgerCreateCredential, memberAuthorizer);
    }
    if (this.ledgerRotateKeys) {
      this.route('LedgerRotateKeys', httpApi, '/vault/credentials/rotate', apigw.HttpMethod.POST, this.ledgerRotateKeys, memberAuthorizer);
    }
  }
}
