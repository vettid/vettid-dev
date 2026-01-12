import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_authorizers as authorizers,
  aws_apigatewayv2_integrations as integrations,
  aws_ssm as ssm,
  aws_ec2 as ec2,
  custom_resources as cr,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';
// LedgerStack removed - legacy Protean Credential System replaced by vault-manager JetStream
import { NitroStack } from './nitro-stack';

export interface VaultStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  memberAuthorizer: apigw.IHttpRouteAuthorizer;
  nitro?: NitroStack;    // For enclave communication
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
 *
 * Note: Legacy credential tables (Credentials, CredentialKeys, TransactionKeys, LedgerAuthTokens)
 * have been removed - vault-manager uses JetStream storage in Nitro enclave.
 */
export class VaultStack extends cdk.Stack {
  private readonly props: VaultStackProps;

  // Public Lambda functions to be used by VettIDStack for route creation
  // Legacy enrollStart and enrollSetPassword removed - enrollment now via vault-manager
  public readonly enrollFinalize!: lambdaNode.NodejsFunction;
  public readonly createEnrollmentSession!: lambdaNode.NodejsFunction;
  public readonly cancelEnrollmentSession!: lambdaNode.NodejsFunction;
  public readonly authenticateEnrollment!: lambdaNode.NodejsFunction;
  public readonly enrollUpdateStatus!: lambdaNode.NodejsFunction;
  public readonly getEnrollmentStatus!: lambdaNode.NodejsFunction;
  // Legacy auth handlers removed - vault-manager handles auth via NATS

  // Device attestation handlers (Phase 2)
  public readonly verifyAndroidAttestation!: lambdaNode.NodejsFunction;
  public readonly verifyIosAttestation!: lambdaNode.NodejsFunction;

  // NATS account management functions
  public readonly natsCreateAccount!: lambdaNode.NodejsFunction;
  public readonly natsGenerateToken!: lambdaNode.NodejsFunction;
  public readonly natsRevokeToken!: lambdaNode.NodejsFunction;
  public readonly natsGetStatus!: lambdaNode.NodejsFunction;
  public readonly natsLookupAccountJwt!: lambdaNode.NodejsFunction;

  // Vault status functions (enclave-based)
  public readonly initializeVault!: lambdaNode.NodejsFunction;
  public readonly getVaultStatus!: lambdaNode.NodejsFunction;  // Member-facing vault status
  public readonly getVaultHealth!: lambdaNode.NodejsFunction;
  public readonly vaultReady!: lambdaNode.NodejsFunction;  // Internal endpoint for vault-manager ready signal
  public readonly updateVaultHealth!: lambdaNode.NodejsFunction;  // Internal endpoint for vault-manager health updates

  // Legacy vaultStatusAction removed - use Cognito-authenticated getVaultStatus instead

  // Handler registry functions (public endpoints)
  public readonly listHandlers!: lambdaNode.NodejsFunction;
  public readonly getHandler!: lambdaNode.NodejsFunction;
  public readonly installHandler!: lambdaNode.NodejsFunction;
  public readonly uninstallHandler!: lambdaNode.NodejsFunction;
  public readonly listInstalledHandlers!: lambdaNode.NodejsFunction;
  public readonly executeHandler!: lambdaNode.NodejsFunction;

  // Phase 7: Profile management (connections and messaging are vault-to-vault via NATS)
  public readonly getProfile!: lambdaNode.NodejsFunction;
  public readonly updateProfile!: lambdaNode.NodejsFunction;

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

  // Nitro Attestation
  public readonly verifyNitroAttestation!: lambdaNode.NodejsFunction;
  public readonly getPcrConfig!: lambdaNode.NodejsFunction;

  // Credential Recovery (24-hour delay) - Legacy
  public readonly requestCredentialRecovery!: lambdaNode.NodejsFunction;
  public readonly getRecoveryStatus!: lambdaNode.NodejsFunction;
  public readonly cancelCredentialRecovery!: lambdaNode.NodejsFunction;
  public readonly downloadRecoveredCredential!: lambdaNode.NodejsFunction;
  public readonly getRecoveryQR!: lambdaNode.NodejsFunction;  // QR code for recovery (Architecture v2.0)

  // Vault Deletion (24-hour delay)
  public readonly deleteVaultRequest!: lambdaNode.NodejsFunction;
  public readonly deleteVaultCancel!: lambdaNode.NodejsFunction;
  public readonly deleteVaultConfirm!: lambdaNode.NodejsFunction;
  public readonly deleteVaultStatus!: lambdaNode.NodejsFunction;

  // Credential Restore (transfer and recovery flows)
  public readonly restoreRequest!: lambdaNode.NodejsFunction;
  public readonly restoreApprove!: lambdaNode.NodejsFunction;
  public readonly restoreDeny!: lambdaNode.NodejsFunction;
  public readonly restoreCancel!: lambdaNode.NodejsFunction;
  public readonly restoreConfirm!: lambdaNode.NodejsFunction;
  public readonly restoreStatus!: lambdaNode.NodejsFunction;

  // Backup Settings
  public readonly backupSettingsHandler!: lambdaNode.NodejsFunction;

  // BYOV (Bring Your Own Vault)
  public readonly registerByovVault!: lambdaNode.NodejsFunction;
  public readonly getByovStatus!: lambdaNode.NodejsFunction;
  public readonly verifyByovVault!: lambdaNode.NodejsFunction;
  public readonly updateByovVault!: lambdaNode.NodejsFunction;
  public readonly deleteByovVault!: lambdaNode.NodejsFunction;

  // Note: Ledger handlers removed - vault-manager uses JetStream storage

  // Test Automation Endpoints (for Android E2E testing)
  public readonly testHealth!: lambdaNode.NodejsFunction;
  public readonly testCreateInvitation!: lambdaNode.NodejsFunction;
  public readonly testCleanup!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: VaultStackProps) {
    super(scope, id, {
      ...props,
      description: 'VettID Vault - enrollment and authentication services (v2: JetStream storage)',
    });

    this.props = props;
    const tables = props.infrastructure.tables;
    const memberUserPool = props.infrastructure.memberUserPool;

    // Default environment variables for vault functions
    // Note: Legacy tables (Credentials, CredentialKeys, TransactionKeys, LedgerAuthTokens)
    // removed - vault-manager uses JetStream storage. Handlers referencing these will fail.
    // SECURITY: STAGE=prod ensures localhost origins are not allowed in CORS
    const defaultEnv = {
      TABLE_ACTION_TOKENS: tables.actionTokens.tableName,
      TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
      TABLE_INVITES: tables.invites.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      STAGE: 'prod',  // SECURITY: Ensures CORS excludes localhost origins
    };

    // ===== VAULT ENROLLMENT =====

    // Environment variables for Nitro Enclave integration
    const enclaveEnv = {
      NATS_URL: 'nats://nats.internal.vettid.dev:4222',
      BACKEND_CREDS_PARAM: '/vettid/nitro/parent-nats-creds',
    };

    // VPC configuration for Lambdas that need access to NATS internal DNS
    const vpcConfig = props.nitro ? {
      vpc: props.nitro.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [props.nitro.lambdaSecurityGroup],
    } : {};

    // Legacy enrollStart and enrollSetPassword removed - enrollment via vault-manager

    // SSM Parameter for vault AMI ID
    // Update this parameter to change the AMI without redeploying Lambda:
    //   aws ssm put-parameter --name "/vettid/vault/ami-id" --value "ami-NEW" --overwrite
    const vaultAmiParameter = new ssm.StringParameter(this, 'VaultAmiParameter', {
      parameterName: '/vettid/vault/ami-id',
      stringValue: process.env.VAULT_AMI_ID || 'ami-0a6800ad4abd288a5',
      description: 'AMI ID for vault EC2 instances. Update via SSM to change without redeploying.',
    });

    // Enclave configuration (Nitro-based architecture)
    const enclaveConfigEnv = {
      // Internal NATS endpoint for vault-to-NATS communication via VPC peering (plain TCP)
      NATS_INTERNAL_ENDPOINT: 'nats.internal.vettid.dev:4222',
      BACKEND_API_URL: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com',
    };

    // NATS operator secret for signing JWTs (used by enrollFinalize and NATS functions)
    const natsOperatorSecretRef = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'NatsOperatorSecretForEnroll', 'vettid/nats/operator-key'
    );

    // Note: NATS internal CA secret no longer needed - NLB terminates TLS with ACM (publicly trusted)

    this.enrollFinalize = new lambdaNode.NodejsFunction(this, 'EnrollFinalizeFn', {
      entry: 'lambda/handlers/vault/enrollFinalize.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
        // Auto-provisioning environment variables
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
        NATS_OPERATOR_SECRET_ARN: natsOperatorSecretRef.secretArn,
        // Note: NATS_CA_SECRET_ARN no longer needed - NLB terminates TLS with ACM (publicly trusted)
        ...enclaveConfigEnv,
        // Enclave integration
        ...enclaveEnv,
      },
      timeout: cdk.Duration.seconds(60), // Increased for auto-provisioning
      ...vpcConfig, // Required for NATS internal DNS resolution
    });
    // Grant SSM read permission for vault AMI parameter
    vaultAmiParameter.grantRead(this.enrollFinalize);

    // Grant SSM read permission for NATS credentials (for enclave communication)
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:GetParameter'],
      resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter/vettid/nitro/parent-nats-creds`],
    }));

    // Web-initiated enrollment session (for QR code flow)
    this.createEnrollmentSession = new lambdaNode.NodejsFunction(this, 'CreateEnrollmentSessionFn', {
      entry: 'lambda/handlers/vault/createEnrollmentSession.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        API_URL: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com',
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Cancel enrollment session
    this.cancelEnrollmentSession = new lambdaNode.NodejsFunction(this, 'CancelEnrollmentSessionFn', {
      entry: 'lambda/handlers/vault/cancelEnrollmentSession.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Authenticate enrollment (public endpoint for mobile to exchange session_token for JWT)
    this.authenticateEnrollment = new lambdaNode.NodejsFunction(this, 'AuthenticateEnrollmentFn', {
      entry: 'lambda/handlers/vault/authenticateEnrollment.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_AUDIT: tables.audit.tableName,
        ENROLLMENT_JWT_SECRET_ARN: props.infrastructure.enrollmentJwtSecretArn,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant read access to the enrollment JWT secret
    this.authenticateEnrollment.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [props.infrastructure.enrollmentJwtSecretArn],
    }));

    // Update enrollment status (app reports progress through NATS-based phases)
    this.enrollUpdateStatus = new lambdaNode.NodejsFunction(this, 'EnrollUpdateStatusFn', {
      entry: 'lambda/handlers/vault/enrollUpdateStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_AUDIT: tables.audit.tableName,
        ENROLLMENT_JWT_SECRET_ARN: props.infrastructure.enrollmentJwtSecretArn,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant read access to the enrollment JWT secret for status updates
    this.enrollUpdateStatus.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [props.infrastructure.enrollmentJwtSecretArn],
    }));

    // Get enrollment status (Account Portal polls for progress)
    this.getEnrollmentStatus = new lambdaNode.NodejsFunction(this, 'GetEnrollmentStatusFn', {
      entry: 'lambda/handlers/vault/getEnrollmentStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Note: Enrollment authorizer Lambda is defined in InfrastructureStack
    // to avoid cyclic dependencies between VettIDStack and VaultStack

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
    // Legacy actionRequest and authExecute removed - vault-manager handles auth via NATS

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
      // SECURITY: KMS key for envelope encryption of account seeds (Ed25519 private keys)
      NATS_SEED_KMS_KEY_ARN: props.infrastructure.natsSeedEncryptionKey.keyArn,
      // Note: NATS_CA_SECRET_ARN no longer needed - NLB terminates TLS with ACM (publicly trusted)
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

    // NATS Account JWT lookup for URL resolver (called by NATS servers, no auth required)
    // Also returns system account JWT from Secrets Manager for NATS cluster startup
    this.natsLookupAccountJwt = new lambdaNode.NodejsFunction(this, 'NatsLookupAccountJwtFn', {
      entry: 'lambda/handlers/nats/lookupAccountJwt.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        NATS_OPERATOR_SECRET_ARN: natsOperatorSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(10),
    });
    // Grant permission to read system account JWT from Secrets Manager
    natsOperatorSecret.grantRead(this.natsLookupAccountJwt);

    // ===== VAULT STATUS (ENCLAVE-BASED) =====

    this.initializeVault = new lambdaNode.NodejsFunction(this, 'InitializeVaultFn', {
      entry: 'lambda/handlers/vault/initializeVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Member-facing vault status endpoint
    this.getVaultStatus = new lambdaNode.NodejsFunction(this, 'GetVaultStatusFn', {
      entry: 'lambda/handlers/vault/getVaultStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
        TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      },
      timeout: cdk.Duration.seconds(10),
    });

    this.getVaultHealth = new lambdaNode.NodejsFunction(this, 'GetVaultHealthFn', {
      entry: 'lambda/handlers/vault/getVaultHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Legacy getVaultStatus removed - status via vault-manager

    // Internal endpoint called by vault-manager when it's ready
    this.vaultReady = new lambdaNode.NodejsFunction(this, 'VaultReadyFn', {
      entry: 'lambda/handlers/vault/vaultReady.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Internal endpoint called by vault-manager every 30s with health updates
    this.updateVaultHealth = new lambdaNode.NodejsFunction(this, 'UpdateVaultHealthFn', {
      entry: 'lambda/handlers/vault/updateVaultHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      },
      timeout: cdk.Duration.seconds(10),
    });

    // ===== ACTION-TOKEN AUTHENTICATED VAULT STATUS =====
    // Legacy vaultActionEnv and vaultStatusAction removed - status via vault-manager

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
    // Legacy enrollStart/enrollSetPassword grants removed
    tables.enrollmentSessions.grantReadWriteData(this.enrollFinalize);
    tables.enrollmentSessions.grantReadWriteData(this.createEnrollmentSession);
    tables.natsAccounts.grantReadData(this.createEnrollmentSession);
    tables.audit.grantReadWriteData(this.createEnrollmentSession);
    tables.enrollmentSessions.grantReadWriteData(this.cancelEnrollmentSession);
    tables.audit.grantReadWriteData(this.cancelEnrollmentSession);

    // Authenticate enrollment permissions
    tables.enrollmentSessions.grantReadWriteData(this.authenticateEnrollment);
    tables.audit.grantReadWriteData(this.authenticateEnrollment);

    // Enrollment status update permissions (app reports progress)
    tables.enrollmentSessions.grantReadWriteData(this.enrollUpdateStatus);
    tables.audit.grantWriteData(this.enrollUpdateStatus);

    // Get enrollment status permissions (Account Portal polling)
    tables.enrollmentSessions.grantReadData(this.getEnrollmentStatus);

    // Legacy credential table grants removed - vault-manager uses JetStream storage

    // Invites table - enrollFinalize marks as used
    tables.invites.grantReadWriteData(this.enrollFinalize);

    // Legacy actionRequest/authExecute grants removed

    tables.registrations.grantReadData(this.enrollFinalize);

    // Grant audit table permissions for vault functions
    tables.audit.grantReadWriteData(this.enrollFinalize);

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

    // ===== AUTO-PROVISIONING PERMISSIONS FOR enrollFinalize =====
    // enrollFinalize now auto-provisions vault EC2 after enrollment completes

    // Grant NATS accounts table access for enrollFinalize
    tables.natsAccounts.grantReadWriteData(this.enrollFinalize);

    // Grant vault instances table access for enrollFinalize
    tables.vaultInstances.grantReadWriteData(this.enrollFinalize);

    // Grant NATS operator secret access for generating vault credentials
    natsOperatorSecretRef.grantRead(this.enrollFinalize);

    // Note: NATS internal CA secret grant no longer needed - NLB terminates TLS with ACM (publicly trusted)

    // EC2 permissions for auto-provisioning (same as provisionVault)
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DescribeSubnets'],
      resources: ['*'],
    }));

    // EC2 RunInstances - split into two statements:
    // 1. Resources being created (instance, volume) - require Application tag
    // SECURITY: Restrict to specific instance types and single instance per request
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:RunInstances'],
      resources: [
        `arn:aws:ec2:${this.region}:${this.account}:instance/*`,
        `arn:aws:ec2:${this.region}:${this.account}:volume/*`,
      ],
      conditions: {
        StringEquals: {
          'aws:RequestTag/Application': 'vettid-vault',
          // SECURITY: Only allow Nitro Enclave capable instance types
          'ec2:InstanceType': ['c5a.xlarge', 'c6a.xlarge', 'm5.xlarge', 'm6a.xlarge'],
        },
        NumericLessThanEquals: {
          // SECURITY: Limit to 1 instance per request to prevent runaway costs
          'ec2:InstanceCount': '1',
        },
      },
    }));

    // 2. Infrastructure references (ami, subnet, sg, network-interface) - no condition
    // These are pre-existing or auto-created resources that don't get tags
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:RunInstances'],
      resources: [
        `arn:aws:ec2:${this.region}:${this.account}:network-interface/*`,
        `arn:aws:ec2:${this.region}::image/*`,
        `arn:aws:ec2:${this.region}:${this.account}:subnet/*`,
        `arn:aws:ec2:${this.region}:${this.account}:security-group/*`,
      ],
    }));

    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:CreateTags'],
      resources: [`arn:aws:ec2:${this.region}:${this.account}:*/*`],
      conditions: {
        StringEquals: {
          'ec2:CreateAction': 'RunInstances',
          'aws:RequestTag/Application': 'vettid-vault',
        },
      },
    }));

    // Grant IAM pass role permission for instance profile
    this.enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: ['iam:PassRole'],
      resources: [`arn:aws:iam::${this.account}:role/vettid-vault-*`],
    }));

    // Legacy SES permissions for enrollStart/actionRequest removed

    // ===== NATS PERMISSIONS =====

    // Grant NATS accounts table access
    tables.natsAccounts.grantReadWriteData(this.natsCreateAccount);
    tables.natsAccounts.grantReadData(this.natsGenerateToken);
    tables.natsAccounts.grantReadData(this.natsGetStatus);
    tables.natsAccounts.grantReadData(this.natsLookupAccountJwt);

    // Grant NATS tokens table access
    tables.natsTokens.grantReadWriteData(this.natsGenerateToken);
    tables.natsTokens.grantReadWriteData(this.natsRevokeToken);
    tables.natsTokens.grantReadData(this.natsGetStatus);

    // SECURITY: Grant revokeToken access to accounts table for NATS-level revocation enforcement
    // When a token is revoked, we regenerate the account JWT with the user's public key in revocations
    tables.natsAccounts.grantReadWriteData(this.natsRevokeToken);

    // Grant audit table access for NATS functions
    tables.audit.grantReadWriteData(this.natsCreateAccount);
    tables.audit.grantReadWriteData(this.natsGenerateToken);
    tables.audit.grantReadWriteData(this.natsRevokeToken);

    // Grant NATS operator secret access for JWT signing
    natsOperatorSecret.grantRead(this.natsCreateAccount);
    natsOperatorSecret.grantRead(this.natsGenerateToken);
    // SECURITY: revokeToken needs operator secret to regenerate account JWT with revocations
    natsOperatorSecret.grantRead(this.natsRevokeToken);

    // SECURITY: Grant KMS access for NATS seed envelope encryption
    // - natsCreateAccount: encrypt seeds before storing in DynamoDB
    // - natsGenerateToken: decrypt seeds to sign user JWTs
    props.infrastructure.natsSeedEncryptionKey.grantEncrypt(this.natsCreateAccount);
    props.infrastructure.natsSeedEncryptionKey.grantDecrypt(this.natsGenerateToken);

    // Note: NATS internal CA secret grant no longer needed - NLB terminates TLS with ACM (publicly trusted)

    // ===== VAULT LIFECYCLE PERMISSIONS (Nitro Enclave Model) =====
    // Note: EC2-per-user provisioning removed - now using multi-tenant Nitro Enclave architecture

    // Grant vault instances table access for remaining handlers
    tables.vaultInstances.grantReadWriteData(this.initializeVault);
    tables.vaultInstances.grantReadWriteData(this.getVaultHealth);
    tables.vaultInstances.grantReadWriteData(this.vaultReady);
    tables.vaultInstances.grantReadWriteData(this.updateVaultHealth);

    // Member-facing vault status endpoint permissions
    tables.vaultInstances.grantReadData(this.getVaultStatus);
    tables.enrollmentSessions.grantReadData(this.getVaultStatus);
    tables.natsAccounts.grantReadData(this.getVaultStatus);

    // Legacy getVaultStatus and vaultStatusAction grants removed - status via vault-manager

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

    // ===== PHASE 7: PROFILE MANAGEMENT =====
    // NOTE: Connections and messaging are handled vault-to-vault via NATS, not Lambda.
    // See vault-manager handlers: connection.*, message.*

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

    // Profiles table permissions
    tables.profiles.grantReadWriteData(this.getProfile); // Creates default if missing
    tables.profiles.grantReadWriteData(this.updateProfile);

    // ===== PHASE 8: BACKUP SYSTEM =====

    const backupEnv = {
      TABLE_BACKUPS: tables.backups.tableName,
      TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
      TABLE_PROFILES: tables.profiles.tableName,
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

    // ===== NITRO ATTESTATION =====

    this.verifyNitroAttestation = new lambdaNode.NodejsFunction(this, 'VerifyNitroAttestationFn', {
      entry: 'lambda/handlers/vault/verifyNitroAttestation.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_AUDIT: tables.audit.tableName,
        TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
        // Legacy TABLE_CREDENTIALS removed - vault-manager uses JetStream storage
        // PCR values will be fetched from SSM Parameter Store in production
        // NITRO_EXPECTED_PCRS: JSON.stringify([...])
      },
      timeout: cdk.Duration.seconds(30),
    });

    // PCR configuration endpoint - returns signed PCR values for mobile app verification
    const pcrSigningKeySecret = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'PcrSigningKeySecret', 'vettid/pcr-signing-key'
    );

    this.getPcrConfig = new lambdaNode.NodejsFunction(this, 'GetPcrConfigFn', {
      entry: 'lambda/handlers/vault/getPcrConfig.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        PCR_SIGNING_KEY_SECRET: pcrSigningKeySecret.secretName,
      },
      timeout: cdk.Duration.seconds(10),
    });

    // Grant read access to the PCR signing key secret
    pcrSigningKeySecret.grantRead(this.getPcrConfig);

    // Grant read access to PCR values in SSM Parameter Store
    this.getPcrConfig.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ssm:GetParameter'],
      resources: [
        `arn:aws:ssm:${this.region}:${this.account}:parameter/vettid/enclave/pcr/*`,
      ],
    }));

    // ===== CREDENTIAL RECOVERY (24-HOUR DELAY) =====

    const recoveryEnv = {
      TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      TABLE_RECOVERY_REQUESTS: tables.credentialRecoveryRequests.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
      FROM_EMAIL: 'noreply@vettid.dev',
    };

    this.requestCredentialRecovery = new lambdaNode.NodejsFunction(this, 'RequestCredentialRecoveryFn', {
      entry: 'lambda/handlers/backup/requestCredentialRecovery.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: recoveryEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.getRecoveryStatus = new lambdaNode.NodejsFunction(this, 'GetRecoveryStatusFn', {
      entry: 'lambda/handlers/backup/getRecoveryStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_RECOVERY_REQUESTS: tables.credentialRecoveryRequests.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    this.cancelCredentialRecovery = new lambdaNode.NodejsFunction(this, 'CancelCredentialRecoveryFn', {
      entry: 'lambda/handlers/backup/cancelCredentialRecovery.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: recoveryEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.downloadRecoveredCredential = new lambdaNode.NodejsFunction(this, 'DownloadRecoveredCredentialFn', {
      entry: 'lambda/handlers/backup/downloadRecoveredCredential.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: recoveryEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // QR code recovery endpoint (Architecture v2.0 Section 5.18)
    this.getRecoveryQR = new lambdaNode.NodejsFunction(this, 'GetRecoveryQRFn', {
      entry: 'lambda/handlers/backup/getRecoveryQR.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_RECOVERY_REQUESTS: tables.credentialRecoveryRequests.tableName,
        TABLE_AUDIT: tables.audit.tableName,
        NATS_ENDPOINT: 'nats.vettid.dev:443',
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions for recovery functions
    tables.credentialRecoveryRequests.grantReadWriteData(this.requestCredentialRecovery);
    tables.credentialRecoveryRequests.grantReadWriteData(this.getRecoveryStatus);
    tables.credentialRecoveryRequests.grantReadWriteData(this.cancelCredentialRecovery);
    tables.credentialRecoveryRequests.grantReadWriteData(this.downloadRecoveredCredential);
    tables.credentialRecoveryRequests.grantReadWriteData(this.getRecoveryQR);
    tables.credentialBackups.grantReadData(this.requestCredentialRecovery);
    tables.credentialBackups.grantReadData(this.downloadRecoveredCredential);
    tables.audit.grantWriteData(this.getRecoveryQR);
    props.infrastructure.backupBucket.grantRead(this.downloadRecoveredCredential);
    tables.audit.grantWriteData(this.verifyNitroAttestation);
    tables.enrollmentSessions.grantReadData(this.verifyNitroAttestation);
    // Legacy credentials grant removed
    tables.audit.grantWriteData(this.requestCredentialRecovery);
    tables.audit.grantWriteData(this.cancelCredentialRecovery);
    tables.audit.grantWriteData(this.downloadRecoveredCredential);

    // ===== VAULT DELETION (24-hour delay) =====

    const vaultDeletionEnv = {
      TABLE_VAULT_DELETION_REQUESTS: tables.vaultDeletionRequests.tableName,
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      // Legacy credential tables removed - vault-manager uses JetStream storage
    };

    this.deleteVaultRequest = new lambdaNode.NodejsFunction(this, 'DeleteVaultRequestFn', {
      entry: 'lambda/handlers/vault/deleteVaultRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultDeletionEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.deleteVaultCancel = new lambdaNode.NodejsFunction(this, 'DeleteVaultCancelFn', {
      entry: 'lambda/handlers/vault/deleteVaultCancel.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultDeletionEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.deleteVaultConfirm = new lambdaNode.NodejsFunction(this, 'DeleteVaultConfirmFn', {
      entry: 'lambda/handlers/vault/deleteVaultConfirm.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultDeletionEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.deleteVaultStatus = new lambdaNode.NodejsFunction(this, 'DeleteVaultStatusFn', {
      entry: 'lambda/handlers/vault/deleteVaultStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultDeletionEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions for vault deletion functions
    tables.vaultDeletionRequests.grantReadWriteData(this.deleteVaultRequest);
    tables.vaultDeletionRequests.grantReadWriteData(this.deleteVaultCancel);
    tables.vaultDeletionRequests.grantReadWriteData(this.deleteVaultConfirm);
    tables.vaultDeletionRequests.grantReadData(this.deleteVaultStatus);
    tables.natsAccounts.grantReadData(this.deleteVaultRequest);
    tables.natsAccounts.grantReadWriteData(this.deleteVaultConfirm);
    tables.audit.grantWriteData(this.deleteVaultRequest);
    tables.audit.grantWriteData(this.deleteVaultCancel);
    tables.audit.grantWriteData(this.deleteVaultConfirm);

    // ===== CREDENTIAL RESTORE (transfer and recovery flows) =====

    const credentialRestoreEnv = {
      TABLE_CREDENTIAL_RECOVERY_REQUESTS: tables.credentialRecoveryRequests.tableName,
      TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      NATS_OPERATOR_SECRET_ARN: natsOperatorSecretRef.secretArn,
      NATS_ENDPOINT: 'nats.vettid.dev:443',
      CREDENTIAL_BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
      // Legacy credential tables removed - vault-manager uses JetStream storage
    };

    this.restoreRequest = new lambdaNode.NodejsFunction(this, 'RestoreRequestFn', {
      entry: 'lambda/handlers/vault/restoreRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreApprove = new lambdaNode.NodejsFunction(this, 'RestoreApproveFn', {
      entry: 'lambda/handlers/vault/restoreApprove.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreDeny = new lambdaNode.NodejsFunction(this, 'RestoreDenyFn', {
      entry: 'lambda/handlers/vault/restoreDeny.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreCancel = new lambdaNode.NodejsFunction(this, 'RestoreCancelFn', {
      entry: 'lambda/handlers/vault/restoreCancel.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreConfirm = new lambdaNode.NodejsFunction(this, 'RestoreConfirmFn', {
      entry: 'lambda/handlers/vault/restoreConfirm.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.restoreStatus = new lambdaNode.NodejsFunction(this, 'RestoreStatusFn', {
      entry: 'lambda/handlers/vault/restoreStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: credentialRestoreEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions for credential restore functions
    tables.credentialRecoveryRequests.grantReadWriteData(this.restoreRequest);
    tables.credentialRecoveryRequests.grantReadWriteData(this.restoreApprove);
    tables.credentialRecoveryRequests.grantReadWriteData(this.restoreDeny);
    tables.credentialRecoveryRequests.grantReadWriteData(this.restoreCancel);
    tables.credentialRecoveryRequests.grantReadWriteData(this.restoreConfirm);
    tables.credentialRecoveryRequests.grantReadData(this.restoreStatus);
    tables.credentialBackups.grantReadData(this.restoreConfirm);
    tables.audit.grantWriteData(this.restoreRequest);
    tables.audit.grantWriteData(this.restoreApprove);
    tables.audit.grantWriteData(this.restoreDeny);
    tables.audit.grantWriteData(this.restoreCancel);
    tables.audit.grantWriteData(this.restoreConfirm);

    // NATS accounts table access for restore handlers
    tables.natsAccounts.grantReadData(this.restoreRequest);
    tables.natsAccounts.grantReadWriteData(this.restoreApprove);
    tables.natsAccounts.grantReadWriteData(this.restoreConfirm);

    // NATS operator secret for restoreConfirm to generate bootstrap credentials
    natsOperatorSecretRef.grantRead(this.restoreConfirm);

    // S3 bucket read access for restoreConfirm to fetch credential backups
    props.infrastructure.backupBucket.grantRead(this.restoreConfirm);

    // ===== BACKUP SETTINGS =====

    this.backupSettingsHandler = new lambdaNode.NodejsFunction(this, 'BackupSettingsHandlerFn', {
      entry: 'lambda/handlers/vault/backupSettings.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_BACKUP_SETTINGS: tables.backupSettings.tableName,
        TABLE_AUDIT: tables.audit.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    tables.backupSettings.grantReadWriteData(this.backupSettingsHandler);
    tables.audit.grantWriteData(this.backupSettingsHandler);

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

    // triggerBackup needs read access to profiles (connections/messages are vault-managed)
    tables.profiles.grantReadData(this.triggerBackup);

    // restoreBackup needs write access to profiles (connections/messages are vault-managed)
    tables.profiles.grantReadWriteData(this.restoreBackup);

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

    // ===== TEST AUTOMATION ENDPOINTS =====
    // These endpoints enable automated E2E testing for Android app
    // SECURITY: Protected by TEST_API_KEY - endpoints disabled if key not configured
    // SECURITY: Test endpoints should not be deployed in production

    // SECURITY: Require explicit configuration - no fallback to prevent accidental exposure
    const testApiKey = process.env.VETTID_TEST_API_KEY;
    if (!testApiKey) {
      console.warn('VETTID_TEST_API_KEY not set - test endpoints will be disabled');
    }

    const testEnv = {
      ...defaultEnv,
      TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
      // SECURITY: Empty string disables validation in handler (endpoints return 403)
      TEST_API_KEY: testApiKey || '',
      API_URL: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com',
    };

    this.testHealth = new lambdaNode.NodejsFunction(this, 'TestHealthFn', {
      entry: 'lambda/handlers/test/testHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: testEnv,
      timeout: cdk.Duration.seconds(10),
    });

    this.testCreateInvitation = new lambdaNode.NodejsFunction(this, 'TestCreateInvitationFn', {
      entry: 'lambda/handlers/test/testCreateInvitation.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: testEnv,
      timeout: cdk.Duration.seconds(30),
    });

    this.testCleanup = new lambdaNode.NodejsFunction(this, 'TestCleanupFn', {
      entry: 'lambda/handlers/test/testCleanup.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...testEnv,
        TABLE_ACTION_TOKENS: tables.actionTokens.tableName,
        // Legacy credential tables removed - vault-manager uses JetStream storage
      },
      timeout: cdk.Duration.seconds(60), // Cleanup may take longer
    });

    // Grant table access for test endpoints
    tables.invites.grantReadWriteData(this.testHealth);
    tables.enrollmentSessions.grantReadData(this.testHealth);
    tables.natsAccounts.grantReadData(this.testHealth);

    tables.invites.grantReadWriteData(this.testCreateInvitation);
    tables.enrollmentSessions.grantReadWriteData(this.testCreateInvitation);
    tables.audit.grantReadWriteData(this.testCreateInvitation);

    tables.invites.grantReadWriteData(this.testCleanup);
    tables.enrollmentSessions.grantReadWriteData(this.testCleanup);
    tables.natsAccounts.grantReadWriteData(this.testCleanup);
    tables.actionTokens.grantReadWriteData(this.testCleanup);
    tables.audit.grantReadWriteData(this.testCleanup);

    // Note: Ledger (Protean Credential System) section removed
    // Legacy PostgreSQL ledger replaced by vault-manager JetStream storage

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
    // Get enrollment authorizer Lambda from infrastructure stack (avoids cyclic dependency)
    const enrollmentAuthorizerFn = this.props.infrastructure.enrollmentAuthorizerFn;

    // Create custom Lambda authorizer for mobile enrollment endpoints
    const enrollmentLambdaAuthorizer = new authorizers.HttpLambdaAuthorizer(
      'EnrollmentAuthorizer',
      enrollmentAuthorizerFn,
      {
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE],
        resultsCacheTtl: cdk.Duration.seconds(0), // Don't cache - tokens are short-lived
      }
    );

    // Web-initiated enrollment session management (requires member JWT from web)
    this.route('CreateEnrollmentSession', httpApi, '/vault/enroll/session', apigw.HttpMethod.POST, this.createEnrollmentSession, memberAuthorizer);
    this.route('CancelEnrollmentSession', httpApi, '/vault/enroll/cancel', apigw.HttpMethod.POST, this.cancelEnrollmentSession, memberAuthorizer);

    // Public endpoint: Mobile exchanges session_token for enrollment JWT (no auth required)
    new apigw.HttpRoute(this, 'AuthenticateEnrollment', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/enroll/authenticate', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('AuthenticateEnrollmentInt', this.authenticateEnrollment),
      // No authorizer - this is a public endpoint
    });

    // Mobile enrollment - enrollFinalize now handles complete enrollment via vault-manager
    // Legacy enrollStart/enrollSetPassword removed - vault-manager handles key generation
    this.route('EnrollFinalize', httpApi, '/vault/enroll/finalize', apigw.HttpMethod.POST, this.enrollFinalize, enrollmentLambdaAuthorizer);

    // Enrollment status update - mobile app reports phase completion (uses enrollment JWT)
    new apigw.HttpRoute(this, 'EnrollUpdateStatus', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/enroll/status', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('EnrollUpdateStatusInt', this.enrollUpdateStatus),
      // Uses enrollment JWT - validated in handler
    });

    // Get enrollment status - Account Portal polls for progress (uses member JWT)
    this.route('GetEnrollmentStatus', httpApi, '/vault/enroll/status', apigw.HttpMethod.GET, this.getEnrollmentStatus, memberAuthorizer);

    // Device Attestation (Phase 2) - also uses enrollment JWT
    this.route('VerifyAndroidAttestation', httpApi, '/vault/enroll/attestation/android', apigw.HttpMethod.POST, this.verifyAndroidAttestation, enrollmentLambdaAuthorizer);
    this.route('VerifyIosAttestation', httpApi, '/vault/enroll/attestation/ios', apigw.HttpMethod.POST, this.verifyIosAttestation, enrollmentLambdaAuthorizer);

    // Legacy vault auth endpoints removed - auth now via NATS to vault-manager

    // NATS Account Management
    this.route('NatsCreateAccount', httpApi, '/vault/nats/account', apigw.HttpMethod.POST, this.natsCreateAccount, memberAuthorizer);
    this.route('NatsGenerateToken', httpApi, '/vault/nats/token', apigw.HttpMethod.POST, this.natsGenerateToken, memberAuthorizer);
    this.route('NatsRevokeToken', httpApi, '/vault/nats/token/revoke', apigw.HttpMethod.POST, this.natsRevokeToken, memberAuthorizer);
    this.route('NatsGetStatus', httpApi, '/vault/nats/status', apigw.HttpMethod.GET, this.natsGetStatus, memberAuthorizer);

    // NATS URL Resolver endpoint (public - called by NATS servers for account JWT lookup)
    new apigw.HttpRoute(this, 'NatsLookupAccountJwt', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/nats/jwt/v1/accounts/{account_public_key}', apigw.HttpMethod.GET),
      integration: new integrations.HttpLambdaIntegration('NatsLookupAccountJwtIntegration', this.natsLookupAccountJwt),
    });

    // Vault Lifecycle Management (Nitro enclave model - no EC2-per-user provisioning)
    this.route('InitializeVault', httpApi, '/vault/initialize', apigw.HttpMethod.POST, this.initializeVault, memberAuthorizer);
    this.route('GetVaultHealth', httpApi, '/vault/health', apigw.HttpMethod.GET, this.getVaultHealth, memberAuthorizer);
    this.route('GetVaultStatus', httpApi, '/vault/status', apigw.HttpMethod.GET, this.getVaultStatus, memberAuthorizer);

    // Internal endpoint called by vault-manager when it's ready (no auth - validated by instance ID and EC2 tags)
    new apigw.HttpRoute(this, 'VaultReady', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/internal/ready', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('VaultReadyIntegration', this.vaultReady),
    });

    // Internal endpoint called by vault-manager every 30s for health updates (no auth - validated by instance ID)
    new apigw.HttpRoute(this, 'UpdateVaultHealth', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/internal/health', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('UpdateVaultHealthIntegration', this.updateVaultHealth),
    });

    // Legacy ACTION-TOKEN endpoints removed - mobile auth now via NATS to vault-manager

    // Handler Registry Routes
    this.route('ListHandlers', httpApi, '/registry/handlers', apigw.HttpMethod.GET, this.listHandlers, memberAuthorizer);
    this.route('GetHandler', httpApi, '/registry/handlers/{id}', apigw.HttpMethod.GET, this.getHandler, memberAuthorizer);
    this.route('InstallHandler', httpApi, '/vault/handlers/install', apigw.HttpMethod.POST, this.installHandler, memberAuthorizer);
    this.route('UninstallHandler', httpApi, '/vault/handlers/uninstall', apigw.HttpMethod.POST, this.uninstallHandler, memberAuthorizer);
    this.route('ListInstalledHandlers', httpApi, '/vault/handlers', apigw.HttpMethod.GET, this.listInstalledHandlers, memberAuthorizer);
    this.route('ExecuteHandler', httpApi, '/vault/handlers/{id}/execute', apigw.HttpMethod.POST, this.executeHandler, memberAuthorizer);

    // Profile management (connections/messaging are vault-to-vault via NATS)
    this.route('GetProfile', httpApi, '/profile', apigw.HttpMethod.GET, this.getProfile, memberAuthorizer);
    this.route('UpdateProfile', httpApi, '/profile', apigw.HttpMethod.PATCH, this.updateProfile, memberAuthorizer);

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

    // Nitro Enclave Attestation (public - apps verify enclave identity before enrollment)
    new apigw.HttpRoute(this, 'VerifyNitroAttestation', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/attestation/nitro', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('VerifyNitroAttestationInt', this.verifyNitroAttestation),
      // No authorizer - public endpoint for apps to verify enclave before enrollment
    });

    // PCR Configuration (public - apps fetch signed PCR values for attestation verification)
    new apigw.HttpRoute(this, 'GetPcrConfig', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/pcrs/current', apigw.HttpMethod.GET),
      integration: new integrations.HttpLambdaIntegration('GetPcrConfigInt', this.getPcrConfig),
      // No authorizer - public endpoint for apps to get expected PCR values
    });

    // Credential Recovery (24-hour delay for security)
    this.route('RequestCredentialRecovery', httpApi, '/vault/recovery/request', apigw.HttpMethod.POST, this.requestCredentialRecovery, memberAuthorizer);
    this.route('GetRecoveryStatus', httpApi, '/vault/recovery/status', apigw.HttpMethod.GET, this.getRecoveryStatus, memberAuthorizer);
    this.route('CancelCredentialRecovery', httpApi, '/vault/recovery/cancel', apigw.HttpMethod.POST, this.cancelCredentialRecovery, memberAuthorizer);
    this.route('DownloadRecoveredCredential', httpApi, '/vault/recovery/download', apigw.HttpMethod.GET, this.downloadRecoveredCredential, memberAuthorizer);
    this.route('GetRecoveryQR', httpApi, '/vault/recovery/qr', apigw.HttpMethod.GET, this.getRecoveryQR, memberAuthorizer);

    // Vault Deletion Routes (24-hour delay)
    this.route('DeleteVaultRequest', httpApi, '/vault/delete/request', apigw.HttpMethod.POST, this.deleteVaultRequest, memberAuthorizer);
    this.route('DeleteVaultCancel', httpApi, '/vault/delete/cancel', apigw.HttpMethod.POST, this.deleteVaultCancel, memberAuthorizer);
    this.route('DeleteVaultConfirm', httpApi, '/vault/delete/confirm', apigw.HttpMethod.POST, this.deleteVaultConfirm, memberAuthorizer);
    this.route('DeleteVaultStatus', httpApi, '/vault/delete/status', apigw.HttpMethod.GET, this.deleteVaultStatus, memberAuthorizer);

    // Credential Restore Routes (transfer and recovery flows)
    this.route('RestoreRequest', httpApi, '/vault/credentials/restore/request', apigw.HttpMethod.POST, this.restoreRequest, memberAuthorizer);
    this.route('RestoreCancel', httpApi, '/vault/credentials/restore/cancel', apigw.HttpMethod.POST, this.restoreCancel, memberAuthorizer);
    this.route('RestoreConfirm', httpApi, '/vault/credentials/restore/confirm', apigw.HttpMethod.POST, this.restoreConfirm, memberAuthorizer);
    this.route('RestoreStatus', httpApi, '/vault/credentials/restore/status', apigw.HttpMethod.GET, this.restoreStatus, memberAuthorizer);

    // Credential Restore from Mobile Device (uses enrollment JWT authorizer)
    // These are called by the mobile app when approving/denying transfer requests
    new apigw.HttpRoute(this, 'RestoreApprove', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/credentials/restore/approve', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('RestoreApproveInt', this.restoreApprove),
      authorizer: new authorizers.HttpLambdaAuthorizer('RestoreApproveAuthorizer', this.props.infrastructure.enrollmentAuthorizerFn, {
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE],
      }),
    });
    new apigw.HttpRoute(this, 'RestoreDeny', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/vault/credentials/restore/deny', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('RestoreDenyInt', this.restoreDeny),
      authorizer: new authorizers.HttpLambdaAuthorizer('RestoreDenyAuthorizer', this.props.infrastructure.enrollmentAuthorizerFn, {
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE],
      }),
    });

    // Backup Settings Routes
    this.route('GetBackupSettingsNew', httpApi, '/vault/credentials/backup/settings', apigw.HttpMethod.GET, this.backupSettingsHandler, memberAuthorizer);
    this.route('UpdateBackupSettingsNew', httpApi, '/vault/credentials/backup/settings', apigw.HttpMethod.PUT, this.backupSettingsHandler, memberAuthorizer);

    // BYOV (Bring Your Own Vault) Routes
    this.route('RegisterByovVault', httpApi, '/vault/byov/register', apigw.HttpMethod.POST, this.registerByovVault, memberAuthorizer);
    this.route('GetByovStatus', httpApi, '/vault/byov/status', apigw.HttpMethod.GET, this.getByovStatus, memberAuthorizer);
    this.route('VerifyByovVault', httpApi, '/vault/byov/verify', apigw.HttpMethod.POST, this.verifyByovVault, memberAuthorizer);
    this.route('UpdateByovVault', httpApi, '/vault/byov', apigw.HttpMethod.PATCH, this.updateByovVault, memberAuthorizer);
    this.route('DeleteByovVault', httpApi, '/vault/byov', apigw.HttpMethod.DELETE, this.deleteByovVault, memberAuthorizer);

    // Note: Ledger routes removed - vault-manager uses JetStream storage

    // ===== TEST AUTOMATION ENDPOINTS =====
    // Public endpoints protected by TEST_API_KEY header (validated in handler)
    // These enable automated E2E testing for Android app

    new apigw.HttpRoute(this, 'TestHealth', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/test/health', apigw.HttpMethod.GET),
      integration: new integrations.HttpLambdaIntegration('TestHealthInt', this.testHealth),
      // No authorizer - uses API key in header
    });

    new apigw.HttpRoute(this, 'TestCreateInvitation', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/test/create-invitation', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('TestCreateInvitationInt', this.testCreateInvitation),
      // No authorizer - uses API key in header
    });

    new apigw.HttpRoute(this, 'TestCleanup', {
      httpApi,
      routeKey: apigw.HttpRouteKey.with('/test/cleanup', apigw.HttpMethod.POST),
      integration: new integrations.HttpLambdaIntegration('TestCleanupInt', this.testCleanup),
      // No authorizer - uses API key in header
    });
  }
}
