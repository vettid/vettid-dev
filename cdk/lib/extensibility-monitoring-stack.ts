import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface ExtensibilityMonitoringStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  adminAuthorizer: apigw.IHttpRouteAuthorizer;
}

/**
 * VettID Extensibility & Monitoring Stack
 *
 * Contains system extensibility, monitoring, and security functions:
 * - NATS control tokens and token revocation
 * - Handler registry management (VettID-managed handlers only)
 * - Supported services management
 * - Vault status and metrics monitoring
 * - Vault broadcasts
 * - Security events and recovery/deletion request management
 * - System health and logs
 *
 * Split from AdminStack to stay under CloudFormation's 500 resource limit.
 *
 * Depends on: Infrastructure Stack (for tables), Core Stack (for API Gateway)
 */
export class ExtensibilityMonitoringStack extends cdk.Stack {
  // NATS Control functions
  public readonly generateNatsControlToken!: lambdaNode.NodejsFunction;
  public readonly natsRevokeToken!: lambdaNode.NodejsFunction;

  // Handler registry admin functions
  public readonly revokeHandler!: lambdaNode.NodejsFunction;
  public readonly listRegistryHandlers!: lambdaNode.NodejsFunction;

  // Supported services admin functions
  public readonly createService!: lambdaNode.NodejsFunction;
  public readonly updateService!: lambdaNode.NodejsFunction;
  public readonly deleteService!: lambdaNode.NodejsFunction;
  public readonly listServices!: lambdaNode.NodejsFunction;
  public readonly toggleServiceStatus!: lambdaNode.NodejsFunction;

  // Service Registry admin functions (NATS-authenticated services)
  public readonly registerServiceCredentials!: lambdaNode.NodejsFunction;
  public readonly verifyServiceAttestation!: lambdaNode.NodejsFunction;
  public readonly listServiceDirectory!: lambdaNode.NodejsFunction;

  // Vault management admin functions
  public readonly getVaultStatus!: lambdaNode.NodejsFunction;
  public readonly getVaultMetrics!: lambdaNode.NodejsFunction;
  public readonly decommissionVault!: lambdaNode.NodejsFunction;

  // Handler functions
  public readonly listDeployedHandlers!: lambdaNode.NodejsFunction;

  // Communications / Vault broadcast functions
  public readonly sendVaultBroadcast!: lambdaNode.NodejsFunction;
  public readonly listVaultBroadcasts!: lambdaNode.NodejsFunction;

  // Security events functions
  public readonly getSecurityEvents!: lambdaNode.NodejsFunction;
  public readonly listCredentialRecoveryRequests!: lambdaNode.NodejsFunction;
  public readonly listVaultDeletionRequests!: lambdaNode.NodejsFunction;
  public readonly cancelRecoveryRequest!: lambdaNode.NodejsFunction;
  public readonly cancelDeletionRequest!: lambdaNode.NodejsFunction;

  // System monitoring functions
  public readonly getSystemHealth!: lambdaNode.NodejsFunction;
  public readonly getSystemLogs!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: ExtensibilityMonitoringStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const handlersBucket = props.infrastructure.handlersBucket;

    // Default environment variables for all functions
    // SECURITY: STAGE=prod ensures localhost origins are not allowed in CORS
    const defaultEnv = {
      TABLE_AUDIT: tables.audit.tableName,
      STAGE: 'prod',
      ALLOWED_ORIGINS: 'https://admin.vettid.dev,https://vettid.dev',
    };

    // ===== NATS CONTROL =====

    // NATS operator secret for signing JWTs
    const natsOperatorSecret = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'NatsOperatorSecret', 'vettid/nats/operator-key'
    );

    const generateNatsControlToken = new lambdaNode.NodejsFunction(this, 'GenerateNatsControlTokenFn', {
      entry: 'lambda/handlers/nats/generateControlToken.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        TABLE_NATS_TOKENS: tables.natsTokens.tableName,
        NATS_DOMAIN: 'nats.vettid.dev',
        NATS_OPERATOR_SECRET_ARN: natsOperatorSecret.secretArn,
        // SECURITY: KMS key for envelope decryption of account seeds
        NATS_SEED_KMS_KEY_ARN: props.infrastructure.natsSeedEncryptionKey.keyArn,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant access to NATS operator secret
    natsOperatorSecret.grantRead(generateNatsControlToken);
    // SECURITY: Grant KMS decrypt for account seeds
    props.infrastructure.natsSeedEncryptionKey.grantDecrypt(generateNatsControlToken);
    // Grant NATS control permissions
    tables.natsAccounts.grantReadData(generateNatsControlToken);
    tables.natsTokens.grantReadWriteData(generateNatsControlToken);
    tables.audit.grantReadWriteData(generateNatsControlToken);

    // NATS Token Revocation - allows admins to revoke user NATS tokens
    const natsRevokeToken = new lambdaNode.NodejsFunction(this, 'NatsRevokeTokenFn', {
      entry: 'lambda/handlers/admin/natsRevokeToken.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        TABLE_NATS_TOKENS: tables.natsTokens.tableName,
        NATS_OPERATOR_SECRET_ARN: natsOperatorSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant access to NATS tables and operator secret
    tables.natsAccounts.grantReadWriteData(natsRevokeToken);
    tables.natsTokens.grantReadWriteData(natsRevokeToken);
    tables.audit.grantReadWriteData(natsRevokeToken);
    natsOperatorSecret.grantRead(natsRevokeToken);

    this.generateNatsControlToken = generateNatsControlToken;
    this.natsRevokeToken = natsRevokeToken;

    // ===== HANDLER REGISTRY ADMIN FUNCTIONS =====

    const handlerEnv = {
      ...defaultEnv,
      TABLE_HANDLERS: tables.handlers.tableName,
      BUCKET_HANDLERS: handlersBucket.bucketName,
    };

    const revokeHandler = new lambdaNode.NodejsFunction(this, 'RevokeHandlerFn', {
      entry: 'lambda/handlers/admin/revokeHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const listRegistryHandlers = new lambdaNode.NodejsFunction(this, 'ListRegistryHandlersFn', {
      entry: 'lambda/handlers/admin/listRegistryHandlers.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: handlerEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Handler registry table permissions
    tables.handlers.grantReadWriteData(revokeHandler);
    tables.handlers.grantReadData(listRegistryHandlers);

    this.revokeHandler = revokeHandler;
    this.listRegistryHandlers = listRegistryHandlers;

    // ===== SUPPORTED SERVICES ADMIN FUNCTIONS =====

    const serviceEnv = {
      ...defaultEnv,
      TABLE_SUPPORTED_SERVICES: tables.supportedServices.tableName,
    };

    const createService = new lambdaNode.NodejsFunction(this, 'CreateServiceFn', {
      entry: 'lambda/handlers/admin/createService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const updateService = new lambdaNode.NodejsFunction(this, 'UpdateServiceFn', {
      entry: 'lambda/handlers/admin/updateService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const deleteService = new lambdaNode.NodejsFunction(this, 'DeleteServiceFn', {
      entry: 'lambda/handlers/admin/deleteService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const listServices = new lambdaNode.NodejsFunction(this, 'ListServicesFn', {
      entry: 'lambda/handlers/admin/listServices.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const toggleServiceStatus = new lambdaNode.NodejsFunction(this, 'ToggleServiceStatusFn', {
      entry: 'lambda/handlers/admin/toggleServiceStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Supported services table permissions
    tables.supportedServices.grantReadWriteData(createService);
    tables.supportedServices.grantReadWriteData(updateService);
    tables.supportedServices.grantReadWriteData(deleteService);
    tables.supportedServices.grantReadData(listServices);
    tables.supportedServices.grantReadWriteData(toggleServiceStatus);

    this.createService = createService;
    this.updateService = updateService;
    this.deleteService = deleteService;
    this.listServices = listServices;
    this.toggleServiceStatus = toggleServiceStatus;

    // ===== SERVICE REGISTRY (NATS-AUTHENTICATED SERVICES) =====

    const serviceRegistryEnv = {
      ...defaultEnv,
      TABLE_SUPPORTED_SERVICES: tables.supportedServices.tableName,
      TABLE_SERVICE_REGISTRY: tables.serviceRegistry.tableName,
      NATS_OPERATOR_SECRET_ARN: natsOperatorSecret.secretArn,
      NATS_SEED_KMS_KEY_ID: props.infrastructure.natsSeedEncryptionKey.keyId,
    };

    // Register NATS credentials for an existing supported service
    const registerServiceCredentials = new lambdaNode.NodejsFunction(this, 'RegisterServiceCredentialsFn', {
      entry: 'lambda/handlers/admin/registerServiceCredentials.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceRegistryEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Verify service domain ownership via DNS TXT or signature challenge
    const verifyServiceAttestation = new lambdaNode.NodejsFunction(this, 'VerifyServiceAttestationFn', {
      entry: 'lambda/handlers/admin/verifyServiceAttestation.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: serviceRegistryEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Public endpoint to list services with connection capabilities
    const listServiceDirectory = new lambdaNode.NodejsFunction(this, 'ListServiceDirectoryFn', {
      entry: 'lambda/handlers/public/listServiceDirectory.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        TABLE_SUPPORTED_SERVICES: tables.supportedServices.tableName,
        TABLE_SERVICE_REGISTRY: tables.serviceRegistry.tableName,
        STAGE: 'prod',
        ALLOWED_ORIGINS: 'https://vettid.dev,https://admin.vettid.dev',
      },
      timeout: cdk.Duration.seconds(15),
    });

    // Service registry permissions
    tables.supportedServices.grantReadData(registerServiceCredentials);
    tables.serviceRegistry.grantReadWriteData(registerServiceCredentials);
    tables.audit.grantReadWriteData(registerServiceCredentials);
    natsOperatorSecret.grantRead(registerServiceCredentials);
    // KMS encrypt permission for encrypting NATS seeds
    props.infrastructure.natsSeedEncryptionKey.grantEncrypt(registerServiceCredentials);

    tables.serviceRegistry.grantReadWriteData(verifyServiceAttestation);
    tables.audit.grantReadWriteData(verifyServiceAttestation);

    tables.supportedServices.grantReadData(listServiceDirectory);
    tables.serviceRegistry.grantReadData(listServiceDirectory);

    this.registerServiceCredentials = registerServiceCredentials;
    this.verifyServiceAttestation = verifyServiceAttestation;
    this.listServiceDirectory = listServiceDirectory;

    // ===== VAULT MANAGEMENT ADMIN FUNCTIONS =====

    const vaultEnv = {
      ...defaultEnv,
      TABLE_VAULT_INSTANCES: tables.vaultInstances.tableName,
      TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
    };

    const getVaultStatus = new lambdaNode.NodejsFunction(this, 'GetVaultStatusFn', {
      entry: 'lambda/handlers/admin/getVaultStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const getVaultMetrics = new lambdaNode.NodejsFunction(this, 'GetVaultMetricsFn', {
      entry: 'lambda/handlers/admin/getVaultMetrics.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: vaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Vault management table permissions
    tables.vaultInstances.grantReadData(getVaultStatus);
    tables.enrollmentSessions.grantReadData(getVaultStatus);
    tables.vaultInstances.grantReadData(getVaultMetrics);
    tables.enrollmentSessions.grantReadData(getVaultMetrics);
    tables.registrations.grantReadData(getVaultMetrics);
    tables.audit.grantReadData(getVaultMetrics);

    this.getVaultStatus = getVaultStatus;
    this.getVaultMetrics = getVaultMetrics;

    // NATS operator secret for decommission (to send enclave.vault.reset message)
    const natsOperatorSecretForDecommission = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'NatsOperatorSecretForDecommission', 'vettid/nats/operator-key'
    );

    // Vault Decommission - Complete cleanup of user's vault data
    const decommissionVault = new lambdaNode.NodejsFunction(this, 'DecommissionVaultFn', {
      entry: 'lambda/handlers/admin/decommissionVault.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_NATS_ACCOUNTS: tables.natsAccounts.tableName,
        TABLE_NATS_TOKENS: tables.natsTokens.tableName,
        TABLE_ENROLLMENT_SESSIONS: tables.enrollmentSessions.tableName,
        TABLE_CREDENTIAL_BACKUPS: tables.credentialBackups.tableName,
        TABLE_PROFILES: tables.profiles.tableName,
        BACKUP_BUCKET: props.infrastructure.backupBucket.bucketName,
        NATS_OPERATOR_SECRET_ARN: natsOperatorSecretForDecommission.secretArn,
        NATS_DOMAIN: 'nats.vettid.dev',
      },
      timeout: cdk.Duration.seconds(60), // Longer timeout for batch deletions
    });

    // Grant full read/write to all vault-related tables
    tables.natsAccounts.grantReadWriteData(decommissionVault);
    tables.natsTokens.grantReadWriteData(decommissionVault);
    tables.enrollmentSessions.grantReadWriteData(decommissionVault);
    tables.credentialBackups.grantReadWriteData(decommissionVault);
    tables.profiles.grantReadWriteData(decommissionVault);
    tables.audit.grantReadWriteData(decommissionVault);
    // S3 permissions for backup cleanup
    props.infrastructure.backupBucket.grantReadWrite(decommissionVault);
    // Secrets Manager permissions for NATS operator key (to send enclave.vault.reset message)
    // Note: Using explicit IAM policy because fromSecretNameV2 grantRead may not properly resolve
    decommissionVault.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:vettid/nats/operator-key-*`],
    }));

    this.decommissionVault = decommissionVault;

    // ===== DEPLOYED HANDLERS (VettID-managed only) =====

    // List deployed handlers uses the main handlers registry table
    const listDeployedHandlers = new lambdaNode.NodejsFunction(this, 'ListDeployedHandlersFn', {
      entry: 'lambda/handlers/admin/listDeployedHandlers.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_HANDLERS: tables.handlers.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Handler permissions
    tables.handlers.grantReadData(listDeployedHandlers);
    tables.audit.grantReadWriteData(listDeployedHandlers);

    this.listDeployedHandlers = listDeployedHandlers;

    // ===== COMMUNICATIONS / VAULT BROADCASTS =====

    // NATS operator secret for system account credentials (reusing the same secret)
    const natsOperatorSecretForBroadcasts = cdk.aws_secretsmanager.Secret.fromSecretNameV2(
      this, 'NatsOperatorSecretForBroadcasts', 'vettid/nats/operator-key'
    );

    const broadcastEnv = {
      ...defaultEnv,
      TABLE_VAULT_BROADCASTS: tables.vaultBroadcasts.tableName,
      NATS_DOMAIN: 'nats.vettid.dev',
      NATS_OPERATOR_SECRET_ARN: natsOperatorSecretForBroadcasts.secretArn,
    };

    const sendVaultBroadcast = new lambdaNode.NodejsFunction(this, 'SendVaultBroadcastFn', {
      entry: 'lambda/handlers/admin/sendVaultBroadcast.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: broadcastEnv,
      timeout: cdk.Duration.seconds(60), // Increased for NATS connection
    });

    const listVaultBroadcasts = new lambdaNode.NodejsFunction(this, 'ListVaultBroadcastsFn', {
      entry: 'lambda/handlers/admin/listVaultBroadcasts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_VAULT_BROADCASTS: tables.vaultBroadcasts.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Broadcast permissions
    tables.vaultBroadcasts.grantReadWriteData(sendVaultBroadcast);
    tables.vaultBroadcasts.grantReadData(listVaultBroadcasts);
    tables.audit.grantReadWriteData(sendVaultBroadcast);
    tables.audit.grantReadWriteData(listVaultBroadcasts);

    // Grant access to NATS operator secret for system account credentials
    natsOperatorSecretForBroadcasts.grantRead(sendVaultBroadcast);

    this.sendVaultBroadcast = sendVaultBroadcast;
    this.listVaultBroadcasts = listVaultBroadcasts;

    // ===== SECURITY EVENTS =====

    const securityEnv = {
      ...defaultEnv,
      TABLE_CREDENTIAL_RECOVERY_REQUESTS: tables.credentialRecoveryRequests.tableName,
      TABLE_VAULT_DELETION_REQUESTS: tables.vaultDeletionRequests.tableName,
    };

    const getSecurityEvents = new lambdaNode.NodejsFunction(this, 'GetSecurityEventsFn', {
      entry: 'lambda/handlers/admin/getSecurityEvents.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: securityEnv,
    });

    const listCredentialRecoveryRequests = new lambdaNode.NodejsFunction(this, 'ListCredentialRecoveryRequestsFn', {
      entry: 'lambda/handlers/admin/listCredentialRecoveryRequests.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: securityEnv,
    });

    const listVaultDeletionRequests = new lambdaNode.NodejsFunction(this, 'ListVaultDeletionRequestsFn', {
      entry: 'lambda/handlers/admin/listVaultDeletionRequests.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: securityEnv,
    });

    const cancelRecoveryRequest = new lambdaNode.NodejsFunction(this, 'CancelRecoveryRequestFn', {
      entry: 'lambda/handlers/admin/cancelRecoveryRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: securityEnv,
    });

    const cancelDeletionRequest = new lambdaNode.NodejsFunction(this, 'CancelDeletionRequestFn', {
      entry: 'lambda/handlers/admin/cancelDeletionRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: securityEnv,
    });

    // Grant permissions for security functions
    tables.audit.grantReadData(getSecurityEvents);
    tables.credentialRecoveryRequests.grantReadData(getSecurityEvents);
    tables.vaultDeletionRequests.grantReadData(getSecurityEvents);
    tables.credentialRecoveryRequests.grantReadData(listCredentialRecoveryRequests);
    tables.vaultDeletionRequests.grantReadData(listVaultDeletionRequests);
    tables.credentialRecoveryRequests.grantReadWriteData(cancelRecoveryRequest);
    tables.vaultDeletionRequests.grantReadWriteData(cancelDeletionRequest);
    tables.audit.grantReadWriteData(cancelRecoveryRequest);
    tables.audit.grantReadWriteData(cancelDeletionRequest);

    this.getSecurityEvents = getSecurityEvents;
    this.listCredentialRecoveryRequests = listCredentialRecoveryRequests;
    this.listVaultDeletionRequests = listVaultDeletionRequests;
    this.cancelRecoveryRequest = cancelRecoveryRequest;
    this.cancelDeletionRequest = cancelDeletionRequest;

    // ===== SYSTEM MONITORING =====

    const getSystemHealth = new lambdaNode.NodejsFunction(this, 'GetSystemHealthFn', {
      entry: 'lambda/handlers/admin/getSystemHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const getSystemLogs = new lambdaNode.NodejsFunction(this, 'GetSystemLogsFn', {
      entry: 'lambda/handlers/admin/getSystemLogs.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant system monitoring permissions
    // SECURITY: Scope to VettID-specific resources only
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:GetSendQuota'],
      resources: ['*'], // SES quota doesn't support resource-level permissions
    }));
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: ['dynamodb:DescribeTable'],
      resources: [
        `arn:aws:dynamodb:${this.region}:${this.account}:table/VettID-*`,
      ],
    }));
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:GetMetricStatistics'],
      resources: ['*'], // CloudWatch metrics don't support resource-level permissions
    }));
    // NATS cluster health monitoring via NLB target group
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'elasticloadbalancing:DescribeTargetGroups',
        'elasticloadbalancing:DescribeTargetHealth',
      ],
      resources: ['*'], // Target group discovery requires listing all target groups
    }));
    // Nitro Enclave ASG health monitoring
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'autoscaling:DescribeAutoScalingGroups',
        'autoscaling:DescribeInstanceRefreshes',
      ],
      resources: ['*'], // ASG discovery requires listing all groups
    }));
    // SSM parameter access for AMI version tracking
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:GetParameter'],
      resources: [
        `arn:aws:ssm:${this.region}:${this.account}:parameter/vettid/nitro-enclave/*`,
      ],
    }));

    // SECURITY: Scope logs access to VettID log groups only
    getSystemLogs.addToRolePolicy(new iam.PolicyStatement({
      actions: ['logs:DescribeLogGroups'],
      resources: [
        `arn:aws:logs:${this.region}:${this.account}:log-group:*`,
      ],
    }));
    getSystemLogs.addToRolePolicy(new iam.PolicyStatement({
      actions: ['logs:FilterLogEvents'],
      resources: [
        `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/VettID-*:*`,
        `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/VettIDStack-*:*`,
        `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/apigateway/vettid-*:*`,
      ],
    }));

    this.getSystemHealth = getSystemHealth;
    this.getSystemLogs = getSystemLogs;

    // ===== ADD API ROUTES =====
    this.addRoutes(props.httpApi, props.adminAuthorizer);
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
   * Helper to create a public route without authorization
   */
  private publicRoute(
    id: string,
    httpApi: apigw.HttpApi,
    path: string,
    method: apigw.HttpMethod,
    handler: lambdaNode.NodejsFunction,
  ): void {
    new apigw.HttpRoute(this, id, {
      httpApi,
      routeKey: apigw.HttpRouteKey.with(path, method),
      integration: new integrations.HttpLambdaIntegration(`${id}Int`, handler),
    });
  }

  /**
   * Add extensibility and monitoring routes to the HTTP API
   * Routes are created in this stack to stay under CloudFormation's 500 resource limit
   * Using HttpRoute directly (not httpApi.addRoutes) to avoid cyclic dependencies
   */
  private addRoutes(httpApi: apigw.HttpApi, adminAuthorizer: apigw.IHttpRouteAuthorizer): void {
    // NATS Control - Admin-only endpoint for issuing control tokens
    this.route('GenerateNatsControlToken', httpApi, '/admin/nats/control-token', apigw.HttpMethod.POST, this.generateNatsControlToken, adminAuthorizer);
    this.route('NatsRevokeToken', httpApi, '/admin/nats/revoke-token', apigw.HttpMethod.POST, this.natsRevokeToken, adminAuthorizer);

    // Handler Registry Admin - Admin-only endpoints for managing VettID handler registry
    this.route('ListRegistryHandlers', httpApi, '/admin/registry/handlers', apigw.HttpMethod.GET, this.listRegistryHandlers, adminAuthorizer);
    this.route('RevokeHandler', httpApi, '/admin/registry/handlers/revoke', apigw.HttpMethod.POST, this.revokeHandler, adminAuthorizer);

    // Supported Services Admin - Admin-only endpoints for managing supported services
    this.route('ListServices', httpApi, '/admin/services', apigw.HttpMethod.GET, this.listServices, adminAuthorizer);
    this.route('CreateService', httpApi, '/admin/services', apigw.HttpMethod.POST, this.createService, adminAuthorizer);
    this.route('UpdateService', httpApi, '/admin/services', apigw.HttpMethod.PUT, this.updateService, adminAuthorizer);
    this.route('DeleteService', httpApi, '/admin/services/delete', apigw.HttpMethod.POST, this.deleteService, adminAuthorizer);
    this.route('ToggleServiceStatus', httpApi, '/admin/services/status', apigw.HttpMethod.POST, this.toggleServiceStatus, adminAuthorizer);

    // Service Registry Admin - Admin-only endpoints for NATS-authenticated services
    this.route('RegisterServiceCredentials', httpApi, '/admin/service-registry', apigw.HttpMethod.POST, this.registerServiceCredentials, adminAuthorizer);
    this.route('VerifyServiceAttestation', httpApi, '/admin/service-registry/{service_id}/attest', apigw.HttpMethod.POST, this.verifyServiceAttestation, adminAuthorizer);

    // Vault Management Admin - Admin-only endpoints for vault monitoring
    this.route('GetVaultStatus', httpApi, '/admin/vault-status', apigw.HttpMethod.GET, this.getVaultStatus, adminAuthorizer);
    this.route('GetVaultMetrics', httpApi, '/admin/vault-metrics', apigw.HttpMethod.GET, this.getVaultMetrics, adminAuthorizer);
    this.route('DecommissionVault', httpApi, '/admin/vault/{user_guid}/decommission', apigw.HttpMethod.DELETE, this.decommissionVault, adminAuthorizer);

    // Deployed Handlers - View VettID-managed deployed handlers
    this.route('ListDeployedHandlers', httpApi, '/admin/handlers/deployed', apigw.HttpMethod.GET, this.listDeployedHandlers, adminAuthorizer);

    // Communications / Vault Broadcasts
    this.route('SendVaultBroadcast', httpApi, '/admin/broadcasts', apigw.HttpMethod.POST, this.sendVaultBroadcast, adminAuthorizer);
    this.route('ListVaultBroadcasts', httpApi, '/admin/broadcasts', apigw.HttpMethod.GET, this.listVaultBroadcasts, adminAuthorizer);

    // Security Events - Security monitoring and request management
    this.route('GetSecurityEvents', httpApi, '/admin/security-events', apigw.HttpMethod.GET, this.getSecurityEvents, adminAuthorizer);
    this.route('ListCredentialRecoveryRequests', httpApi, '/admin/credential-recovery-requests', apigw.HttpMethod.GET, this.listCredentialRecoveryRequests, adminAuthorizer);
    this.route('ListVaultDeletionRequests', httpApi, '/admin/vault-deletion-requests', apigw.HttpMethod.GET, this.listVaultDeletionRequests, adminAuthorizer);
    this.route('CancelRecoveryRequest', httpApi, '/admin/credential-recovery-requests/{recovery_id}/cancel', apigw.HttpMethod.POST, this.cancelRecoveryRequest, adminAuthorizer);
    this.route('CancelDeletionRequest', httpApi, '/admin/vault-deletion-requests/{request_id}/cancel', apigw.HttpMethod.POST, this.cancelDeletionRequest, adminAuthorizer);

    // System Monitoring routes
    this.route('GetSystemHealth', httpApi, '/admin/system-health', apigw.HttpMethod.GET, this.getSystemHealth, adminAuthorizer);
    this.route('GetSystemLogs', httpApi, '/admin/system-logs', apigw.HttpMethod.GET, this.getSystemLogs, adminAuthorizer);

    // Public Service Directory - No auth required
    this.publicRoute('ListServiceDirectory', httpApi, '/services/directory', apigw.HttpMethod.GET, this.listServiceDirectory);
  }
}
