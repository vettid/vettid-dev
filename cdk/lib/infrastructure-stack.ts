import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_dynamodb as dynamodb,
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_cognito as cognito,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_authorizers as authorizers,
  aws_iam as iam,
  aws_s3 as s3,
  aws_secretsmanager as secretsmanager,
  aws_kms as kms,
} from 'aws-cdk-lib';

/**
 * VettID Infrastructure Stack
 *
 * Contains foundational resources that other stacks depend on:
 * - All DynamoDB tables (16 tables)
 * - Cognito User Pools (admin and member)
 * - HTTP API Gateway
 * - API Gateway authorizers
 *
 * This stack is deployed first and exports resources for use by other stacks.
 */
export class InfrastructureStack extends cdk.Stack {
  // Public properties for other stacks to access
  public readonly tables: {
    invites: dynamodb.Table;
    registrations: dynamodb.Table;
    audit: dynamodb.Table;
    waitlist: dynamodb.Table;
    magicLinkTokens: dynamodb.Table;
    membershipTerms: dynamodb.Table;
    subscriptions: dynamodb.Table;
    proposals: dynamodb.Table;
    votes: dynamodb.Table;
    subscriptionTypes: dynamodb.Table;
    sentEmails: dynamodb.Table;
    // Legacy credential tables removed - replaced by vault-manager JetStream storage
    actionTokens: dynamodb.Table;
    enrollmentSessions: dynamodb.Table;
    notificationPreferences: dynamodb.Table;
    pendingAdmins: dynamodb.Table;
    natsAccounts: dynamodb.Table;
    natsTokens: dynamodb.Table;
    vaultInstances: dynamodb.Table;
    handlers: dynamodb.Table;
    handlerInstallations: dynamodb.Table;
    handlerSubmissions: dynamodb.Table;
    // Phase 7: Profiles
    profiles: dynamodb.Table;
    // Phase 8: Backup System
    backups: dynamodb.Table;
    credentialBackups: dynamodb.Table;
    backupSettings: dynamodb.Table;
    credentialRecoveryRequests: dynamodb.Table;
    credentialTransfers: dynamodb.Table;
    vaultDeletionRequests: dynamodb.Table;
    // Supported Services Registry
    supportedServices: dynamodb.Table;
    // Service Registry (NATS-authenticated services)
    serviceRegistry: dynamodb.Table;
    // Dynamic Handler Loading
    handlerManifest: dynamodb.Table;
    // Admin Portal: Communications
    vaultBroadcasts: dynamodb.Table;
    // Control Command Signing
    commandIdempotency: dynamodb.Table;
    // Volunteer Help Requests
    helpRequests: dynamodb.Table;
  };

  // S3 Buckets
  public readonly termsBucket!: s3.Bucket;
  public readonly handlersBucket!: s3.Bucket;
  public readonly backupBucket!: s3.Bucket;
  public readonly publishedVotesBucket!: s3.Bucket;

  // Cognito resources
  public readonly memberUserPool!: cognito.UserPool;
  public readonly adminUserPool!: cognito.UserPool;
  public readonly memberAppClient!: cognito.UserPoolClient;
  public readonly adminAppClient!: cognito.UserPoolClient;
  public readonly memberPoolDomain!: cognito.UserPoolDomain;
  public readonly adminPoolDomain!: cognito.UserPoolDomain;

  // Authorizers (to be used with VettIDStack's HTTP API)
  public readonly adminAuthorizer!: apigw.IHttpRouteAuthorizer;
  public readonly memberAuthorizer!: apigw.IHttpRouteAuthorizer;

  // Enrollment authorizer Lambda (for VaultStack)
  public readonly enrollmentAuthorizerFn!: lambdaNode.NodejsFunction;

  // Enrollment JWT secret ARN (for VaultStack to use)
  public readonly enrollmentJwtSecretArn!: string;

  // Action token signing secret ARN (for VaultStack actionRequest)
  public readonly actionTokenSecretArn!: string;

  // Handler signing key secret ARN (for dynamic handler loading)
  public readonly handlerSigningKeySecretArn!: string;

  // Control command signing key secret ARN (for signed control commands)
  public readonly controlSigningKeySecretArn!: string;

  // NATS seed encryption key (for application-level envelope encryption of account seeds)
  public readonly natsSeedEncryptionKey!: kms.Key;

  // Voting KMS key (for proposal signing with ECDSA-SHA256)
  public readonly votingKey!: kms.Key;

  // Shared utilities Lambda layer
  public readonly sharedUtilsLayer!: lambda.LayerVersion;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ===== EMAIL CONFIGURATION =====
    // Read from CDK context (can be overridden via -c flag or cdk.json)
    const sesFromAuthEmail = this.node.tryGetContext('vettid:sesFromAuthEmail') || 'no-reply@auth.vettid.dev';

    // ===== KMS KEY FOR DYNAMODB ENCRYPTION =====
    // SECURITY: Customer-managed key for DynamoDB table encryption
    // This provides:
    // - Audit trail via CloudTrail for key usage
    // - Ability to revoke access by disabling the key
    // - Compliance with data protection requirements
    const dynamoDbEncryptionKey = new kms.Key(this, 'DynamoDbEncryptionKey', {
      alias: 'vettid-dynamodb',
      description: 'Customer-managed KMS key for DynamoDB table encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN, // Retain key to prevent data loss
    });

    // ===== KMS KEY FOR NATS SEED ENCRYPTION =====
    // SECURITY: Application-level envelope encryption for NATS account seeds
    // This provides defense-in-depth beyond DynamoDB's table-level encryption:
    // - Seeds remain encrypted even if DynamoDB access is compromised
    // - Decryption requires explicit KMS permissions (principle of least privilege)
    // - CloudTrail audit trail for every decrypt operation
    // - Ability to revoke access by modifying key policy
    const natsSeedEncryptionKey = new kms.Key(this, 'NatsSeedEncryptionKey', {
      alias: 'vettid-nats-seed',
      description: 'Envelope encryption for NATS account seeds (Ed25519 private keys)',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN, // Retain to prevent credential loss
    });
    this.natsSeedEncryptionKey = natsSeedEncryptionKey;

    // ===== KMS KEY FOR VOTING/PROPOSAL SIGNING =====
    // SECURITY: Asymmetric ECC key for ECDSA-SHA256 proposal signing
    // - Proposals are signed by VettID to prove authenticity
    // - Mobile apps and vaults verify proposal signatures before voting
    // - The public key can be exported for client-side verification
    // - The private key never leaves KMS (hardware security module)
    const votingKey = new kms.Key(this, 'VotingKey', {
      alias: 'vettid-voting',
      description: 'Asymmetric ECC key for proposal signing (ECDSA-SHA256)',
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: cdk.RemovalPolicy.RETAIN, // Retain to verify historical proposals
    });
    this.votingKey = votingKey;

    // ===== DYNAMODB TABLES =====

    // Invites table
    const invites = new dynamodb.Table(this, 'Invites', {
      partitionKey: { name: 'code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for looking up invites by user_guid
    invites.addGlobalSecondaryIndex({
      indexName: 'user-guid-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Registrations table with GSI
    const registrations = new dynamodb.Table(this, 'Registrations', {
      partitionKey: { name: 'registration_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    registrations.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Email index for efficient lookups by email (avoids full table scans)
    registrations.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // User GUID index for looking up registrations by user_guid (used by sendBulkEmail for subscribers)
    registrations.addGlobalSecondaryIndex({
      indexName: 'user-guid-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Audit log table
    const audit = new dynamodb.Table(this, 'Audit', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true, // SECURITY: Enable PITR for critical audit logs
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    audit.addGlobalSecondaryIndex({
      indexName: 'email-timestamp-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAtTimestamp', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for querying admin activity by actor (the admin who performed the action)
    audit.addGlobalSecondaryIndex({
      indexName: 'actor-email-index',
      partitionKey: { name: 'actor_email', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAtTimestamp', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Waitlist table
    const waitlist = new dynamodb.Table(this, 'Waitlist', {
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    waitlist.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Magic link tokens table
    const magicLinkTokens = new dynamodb.Table(this, 'MagicLinkTokens', {
      partitionKey: { name: 'token', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Membership terms table
    const membershipTerms = new dynamodb.Table(this, 'MembershipTerms', {
      partitionKey: { name: 'version_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    membershipTerms.addGlobalSecondaryIndex({
      indexName: 'current-index',
      partitionKey: { name: 'is_current', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Subscriptions table
    // DESIGN DECISION: Single-subscription-per-user model
    // - PK is user_guid (not subscription_id) to enforce one active subscription per user
    // - Creating a new subscription overwrites the existing one via PutItem
    // - Previous subscriptions are preserved in the Audit table with action='subscription_replaced'
    // - This design simplifies logic and avoids complex multi-subscription management
    // - To support multiple subscriptions per user in the future, change PK to subscription_id
    //   and add a GSI on user_guid
    const subscriptions = new dynamodb.Table(this, 'Subscriptions', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Proposals table
    const proposals = new dynamodb.Table(this, 'Proposals', {
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    proposals.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Votes table
    const votes = new dynamodb.Table(this, 'Votes', {
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    votes.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'voted_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    votes.addGlobalSecondaryIndex({
      indexName: 'proposal-vote-index',
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'vote', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Subscription types table
    const subscriptionTypes = new dynamodb.Table(this, 'SubscriptionTypes', {
      partitionKey: { name: 'subscription_type_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true, // SECURITY: Enable PITR for configuration data
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Sent emails table (for bulk email tracking)
    const sentEmails = new dynamodb.Table(this, 'SentEmails', {
      partitionKey: { name: 'email_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    sentEmails.addGlobalSecondaryIndex({
      indexName: 'sent-at-index',
      partitionKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== VAULT SERVICES TABLES =====
    // Note: Legacy credential tables (Credentials, CredentialKeys, TransactionKeys, LedgerAuthTokens)
    // have been removed - replaced by vault-manager JetStream storage in Nitro enclave

    // Action tokens table
    const actionTokens = new dynamodb.Table(this, 'ActionTokens', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    actionTokens.addGlobalSecondaryIndex({
      indexName: 'token-index',
      partitionKey: { name: 'token', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Enrollment sessions table
    const enrollmentSessions = new dynamodb.Table(this, 'EnrollmentSessions', {
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    enrollmentSessions.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    enrollmentSessions.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up sessions by token (used by mobile authenticate endpoint)
    enrollmentSessions.addGlobalSecondaryIndex({
      indexName: 'token-index',
      partitionKey: { name: 'session_token', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up sessions by short enrollment code (used by mobile resolve-code endpoint)
    enrollmentSessions.addGlobalSecondaryIndex({
      indexName: 'code-index',
      partitionKey: { name: 'enrollment_code', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Notification Preferences table
    const notificationPreferences = new dynamodb.Table(this, 'NotificationPreferences', {
      partitionKey: { name: 'notification_type', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'admin_email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Pending Admins table - stores admin invitations awaiting SES verification
    const pendingAdmins = new dynamodb.Table(this, 'PendingAdmins', {
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expires_at',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // ===== NATS INFRASTRUCTURE TABLES =====

    // NATS Accounts table - stores member NATS namespace allocations
    // TTL enabled for automatic cleanup of incomplete enrollments
    // (accounts stuck in 'enrolling' status will have enrollment_ttl set)
    const natsAccounts = new dynamodb.Table(this, 'NatsAccounts', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
      timeToLiveAttribute: 'enrollment_ttl',  // Auto-delete incomplete enrollments
    });

    // GSI for NATS account JWT lookup by account public key (used by NATS URL resolver)
    natsAccounts.addGlobalSecondaryIndex({
      indexName: 'account-key-index',
      partitionKey: { name: 'account_public_key', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // NATS Tokens table - stores issued NATS JWT tokens
    const natsTokens = new dynamodb.Table(this, 'NatsTokens', {
      partitionKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    natsTokens.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'issued_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== VAULT INSTANCES TABLE =====

    // Vault Instances table - stores EC2 vault instance state per user
    const vaultInstances = new dynamodb.Table(this, 'VaultInstances', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    vaultInstances.addGlobalSecondaryIndex({
      indexName: 'instance-index',
      partitionKey: { name: 'instance_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    vaultInstances.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== HANDLER REGISTRY TABLES =====

    // Handlers table - stores handler metadata in the registry
    const handlers = new dynamodb.Table(this, 'Handlers', {
      partitionKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    handlers.addGlobalSecondaryIndex({
      indexName: 'category-index',
      partitionKey: { name: 'category', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'name', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    handlers.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'published_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Handler Installations table - tracks which handlers are installed per user
    const handlerInstallations = new dynamodb.Table(this, 'HandlerInstallations', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    handlerInstallations.addGlobalSecondaryIndex({
      indexName: 'handler-index',
      partitionKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'installed_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== PHASE 7: PROFILES TABLE =====

    // Profiles table - stores user profile information
    const profiles = new dynamodb.Table(this, 'Profiles', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // ===== PHASE 8: BACKUP SYSTEM TABLES =====

    // Backups table - stores vault backup metadata
    const backups = new dynamodb.Table(this, 'Backups', {
      partitionKey: { name: 'backup_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for querying backups by member (sorted by created_at)
    backups.addGlobalSecondaryIndex({
      indexName: 'member-created-index',
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Credential Backups table - stores encrypted credential backup metadata
    const credentialBackups = new dynamodb.Table(this, 'CredentialBackups', {
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Backup Settings table - stores per-member backup preferences
    const backupSettings = new dynamodb.Table(this, 'BackupSettings', {
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // Credential Recovery Requests table - tracks 24-hour delayed recovery requests
    const credentialRecoveryRequests = new dynamodb.Table(this, 'CredentialRecoveryRequests', {
      partitionKey: { name: 'recovery_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',  // Auto-delete expired requests
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for finding active recovery requests by member
    credentialRecoveryRequests.addGlobalSecondaryIndex({
      indexName: 'member-status-index',
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Credential Transfers table - tracks device-to-device credential transfers
    const credentialTransfers = new dynamodb.Table(this, 'CredentialTransfers', {
      partitionKey: { name: 'transfer_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',  // Auto-delete expired transfers
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for finding active transfers by member
    credentialTransfers.addGlobalSecondaryIndex({
      indexName: 'member-status-index',
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Vault Deletion Requests table - tracks 24-hour delayed vault deletion requests
    const vaultDeletionRequests = new dynamodb.Table(this, 'VaultDeletionRequests', {
      partitionKey: { name: 'request_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'ttl',  // Auto-delete expired requests
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for finding active deletion requests by member
    vaultDeletionRequests.addGlobalSecondaryIndex({
      indexName: 'member-status-index',
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== HANDLER SUBMISSIONS =====

    // Handler Submissions table - tracks WASM handler submissions for review
    // Note: This table is maintained for backward compatibility with deployed stacks
    const handlerSubmissions = new dynamodb.Table(this, 'HandlerSubmissions', {
      partitionKey: { name: 'submission_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for listing submissions by handler
    handlerSubmissions.addGlobalSecondaryIndex({
      indexName: 'handler-index',
      partitionKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'submitted_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for filtering by status
    handlerSubmissions.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'submitted_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== SUPPORTED SERVICES REGISTRY =====

    // Supported Services table - stores third-party service integrations
    const supportedServices = new dynamodb.Table(this, 'SupportedServices', {
      partitionKey: { name: 'service_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for filtering by status
    supportedServices.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sort_order', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for filtering by service type
    supportedServices.addGlobalSecondaryIndex({
      indexName: 'service-type-index',
      partitionKey: { name: 'service_type', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'name', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== SERVICE REGISTRY (NATS-authenticated services) =====

    // ServiceRegistry table - stores NATS-authenticated third-party service credentials
    // This table extends supportedServices with actual NATS authentication credentials
    // and attestation status for services that connect directly to user vaults.
    // Schema:
    //   service_id (PK): Matches supportedServices.service_id
    //   status: 'pending' | 'active' | 'suspended' | 'revoked'
    //   domain: Verified domain (e.g., signal.org) - must be unique
    //   public_key: Ed25519 public key for signature verification
    //   encryption_key: X25519 public key for E2E encryption
    //   nats_account_public_key: NATS account public key
    //   nats_account_seed_encrypted: KMS-encrypted NATS account seed
    //   attestations: List of attestation records with timestamps
    //   webhook_url: Optional callback URL for service notifications
    //   rate_limit: Messages per second limit (default 100)
    //   created_at, updated_at: ISO timestamps
    const serviceRegistry = new dynamodb.Table(this, 'ServiceRegistry', {
      partitionKey: { name: 'service_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for looking up service by domain (for attestation verification)
    serviceRegistry.addGlobalSecondaryIndex({
      indexName: 'domain-index',
      partitionKey: { name: 'domain', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for listing services by status (for admin dashboard and directory API)
    serviceRegistry.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== DYNAMIC HANDLER LOADING =====

    // Handler Manifest table - stores current version info for dynamic WASM loading
    // Schema:
    //   handler_id (PK): e.g., "messaging.send", "crypto.sign"
    //   current_version: "1.2.0"
    //   s3_key: "handlers/messaging/v1.2.0.wasm"
    //   sha256: hash of WASM file for integrity verification
    //   signature: Ed25519 signature of WASM file
    //   rollout_percent: 0-100 for gradual rollouts
    //   fallback_version: version to use if rollout fails
    //   updated_at: ISO timestamp
    const handlerManifest = new dynamodb.Table(this, 'HandlerManifest', {
      partitionKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // ===== ADMIN PORTAL: COMMUNICATIONS =====

    // Vault Broadcasts table - stores broadcast history for NATS vault messaging
    // Schema:
    //   broadcast_id (PK): UUID for the broadcast
    //   type: "system_announcement" | "security_alert" | "admin_message"
    //   priority: "normal" | "high" | "critical"
    //   title: broadcast title
    //   message: broadcast message content
    //   sent_at: ISO timestamp
    //   sent_by: admin email who sent it
    //   delivery_count: number of vaults that received it
    //   nats_subject: NATS subject used for delivery
    const vaultBroadcasts = new dynamodb.Table(this, 'VaultBroadcasts', {
      partitionKey: { name: 'broadcast_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for listing broadcasts by type (sorted by sent_at)
    vaultBroadcasts.addGlobalSecondaryIndex({
      indexName: 'type-sent-index',
      partitionKey: { name: 'type', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for listing all broadcasts by sent_at (for history view)
    vaultBroadcasts.addGlobalSecondaryIndex({
      indexName: 'sent-at-index',
      partitionKey: { name: 'year_month', type: dynamodb.AttributeType.STRING },  // e.g., "2025-01"
      sortKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== CONTROL COMMAND SIGNING =====
    // Command idempotency table - tracks processed command IDs to prevent replay attacks
    // Records are automatically deleted after 24 hours via TTL
    // Schema:
    //   command_id: unique command identifier (PK)
    //   command: command name
    //   issued_by: admin email
    //   processed_at: ISO timestamp
    //   ttl: Unix timestamp for TTL deletion
    const commandIdempotency = new dynamodb.Table(this, 'CommandIdempotency', {
      partitionKey: { name: 'command_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // ===== VOLUNTEER HELP REQUESTS =====
    // Table for storing volunteer/help request submissions from the public /help form
    // Schema:
    //   request_id: UUID (PK)
    //   name: submitter's name
    //   email: submitter's email
    //   phone: submitter's phone
    //   linkedin_url: optional LinkedIn profile URL
    //   help_types: array of selected help types
    //   message: personal note/description
    //   status: 'new' | 'contacted' | 'in_progress' | 'archived'
    //   admin_notes: notes from admin follow-ups
    //   created_at: ISO timestamp
    //   updated_at: ISO timestamp
    const helpRequests = new dynamodb.Table(this, 'HelpRequests', {
      partitionKey: { name: 'request_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: dynamoDbEncryptionKey,
    });

    // GSI for querying by status (admin view)
    helpRequests.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== S3 BUCKETS =====

    // S3 bucket for membership terms PDFs (shared by VettIDStack and AdminStack)
    const termsBucket = new s3.Bucket(this, 'MembershipTermsBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // S3 bucket for WASM handler packages
    const handlersBucket = new s3.Bucket(this, 'HandlerPackagesBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // S3 bucket for vault and credential backups
    const backupBucket = new s3.Bucket(this, 'VaultBackupsBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [
        {
          // Clean up incomplete multipart uploads after 7 days
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
        {
          // Move old versions to cheaper storage after 30 days
          noncurrentVersionTransitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: cdk.Duration.days(30),
            },
          ],
          // Delete old versions after 90 days
          noncurrentVersionExpiration: cdk.Duration.days(90),
        },
      ],
    });

    // S3 bucket for published vote results (anonymized vote lists + Merkle trees)
    // Purpose: Transparent, auditable voting results without revealing voter identities
    // Structure:
    //   {proposal_id}/votes.json - Anonymized vote list [{voting_public_key, vote, vote_signature}]
    //   {proposal_id}/merkle.json - Merkle tree root and structure for verification
    const publishedVotesBucket = new s3.Bucket(this, 'PublishedVotesBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [
        {
          // Clean up incomplete multipart uploads after 7 days
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
        {
          // Archive to Glacier after 1 year for compliance/audit purposes
          transitions: [
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(365),
            },
          ],
        },
      ],
    });

    // ===== ASSIGN TO PUBLIC PROPERTIES =====

    this.tables = {
      invites,
      registrations,
      audit,
      waitlist,
      magicLinkTokens,
      membershipTerms,
      subscriptions,
      proposals,
      votes,
      subscriptionTypes,
      sentEmails,
      // Legacy credential tables removed - vault-manager uses JetStream storage
      actionTokens,
      enrollmentSessions,
      notificationPreferences,
      pendingAdmins,
      natsAccounts,
      natsTokens,
      vaultInstances,
      handlers,
      handlerInstallations,
      handlerSubmissions,
      // Phase 7: Profiles
      profiles,
      // Phase 8: Backup System
      backups,
      credentialBackups,
      backupSettings,
      credentialRecoveryRequests,
      credentialTransfers,
      vaultDeletionRequests,
      // Supported Services Registry
      supportedServices,
      // Service Registry (NATS-authenticated services)
      serviceRegistry,
      // Dynamic Handler Loading
      handlerManifest,
      // Admin Portal: Communications
      vaultBroadcasts,
      // Control Command Signing
      commandIdempotency,
      // Volunteer Help Requests
      helpRequests,
    };

    this.termsBucket = termsBucket;
    this.handlersBucket = handlersBucket;
    this.backupBucket = backupBucket;
    this.publishedVotesBucket = publishedVotesBucket;

    // ===== AUTH LAMBDA FUNCTIONS =====

    // Custom auth Lambda functions for passwordless magic link authentication
    // These must be created before the user pool that references them
    const defineAuthChallenge = new lambdaNode.NodejsFunction(this, 'DefineAuthChallengeFn', {
      entry: 'lambda/handlers/auth/defineAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
    });

    const createAuthChallenge = new lambdaNode.NodejsFunction(this, 'CreateAuthChallengeFn', {
      entry: 'lambda/handlers/auth/createAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        MAGIC_LINK_TABLE: magicLinkTokens.tableName,
        REGISTRATIONS_TABLE: registrations.tableName,
        MAGIC_LINK_URL: 'https://vettid.dev/auth',
        SES_FROM: sesFromAuthEmail,
      },
      timeout: cdk.Duration.seconds(10),
    });

    const verifyAuthChallenge = new lambdaNode.NodejsFunction(this, 'VerifyAuthChallengeFn', {
      entry: 'lambda/handlers/auth/verifyAuthChallenge.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        MAGIC_LINK_TABLE: magicLinkTokens.tableName,
        REGISTRATIONS_TABLE: registrations.tableName,
      },
      timeout: cdk.Duration.seconds(10),
    });

    // PreTokenGeneration trigger for admin user pool - adds custom:admin_type to ID token
    const preTokenGeneration = new lambdaNode.NodejsFunction(this, 'PreTokenGenerationFn', {
      entry: 'lambda/triggers/preTokenGeneration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
    });

    // PostAuthentication trigger - updates last_login_at on each login
    const postAuthentication = new lambdaNode.NodejsFunction(this, 'PostAuthenticationFn', {
      entry: 'lambda/triggers/postAuthentication.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      initialPolicy: [
        // Permission to update user attributes (for last_login_at tracking)
        // Uses ARN pattern to avoid circular dependency with the user pool
        new iam.PolicyStatement({
          actions: ['cognito-idp:AdminUpdateUserAttributes'],
          resources: [`arn:aws:cognito-idp:${cdk.Aws.REGION}:${cdk.Aws.ACCOUNT_ID}:userpool/*`],
        }),
      ],
    });

    // Grant permissions to auth Lambda functions
    magicLinkTokens.grantReadWriteData(createAuthChallenge);
    magicLinkTokens.grantReadWriteData(verifyAuthChallenge);
    registrations.grantReadData(createAuthChallenge); // For PIN status check
    registrations.grantReadData(verifyAuthChallenge); // For PIN validation

    // Grant CloudWatch metrics permissions to verifyAuthChallenge for failed login tracking
    verifyAuthChallenge.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'], // CloudWatch PutMetricData doesn't support resource-level permissions
      conditions: {
        StringEquals: {
          'cloudwatch:namespace': 'VettID/Authentication'
        }
      }
    }));

    // Grant SES permissions to createAuthChallenge
    // Sends from no-reply@auth.vettid.dev, but AWS SES in sandbox mode requires
    // IAM permission for both sender AND recipient identities
    createAuthChallenge.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendRawEmail'],
      resources: [
        `arn:aws:ses:${this.region}:${this.account}:identity/auth.vettid.dev`,
        `arn:aws:ses:${this.region}:${this.account}:identity/*`, // Recipients in sandbox mode
      ],
    }));


    // ===== COGNITO USER POOLS =====



    // Member user pool - for VettID members accessing vettid.dev/account
    // Uses passwordless magic link authentication via custom auth flow
    const memberUserPool = new cognito.UserPool(this, 'MemberUserPool', {
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(1), // SECURITY: Short temp password validity
      },
      // NOTE: advancedSecurityMode requires Cognito Plus tier (currently on Essentials)
      // Account lockout would need to be implemented at application layer instead
      email: cognito.UserPoolEmail.withSES({
        fromEmail: 'no-reply@auth.vettid.dev',
        fromName: 'VettID',
        sesRegion: 'us-east-1',
        sesVerifiedDomain: 'auth.vettid.dev',
      }),
      customAttributes: {
        'user_guid': new cognito.StringAttribute({ minLen: 36, maxLen: 36, mutable: false }),
      },
      lambdaTriggers: {
        defineAuthChallenge: defineAuthChallenge,
        createAuthChallenge: createAuthChallenge,
        verifyAuthChallengeResponse: verifyAuthChallenge,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const memberDomainPrefix = `vettid-members-${cdk.Names.uniqueId(this).toLowerCase().slice(0, 10)}`.replace(/[^a-z0-9-]/g, '');
    const memberPoolDomain = memberUserPool.addDomain('MemberCognitoDomain', { cognitoDomain: { domainPrefix: memberDomainPrefix } });
    new cognito.CfnUserPoolGroup(this, 'RegisteredGroup', { userPoolId: memberUserPool.userPoolId, groupName: 'registered' });
    new cognito.CfnUserPoolGroup(this, 'MemberGroup', { userPoolId: memberUserPool.userPoolId, groupName: 'member' });

    // Admin user pool - for VettID administrators accessing admin.vettid.dev
    // MFA is REQUIRED for all admin users (TOTP only, no SMS)
    const adminUserPool = new cognito.UserPool(this, 'AdminUserPool', {
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
        tempPasswordValidity: cdk.Duration.days(1), // SECURITY: Short temp password validity
      },
      // NOTE: advancedSecurityMode requires Cognito Plus tier (currently on Essentials)
      // Account lockout would need to be implemented at application layer instead
      // Require MFA for all admin users - critical security control
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: {
        sms: false,  // SMS is less secure and susceptible to SIM swapping attacks
        otp: true,   // TOTP apps like Google Authenticator, Authy, 1Password
      },
      email: cognito.UserPoolEmail.withSES({
        fromEmail: 'no-reply@auth.vettid.dev',
        fromName: 'VettID Admin',
        sesRegion: 'us-east-1',
        sesVerifiedDomain: 'auth.vettid.dev',
      }),
      customAttributes: {
        'admin_type': new cognito.StringAttribute({ minLen: 1, maxLen: 50, mutable: true }),
        'last_login_at': new cognito.StringAttribute({ minLen: 1, maxLen: 30, mutable: true }),
      },
      lambdaTriggers: {
        preTokenGeneration: preTokenGeneration,
        postAuthentication: postAuthentication,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const adminDomainPrefix = `vettid-admin-${cdk.Names.uniqueId(this).toLowerCase().slice(0, 10)}`.replace(/[^a-z0-9-]/g, '');
    const adminPoolDomain = adminUserPool.addDomain('AdminCognitoDomain', { cognitoDomain: { domainPrefix: adminDomainPrefix } });
    new cognito.CfnUserPoolGroup(this, 'AdminGroup', { userPoolId: adminUserPool.userPoolId, groupName: 'admin' });

    // Custom UI for admin Cognito hosted UI - matches VettID branding
    // Note: Cognito only allows specific CSS classes without pseudo-selectors
    const cognitoCustomCSS = `
      .logo-customizable {
        max-width: 100%;
        max-height: 100px;
      }
      .banner-customizable {
        padding: 25px 0px 25px 0px;
        background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
      }
      .submitButton-customizable {
        font-size: 14px;
        font-weight: bold;
        margin: 20px 0px 10px 0px;
        height: 40px;
        padding: 0px;
        border-radius: 2px;
        color: #000;
        background: linear-gradient(135deg, #ffc125 0%, #e0a800 100%);
        border: none;
        box-shadow: 0 4px 14px rgba(255, 193, 37, 0.5);
      }
      .inputField-customizable {
        font-size: 14px;
        height: 40px;
        padding: 0.6rem;
        border-radius: 2px;
        border: 1px solid #333;
        background: #050505;
        color: #e0e0e0;
      }
      .background-customizable {
        background: #000;
      }
      .textDescription-customizable {
        padding-top: 10px;
        padding-bottom: 10px;
        display: block;
        font-size: 16px;
        color: #e0e0e0;
      }
      .idpDescription-customizable {
        padding-top: 10px;
        padding-bottom: 10px;
        display: block;
        font-size: 16px;
        color: #e0e0e0;
      }
      .legalText-customizable {
        color: #999;
        font-size: 11px;
      }
      .errorMessage-customizable {
        padding: 5px;
        font-size: 14px;
        width: 100%;
        background: #1a0505;
        border: 2px solid #dc2626;
        color: #fecaca;
        border-radius: 4px;
      }
      .socialButton-customizable {
        height: 40px;
        text-align: left;
        width: 100%;
        border-radius: 2px;
        background: #0a0a0a;
        border: 1px solid #333;
        color: #e0e0e0;
      }
    `;

    // Admin app client - for admin.vettid.dev (uses adminUserPool)
    const adminAppClient = new cognito.UserPoolClient(this, 'AdminWebClient', {
      userPool: adminUserPool,
      authFlows: { userPassword: false, userSrp: false, adminUserPassword: false },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls: ['https://admin.vettid.dev/index.html'],
        logoutUrls: ['https://admin.vettid.dev/index.html'],
      },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      refreshTokenValidity: cdk.Duration.days(30),
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true, emailVerified: true, givenName: true, familyName: true })
        .withCustomAttributes('admin_type'),
      writeAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ givenName: true, familyName: true })
        .withCustomAttributes('admin_type'),
    });

    // Apply VettID branding CSS to Cognito hosted UI
    // Note: Logo must be uploaded separately via AWS CLI (see deployment instructions)
    new cognito.CfnUserPoolUICustomizationAttachment(this, 'AdminUICustomization', {
      userPoolId: adminUserPool.userPoolId,
      clientId: adminAppClient.userPoolClientId,
      css: cognitoCustomCSS,
    });

    // Member app client - for vettid.dev/account (uses memberUserPool with magic link auth)
    const memberAppClient = new cognito.UserPoolClient(this, 'MemberWebClient', {
      userPool: memberUserPool,
      authFlows: {
        userPassword: false,
        userSrp: false,
        adminUserPassword: false,
        custom: true, // Enable custom auth flow for magic links
      },
      generateSecret: false,
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ===== AUTHORIZERS =====

    // Authorizers for admin and member user pools (to be used by VettIDStack's HTTP API)
    const adminAuthorizer = new authorizers.HttpUserPoolAuthorizer('AdminAuthorizer', adminUserPool, {
      userPoolClients: [adminAppClient]
    });
    const memberAuthorizer = new authorizers.HttpUserPoolAuthorizer('MemberAuthorizer', memberUserPool, {
      userPoolClients: [memberAppClient]
    });

    // ===== ENROLLMENT JWT SECRET =====
    // Create a secret for enrollment JWT signing (used by mobile enrollment flow)
    const enrollmentJwtSecret = new secretsmanager.Secret(this, 'EnrollmentJwtSecret', {
      secretName: 'vettid/enrollment/jwt-secret',
      description: 'JWT secret for mobile device enrollment authentication',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'secret',
        passwordLength: 64,
        excludePunctuation: true, // Simpler secret for JWT signing
      },
    });

    // Export the secret ARN for other stacks
    this.enrollmentJwtSecretArn = enrollmentJwtSecret.secretArn;

    // ===== ACTION TOKEN SIGNING SECRET =====
    // Create a secret for action token signing (used by /api/v1/action/request)
    const actionTokenSecret = new secretsmanager.Secret(this, 'ActionTokenSecret', {
      secretName: 'vettid/action-token/signing-key',
      description: 'HMAC signing key for action tokens',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'signing_key',
        passwordLength: 64,
        excludePunctuation: true,
      },
    });

    // Export the secret ARN for VaultStack
    this.actionTokenSecretArn = actionTokenSecret.secretArn;

    // ===== HANDLER SIGNING KEY =====
    // Ed25519 keypair for signing WASM handler packages
    // The private key is used by CI/CD to sign handlers
    // The public key is embedded in the enclave AMI for verification
    // SECURITY: Secret is created empty - keypair MUST be generated and stored manually:
    //   openssl genpkey -algorithm ed25519 -out private.pem
    //   openssl pkey -in private.pem -pubout -out public.pem
    //   aws secretsmanager put-secret-value --secret-id vettid/handler-signing-key \
    //     --secret-string "$(jq -n --arg priv "$(cat private.pem)" --arg pub "$(cat public.pem)" \
    //       '{private_key: $priv, public_key: $pub}')"
    const handlerSigningKeySecret = new secretsmanager.Secret(this, 'HandlerSigningKeySecret', {
      secretName: 'vettid/handler-signing-key',
      description: 'Ed25519 keypair for signing WASM handler packages - REQUIRES MANUAL INITIALIZATION',
      // Generate a random placeholder that forces manual initialization
      // The enclave will fail to verify signatures until real keys are stored
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          status: 'UNINITIALIZED',
          instructions: 'Run: openssl genpkey -algorithm ed25519 -out private.pem && aws secretsmanager put-secret-value --secret-id vettid/handler-signing-key --secret-string "$(jq -n --rawfile priv private.pem --rawfile pub <(openssl pkey -in private.pem -pubout) \'{private_key: $priv, public_key: $pub}\')"',
        }),
        generateStringKey: 'initialization_token',
        excludePunctuation: true,
      },
    });

    // Export the secret ARN
    this.handlerSigningKeySecretArn = handlerSigningKeySecret.secretArn;

    // ===== CONTROL COMMAND SIGNING KEY =====
    // Ed25519 keypair for signing control commands sent to enclave parent processes
    // Provides authenticity, integrity, and replay prevention for admin operations
    // SECURITY: Secret is created empty - keypair MUST be generated and stored manually:
    //   node -e "const {generateSigningKeyPair}=require('./dist/lambda/common/control-signing');console.log(JSON.stringify(generateSigningKeyPair()))" | \
    //     aws secretsmanager put-secret-value --secret-id vettid/control-signing-key --secret-string file:///dev/stdin
    // Or use OpenSSL:
    //   openssl genpkey -algorithm ed25519 -out private.pem
    //   openssl pkey -in private.pem -pubout -out public.pem
    //   aws secretsmanager put-secret-value --secret-id vettid/control-signing-key \
    //     --secret-string "$(jq -n --arg priv "$(cat private.pem)" --arg pub "$(cat public.pem)" \
    //       '{private_key: $priv, public_key: $pub}')"
    const controlSigningKeySecret = new secretsmanager.Secret(this, 'ControlSigningKeySecret', {
      secretName: 'vettid/control-signing-key',
      description: 'Ed25519 keypair for signing control commands - REQUIRES MANUAL INITIALIZATION',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          status: 'UNINITIALIZED',
          instructions: 'Generate Ed25519 keypair and store using: openssl genpkey -algorithm ed25519 -out private.pem && aws secretsmanager put-secret-value --secret-id vettid/control-signing-key --secret-string "$(jq -n --rawfile priv private.pem --rawfile pub <(openssl pkey -in private.pem -pubout) \'{private_key: $priv, public_key: $pub}\')"',
        }),
        generateStringKey: 'initialization_token',
        excludePunctuation: true,
      },
    });

    // Export the secret ARN
    this.controlSigningKeySecretArn = controlSigningKeySecret.secretArn;

    // ===== CI/CD ROLE FOR HANDLER DEPLOYMENT =====
    // This role is assumed by GitHub Actions to deploy WASM handlers
    // Permissions: S3 write (handlers), DynamoDB write (manifest), Secrets read (signing key)
    const handlerDeployRole = new iam.Role(this, 'HandlerDeployRole', {
      roleName: 'vettid-handler-deploy-role',
      description: 'IAM role for CI/CD to deploy WASM handlers',
      assumedBy: new iam.FederatedPrincipal(
        `arn:aws:iam::${this.account}:oidc-provider/token.actions.githubusercontent.com`,
        {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          },
          StringLike: {
            // Allow from mesmerverse repos (adjust as needed)
            'token.actions.githubusercontent.com:sub': 'repo:mesmerverse/*:*',
          },
        },
        'sts:AssumeRoleWithWebIdentity'
      ),
    });

    // Grant permissions to deploy handlers
    handlersBucket.grantReadWrite(handlerDeployRole);
    handlerManifest.grantReadWriteData(handlerDeployRole);
    handlerSigningKeySecret.grantRead(handlerDeployRole);

    // Output the role ARN for GitHub Actions configuration
    new cdk.CfnOutput(this, 'HandlerDeployRoleArn', {
      value: handlerDeployRole.roleArn,
      description: 'IAM role ARN for GitHub Actions handler deployment',
      exportName: 'VettID-HandlerDeployRoleArn',
    });

    // Custom enrollment authorizer Lambda (for mobile enrollment flow)
    // This Lambda validates enrollment JWTs issued by the /vault/enroll/authenticate endpoint
    this.enrollmentAuthorizerFn = new lambdaNode.NodejsFunction(this, 'EnrollmentAuthorizerFn', {
      entry: 'lambda/handlers/auth/enrollmentAuthorizer.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ENROLLMENT_JWT_SECRET_ARN: enrollmentJwtSecret.secretArn,
      },
      timeout: cdk.Duration.seconds(10),
    });

    // Grant the authorizer Lambda read access to the secret
    enrollmentJwtSecret.grantRead(this.enrollmentAuthorizerFn);

    // ===== CUSTOM RESOURCES =====

    // Seed initial membership terms from terms.txt
    const seedTermsLambda = new lambdaNode.NodejsFunction(this, 'SeedInitialTermsFn', {
      entry: 'lambda/custom-resources/seedInitialTerms.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(60),
      environment: {
        TABLE_MEMBERSHIP_TERMS: membershipTerms.tableName,
        TERMS_BUCKET: termsBucket.bucketName,
      },
      bundling: {
        nodeModules: [],
        commandHooks: {
          beforeBundling(inputDir: string, outputDir: string): string[] {
            return [];
          },
          beforeInstall(inputDir: string, outputDir: string): string[] {
            return [];
          },
          afterBundling(inputDir: string, outputDir: string): string[] {
            return [
              `cp ${inputDir}/assets/initial-terms.txt ${outputDir}/initial-terms.txt`,
            ];
          },
        },
      },
    });

    membershipTerms.grantReadWriteData(seedTermsLambda);
    termsBucket.grantReadWrite(seedTermsLambda);

    const seedTermsProvider = new cdk.custom_resources.Provider(this, 'SeedInitialTermsProvider', {
      onEventHandler: seedTermsLambda,
    });

    new cdk.CustomResource(this, 'SeedInitialTermsResource', {
      serviceToken: seedTermsProvider.serviceToken,
    });

    // Apply Cognito UI customization (logo + CSS) to both user pools
    const applyCognitoUILambda = new lambdaNode.NodejsFunction(this, 'ApplyCognitoUIFn', {
      entry: 'lambda/custom-resources/applyCognitoUI.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(60),
      environment: {
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
        ADMIN_CLIENT_ID: adminAppClient.userPoolClientId,
        MEMBER_USER_POOL_ID: memberUserPool.userPoolId,
        MEMBER_CLIENT_ID: memberAppClient.userPoolClientId,
      },
      bundling: {
        nodeModules: [],
        commandHooks: {
          beforeBundling(inputDir: string, outputDir: string): string[] {
            return [];
          },
          beforeInstall(inputDir: string, outputDir: string): string[] {
            return [];
          },
          afterBundling(inputDir: string, outputDir: string): string[] {
            return [
              `cp ${inputDir}/frontend/assets/logo.jpg ${outputDir}/logo.jpg`,
              `cp ${inputDir}/assets/cognito-ui.css ${outputDir}/cognito-ui.css`,
            ];
          },
        },
      },
    });

    // Grant permission to update Cognito UI customization
    applyCognitoUILambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:SetUICustomization'],
      resources: [adminUserPool.userPoolArn, memberUserPool.userPoolArn],
    }));

    const applyCognitoUIProvider = new cdk.custom_resources.Provider(this, 'ApplyCognitoUIProvider', {
      onEventHandler: applyCognitoUILambda,
    });

    new cdk.CustomResource(this, 'ApplyCognitoUIResource', {
      serviceToken: applyCognitoUIProvider.serviceToken,
    });

    // ===== LAMBDA LAYERS =====

    // Shared utilities layer - provides common functionality across Lambda handlers
    // Contains: AWS SDK clients, HTTP responses, auth helpers, validation, security utils
    // Build with: cd lambda/layers/shared-utils && ./build-layer.sh
    const sharedUtilsLayer = new lambda.LayerVersion(this, 'SharedUtilsLayer', {
      code: lambda.Code.fromAsset('lambda/layers/shared-utils/layer'),
      compatibleRuntimes: [lambda.Runtime.NODEJS_20_X, lambda.Runtime.NODEJS_22_X],
      description: 'VettID shared utilities - AWS clients, responses, auth, validation',
      layerVersionName: 'vettid-shared-utils',
    });
    this.sharedUtilsLayer = sharedUtilsLayer;

    // Export Cognito resources
    this.memberUserPool = memberUserPool;
    this.adminUserPool = adminUserPool;
    this.memberAppClient = memberAppClient;
    this.adminAppClient = adminAppClient;
    this.memberPoolDomain = memberPoolDomain;
    this.adminPoolDomain = adminPoolDomain;
    this.adminAuthorizer = adminAuthorizer;
    this.memberAuthorizer = memberAuthorizer;
  }
}
