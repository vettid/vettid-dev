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
    credentials: dynamodb.Table;
    credentialKeys: dynamodb.Table;
    transactionKeys: dynamodb.Table;
    ledgerAuthTokens: dynamodb.Table;
    actionTokens: dynamodb.Table;
    enrollmentSessions: dynamodb.Table;
    notificationPreferences: dynamodb.Table;
    pendingAdmins: dynamodb.Table;
    natsAccounts: dynamodb.Table;
    natsTokens: dynamodb.Table;
    vaultInstances: dynamodb.Table;
    handlers: dynamodb.Table;
    handlerInstallations: dynamodb.Table;
    // Phase 7: Connections & Messaging
    connections: dynamodb.Table;
    connectionInvitations: dynamodb.Table;
    messages: dynamodb.Table;
    profiles: dynamodb.Table;
    // Phase 8: Backup System
    backups: dynamodb.Table;
    credentialBackups: dynamodb.Table;
    backupSettings: dynamodb.Table;
  };

  // S3 Buckets
  public readonly termsBucket!: s3.Bucket;
  public readonly handlersBucket!: s3.Bucket;
  public readonly backupBucket!: s3.Bucket;

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

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ===== DYNAMODB TABLES =====

    // Invites table
    const invites = new dynamodb.Table(this, 'Invites', {
      partitionKey: { name: 'code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
    });

    // Registrations table with GSI
    const registrations = new dynamodb.Table(this, 'Registrations', {
      partitionKey: { name: 'registration_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
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

    // Audit log table
    const audit = new dynamodb.Table(this, 'Audit', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    audit.addGlobalSecondaryIndex({
      indexName: 'email-timestamp-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAtTimestamp', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Waitlist table
    const waitlist = new dynamodb.Table(this, 'Waitlist', {
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
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
    });

    // Membership terms table
    const membershipTerms = new dynamodb.Table(this, 'MembershipTerms', {
      partitionKey: { name: 'version_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
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
      pointInTimeRecovery: true
    });

    // Proposals table
    const proposals = new dynamodb.Table(this, 'Proposals', {
      partitionKey: { name: 'proposal_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
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
      pointInTimeRecovery: true
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
    });

    // Sent emails table (for bulk email tracking)
    const sentEmails = new dynamodb.Table(this, 'SentEmails', {
      partitionKey: { name: 'email_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
    });

    sentEmails.addGlobalSecondaryIndex({
      indexName: 'sent-at-index',
      partitionKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== VAULT SERVICES TABLES =====

    // Credentials table
    const credentials = new dynamodb.Table(this, 'Credentials', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'credential_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
    });

    // Credential keys table
    const credentialKeys = new dynamodb.Table(this, 'CredentialKeys', {
      partitionKey: { name: 'credential_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true
    });

    credentialKeys.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Transaction keys table
    const transactionKeys = new dynamodb.Table(this, 'TransactionKeys', {
      partitionKey: { name: 'transaction_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
    });

    transactionKeys.addGlobalSecondaryIndex({
      indexName: 'user-index',
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Ledger auth tokens table
    const ledgerAuthTokens = new dynamodb.Table(this, 'LedgerAuthTokens', {
      partitionKey: { name: 'token', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
    });

    // Action tokens table
    const actionTokens = new dynamodb.Table(this, 'ActionTokens', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
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

    // Notification Preferences table
    const notificationPreferences = new dynamodb.Table(this, 'NotificationPreferences', {
      partitionKey: { name: 'notification_type', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'admin_email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Pending Admins table - stores admin invitations awaiting SES verification
    const pendingAdmins = new dynamodb.Table(this, 'PendingAdmins', {
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expires_at',
    });

    // ===== NATS INFRASTRUCTURE TABLES =====

    // NATS Accounts table - stores member NATS namespace allocations
    const natsAccounts = new dynamodb.Table(this, 'NatsAccounts', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // NATS Tokens table - stores issued NATS JWT tokens
    const natsTokens = new dynamodb.Table(this, 'NatsTokens', {
      partitionKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
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
    });

    handlerInstallations.addGlobalSecondaryIndex({
      indexName: 'handler-index',
      partitionKey: { name: 'handler_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'installed_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===== PHASE 7: CONNECTIONS & MESSAGING TABLES =====

    // Connections table - stores connection relationships between users
    const connections = new dynamodb.Table(this, 'Connections', {
      partitionKey: { name: 'owner_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'peer_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    connections.addGlobalSecondaryIndex({
      indexName: 'connection-id-index',
      partitionKey: { name: 'connection_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    connections.addGlobalSecondaryIndex({
      indexName: 'peer-guid-index',
      partitionKey: { name: 'peer_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Connection Invitations table - stores pending connection invitations
    const connectionInvitations = new dynamodb.Table(this, 'ConnectionInvitations', {
      partitionKey: { name: 'invitation_code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      timeToLiveAttribute: 'ttl',
    });

    connectionInvitations.addGlobalSecondaryIndex({
      indexName: 'creator-index',
      partitionKey: { name: 'creator_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    connectionInvitations.addGlobalSecondaryIndex({
      indexName: 'invitation-id-index',
      partitionKey: { name: 'invitation_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Messages table - stores encrypted messages between connected users
    const messages = new dynamodb.Table(this, 'Messages', {
      partitionKey: { name: 'message_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    messages.addGlobalSecondaryIndex({
      indexName: 'connection-sent-index',
      partitionKey: { name: 'connection_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    messages.addGlobalSecondaryIndex({
      indexName: 'recipient-index',
      partitionKey: { name: 'recipient_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sent_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Profiles table - stores user profile information
    const profiles = new dynamodb.Table(this, 'Profiles', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // ===== PHASE 8: BACKUP SYSTEM TABLES =====

    // Backups table - stores vault backup metadata
    const backups = new dynamodb.Table(this, 'Backups', {
      partitionKey: { name: 'backup_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
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
    });

    // Backup Settings table - stores per-member backup preferences
    const backupSettings = new dynamodb.Table(this, 'BackupSettings', {
      partitionKey: { name: 'member_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
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
      credentials,
      credentialKeys,
      transactionKeys,
      ledgerAuthTokens,
      actionTokens,
      enrollmentSessions,
      notificationPreferences,
      pendingAdmins,
      natsAccounts,
      natsTokens,
      vaultInstances,
      handlers,
      handlerInstallations,
      // Phase 7: Connections & Messaging
      connections,
      connectionInvitations,
      messages,
      profiles,
      // Phase 8: Backup System
      backups,
      credentialBackups,
      backupSettings,
    };

    this.termsBucket = termsBucket;
    this.handlersBucket = handlersBucket;
    this.backupBucket = backupBucket;

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
        SES_FROM: 'no-reply@auth.vettid.dev',
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
    // Note: Using wildcard for identities to support SES sandbox mode (requires verified recipients)
    // In production mode, only FROM address needs to be verified
    createAuthChallenge.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendRawEmail'],
      resources: [`arn:aws:ses:${this.region}:${this.account}:identity/*`],
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
      },
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
      },
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
      },
      lambdaTriggers: {
        preTokenGeneration: preTokenGeneration,
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

    // ===== CUSTOM RESOURCES =====

    // Seed initial membership terms from terms.txt
    const seedTermsLambda = new lambdaNode.NodejsFunction(this, 'SeedInitialTermsFn', {
      entry: 'lambda/custom-resources/seedInitialTerms.ts',
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_20_X,
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
      runtime: lambda.Runtime.NODEJS_20_X,
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
