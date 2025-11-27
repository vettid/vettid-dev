import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_dynamodb as dynamodb,
} from 'aws-cdk-lib';

/**
 * VettID Infrastructure Stack
 *
 * Contains foundational data storage resources that other stacks depend on:
 * - All DynamoDB tables (16 tables)
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
    credentials: dynamodb.Table;
    credentialKeys: dynamodb.Table;
    transactionKeys: dynamodb.Table;
    ledgerAuthTokens: dynamodb.Table;
    actionTokens: dynamodb.Table;
    enrollmentSessions: dynamodb.Table;
  };

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ===== DYNAMODB TABLES =====

    // Invites table
    const invites = new dynamodb.Table(this, 'Invites', {
      partitionKey: { name: 'code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
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
      pointInTimeRecovery: true,
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
      pointInTimeRecovery: true,
    });

    membershipTerms.addGlobalSecondaryIndex({
      indexName: 'current-index',
      partitionKey: { name: 'is_current', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Subscriptions table
    const subscriptions = new dynamodb.Table(this, 'Subscriptions', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
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
      pointInTimeRecovery: true,
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

    // ===== VAULT SERVICES TABLES =====

    // Credentials table
    const credentials = new dynamodb.Table(this, 'Credentials', {
      partitionKey: { name: 'user_guid', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'credential_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
    });

    // Credential keys table
    const credentialKeys = new dynamodb.Table(this, 'CredentialKeys', {
      partitionKey: { name: 'credential_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
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
      credentials,
      credentialKeys,
      transactionKeys,
      ledgerAuthTokens,
      actionTokens,
      enrollmentSessions,
    };
  }
}
