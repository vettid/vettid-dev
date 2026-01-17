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

export interface BusinessGovernanceStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  adminAuthorizer: apigw.IHttpRouteAuthorizer;
}

/**
 * VettID Business Governance Stack
 *
 * Contains business logic and governance:
 * - Membership management
 * - Proposal management
 * - Subscription management
 * - Waitlist management
 * - Email management
 * - Audit log
 *
 * Split from AdminStack to stay under CloudFormation's 500 resource limit.
 */
export class BusinessGovernanceStack extends cdk.Stack {
  // Membership Management
  public readonly listMembershipRequests!: lambdaNode.NodejsFunction;
  public readonly approveMembership!: lambdaNode.NodejsFunction;
  public readonly denyMembership!: lambdaNode.NodejsFunction;
  public readonly createMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly getCurrentMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly listMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly getTermsDownloadUrl!: lambdaNode.NodejsFunction;
  public readonly regenerateTermsPdf!: lambdaNode.NodejsFunction;

  // Proposal Management
  public readonly createProposal!: lambdaNode.NodejsFunction;
  public readonly listProposals!: lambdaNode.NodejsFunction;
  public readonly suspendProposal!: lambdaNode.NodejsFunction;
  public readonly getProposalVoteCounts!: lambdaNode.NodejsFunction;
  public readonly publishVoteResults!: lambdaNode.NodejsFunction;

  // Subscription Management
  public readonly listSubscriptions!: lambdaNode.NodejsFunction;
  public readonly extendSubscription!: lambdaNode.NodejsFunction;
  public readonly reactivateSubscription!: lambdaNode.NodejsFunction;
  public readonly createSubscriptionType!: lambdaNode.NodejsFunction;
  public readonly listSubscriptionTypes!: lambdaNode.NodejsFunction;
  public readonly enableSubscriptionType!: lambdaNode.NodejsFunction;
  public readonly disableSubscriptionType!: lambdaNode.NodejsFunction;

  // Waitlist Management
  public readonly listWaitlist!: lambdaNode.NodejsFunction;
  public readonly sendWaitlistInvites!: lambdaNode.NodejsFunction;
  public readonly deleteWaitlistEntries!: lambdaNode.NodejsFunction;
  public readonly addWaitlistEntry!: lambdaNode.NodejsFunction;

  // Help Request Management
  public readonly listHelpRequests!: lambdaNode.NodejsFunction;
  public readonly updateHelpRequest!: lambdaNode.NodejsFunction;

  // Email Management
  public readonly sendBulkEmail!: lambdaNode.NodejsFunction;
  public readonly listSentEmails!: lambdaNode.NodejsFunction;

  // Audit
  public readonly getAuditLog!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: BusinessGovernanceStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const termsBucket = props.infrastructure.termsBucket;
    const memberUserPool = props.infrastructure.memberUserPool;

    // Default environment variables
    const defaultEnv = {
      TABLE_REGISTRATIONS: tables.registrations.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      TABLE_MEMBERSHIP_TERMS: tables.membershipTerms.tableName,
      TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName,
      TABLE_PROPOSALS: tables.proposals.tableName,
      TABLE_VOTES: tables.votes.tableName,
      TABLE_SUBSCRIPTION_TYPES: tables.subscriptionTypes.tableName,
      TABLE_WAITLIST: tables.waitlist.tableName,
      TABLE_SENT_EMAILS: tables.sentEmails.tableName,
      TABLE_INVITES: tables.invites.tableName,
      TABLE_HELP_REQUESTS: tables.helpRequests.tableName,
      STAGE: 'prod',
      ALLOWED_ORIGINS: 'https://admin.vettid.dev,https://vettid.dev',
    };

    // ===== MEMBERSHIP MANAGEMENT =====

    const listMembershipRequests = new lambdaNode.NodejsFunction(this, 'ListMembershipRequestsFn', {
      entry: 'lambda/handlers/admin/listMembershipRequests.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const approveMembership = new lambdaNode.NodejsFunction(this, 'ApproveMembershipFn', {
      entry: 'lambda/handlers/admin/approveMembership.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const denyMembership = new lambdaNode.NodejsFunction(this, 'DenyMembershipFn', {
      entry: 'lambda/handlers/admin/denyMembership.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const createMembershipTerms = new lambdaNode.NodejsFunction(this, 'CreateMembershipTermsFn', {
      entry: 'lambda/handlers/admin/createMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TERMS_BUCKET: termsBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
      bundling: {
        nodeModules: ['pdfkit'],
        commandHooks: {
          beforeBundling(inputDir: string, outputDir: string): string[] {
            return [];
          },
          afterBundling(inputDir: string, outputDir: string): string[] {
            return [
              `mkdir -p ${outputDir}/assets`,
              `cp ${inputDir}/lambda/assets/logo.jpg ${outputDir}/assets/logo.jpg`,
              `mkdir -p ${outputDir}/data`,
              `cp -r ${inputDir}/node_modules/pdfkit/js/data/* ${outputDir}/data/`
            ];
          },
          beforeInstall() {
            return [];
          },
        },
      },
    });

    const getCurrentMembershipTerms = new lambdaNode.NodejsFunction(this, 'GetCurrentMembershipTermsFn', {
      entry: 'lambda/handlers/admin/getCurrentMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TERMS_BUCKET: termsBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const listMembershipTerms = new lambdaNode.NodejsFunction(this, 'ListMembershipTermsFn', {
      entry: 'lambda/handlers/admin/listMembershipTerms.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const getTermsDownloadUrl = new lambdaNode.NodejsFunction(this, 'GetTermsDownloadUrlFn', {
      entry: 'lambda/handlers/admin/getTermsDownloadUrl.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TERMS_BUCKET: termsBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const regenerateTermsPdf = new lambdaNode.NodejsFunction(this, 'RegenerateTermsPdfFn', {
      entry: 'lambda/handlers/admin/regenerateTermsPdf.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TERMS_BUCKET: termsBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(60),
      bundling: {
        nodeModules: ['pdfkit'],
        commandHooks: {
          beforeBundling(inputDir: string, outputDir: string): string[] {
            return [];
          },
          afterBundling(inputDir: string, outputDir: string): string[] {
            return [
              `mkdir -p ${outputDir}/assets`,
              `cp ${inputDir}/lambda/assets/logo.jpg ${outputDir}/assets/logo.jpg`,
              `mkdir -p ${outputDir}/data`,
              `cp -r ${inputDir}/node_modules/pdfkit/js/data/* ${outputDir}/data/`
            ];
          },
          beforeInstall() {
            return [];
          },
        },
      },
    });

    // Grant permissions
    tables.membershipTerms.grantReadWriteData(listMembershipRequests);
    tables.registrations.grantReadData(listMembershipRequests);
    tables.membershipTerms.grantReadWriteData(approveMembership);
    tables.membershipTerms.grantReadWriteData(denyMembership);
    tables.membershipTerms.grantReadWriteData(createMembershipTerms);
    tables.membershipTerms.grantReadData(getCurrentMembershipTerms);
    tables.membershipTerms.grantReadData(listMembershipTerms);
    tables.membershipTerms.grantReadData(getTermsDownloadUrl);
    tables.membershipTerms.grantReadWriteData(regenerateTermsPdf);
    tables.audit.grantReadWriteData(approveMembership);
    tables.audit.grantReadWriteData(denyMembership);
    tables.audit.grantReadWriteData(createMembershipTerms);
    tables.audit.grantReadWriteData(regenerateTermsPdf);

    // S3 permissions for terms bucket
    termsBucket.grantReadWrite(createMembershipTerms);
    termsBucket.grantRead(getCurrentMembershipTerms);
    termsBucket.grantRead(getTermsDownloadUrl);
    termsBucket.grantReadWrite(regenerateTermsPdf);

    this.listMembershipRequests = listMembershipRequests;
    this.approveMembership = approveMembership;
    this.denyMembership = denyMembership;
    this.createMembershipTerms = createMembershipTerms;
    this.getCurrentMembershipTerms = getCurrentMembershipTerms;
    this.listMembershipTerms = listMembershipTerms;
    this.getTermsDownloadUrl = getTermsDownloadUrl;
    this.regenerateTermsPdf = regenerateTermsPdf;

    // ===== PROPOSAL MANAGEMENT =====

    const votingKey = props.infrastructure.votingKey;

    const createProposal = new lambdaNode.NodejsFunction(this, 'CreateProposalFn', {
      entry: 'lambda/handlers/admin/createProposal.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        VOTING_KEY_ID: votingKey.keyId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const listProposals = new lambdaNode.NodejsFunction(this, 'ListProposalsFn', {
      entry: 'lambda/handlers/admin/listProposals.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const suspendProposal = new lambdaNode.NodejsFunction(this, 'SuspendProposalFn', {
      entry: 'lambda/handlers/admin/suspendProposal.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const getProposalVoteCounts = new lambdaNode.NodejsFunction(this, 'GetProposalVoteCountsFn', {
      entry: 'lambda/handlers/admin/getProposalVoteCounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Publish vote results to S3 with Merkle tree
    const publishedVotesBucket = props.infrastructure.publishedVotesBucket;
    const publishVoteResults = new lambdaNode.NodejsFunction(this, 'PublishVoteResultsFn', {
      entry: 'lambda/handlers/admin/publishVoteResults.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        PUBLISHED_VOTES_BUCKET: publishedVotesBucket.bucketName,
      },
      timeout: cdk.Duration.seconds(60), // Allow time for processing large vote lists
    });

    // Grant permissions
    tables.proposals.grantReadWriteData(createProposal);
    tables.proposals.grantReadData(listProposals);
    tables.proposals.grantReadWriteData(suspendProposal);
    tables.proposals.grantReadData(getProposalVoteCounts);
    tables.votes.grantReadData(getProposalVoteCounts);
    tables.audit.grantReadWriteData(createProposal);
    tables.audit.grantReadWriteData(suspendProposal);

    // Grant KMS sign permission to createProposal for proposal signing
    votingKey.grant(createProposal, 'kms:Sign');

    // publishVoteResults needs to read proposals/votes and write to S3
    tables.proposals.grantReadWriteData(publishVoteResults);
    tables.votes.grantReadData(publishVoteResults);
    tables.audit.grantReadWriteData(publishVoteResults);
    publishedVotesBucket.grantReadWrite(publishVoteResults);

    this.createProposal = createProposal;
    this.listProposals = listProposals;
    this.suspendProposal = suspendProposal;
    this.getProposalVoteCounts = getProposalVoteCounts;
    this.publishVoteResults = publishVoteResults;

    // ===== SUBSCRIPTION MANAGEMENT =====

    const listSubscriptions = new lambdaNode.NodejsFunction(this, 'ListSubscriptionsFn', {
      entry: 'lambda/handlers/admin/listSubscriptions.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const extendSubscription = new lambdaNode.NodejsFunction(this, 'ExtendSubscriptionFn', {
      entry: 'lambda/handlers/admin/extendSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const reactivateSubscription = new lambdaNode.NodejsFunction(this, 'ReactivateSubscriptionFn', {
      entry: 'lambda/handlers/admin/reactivateSubscription.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const createSubscriptionType = new lambdaNode.NodejsFunction(this, 'CreateSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/createSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const listSubscriptionTypes = new lambdaNode.NodejsFunction(this, 'ListSubscriptionTypesFn', {
      entry: 'lambda/handlers/admin/listSubscriptionTypes.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const enableSubscriptionType = new lambdaNode.NodejsFunction(this, 'EnableSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/enableSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const disableSubscriptionType = new lambdaNode.NodejsFunction(this, 'DisableSubscriptionTypeFn', {
      entry: 'lambda/handlers/admin/disableSubscriptionType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions
    tables.subscriptions.grantReadWriteData(listSubscriptions);
    tables.registrations.grantReadData(listSubscriptions);
    tables.audit.grantReadData(listSubscriptions);
    tables.subscriptions.grantReadWriteData(extendSubscription);
    tables.subscriptions.grantReadWriteData(reactivateSubscription);
    tables.subscriptionTypes.grantReadWriteData(createSubscriptionType);
    tables.subscriptionTypes.grantReadData(listSubscriptionTypes);
    tables.subscriptionTypes.grantReadWriteData(enableSubscriptionType);
    tables.subscriptionTypes.grantReadWriteData(disableSubscriptionType);
    tables.audit.grantReadWriteData(extendSubscription);
    tables.audit.grantReadWriteData(reactivateSubscription);
    tables.audit.grantReadWriteData(createSubscriptionType);
    tables.audit.grantReadWriteData(enableSubscriptionType);
    tables.audit.grantReadWriteData(disableSubscriptionType);

    this.listSubscriptions = listSubscriptions;
    this.extendSubscription = extendSubscription;
    this.reactivateSubscription = reactivateSubscription;
    this.createSubscriptionType = createSubscriptionType;
    this.listSubscriptionTypes = listSubscriptionTypes;
    this.enableSubscriptionType = enableSubscriptionType;
    this.disableSubscriptionType = disableSubscriptionType;

    // ===== WAITLIST MANAGEMENT =====

    const listWaitlist = new lambdaNode.NodejsFunction(this, 'ListWaitlistFn', {
      entry: 'lambda/handlers/admin/listWaitlist.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const sendWaitlistInvites = new lambdaNode.NodejsFunction(this, 'SendWaitlistInvitesFn', {
      entry: 'lambda/handlers/admin/sendWaitlistInvites.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM_EMAIL: 'no-reply@auth.vettid.dev',
        USER_POOL_ID: memberUserPool.userPoolId,
        REGISTERED_GROUP: 'registered',
      },
      timeout: cdk.Duration.seconds(60),
    });

    const deleteWaitlistEntries = new lambdaNode.NodejsFunction(this, 'DeleteWaitlistEntriesFn', {
      entry: 'lambda/handlers/admin/deleteWaitlistEntries.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const addWaitlistEntry = new lambdaNode.NodejsFunction(this, 'AddWaitlistEntryFn', {
      entry: 'lambda/handlers/admin/addWaitlistEntry.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions
    tables.waitlist.grantReadData(listWaitlist);
    tables.waitlist.grantReadWriteData(sendWaitlistInvites);
    tables.registrations.grantReadWriteData(sendWaitlistInvites);
    tables.invites.grantReadWriteData(sendWaitlistInvites);
    tables.waitlist.grantReadWriteData(deleteWaitlistEntries);
    tables.waitlist.grantReadWriteData(addWaitlistEntry);
    tables.audit.grantReadWriteData(sendWaitlistInvites);
    tables.audit.grantReadWriteData(deleteWaitlistEntries);
    tables.audit.grantReadWriteData(addWaitlistEntry);

    // SES and Cognito permissions for waitlist invites
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendTemplatedEmail'],
      resources: ['*'],
    }));
    // SES verification permissions (for sandbox mode)
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:GetIdentityVerificationAttributes', 'ses:VerifyEmailIdentity'],
      resources: ['*'], // These SES actions don't support resource-level permissions
    }));
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminCreateUser', 'cognito-idp:AdminAddUserToGroup', 'cognito-idp:AdminGetUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    this.listWaitlist = listWaitlist;
    this.sendWaitlistInvites = sendWaitlistInvites;
    this.deleteWaitlistEntries = deleteWaitlistEntries;
    this.addWaitlistEntry = addWaitlistEntry;

    // ===== HELP REQUEST MANAGEMENT =====

    const listHelpRequests = new lambdaNode.NodejsFunction(this, 'ListHelpRequestsFn', {
      entry: 'lambda/handlers/admin/listHelpRequests.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
      description: 'List volunteer help requests with filtering and pagination',
    });

    const updateHelpRequest = new lambdaNode.NodejsFunction(this, 'UpdateHelpRequestFn', {
      entry: 'lambda/handlers/admin/updateHelpRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
      description: 'Update help request status and admin notes',
    });

    // Grant permissions
    tables.helpRequests.grantReadData(listHelpRequests);
    tables.helpRequests.grantReadWriteData(updateHelpRequest);
    tables.audit.grantReadWriteData(updateHelpRequest);

    this.listHelpRequests = listHelpRequests;
    this.updateHelpRequest = updateHelpRequest;

    // ===== EMAIL MANAGEMENT =====

    const sendBulkEmail = new lambdaNode.NodejsFunction(this, 'SendBulkEmailFn', {
      entry: 'lambda/handlers/admin/sendBulkEmail.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(60),
    });

    const listSentEmails = new lambdaNode.NodejsFunction(this, 'ListSentEmailsFn', {
      entry: 'lambda/handlers/admin/listSentEmails.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions
    tables.sentEmails.grantReadWriteData(sendBulkEmail);
    tables.waitlist.grantReadData(sendBulkEmail);
    tables.registrations.grantReadData(sendBulkEmail);
    tables.subscriptions.grantReadData(sendBulkEmail);
    tables.sentEmails.grantReadData(listSentEmails);
    tables.audit.grantReadWriteData(sendBulkEmail);

    // SES permissions
    sendBulkEmail.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendBulkEmail', 'ses:SendTemplatedEmail'],
      resources: ['*'],
    }));

    this.sendBulkEmail = sendBulkEmail;
    this.listSentEmails = listSentEmails;

    // ===== AUDIT LOG =====

    const getAuditLog = new lambdaNode.NodejsFunction(this, 'GetAuditLogFn', {
      entry: 'lambda/handlers/admin/getAuditLog.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    tables.audit.grantReadData(getAuditLog);

    this.getAuditLog = getAuditLog;

    // Add API routes
    this.addRoutes(props.httpApi, props.adminAuthorizer);
  }

  /**
   * Helper to create a route in this stack's scope
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
   * Add routes to the HTTP API
   */
  private addRoutes(httpApi: apigw.HttpApi, adminAuthorizer: apigw.IHttpRouteAuthorizer): void {
    // Membership Management
    this.route('ListMembershipRequests', httpApi, '/admin/membership-requests', apigw.HttpMethod.GET, this.listMembershipRequests, adminAuthorizer);
    this.route('ApproveMembership', httpApi, '/admin/membership-requests/{id}/approve', apigw.HttpMethod.POST, this.approveMembership, adminAuthorizer);
    this.route('DenyMembership', httpApi, '/admin/membership-requests/{id}/deny', apigw.HttpMethod.POST, this.denyMembership, adminAuthorizer);
    this.route('CreateMembershipTerms', httpApi, '/admin/membership-terms', apigw.HttpMethod.POST, this.createMembershipTerms, adminAuthorizer);
    this.route('GetCurrentMembershipTerms', httpApi, '/admin/membership-terms/current', apigw.HttpMethod.GET, this.getCurrentMembershipTerms, adminAuthorizer);
    this.route('ListMembershipTerms', httpApi, '/admin/membership-terms', apigw.HttpMethod.GET, this.listMembershipTerms, adminAuthorizer);
    this.route('GetTermsDownloadUrl', httpApi, '/admin/membership-terms/{version_id}/download', apigw.HttpMethod.GET, this.getTermsDownloadUrl, adminAuthorizer);
    this.route('RegenerateTermsPdf', httpApi, '/admin/membership-terms/{version_id}/regenerate-pdf', apigw.HttpMethod.POST, this.regenerateTermsPdf, adminAuthorizer);

    // Proposal Management
    this.route('CreateProposal', httpApi, '/admin/proposals', apigw.HttpMethod.POST, this.createProposal, adminAuthorizer);
    this.route('ListProposals', httpApi, '/admin/proposals', apigw.HttpMethod.GET, this.listProposals, adminAuthorizer);
    this.route('SuspendProposal', httpApi, '/admin/proposals/{id}/suspend', apigw.HttpMethod.POST, this.suspendProposal, adminAuthorizer);
    this.route('GetProposalVoteCounts', httpApi, '/admin/proposals/{proposal_id}/vote-counts', apigw.HttpMethod.GET, this.getProposalVoteCounts, adminAuthorizer);
    this.route('PublishVoteResults', httpApi, '/admin/proposals/{proposal_id}/publish-results', apigw.HttpMethod.POST, this.publishVoteResults, adminAuthorizer);

    // Subscription Management
    this.route('ListSubscriptions', httpApi, '/admin/subscriptions', apigw.HttpMethod.GET, this.listSubscriptions, adminAuthorizer);
    this.route('ExtendSubscription', httpApi, '/admin/subscriptions/{id}/extend', apigw.HttpMethod.POST, this.extendSubscription, adminAuthorizer);
    this.route('ReactivateSubscription', httpApi, '/admin/subscriptions/{id}/reactivate', apigw.HttpMethod.POST, this.reactivateSubscription, adminAuthorizer);
    this.route('CreateSubscriptionType', httpApi, '/admin/subscription-types', apigw.HttpMethod.POST, this.createSubscriptionType, adminAuthorizer);
    this.route('ListSubscriptionTypes', httpApi, '/admin/subscription-types', apigw.HttpMethod.GET, this.listSubscriptionTypes, adminAuthorizer);
    this.route('EnableSubscriptionType', httpApi, '/admin/subscription-types/{id}/enable', apigw.HttpMethod.POST, this.enableSubscriptionType, adminAuthorizer);
    this.route('DisableSubscriptionType', httpApi, '/admin/subscription-types/{id}/disable', apigw.HttpMethod.POST, this.disableSubscriptionType, adminAuthorizer);

    // Waitlist Management
    this.route('ListWaitlist', httpApi, '/admin/waitlist', apigw.HttpMethod.GET, this.listWaitlist, adminAuthorizer);
    this.route('AddWaitlistEntry', httpApi, '/admin/waitlist', apigw.HttpMethod.POST, this.addWaitlistEntry, adminAuthorizer);
    this.route('SendWaitlistInvites', httpApi, '/admin/waitlist/send-invites', apigw.HttpMethod.POST, this.sendWaitlistInvites, adminAuthorizer);
    this.route('DeleteWaitlistEntries', httpApi, '/admin/waitlist', apigw.HttpMethod.DELETE, this.deleteWaitlistEntries, adminAuthorizer);

    // Help Request Management
    this.route('ListHelpRequests', httpApi, '/admin/help-requests', apigw.HttpMethod.GET, this.listHelpRequests, adminAuthorizer);
    this.route('UpdateHelpRequest', httpApi, '/admin/help-requests/{request_id}', apigw.HttpMethod.PATCH, this.updateHelpRequest, adminAuthorizer);

    // Email Management
    this.route('SendBulkEmail', httpApi, '/admin/send-bulk-email', apigw.HttpMethod.POST, this.sendBulkEmail, adminAuthorizer);
    this.route('ListSentEmails', httpApi, '/admin/sent-emails', apigw.HttpMethod.GET, this.listSentEmails, adminAuthorizer);

    // Audit Log
    this.route('GetAuditLog', httpApi, '/admin/audit', apigw.HttpMethod.GET, this.getAuditLog, adminAuthorizer);
  }
}
