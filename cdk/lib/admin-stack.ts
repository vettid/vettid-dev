import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_events as events,
  aws_events_targets as targets_events,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface AdminStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  adminAuthorizer: apigw.IHttpRouteAuthorizer;
}

/**
 * VettID Admin Stack
 *
 * Contains admin functionality, proposal management, and scheduled tasks:
 * - Admin Lambda functions
 * - EventBridge scheduled tasks
 * - API routes added to Core stack's API Gateway
 *
 * Depends on: Infrastructure Stack (for tables), Core Stack (for API Gateway)
 */
export class AdminStack extends cdk.Stack {
  // Public Lambda functions to be used by VettIDStack for API routes
  public readonly listRegistrations!: lambdaNode.NodejsFunction;
  public readonly approveRegistration!: lambdaNode.NodejsFunction;
  public readonly rejectRegistration!: lambdaNode.NodejsFunction;
  public readonly createInvite!: lambdaNode.NodejsFunction;
  public readonly listInvites!: lambdaNode.NodejsFunction;
  public readonly expireInvite!: lambdaNode.NodejsFunction;
  public readonly deleteInvite!: lambdaNode.NodejsFunction;
  public readonly disableUser!: lambdaNode.NodejsFunction;
  public readonly enableUser!: lambdaNode.NodejsFunction;
  public readonly deleteUser!: lambdaNode.NodejsFunction;
  public readonly permanentlyDeleteUser!: lambdaNode.NodejsFunction;
  public readonly listAdmins!: lambdaNode.NodejsFunction;
  public readonly addAdmin!: lambdaNode.NodejsFunction;
  public readonly removeAdmin!: lambdaNode.NodejsFunction;
  public readonly disableAdmin!: lambdaNode.NodejsFunction;
  public readonly enableAdmin!: lambdaNode.NodejsFunction;
  public readonly updateAdminType!: lambdaNode.NodejsFunction;
  public readonly resetAdminPassword!: lambdaNode.NodejsFunction;
  public readonly changePassword!: lambdaNode.NodejsFunction;
  public readonly setupMfa!: lambdaNode.NodejsFunction;
  public readonly inviteAdmin!: lambdaNode.NodejsFunction;
  public readonly listPendingAdmins!: lambdaNode.NodejsFunction;
  public readonly activateAdmin!: lambdaNode.NodejsFunction;
  public readonly cancelPendingAdmin!: lambdaNode.NodejsFunction;
  public readonly resendAdminVerification!: lambdaNode.NodejsFunction;
  public readonly listMembershipRequests!: lambdaNode.NodejsFunction;
  public readonly approveMembership!: lambdaNode.NodejsFunction;
  public readonly denyMembership!: lambdaNode.NodejsFunction;
  public readonly createMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly getCurrentMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly listMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly getTermsDownloadUrl!: lambdaNode.NodejsFunction;
  public readonly createProposal!: lambdaNode.NodejsFunction;
  public readonly listProposals!: lambdaNode.NodejsFunction;
  public readonly suspendProposal!: lambdaNode.NodejsFunction;
  public readonly getProposalVoteCounts!: lambdaNode.NodejsFunction;
  public readonly listSubscriptions!: lambdaNode.NodejsFunction;
  public readonly extendSubscription!: lambdaNode.NodejsFunction;
  public readonly reactivateSubscription!: lambdaNode.NodejsFunction;
  public readonly createSubscriptionType!: lambdaNode.NodejsFunction;
  public readonly listSubscriptionTypes!: lambdaNode.NodejsFunction;
  public readonly enableSubscriptionType!: lambdaNode.NodejsFunction;
  public readonly disableSubscriptionType!: lambdaNode.NodejsFunction;
  public readonly listWaitlist!: lambdaNode.NodejsFunction;
  public readonly sendWaitlistInvites!: lambdaNode.NodejsFunction;
  public readonly deleteWaitlistEntries!: lambdaNode.NodejsFunction;
  public readonly getSystemHealth!: lambdaNode.NodejsFunction;
  public readonly getSystemLogs!: lambdaNode.NodejsFunction;
  public readonly sendBulkEmail!: lambdaNode.NodejsFunction;
  public readonly listSentEmails!: lambdaNode.NodejsFunction;
  public readonly getNotifications!: lambdaNode.NodejsFunction;
  public readonly addNotification!: lambdaNode.NodejsFunction;
  public readonly removeNotification!: lambdaNode.NodejsFunction;
  public readonly getAuditLog!: lambdaNode.NodejsFunction;
  public readonly generateNatsControlToken!: lambdaNode.NodejsFunction;

  // Handler registry admin functions
  public readonly uploadHandler!: lambdaNode.NodejsFunction;
  public readonly signHandler!: lambdaNode.NodejsFunction;
  public readonly revokeHandler!: lambdaNode.NodejsFunction;
  public readonly deleteHandler!: lambdaNode.NodejsFunction;
  public readonly listRegistryHandlers!: lambdaNode.NodejsFunction;

  // Supported services admin functions
  public readonly createService!: lambdaNode.NodejsFunction;
  public readonly updateService!: lambdaNode.NodejsFunction;
  public readonly deleteService!: lambdaNode.NodejsFunction;
  public readonly listServices!: lambdaNode.NodejsFunction;
  public readonly toggleServiceStatus!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: AdminStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const adminUserPool = props.infrastructure.adminUserPool;
    const memberUserPool = props.infrastructure.memberUserPool;
    const termsBucket = props.infrastructure.termsBucket;

    // Default environment variables for all admin functions
    const defaultEnv = {
      TABLE_INVITES: tables.invites.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      TABLE_MEMBERSHIP_TERMS: tables.membershipTerms.tableName,
      TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName,
      TABLE_PROPOSALS: tables.proposals.tableName,
      TABLE_VOTES: tables.votes.tableName,
      TABLE_SUBSCRIPTION_TYPES: tables.subscriptionTypes.tableName,
      TABLE_WAITLIST: tables.waitlist.tableName,
      TABLE_SENT_EMAILS: tables.sentEmails.tableName,
      TABLE_NOTIFICATION_PREFERENCES: tables.notificationPreferences.tableName,
      PENDING_ADMINS_TABLE: tables.pendingAdmins.tableName,
      ALLOWED_ORIGINS: 'https://admin.vettid.dev,http://localhost:3000,http://localhost:5173',
    };

    // ===== REGISTRATION MANAGEMENT =====

    const listRegistrations = new lambdaNode.NodejsFunction(this, 'ListRegistrationsFn', {
      entry: 'lambda/handlers/admin/listRegistrations.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const approveRegistration = new lambdaNode.NodejsFunction(this, 'ApproveRegistrationFn', {
      entry: 'lambda/handlers/admin/approveRegistration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
        MEMBER_GROUP: 'member',
      },
      timeout: cdk.Duration.seconds(30),
    });

    const rejectRegistration = new lambdaNode.NodejsFunction(this, 'RejectRegistrationFn', {
      entry: 'lambda/handlers/admin/rejectRegistration.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== INVITE MANAGEMENT =====

    const createInvite = new lambdaNode.NodejsFunction(this, 'CreateInviteFn', {
      entry: 'lambda/handlers/admin/createInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const listInvites = new lambdaNode.NodejsFunction(this, 'ListInvitesFn', {
      entry: 'lambda/handlers/admin/listInvites.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const expireInvite = new lambdaNode.NodejsFunction(this, 'ExpireInviteFn', {
      entry: 'lambda/handlers/admin/expireInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const deleteInvite = new lambdaNode.NodejsFunction(this, 'DeleteInviteFn', {
      entry: 'lambda/handlers/admin/deleteInvite.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== USER MANAGEMENT =====

    const disableUser = new lambdaNode.NodejsFunction(this, 'DisableUserFn', {
      entry: 'lambda/handlers/admin/disableUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const enableUser = new lambdaNode.NodejsFunction(this, 'EnableUserFn', {
      entry: 'lambda/handlers/admin/enableUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const deleteUser = new lambdaNode.NodejsFunction(this, 'DeleteUserFn', {
      entry: 'lambda/handlers/admin/deleteUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
        TABLE_WAITLIST: tables.waitlist.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const permanentlyDeleteUser = new lambdaNode.NodejsFunction(this, 'PermanentlyDeleteUserFn', {
      entry: 'lambda/handlers/admin/permanentlyDeleteUser.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== ADMIN MANAGEMENT =====

    const listAdmins = new lambdaNode.NodejsFunction(this, 'ListAdminsFn', {
      entry: 'lambda/handlers/admin/listAdmins.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const addAdmin = new lambdaNode.NodejsFunction(this, 'AddAdminFn', {
      entry: 'lambda/handlers/admin/addAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const removeAdmin = new lambdaNode.NodejsFunction(this, 'RemoveAdminFn', {
      entry: 'lambda/handlers/admin/removeAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const disableAdmin = new lambdaNode.NodejsFunction(this, 'DisableAdminFn', {
      entry: 'lambda/handlers/admin/disableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const enableAdmin = new lambdaNode.NodejsFunction(this, 'EnableAdminFn', {
      entry: 'lambda/handlers/admin/enableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const updateAdminType = new lambdaNode.NodejsFunction(this, 'UpdateAdminTypeFn', {
      entry: 'lambda/handlers/admin/updateAdminType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const resetAdminPassword = new lambdaNode.NodejsFunction(this, 'ResetAdminPasswordFn', {
      entry: 'lambda/handlers/admin/resetAdminPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const changePassword = new lambdaNode.NodejsFunction(this, 'ChangePasswordFn', {
      entry: 'lambda/handlers/admin/changePassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const setupMfa = new lambdaNode.NodejsFunction(this, 'SetupMfaFn', {
      entry: 'lambda/handlers/admin/setupMfa.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== PENDING ADMIN INVITATION (2-STEP FLOW) =====

    const inviteAdmin = new lambdaNode.NodejsFunction(this, 'InviteAdminFn', {
      entry: 'lambda/handlers/admin/inviteAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const listPendingAdmins = new lambdaNode.NodejsFunction(this, 'ListPendingAdminsFn', {
      entry: 'lambda/handlers/admin/listPendingAdmins.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const activateAdmin = new lambdaNode.NodejsFunction(this, 'ActivateAdminFn', {
      entry: 'lambda/handlers/admin/activateAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const cancelPendingAdmin = new lambdaNode.NodejsFunction(this, 'CancelPendingAdminFn', {
      entry: 'lambda/handlers/admin/cancelPendingAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const resendAdminVerification = new lambdaNode.NodejsFunction(this, 'ResendAdminVerificationFn', {
      entry: 'lambda/handlers/admin/resendAdminVerification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== NOTIFICATION MANAGEMENT =====

    const getNotifications = new lambdaNode.NodejsFunction(this, 'GetNotificationsFn', {
      entry: 'lambda/handlers/admin/getNotifications.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const addNotification = new lambdaNode.NodejsFunction(this, 'AddNotificationFn', {
      entry: 'lambda/handlers/admin/addNotification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const removeNotification = new lambdaNode.NodejsFunction(this, 'RemoveNotificationFn', {
      entry: 'lambda/handlers/admin/removeNotification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== AUDIT LOG =====

    const getAuditLog = new lambdaNode.NodejsFunction(this, 'GetAuditLogFn', {
      entry: 'lambda/handlers/admin/getAuditLog.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

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
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant access to NATS operator secret
    natsOperatorSecret.grantRead(generateNatsControlToken);

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
              // Copy VettID logo
              `mkdir -p ${outputDir}/assets`,
              `cp ${inputDir}/lambda/assets/logo.jpg ${outputDir}/assets/logo.jpg`,
              // Copy PDFKit data files (font metrics)
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
      environment: {
        ...defaultEnv,
      },
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

    // ===== PROPOSAL MANAGEMENT =====

    const createProposal = new lambdaNode.NodejsFunction(this, 'CreateProposalFn', {
      entry: 'lambda/handlers/admin/createProposal.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
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
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(60),
    });

    const deleteWaitlistEntries = new lambdaNode.NodejsFunction(this, 'DeleteWaitlistEntriesFn', {
      entry: 'lambda/handlers/admin/deleteWaitlistEntries.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== SYSTEM MONITORING =====

    const getSystemHealth = new lambdaNode.NodejsFunction(this, 'GetSystemHealthFn', {
      entry: 'lambda/handlers/admin/getSystemHealth.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        TABLE_MAGIC_LINK_TOKENS: tables.magicLinkTokens.tableName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    const getSystemLogs = new lambdaNode.NodejsFunction(this, 'GetSystemLogsFn', {
      entry: 'lambda/handlers/admin/getSystemLogs.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

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

    // ===== SCHEDULED TASKS =====

    const cleanupExpiredAccounts = new lambdaNode.NodejsFunction(this, 'CleanupExpiredAccountsFn', {
      entry: 'lambda/handlers/scheduled/cleanupExpiredAccounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(60),
    });

    // ===== PERMISSIONS =====

    // Grant table permissions
    tables.invites.grantReadWriteData(createInvite);
    tables.invites.grantReadData(listInvites);
    tables.invites.grantReadWriteData(expireInvite);
    tables.invites.grantReadWriteData(deleteInvite);
    tables.audit.grantReadWriteData(createInvite); // Audit logging
    tables.audit.grantReadWriteData(expireInvite); // Audit logging
    tables.audit.grantReadWriteData(deleteInvite); // Audit logging

    tables.registrations.grantReadWriteData(listRegistrations);
    tables.registrations.grantReadWriteData(approveRegistration);
    tables.registrations.grantReadWriteData(rejectRegistration);
    tables.registrations.grantReadWriteData(disableUser);
    tables.registrations.grantReadWriteData(deleteUser);
    tables.registrations.grantReadWriteData(enableUser);
    tables.registrations.grantReadWriteData(permanentlyDeleteUser);
    tables.registrations.grantReadWriteData(cleanupExpiredAccounts);

    tables.subscriptions.grantReadWriteData(permanentlyDeleteUser);
    tables.subscriptions.grantReadWriteData(listSubscriptions);
    tables.registrations.grantReadData(listSubscriptions); // Need to join registration data
    tables.audit.grantReadData(listSubscriptions); // Need to fetch email preferences
    tables.subscriptions.grantReadWriteData(extendSubscription);
    tables.audit.grantReadWriteData(extendSubscription); // Audit logging
    tables.subscriptions.grantReadWriteData(reactivateSubscription);
    tables.audit.grantReadWriteData(reactivateSubscription); // Audit logging

    tables.subscriptionTypes.grantReadWriteData(createSubscriptionType);
    tables.subscriptionTypes.grantReadData(listSubscriptionTypes);
    tables.subscriptionTypes.grantReadWriteData(enableSubscriptionType);
    tables.subscriptionTypes.grantReadWriteData(disableSubscriptionType);
    tables.audit.grantReadWriteData(createSubscriptionType); // Audit logging
    tables.audit.grantReadWriteData(enableSubscriptionType); // Audit logging
    tables.audit.grantReadWriteData(disableSubscriptionType); // Audit logging

    tables.membershipTerms.grantReadWriteData(listMembershipRequests);
    tables.registrations.grantReadData(listMembershipRequests); // Need to scan for approved registrations
    tables.membershipTerms.grantReadWriteData(approveMembership);
    tables.membershipTerms.grantReadWriteData(denyMembership);
    tables.membershipTerms.grantReadWriteData(createMembershipTerms);
    tables.membershipTerms.grantReadData(getCurrentMembershipTerms);
    tables.membershipTerms.grantReadData(listMembershipTerms);

    tables.proposals.grantReadWriteData(createProposal);
    tables.audit.grantReadWriteData(createProposal); // Audit logging
    tables.proposals.grantReadData(listProposals);
    tables.proposals.grantReadWriteData(suspendProposal);
    tables.audit.grantReadWriteData(suspendProposal); // Audit logging
    tables.proposals.grantReadData(getProposalVoteCounts);

    tables.votes.grantReadData(getProposalVoteCounts);

    tables.waitlist.grantReadData(listWaitlist);
    tables.waitlist.grantReadWriteData(sendWaitlistInvites);
    tables.invites.grantReadWriteData(sendWaitlistInvites); // Create invite codes
    tables.audit.grantReadWriteData(sendWaitlistInvites); // Audit logging
    tables.waitlist.grantReadWriteData(deleteWaitlistEntries);
    tables.audit.grantReadWriteData(deleteWaitlistEntries); // Audit logging
    tables.waitlist.grantReadWriteData(deleteUser); // Delete waitlist entries during user deletion

    tables.sentEmails.grantReadWriteData(sendBulkEmail);
    tables.waitlist.grantReadData(sendBulkEmail); // Query waitlist for emails
    tables.registrations.grantReadData(sendBulkEmail); // Query registrations for emails
    tables.subscriptions.grantReadData(sendBulkEmail); // Query subscriptions for emails
    tables.sentEmails.grantReadData(listSentEmails);

    tables.audit.grantReadWriteData(approveRegistration);
    tables.audit.grantReadWriteData(rejectRegistration);
    tables.audit.grantReadWriteData(disableUser);
    tables.audit.grantReadWriteData(deleteUser);
    tables.audit.grantReadWriteData(enableUser);
    tables.audit.grantReadWriteData(permanentlyDeleteUser);
    tables.audit.grantReadWriteData(listRegistrations); // Audit logging
    tables.audit.grantReadWriteData(addAdmin); // Audit logging and rate limiting
    tables.audit.grantReadWriteData(resetAdminPassword); // Audit logging
    tables.audit.grantReadWriteData(changePassword); // Audit logging
    tables.audit.grantReadData(getAuditLog); // Query audit logs

    // Notification preferences permissions
    tables.notificationPreferences.grantReadData(getNotifications);
    tables.notificationPreferences.grantReadWriteData(addNotification);
    tables.notificationPreferences.grantReadWriteData(removeNotification);

    // Pending admins table permissions
    tables.pendingAdmins.grantReadWriteData(inviteAdmin);
    tables.pendingAdmins.grantReadData(listPendingAdmins);
    tables.pendingAdmins.grantReadWriteData(activateAdmin);
    tables.pendingAdmins.grantReadWriteData(cancelPendingAdmin);
    tables.pendingAdmins.grantReadData(resendAdminVerification);

    // Audit permissions for pending admin functions
    tables.audit.grantReadWriteData(inviteAdmin);
    tables.audit.grantReadWriteData(activateAdmin);
    tables.audit.grantReadWriteData(cancelPendingAdmin);
    tables.audit.grantReadWriteData(resendAdminVerification);

    // SES permissions scoped to specific identity and region
    // Hardened: restrict to vettid.dev domain only (covers no-reply@vettid.dev)
    // In sandbox mode, also need permission for recipient identities
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/vettid.dev`;
    const sesConfigSetArn = `arn:aws:ses:${this.region}:${this.account}:configuration-set/*`;
    const sesTemplateArn = `arn:aws:ses:${this.region}:${this.account}:template/*`;
    const sesAllIdentitiesArn = `arn:aws:ses:${this.region}:${this.account}:identity/*`;

    // Grant SES permissions for resetAdminPassword
    resetAdminPassword.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail'],
      resources: [sesIdentityArn, sesConfigSetArn],
    }));

    // Grant Cognito permissions for resetAdminPassword
    resetAdminPassword.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminSetUserPassword'],
      resources: [adminUserPool.userPoolArn],
    }));

    // Grant SES permissions for pending admin flow (verify emails, check status, delete identity)
    inviteAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:VerifyEmailIdentity', 'ses:GetIdentityVerificationAttributes'],
      resources: ['*'], // SES verification actions don't support resource-level permissions
    }));
    inviteAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser'],
      resources: [adminUserPool.userPoolArn],
    }));

    listPendingAdmins.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:GetIdentityVerificationAttributes'],
      resources: ['*'],
    }));

    // SECURITY: Split SES actions - GetIdentityVerificationAttributes doesn't support resource-level
    activateAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:GetIdentityVerificationAttributes'],
      resources: ['*'], // This action doesn't support resource-level permissions
    }));
    activateAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail'],
      resources: [sesIdentityArn, sesConfigSetArn, sesAllIdentitiesArn],
    }));
    activateAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminCreateUser',
        'cognito-idp:AdminAddUserToGroup',
        'cognito-idp:AdminSetUserPassword',
      ],
      resources: [adminUserPool.userPoolArn],
    }));

    cancelPendingAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:DeleteIdentity'],
      resources: ['*'],
    }));

    resendAdminVerification.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:VerifyEmailIdentity', 'ses:GetIdentityVerificationAttributes'],
      resources: ['*'],
    }));

    // Grant S3 permissions for membership terms
    termsBucket.grantReadWrite(createMembershipTerms);
    termsBucket.grantRead(getCurrentMembershipTerms);
    termsBucket.grantRead(getTermsDownloadUrl);

    // Grant Cognito permissions
    approveRegistration.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminCreateUser',
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminAddUserToGroup',
        'cognito-idp:AdminSetUserPassword',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    disableUser.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminDisableUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    enableUser.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminEnableUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    deleteUser.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminDeleteUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    // Grant Cognito permissions for reject registration (needs to check user and remove from groups)
    rejectRegistration.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminListGroupsForUser',
        'cognito-idp:AdminRemoveUserFromGroup',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    // Grant Cognito permissions for list registrations (needs to check user status and groups)
    listRegistrations.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminListGroupsForUser',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    // Grant Cognito permissions for approve membership (needs to add user to member group)
    approveMembership.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminAddUserToGroup'],
      resources: [memberUserPool.userPoolArn],
    }));

    permanentlyDeleteUser.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminDeleteUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    cleanupExpiredAccounts.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminDeleteUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    [listAdmins, addAdmin, removeAdmin, disableAdmin, enableAdmin, updateAdminType, resetAdminPassword, setupMfa].forEach(fn => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: [
          'cognito-idp:AdminCreateUser',
          'cognito-idp:AdminGetUser',
          'cognito-idp:AdminDisableUser',
          'cognito-idp:AdminEnableUser',
          'cognito-idp:AdminDeleteUser',
          'cognito-idp:AdminAddUserToGroup',
          'cognito-idp:AdminRemoveUserFromGroup',
          'cognito-idp:AdminListGroupsForUser',
          'cognito-idp:AdminSetUserPassword',
          'cognito-idp:AdminUpdateUserAttributes',
          'cognito-idp:ListUsers',
          'cognito-idp:ListUsersInGroup',
        ],
        resources: [adminUserPool.userPoolArn],
      }));
    });

    // Grant SES permissions for addAdmin to verify new admin emails
    // Note: VerifyEmailIdentity and GetIdentityVerificationAttributes don't support resource-level permissions
    addAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ses:VerifyEmailIdentity',
        'ses:GetIdentityVerificationAttributes',
      ],
      resources: ['*'], // These SES actions don't support resource-level permissions per AWS docs
    }));

    // Grant SES permissions for sending and verifying emails
    // In sandbox mode, need permission for both sender (vettid.dev) AND recipient identities
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendTemplatedEmail'],
      resources: [sesIdentityArn, sesTemplateArn, sesConfigSetArn, sesAllIdentitiesArn],
    }));
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:GetIdentityVerificationAttributes', 'ses:VerifyEmailIdentity'],
      resources: ['*'], // These SES actions don't support resource-level permissions per AWS docs
    }));

    // Grant SES permissions for bulk email sending
    // In sandbox mode, need permission for recipient identities too
    sendBulkEmail.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail'],
      resources: [sesIdentityArn, sesConfigSetArn, sesAllIdentitiesArn],
    }));

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

    // Export Lambda functions for VettIDStack to use in API routes
    this.listRegistrations = listRegistrations;
    this.approveRegistration = approveRegistration;
    this.rejectRegistration = rejectRegistration;
    this.createInvite = createInvite;
    this.listInvites = listInvites;
    this.expireInvite = expireInvite;
    this.deleteInvite = deleteInvite;
    this.disableUser = disableUser;
    this.enableUser = enableUser;
    this.deleteUser = deleteUser;
    this.permanentlyDeleteUser = permanentlyDeleteUser;
    this.listAdmins = listAdmins;
    this.addAdmin = addAdmin;
    this.removeAdmin = removeAdmin;
    this.disableAdmin = disableAdmin;
    this.enableAdmin = enableAdmin;
    this.updateAdminType = updateAdminType;
    this.resetAdminPassword = resetAdminPassword;
    this.changePassword = changePassword;
    this.setupMfa = setupMfa;
    this.inviteAdmin = inviteAdmin;
    this.listPendingAdmins = listPendingAdmins;
    this.activateAdmin = activateAdmin;
    this.cancelPendingAdmin = cancelPendingAdmin;
    this.resendAdminVerification = resendAdminVerification;
    this.listMembershipRequests = listMembershipRequests;
    this.approveMembership = approveMembership;
    this.denyMembership = denyMembership;
    this.createMembershipTerms = createMembershipTerms;
    this.getCurrentMembershipTerms = getCurrentMembershipTerms;
    this.listMembershipTerms = listMembershipTerms;
    this.getTermsDownloadUrl = getTermsDownloadUrl;
    this.createProposal = createProposal;
    this.listProposals = listProposals;
    this.suspendProposal = suspendProposal;
    this.getProposalVoteCounts = getProposalVoteCounts;
    this.listSubscriptions = listSubscriptions;
    this.extendSubscription = extendSubscription;
    this.reactivateSubscription = reactivateSubscription;
    this.createSubscriptionType = createSubscriptionType;
    this.listSubscriptionTypes = listSubscriptionTypes;
    this.enableSubscriptionType = enableSubscriptionType;
    this.disableSubscriptionType = disableSubscriptionType;
    this.listWaitlist = listWaitlist;
    this.sendWaitlistInvites = sendWaitlistInvites;
    this.deleteWaitlistEntries = deleteWaitlistEntries;
    this.getSystemHealth = getSystemHealth;
    this.getSystemLogs = getSystemLogs;
    this.sendBulkEmail = sendBulkEmail;
    this.listSentEmails = listSentEmails;
    this.getNotifications = getNotifications;
    this.addNotification = addNotification;
    this.removeNotification = removeNotification;
    this.getAuditLog = getAuditLog;
    this.generateNatsControlToken = generateNatsControlToken;

    // ===== HANDLER REGISTRY ADMIN FUNCTIONS =====

    const handlerEnv = {
      TABLE_HANDLERS: tables.handlers.tableName,
      BUCKET_HANDLERS: props.infrastructure.handlersBucket.bucketName,
    };

    const uploadHandler = new lambdaNode.NodejsFunction(this, 'UploadHandlerFn', {
      entry: 'lambda/handlers/admin/uploadHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...handlerEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const signHandler = new lambdaNode.NodejsFunction(this, 'SignHandlerFn', {
      entry: 'lambda/handlers/admin/signHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...handlerEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const revokeHandler = new lambdaNode.NodejsFunction(this, 'RevokeHandlerFn', {
      entry: 'lambda/handlers/admin/revokeHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...handlerEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const deleteHandler = new lambdaNode.NodejsFunction(this, 'DeleteHandlerFn', {
      entry: 'lambda/handlers/admin/deleteHandler.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...handlerEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const listRegistryHandlers = new lambdaNode.NodejsFunction(this, 'ListRegistryHandlersFn', {
      entry: 'lambda/handlers/admin/listRegistryHandlers.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...handlerEnv },
      timeout: cdk.Duration.seconds(30),
    });

    // Handler registry table permissions
    tables.handlers.grantReadWriteData(uploadHandler);
    tables.handlers.grantReadWriteData(signHandler);
    tables.handlers.grantReadWriteData(revokeHandler);
    tables.handlers.grantReadWriteData(deleteHandler);
    tables.handlers.grantReadData(listRegistryHandlers);

    // S3 bucket permissions for handler packages
    props.infrastructure.handlersBucket.grantReadWrite(uploadHandler);
    props.infrastructure.handlersBucket.grantRead(signHandler);
    props.infrastructure.handlersBucket.grantReadWrite(deleteHandler);

    this.uploadHandler = uploadHandler;
    this.signHandler = signHandler;
    this.revokeHandler = revokeHandler;
    this.deleteHandler = deleteHandler;
    this.listRegistryHandlers = listRegistryHandlers;

    // ===== SUPPORTED SERVICES ADMIN FUNCTIONS =====

    const serviceEnv = {
      TABLE_SUPPORTED_SERVICES: tables.supportedServices.tableName,
    };

    const createService = new lambdaNode.NodejsFunction(this, 'CreateServiceFn', {
      entry: 'lambda/handlers/admin/createService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...serviceEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const updateService = new lambdaNode.NodejsFunction(this, 'UpdateServiceFn', {
      entry: 'lambda/handlers/admin/updateService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...serviceEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const deleteService = new lambdaNode.NodejsFunction(this, 'DeleteServiceFn', {
      entry: 'lambda/handlers/admin/deleteService.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...serviceEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const listServices = new lambdaNode.NodejsFunction(this, 'ListServicesFn', {
      entry: 'lambda/handlers/admin/listServices.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...serviceEnv },
      timeout: cdk.Duration.seconds(30),
    });

    const toggleServiceStatus = new lambdaNode.NodejsFunction(this, 'ToggleServiceStatusFn', {
      entry: 'lambda/handlers/admin/toggleServiceStatus.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: { ...defaultEnv, ...serviceEnv },
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

    // ===== NATS CONTROL PERMISSIONS =====
    tables.natsAccounts.grantReadData(generateNatsControlToken);
    tables.natsTokens.grantReadWriteData(generateNatsControlToken);
    tables.audit.grantReadWriteData(generateNatsControlToken);

    // ===== SCHEDULED TASKS =====

    // Daily cleanup at 2 AM UTC
    const dailyCleanupRule = new events.Rule(this, 'DailyCleanupRule', {
      schedule: events.Schedule.cron({ minute: '0', hour: '2' }),
      description: 'Delete soft-deleted accounts older than 30 days',
    });
    dailyCleanupRule.addTarget(new targets_events.LambdaFunction(cleanupExpiredAccounts));

    // Add API routes - done here to keep route resources in AdminStack
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
   * Add admin routes to the HTTP API
   * Routes are created in AdminStack to stay under CloudFormation's 500 resource limit
   * Using HttpRoute directly (not httpApi.addRoutes) to avoid cyclic dependencies
   */
  private addRoutes(httpApi: apigw.HttpApi, adminAuthorizer: apigw.IHttpRouteAuthorizer): void {
    // Registration Management
    this.route('ListRegistrations', httpApi, '/admin/registrations', apigw.HttpMethod.GET, this.listRegistrations, adminAuthorizer);
    this.route('ApproveRegistration', httpApi, '/admin/registrations/{registration_id}/approve', apigw.HttpMethod.POST, this.approveRegistration, adminAuthorizer);
    this.route('RejectRegistration', httpApi, '/admin/registrations/{registration_id}/reject', apigw.HttpMethod.POST, this.rejectRegistration, adminAuthorizer);

    // Invite Management
    this.route('CreateInvite', httpApi, '/admin/invites', apigw.HttpMethod.POST, this.createInvite, adminAuthorizer);
    this.route('ListInvites', httpApi, '/admin/invites', apigw.HttpMethod.GET, this.listInvites, adminAuthorizer);
    this.route('ExpireInvite', httpApi, '/admin/invites/{code}/expire', apigw.HttpMethod.POST, this.expireInvite, adminAuthorizer);
    this.route('DeleteInvite', httpApi, '/admin/invites/{code}', apigw.HttpMethod.DELETE, this.deleteInvite, adminAuthorizer);

    // User Management
    this.route('DisableUser', httpApi, '/admin/users/{user_id}/disable', apigw.HttpMethod.POST, this.disableUser, adminAuthorizer);
    this.route('EnableUser', httpApi, '/admin/users/{user_id}/enable', apigw.HttpMethod.POST, this.enableUser, adminAuthorizer);
    this.route('DeleteUser', httpApi, '/admin/users/{user_id}', apigw.HttpMethod.DELETE, this.deleteUser, adminAuthorizer);
    this.route('PermanentlyDeleteUser', httpApi, '/admin/users/{user_id}/permanently-delete', apigw.HttpMethod.DELETE, this.permanentlyDeleteUser, adminAuthorizer);

    // Admin Management
    this.route('ListAdmins', httpApi, '/admin/admins', apigw.HttpMethod.GET, this.listAdmins, adminAuthorizer);
    this.route('AddAdmin', httpApi, '/admin/admins', apigw.HttpMethod.POST, this.addAdmin, adminAuthorizer);
    this.route('RemoveAdmin', httpApi, '/admin/admins/{username}', apigw.HttpMethod.DELETE, this.removeAdmin, adminAuthorizer);
    this.route('DisableAdmin', httpApi, '/admin/admins/{username}/disable', apigw.HttpMethod.POST, this.disableAdmin, adminAuthorizer);
    this.route('EnableAdmin', httpApi, '/admin/admins/{username}/enable', apigw.HttpMethod.POST, this.enableAdmin, adminAuthorizer);
    this.route('UpdateAdminType', httpApi, '/admin/admins/{username}/type', apigw.HttpMethod.PUT, this.updateAdminType, adminAuthorizer);
    this.route('ResetAdminPassword', httpApi, '/admin/admins/{username}/reset-password', apigw.HttpMethod.POST, this.resetAdminPassword, adminAuthorizer);
    this.route('ChangePassword', httpApi, '/admin/change-password', apigw.HttpMethod.POST, this.changePassword, adminAuthorizer);
    this.route('SetupMfaGet', httpApi, '/admin/mfa', apigw.HttpMethod.GET, this.setupMfa, adminAuthorizer);
    this.route('SetupMfaPost', httpApi, '/admin/mfa', apigw.HttpMethod.POST, this.setupMfa, adminAuthorizer);

    // Pending Admin Invitation routes (2-step flow)
    this.route('ListPendingAdmins', httpApi, '/admin/pending-admins', apigw.HttpMethod.GET, this.listPendingAdmins, adminAuthorizer);
    this.route('InviteAdmin', httpApi, '/admin/pending-admins', apigw.HttpMethod.POST, this.inviteAdmin, adminAuthorizer);
    this.route('ActivateAdmin', httpApi, '/admin/pending-admins/{email}/activate', apigw.HttpMethod.POST, this.activateAdmin, adminAuthorizer);
    this.route('CancelPendingAdmin', httpApi, '/admin/pending-admins/{email}', apigw.HttpMethod.DELETE, this.cancelPendingAdmin, adminAuthorizer);
    this.route('ResendAdminVerification', httpApi, '/admin/pending-admins/{email}/resend', apigw.HttpMethod.POST, this.resendAdminVerification, adminAuthorizer);

    // Membership Management routes
    this.route('ListMembershipRequests', httpApi, '/admin/membership-requests', apigw.HttpMethod.GET, this.listMembershipRequests, adminAuthorizer);
    this.route('ApproveMembership', httpApi, '/admin/membership-requests/{id}/approve', apigw.HttpMethod.POST, this.approveMembership, adminAuthorizer);
    this.route('DenyMembership', httpApi, '/admin/membership-requests/{id}/deny', apigw.HttpMethod.POST, this.denyMembership, adminAuthorizer);
    this.route('CreateMembershipTerms', httpApi, '/admin/membership-terms', apigw.HttpMethod.POST, this.createMembershipTerms, adminAuthorizer);
    this.route('GetCurrentMembershipTerms', httpApi, '/admin/membership-terms/current', apigw.HttpMethod.GET, this.getCurrentMembershipTerms, adminAuthorizer);
    this.route('ListMembershipTerms', httpApi, '/admin/membership-terms', apigw.HttpMethod.GET, this.listMembershipTerms, adminAuthorizer);
    this.route('GetTermsDownloadUrl', httpApi, '/admin/membership-terms/{version_id}/download', apigw.HttpMethod.GET, this.getTermsDownloadUrl, adminAuthorizer);

    // Proposal Management routes
    this.route('CreateProposal', httpApi, '/admin/proposals', apigw.HttpMethod.POST, this.createProposal, adminAuthorizer);
    this.route('ListProposals', httpApi, '/admin/proposals', apigw.HttpMethod.GET, this.listProposals, adminAuthorizer);
    this.route('SuspendProposal', httpApi, '/admin/proposals/{id}/suspend', apigw.HttpMethod.POST, this.suspendProposal, adminAuthorizer);
    this.route('GetProposalVoteCounts', httpApi, '/admin/proposals/{proposal_id}/vote-counts', apigw.HttpMethod.GET, this.getProposalVoteCounts, adminAuthorizer);

    // Subscription Management routes
    this.route('ListSubscriptions', httpApi, '/admin/subscriptions', apigw.HttpMethod.GET, this.listSubscriptions, adminAuthorizer);
    this.route('ExtendSubscription', httpApi, '/admin/subscriptions/{id}/extend', apigw.HttpMethod.POST, this.extendSubscription, adminAuthorizer);
    this.route('ReactivateSubscription', httpApi, '/admin/subscriptions/{id}/reactivate', apigw.HttpMethod.POST, this.reactivateSubscription, adminAuthorizer);
    this.route('CreateSubscriptionType', httpApi, '/admin/subscription-types', apigw.HttpMethod.POST, this.createSubscriptionType, adminAuthorizer);
    this.route('ListSubscriptionTypes', httpApi, '/admin/subscription-types', apigw.HttpMethod.GET, this.listSubscriptionTypes, adminAuthorizer);
    this.route('EnableSubscriptionType', httpApi, '/admin/subscription-types/{id}/enable', apigw.HttpMethod.POST, this.enableSubscriptionType, adminAuthorizer);
    this.route('DisableSubscriptionType', httpApi, '/admin/subscription-types/{id}/disable', apigw.HttpMethod.POST, this.disableSubscriptionType, adminAuthorizer);

    // Waitlist Management routes
    this.route('ListWaitlist', httpApi, '/admin/waitlist', apigw.HttpMethod.GET, this.listWaitlist, adminAuthorizer);
    this.route('SendWaitlistInvites', httpApi, '/admin/waitlist/send-invites', apigw.HttpMethod.POST, this.sendWaitlistInvites, adminAuthorizer);
    this.route('DeleteWaitlistEntries', httpApi, '/admin/waitlist', apigw.HttpMethod.DELETE, this.deleteWaitlistEntries, adminAuthorizer);

    // System Monitoring routes
    this.route('GetSystemHealth', httpApi, '/admin/system-health', apigw.HttpMethod.GET, this.getSystemHealth, adminAuthorizer);
    this.route('GetSystemLogs', httpApi, '/admin/system-logs', apigw.HttpMethod.GET, this.getSystemLogs, adminAuthorizer);

    // Email Management routes
    this.route('SendBulkEmail', httpApi, '/admin/send-bulk-email', apigw.HttpMethod.POST, this.sendBulkEmail, adminAuthorizer);
    this.route('ListSentEmails', httpApi, '/admin/sent-emails', apigw.HttpMethod.GET, this.listSentEmails, adminAuthorizer);

    // Notification Management routes
    this.route('GetNotifications', httpApi, '/admin/notifications/{type}', apigw.HttpMethod.GET, this.getNotifications, adminAuthorizer);
    this.route('AddNotification', httpApi, '/admin/notifications/{type}', apigw.HttpMethod.POST, this.addNotification, adminAuthorizer);
    this.route('RemoveNotification', httpApi, '/admin/notifications/{type}/{email}', apigw.HttpMethod.DELETE, this.removeNotification, adminAuthorizer);

    // Audit Log route
    this.route('GetAuditLog', httpApi, '/admin/audit', apigw.HttpMethod.GET, this.getAuditLog, adminAuthorizer);

    // NATS Control - Admin-only endpoint for issuing control tokens
    this.route('GenerateNatsControlToken', httpApi, '/admin/nats/control-token', apigw.HttpMethod.POST, this.generateNatsControlToken, adminAuthorizer);

    // Handler Registry Admin - Admin-only endpoints for managing handler registry
    this.route('ListRegistryHandlers', httpApi, '/admin/registry/handlers', apigw.HttpMethod.GET, this.listRegistryHandlers, adminAuthorizer);
    this.route('UploadHandler', httpApi, '/admin/registry/handlers', apigw.HttpMethod.POST, this.uploadHandler, adminAuthorizer);
    this.route('SignHandler', httpApi, '/admin/registry/handlers/sign', apigw.HttpMethod.POST, this.signHandler, adminAuthorizer);
    this.route('RevokeHandler', httpApi, '/admin/registry/handlers/revoke', apigw.HttpMethod.POST, this.revokeHandler, adminAuthorizer);
    this.route('DeleteHandler', httpApi, '/admin/registry/handlers/delete', apigw.HttpMethod.POST, this.deleteHandler, adminAuthorizer);

    // Supported Services Admin - Admin-only endpoints for managing supported services
    this.route('ListServices', httpApi, '/admin/services', apigw.HttpMethod.GET, this.listServices, adminAuthorizer);
    this.route('CreateService', httpApi, '/admin/services', apigw.HttpMethod.POST, this.createService, adminAuthorizer);
    this.route('UpdateService', httpApi, '/admin/services', apigw.HttpMethod.PUT, this.updateService, adminAuthorizer);
    this.route('DeleteService', httpApi, '/admin/services/delete', apigw.HttpMethod.POST, this.deleteService, adminAuthorizer);
    this.route('ToggleServiceStatus', httpApi, '/admin/services/status', apigw.HttpMethod.POST, this.toggleServiceStatus, adminAuthorizer);
  }
}
