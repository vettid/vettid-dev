import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_iam as iam,
  aws_events as events,
  aws_events_targets as targets_events,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface AdminStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
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
  public readonly listMembershipRequests!: lambdaNode.NodejsFunction;
  public readonly approveMembership!: lambdaNode.NodejsFunction;
  public readonly denyMembership!: lambdaNode.NodejsFunction;
  public readonly createMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly getCurrentMembershipTerms!: lambdaNode.NodejsFunction;
  public readonly listMembershipTerms!: lambdaNode.NodejsFunction;
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

    // Grant SES permissions for resetAdminPassword
    resetAdminPassword.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail'],
      resources: ['*'], // Need wildcard to send from noreply@vettid.dev
    }));

    // Grant Cognito permissions for resetAdminPassword
    resetAdminPassword.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminGetUser', 'cognito-idp:AdminSetUserPassword'],
      resources: [adminUserPool.userPoolArn],
    }));

    // Grant S3 permissions for membership terms
    termsBucket.grantReadWrite(createMembershipTerms);
    termsBucket.grantRead(getCurrentMembershipTerms);
    termsBucket.grantRead(listMembershipTerms);

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
    addAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ses:VerifyEmailIdentity',
        'ses:GetIdentityVerificationAttributes',
      ],
      resources: ['*'],
    }));

    // Grant SES permissions for sending and verifying emails
    sendWaitlistInvites.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ses:SendEmail',
        'ses:SendTemplatedEmail',
        'ses:GetIdentityVerificationAttributes',
        'ses:VerifyEmailIdentity',
      ],
      resources: ['*'], // Need wildcard to verify any email and send from noreply@vettid.dev
    }));

    // Grant SES permissions for bulk email sending
    sendBulkEmail.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail'],
      resources: ['*'], // Need wildcard to send from noreply@vettid.dev
    }));

    // Grant system monitoring permissions
    getSystemHealth.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ses:GetSendQuota',
        'dynamodb:DescribeTable',
        'cloudwatch:GetMetricStatistics',
      ],
      resources: ['*'],
    }));

    getSystemLogs.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'logs:DescribeLogGroups',
        'logs:FilterLogEvents',
      ],
      resources: ['*'],
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
    this.listMembershipRequests = listMembershipRequests;
    this.approveMembership = approveMembership;
    this.denyMembership = denyMembership;
    this.createMembershipTerms = createMembershipTerms;
    this.getCurrentMembershipTerms = getCurrentMembershipTerms;
    this.listMembershipTerms = listMembershipTerms;
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

    // ===== SCHEDULED TASKS =====

    // Daily cleanup at 2 AM UTC
    const dailyCleanupRule = new events.Rule(this, 'DailyCleanupRule', {
      schedule: events.Schedule.cron({ minute: '0', hour: '2' }),
      description: 'Delete soft-deleted accounts older than 30 days',
    });
    dailyCleanupRule.addTarget(new targets_events.LambdaFunction(cleanupExpiredAccounts));
  }
}
