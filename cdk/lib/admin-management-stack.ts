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

export interface AdminManagementStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  adminAuthorizer: apigw.IHttpRouteAuthorizer;
}

/**
 * VettID Admin Management Stack
 *
 * Contains admin/user lifecycle management:
 * - Registration management
 * - Invite management
 * - User management
 * - Admin management
 * - Pending admin invitations
 * - Notifications
 * - Scheduled cleanup tasks
 *
 * Split from AdminStack to stay under CloudFormation's 500 resource limit.
 */
export class AdminManagementStack extends cdk.Stack {
  // Registration Management
  public readonly listRegistrations!: lambdaNode.NodejsFunction;
  public readonly approveRegistration!: lambdaNode.NodejsFunction;
  public readonly rejectRegistration!: lambdaNode.NodejsFunction;

  // Invite Management
  public readonly createInvite!: lambdaNode.NodejsFunction;
  public readonly listInvites!: lambdaNode.NodejsFunction;
  public readonly expireInvite!: lambdaNode.NodejsFunction;
  public readonly deleteInvite!: lambdaNode.NodejsFunction;

  // User Management
  public readonly disableUser!: lambdaNode.NodejsFunction;
  public readonly enableUser!: lambdaNode.NodejsFunction;
  public readonly deleteUser!: lambdaNode.NodejsFunction;
  public readonly permanentlyDeleteUser!: lambdaNode.NodejsFunction;

  // Admin Management
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

  // Pending Admin Management
  public readonly listPendingAdmins!: lambdaNode.NodejsFunction;
  public readonly activateAdmin!: lambdaNode.NodejsFunction;
  public readonly cancelPendingAdmin!: lambdaNode.NodejsFunction;
  public readonly resendAdminVerification!: lambdaNode.NodejsFunction;

  // Notifications
  public readonly getNotifications!: lambdaNode.NodejsFunction;
  public readonly addNotification!: lambdaNode.NodejsFunction;
  public readonly removeNotification!: lambdaNode.NodejsFunction;

  constructor(scope: Construct, id: string, props: AdminManagementStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const adminUserPool = props.infrastructure.adminUserPool;
    const memberUserPool = props.infrastructure.memberUserPool;

    // Default environment variables for admin management functions
    const defaultEnv = {
      TABLE_INVITES: tables.invites.tableName,
      TABLE_REGISTRATIONS: tables.registrations.tableName,
      TABLE_AUDIT: tables.audit.tableName,
      TABLE_SUBSCRIPTIONS: tables.subscriptions.tableName,
      TABLE_WAITLIST: tables.waitlist.tableName,
      TABLE_NOTIFICATION_PREFERENCES: tables.notificationPreferences.tableName,
      PENDING_ADMINS_TABLE: tables.pendingAdmins.tableName,
      STAGE: 'prod',
      ALLOWED_ORIGINS: 'https://admin.vettid.dev,https://vettid.dev',
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

    // Grant permissions
    tables.registrations.grantReadData(listRegistrations);
    tables.registrations.grantReadWriteData(approveRegistration);
    tables.registrations.grantReadWriteData(rejectRegistration);
    tables.audit.grantReadWriteData(approveRegistration);
    tables.audit.grantReadWriteData(rejectRegistration);

    // Cognito permissions for approving registrations
    approveRegistration.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminCreateUser',
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminAddUserToGroup',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    this.listRegistrations = listRegistrations;
    this.approveRegistration = approveRegistration;
    this.rejectRegistration = rejectRegistration;

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

    // Grant permissions
    tables.invites.grantReadWriteData(createInvite);
    tables.invites.grantReadData(listInvites);
    tables.invites.grantReadWriteData(expireInvite);
    tables.invites.grantReadWriteData(deleteInvite);
    tables.audit.grantReadWriteData(createInvite);
    tables.audit.grantReadWriteData(expireInvite);
    tables.audit.grantReadWriteData(deleteInvite);

    this.createInvite = createInvite;
    this.listInvites = listInvites;
    this.expireInvite = expireInvite;
    this.deleteInvite = deleteInvite;

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

    // Grant permissions
    tables.registrations.grantReadWriteData(disableUser);
    tables.registrations.grantReadWriteData(enableUser);
    tables.registrations.grantReadWriteData(deleteUser);
    tables.registrations.grantReadWriteData(permanentlyDeleteUser);
    tables.subscriptions.grantReadWriteData(permanentlyDeleteUser);
    tables.waitlist.grantReadWriteData(deleteUser);
    tables.audit.grantReadWriteData(disableUser);
    tables.audit.grantReadWriteData(enableUser);
    tables.audit.grantReadWriteData(deleteUser);
    tables.audit.grantReadWriteData(permanentlyDeleteUser);

    // Cognito permissions
    const cognitoUserPolicy = new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminDisableUser',
        'cognito-idp:AdminEnableUser',
        'cognito-idp:AdminDeleteUser',
        'cognito-idp:AdminGetUser',
      ],
      resources: [memberUserPool.userPoolArn],
    });
    disableUser.addToRolePolicy(cognitoUserPolicy);
    enableUser.addToRolePolicy(cognitoUserPolicy);
    deleteUser.addToRolePolicy(cognitoUserPolicy);
    permanentlyDeleteUser.addToRolePolicy(cognitoUserPolicy);

    this.disableUser = disableUser;
    this.enableUser = enableUser;
    this.deleteUser = deleteUser;
    this.permanentlyDeleteUser = permanentlyDeleteUser;

    // ===== ADMIN MANAGEMENT =====

    const adminEnv = {
      ...defaultEnv,
      ADMIN_USER_POOL_ID: adminUserPool.userPoolId,
      ADMIN_GROUP: 'admin',
    };

    const listAdmins = new lambdaNode.NodejsFunction(this, 'ListAdminsFn', {
      entry: 'lambda/handlers/admin/listAdmins.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const addAdmin = new lambdaNode.NodejsFunction(this, 'AddAdminFn', {
      entry: 'lambda/handlers/admin/addAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const removeAdmin = new lambdaNode.NodejsFunction(this, 'RemoveAdminFn', {
      entry: 'lambda/handlers/admin/removeAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const disableAdmin = new lambdaNode.NodejsFunction(this, 'DisableAdminFn', {
      entry: 'lambda/handlers/admin/disableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const enableAdmin = new lambdaNode.NodejsFunction(this, 'EnableAdminFn', {
      entry: 'lambda/handlers/admin/enableAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const updateAdminType = new lambdaNode.NodejsFunction(this, 'UpdateAdminTypeFn', {
      entry: 'lambda/handlers/admin/updateAdminType.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const resetAdminPassword = new lambdaNode.NodejsFunction(this, 'ResetAdminPasswordFn', {
      entry: 'lambda/handlers/admin/resetAdminPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const changePassword = new lambdaNode.NodejsFunction(this, 'ChangePasswordFn', {
      entry: 'lambda/handlers/admin/changePassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const setupMfa = new lambdaNode.NodejsFunction(this, 'SetupMfaFn', {
      entry: 'lambda/handlers/admin/setupMfa.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const inviteAdmin = new lambdaNode.NodejsFunction(this, 'InviteAdminFn', {
      entry: 'lambda/handlers/admin/inviteAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant admin Cognito permissions
    const cognitoAdminPolicy = new iam.PolicyStatement({
      actions: [
        'cognito-idp:ListUsers',
        'cognito-idp:ListUsersInGroup',
        'cognito-idp:AdminCreateUser',
        'cognito-idp:AdminDeleteUser',
        'cognito-idp:AdminDisableUser',
        'cognito-idp:AdminEnableUser',
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminUpdateUserAttributes',
        'cognito-idp:AdminAddUserToGroup',
        'cognito-idp:AdminRemoveUserFromGroup',
        'cognito-idp:AdminResetUserPassword',
        'cognito-idp:AdminSetUserPassword',
        'cognito-idp:AssociateSoftwareToken',
        'cognito-idp:VerifySoftwareToken',
        'cognito-idp:SetUserMFAPreference',
        'cognito-idp:AdminSetUserMFAPreference',
      ],
      resources: [adminUserPool.userPoolArn],
    });

    listAdmins.addToRolePolicy(cognitoAdminPolicy);
    addAdmin.addToRolePolicy(cognitoAdminPolicy);
    removeAdmin.addToRolePolicy(cognitoAdminPolicy);
    disableAdmin.addToRolePolicy(cognitoAdminPolicy);
    enableAdmin.addToRolePolicy(cognitoAdminPolicy);
    updateAdminType.addToRolePolicy(cognitoAdminPolicy);
    resetAdminPassword.addToRolePolicy(cognitoAdminPolicy);
    changePassword.addToRolePolicy(cognitoAdminPolicy);
    setupMfa.addToRolePolicy(cognitoAdminPolicy);
    inviteAdmin.addToRolePolicy(cognitoAdminPolicy);

    // Audit permissions
    tables.audit.grantReadWriteData(addAdmin);
    tables.audit.grantReadWriteData(removeAdmin);
    tables.audit.grantReadWriteData(disableAdmin);
    tables.audit.grantReadWriteData(enableAdmin);
    tables.audit.grantReadWriteData(updateAdminType);
    tables.audit.grantReadWriteData(resetAdminPassword);
    tables.audit.grantReadWriteData(changePassword);
    tables.audit.grantReadWriteData(inviteAdmin);

    // Pending admins table for invite flow
    tables.pendingAdmins.grantReadWriteData(inviteAdmin);

    // SES permissions for admin invitations (including email verification)
    inviteAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ses:SendEmail',
        'ses:SendTemplatedEmail',
        'ses:VerifyEmailIdentity',
        'ses:GetIdentityVerificationAttributes'
      ],
      resources: ['*'],
    }));

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

    // ===== PENDING ADMIN MANAGEMENT =====

    const listPendingAdmins = new lambdaNode.NodejsFunction(this, 'ListPendingAdminsFn', {
      entry: 'lambda/handlers/admin/listPendingAdmins.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const activateAdmin = new lambdaNode.NodejsFunction(this, 'ActivateAdminFn', {
      entry: 'lambda/handlers/admin/activateAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const cancelPendingAdmin = new lambdaNode.NodejsFunction(this, 'CancelPendingAdminFn', {
      entry: 'lambda/handlers/admin/cancelPendingAdmin.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const resendAdminVerification = new lambdaNode.NodejsFunction(this, 'ResendAdminVerificationFn', {
      entry: 'lambda/handlers/admin/resendAdminVerification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: adminEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions
    tables.pendingAdmins.grantReadData(listPendingAdmins);
    tables.pendingAdmins.grantReadWriteData(activateAdmin);
    tables.pendingAdmins.grantReadWriteData(cancelPendingAdmin);
    tables.pendingAdmins.grantReadWriteData(resendAdminVerification);
    tables.audit.grantReadWriteData(activateAdmin);
    tables.audit.grantReadWriteData(cancelPendingAdmin);

    // Cognito permissions for activation
    activateAdmin.addToRolePolicy(cognitoAdminPolicy);

    // SES permissions for activation (send welcome email and check verification)
    activateAdmin.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:GetIdentityVerificationAttributes'],
      resources: ['*'],
    }));

    // SES permissions for resend
    resendAdminVerification.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ses:SendEmail', 'ses:SendTemplatedEmail'],
      resources: ['*'],
    }));

    this.listPendingAdmins = listPendingAdmins;
    this.activateAdmin = activateAdmin;
    this.cancelPendingAdmin = cancelPendingAdmin;
    this.resendAdminVerification = resendAdminVerification;

    // ===== NOTIFICATION MANAGEMENT =====

    const getNotifications = new lambdaNode.NodejsFunction(this, 'GetNotificationsFn', {
      entry: 'lambda/handlers/admin/getNotifications.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const addNotification = new lambdaNode.NodejsFunction(this, 'AddNotificationFn', {
      entry: 'lambda/handlers/admin/addNotification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const removeNotification = new lambdaNode.NodejsFunction(this, 'RemoveNotificationFn', {
      entry: 'lambda/handlers/admin/removeNotification.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // Grant permissions
    tables.notificationPreferences.grantReadData(getNotifications);
    tables.notificationPreferences.grantReadWriteData(addNotification);
    tables.notificationPreferences.grantReadWriteData(removeNotification);
    tables.audit.grantReadWriteData(addNotification);
    tables.audit.grantReadWriteData(removeNotification);

    this.getNotifications = getNotifications;
    this.addNotification = addNotification;
    this.removeNotification = removeNotification;

    // ===== SCHEDULED TASKS =====

    const cleanupExpiredAccounts = new lambdaNode.NodejsFunction(this, 'CleanupExpiredAccountsFn', {
      entry: 'lambda/handlers/scheduled/cleanupExpiredAccounts.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.minutes(5),
    });

    // Grant permissions
    tables.registrations.grantReadWriteData(cleanupExpiredAccounts);
    tables.subscriptions.grantReadWriteData(cleanupExpiredAccounts);
    tables.audit.grantReadWriteData(cleanupExpiredAccounts);

    cleanupExpiredAccounts.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:AdminDeleteUser'],
      resources: [memberUserPool.userPoolArn],
    }));

    // Daily cleanup at 2 AM UTC
    const dailyCleanupRule = new events.Rule(this, 'DailyCleanupRule', {
      schedule: events.Schedule.cron({ minute: '0', hour: '2' }),
      description: 'Delete soft-deleted accounts older than 30 days',
    });
    dailyCleanupRule.addTarget(new targets_events.LambdaFunction(cleanupExpiredAccounts));

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

    // Pending Admin Invitation routes
    this.route('ListPendingAdmins', httpApi, '/admin/pending-admins', apigw.HttpMethod.GET, this.listPendingAdmins, adminAuthorizer);
    this.route('InviteAdmin', httpApi, '/admin/pending-admins', apigw.HttpMethod.POST, this.inviteAdmin, adminAuthorizer);
    this.route('ActivateAdmin', httpApi, '/admin/pending-admins/{email}/activate', apigw.HttpMethod.POST, this.activateAdmin, adminAuthorizer);
    this.route('CancelPendingAdmin', httpApi, '/admin/pending-admins/{email}', apigw.HttpMethod.DELETE, this.cancelPendingAdmin, adminAuthorizer);
    this.route('ResendAdminVerification', httpApi, '/admin/pending-admins/{email}/resend', apigw.HttpMethod.POST, this.resendAdminVerification, adminAuthorizer);

    // Notification Management routes
    this.route('GetNotifications', httpApi, '/admin/notifications/{type}', apigw.HttpMethod.GET, this.getNotifications, adminAuthorizer);
    this.route('AddNotification', httpApi, '/admin/notifications/{type}', apigw.HttpMethod.POST, this.addNotification, adminAuthorizer);
    this.route('RemoveNotification', httpApi, '/admin/notifications/{type}/{email}', apigw.HttpMethod.DELETE, this.removeNotification, adminAuthorizer);
  }
}
