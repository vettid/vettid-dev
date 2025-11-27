import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  aws_lambda_nodejs as lambdaNode,
  aws_lambda as lambda,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
  aws_iam as iam,
  aws_cognito as cognito,
} from 'aws-cdk-lib';
import { InfrastructureStack } from './infrastructure-stack';

export interface VaultStackProps extends cdk.StackProps {
  infrastructure: InfrastructureStack;
  httpApi: apigw.HttpApi;
  jwtAuthorizer: apigw.IHttpRouteAuthorizer;
  memberUserPool: cognito.UserPool;
}

/**
 * VettID Vault Stack
 *
 * Contains vault enrollment and authentication services:
 * - Vault enrollment Lambda functions
 * - Vault authentication Lambda functions
 * - API routes added to Core stack's API Gateway
 *
 * Depends on: Infrastructure Stack (for tables), Core Stack (for API Gateway)
 */
export class VaultStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: VaultStackProps) {
    super(scope, id, props);

    const tables = props.infrastructure.tables;
    const { httpApi, jwtAuthorizer, memberUserPool } = props;

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

    const enrollStart = new lambdaNode.NodejsFunction(this, 'EnrollStartFn', {
      entry: 'lambda/handlers/vault/enrollStart.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(30),
    });

    const enrollSetPassword = new lambdaNode.NodejsFunction(this, 'EnrollSetPasswordFn', {
      entry: 'lambda/handlers/vault/enrollSetPassword.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    const enrollFinalize = new lambdaNode.NodejsFunction(this, 'EnrollFinalizeFn', {
      entry: 'lambda/handlers/vault/enrollFinalize.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        USER_POOL_ID: memberUserPool.userPoolId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ===== VAULT AUTHENTICATION =====

    const actionRequest = new lambdaNode.NodejsFunction(this, 'ActionRequestFn', {
      entry: 'lambda/handlers/vault/actionRequest.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: {
        ...defaultEnv,
        SES_FROM: 'no-reply@auth.vettid.dev',
      },
      timeout: cdk.Duration.seconds(30),
    });

    const authExecute = new lambdaNode.NodejsFunction(this, 'AuthExecuteFn', {
      entry: 'lambda/handlers/vault/authExecute.ts',
      runtime: lambda.Runtime.NODEJS_22_X,
      environment: defaultEnv,
      timeout: cdk.Duration.seconds(30),
    });

    // ===== PERMISSIONS =====

    // Grant table permissions
    tables.enrollmentSessions.grantReadWriteData(enrollStart);
    tables.enrollmentSessions.grantReadWriteData(enrollSetPassword);
    tables.enrollmentSessions.grantReadWriteData(enrollFinalize);

    tables.credentials.grantReadWriteData(enrollFinalize);
    tables.credentials.grantReadData(actionRequest);
    tables.credentials.grantReadData(authExecute);

    tables.credentialKeys.grantReadWriteData(enrollFinalize);
    tables.credentialKeys.grantReadData(actionRequest);
    tables.credentialKeys.grantReadData(authExecute);

    tables.transactionKeys.grantReadWriteData(actionRequest);
    tables.transactionKeys.grantReadWriteData(authExecute);

    tables.ledgerAuthTokens.grantReadWriteData(authExecute);

    tables.actionTokens.grantReadWriteData(actionRequest);
    tables.actionTokens.grantReadWriteData(authExecute);

    tables.registrations.grantReadData(enrollStart);
    tables.registrations.grantReadData(enrollFinalize);

    // Grant Cognito permissions for enrollment finalization
    enrollFinalize.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'cognito-idp:AdminGetUser',
        'cognito-idp:AdminUpdateUserAttributes',
      ],
      resources: [memberUserPool.userPoolArn],
    }));

    // Grant SES permissions for email sending
    const sesIdentityArn = `arn:aws:ses:${this.region}:${this.account}:identity/auth.vettid.dev`;
    [enrollStart, actionRequest].forEach(fn => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ses:SendEmail', 'ses:SendTemplatedEmail'],
        resources: [sesIdentityArn],
      }));
    });

    // ===== API ROUTES =====

    httpApi.addRoutes({
      path: '/vault/enroll/start',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollStartInt', enrollStart),
      authorizer: jwtAuthorizer,
    });

    httpApi.addRoutes({
      path: '/vault/enroll/set-password',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollSetPasswordInt', enrollSetPassword),
      authorizer: jwtAuthorizer,
    });

    httpApi.addRoutes({
      path: '/vault/enroll/finalize',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('EnrollFinalizeInt', enrollFinalize),
      authorizer: jwtAuthorizer,
    });

    httpApi.addRoutes({
      path: '/vault/action/request',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('ActionRequestInt', actionRequest),
      authorizer: jwtAuthorizer,
    });

    httpApi.addRoutes({
      path: '/vault/auth/execute',
      methods: [apigw.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('AuthExecuteInt', authExecute),
      authorizer: jwtAuthorizer,
    });
  }
}
