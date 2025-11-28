#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';
import { AdminStack } from '../lib/admin-stack';
import { VaultStack } from '../lib/vault-stack';

const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'us-east-1'
};

// 1. Deploy infrastructure stack first (DynamoDB tables)
const infrastructure = new InfrastructureStack(app, 'VettID-Infrastructure', { env });

// 2. Deploy core stack (S3, CloudFront, Cognito, API Gateway, core Lambdas)
const core = new VettIdStack(app, 'VettIDStack', {
  env,
  infrastructure,
});

// 3. Deploy admin stack (admin Lambda functions only, routes added by VettIDStack)
const admin = new AdminStack(app, 'VettID-Admin', {
  env,
  infrastructure,
  termsBucket: core.termsBucket,
});

// 4. Add admin routes to VettIDStack API
core.addAdminRoutes(admin);

// 4. Deploy vault stack (vault Lambda functions and routes)
// TODO: Commented out due to cyclic dependency during synthesis - needs investigation
// Vault functionality currently remains in VettIDStack
/*
new VaultStack(app, 'VettID-Vault', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  jwtAuthorizer: core.memberAuthorizer,
  memberUserPool: core.memberUserPool,
});
*/
