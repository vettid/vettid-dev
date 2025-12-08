#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';
import { AdminStack } from '../lib/admin-stack';
import { VaultStack } from '../lib/vault-stack';
import { NatsStack } from '../lib/nats-stack';
import { LedgerStack } from '../lib/ledger-stack';

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

// 3. Deploy admin stack (admin Lambda functions + API routes)
// Routes are added in AdminStack to stay under CloudFormation's 500 resource limit
const admin = new AdminStack(app, 'VettID-Admin', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  adminAuthorizer: core.adminAuthorizer,
});

// 4. Deploy Ledger stack (Aurora PostgreSQL for Protean Credential System)
// This stack creates its own VPC for database isolation
// Must be deployed before VaultStack if Ledger integration is enabled
const ledger = new LedgerStack(app, 'VettID-Ledger', {
  env,
  environment: (process.env.ENVIRONMENT as 'development' | 'staging' | 'production') || 'development',
});

// 5. Deploy vault stack (vault Lambda functions + API routes)
// Routes are added in VaultStack to stay under CloudFormation's 500 resource limit
// Pass ledger stack to enable Protean Credential System Lambda handlers
const vault = new VaultStack(app, 'VettID-Vault', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  memberAuthorizer: core.memberAuthorizer,
  ledger,  // Enable Ledger (Protean Credential System) handlers
});

// 6. Deploy NATS infrastructure stack (VPC, EC2 cluster, NLB)
// Note: This stack requires the Route 53 hosted zone ID for nats.vettid.dev
// To deploy, provide the hosted zone ID via context or environment variable
const nats = new NatsStack(app, 'VettID-NATS', {
  env,
  domainName: 'nats.vettid.dev',
  hostedZoneId: app.node.tryGetContext('hostedZoneId') || process.env.HOSTED_ZONE_ID || 'PLACEHOLDER',
  zoneName: 'vettid.dev',
});
