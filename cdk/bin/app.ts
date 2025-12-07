#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';
import { AdminStack } from '../lib/admin-stack';
import { VaultStack } from '../lib/vault-stack';
import { NatsStack } from '../lib/nats-stack';

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
});

// 4. Add admin routes to VettIDStack API
core.addAdminRoutes(admin);

// 5. Deploy vault stack (vault Lambda functions only, routes added by VettIDStack)
const vault = new VaultStack(app, 'VettID-Vault', {
  env,
  infrastructure,
});

// 6. Add vault routes to VettIDStack API
core.addVaultRoutes(vault);

// 7. Deploy NATS infrastructure stack (VPC, EC2 cluster, NLB)
// Note: This stack requires the Route 53 hosted zone ID for nats.vettid.dev
// To deploy, provide the hosted zone ID via context or environment variable
const nats = new NatsStack(app, 'VettID-NATS', {
  env,
  domainName: 'nats.vettid.dev',
  hostedZoneId: app.node.tryGetContext('hostedZoneId') || process.env.HOSTED_ZONE_ID || 'PLACEHOLDER',
  zoneName: 'vettid.dev',
});
