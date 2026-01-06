#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';
import { AdminStack } from '../lib/admin-stack';
import { VaultStack } from '../lib/vault-stack';
import { NatsStack } from '../lib/nats-stack';
import { LedgerStack } from '../lib/ledger-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { NitroStack } from '../lib/nitro-stack';

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

// 5. Deploy Nitro Enclave stack (multi-tenant vault architecture)
// This creates the VPC, ALB, and S3 bucket for Nitro Enclave instances
// Moved before AdminStack to allow PCR manifest management
const nitro = new NitroStack(app, 'VettID-Nitro', {
  env,
  infrastructure, // For dynamic handler loading (DynamoDB manifest, S3 handlers)
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

// 6. Deploy NATS infrastructure stack (VPC, EC2 cluster, NLB)
// Uses Route53 fromLookup to auto-discover hosted zone (cached in cdk.context.json)
// VPC peering with Nitro VPC to allow enclave parent processes to connect to NATS
const nats = new NatsStack(app, 'VettID-NATS', {
  env,
  domainName: 'nats.vettid.dev',
  zoneName: 'vettid.dev',
  // URL resolver for member account JWTs (fetched dynamically)
  accountResolverUrl: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com/nats/jwt/v1/accounts/',
  // VPC peering: allow Nitro enclave parent processes to connect to NATS cluster
  nitroVpc: nitro.vpc,
  nitroVpcCidr: NitroStack.VPC_CIDR,
});

// 7. Deploy vault stack (vault Lambda functions + API routes)
// Routes are added in VaultStack to stay under CloudFormation's 500 resource limit
// Pass ledger stack to enable Protean Credential System Lambda handlers
const vault = new VaultStack(app, 'VettID-Vault', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  memberAuthorizer: core.memberAuthorizer,
  ledger,
  nitro,  // For enclave communication
});

// 8. Deploy monitoring stack (CloudWatch dashboard and alarms)
// Optional: pass alarmEmail to receive alert notifications
const monitoring = new MonitoringStack(app, 'VettID-Monitoring', {
  env,
  // alarmEmail: 'alerts@vettid.dev',  // Uncomment to enable email alerts

  // Stack integration - pass resources from other stacks for enhanced monitoring
  httpApi: core.httpApi,

  // Optional: Override default ASG names if different
  // natsAsgName: 'VettID-NATS-NatsAsg',
});
