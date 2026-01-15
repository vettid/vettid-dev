#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';
import { AdminManagementStack } from '../lib/admin-management-stack';
import { BusinessGovernanceStack } from '../lib/business-governance-stack';
import { ExtensibilityMonitoringStack } from '../lib/extensibility-monitoring-stack';
import { VaultStack } from '../lib/vault-stack';
import { NatsStack } from '../lib/nats-stack';
// LedgerStack removed - legacy Protean Credential System replaced by vault-manager JetStream
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

// 3. Deploy admin stacks (admin Lambda functions + API routes)
// Split into 3 stacks to stay under CloudFormation's 500 resource limit:
// - AdminManagementStack: User/admin lifecycle, registration, invites (~155 resources)
// - BusinessGovernanceStack: Memberships, proposals, subscriptions (~111 resources)
// - ExtensibilityMonitoringStack: NATS, handlers, services, security (~150 resources)
const adminManagement = new AdminManagementStack(app, 'VettID-AdminManagement', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  adminAuthorizer: core.adminAuthorizer,
});

const businessGovernance = new BusinessGovernanceStack(app, 'VettID-BusinessGovernance', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  adminAuthorizer: core.adminAuthorizer,
});

const extensibilityMonitoring = new ExtensibilityMonitoringStack(app, 'VettID-ExtensibilityMonitoring', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  adminAuthorizer: core.adminAuthorizer,
});

// 6. Deploy NATS infrastructure stack (VPC, EC2 cluster, NLB)
// Uses Route53 fromLookup to auto-discover hosted zone (cached in cdk.context.json)
// VPC peering with Nitro VPC to allow enclave parent processes to connect to NATS
const nats = new NatsStack(app, 'VettID-NATS', {
  env,
  domainName: 'nats.vettid.dev',
  zoneName: 'vettid.dev',
  // SECURITY: Dynamic URL resolver using the actual API Gateway ID (not hardcoded)
  // This ensures the URL stays in sync if API Gateway is recreated
  accountResolverUrl: `https://${core.httpApi.apiId}.execute-api.${env.region || 'us-east-1'}.amazonaws.com/nats/jwt/v1/accounts/`,
  // VPC peering: allow Nitro enclave parent processes to connect to NATS cluster
  nitroVpc: nitro.vpc,
  nitroVpcCidr: NitroStack.VPC_CIDR,
  // Use pre-built NATS AMI from SSM parameter (created by scripts/deploy-nats-ami.sh)
  amiSsmParameter: '/vettid/nats/ami-id',
});

// 7. Deploy vault stack (vault Lambda functions + API routes)
// Routes are added in VaultStack to stay under CloudFormation's 500 resource limit
const vault = new VaultStack(app, 'VettID-Vault', {
  env,
  infrastructure,
  httpApi: core.httpApi,
  memberAuthorizer: core.memberAuthorizer,
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
