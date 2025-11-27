#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { InfrastructureStack } from '../lib/infrastructure-stack';
import { VettIdStack } from '../lib/vettid-stack';

const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'us-east-1'
};

// Deploy infrastructure stack first (DynamoDB tables, S3 buckets)
const infrastructure = new InfrastructureStack(app, 'VettID-Infrastructure', { env });

// Deploy main stack (depends on infrastructure)
new VettIdStack(app, 'VettIDStack', {
  env,
  infrastructure, // Pass infrastructure for resource access
});
