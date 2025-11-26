#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { VettIdStack } from '../lib/vettid-stack';

const app = new cdk.App();
new VettIdStack(app, 'VettIDStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION || 'us-east-1' }
});
