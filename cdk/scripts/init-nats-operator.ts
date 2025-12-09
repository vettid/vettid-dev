#!/usr/bin/env npx ts-node
/**
 * Initialize NATS Operator Keys
 *
 * This script creates the NATS operator and system account keys and stores them
 * in AWS Secrets Manager. These keys are used to sign account and user JWTs
 * for NATS authentication.
 *
 * Run once after deploying the NATS stack:
 *   npx ts-node scripts/init-nats-operator.ts
 *
 * Key structure in Secrets Manager:
 *   vettid/nats/operator-key:
 *     - operator_seed: The operator's signing seed (SO...)
 *     - operator_public_key: The operator's public key (O...)
 *     - system_account_seed: System account signing seed (SA...)
 *     - system_account_public_key: System account public key (A...)
 */

import { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nkeys from 'nkeys.js';

const REGION = process.env.AWS_REGION || 'us-east-1';
const OPERATOR_SECRET_ID = 'vettid/nats/operator-key';

const secretsClient = new SecretsManagerClient({ region: REGION });

async function main() {
  console.log('Initializing NATS operator keys...');
  console.log(`Region: ${REGION}`);
  console.log(`Secret ID: ${OPERATOR_SECRET_ID}`);

  // Check if keys already exist
  try {
    const existing = await secretsClient.send(new GetSecretValueCommand({
      SecretId: OPERATOR_SECRET_ID,
    }));

    if (existing.SecretString) {
      const data = JSON.parse(existing.SecretString);
      if (data.operator_seed && !data.placeholder) {
        console.log('\nOperator keys already exist!');
        console.log(`Operator Public Key: ${data.operator_public_key}`);
        console.log(`System Account Public Key: ${data.system_account_public_key}`);
        console.log('\nTo regenerate, first delete the secret or clear its values.');
        return;
      }
    }
  } catch (error: any) {
    if (error.name !== 'ResourceNotFoundException') {
      throw error;
    }
    // Secret doesn't exist, will create
  }

  // Generate operator key pair
  console.log('\nGenerating operator key pair...');
  const operatorKeyPair = nkeys.createOperator();
  const operatorSeed = new TextDecoder().decode(operatorKeyPair.getSeed());
  const operatorPublicKey = operatorKeyPair.getPublicKey();

  // Generate system account key pair
  console.log('Generating system account key pair...');
  const systemAccountKeyPair = nkeys.createAccount();
  const systemAccountSeed = new TextDecoder().decode(systemAccountKeyPair.getSeed());
  const systemAccountPublicKey = systemAccountKeyPair.getPublicKey();

  // Store in Secrets Manager
  const secretValue = {
    operator_seed: operatorSeed,
    operator_public_key: operatorPublicKey,
    system_account_seed: systemAccountSeed,
    system_account_public_key: systemAccountPublicKey,
    created_at: new Date().toISOString(),
  };

  console.log('\nStoring keys in Secrets Manager...');
  await secretsClient.send(new PutSecretValueCommand({
    SecretId: OPERATOR_SECRET_ID,
    SecretString: JSON.stringify(secretValue),
  }));

  console.log('\n=== Keys Generated Successfully ===');
  console.log(`Operator Public Key: ${operatorPublicKey}`);
  console.log(`System Account Public Key: ${systemAccountPublicKey}`);
  console.log('\nThese keys are now stored in AWS Secrets Manager.');
  console.log('The Lambda functions will use them to sign NATS JWTs.');

  // Output configuration for NATS server (if needed)
  console.log('\n=== NATS Server Configuration ===');
  console.log('Add this to your NATS server config if using resolver preload:');
  console.log(`\noperator: ${operatorPublicKey}`);
  console.log(`system_account: ${systemAccountPublicKey}`);
}

main().catch((error) => {
  console.error('Error initializing NATS operator:', error);
  process.exit(1);
});
