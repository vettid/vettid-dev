#!/usr/bin/env npx ts-node
/**
 * NATS Operator Key Rotation Script
 *
 * This script rotates the NATS operator keys. This is a CRITICAL operation that:
 * 1. Generates new operator and system/backend account keys
 * 2. Re-signs ALL existing account JWTs in DynamoDB
 * 3. Updates the Secrets Manager secret
 * 4. Requires NATS server restart to take effect
 *
 * SECURITY: This script should only be run in emergency situations:
 * - Operator key compromise detected
 * - Regular key rotation (annually recommended)
 * - Security audit requirement
 *
 * IMPACT:
 * - All connected clients will need to reconnect
 * - New account JWTs must be distributed
 * - NATS servers must be restarted
 *
 * Usage:
 *   # Dry run (no changes made)
 *   npx ts-node scripts/rotate-nats-operator.ts --dry-run
 *
 *   # Execute rotation
 *   npx ts-node scripts/rotate-nats-operator.ts --execute --confirm-rotation
 *
 *   # Emergency rotation (faster, less validation)
 *   npx ts-node scripts/rotate-nats-operator.ts --emergency --confirm-rotation
 */

import {
  SecretsManagerClient,
  PutSecretValueCommand,
  GetSecretValueCommand,
  DescribeSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  DynamoDBClient,
  ScanCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import * as nkeys from 'nkeys.js';
import { createHash } from 'crypto';

const REGION = process.env.AWS_REGION || 'us-east-1';
const OPERATOR_SECRET_ID = 'vettid/nats/operator-key';
const NATS_ACCOUNTS_TABLE = process.env.NATS_ACCOUNTS_TABLE || 'VettID-Infrastructure-NatsAccountsTableFBA66D91-REPLACE';

const secretsClient = new SecretsManagerClient({ region: REGION });
const ddbClient = new DynamoDBClient({ region: REGION });

// Rotation state
interface RotationState {
  dryRun: boolean;
  emergency: boolean;
  confirmed: boolean;
  oldOperatorPublicKey?: string;
  newOperatorPublicKey?: string;
  accountsRotated: number;
  accountsFailed: number;
  startTime: Date;
}

/**
 * Encode a NATS JWT with Ed25519 signature
 */
function encodeJwt(header: object, payload: object, signingKey: nkeys.KeyPair): string {
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const dataToSign = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = signingKey.sign(dataToSign);
  const signatureB64 = Buffer.from(signature).toString('base64url');
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/**
 * Create operator JWT
 */
function createOperatorJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  systemAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256').update(`${operatorPublicKey}:${now}`).digest('hex').substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: operatorPublicKey,
    name: 'VettID',
    nats: {
      type: 'operator',
      version: 2,
      system_account: systemAccountPublicKey,
      account_server_url: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com/nats/jwt/v1/accounts/',
    },
  };

  return encodeJwt({ typ: 'JWT', alg: 'ed25519-nkey' }, claims, operatorKeyPair);
}

/**
 * Create system account JWT
 */
function createSystemAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  systemAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256').update(`${systemAccountPublicKey}:${now}`).digest('hex').substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: systemAccountPublicKey,
    name: 'SYS',
    nats: {
      limits: { subs: -1, data: -1, payload: -1, imports: -1, exports: -1, wildcards: true, conn: -1, leaf: -1 },
      exports: [
        { name: 'account-monitoring-streams', subject: '$SYS.ACCOUNT.*.>', type: 'stream', account_token_position: 3 },
        { name: 'account-monitoring-services', subject: '$SYS.REQ.ACCOUNT.*.*', type: 'service', account_token_position: 4 },
      ],
      type: 'account',
      version: 2,
    },
  };

  return encodeJwt({ typ: 'JWT', alg: 'ed25519-nkey' }, claims, operatorKeyPair);
}

/**
 * Create backend account JWT with JetStream
 */
function createBackendAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  backendAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256').update(`${backendAccountPublicKey}:${now}`).digest('hex').substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: backendAccountPublicKey,
    name: 'BACKEND',
    nats: {
      limits: {
        subs: -1, data: -1, payload: -1, imports: -1, exports: -1, wildcards: true, conn: 10, leaf: -1,
        mem_storage: -1, disk_storage: -1, streams: -1, consumer: -1,
      },
      default_permissions: {
        pub: { allow: ['OwnerSpace.*.forServices.>', '$JS.API.>'] },
        sub: { allow: ['OwnerSpace.*.forServices.>', '$JS.API.>', '_INBOX.>'] },
      },
      type: 'account',
      version: 2,
    },
  };

  return encodeJwt({ typ: 'JWT', alg: 'ed25519-nkey' }, claims, operatorKeyPair);
}

/**
 * Create account JWT for a member account
 */
function createAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  accountPublicKey: string,
  accountName: string,
  revocations?: { [key: string]: number }
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256').update(`${accountPublicKey}:${now}`).digest('hex').substring(0, 22);

  const claims: any = {
    jti,
    iat: now,
    exp: now + (30 * 24 * 60 * 60), // 30 days
    iss: operatorPublicKey,
    sub: accountPublicKey,
    name: accountName,
    nats: {
      limits: {
        subs: 100, data: 10_000_000, payload: 1_048_576, imports: 10, exports: 10,
        wildcards: true, conn: 10, leaf: 0,
      },
      type: 'account',
      version: 2,
    },
  };

  if (revocations && Object.keys(revocations).length > 0) {
    claims.nats.revocations = revocations;
  }

  return encodeJwt({ typ: 'JWT', alg: 'ed25519-nkey' }, claims, operatorKeyPair);
}

/**
 * Rotate all member accounts in DynamoDB
 */
async function rotateAllAccounts(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  state: RotationState
): Promise<void> {
  console.log('\n=== Rotating Member Account JWTs ===');

  let lastEvaluatedKey: any = undefined;
  let totalScanned = 0;

  do {
    const scanResult = await ddbClient.send(new ScanCommand({
      TableName: NATS_ACCOUNTS_TABLE,
      ExclusiveStartKey: lastEvaluatedKey,
    }));

    const items = scanResult.Items || [];
    totalScanned += items.length;

    for (const item of items) {
      const account = unmarshall(item);

      try {
        // Re-sign the account JWT with new operator
        const accountName = account.account_name || `account-${account.user_guid?.substring(0, 8) || 'unknown'}`;
        const newJwt = createAccountJwt(
          operatorKeyPair,
          operatorPublicKey,
          account.account_public_key,
          accountName,
          account.revocations
        );

        if (state.dryRun) {
          console.log(`  [DRY RUN] Would rotate: ${accountName} (${account.account_public_key?.substring(0, 12)}...)`);
          state.accountsRotated++;
        } else {
          // Update the account JWT in DynamoDB
          await ddbClient.send(new UpdateItemCommand({
            TableName: NATS_ACCOUNTS_TABLE,
            Key: marshall({ user_guid: account.user_guid }),
            UpdateExpression: 'SET account_jwt = :jwt, updated_at = :now, rotated_at = :now, rotation_reason = :reason',
            ExpressionAttributeValues: marshall({
              ':jwt': newJwt,
              ':now': new Date().toISOString(),
              ':reason': state.emergency ? 'emergency_rotation' : 'scheduled_rotation',
            }),
          }));

          console.log(`  Rotated: ${accountName} (${account.account_public_key?.substring(0, 12)}...)`);
          state.accountsRotated++;
        }
      } catch (error: any) {
        console.error(`  FAILED: ${account.user_guid}: ${error.message}`);
        state.accountsFailed++;
      }
    }

    lastEvaluatedKey = scanResult.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  console.log(`\nScanned ${totalScanned} accounts`);
  console.log(`Rotated: ${state.accountsRotated}, Failed: ${state.accountsFailed}`);
}

/**
 * Main rotation function
 */
async function main() {
  console.log('=== NATS Operator Key Rotation ===');
  console.log(`Region: ${REGION}`);
  console.log(`Time: ${new Date().toISOString()}\n`);

  // Parse arguments
  const args = process.argv.slice(2);
  const state: RotationState = {
    dryRun: args.includes('--dry-run') || (!args.includes('--execute') && !args.includes('--emergency')),
    emergency: args.includes('--emergency'),
    confirmed: args.includes('--confirm-rotation'),
    accountsRotated: 0,
    accountsFailed: 0,
    startTime: new Date(),
  };

  if (!state.confirmed && !state.dryRun) {
    console.error('ERROR: Rotation requires --confirm-rotation flag');
    console.error('This is a destructive operation that will:');
    console.error('  - Invalidate ALL existing NATS JWTs');
    console.error('  - Require NATS server restart');
    console.error('  - Disconnect all connected clients');
    console.error('\nRun with --dry-run first to preview changes.');
    process.exit(1);
  }

  if (state.dryRun) {
    console.log('*** DRY RUN MODE - No changes will be made ***\n');
  }

  if (state.emergency) {
    console.log('*** EMERGENCY ROTATION MODE ***\n');
  }

  // Get current operator secret
  console.log('Fetching current operator secret...');
  let currentSecret: any;
  try {
    const response = await secretsClient.send(new GetSecretValueCommand({
      SecretId: OPERATOR_SECRET_ID,
    }));
    currentSecret = JSON.parse(response.SecretString || '{}');
    state.oldOperatorPublicKey = currentSecret.operator_public_key;
    console.log(`Current operator: ${state.oldOperatorPublicKey?.substring(0, 16)}...`);
  } catch (error: any) {
    console.error(`Failed to get current secret: ${error.message}`);
    process.exit(1);
  }

  // Generate new operator keys
  console.log('\nGenerating new operator key pair...');
  const newOperatorKeyPair = nkeys.createOperator();
  const newOperatorSeed = new TextDecoder().decode(newOperatorKeyPair.getSeed());
  const newOperatorPublicKey = newOperatorKeyPair.getPublicKey();
  state.newOperatorPublicKey = newOperatorPublicKey;

  console.log(`New operator: ${newOperatorPublicKey.substring(0, 16)}...`);

  // Generate new system account
  console.log('Generating new system account key pair...');
  const newSystemAccountKeyPair = nkeys.createAccount();
  const newSystemAccountSeed = new TextDecoder().decode(newSystemAccountKeyPair.getSeed());
  const newSystemAccountPublicKey = newSystemAccountKeyPair.getPublicKey();

  // Generate new backend account
  console.log('Generating new backend account key pair...');
  const newBackendAccountKeyPair = nkeys.createAccount();
  const newBackendAccountSeed = new TextDecoder().decode(newBackendAccountKeyPair.getSeed());
  const newBackendAccountPublicKey = newBackendAccountKeyPair.getPublicKey();

  // Generate JWTs
  console.log('Generating new JWTs...');
  const newOperatorJwt = createOperatorJwt(newOperatorKeyPair, newOperatorPublicKey, newSystemAccountPublicKey);
  const newSystemAccountJwt = createSystemAccountJwt(newOperatorKeyPair, newOperatorPublicKey, newSystemAccountPublicKey);
  const newBackendAccountJwt = createBackendAccountJwt(newOperatorKeyPair, newOperatorPublicKey, newBackendAccountPublicKey);

  // Rotate all member accounts
  await rotateAllAccounts(newOperatorKeyPair, newOperatorPublicKey, state);

  // Update Secrets Manager
  if (!state.dryRun) {
    console.log('\nUpdating Secrets Manager...');

    const newSecretValue = {
      // New operator keys
      operator_seed: newOperatorSeed,
      operator_public_key: newOperatorPublicKey,
      operator_jwt: newOperatorJwt,
      // New system account
      system_account_seed: newSystemAccountSeed,
      system_account_public_key: newSystemAccountPublicKey,
      system_account_jwt: newSystemAccountJwt,
      // New backend account
      backend_account_seed: newBackendAccountSeed,
      backend_account_public_key: newBackendAccountPublicKey,
      backend_account_jwt: newBackendAccountJwt,
      // Rotation metadata
      rotated_at: new Date().toISOString(),
      rotation_reason: state.emergency ? 'emergency' : 'scheduled',
      previous_operator_public_key: state.oldOperatorPublicKey,
      created_at: currentSecret.created_at,
    };

    await secretsClient.send(new PutSecretValueCommand({
      SecretId: OPERATOR_SECRET_ID,
      SecretString: JSON.stringify(newSecretValue),
    }));

    console.log('Secrets Manager updated successfully');
  }

  // Summary
  const duration = (new Date().getTime() - state.startTime.getTime()) / 1000;
  console.log('\n=== Rotation Summary ===');
  console.log(`Mode: ${state.dryRun ? 'DRY RUN' : state.emergency ? 'EMERGENCY' : 'STANDARD'}`);
  console.log(`Duration: ${duration.toFixed(1)} seconds`);
  console.log(`Old Operator: ${state.oldOperatorPublicKey?.substring(0, 16)}...`);
  console.log(`New Operator: ${state.newOperatorPublicKey?.substring(0, 16)}...`);
  console.log(`New System Account: ${newSystemAccountPublicKey.substring(0, 16)}...`);
  console.log(`New Backend Account: ${newBackendAccountPublicKey.substring(0, 16)}...`);
  console.log(`Accounts Rotated: ${state.accountsRotated}`);
  console.log(`Accounts Failed: ${state.accountsFailed}`);

  if (!state.dryRun) {
    console.log('\n=== NEXT STEPS (REQUIRED) ===');
    console.log('1. Restart NATS servers to load new operator:');
    console.log('   aws autoscaling start-instance-refresh --auto-scaling-group-name <NATS_ASG_NAME>');
    console.log('');
    console.log('2. Verify NATS cluster is healthy:');
    console.log('   nats server check connection -s tls://nats.vettid.dev:4222');
    console.log('');
    console.log('3. Monitor for client reconnection issues in CloudWatch');
    console.log('');
    console.log('4. Invalidate Lambda nats-jwt.ts cache:');
    console.log('   # Lambdas will auto-refresh on next invocation (5 min cache)');
  }
}

main().catch((error) => {
  console.error('Rotation failed:', error);
  process.exit(1);
});
