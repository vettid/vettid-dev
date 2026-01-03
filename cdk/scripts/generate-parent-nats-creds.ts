#!/usr/bin/env npx ts-node
/**
 * Generate NATS Credentials for Nitro Enclave Parent Process
 *
 * This script generates NATS credentials for the parent process running on
 * Nitro Enclave host instances. The parent acts as a bridge between NATS and
 * the enclave, forwarding messages to vault processes inside the enclave.
 *
 * The parent uses the Backend Account and needs broad permissions to:
 * - Subscribe to all OwnerSpace.*.forVault.> (messages from apps)
 * - Publish to all OwnerSpace.*.forApp.> (responses to apps)
 * - Subscribe to OwnerSpace.*.forServices.> (health/status from vaults)
 * - Handle MessageSpace traffic for connections
 *
 * Usage:
 *   npx ts-node scripts/generate-parent-nats-creds.ts
 *   npx ts-node scripts/generate-parent-nats-creds.ts --regenerate
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SSMClient, PutParameterCommand, GetParameterCommand } from '@aws-sdk/client-ssm';
import * as nkeys from 'nkeys.js';
import { createHash } from 'crypto';

const OPERATOR_SECRET_ID = 'vettid/nats/operator-key';
const PARENT_CREDS_PARAM = '/vettid/nitro/parent-nats-creds';

const secretsClient = new SecretsManagerClient({});
const ssmClient = new SSMClient({});

interface OperatorSecrets {
  operator_seed: string;
  operator_public_key: string;
  backend_account_seed: string;
  backend_account_public_key: string;
  backend_account_jwt: string;
}

interface NatsUserClaims {
  jti: string;
  iat: number;
  exp: number;
  iss: string;
  sub: string;
  name: string;
  nats: {
    pub?: { allow?: string[]; deny?: string[] };
    sub?: { allow?: string[]; deny?: string[] };
    subs?: number;
    data?: number;
    payload?: number;
    type?: string;
    version?: number;
  };
}

function encodeJwt(header: object, payload: object, signingKey: nkeys.KeyPair): string {
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const dataToSign = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = signingKey.sign(dataToSign);
  const signatureB64 = Buffer.from(signature).toString('base64url');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function getOperatorSecrets(): Promise<OperatorSecrets> {
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: OPERATOR_SECRET_ID,
  }));

  if (!response.SecretString) {
    throw new Error('NATS operator secret is empty');
  }

  const secret = JSON.parse(response.SecretString);

  if (!secret.backend_account_seed) {
    throw new Error('Backend account not initialized. Run: npx ts-node scripts/init-nats-operator.ts');
  }

  return secret as OperatorSecrets;
}

function formatCredsFile(jwt: string, seed: string): string {
  return `-----BEGIN NATS USER JWT-----
${jwt}
-----END NATS USER JWT-----

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
${seed}
-----END USER NKEY SEED-----
`;
}

async function generateParentCredentials(): Promise<{ creds: string; expiresAt: Date }> {
  const secrets = await getOperatorSecrets();

  // Create user key pair for the parent process
  const userKeyPair = nkeys.createUser();
  const seed = new TextDecoder().decode(userKeyPair.getSeed());
  const publicKey = userKeyPair.getPublicKey();

  // Get account keypair for signing
  const accountKeyPair = nkeys.fromSeed(new TextEncoder().encode(secrets.backend_account_seed));

  const now = Math.floor(Date.now() / 1000);
  // Long-lived credentials: 1 year (parent instances don't change frequently)
  const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  const exp = Math.floor(expiresAt.getTime() / 1000);

  const jti = createHash('sha256')
    .update(`parent-${publicKey}:${now}`)
    .digest('hex')
    .substring(0, 22);

  // Parent process needs broad permissions to handle all vault traffic
  // It acts as a bridge between NATS and the enclave
  const claims: NatsUserClaims = {
    jti,
    iat: now,
    exp,
    iss: secrets.backend_account_public_key,
    sub: publicKey,
    name: 'nitro-parent',
    nats: {
      pub: {
        allow: [
          // Publish responses back to apps (includes call signaling)
          'OwnerSpace.*.forApp.>',
          // Publish to MessageSpace for connections
          'MessageSpace.*.forOwner.>',
          'MessageSpace.*.ownerProfile',
          // Health/metrics to backend services
          'OwnerSpace.*.forServices.>',
        ],
      },
      sub: {
        allow: [
          // Subscribe to messages from apps (includes call signaling)
          'OwnerSpace.*.forVault.>',
          // Subscribe to control commands
          'OwnerSpace.*.control',
          // Subscribe to event type queries
          'OwnerSpace.*.eventTypes',
          // Subscribe to MessageSpace for connections
          'MessageSpace.*.forOwner.>',
          // Subscribe to health check requests
          'OwnerSpace.*.forServices.>',
        ],
      },
      subs: -1,      // Unlimited subscriptions
      data: -1,      // Unlimited data
      payload: -1,   // Unlimited payload
      type: 'user',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  const jwt = encodeJwt(header, claims, accountKeyPair);
  const creds = formatCredsFile(jwt, seed);

  return { creds, expiresAt };
}

async function checkExistingCredentials(): Promise<boolean> {
  try {
    await ssmClient.send(new GetParameterCommand({
      Name: PARENT_CREDS_PARAM,
      WithDecryption: true,
    }));
    return true;
  } catch (error: any) {
    if (error.name === 'ParameterNotFound') {
      return false;
    }
    throw error;
  }
}

async function storeCredentials(creds: string, expiresAt: Date, isNew: boolean): Promise<void> {
  if (isNew) {
    // Create new parameter with tags
    await ssmClient.send(new PutParameterCommand({
      Name: PARENT_CREDS_PARAM,
      Description: `NATS credentials for Nitro Enclave parent process. Expires: ${expiresAt.toISOString()}`,
      Value: creds,
      Type: 'SecureString',
      Tags: [
        { Key: 'Application', Value: 'vettid' },
        { Key: 'Component', Value: 'nitro-parent' },
      ],
    }));
  } else {
    // Update existing parameter (no tags allowed with overwrite)
    await ssmClient.send(new PutParameterCommand({
      Name: PARENT_CREDS_PARAM,
      Description: `NATS credentials for Nitro Enclave parent process. Expires: ${expiresAt.toISOString()}`,
      Value: creds,
      Type: 'SecureString',
      Overwrite: true,
    }));
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const regenerate = args.includes('--regenerate');

  console.log('=== VettID Nitro Parent NATS Credentials Generator ===\n');

  // Check if credentials already exist
  const exists = await checkExistingCredentials();

  if (exists && !regenerate) {
    console.log(`Credentials already exist at SSM parameter: ${PARENT_CREDS_PARAM}`);
    console.log('Use --regenerate to create new credentials.');
    return;
  }

  if (exists) {
    console.log('Regenerating credentials (existing credentials will be replaced)...\n');
  }

  // Generate new credentials
  console.log('Generating NATS credentials for parent process...');
  const { creds, expiresAt } = await generateParentCredentials();

  // Store in SSM
  console.log(`Storing credentials in SSM parameter: ${PARENT_CREDS_PARAM}`);
  await storeCredentials(creds, expiresAt, !exists);

  console.log('\n=== Success ===');
  console.log(`Credentials stored at: ${PARENT_CREDS_PARAM}`);
  console.log(`Expires at: ${expiresAt.toISOString()}`);
  console.log('\nParent instances will fetch credentials on startup.');
  console.log('Restart existing instances to pick up new credentials.');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
