#!/usr/bin/env npx ts-node
/**
 * Generate NATS Credentials for Test App Client
 *
 * Creates credentials that simulate a mobile app for testing purposes.
 * The app client can:
 * - Publish to OwnerSpace.*.forVault.> (send to vault)
 * - Subscribe to OwnerSpace.*.forApp.> (receive from vault)
 *
 * Usage:
 *   npx ts-node scripts/generate-test-app-creds.ts
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nkeys from 'nkeys.js';
import { createHash, randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const OPERATOR_SECRET_ID = 'vettid/nats/operator-key';

const secretsClient = new SecretsManagerClient({});

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

async function generateTestAppCredentials(): Promise<string> {
  const secrets = await getOperatorSecrets();

  // Create user key pair for the test app
  const userKeyPair = nkeys.createUser();
  const seed = new TextDecoder().decode(userKeyPair.getSeed());
  const publicKey = userKeyPair.getPublicKey();

  // Get account keypair for signing
  const accountKeyPair = nkeys.fromSeed(new TextEncoder().encode(secrets.backend_account_seed));

  const now = Math.floor(Date.now() / 1000);
  // Short-lived for testing: 1 day
  const exp = now + 86400;

  // SECURITY: JTI includes randomness to prevent collisions
  const jti = createHash('sha256')
    .update(`test-app-${publicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  // Test app needs to simulate a mobile client
  const claims: NatsUserClaims = {
    jti,
    iat: now,
    exp,
    iss: secrets.backend_account_public_key,
    sub: publicKey,
    name: 'test-app-client',
    nats: {
      pub: {
        allow: [
          // Publish to vault (like mobile app does)
          'OwnerSpace.*.forVault.>',
          // Publish to MessageSpace for connections
          'MessageSpace.*.forOwner.>',
        ],
      },
      sub: {
        allow: [
          // Subscribe to receive from vault (like mobile app does)
          'OwnerSpace.*.forApp.>',
          // Subscribe to MessageSpace for connections
          'MessageSpace.*.forOwner.>',
        ],
      },
      subs: -1,
      data: -1,
      payload: -1,
      type: 'user',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  const jwt = encodeJwt(header, claims, accountKeyPair);
  return formatCredsFile(jwt, seed);
}

async function main(): Promise<void> {
  console.log('=== VettID Test App NATS Credentials Generator ===\n');

  console.log('Generating NATS credentials for test app client...');
  const creds = await generateTestAppCredentials();

  // Write to file
  const outputPath = path.join(__dirname, 'test-app-nats.creds');
  fs.writeFileSync(outputPath, creds, { mode: 0o600 });

  console.log(`\nCredentials written to: ${outputPath}`);
  console.log('\nThis credential allows:');
  console.log('  - Publish to: OwnerSpace.*.forVault.>');
  console.log('  - Subscribe to: OwnerSpace.*.forApp.>');
  console.log('\nUse for testing call signaling flow.');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
