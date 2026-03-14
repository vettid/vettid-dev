#!/usr/bin/env npx ts-node
/**
 * Initialize NATS Operator Keys
 *
 * This script creates the NATS operator, system account, and backend account keys
 * and stores them in AWS Secrets Manager. These keys are used to sign account and
 * user JWTs for NATS authentication.
 *
 * Run once after deploying the NATS stack:
 *   npx ts-node scripts/init-nats-operator.ts
 *
 * Key structure in Secrets Manager:
 *   vettid/nats/operator-key:
 *     - operator_seed: The operator's signing seed (SO...)
 *     - operator_public_key: The operator's public key (O...)
 *     - operator_jwt: The operator JWT (self-signed)
 *     - system_account_seed: System account signing seed (SA...)
 *     - system_account_public_key: System account public key (A...)
 *     - system_account_jwt: System account JWT (signed by operator)
 *     - backend_account_seed: Backend account signing seed (SA...)
 *     - backend_account_public_key: Backend account public key (A...)
 *     - backend_account_jwt: Backend account JWT with JetStream enabled
 */

import { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nkeys from 'nkeys.js';
import { createHash, randomUUID } from 'crypto';

const REGION = process.env.AWS_REGION || 'us-east-1';
const OPERATOR_SECRET_ID = 'vettid/nats/operator-key';

const secretsClient = new SecretsManagerClient({ region: REGION });

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
 * Create an operator JWT (self-signed)
 */
function createOperatorJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  systemAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256')
    .update(`${operatorPublicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,  // Self-signed
    sub: operatorPublicKey,
    name: 'VettID',
    nats: {
      type: 'operator',
      version: 2,
      system_account: systemAccountPublicKey,
      account_server_url: 'https://tiqpij5mue.execute-api.us-east-1.amazonaws.com/nats/jwt/v1/accounts/',
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  return encodeJwt(header, claims, operatorKeyPair);
}

/**
 * Create a system account JWT (signed by operator)
 */
function createSystemAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  systemAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256')
    .update(`${systemAccountPublicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  // Note: JetStream CANNOT be enabled on system account - NATS rejects it
  // Use a separate "backend" account for JetStream operations
  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: systemAccountPublicKey,
    name: 'SYS',
    nats: {
      limits: {
        subs: -1,
        data: -1,
        payload: -1,
        imports: -1,
        exports: -1,
        wildcards: true,
        conn: -1,
        leaf: -1,
      },
      exports: [
        { name: 'account-monitoring-streams', subject: '$SYS.ACCOUNT.*.>', type: 'stream', account_token_position: 3 },
        { name: 'account-monitoring-services', subject: '$SYS.REQ.ACCOUNT.*.*', type: 'service', account_token_position: 4 },
      ],
      type: 'account',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  return encodeJwt(header, claims, operatorKeyPair);
}

/**
 * Create a backend account JWT (signed by operator) with JetStream enabled
 * This account is used by Lambda functions for JetStream operations (health monitoring)
 */
function createBackendAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  backendAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256')
    .update(`${backendAccountPublicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: backendAccountPublicKey,
    name: 'BACKEND',
    nats: {
      limits: {
        subs: -1,
        data: -1,
        payload: -1,
        imports: -1,
        exports: -1,
        wildcards: true,
        conn: 10,  // Limited connections for backend services
        leaf: -1,
        // JetStream limits (inside limits object, not separate)
        // These field names are what NATS expects for account JWTs
        mem_storage: -1,        // Unlimited memory storage (use -1 for no limit)
        disk_storage: -1,       // Unlimited disk storage (use -1 for no limit)
        streams: -1,            // Unlimited streams
        consumer: -1,           // Unlimited consumers
      },
      // Default permissions - can subscribe to health topics
      default_permissions: {
        pub: {
          allow: [
            'OwnerSpace.*.forServices.>',  // Health messages from vaults
            '$JS.API.>',                    // JetStream API
          ],
        },
        sub: {
          allow: [
            'OwnerSpace.*.forServices.>',  // Health messages from vaults
            '$JS.API.>',                    // JetStream API
            '_INBOX.>',                     // Reply subjects
          ],
        },
      },
      type: 'account',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  return encodeJwt(header, claims, operatorKeyPair);
}

/**
 * Create a guest account JWT (signed by operator)
 * This account is used by invitation scanners to fetch invitation data
 * from the INVITATIONS JetStream stream. Minimal permissions — subscribe only.
 */
function createGuestAccountJwt(
  operatorKeyPair: nkeys.KeyPair,
  operatorPublicKey: string,
  guestAccountPublicKey: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256')
    .update(`${guestAccountPublicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  const claims = {
    jti,
    iat: now,
    iss: operatorPublicKey,
    sub: guestAccountPublicKey,
    name: 'GUEST',
    nats: {
      limits: {
        subs: 10,
        data: 1_000_000,      // 1 MB/sec
        payload: 65536,        // 64 KB max message
        imports: 0,
        exports: 0,
        wildcards: false,      // No wildcard subscriptions
        conn: 100,             // Allow many concurrent scanners
        leaf: 0,
        mem_storage: -1,
        disk_storage: 0,
        streams: 0,            // Cannot create streams
        consumer: 10,          // Can create ephemeral consumers to read invitations
      },
      default_permissions: {
        pub: {
          allow: [
            // JetStream consumer API for INVITATIONS stream only
            '$JS.API.CONSUMER.CREATE.INVITATIONS',
            '$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>',
          ],
        },
        sub: {
          allow: [
            // JetStream consumer API for INVITATIONS stream only
            '$JS.API.CONSUMER.CREATE.INVITATIONS',
            '$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>',
            '$JS.API.STREAM.INFO.INVITATIONS',
          ],
        },
      },
      type: 'account',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  return encodeJwt(header, claims, operatorKeyPair);
}

/**
 * Generate a guest user JWT + seed for embedding in the app.
 * This user has minimal permissions to read invitation data.
 */
function generateGuestUserCredentials(
  guestAccountSeed: string,
  guestAccountPublicKey: string
): { jwt: string; seed: string } {
  const accountKeyPair = nkeys.fromSeed(new TextEncoder().encode(guestAccountSeed));
  const userKeyPair = nkeys.createUser();
  const userPublicKey = userKeyPair.getPublicKey();
  const userSeed = new TextDecoder().decode(userKeyPair.getSeed());

  const now = Math.floor(Date.now() / 1000);
  const LIFETIME_DAYS = 365; // Long-lived — rotated with operator rotation
  const exp = now + LIFETIME_DAYS * 24 * 60 * 60;
  const jti = createHash('sha256')
    .update(`guest-user-${userPublicKey}:${now}:${randomUUID()}`)
    .digest('hex')
    .substring(0, 22);

  const claims = {
    jti,
    iat: now,
    exp,
    iss: guestAccountPublicKey,
    sub: userPublicKey,
    name: 'guest-scanner',
    nats: {
      pub: {
        allow: [
          '$JS.API.CONSUMER.CREATE.INVITATIONS',
          '$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>',
        ],
      },
      sub: {
        allow: [
          '$JS.API.CONSUMER.CREATE.INVITATIONS',
          '$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>',
          '$JS.API.STREAM.INFO.INVITATIONS',
        ],
      },
      subs: 5,
      data: 1_000_000,
      payload: 65536,
      type: 'user',
      version: 2,
    },
  };

  const header = { typ: 'JWT', alg: 'ed25519-nkey' };
  const jwt = encodeJwt(header, claims, accountKeyPair);

  return { jwt, seed: userSeed };
}

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
        // Check if JWTs exist - if not, regenerate them with existing keys
        // Force regenerate JWTs if --regenerate flag passed or JWTs missing
        const forceRegenerate = process.argv.includes('--regenerate');
        const needsBackendAccount = !data.backend_account_seed || !data.backend_account_jwt;
        const needsGuestAccount = !data.guest_account_seed || !data.guest_account_jwt;

        if (!data.operator_jwt || !data.system_account_jwt || needsBackendAccount || needsGuestAccount || forceRegenerate) {
          console.log('\nRegenerating JWTs with updated claims...');
          const operatorKeyPair = nkeys.fromSeed(new TextEncoder().encode(data.operator_seed));
          const operatorJwt = createOperatorJwt(operatorKeyPair, data.operator_public_key, data.system_account_public_key);
          const systemAccountJwt = createSystemAccountJwt(operatorKeyPair, data.operator_public_key, data.system_account_public_key);

          // Generate backend account if it doesn't exist
          let backendAccountSeed = data.backend_account_seed;
          let backendAccountPublicKey = data.backend_account_public_key;

          if (!backendAccountSeed) {
            console.log('Generating new backend account key pair...');
            const backendAccountKeyPair = nkeys.createAccount();
            backendAccountSeed = new TextDecoder().decode(backendAccountKeyPair.getSeed());
            backendAccountPublicKey = backendAccountKeyPair.getPublicKey();
          }

          const backendAccountJwt = createBackendAccountJwt(operatorKeyPair, data.operator_public_key, backendAccountPublicKey);

          // Generate guest account if it doesn't exist
          let guestAccountSeed = data.guest_account_seed;
          let guestAccountPublicKey = data.guest_account_public_key;

          if (!guestAccountSeed) {
            console.log('Generating new guest account key pair...');
            const guestAccountKeyPair = nkeys.createAccount();
            guestAccountSeed = new TextDecoder().decode(guestAccountKeyPair.getSeed());
            guestAccountPublicKey = guestAccountKeyPair.getPublicKey();
          }

          const guestAccountJwt = createGuestAccountJwt(operatorKeyPair, data.operator_public_key, guestAccountPublicKey);
          const guestUserCreds = generateGuestUserCredentials(guestAccountSeed, guestAccountPublicKey);

          // Update secret with JWTs
          const updatedValue = {
            ...data,
            operator_jwt: operatorJwt,
            system_account_jwt: systemAccountJwt,
            backend_account_seed: backendAccountSeed,
            backend_account_public_key: backendAccountPublicKey,
            backend_account_jwt: backendAccountJwt,
            guest_account_seed: guestAccountSeed,
            guest_account_public_key: guestAccountPublicKey,
            guest_account_jwt: guestAccountJwt,
            guest_user_jwt: guestUserCreds.jwt,
            guest_user_seed: guestUserCreds.seed,
            updated_at: new Date().toISOString(),
          };

          await secretsClient.send(new PutSecretValueCommand({
            SecretId: OPERATOR_SECRET_ID,
            SecretString: JSON.stringify(updatedValue),
          }));

          console.log('\n=== JWTs Generated Successfully ===');
          console.log(`Operator Public Key: ${data.operator_public_key}`);
          console.log(`System Account Public Key: ${data.system_account_public_key}`);
          console.log(`Backend Account Public Key: ${backendAccountPublicKey}`);
          console.log(`Guest Account Public Key: ${guestAccountPublicKey}`);
          console.log(`\nGuest user JWT (for app embedding):`);
          console.log(`  JWT: ${guestUserCreds.jwt.substring(0, 50)}...`);
          console.log(`  Seed: ${guestUserCreds.seed}`);
          console.log('\nJWTs have been added to the existing secret.');
          return;
        }

        console.log('\nOperator keys and JWTs already exist!');
        console.log(`Operator Public Key: ${data.operator_public_key}`);
        console.log(`System Account Public Key: ${data.system_account_public_key}`);
        console.log(`Backend Account Public Key: ${data.backend_account_public_key || 'Not yet created'}`);
        console.log(`Operator JWT: ${data.operator_jwt.substring(0, 50)}...`);
        console.log('\nTo regenerate, use --regenerate flag.');
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

  // Generate backend account key pair (for Lambda JetStream operations)
  console.log('Generating backend account key pair...');
  const backendAccountKeyPair = nkeys.createAccount();
  const backendAccountSeed = new TextDecoder().decode(backendAccountKeyPair.getSeed());
  const backendAccountPublicKey = backendAccountKeyPair.getPublicKey();

  // Generate operator JWT (self-signed)
  console.log('Generating operator JWT...');
  const operatorJwt = createOperatorJwt(operatorKeyPair, operatorPublicKey, systemAccountPublicKey);

  // Generate system account JWT (signed by operator)
  console.log('Generating system account JWT...');
  const systemAccountJwt = createSystemAccountJwt(operatorKeyPair, operatorPublicKey, systemAccountPublicKey);

  // Generate backend account JWT (signed by operator, with JetStream enabled)
  console.log('Generating backend account JWT...');
  const backendAccountJwt = createBackendAccountJwt(operatorKeyPair, operatorPublicKey, backendAccountPublicKey);

  // Generate guest account key pair (for invitation scanner access)
  console.log('Generating guest account key pair...');
  const guestAccountKeyPair = nkeys.createAccount();
  const guestAccountSeed = new TextDecoder().decode(guestAccountKeyPair.getSeed());
  const guestAccountPublicKey = guestAccountKeyPair.getPublicKey();

  // Generate guest account JWT
  console.log('Generating guest account JWT...');
  const guestAccountJwt = createGuestAccountJwt(operatorKeyPair, operatorPublicKey, guestAccountPublicKey);

  // Generate guest user credentials (for embedding in the app)
  console.log('Generating guest user credentials...');
  const guestUserCreds = generateGuestUserCredentials(guestAccountSeed, guestAccountPublicKey);

  // Store in Secrets Manager
  const secretValue = {
    operator_seed: operatorSeed,
    operator_public_key: operatorPublicKey,
    operator_jwt: operatorJwt,
    system_account_seed: systemAccountSeed,
    system_account_public_key: systemAccountPublicKey,
    system_account_jwt: systemAccountJwt,
    backend_account_seed: backendAccountSeed,
    backend_account_public_key: backendAccountPublicKey,
    backend_account_jwt: backendAccountJwt,
    guest_account_seed: guestAccountSeed,
    guest_account_public_key: guestAccountPublicKey,
    guest_account_jwt: guestAccountJwt,
    guest_user_jwt: guestUserCreds.jwt,
    guest_user_seed: guestUserCreds.seed,
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
  console.log(`Backend Account Public Key: ${backendAccountPublicKey}`);
  console.log(`Guest Account Public Key: ${guestAccountPublicKey}`);
  console.log(`\nGuest user credentials (embed in app):`);
  console.log(`  JWT: ${guestUserCreds.jwt.substring(0, 50)}...`);
  console.log(`  Seed: ${guestUserCreds.seed}`);
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
