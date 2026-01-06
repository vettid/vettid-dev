/**
 * NATS Publisher Utility
 *
 * Provides functions to publish messages to NATS from Lambda functions.
 * Uses the system account credentials from Secrets Manager for publishing
 * system-wide broadcasts and control messages.
 *
 * The NATS cluster is accessible via TLS on port 443 through the NLB.
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { connect, NatsConnection, StringCodec, credsAuthenticator } from 'nats';
import * as nkeys from 'nkeys.js';
import { createHash } from 'crypto';

const OPERATOR_SECRET_ID = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';
const NATS_DOMAIN = process.env.NATS_DOMAIN || 'nats.vettid.dev';

const secretsClient = new SecretsManagerClient({});
const sc = StringCodec();

// Cache system credentials for Lambda reuse
let cachedSystemCreds: string | null = null;
let cacheTime = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface SystemCredentials {
  jwt: string;
  seed: string;
  creds: string;
}

interface NatsAccountClaims {
  jti: string;
  iat: number;
  exp?: number;
  iss: string;
  sub: string;
  name: string;
  nats: {
    limits?: object;
    type?: string;
    version?: number;
  };
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

/**
 * Encode a JWT without external libraries
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
 * Format credentials as NATS creds file content
 */
function formatCredsFile(jwt: string, seed: string): string {
  return `-----BEGIN NATS USER JWT-----
${jwt}
------END NATS USER JWT-----

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
${seed}
------END USER NKEY SEED-----
`;
}

/**
 * Get system credentials for publishing broadcasts
 * The system account has permissions to publish to Broadcast.* subjects
 */
async function getSystemCredentials(): Promise<SystemCredentials> {
  const now = Date.now();

  // Return cached credentials if still valid
  if (cachedSystemCreds && (now - cacheTime) < CACHE_TTL_MS) {
    const lines = cachedSystemCreds.split('\n');
    const jwtStart = lines.findIndex(l => l.includes('BEGIN NATS USER JWT'));
    const jwtEnd = lines.findIndex(l => l.includes('END NATS USER JWT'));
    const seedStart = lines.findIndex(l => l.includes('BEGIN USER NKEY SEED'));
    const seedEnd = lines.findIndex(l => l.includes('END USER NKEY SEED'));

    const jwt = lines.slice(jwtStart + 1, jwtEnd).join('').trim();
    const seed = lines.slice(seedStart + 1, seedEnd).join('').trim();

    return { jwt, seed, creds: cachedSystemCreds };
  }

  // Fetch operator secret
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: OPERATOR_SECRET_ID,
  }));

  if (!response.SecretString) {
    throw new Error('NATS operator secret is empty');
  }

  const secret = JSON.parse(response.SecretString);

  if (!secret.system_account_seed || !secret.system_account_public_key) {
    throw new Error('NATS operator secret missing system account keys');
  }

  // Generate a system user for publishing broadcasts
  const systemAccountSeed = secret.system_account_seed;
  const systemAccountKeyPair = nkeys.fromSeed(new TextEncoder().encode(systemAccountSeed));
  const systemAccountPublicKey = systemAccountKeyPair.getPublicKey();

  // Create a user key pair for this session
  const userKeyPair = nkeys.createUser();
  const userSeed = new TextDecoder().decode(userKeyPair.getSeed());
  const userPublicKey = userKeyPair.getPublicKey();

  const nowSec = Math.floor(Date.now() / 1000);
  const exp = nowSec + 3600; // 1 hour expiry

  const jti = createHash('sha256')
    .update(`${userPublicKey}:${nowSec}`)
    .digest('hex')
    .substring(0, 22);

  // System user permissions - can publish to all Broadcast.* subjects
  const userClaims: NatsUserClaims = {
    jti,
    iat: nowSec,
    exp,
    iss: systemAccountPublicKey,
    sub: userPublicKey,
    name: 'system-broadcast-publisher',
    nats: {
      pub: { allow: ['Broadcast.>', 'Control.>'] },
      sub: { allow: [] },
      subs: 0,
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

  const jwt = encodeJwt(header, userClaims, systemAccountKeyPair);
  const creds = formatCredsFile(jwt, userSeed);

  // Cache the credentials
  cachedSystemCreds = creds;
  cacheTime = now;

  return { jwt, seed: userSeed, creds };
}

/**
 * Publish a message to NATS
 *
 * @param subject - The NATS subject to publish to
 * @param payload - The message payload (will be JSON encoded)
 * @returns Promise<boolean> - true if published successfully
 */
export async function publishToNats(
  subject: string,
  payload: object
): Promise<{ success: boolean; error?: string }> {
  let nc: NatsConnection | null = null;

  try {
    // Get system credentials
    const { creds } = await getSystemCredentials();

    // Connect to NATS
    nc = await connect({
      servers: [`tls://${NATS_DOMAIN}:443`],
      authenticator: credsAuthenticator(new TextEncoder().encode(creds)),
      reconnect: false,
      maxReconnectAttempts: 0,
      timeout: 10000, // 10 second connection timeout
    });

    // Publish the message
    const data = sc.encode(JSON.stringify(payload));
    nc.publish(subject, data);

    // Flush to ensure the message is sent
    await nc.flush();

    console.log(`Published message to NATS subject: ${subject}`);
    return { success: true };
  } catch (error: any) {
    console.error('Failed to publish to NATS:', error.message);
    return { success: false, error: error.message };
  } finally {
    // Clean up connection
    if (nc) {
      try {
        await nc.drain();
      } catch {
        // Ignore drain errors
      }
    }
  }
}

/**
 * Publish a vault broadcast message
 *
 * @param broadcastType - Type of broadcast (system_announcement, security_alert, admin_message)
 * @param payload - The broadcast payload
 */
export async function publishVaultBroadcast(
  broadcastType: string,
  payload: {
    broadcast_id: string;
    type: string;
    priority: string;
    title: string;
    message: string;
    sent_at: string;
    sent_by: string;
  }
): Promise<{ success: boolean; error?: string }> {
  // Map broadcast type to NATS subject
  const BROADCAST_SUBJECTS: Record<string, string> = {
    system_announcement: 'Broadcast.system.announcement',
    security_alert: 'Broadcast.security.alert',
    admin_message: 'Broadcast.admin.message',
  };

  const subject = BROADCAST_SUBJECTS[broadcastType];
  if (!subject) {
    return { success: false, error: `Unknown broadcast type: ${broadcastType}` };
  }

  return publishToNats(subject, payload);
}
