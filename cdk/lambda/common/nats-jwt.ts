/**
 * NATS JWT Utility Module
 *
 * Provides functions to generate NATS account and user JWTs using nkeys.
 * The operator keys are stored in AWS Secrets Manager and cached for performance.
 *
 * NATS uses Ed25519 keys (nkeys) and JWTs for authentication:
 * - Operator: Signs account JWTs
 * - Account: Signs user JWTs (each member has their own account)
 * - User: Used by clients to connect to NATS
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nkeys from 'nkeys.js';
import { createHash } from 'crypto';

const OPERATOR_SECRET_ID = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';

const secretsClient = new SecretsManagerClient({});

// Cache operator keys for Lambda reuse
let cachedOperatorKeys: OperatorKeys | null = null;
let cachedSecretVersionId: string | null = null;
let cacheTime = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * SECURITY: JWT expiration and resource limit constants
 */
const ACCOUNT_JWT_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days - monthly renewal required
const USER_JWT_MAX_TTL_MS = 24 * 60 * 60 * 1000;   // 24 hours max for user JWTs

/**
 * SECURITY: Per-account resource limits to prevent DoS
 * These are reasonable limits for mobile app + vault use case
 */
const ACCOUNT_LIMITS = {
  subs: 100,           // Max subscriptions per account
  data: 10_000_000,    // 10 MB/sec data transfer
  payload: 1_048_576,  // 1 MB max message payload
  imports: 10,         // Max imports
  exports: 10,         // Max exports
  wildcards: true,     // Allow wildcards for OwnerSpace.{guid}.>
  conn: 10,            // Max connections (mobile + vault + backup)
  leaf: 0,             // No leaf nodes needed
};

/**
 * Force invalidate the operator keys cache
 * Call this when keys are rotated in Secrets Manager
 */
export function invalidateOperatorKeysCache(): void {
  cachedOperatorKeys = null;
  cachedSecretVersionId = null;
  cacheTime = 0;
}

interface OperatorKeys {
  operatorSeed: string;
  operatorPublicKey: string;
  systemAccountSeed: string;
  systemAccountPublicKey: string;
}

interface NatsUserClaims {
  jti: string;           // JWT ID
  iat: number;           // Issued at
  exp: number;           // Expiration
  iss: string;           // Issuer (account public key)
  sub: string;           // Subject (user public key)
  name: string;          // User name
  nats: {
    pub?: { allow?: string[]; deny?: string[] };
    sub?: { allow?: string[]; deny?: string[] };
    subs?: number;       // Max subscriptions (-1 = unlimited)
    data?: number;       // Max data (-1 = unlimited)
    payload?: number;    // Max payload (-1 = unlimited)
    type?: string;       // JWT type
    version?: number;    // JWT version
  };
}

interface NatsAccountClaims {
  jti: string;           // JWT ID
  iat: number;           // Issued at
  exp?: number;          // Expiration (optional for accounts)
  iss: string;           // Issuer (operator public key)
  sub: string;           // Subject (account public key)
  name: string;          // Account name
  nats: {
    limits?: {
      subs?: number;
      data?: number;
      payload?: number;
      imports?: number;
      exports?: number;
      wildcards?: boolean;
      conn?: number;
      leaf?: number;
    };
    default_permissions?: {
      pub?: { allow?: string[]; deny?: string[] };
      sub?: { allow?: string[]; deny?: string[] };
    };
    // SECURITY: Revocations - maps user public key to Unix timestamp of revocation
    // Any user JWT issued BEFORE this timestamp is considered revoked
    revocations?: { [userPublicKey: string]: number };
    type?: string;
    version?: number;
  };
}

interface GeneratedCredentials {
  jwt: string;
  seed: string;
  publicKey: string;
}

/**
 * Get operator keys from Secrets Manager (cached with version validation)
 * Cache is invalidated when secret version changes for immediate key rotation support
 */
async function getOperatorKeys(): Promise<OperatorKeys> {
  const now = Date.now();

  if (cachedOperatorKeys && (now - cacheTime) < CACHE_TTL_MS) {
    return cachedOperatorKeys;
  }

  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: OPERATOR_SECRET_ID,
  }));

  if (!response.SecretString) {
    throw new Error('NATS operator secret is empty');
  }

  // Check if secret version changed (indicates key rotation)
  const newVersionId = response.VersionId;
  if (cachedSecretVersionId && newVersionId !== cachedSecretVersionId) {
    console.info('[NATS-JWT] Operator keys rotated, updating cache');
  }

  const secret = JSON.parse(response.SecretString);

  if (!secret.operator_seed) {
    throw new Error('NATS operator keys not initialized. Run: npx ts-node scripts/init-nats-operator.ts');
  }

  // Validate secret structure before caching
  if (!secret.operator_public_key || !secret.system_account_seed || !secret.system_account_public_key) {
    throw new Error('NATS operator secret missing required fields');
  }

  cachedOperatorKeys = {
    operatorSeed: secret.operator_seed,
    operatorPublicKey: secret.operator_public_key,
    systemAccountSeed: secret.system_account_seed,
    systemAccountPublicKey: secret.system_account_public_key,
  };
  cachedSecretVersionId = newVersionId || null;
  cacheTime = now;

  return cachedOperatorKeys;
}

/**
 * Encode a JWT without external libraries
 * NATS JWTs use a specific format with Ed25519 signatures
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
 * Create a NATS account for a member
 *
 * Each member gets their own NATS account which provides namespace isolation.
 * The account is signed by the operator.
 *
 * @param accountName - Display name for the account
 * @param accountPublicKey - The account's nkey public key
 * @param revocations - Optional map of revoked user public keys to revocation timestamps
 */
export async function createAccountJwt(
  accountName: string,
  accountPublicKey: string,
  revocations?: { [userPublicKey: string]: number }
): Promise<string> {
  const operatorKeys = await getOperatorKeys();
  const operatorKeyPair = nkeys.fromSeed(new TextEncoder().encode(operatorKeys.operatorSeed));

  const now = Math.floor(Date.now() / 1000);
  const jti = createHash('sha256')
    .update(`${accountPublicKey}:${now}`)
    .digest('hex')
    .substring(0, 22);

  const claims: NatsAccountClaims = {
    jti,
    iat: now,
    exp: now + ACCOUNT_JWT_TTL_SECONDS, // SECURITY: 90-day expiration requires renewal
    iss: operatorKeys.operatorPublicKey,
    sub: accountPublicKey,
    name: accountName,
    nats: {
      limits: ACCOUNT_LIMITS, // SECURITY: Use defined resource limits instead of unlimited
      // SECURITY: Include revocations if any - NATS will reject connections from revoked users
      revocations: revocations && Object.keys(revocations).length > 0 ? revocations : undefined,
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
 * Create a NATS user JWT for a member
 *
 * The user JWT grants specific permissions based on client type:
 * - app: Mobile app permissions (publish to forVault, subscribe to forApp)
 * - vault: Vault instance permissions (publish to forApp, subscribe to forVault + control)
 */
export async function createUserJwt(
  userName: string,
  userPublicKey: string,
  accountSeed: string,
  permissions: {
    pub?: { allow?: string[]; deny?: string[] };
    sub?: { allow?: string[]; deny?: string[] };
  },
  expiresAt: Date
): Promise<string> {
  // SECURITY: Validate expiration doesn't exceed max TTL (prevents long-lived tokens)
  const now = Date.now();
  const requestedTtl = expiresAt.getTime() - now;
  if (requestedTtl > USER_JWT_MAX_TTL_MS) {
    throw new Error(`User JWT expiration exceeds maximum TTL of ${USER_JWT_MAX_TTL_MS / (1000 * 60 * 60)} hours`);
  }
  if (requestedTtl <= 0) {
    throw new Error('User JWT expiration must be in the future');
  }

  const accountKeyPair = nkeys.fromSeed(new TextEncoder().encode(accountSeed));
  const accountPublicKey = accountKeyPair.getPublicKey();

  const nowSeconds = Math.floor(now / 1000);
  const exp = Math.floor(expiresAt.getTime() / 1000);

  const jti = createHash('sha256')
    .update(`${userPublicKey}:${nowSeconds}`)
    .digest('hex')
    .substring(0, 22);

  const claims: NatsUserClaims = {
    jti,
    iat: nowSeconds,
    exp,
    iss: accountPublicKey,
    sub: userPublicKey,
    name: userName,
    nats: {
      pub: permissions.pub,
      sub: permissions.sub,
      subs: 50,             // SECURITY: Reasonable subscription limit
      data: 5_000_000,      // SECURITY: 5 MB/sec per user
      payload: 1_048_576,   // SECURITY: 1 MB max payload
      type: 'user',
      version: 2,
    },
  };

  const header = {
    typ: 'JWT',
    alg: 'ed25519-nkey',
  };

  return encodeJwt(header, claims, accountKeyPair);
}

/**
 * Generate a new account key pair and JWT
 */
export async function generateAccountCredentials(
  memberGuid: string
): Promise<GeneratedCredentials & { accountJwt: string }> {
  const accountKeyPair = nkeys.createAccount();
  const seed = new TextDecoder().decode(accountKeyPair.getSeed());
  const publicKey = accountKeyPair.getPublicKey();

  const accountName = `account-${memberGuid.substring(0, 8)}`;
  const accountJwt = await createAccountJwt(accountName, publicKey);

  return {
    jwt: accountJwt,
    seed,
    publicKey,
    accountJwt,
  };
}

/**
 * Generate user credentials for NATS connection
 */
export async function generateUserCredentials(
  userGuid: string,
  accountSeed: string,
  clientType: 'app' | 'vault' | 'control',
  ownerSpace: string,
  messageSpace: string,
  expiresAt: Date
): Promise<GeneratedCredentials> {
  // Create user key pair
  const userKeyPair = nkeys.createUser();
  const seed = new TextDecoder().decode(userKeyPair.getSeed());
  const publicKey = userKeyPair.getPublicKey();

  // Define permissions based on client type
  let pubAllow: string[];
  let subAllow: string[];

  // SECURITY: Explicit deny rules to prevent cross-namespace access and system topic abuse
  const systemDenyPatterns = [
    '$SYS.>',           // System topics
    '$JS.>',            // JetStream internal topics
    '_INBOX.>',         // Internal inbox topics
    'Broadcast.>',      // Admin broadcast topics (only admins should publish)
  ];

  if (clientType === 'app') {
    // Mobile app: publish to vault, subscribe from vault
    pubAllow = [`${ownerSpace}.forVault.>`];
    subAllow = [`${ownerSpace}.forApp.>`, `${ownerSpace}.eventTypes`];
  } else if (clientType === 'vault') {
    // Vault instance: publish to app, services, connections, and call signaling; subscribe from app, control, and calls
    pubAllow = [
      `${ownerSpace}.forApp.>`,
      `${ownerSpace}.forServices.>`,   // For health/status messages to backend
      `${messageSpace}.forOwner.>`,
      `${messageSpace}.ownerProfile`,
      `${messageSpace}.call.>`,        // Vault-to-vault call signaling (outbound)
    ];
    subAllow = [
      `${ownerSpace}.forVault.>`,
      `${ownerSpace}.control`,
      `${ownerSpace}.eventTypes`,
      `${messageSpace}.forOwner.>`,
      `${messageSpace}.call.>`,        // Vault-to-vault call signaling (inbound)
      'Broadcast.>',                    // Allow subscribing to admin broadcasts
    ];
  } else {
    // Control: publish to control topic only
    pubAllow = [`${ownerSpace}.control`];
    subAllow = [];
  }

  const userName = `${clientType}-${userGuid.substring(0, 8)}`;

  const jwt = await createUserJwt(
    userName,
    publicKey,
    accountSeed,
    {
      // SECURITY: Explicit allow and deny lists for defense-in-depth
      pub: { allow: pubAllow, deny: systemDenyPatterns },
      sub: { allow: subAllow, deny: systemDenyPatterns.filter(p => p !== 'Broadcast.>') }, // Vaults can subscribe to broadcasts
    },
    expiresAt
  );

  return {
    jwt,
    seed,
    publicKey,
  };
}

/**
 * Generate temporary bootstrap credentials for initial app connection
 *
 * These credentials are short-lived (1 hour) and have minimal permissions:
 * - Can only publish to: OwnerSpace.{guid}.forVault.app.bootstrap
 * - Can only subscribe to: OwnerSpace.{guid}.forApp.app.bootstrap.>
 *
 * The app uses these to call the vault's app.bootstrap handler and receive
 * full credentials generated by the vault.
 *
 * Note: Response topic follows pattern: forApp.{eventType}.{requestId}
 * For app.bootstrap event type, this becomes: forApp.app.bootstrap.{id}
 */
export async function generateBootstrapCredentials(
  userGuid: string,
  accountSeed: string,
  ownerSpace: string
): Promise<GeneratedCredentials> {
  // Create user key pair
  const userKeyPair = nkeys.createUser();
  const seed = new TextDecoder().decode(userKeyPair.getSeed());
  const publicKey = userKeyPair.getPublicKey();

  // Bootstrap-only permissions: just enough to call app.bootstrap and get response
  // Response topic pattern: forApp.{eventType}.{requestId} → forApp.app.bootstrap.{id}
  const pubAllow = [`${ownerSpace}.forVault.app.bootstrap`];
  const subAllow = [`${ownerSpace}.forApp.app.bootstrap.>`];

  const userName = `bootstrap-${userGuid.substring(0, 8)}`;

  // Short-lived: 1 hour expiry
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

  const jwt = await createUserJwt(
    userName,
    publicKey,
    accountSeed,
    {
      pub: { allow: pubAllow },
      sub: { allow: subAllow },
    },
    expiresAt
  );

  return {
    jwt,
    seed,
    publicKey,
  };
}

/**
 * Format credentials as NATS creds file content
 * This can be saved to a .creds file for use with NATS clients
 */
export function formatCredsFile(jwt: string, seed: string): string {
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

/**
 * Regenerate an account JWT with updated revocations
 *
 * This is called when a user token is revoked to update the account JWT
 * with the new revocation list. The NATS URL resolver will serve the
 * updated JWT, and NATS servers will enforce the revocation.
 *
 * @param accountName - Display name for the account (e.g., "account-abc12345")
 * @param accountPublicKey - The account's nkey public key
 * @param revocations - Map of revoked user public keys to revocation timestamps
 */
export async function regenerateAccountJwtWithRevocations(
  accountName: string,
  accountPublicKey: string,
  revocations: { [userPublicKey: string]: number }
): Promise<string> {
  return createAccountJwt(accountName, accountPublicKey, revocations);
}

/**
 * Get the operator public key (for debugging/validation)
 */
export async function getOperatorPublicKey(): Promise<string> {
  const keys = await getOperatorKeys();
  return keys.operatorPublicKey;
}

/**
 * Get the system account public key (for debugging/validation)
 */
export async function getSystemAccountPublicKey(): Promise<string> {
  const keys = await getOperatorKeys();
  return keys.systemAccountPublicKey;
}
