import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  CreateSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { generateKeyPairSync, sign as nodeSign } from 'crypto';
import {
  DEMO_ALICE_USER_GUID,
  DEMO_ALICE_AGENT_CONN_ID,
  DEMO_ALICE_KID,
  DEMO_ATTEST_SECRET_NAME,
  DEMO_DEFAULT_DURATION_SECS,
  DEMO_MAX_DURATION_SECS,
  DEMO_SCOPE_OPTIONS,
} from './_demoFixtures';

/**
 * POST /v1/public/leash/demo/mint
 *
 * Mints a fresh LEASH for the gamified demo on vettid.dev. Caller
 * supplies `scope` (subset of DEMO_SCOPE_OPTIONS), `agent_pubkey`
 * (the page generates one client-side for the static demo), and
 * optional `duration_secs`. Returns the compact JWT + jti.
 *
 * Issuer is always Demo Alice — no real-user GUIDs are accepted.
 * Attestation keypair is lazy-bootstrapped in Secrets Manager on
 * first invocation; Alice's pubkey is mirrored to LeashAttestKeys
 * so the public verifier resolves it normally.
 *
 * Body:
 *   {
 *     "scope": ["profile.email:read", ...],
 *     "agent_pubkey": "<base64url ed25519 pubkey, 32B>",
 *     "duration_secs": 120
 *   }
 *
 * Response:
 *   { "leash": "<jwt>", "jti": "leash-...", "kid": "...",
 *     "issued_at": ..., "expires_at": ... }
 */

const ddb = new DynamoDBClient({});
const sm = new SecretsManagerClient({});
const TABLE_LEASH_ATTEST_KEYS = process.env.TABLE_LEASH_ATTEST_KEYS!;
const TABLE_LEASH_ISSUED = process.env.TABLE_LEASH_ISSUED!;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

interface PersistedAttestKey {
  private_b64: string; // raw 64-byte Ed25519 private
  public_b64: string;  // raw 32-byte Ed25519 public
}

let cachedKey: PersistedAttestKey | null = null;

async function ensureAttestKey(): Promise<PersistedAttestKey> {
  if (cachedKey) return cachedKey;

  // Try to load existing.
  try {
    const r = await sm.send(new GetSecretValueCommand({ SecretId: DEMO_ATTEST_SECRET_NAME }));
    if (r.SecretString) {
      cachedKey = JSON.parse(r.SecretString) as PersistedAttestKey;
      return cachedKey;
    }
  } catch (e: unknown) {
    const name = (e as { name?: string })?.name;
    if (name !== 'ResourceNotFoundException') throw e;
  }

  // Generate fresh + publish pubkey to LeashAttestKeys table.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  // Extract the raw 32-byte private seed from PKCS8 — Node doesn't
  // expose it directly, but signing works against the KeyObject so
  // we serialize the PKCS8 DER and rebuild on use. For storage,
  // however, we keep the raw seed so the JSON is portable.
  // PKCS8 Ed25519 private has a fixed 16-byte prefix before the seed.
  const rawPriv = privDer.subarray(16, 48);

  const wrapped: PersistedAttestKey = {
    private_b64: rawPriv.toString('base64'),
    public_b64: rawPub.toString('base64'),
  };

  await sm.send(new CreateSecretCommand({
    Name: DEMO_ATTEST_SECRET_NAME,
    SecretString: JSON.stringify(wrapped),
    Description: 'Ed25519 attestation key for the LEASH demo on vettid.dev. NOT user data.',
  }));

  // Publish pubkey to LeashAttestKeys so the public verifier can
  // resolve Demo Alice. Idempotent: re-publish on rotation.
  await ddb.send(new PutItemCommand({
    TableName: TABLE_LEASH_ATTEST_KEYS,
    Item: marshall({
      user_guid: DEMO_ALICE_USER_GUID,
      kid: DEMO_ALICE_KID,
      alg: 'EdDSA',
      pubkey: rawPub.toString('base64url').replace(/=+$/, ''),
      created_at: Math.floor(Date.now() / 1000),
    }),
  }));

  cachedKey = wrapped;
  return wrapped;
}

function b64UrlEncode(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function ed25519SignWithRawSeed(seedRaw: Buffer, msg: Buffer): Buffer {
  // Reconstruct a KeyObject from the raw seed via PKCS8 DER prefix.
  const { createPrivateKey } = require('crypto');
  const pkcs8Prefix = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = Buffer.concat([pkcs8Prefix, seedRaw]);
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return nodeSign(null, msg, key);
}

function validateScope(scope: unknown): string[] {
  if (!Array.isArray(scope) || scope.length === 0) {
    throw new Error('scope must be a non-empty array');
  }
  const allowed = new Set(DEMO_SCOPE_OPTIONS);
  for (const s of scope) {
    if (typeof s !== 'string' || !allowed.has(s)) {
      throw new Error(`scope token "${s}" not in demo allowlist`);
    }
  }
  return scope as string[];
}

function validateAgentPubkey(p: unknown): string {
  if (typeof p !== 'string') throw new Error('agent_pubkey must be a string');
  const b64 = p.replace(/-/g, '+').replace(/_/g, '/').padEnd(p.length + ((4 - p.length % 4) % 4), '=');
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== 32) throw new Error('agent_pubkey must decode to 32 bytes');
  return p;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  let body: { scope?: unknown; agent_pubkey?: unknown; duration_secs?: unknown };
  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'malformed JSON' }) };
  }

  let scope: string[];
  let agentPubkey: string;
  try {
    scope = validateScope(body.scope);
    agentPubkey = validateAgentPubkey(body.agent_pubkey);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'invalid input';
    return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: msg }) };
  }

  let durationSecs = typeof body.duration_secs === 'number' ? body.duration_secs : DEMO_DEFAULT_DURATION_SECS;
  if (durationSecs <= 0) durationSecs = DEMO_DEFAULT_DURATION_SECS;
  if (durationSecs > DEMO_MAX_DURATION_SECS) durationSecs = DEMO_MAX_DURATION_SECS;

  try {
    const attestKey = await ensureAttestKey();

    const now = Math.floor(Date.now() / 1000);
    const jti = `leash-demo-${cryptoRandomId()}`;
    const header = { alg: 'EdDSA', typ: 'leash+jwt', kid: DEMO_ALICE_KID };
    const claims = {
      iss: `did:vettid:${DEMO_ALICE_USER_GUID}`,
      sub: `agent:${DEMO_ALICE_AGENT_CONN_ID}`,
      iat: now,
      nbf: now,
      exp: now + durationSecs,
      jti,
      'vettid:v': 1,
      'vettid:scope': scope,
      'vettid:grant_version': 1,
      'vettid:profile_version': 0,
      'vettid:agent_pubkey': agentPubkey,
      'vettid:revocation_url': `https://api.vettid.dev/v1/public/leash/status/${jti}`,
      'vettid:audience': null,
    };

    const hb64 = b64UrlEncode(Buffer.from(JSON.stringify(header)));
    const cb64 = b64UrlEncode(Buffer.from(JSON.stringify(claims)));
    const signingInput = `${hb64}.${cb64}`;

    const privSeed = Buffer.from(attestKey.private_b64, 'base64');
    const sig = ed25519SignWithRawSeed(privSeed, Buffer.from(signingInput, 'utf8'));
    const token = `${signingInput}.${b64UrlEncode(sig)}`;

    // Mirror to LeashIssued so the revocation Lambda can find it.
    await ddb.send(new PutItemCommand({
      TableName: TABLE_LEASH_ISSUED,
      Item: marshall({
        jti,
        subject: `agent:${DEMO_ALICE_AGENT_CONN_ID}`,
        scope,
        issued_at: now,
        expires_at: now + durationSecs,
        expires_at_ttl: now + durationSecs,
        revoked: false,
        iss: `did:vettid:${DEMO_ALICE_USER_GUID}`,
        grant_version: 1,
        profile_version: 0,
      }),
    }));

    return {
      statusCode: 200,
      headers: { ...corsHeaders, 'Cache-Control': 'no-store' },
      body: JSON.stringify({
        leash: token,
        jti,
        kid: DEMO_ALICE_KID,
        issued_at: now,
        expires_at: now + durationSecs,
      }),
    };
  } catch (err: unknown) {
    const m = err instanceof Error ? err.message : 'unknown';
    console.error('demoMintLeash failed', { error: m });
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'mint failed' }) };
  }
};

function cryptoRandomId(): string {
  const { randomBytes } = require('crypto');
  return randomBytes(12).toString('hex');
}
