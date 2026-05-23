/**
 * Unit tests for POST /v1/public/leash/verify
 *
 * Golden-vector tests for the LEASH JWT verifier. Each test mints a
 * real leash in-process, posts it through the handler, and asserts
 * on the verification chain. Exercises every rejection reason from
 * the verifier algorithm in docs/LEASH-TOKEN-FORMAT.md so a future
 * refactor that drops a check fails loudly.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2 } from 'aws-lambda';
import { generateKeyPairSync, sign as nodeSign, createPublicKey, KeyObject } from 'crypto';

// ---------------------------------------------------------------------------
// DDB mock — captures last Query/Get input, returns programmed rows
// ---------------------------------------------------------------------------

interface MockState {
  attestRows: Array<Record<string, unknown>>;
  issuedRow: Record<string, unknown> | null;
}
const mockState: MockState = { attestRows: [], issuedRow: null };

const mockSend = jest.fn((cmd: { input: { TableName?: string; Key?: unknown } }) => {
  const tn = cmd.input.TableName;
  if (tn === 'test-leash-attest-keys') {
    return Promise.resolve({
      Items: mockState.attestRows.map((row) => marshallRow(row)),
    });
  }
  if (tn === 'test-leash-issued') {
    if (!mockState.issuedRow) return Promise.resolve({});
    return Promise.resolve({ Item: marshallRow(mockState.issuedRow) });
  }
  throw new Error(`unexpected table: ${tn}`);
});

// Minimal DDB AttributeValue marshalling for our test shapes.
function marshallRow(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (typeof v === 'string') out[k] = { S: v };
    else if (typeof v === 'number') out[k] = { N: String(v) };
    else if (typeof v === 'boolean') out[k] = { BOOL: v };
    else if (v === null) out[k] = { NULL: true };
    else if (Array.isArray(v)) out[k] = { L: v.map((x) => ({ S: String(x) })) };
    else out[k] = { S: JSON.stringify(v) };
  }
  return out;
}

jest.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn(() => ({ send: mockSend })),
  QueryCommand: jest.fn((input: unknown) => ({ input })),
  GetItemCommand: jest.fn((input: unknown) => ({ input })),
}));

process.env.TABLE_LEASH_ATTEST_KEYS = 'test-leash-attest-keys';
process.env.TABLE_LEASH_ISSUED = 'test-leash-issued';

// Import the handler AFTER mocks are set up.
import { handler } from '../../../lambda/handlers/public/verifyLeash';

// ---------------------------------------------------------------------------
// Test helpers — mint a real leash + envelope so the verifier runs against
// the same crypto path it would see in production
// ---------------------------------------------------------------------------

interface MintedLeash {
  jwt: string;
  jti: string;
  userGuid: string;
  kid: string;
  attestPubB64: string;
  agentPriv: KeyObject;
  agentPubB64: string;
  scopes: string[];
  expiresAt: number;
  issuedAt: number;
}

function bytesToB64Url(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function rawPubFromKey(key: KeyObject): Buffer {
  // Strip the 12-byte SPKI prefix to get the raw 32-byte Ed25519 pubkey.
  const der = key.export({ format: 'der', type: 'spki' });
  return der.subarray(12);
}

function mintLeash(opts?: {
  userGuid?: string;
  scopes?: string[];
  expiresInSecs?: number;
  schemaVersion?: number;
  audience?: string | null;
}): MintedLeash {
  const userGuid = opts?.userGuid ?? 'alice-test-guid';
  const kid = `leash-attest-${userGuid}-v1`;
  const scopes = opts?.scopes ?? ['profile.email:read'];
  const expiresInSecs = opts?.expiresInSecs ?? 3600;

  const { publicKey: attestPub, privateKey: attestPriv } = generateKeyPairSync('ed25519');
  const { publicKey: agentPub, privateKey: agentPriv } = generateKeyPairSync('ed25519');
  const attestRaw = rawPubFromKey(attestPub);
  const agentRaw = rawPubFromKey(agentPub);
  const attestPubB64 = bytesToB64Url(attestRaw);
  const agentPubB64 = bytesToB64Url(agentRaw);

  const now = Math.floor(Date.now() / 1000);
  const jti = `leash-test-${Math.random().toString(36).slice(2)}`;

  const header = { alg: 'EdDSA', typ: 'leash+jwt', kid };
  const claims: Record<string, unknown> = {
    iss: `did:vettid:${userGuid}`,
    sub: 'agent:test-agent-conn',
    iat: now,
    nbf: now,
    exp: now + expiresInSecs,
    jti,
    'vettid:v': opts?.schemaVersion ?? 1,
    'vettid:scope': scopes,
    'vettid:grant_version': 1,
    'vettid:profile_version': 0,
    'vettid:agent_pubkey': agentPubB64,
    'vettid:revocation_url': `https://api.vettid.dev/v1/public/leash/status/${jti}`,
    'vettid:audience': opts?.audience ?? null,
  };

  const hb64 = bytesToB64Url(Buffer.from(JSON.stringify(header)));
  const cb64 = bytesToB64Url(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${hb64}.${cb64}`;
  const sig = nodeSign(null, Buffer.from(signingInput), attestPriv);
  const jwt = `${signingInput}.${bytesToB64Url(sig)}`;

  return {
    jwt,
    jti,
    userGuid,
    kid,
    attestPubB64,
    agentPriv,
    agentPubB64,
    scopes,
    expiresAt: claims.exp as number,
    issuedAt: now,
  };
}

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJSON((value as Record<string, unknown>)[k])}`)
    .join(',')}}`;
}

function buildEnvelope(leash: MintedLeash, action: string, opts?: {
  withGoodSig?: boolean;
  badSig?: boolean;
  driftSecs?: number;
}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  const timestamp = now + (opts?.driftSecs ?? 0);
  const nonce = bytesToB64Url(Buffer.from('test-nonce-1234567890abcdef'));
  const env: Record<string, unknown> = {
    leash: leash.jwt,
    request: { action },
    nonce,
    timestamp,
  };
  const canon = canonicalJSON(env);
  let sig: Buffer;
  if (opts?.badSig) {
    sig = Buffer.alloc(64); // zero sig will never verify
  } else if (opts?.withGoodSig === false) {
    sig = Buffer.alloc(64);
  } else {
    sig = nodeSign(null, Buffer.from(canon), leash.agentPriv);
  }
  env.agent_sig = bytesToB64Url(sig);
  return env;
}

function makeEvent(body: unknown): APIGatewayProxyEventV2 {
  return {
    version: '2.0',
    routeKey: 'POST /v1/public/leash/verify',
    rawPath: '/v1/public/leash/verify',
    rawQueryString: '',
    headers: {},
    requestContext: {
      accountId: '000000000000',
      apiId: 'a',
      domainName: 'api.test',
      domainPrefix: 'api',
      http: {
        method: 'POST',
        path: '/v1/public/leash/verify',
        protocol: 'HTTP/1.1',
        sourceIp: '127.0.0.1',
        userAgent: 'jest',
      },
      requestId: 'req-test',
      routeKey: 'POST /v1/public/leash/verify',
      stage: 'test',
      time: new Date().toISOString(),
      timeEpoch: Date.now(),
    },
    isBase64Encoded: false,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  } as unknown as APIGatewayProxyEventV2;
}

function parseBody(result: APIGatewayProxyStructuredResultV2): Record<string, unknown> {
  return JSON.parse(typeof result.body === 'string' ? result.body : '');
}

// Programmatically tell the DDB mock what the verifier should see when
// it queries the attest-key table and the issued-record table.
function seedDDB(leash: MintedLeash, opts?: {
  revoked?: boolean;
  revokedAt?: number;
  unknownJti?: boolean;
  unknownKid?: boolean;
}) {
  mockState.attestRows = opts?.unknownKid ? [] : [
    {
      user_guid: leash.userGuid,
      kid: leash.kid,
      alg: 'EdDSA',
      pubkey: leash.attestPubB64,
      created_at: leash.issuedAt,
    },
  ];
  mockState.issuedRow = opts?.unknownJti ? null : {
    jti: leash.jti,
    revoked: opts?.revoked ?? false,
    revoked_at: opts?.revokedAt ?? null,
    reason: null,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockState.attestRows = [];
  mockState.issuedRow = null;
});

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe('happy path', () => {
  it('verifies a freshly-minted leash end-to-end', async () => {
    const leash = mintLeash({ scopes: ['profile.email:read', 'credential.sign:cred-x'] });
    seedDDB(leash);
    const result = await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2;
    const body = parseBody(result);

    expect(result.statusCode).toBe(200);
    expect(body.verified).toBe(true);
    expect(body.rejection_reason).toBeNull();
    expect(body.issuer).toBe(`did:vettid:${leash.userGuid}`);
    expect(body.scope_matched).toBe('profile.email:read');
    expect(body.scopes_granted).toEqual(leash.scopes);
    const checks = body.checks as Array<{ name: string; status: string }>;
    expect(checks.find((c) => c.name === 'jwt-sig')?.status).toBe('pass');
    expect(checks.find((c) => c.name === 'pop')?.status).toBe('pass');
    expect(checks.find((c) => c.name === 'scope')?.status).toBe('pass');
    expect(checks.find((c) => c.name === 'revocation')?.status).toBe('pass');
  });
});

// ---------------------------------------------------------------------------
// Rejection paths — one test per algorithm reject reason
// ---------------------------------------------------------------------------

describe('rejections', () => {
  it('rejects when alg is not EdDSA', async () => {
    const leash = mintLeash();
    // Tamper the header to claim HS256.
    const [, cb64, sb64] = leash.jwt.split('.');
    const tampered = `${bytesToB64Url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'leash+jwt', kid: leash.kid })))}.${cb64}.${sb64}`;
    const envelope = buildEnvelope(leash, 'profile.email:read');
    envelope.leash = tampered;
    seedDDB(leash);
    const body = parseBody(await handler(makeEvent(envelope)) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('header-alg');
  });

  it('rejects when typ is wrong', async () => {
    const leash = mintLeash();
    const [, cb64, sb64] = leash.jwt.split('.');
    const tampered = `${bytesToB64Url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'jwt', kid: leash.kid })))}.${cb64}.${sb64}`;
    const envelope = buildEnvelope(leash, 'profile.email:read');
    envelope.leash = tampered;
    seedDDB(leash);
    const body = parseBody(await handler(makeEvent(envelope)) as APIGatewayProxyStructuredResultV2);
    expect(body.rejection_reason).toBe('header-typ');
  });

  it('rejects on unknown issuer (no attest key in DDB)', async () => {
    const leash = mintLeash();
    seedDDB(leash, { unknownKid: true });
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('issuer-unknown');
  });

  it('rejects on bad JWT signature (verifier uses wrong attest pubkey)', async () => {
    const leash = mintLeash();
    // Seed with a DIFFERENT pubkey so signature verification fails.
    const decoy = mintLeash();
    mockState.attestRows = [{
      user_guid: leash.userGuid,
      kid: leash.kid,
      alg: 'EdDSA',
      pubkey: decoy.attestPubB64,
      created_at: 0,
    }];
    mockState.issuedRow = { jti: leash.jti, revoked: false, revoked_at: null, reason: null };
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('bad-sig');
  });

  it('rejects expired leash', async () => {
    const leash = mintLeash({ expiresInSecs: -10 });
    seedDDB(leash);
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('expired');
  });

  it('rejects when proof-of-possession signature is bad', async () => {
    const leash = mintLeash();
    seedDDB(leash);
    const envelope = buildEnvelope(leash, 'profile.email:read', { badSig: true });
    const body = parseBody(await handler(makeEvent(envelope)) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('pop-failed');
  });

  it('rejects stale envelope (timestamp way in the past)', async () => {
    const leash = mintLeash();
    seedDDB(leash);
    const envelope = buildEnvelope(leash, 'profile.email:read', { driftSecs: -120 });
    const body = parseBody(await handler(makeEvent(envelope)) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('stale-envelope');
  });

  it('rejects on scope miss', async () => {
    const leash = mintLeash({ scopes: ['profile.email:read'] });
    seedDDB(leash);
    const envelope = buildEnvelope(leash, 'wallet.balance:read');
    const body = parseBody(await handler(makeEvent(envelope)) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('scope-miss');
  });

  it('rejects revoked leash', async () => {
    const leash = mintLeash();
    seedDDB(leash, { revoked: true, revokedAt: leash.issuedAt + 60 });
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('revoked');
  });

  it('rejects when jti is not in the issuance log', async () => {
    const leash = mintLeash();
    seedDDB(leash, { unknownJti: true });
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('revoked');
  });

  it('rejects unsupported schema version', async () => {
    const leash = mintLeash({ schemaVersion: 999 });
    seedDDB(leash);
    const body = parseBody(await handler(makeEvent(buildEnvelope(leash, 'profile.email:read'))) as APIGatewayProxyStructuredResultV2);
    expect(body.verified).toBe(false);
    expect(body.rejection_reason).toBe('unsupported-version');
  });

  it('returns 400 on malformed JSON body', async () => {
    const result = await handler(makeEvent('not-json')) as APIGatewayProxyStructuredResultV2;
    expect(result.statusCode).toBe(400);
    expect(parseBody(result).error).toMatch(/malformed/);
  });
});
