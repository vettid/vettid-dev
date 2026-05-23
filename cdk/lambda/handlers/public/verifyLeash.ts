import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { DynamoDBClient, QueryCommand, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall, marshall } from '@aws-sdk/util-dynamodb';
import { verify, createPublicKey } from 'crypto';

const ddb = new DynamoDBClient({});
const TABLE_LEASH_ATTEST_KEYS = process.env.TABLE_LEASH_ATTEST_KEYS!;
const TABLE_LEASH_ISSUED = process.env.TABLE_LEASH_ISSUED!;
// Optional — when set, the verifier appends each result to the named
// demo session if the request carries X-Demo-Session. Omitted in
// environments without the gamified demo wired in.
const TABLE_LEASH_DEMO_SESSIONS = process.env.TABLE_LEASH_DEMO_SESSIONS;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

/**
 * POST /v1/public/leash/verify
 *
 * Full LEASH verification per docs/LEASH-TOKEN-FORMAT.md §"Verification
 * algorithm". Runs every check (signature, expiry, proof-of-possession,
 * scope match, revocation) and returns a structured verification chain
 * so the caller can see exactly what passed/failed and why.
 *
 * Request body (LEASH verifier envelope):
 *   {
 *     "leash":     "<compact-JWT>",
 *     "request":   { "action": "...", ...args },
 *     "nonce":     "<16B base64url>",
 *     "timestamp": <unix-sec>,
 *     "agent_sig": "<EdDSA sig over canonical JSON, base64url>"
 *   }
 *
 * Response (200 always, even on rejection — verification failure is
 * carried in the body so demos can render the chain):
 *   {
 *     "verified": bool,
 *     "rejection_reason": string|null,
 *     "checks": [
 *       { "name": "header", "status": "pass"|"fail", "detail": "..." },
 *       ...
 *     ],
 *     "issuer":  string|null,
 *     "subject": string|null,
 *     "scopes_granted": string[]|null,
 *     "scope_matched":  string|null,
 *     "time_remaining_secs": number|null,
 *     "grant_version":  number|null,
 *     "profile_version_at_grant": number|null,
 *     "evidence": { jwt_pubkey_kid, agent_pubkey_used },
 *     "checked_at": <unix-sec>
 *   }
 *
 * Failure-mode response (4xx/5xx): only used for malformed input or
 * internal errors. Legitimate verification rejections return 200.
 */
export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const now = Math.floor(Date.now() / 1000);
  const checks: VerifyCheck[] = [];
  const result: VerifyResponse = {
    verified: false,
    rejection_reason: null,
    checks,
    issuer: null,
    subject: null,
    scopes_granted: null,
    scope_matched: null,
    time_remaining_secs: null,
    grant_version: null,
    profile_version_at_grant: null,
    evidence: { jwt_pubkey_kid: null, agent_pubkey_used: null },
    checked_at: now,
  };

  // ---- Parse request body --------------------------------------------------
  let body: VerifyRequest;
  try {
    body = JSON.parse(event.body ?? '');
  } catch (e) {
    return badRequest('malformed JSON body');
  }
  if (!body.leash || typeof body.leash !== 'string') {
    return badRequest('missing leash field');
  }
  if (!body.request) {
    return badRequest('missing request field');
  }
  if (!body.nonce || typeof body.nonce !== 'string') {
    return badRequest('missing nonce');
  }
  if (typeof body.timestamp !== 'number') {
    return badRequest('missing timestamp');
  }
  if (!body.agent_sig || typeof body.agent_sig !== 'string') {
    return badRequest('missing agent_sig');
  }

  // ---- 1. Parse JWT compact form ------------------------------------------
  const parts = body.leash.split('.');
  if (parts.length !== 3) {
    return finalize(result, 'malformed', addCheck(checks, 'parse', 'fail', 'expected 3 JWT segments'));
  }
  const [hb64, cb64, sb64] = parts;

  let header: JoseHeader;
  let claims: LeashClaims;
  try {
    header = JSON.parse(Buffer.from(b64urlToBytes(hb64)).toString('utf8'));
    claims = JSON.parse(Buffer.from(b64urlToBytes(cb64)).toString('utf8'));
  } catch (e) {
    return finalize(result, 'malformed', addCheck(checks, 'parse', 'fail', 'header/claims decode failed'));
  }
  addCheck(checks, 'parse', 'pass', '3 segments decoded');

  // ---- 2. Header shape ----------------------------------------------------
  if (header.alg !== 'EdDSA') {
    return finalize(result, 'header-alg', addCheck(checks, 'header', 'fail', `alg must be EdDSA, got ${header.alg}`));
  }
  if (header.typ !== 'leash+jwt') {
    return finalize(result, 'header-typ', addCheck(checks, 'header', 'fail', `typ must be leash+jwt, got ${header.typ}`));
  }
  if (!header.kid) {
    return finalize(result, 'header-kid', addCheck(checks, 'header', 'fail', 'missing kid'));
  }
  addCheck(checks, 'header', 'pass', 'alg=EdDSA typ=leash+jwt kid present');
  result.evidence.jwt_pubkey_kid = header.kid;

  // ---- 3. Resolve issuer pubkey via DDB -----------------------------------
  if (typeof claims.iss !== 'string' || !claims.iss.startsWith('did:vettid:')) {
    return finalize(result, 'iss-format', addCheck(checks, 'issuer', 'fail', `iss must start with did:vettid:`));
  }
  const userGuid = claims.iss.slice('did:vettid:'.length);
  result.issuer = claims.iss;

  let attestPubkeyB64: string | null = null;
  try {
    const q = await ddb.send(new QueryCommand({
      TableName: TABLE_LEASH_ATTEST_KEYS,
      KeyConditionExpression: 'user_guid = :pk AND kid = :sk',
      ExpressionAttributeValues: {
        ':pk': { S: userGuid },
        ':sk': { S: header.kid },
      },
    }));
    if ((q.Items ?? []).length === 0) {
      return finalize(result, 'issuer-unknown',
        addCheck(checks, 'issuer-pubkey', 'fail', `no attestation key found for ${userGuid}/${header.kid}`));
    }
    const row = unmarshall(q.Items![0]);
    attestPubkeyB64 = row.pubkey;
    if (typeof attestPubkeyB64 !== 'string') {
      return finalize(result, 'issuer-malformed',
        addCheck(checks, 'issuer-pubkey', 'fail', 'attestation row missing pubkey'));
    }
    addCheck(checks, 'issuer-pubkey', 'pass', `resolved kid ${header.kid}`);
  } catch (e: unknown) {
    const m = e instanceof Error ? e.message : 'unknown';
    return internalError(`DDB attest-key lookup failed: ${m}`);
  }

  // ---- 4. Verify JWT signature --------------------------------------------
  const signingInput = `${hb64}.${cb64}`;
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlToBytes(sb64);
  } catch (e) {
    return finalize(result, 'sig-decode',
      addCheck(checks, 'jwt-sig', 'fail', 'signature segment is not base64url'));
  }
  if (!verifyEd25519(attestPubkeyB64, Buffer.from(signingInput, 'utf8'), Buffer.from(sigBytes))) {
    return finalize(result, 'bad-sig',
      addCheck(checks, 'jwt-sig', 'fail', 'EdDSA verification failed'));
  }
  addCheck(checks, 'jwt-sig', 'pass', 'EdDSA signature valid');

  // ---- 5. Time-bound checks -----------------------------------------------
  if (typeof claims.nbf !== 'number' || typeof claims.exp !== 'number') {
    return finalize(result, 'time-format',
      addCheck(checks, 'expiry', 'fail', 'nbf/exp must be numbers'));
  }
  if (now < claims.nbf) {
    return finalize(result, 'not-yet-valid',
      addCheck(checks, 'expiry', 'fail', `now (${now}) < nbf (${claims.nbf})`));
  }
  if (now > claims.exp) {
    return finalize(result, 'expired',
      addCheck(checks, 'expiry', 'fail', `now (${now}) > exp (${claims.exp})`));
  }
  result.time_remaining_secs = claims.exp - now;
  addCheck(checks, 'expiry', 'pass', `${result.time_remaining_secs}s remaining`);

  // ---- 6. Schema version --------------------------------------------------
  if (claims['vettid:v'] !== 1) {
    return finalize(result, 'unsupported-version',
      addCheck(checks, 'schema-version', 'fail', `unknown vettid:v ${claims['vettid:v']}`));
  }
  addCheck(checks, 'schema-version', 'pass', 'v1');

  // ---- 7. Proof of Possession ---------------------------------------------
  const agentPubkeyB64 = claims['vettid:agent_pubkey'];
  if (typeof agentPubkeyB64 !== 'string') {
    return finalize(result, 'pop-missing-pubkey',
      addCheck(checks, 'pop', 'fail', 'vettid:agent_pubkey missing'));
  }
  result.evidence.agent_pubkey_used = agentPubkeyB64;

  const canonEnv = canonicalJSON({
    leash: body.leash,
    request: body.request,
    nonce: body.nonce,
    timestamp: body.timestamp,
  });
  let agentSigBytes: Uint8Array;
  try {
    agentSigBytes = b64urlToBytes(body.agent_sig);
  } catch (e) {
    return finalize(result, 'pop-sig-decode',
      addCheck(checks, 'pop', 'fail', 'agent_sig is not base64url'));
  }
  if (!verifyEd25519(agentPubkeyB64, Buffer.from(canonEnv, 'utf8'), Buffer.from(agentSigBytes))) {
    return finalize(result, 'pop-failed',
      addCheck(checks, 'pop', 'fail',
        'agent_sig did not verify under vettid:agent_pubkey — likely a replayed bearer token'));
  }
  addCheck(checks, 'pop', 'pass', 'agent proved possession');

  // ---- 8. Envelope freshness ----------------------------------------------
  const drift = Math.abs(now - body.timestamp);
  if (drift > 60) {
    return finalize(result, 'stale-envelope',
      addCheck(checks, 'envelope-fresh', 'fail',
        `envelope timestamp drift ${drift}s exceeds ±60s window`));
  }
  addCheck(checks, 'envelope-fresh', 'pass', `${drift}s clock drift`);

  // ---- 9. Scope match -----------------------------------------------------
  const scopes = Array.isArray(claims['vettid:scope']) ? claims['vettid:scope'] : [];
  result.scopes_granted = scopes;
  const requestedScope = deriveScopeToken(body.request);
  if (!requestedScope) {
    return finalize(result, 'scope-derivation-failed',
      addCheck(checks, 'scope', 'fail',
        `couldn't derive scope token from request — supply request.action like "profile.email:read"`));
  }
  if (!scopes.includes(requestedScope)) {
    return finalize(result, 'scope-miss',
      addCheck(checks, 'scope', 'fail',
        `action "${requestedScope}" not in granted scopes [${scopes.join(', ')}]`));
  }
  result.scope_matched = requestedScope;
  addCheck(checks, 'scope', 'pass', `"${requestedScope}" matched`);

  // ---- 10. Revocation lookup ---------------------------------------------
  if (typeof claims.jti !== 'string') {
    return finalize(result, 'jti-missing',
      addCheck(checks, 'revocation', 'fail', 'jti missing'));
  }
  try {
    const r = await ddb.send(new GetItemCommand({
      TableName: TABLE_LEASH_ISSUED,
      Key: { jti: { S: claims.jti } },
    }));
    if (!r.Item) {
      // Spec: unknown jti = treat as revoked.
      return finalize(result, 'revoked',
        addCheck(checks, 'revocation', 'fail',
          'jti not found in issuance log — treat as revoked per spec'));
    }
    const row = unmarshall(r.Item);
    if (row.revoked === true) {
      const revokedAt = row.revoked_at;
      return finalize(result, 'revoked',
        addCheck(checks, 'revocation', 'fail',
          `revoked at ${revokedAt}${row.reason ? ` (${row.reason})` : ''}`));
    }
    addCheck(checks, 'revocation', 'pass', 'active');
  } catch (e: unknown) {
    const m = e instanceof Error ? e.message : 'unknown';
    return internalError(`revocation lookup failed: ${m}`);
  }

  // ---- Success ------------------------------------------------------------
  result.verified = true;
  result.subject = typeof claims.sub === 'string' ? claims.sub : null;
  result.grant_version = typeof claims['vettid:grant_version'] === 'number'
    ? claims['vettid:grant_version'] : null;
  result.profile_version_at_grant = typeof claims['vettid:profile_version'] === 'number'
    ? claims['vettid:profile_version'] : null;

  // If the request opted into a demo session (X-Demo-Session header
  // OR `session_token` field in the body), append the result so the
  // demo page can poll for it. Best-effort: a failed append doesn't
  // change the verification verdict.
  await appendToDemoSessionIfAny(event, body, result);

  return ok(result);
};

// ---------------------------------------------------------------------------
// Live-tester demo session emit
// ---------------------------------------------------------------------------

async function appendToDemoSessionIfAny(
  event: APIGatewayProxyEventV2,
  reqBody: VerifyRequest,
  result: VerifyResponse,
): Promise<void> {
  if (!TABLE_LEASH_DEMO_SESSIONS) return;

  // Headers in API Gateway v2 are lowercase-normalized.
  const token = (event.headers?.['x-demo-session'] as string | undefined) ||
                (event.headers?.['X-Demo-Session'] as string | undefined) ||
                (typeof (reqBody as unknown as { session_token?: unknown }).session_token === 'string'
                  ? (reqBody as unknown as { session_token: string }).session_token
                  : undefined);
  if (!token || !token.startsWith('ses_')) return;

  const entry = {
    at: Math.floor(Date.now() / 1000),
    verified: result.verified,
    rejection_reason: result.rejection_reason,
    issuer: result.issuer,
    scope_matched: result.scope_matched,
    checks: result.checks,
  };

  try {
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_LEASH_DEMO_SESSIONS,
      Key: { session_token: { S: token } },
      // Append to the existing results list; fall back to fresh list
      // if the row was created without one (older session shape).
      UpdateExpression: 'SET results = list_append(if_not_exists(results, :empty), :entry)',
      ExpressionAttributeValues: marshall({
        ':entry': [entry],
        ':empty': [],
      }),
      // Only write if the session exists — silent skip if expired.
      ConditionExpression: 'attribute_exists(session_token)',
    }));
  } catch (e: unknown) {
    // Don't fail the verify on session-append errors — the verdict
    // is already correct from the caller's point of view.
    const m = e instanceof Error ? e.message : 'unknown';
    console.log('demo session append skipped', { token, error: m });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface JoseHeader {
  alg: string;
  typ: string;
  kid: string;
}

interface LeashClaims {
  iss?: string;
  sub?: string;
  iat?: number;
  nbf?: number;
  exp?: number;
  jti?: string;
  'vettid:v'?: number;
  'vettid:scope'?: string[];
  'vettid:grant_version'?: number;
  'vettid:profile_version'?: number;
  'vettid:agent_pubkey'?: string;
  'vettid:revocation_url'?: string;
  'vettid:audience'?: string | null;
}

interface VerifyRequest {
  leash: string;
  request: { action?: string; [k: string]: unknown };
  nonce: string;
  timestamp: number;
  agent_sig: string;
}

interface VerifyCheck {
  name: string;
  status: 'pass' | 'fail';
  detail: string;
}

interface VerifyResponse {
  verified: boolean;
  rejection_reason: string | null;
  checks: VerifyCheck[];
  issuer: string | null;
  subject: string | null;
  scopes_granted: string[] | null;
  scope_matched: string | null;
  time_remaining_secs: number | null;
  grant_version: number | null;
  profile_version_at_grant: number | null;
  evidence: { jwt_pubkey_kid: string | null; agent_pubkey_used: string | null };
  checked_at: number;
}

function addCheck(checks: VerifyCheck[], name: string, status: 'pass' | 'fail', detail: string): VerifyCheck[] {
  checks.push({ name, status, detail });
  return checks;
}

function finalize(result: VerifyResponse, reason: string, _: VerifyCheck[]): APIGatewayProxyResultV2 {
  result.verified = false;
  result.rejection_reason = reason;
  return ok(result);
}

function ok(body: unknown): APIGatewayProxyResultV2 {
  return { statusCode: 200, headers: corsHeaders, body: JSON.stringify(body) };
}

function badRequest(message: string): APIGatewayProxyResultV2 {
  return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: message }) };
}

function internalError(message: string): APIGatewayProxyResultV2 {
  return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: message }) };
}

/**
 * Decode base64url (no padding) to Uint8Array. Node's atob accepts
 * base64 but not base64url — convert first.
 */
function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + ((4 - s.length % 4) % 4), '=');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Verify EdDSA over (msg) using base64url-encoded raw 32-byte Ed25519
 * pubkey. Node's crypto.verify takes a KeyObject; we construct one
 * from the raw bytes via SPKI DER.
 */
function verifyEd25519(pubkeyB64: string, msg: Buffer, sig: Buffer): boolean {
  try {
    const rawPub = Buffer.from(b64urlToBytes(pubkeyB64));
    if (rawPub.length !== 32) return false;
    // SPKI DER prefix for Ed25519 (RFC 8410 §4): the constant header
    // for an Ed25519 SubjectPublicKeyInfo wrapping a 32-byte key.
    const spkiPrefix = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    const spki = Buffer.concat([spkiPrefix, rawPub]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return verify(null, msg, key, sig);
  } catch {
    return false;
  }
}

/**
 * Canonical JSON: object keys recursively sorted, no whitespace.
 * Used for the PoP signature canonicalization so the agent and the
 * verifier produce byte-identical signing inputs.
 */
function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJSON((value as Record<string, unknown>)[k])}`)
    .join(',')}}`;
}

/**
 * Derive the scope token from a request.action string. Verifiers check
 * whether this string appears literally in vettid:scope.
 *
 * v1 supports request.action as a pre-formatted scope token like
 * "profile.email:read". v2 would support a richer object shape and
 * derive the token from action verb + resource path.
 */
function deriveScopeToken(request: { action?: string }): string | null {
  if (typeof request.action === 'string' && request.action.includes(':')) {
    return request.action;
  }
  return null;
}
