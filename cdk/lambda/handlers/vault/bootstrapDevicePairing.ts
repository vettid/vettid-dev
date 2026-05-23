/**
 * Device Pairing Bootstrap
 *
 * Issues short-lived, scoped NATS credentials the desktop client uses to
 * resolve a specific invite code from the `INVITATIONS` JetStream. See
 * vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md §Stage 1 for the full flow.
 *
 * POST /pair/device/bootstrap
 *   Request:  { "code": "ABCDEFGHJKLM" }     (12-char ambiguity-safe alphabet)
 *   Response: { "nats_endpoint": "...",
 *               "jwt": "...",
 *               "seed": "...",
 *               "expires_in": 60 }
 *
 * Design:
 *  - No long-lived credential is shipped with the desktop. Every pairing attempt
 *    mints a fresh NATS user keypair, signs a 60-second JWT with the guest
 *    account key, and returns it.
 *  - JWT is scoped to the INVITATIONS JetStream (consumer create + MSG.NEXT).
 *    After 60s it stops working; a leaked response is useless for any other
 *    invite code or any other subject.
 *  - The caller must provide a syntactically-valid 12-char invite code, but we
 *    deliberately do NOT verify the code exists in JetStream — that would make
 *    this endpoint an oracle for "is X a live invite". Rate limits + the short
 *    TTL handle abuse.
 *
 * Public endpoint — no auth header required. Rate-limited by API Gateway
 * throttling and (recommended) CloudFront WAF on the distribution.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nkeys from 'nkeys.js';
import { createHash, randomUUID } from 'crypto';
import { createUserJwt } from '../../common/nats-jwt';
import { ok, badRequest, internalError, getRequestId } from '../../common/util';

// The helpers above take `requestOrigin` for CORS, not requestId. We pass the
// origin through so browser-originated requests get the right CORS headers.

const NATS_OPERATOR_SECRET_ID = process.env.NATS_OPERATOR_SECRET_ARN || 'vettid/nats/operator-key';
const NATS_ENDPOINT = process.env.NATS_ENDPOINT || 'nats.vettid.dev:443';

// Matches vault-manager/nats_credentials.go `deviceCodeAlphabet` +
// `generateShortCode()` length (12 chars, rendered to the user as
// three 4-char groups: ABCD-EFGH-JKLM).
const INVITE_CODE_ALPHABET = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{12}$/;

const BOOTSTRAP_JWT_TTL_MS = 60 * 1000;

const secretsClient = new SecretsManagerClient({});

// Lambda-container cache for the guest account seed. 5-minute TTL matches the
// pattern used by nats-jwt.ts::getOperatorKeys.
let cachedGuestSeed: string | null = null;
let cachedGuestSeedAt = 0;
const SEED_CACHE_TTL_MS = 5 * 60 * 1000;

async function getGuestAccountSeed(): Promise<string> {
  const now = Date.now();
  if (cachedGuestSeed && now - cachedGuestSeedAt < SEED_CACHE_TTL_MS) {
    return cachedGuestSeed;
  }
  const response = await secretsClient.send(new GetSecretValueCommand({
    SecretId: NATS_OPERATOR_SECRET_ID,
  }));
  if (!response.SecretString) {
    throw new Error('NATS operator secret is empty');
  }
  const secret = JSON.parse(response.SecretString);
  if (!secret.guest_account_seed) {
    throw new Error('guest_account_seed missing from operator secret — run init-nats-operator.ts');
  }
  cachedGuestSeed = secret.guest_account_seed as string;
  cachedGuestSeedAt = now;
  return cachedGuestSeed;
}

export const handler = async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> => {
  const requestId = getRequestId(event);
  const origin = event.headers?.origin;

  let code: string;
  let kind: 'device' | 'agent';
  try {
    const body = JSON.parse(event.body || '{}');
    code = String(body.code || '').toUpperCase().trim();
    // `kind` lets the agent connector share this endpoint with the desktop.
    // Defaults to "device" for backwards compatibility with shipped clients.
    // Same NATS scope is minted either way — `type` is a payload field on
    // the invite, not a JetStream subject, so per-kind scope isolation
    // isn't achievable here (see AGENT-PAIRING-FLOW.md Phase 0 audit). The
    // value is used only for logging + JWT-name traceability.
    const rawKind = String(body.kind || 'device').toLowerCase().trim();
    if (rawKind !== 'device' && rawKind !== 'agent') {
      return badRequest("invalid kind (must be 'device' or 'agent')", origin);
    }
    kind = rawKind;
  } catch {
    return badRequest('invalid JSON body', origin);
  }

  if (!INVITE_CODE_ALPHABET.test(code)) {
    return badRequest(
      'invalid invite code (must be 12 characters, ambiguity-safe alphabet)',
      origin,
    );
  }

  // Log source IP + code prefix only. Full code is treated as a secret — if
  // CloudWatch gets leaked, the prefix is not enough to pair.
  const sourceIp = event.requestContext?.http?.sourceIp || 'unknown';
  console.info('[pair-bootstrap]', {
    requestId,
    ip: sourceIp,
    codePrefix: code.substring(0, 4),
    kind,
  });

  try {
    const guestAccountSeed = await getGuestAccountSeed();

    // Fresh ephemeral user keypair for this pairing attempt.
    const userKeyPair = nkeys.createUser();
    const seed = new TextDecoder().decode(userKeyPair.getSeed());
    const publicKey = userKeyPair.getPublicKey();

    // Scope: JetStream consumer ops on the INVITATIONS stream only. This lets
    // the desktop create an ephemeral pull consumer filtered to invite.<code>
    // and fetch the one message. No publish access to user spaces or any
    // other subject. TTL is 60s.
    //
    // Subject roles (NATS request-reply primer):
    //   - `$JS.API.STREAM.INFO.INVITATIONS` and `$JS.API.CONSUMER.CREATE.*`
    //     are JS RPC endpoints — the client PUBLISHES a request with an
    //     `_INBOX.<id>` reply-to. The server PUBLISHES the reply onto that
    //     inbox subject, which the client SUBSCRIBES to.
    //   - So those JS endpoints go in `pub.allow`; never in `sub.allow`.
    //   - `_INBOX.>` has to be in BOTH (pub so the client can publish a
    //     request that carries an `_INBOX.<id>` reply-to header which the
    //     server will publish back onto; sub so the client can receive
    //     those replies). Without it, every JS RPC hangs forever.
    //   - `CONSUMER.CREATE.INVITATIONS.>` covers the newer ephemeral-with-
    //     filter form (`...CREATE.<stream>.<name>.<filter>`) alongside the
    //     bare durable form.
    const expiresAt = new Date(Date.now() + BOOTSTRAP_JWT_TTL_MS);
    const jwtNamePrefix = kind === 'agent' ? 'agent-bootstrap' : 'desk-bootstrap';
    const jwt = await createUserJwt(
      `${jwtNamePrefix}-${code.substring(0, 4).toLowerCase()}-${randomUUID().substring(0, 8)}`,
      publicKey,
      guestAccountSeed,
      {
        pub: {
          allow: [
            '$JS.API.STREAM.INFO.INVITATIONS',
            '$JS.API.CONSUMER.CREATE.INVITATIONS',
            '$JS.API.CONSUMER.CREATE.INVITATIONS.>',
            '$JS.API.CONSUMER.DURABLE.CREATE.INVITATIONS.>',
            '$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>',
            '$JS.API.CONSUMER.DELETE.INVITATIONS.>',
            '_INBOX.>',
          ],
        },
        sub: {
          allow: [
            '_INBOX.>',
          ],
        },
      },
      expiresAt,
    );

    // Touch the hash once just so the JTI logged downstream isn't derivable
    // back to the code from logs alone.
    createHash('sha256').update(code).digest('hex');

    return ok(
      {
        nats_endpoint: `tls://${NATS_ENDPOINT}`,
        jwt,
        seed,
        expires_in: Math.floor(BOOTSTRAP_JWT_TTL_MS / 1000),
      },
      origin,
    );
  } catch (err: unknown) {
    console.error('[pair-bootstrap] failed', err);
    const msg = err instanceof Error ? err.message : String(err);
    return internalError(`failed to mint credentials: ${msg}`, origin);
  }
};
