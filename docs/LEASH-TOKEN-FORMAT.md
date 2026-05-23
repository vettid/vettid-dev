# LEASH Token Format v1

**Status:** Draft — Sprint 1 of the LEASH demo workstream.
**Audience:** anyone implementing a verifier, mint, or relying-party for VettID
agent delegation tokens.

## What this is

A LEASH token is a cryptographically-signed assertion that a VettID user
("issuer") has delegated a scoped, time-bound capability to an agent
("subject"), and that the assertion can be verified by any third party
without trusting VettID's servers, without contacting the user's enclave,
and without ever holding the user's underlying secrets.

The name is the model: a leash is **short, scoped, version-bound,
revocable, and never lets the agent off it**. The token is the on-the-wire
encoding of one leash.

## Wire format

Compact JWT (RFC 7519), restricted to a single algorithm to eliminate
algorithm-confusion attacks. Verifiers MUST reject tokens whose header
deviates from the shape below.

### Header (JOSE, base64url-encoded JSON)

```json
{
  "alg": "EdDSA",
  "typ": "leash+jwt",
  "kid": "leash-attest-{user_guid}-v1"
}
```

- `alg` — MUST be `EdDSA`. Verifiers MUST reject any other value (no
  algorithm negotiation, no `alg: none`, no HS256 confusion).
- `typ` — MUST be `leash+jwt`. Distinguishes from generic JWTs that
  happen to land at the same verifier. Mitigates token-confusion attacks
  where a JWT minted for a different purpose is replayed against a LEASH
  validator (RFC 8725 §3.11).
- `kid` — opaque key identifier. Verifiers use this to look up the
  issuer's public key. Convention:
  `leash-attest-{user_guid}-v{generation}` where `generation` increments
  on key rotation.

### Claims (base64url-encoded JSON)

```json
{
  "iss":  "did:vettid:{user_guid}",
  "sub":  "agent:{agent_conn_id}",
  "iat":  1716483600,
  "nbf":  1716483600,
  "exp":  1716487200,
  "jti":  "leash-01h7f3a2b9c4d5e6f7g8h9j0k1",

  "vettid:v":               1,
  "vettid:scope":           ["profile.email:read", "credential.sign:cred-7a9f"],
  "vettid:grant_version":   4,
  "vettid:profile_version": 47,
  "vettid:agent_pubkey":    "<32-byte Ed25519 pubkey, base64url>",
  "vettid:revocation_url":  "https://api.vettid.dev/v1/public/leash/status/leash-01h7f3a2b9c4d5e6f7g8h9j0k1",
  "vettid:audience":        null
}
```

#### Standard claims (RFC 7519)

| Claim | Required | Meaning |
|-------|----------|---------|
| `iss` | yes | Issuer DID — who delegated this leash. Format: `did:vettid:{user_guid}`. |
| `sub` | yes | Subject — who receives the leash. Format: `agent:{agent_conn_id}`. |
| `iat` | yes | Issued at (unix seconds, UTC). |
| `nbf` | yes | Not before (unix seconds, UTC). MAY equal `iat`. |
| `exp` | yes | Expires (unix seconds, UTC). Verifiers MUST reject if `now > exp`. |
| `jti` | yes | Unique grant identifier. Used as the lookup key for the revocation endpoint. Format: `leash-{ULID}` for sortability + uniqueness. |

#### VettID-specific claims (domain-prefixed)

All VettID-specific claims use the `vettid:` prefix to avoid collisions
with future standard claims and signal "this is part of the LEASH
protocol, not generic JWT."

| Claim | Required | Meaning |
|-------|----------|---------|
| `vettid:v` | yes | Schema version of the leash payload itself. v1 = this document. |
| `vettid:scope` | yes | Array of scope tokens (see grammar below). Empty array = unscoped = SHOULD be rejected. |
| `vettid:grant_version` | yes | Monotonically-increasing integer scoped to `(iss, sub)`. The most recent issuance wins. Blocks rollback attacks where a stale, broader leash is replayed after a tightening. |
| `vettid:profile_version` | yes | Snapshot of the issuer's published-profile version at issuance time. **Informational only in v1** — verifiers surface to the relying party but MUST NOT auto-reject on mismatch. Reserved for per-scope enforcement in v2. |
| `vettid:agent_pubkey` | yes | The Ed25519 public key (base64url, 32 bytes) of the agent that the leash binds to. Bearer presentation is insufficient — the holder MUST also produce a fresh signature with this key on every verification request (see Proof of Possession). |
| `vettid:revocation_url` | yes | HTTPS URL of the revocation status endpoint for this `jti`. Verifiers SHOULD query it on every verify; aggressive caching trades off against revocation latency. |
| `vettid:audience` | no | Intended verifier identity. `null` (or absent) in v1 = any verifier may accept. v2 will require this for stolen-token replay defense. |

### Signature

EdDSA (Ed25519) signature over `base64url(header) || "." || base64url(claims)`,
computed by the issuer's vault using the **attestation key** identified
by `kid`.

The attestation key is **separate** from any internal vault signing key.
It is generated lazily on first leash issuance per user, persisted under
the user's encrypted vault state at `leash/attest_key`, and its public
half is published at the issuer's well-known endpoint (see "Key
publishing" below).

This separation means:

- Internal vault sigs (audit log, peer connections, etc.) never become
  externally-verifiable assertions about delegation.
- Leash signing can be key-rotated independently without disturbing the
  vault's internal signature surface.
- If the attestation key is ever compromised, the impact is bounded to
  outstanding leashes (which expire in minutes to hours), not to the
  user's whole identity.

## Proof of Possession

A signed JWT is a bearer credential — anyone who intercepts it can use it.
LEASH closes this by requiring the agent to demonstrate possession of the
private key matching `vettid:agent_pubkey` on every verification request.
The verifier MUST run both checks (delegation proof AND possession proof)
or the leash provides no security beyond an unsigned URL parameter.

### Verifier request envelope

```json
{
  "leash":     "<compact JWT>",
  "request":   { "action": "...", "args": { ... } },
  "nonce":     "<16-byte random, base64url>",
  "timestamp": 1716483777,
  "agent_sig": "<EdDSA signature, base64url>"
}
```

- `leash` — the LEASH JWT in compact form.
- `request` — the action the agent is attempting. The verifier matches
  this against `vettid:scope`.
- `nonce` — fresh per-request randomness. Prevents an attacker from
  replaying a captured envelope.
- `timestamp` — unix seconds when the envelope was assembled. Verifiers
  SHOULD reject envelopes outside ±60 seconds of their local clock to
  bound the replay window even when `nonce` reuse is undetected.
- `agent_sig` — EdDSA signature over the canonical JSON encoding of
  `{leash, request, nonce, timestamp}` (sorted keys, no whitespace),
  produced by the agent's `vettid:agent_pubkey` private half.

## Scope grammar

```
scope-token  := resource ":" action [ ":" qualifier ]
resource     := identifier ( "." identifier )*
action       := "read" | "write" | "use" | "list" | "sign" | "*"
qualifier    := identifier
identifier   := [a-zA-Z][a-zA-Z0-9_-]*
```

Examples:

| Scope token | Meaning |
|-------------|---------|
| `profile.email:read` | Read the user's email field. |
| `profile.*:read` | (v2 — wildcard) Read any profile field. |
| `credential:list` | Enumerate credentials, no values. |
| `credential.sign:cred-7a9f` | Sign with one specific credential. |
| `wallet.balance:read` | Read wallet balance. |
| `message:send` | Send messages on user's behalf. |
| `*:*` | Unscoped — verifiers SHOULD reject these in production. |

v1 matching is literal string compare. The verifier checks that the
attempted action's scope token appears in `vettid:scope`. Wildcard
matching (`profile.*:read`) is reserved for v2.

## Verification algorithm

```
INPUT:
  envelope  // the request envelope above
  now       // verifier's current unix timestamp

1. Parse envelope.leash as a JWT compact form.
   On parse failure → REJECT (reason: malformed).

2. Decode and validate header:
     header.alg MUST equal "EdDSA"
     header.typ MUST equal "leash+jwt"
     header.kid MUST be present
   On any mismatch → REJECT (reason: header).

3. Resolve issuer public key:
     claims.iss MUST start with "did:vettid:"
     fetch issuer pubkey from well-known URL using user_guid + kid
   On fetch failure or pubkey not found → REJECT (reason: issuer-unknown).

4. Verify JWT signature over base64url(header) || "." || base64url(claims)
   using the resolved pubkey. On fail → REJECT (reason: bad-sig).

5. Time-bound checks:
     now >= claims.nbf
     now <= claims.exp
   On fail → REJECT (reason: expired or not-yet-valid).

6. Schema check:
     claims["vettid:v"] MUST equal 1
   On unknown version → REJECT (reason: unsupported-version).

7. Verify proof of possession:
     canon = canonical_json({
       leash: envelope.leash,
       request: envelope.request,
       nonce: envelope.nonce,
       timestamp: envelope.timestamp
     })
     Verify envelope.agent_sig over canon using claims["vettid:agent_pubkey"].
   On fail → REJECT (reason: pop-failed — likely a replayed bearer token).

8. Envelope freshness:
     abs(now - envelope.timestamp) <= 60
   On fail → REJECT (reason: stale-envelope).

9. Scope match:
     scope_token = derive_scope_token(envelope.request)
     scope_token MUST appear in claims["vettid:scope"]
   On miss → REJECT (reason: scope-miss).

10. Revocation check:
      GET claims["vettid:revocation_url"]
      Response.revoked MUST equal false
    On revoked → REJECT (reason: revoked, with revoked_at).
    On network error → policy choice:
      - Fail-closed (recommended for high-stakes scopes)
      - Fail-open with warning (acceptable for read-only demos)

11. RETURN {
      verified: true,
      issuer: claims.iss,
      subject: claims.sub,
      scope_used: scope_token,
      scopes_granted: claims["vettid:scope"],
      time_remaining_secs: claims.exp - now,
      grant_version: claims["vettid:grant_version"],
      profile_version_at_grant: claims["vettid:profile_version"],
      evidence: { jwt_pubkey_kid: header.kid, agent_pubkey_used: claims["vettid:agent_pubkey"] }
    }
```

## Key publishing

Issuer attestation public keys are published at:

```
GET https://api.vettid.dev/v1/public/leash/keys/{user_guid}
→ {
    "user_guid": "...",
    "keys": [
      {
        "kid": "leash-attest-{user_guid}-v1",
        "alg": "EdDSA",
        "pubkey": "<32-byte Ed25519 pubkey, base64url>",
        "created_at": 1716000000,
        "rotated_at": null
      }
    ]
  }
```

The endpoint is unauthenticated, public-read. Returns all live keys for
the user (active + within rotation grace period); verifiers select by
`kid` from the JWT header.

Verifiers SHOULD cache responses for ~1 hour. Rotation procedure (v2)
will require all live keys to overlap by at least the longest leash TTL
so verifiers see the new key before any leash signed with it lands.

## Revocation endpoint

```
GET https://api.vettid.dev/v1/public/leash/status/{jti}
→ {
    "jti": "leash-...",
    "revoked": false,
    "revoked_at": null,
    "reason": null,
    "checked_at": 1716483800
  }
```

Backed by a Lambda that queries the issuing vault for the current state
of `leash/issued/{jti}`. Returns 404 if the `jti` was never issued by
any known vault (verifiers SHOULD treat 404 the same as `revoked: true`
— a leash that doesn't exist in the issuer's records is not a leash a
relying party should honor).

Caching: verifiers SHOULD cache for ≤30 seconds. Faster than the pubkey
endpoint because revocation is the time-sensitive bit.

## Sample token

A representative LEASH for a fictional user `alice-demo-guid` granting
agent `agent-demo-guid` the right to read email and use one credential
for 1 hour, version 4 of the grant series:

**Header (decoded):**
```json
{
  "alg": "EdDSA",
  "typ": "leash+jwt",
  "kid": "leash-attest-alice-demo-guid-v1"
}
```

**Claims (decoded):**
```json
{
  "iss": "did:vettid:alice-demo-guid",
  "sub": "agent:agent-demo-guid",
  "iat": 1716483600,
  "nbf": 1716483600,
  "exp": 1716487200,
  "jti": "leash-01h7f3a2b9c4d5e6f7g8h9j0k1",
  "vettid:v": 1,
  "vettid:scope": ["profile.email:read", "credential.sign:cred-7a9f"],
  "vettid:grant_version": 4,
  "vettid:profile_version": 47,
  "vettid:agent_pubkey": "lDdr8mOzMz6_iyk7Q-PFmCnG2X8wQNFSDD7gOzNqIKE",
  "vettid:revocation_url": "https://api.vettid.dev/v1/public/leash/status/leash-01h7f3a2b9c4d5e6f7g8h9j0k1",
  "vettid:audience": null
}
```

The compact-form JWT is `base64url(header).base64url(claims).base64url(sig)`.
Sprint 1 produces a real one we can paste into <https://jwt.io>.

## Threat model

What a LEASH defends against:

- **Credential leak via agent compromise.** The agent never holds the
  underlying secret. The leash only authorizes specific actions, performed
  by the vault (or a service that consults the vault), not by the agent
  itself.
- **Token theft.** The agent's possession proof requires the holder's
  private key on every call. A stolen JWT alone produces no valid
  envelopes.
- **Token replay.** Per-envelope nonces + ±60s timestamp window bound
  replay even within a short window.
- **Stale grant replay.** Grant versioning means a wider leash from an
  earlier issuance can't be used after the user has tightened scope.
- **Algorithm confusion.** Fixed `alg=EdDSA` and `typ=leash+jwt` plus a
  custom verifier rejects every classic JWT shenanigan.
- **Revoked-leash use.** Per-jti revocation endpoint, cached briefly, gives
  the user immediate kill-switch.

What a LEASH does NOT defend against (out of scope for v1):

- **Compromised attestation key on the user's side.** If the user's vault
  is broken, the attacker can mint arbitrary leashes for that user. Bounded
  in blast radius by the separation from other vault keys.
- **Compromised verifier.** The verifier sees the agent's intended action.
  A malicious verifier could log it. Use `vettid:audience` (v2) to bind
  leashes to specific verifiers if this matters.
- **Side-channel inference about user data.** The leash claims contain
  scope strings and key IDs; if those reveal sensitive structure about the
  user (e.g., the existence of a "medical-records" credential), they leak.
  Mitigation: use opaque/randomized identifiers for resources.

## v2 hardening notes

When the demo graduates to production, three changes are likely worth it:

1. **PASETO v4.public** instead of JWT. Same EdDSA crypto, but the format
   strips the algorithm field entirely (no negotiation, no confusion) and
   makes claim parsing safer by construction. The tradeoff is universal
   library support — JWT verifiers exist in every language; PASETO does
   not. The v1 choice favors adoption.
2. **Mandatory `vettid:audience`.** Bind every leash to a specific
   verifier identity. Stolen tokens become useless at any other endpoint.
3. **Per-scope enforcement of `vettid:profile_version`.** Today
   informational. v2 lets scope-policy declare which fields are
   version-sensitive (e.g., a leash that references a credential by ID
   should invalidate when that credential rotates).
