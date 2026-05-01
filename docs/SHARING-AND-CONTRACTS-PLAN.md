# Sharing & Contracts Plan

A unified per-connection sharing surface, plus the runtime that enforces
it.

> Drives off two design notes from `vettid/zero-knowledge-trust`:
> [the-shared-table.md](https://github.com/vettid/zero-knowledge-trust/blob/main/shared-table.md)
> for the namespace + sandbox model and
> [the-contract.md](https://github.com/vettid/zero-knowledge-trust/blob/main/the-contract.md)
> for the structured-contract enforcement model.

---

## 0. Why this plan

Today the per-connection sharing story is fragmented across at least
four parallel mechanisms:

| Mechanism | Storage | UI surface |
|---|---|---|
| Handler grants | `connections/{id}/share_handlers` | "Handlers" item on detail screen → dialog |
| Action allowlists | `actions/_enabled[*].allowlist` | (vault-internal, no per-connection UI) |
| Discoverability | `personal-data/{name}.discoverability`, `credential-secrets/_metadata[*].discoverability` | Per-row segmented control on Personal Data / Critical Secrets screens |
| Capability requests | `connections/{id}/_capability_requests` | (request flow exists in vault but not surfaced in UI) |

A peer or service has to interact with all four to get any meaningful
"what is shared with whom" answer, and the user has no single place to
review or modify the picture. The two design notes describe what that
single place should look like — a Sharing screen per connection with
four sections — and a runtime contract enforcement engine that the
Sharing screen renders.

This plan turns that into:

1. A unified data model (`_share_policy`, `_contract`, `sandbox/`,
   `transparent/`) for per-connection sharing state.
2. A request lifecycle that gates every peer-originated subject through
   the same checks.
3. Five UI phases that each ship something testable on their own.

The plan is deliberately sequenced so peer-connection sharing (the
common case) lands before service-connection contracts (the formal
case), and shared sandboxes (the deep one) come last.

---

## 1. Architecture overview

### 1.1 Namespace mapping (existing → conceptual)

The shared-table.md doc names four namespaces. Today's vault storage
already has matching prefixes; this plan introduces only one new one
(`sandbox/`) and fills in some gaps inside `connections/{id}/`.

| Conceptual namespace | Existing storage prefix | Notes |
|---|---|---|
| Personal | `profile/`, `personal-data/`, `credential-secrets/`, `wallets/` | No change. |
| System | `_vault/`, `auth/`, `_audit/`, `connections/_index`, `handlers/_state` | No change. |
| Per-connection | `connections/{id}/...` (existing keys: peer profile cache, message log, handler grants, capability requests) | Adds `_share_policy`, `_contract`, `_quota`, `transparent/`. |
| Shared sandbox | (new) `connections/{id}/sandbox/...` | Phase 5. |

Everything stays inside the vault DEK. Nothing in this plan changes the
wire-encryption model or the at-rest model — it's all higher-level
organization on top of `EncryptedStorage`.

### 1.2 Two connection types, two policy models

Per the contract doc:

- **Peer connections** — symmetric, lightweight. No formal contract.
  Sharing is each side's `_share_policy`: per-item allow/deny + rate +
  retention. Two vaults, each one running its own policy on incoming
  requests, no shared document.

- **Service connections** — asymmetric, formal. The service publishes a
  `Contract` document; the user's vault renders it; the user accepts
  or declines. The vault enforces the contract verbatim on every
  subsequent request. `_contract` lives on the user's side as the
  authoritative copy.

`_share_policy` and `_contract` are deliberately distinct:
- A peer connection has a `_share_policy` only.
- A service connection has both a `_contract` (the document the service
  published) AND a `_share_policy` derived from it (the runtime
  cache). The cache exists so the enforcement engine doesn't re-walk
  the contract document on every request.

### 1.3 The Sharing surface

The Sharing screen replaces today's scattered controls:

```
ConnectionDetailScreen
└── "Sharing" card (new) → SharingScreen
    ├── Shared with me        (peer's catalog → request UI)
    ├── Shared with connection (my policy → per-item editor)
    ├── Shared sandbox         (Phase 5)
    └── Connection contract    (service-vault only; read-only + update flow)
```

Today's "Handlers" / Discoverability controls don't disappear — they
become read paths driven by the new unified policy. The user manages
sharing on the Sharing screen; legacy screens reflect what's there.

---

## 2. Data models

All `json` shapes; serialized into `EncryptedStorage` at the listed
keys.

### 2.1 Share policy (peer + the service-cache)

Storage key: `connections/{id}/_share_policy`

```go
type SharePolicy struct {
    Version   int                       `json:"version"`        // schema version
    UpdatedAt int64                     `json:"updated_at"`     // unix
    Items     map[string]SharePolicyItem `json:"items"`         // keyed by SharePolicyKey()
    Defaults  SharePolicyDefaults       `json:"defaults"`        // applied to items not in map
}

// SharePolicyKey is "<kind>:<id>" — e.g.:
//   data:contact.phone.mobile
//   secret:9d3f-...        (CredentialSecretEntry.ID)
//   wallet:wallet-bc1q...  (WalletRecord.WalletID)
//   handler:profile        (HandlerCatalog ID)
//   action:secrets.share   (ActionDef.ID)
//
// One key namespace covers every shareable thing so the enforcement
// engine has a single dispatch table.
type SharePolicyItem struct {
    Allowed         bool   `json:"allowed"`
    Tier            Tier   `json:"tier"`             // see §2.3
    Retention       Retention `json:"retention"`     // see §2.4
    RateLimitPerHr  int    `json:"rate_limit_per_hour,omitempty"` // 0 = unlimited
    ExpiresAt       int64  `json:"expires_at,omitempty"`           // 0 = never
    RequiresApproval bool   `json:"requires_approval,omitempty"`   // forces consent tier even if catalog says on-demand
    Note             string `json:"note,omitempty"`                 // user-facing memo; surfaces in audit
}

type SharePolicyDefaults struct {
    // For items NOT explicitly listed in Items. The default at
    // connection creation is "everything published-profile-visible is
    // allowed; everything else default-deny".
    AllowPublishedProfile bool `json:"allow_published_profile"` // _system_*, public_key, photo
    DefaultTier           Tier `json:"default_tier"`             // typically Consent
    DefaultRetention      Retention `json:"default_retention"`   // typically Session
}
```

### 2.2 Contract (service connections)

Storage key: `connections/{id}/_contract` (active), `connections/{id}/_contract_pending` (proposed update).

```go
type Contract struct {
    // Identity (per the-contract.md "Identity" section)
    ServiceID         string `json:"service_id"`           // stable identifier
    ServiceName       string `json:"service_name"`
    ServicePublicKey  string `json:"service_public_key"`   // Ed25519, hex
    Verified          bool   `json:"verified"`
    PublishedAt       int64  `json:"published_at"`
    Version           int    `json:"version"`              // monotonic per service_id
    HumanTermsURL     string `json:"human_terms_url,omitempty"`
    PrivacyPolicyURL  string `json:"privacy_policy_url,omitempty"`

    // The structured terms the vault enforces
    Fields      []ContractField     `json:"fields"`
    Permissions ContractPermissions `json:"permissions"`
    RateLimits  ContractRateLimits  `json:"rate_limits"`
    Sandbox     *SandboxTerms       `json:"sandbox,omitempty"` // present when contract includes a shared sandbox

    // Signed by ServicePublicKey; covers all fields above. The vault
    // verifies on contract.publish AND on every retrieval before
    // enforcement (defense-in-depth — storage tampering would be
    // detected).
    Signature string `json:"signature"`
}

type ContractField struct {
    Name      string    `json:"name"`        // dotted: "contact.email", "personal.legal.last_name"
    Tier      Tier      `json:"tier"`        // required | optional | on_demand | consent
    Purpose   string    `json:"purpose"`     // human-readable why
    Retention Retention `json:"retention"`   // session | time_limited | until_revoked
    TTLDays   int       `json:"ttl_days,omitempty"` // valid only when Retention=time_limited
}

type ContractPermissions struct {
    CanStore             bool   `json:"can_store"`
    StorageCategories    []string `json:"storage_categories,omitempty"` // when CanStore
    StorageMaxMB         int    `json:"storage_max_mb,omitempty"`
    CanSendMessages      bool   `json:"can_send_messages"`
    CanRequestAuth       bool   `json:"can_request_auth"`
    CanRequestPayment    bool   `json:"can_request_payment"`
}

type ContractRateLimits struct {
    RequestsPerHour int `json:"requests_per_hour"`
}
```

### 2.3 Tier enum

```go
type Tier string

const (
    TierRequired Tier = "required"  // connection cannot exist without this field
    TierOptional Tier = "optional"  // requested but declinable; connection still proceeds
    TierOnDemand Tier = "on_demand" // service can pull at any time, within rate limits
    TierConsent  Tier = "consent"   // every access requires explicit user approval
)
```

For peer connections, tiers map to share-policy semantics:
- `required` is moot (peer connections have no required fields)
- `optional` ≈ "user offered this; peer can request"
- `on_demand` ≈ "auto-allow within rate limit"
- `consent` ≈ "prompt user every time"

### 2.4 Retention enum

```go
type Retention string

const (
    RetentionSession      Retention = "session"
    RetentionTimeLimited  Retention = "time_limited"
    RetentionUntilRevoked Retention = "until_revoked"
)
```

`session` and `time_limited` need active enforcement (a sweep + lazy
check). `until_revoked` is the do-nothing default — revocation cleans
up.

### 2.5 Token-bucket quota state

Storage key: `connections/{id}/_quota`

```go
type QuotaState struct {
    // Token bucket per (connection, scope). Scope is "request" for
    // contract rate limits; can extend per-action or per-field later.
    Buckets map[string]TokenBucket `json:"buckets"`
}

type TokenBucket struct {
    Capacity     int   `json:"capacity"`      // RequestsPerHour from contract
    Tokens       float64 `json:"tokens"`      // current
    LastRefillAt int64 `json:"last_refill_at"` // unix
}
```

The bucket is refilled lazily: `tokens = min(capacity,
tokens + (now - last_refill) * (capacity / 3600))`. No background
ticker required.

### 2.6 Shared sandbox (Phase 5)

Storage prefix: `connections/{id}/sandbox/`

```
connections/{id}/sandbox/_meta              -> SandboxMeta (host, contract terms, schema version)
connections/{id}/sandbox/local/{key}        -> opaque blob (my private side)
connections/{id}/sandbox/mutual/{key}       -> opaque blob (both can read; writes per contract)
connections/{id}/sandbox/remote/{key}       -> cache of peer's reads of my mutual area (audit)
```

The peer's "their side" lives in the peer's vault, not mine. `remote/`
is read-through cache only.

```go
type SandboxMeta struct {
    HostOwnerSpace string `json:"host_owner_space"` // creator's vault
    CreatedAt      int64  `json:"created_at"`
    Terms          SandboxTerms `json:"terms"`     // copied from contract
}

type SandboxTerms struct {
    PortabilityOnDisconnect bool `json:"portability_on_disconnect"`
    PurgeRemoteSideOnDisconnect bool `json:"purge_remote_side_on_disconnect"`
    MutualWritesRequireApproval bool `json:"mutual_writes_require_approval"`
}
```

### 2.7 Transparent data store

Storage prefix: `connections/{id}/transparent/`

When a peer/service shares a value with me via `capability.respond`
approve, the value lands here keyed by what the peer called it:

```
connections/{id}/transparent/{kind}/{id} -> {value, received_at, retention}
```

This is the user's "the peer shared this with me" inventory. The
Sharing screen's "Shared with me" section reads from here.

---

## 3. Wire ops

### 3.1 New ops

| Op | Direction | Purpose |
|---|---|---|
| `connection.share-policy.get` | app → vault | Fetch `_share_policy` for a connection |
| `connection.share-policy.set` | app → vault | Replace or merge policy items |
| `contract.publish` | service → user-vault | Service-vault delivers a new contract version |
| `contract.get` | app → vault | Fetch active contract for a connection |
| `contract.accept` | app → vault | User accepted; activate a pending contract |
| `contract.decline` | app → vault | User declined; terminate the connection |
| `contract.diff` | app → vault | Compute added/removed/changed for a pending vs active contract |
| `sandbox.create` | app → vault | Provision sandbox storage on this vault |
| `sandbox.put` | app → vault, vault → peer-vault | Write a key in mine-or-mutual; mirrored if shared |
| `sandbox.get` | app → vault, vault → peer-vault | Read a key |
| `sandbox.list` | app → vault | List keys in one of the three areas |
| `sandbox.delete` | app → vault | Delete (governed by contract) |

### 3.2 Existing ops to extend

- `capability.request` / `capability.respond`: already exists. Extend
  to honor `_share_policy` (auto-respond when item is `on_demand` and
  in policy; create pending request when `consent`).
- `handlers.share-handlers.{get,set}`: stays for the legacy "Handlers"
  dialog; internally rewrites to `_share_policy` updates with key
  prefix `handler:`.
- `action.set-enabled`: same — internal rewrites to `_share_policy`
  updates with key prefix `action:`.
- `credential.secret.set-discoverability` /
  `personal-data.set-discoverability`: stay; internal rewrites to
  `_share_policy` defaults plus per-item entries.

The legacy ops are kept as façades so older code (and the existing
screens) keep working through Phase 1–2. Phase 2's exit criteria is
"all writes go through `connection.share-policy.set`; legacy ops are
adapters." Phase 3 can remove them once the Sharing screen is
authoritative.

---

## 4. Enforcement engine

### 4.1 The request lifecycle

Every peer-originated subject (today: `forVault.message.>`,
`forVault.read-receipt`, `forVault.location-update`,
`forVault.btc-payment-request`, `forVault.invoke-action`, etc.)
already passes through `gatePeerSubject` → `peerHandlerForIncomingSubject`
→ `gateOperation` in `handler_authorization.go`.

The plan threads contract checks INSIDE the existing gate, not
parallel to it:

```
gatePeerSubject(operation, payload)
  ├── extractSenderGUID(payload)               (existing)
  ├── findConnectionByPeerGUID(senderGUID)     (existing)
  ├── ContractEnforcer.check(conn, request) ←─ NEW
  │     ├── isContractCurrent(conn)            – pending update? freeze.
  │     ├── isFieldInContract(field)           – contract-declared?
  │     ├── tierAllowsAccess(field, source)    – on_demand ok; consent → pending
  │     ├── retentionStillValid(field, conn)   – auto-purge expired data
  │     ├── isWithinRateLimits(conn)           – token bucket
  │     └── isPolicyAllowed(item)              – peer share-policy
  └── gateOperation(handlerID, "peer", connID) (existing — kept as the final gate)
```

`ContractEnforcer` is the new module. For peer connections (no
`_contract`), it short-circuits into just `isPolicyAllowed`. For
service connections (with `_contract`), it runs the full chain.

### 4.2 Module shape

```go
// vault-manager/contract_enforcer.go (new)
type ContractEnforcer struct {
    storage *EncryptedStorage
    auditLog *AuditLog
}

type EnforceRequest struct {
    ConnectionID string
    Field        string  // "contact.email" or "<empty>" for non-field requests
    Operation    string  // "new-message", "invoke-action.secrets.share", etc.
    Source       string  // "peer" | "service"
    SizeBytes    int     // for storage rate limits
    Now          time.Time
}

type EnforceDecision struct {
    Allow         bool
    PendingApproval bool   // when tier=consent, the request creates a pending notification
    Reason        string   // populated when !Allow
    Code          string   // ERR_CONTRACT_*, ERR_RATE_LIMIT, etc.
}

func (e *ContractEnforcer) Check(req EnforceRequest) EnforceDecision { ... }
```

### 4.3 Integration points

- `messages.go::HandleMessage` calls `ContractEnforcer.Check` BEFORE
  the existing `gateOperation` for any subject in the
  `peerHandlerForIncomingSubject` set.
- `capabilities.go::HandleRequest` checks the policy on inbound
  capability requests; on consent items, creates a pending request as
  today; on on-demand items in policy, auto-responds.
- `wallet_handler.go`'s payment request path: same gate.
- `action_invoker.go`'s 9-step engine: ContractEnforcer slots in as
  step 0 (contract gate runs BEFORE catalog lookup so a service
  contract can deny an action before we even resolve it).

### 4.4 Default-deny everywhere

The single most important rule, lifted directly from the contract
doc:

> *If the field is not in the contract, the request is blocked. It
> does not matter if the field exists in the user's profile.*

The same applies to peer connections, but using `_share_policy`
instead of a contract: if the item isn't in `Items` and isn't covered
by `Defaults.AllowPublishedProfile`, request is denied. No silent
fallthrough.

### 4.5 Token bucket details

- One bucket per connection at the request level (capacity =
  `Contract.RateLimits.RequestsPerHour`).
- Lazy refill: on each request, refill before deduction.
- Persisted to `_quota` after every check (tiny write; storage layer
  buffers).
- A second optional bucket per `(connection, action_id)` lands in
  Phase 3 fast-follow if we need finer control.

### 4.6 Retention sweep

Two-pronged:

1. **Lazy check at access** — every `transparent/` read computes
   age vs the stored retention and returns "expired, request again"
   instead of the value. Cheap, no scan needed.
2. **Background sweep** — once a day, walk
   `connections/*/transparent/*`, drop any blob whose retention has
   lapsed. Cron-like loop on the parent process side (similar to
   `closeExpiredProposals`).

### 4.7 Audit log extension

`audit_log.go` already records connection events. Adds:

```go
const (
    EventTypeContractRequestAllowed = "contract.request.allowed"
    EventTypeContractRequestDenied  = "contract.request.denied"
    EventTypeContractRateLimited    = "contract.request.rate_limited"
    EventTypeContractRetentionExpired = "contract.field.retention_expired"
    EventTypeContractAccepted       = "contract.accepted"
    EventTypeContractDeclined       = "contract.declined"
    EventTypeContractUpdatePublished = "contract.update.published"
    EventTypeSharePolicyChanged     = "share_policy.changed"
)
```

Every `EnforceDecision` writes one record. Audit fields:
`{connection_id, timestamp, contract_version, field, operation, tier,
allow|deny, reason, bytes}`.

---

## 5. UI surfaces

### 5.1 Sharing card (entry point)

A new ListItem on `ConnectionDetailScreen`, between "Handlers" and
"Location Sharing":

```
[icon: share]  Sharing                                       (chevron)
              N items shared with you, M with this peer
```

Tap → `ConnectionSharingScreen`.

### 5.2 ConnectionSharingScreen layout

```
┌ Sharing — <Peer Name> ─────────────────────┐
│                                            │
│ ▾ Shared with me            (3)            │
│   ⓘ Email — last refreshed 2h ago          │
│   ⓘ BTC wallet address — 1d ago             │
│   ⓘ "Project notes" – mutual sandbox        │
│   [Request another item ▾]                  │
│                                            │
│ ▾ Shared with this connection (5/12)        │
│   ⊝ Email           Optional · until revoked │
│   ⊝ Phone           Consent · session         │
│   ⊝ BTC Wallet      Optional · until revoked │
│   …                                         │
│                                            │
│ ▾ Shared sandbox            (Phase 5)       │
│                                            │
│ ▾ Connection contract       (service only)   │
│   v3 · published Mar 14 · accepted Mar 15   │
│   [View contract]  [Update available!]       │
└─────────────────────────────────────────────┘
```

Each section is a collapsible card. Counts in the header give
at-a-glance state.

#### 5.2.1 Shared with me

- Lists items in `connections/{id}/transparent/`
- For peer connections: "Request another item" opens the peer's
  catalogs (data + secrets) → pick → `capability.request`
- Each row supports: tap to view value, "remove from my vault"
  (deletes locally), "ask again" (re-issues capability request when
  retention lapses)

#### 5.2.2 Shared with this connection

- Renders the entire share-policy as a list (data, secrets, wallets,
  handlers, actions all in one ordered table)
- Per-item editor sheet:
  - Allowed (toggle)
  - Tier (segmented: optional / on-demand / consent — Required is
    grayed out for peer connections)
  - Retention (segmented: session / time-limited / until-revoked,
    plus a TTL picker when time_limited)
  - Rate limit (slider: 0 / 5 / 30 / 100 / unlimited per hour)
  - Expires at (date picker, optional)
  - Note
- Default policy on a fresh connection: published-profile fields
  marked Optional + Until-Revoked; everything else default-deny.

#### 5.2.3 Shared sandbox

Phase 5 surface. Ships as "Coming soon" placeholder before then with a
short description of what it'll do.

#### 5.2.4 Connection contract

- For peer connections: short copy explaining peer connections don't
  use formal contracts, just the share policy.
- For service connections: read-only summary (identity, fields by
  tier, retention, permissions, rate limits) plus a "View raw" link
  that drops into the full machine-readable JSON for debugging. If a
  contract update is pending, a banner — `[Update available · Review →]`
  — opens the diff dialog.

### 5.3 Contract review/update flow

Two screens:

- `ContractReviewScreen` — initial acceptance (during connection
  establishment). Renders identity, fields-by-tier, permissions, rate
  limits in a long scroll. Buttons: Accept / Decline. Decline tears
  the connection down.
- `ContractDiffScreen` — update review. Three sections (Added /
  Removed / Changed) with the same level of detail. Buttons: Accept &
  Continue / Disconnect.

Both screens use a consistent template: the user sees the same shape
for every contract from every service.

### 5.4 Audit visibility

Reusing the existing connection audit screen. New event types render
with appropriate icons:
- 🛡 contract accepted/declined/updated
- ⛔ request denied (with the field/operation/reason)
- ⏱ retention expired
- 🪣 rate-limited

The user can filter by event type to see "what has this service
actually accessed?" — the doc's "complete tamper-evident record."

---

## 6. Phased rollout

Each phase is independently shippable and independently testable.

### Phase 1 — Sharing screen scaffold + Shared with me

**Goal**: surface the existing capability flow + read-side of
sharing. No new enforcement. No data model migrations.

**Files added**
- `vettid-android/.../features/sharing/ConnectionSharingScreen.kt`
- `vettid-android/.../features/sharing/ConnectionSharingViewModel.kt`
- `vettid-android/.../features/sharing/SharedWithMeSection.kt`

**Files changed**
- `ConnectionDetailScreen.kt`: add Sharing card
- `VettIDApp.kt`: nav route
- `ConnectionsClient.kt` / `OwnerSpaceClient.kt`: thin wrappers around
  existing `capability.request` / `capability.respond`

**Vault changes**: none (or minor — surface
`connections/{id}/transparent/` listing via a new
`capability.list-shared-with-me` op).

**Test plan**
- Both peers connect. A's peer card shows the new Sharing card.
- A taps Sharing → sees empty Shared-with-me section + B's catalog
  items as request candidates.
- A requests B's email → B's vault creates a pending capability
  approval → B approves → A's `transparent/data:contact.email` lands
  → A's Shared-with-me section shows the row.

### Phase 2 — Peer share-policy unification

**Goal**: one storage location for "what I share with this peer," one
editor surface, and the legacy ops become façades.

**Files added**
- `vettid-dev/enclave/vault-manager/share_policy.go` —
  `SharePolicy` type, get/set ops, key conversion helpers.

**Files changed**
- `vettid-dev/enclave/vault-manager/handler_authorization.go`:
  `isHandlerGrantedToConnection` reads `_share_policy` instead of
  `share_handlers`. Migration path: read-through fallback if
  `_share_policy` is empty but `share_handlers` exists.
- `vettid-dev/enclave/vault-manager/action_authorization.go`: same
  swap for `EnabledAction.Allowlist`.
- `vettid-dev/enclave/vault-manager/credential_secret_handler.go` +
  `personal_data_handler.go`: discoverability becomes the per-item
  policy item. Default updates also touch `_share_policy.Defaults`.
- Android Sharing screen: `SharedWithConnectionSection.kt` becomes
  the canonical editor; the legacy "Handlers" dialog and
  per-row-discoverability controls keep functioning but write through
  the new policy.

**Vault changes**: new ops `connection.share-policy.get` /
`connection.share-policy.set`. Legacy ops re-route internally.

**Test plan**
- Existing handler grants migrate cleanly (read-through on first
  access; explicit migration on next set).
- Toggling a field in the new editor is reflected in the legacy
  Handlers dialog immediately.
- Default policy on a fresh connection: only published-profile fields
  appear as "Allowed" out of the box. All other fields default-deny.

### Phase 3 — Contract data model + enforcement engine

**Goal**: service-vault connections gain a real contract; peer + service
connections both run their incoming requests through
`ContractEnforcer`.

**Files added**
- `vettid-dev/enclave/vault-manager/contract.go` — `Contract` type,
  signature verify, get/publish/accept ops.
- `vettid-dev/enclave/vault-manager/contract_enforcer.go` — the
  request-lifecycle gate.
- `vettid-dev/enclave/vault-manager/quota.go` — token-bucket
  primitive.
- `vettid-dev/enclave/parent/scheduled_retention_sweep.go` — daily
  retention purger.

**Files changed**
- `vettid-dev/enclave/vault-manager/messages.go`: every peer
  dispatch path calls `ContractEnforcer.Check` before
  `gateOperation`.
- `vettid-dev/enclave/vault-manager/audit_log.go`: new event types.
- `vettid-dev/enclave/vault-manager/capabilities.go`: routes through
  policy/contract decision (auto-respond vs pending).

**Vault changes**: new ops `contract.publish` (peer →
`forVault.contract.publish` from a service vault), `contract.get`,
`contract.accept`, `contract.decline`.

**Test plan**
- Build a fake service vault that publishes a Contract with a single
  Required field (email) and an On-Demand field (phone, 10/hour).
- User accepts the contract → email pulls work, phone pulls within
  rate limit work, the 11th phone pull in a 60-minute window is
  rejected with `ERR_RATE_LIMIT`.
- Service publishes v2 with phone removed → user-side records the
  pending update, freezes v1 — any phone request after that point is
  denied with `ERR_CONTRACT_PENDING_UPDATE` until the user accepts
  v2.

### Phase 4 — Contract presentation + update flow

**Goal**: ContractReviewScreen + ContractDiffScreen + the in-app
banner.

**Files added**
- `vettid-android/.../features/contracts/ContractReviewScreen.kt`
- `vettid-android/.../features/contracts/ContractDiffScreen.kt`
- `vettid-android/.../features/contracts/ContractViewModel.kt`

**Files changed**
- Connection establishment flow: when the inviter is a service vault
  with a contract, gate acceptance behind ContractReviewScreen
  instead of the existing peer-style ConnectionReviewScreen.
- `ConnectionSharingScreen`'s Contract section: light up when a
  service connection is selected.

**Vault changes**: minor — `contract.diff` op produces the
add/remove/change buckets the diff screen renders.

**Test plan**
- Accept fresh contract → connection lands active, runtime gate
  enforces.
- Decline fresh contract → connection terminated, no namespace
  created.
- Service publishes v2 → app receives push notification → user opens
  the diff screen → sees Added/Removed/Changed buckets — accept
  proceeds, decline tears down the connection cleanly (revoke flow).

### Phase 5 — Shared sandbox

**Goal**: per the shared-table.md doc, one-table-not-two-copies, host
in creator's vault.

This phase needs its own design pass before code. Key open questions
(see §7).

**Files added** (anticipated)
- `vettid-dev/enclave/vault-manager/sandbox.go`
- `vettid-android/.../features/sharing/sandbox/SandboxScreen.kt`
- A separate `SHARED-SANDBOX-DESIGN.md` companion doc.

**Files changed**
- `Contract` type: optional `Sandbox` block defines the agreement.
- `ContractEnforcer`: extends to gate sandbox writes (mutual area
  rules).
- ContractReviewScreen: a "Sandbox" section when present.

**Test plan**: deferred to design doc.

---

## 7. Decisions

Locked. Each phase implements per these.

### 7.1 Phase 2

- **Disabling a handler cascades.** When a user flips `handler:wallet`
  off in the share-policy, the policy engine MUST auto-disable every
  action whose `defaultHandler == "wallet"` for that connection.
  Same rule for any handler→action linkage. Re-enabling the handler
  does NOT auto-restore actions; the user opts each action back in
  explicitly.

- **Rate limits apply to peer connections too.** Peer-policy items
  carry the same `RateLimitPerHr` field. Default = 0 (unlimited);
  the user can dial in per-item caps when they want to throttle a
  peer the same way they would a service.

### 7.2 Phase 3

- **Contract format: JSON.** Single source of truth, readable,
  consistent with the rest of the wire.

- **Service key verification: same path as peer profile.** The
  `service_public_key` is captured at connection-establishment from
  the service's published profile and pinned. Key rotation is
  out-of-band: the service publishes a `key.rotate` event on its own
  profile subject signed by the OLD key; user-side captures the new
  key and the user is shown a confirmation diff. Until the user
  confirms, the service's old key remains the verifier — a
  compromised service cannot silently swap keys without the user
  noticing.

- **NEW — `signing.request` handler.** Both directions get a
  challenge-response op. Use cases: user verifies the service still
  controls its declared key; service verifies the user's identity at
  login or for high-value actions; anti-impersonation if a key is
  suspected compromised. Request shape:
  ```
  signing.request:  {nonce, purpose, ttl}
  signing.respond:  {nonce, signature(over nonce + connection_id + timestamp), public_key}
  ```
  - The signing handler is gated by the same share-policy / contract
    machinery as everything else — nothing signs anything without
    explicit consent.
  - Becomes its own catalog handler ID `signing` with operations
    `request` and `respond`. Surfaced in Phase 3 alongside the
    enforcement engine.

- **Retention sweep: inside the vault-manager.** More secure — the
  parent process runs outside the attestation envelope, so a
  compromised parent could skip or delay the sweep. The vault-manager
  runs inside the enclave, so the retention check is part of the
  attested code path. Implementation: a dedicated goroutine started
  at boot ticks at 24h intervals (with the next-run anchored to
  midnight UTC on first start) and walks `connections/*/transparent/`
  + per-field retention. No external cron required. Each sweep emits
  a single audit record summarizing scanned/expired counts.

### 7.3 Phase 4

- **Contract update delivery: push + banner.** Vault publishes
  `forApp.contract.update.available` to the user's owner space when
  the service publishes a new version. The Android app receives the
  push notification AND surfaces a non-dismissable banner on the
  connection card + the Sharing screen's Contract section until the
  user accepts or declines. Old contract is frozen the moment the
  vault accepts the new contract document for review (not when the
  user opens the banner).

### 7.4 Phase 5 (sandbox)

- **Hosting: creator holds the key.** Whoever called `sandbox.create`
  hosts the sandbox in their vault. Encryption-at-rest is the host's
  vault DEK. The peer accesses through the connection — no replicated
  copy, no shared encryption material across vaults. Disconnection
  rules (purge / portability) come from the contract.

- **Concurrency: last-write-wins.** Per-key timestamps; on conflict,
  the later `write_at` wins. Lines up with the doc's "one table, not
  two copies" framing — there's no second copy to merge. We surface
  the conflict in the audit log so the user can see overwrites if
  they care, but the wire op never returns a conflict error.

- **Wire ops: dedicated `sandbox.*` handlers.** Not piggybacking on
  `capability.request` — sandbox writes/reads need their own audit
  shape and their own enforcement gate (mutual-area write rules).
  Adding a handler ID `sandbox` to the catalog with operations
  `create`, `put`, `get`, `list`, `delete`. Every op records an
  audit row keyed by `{connection_id, area, key, action,
  bytes}` so disputes have full provenance.

These remain to be designed in the Phase 5 companion doc:
- Whether the host-side encryption can be augmented with peer-key
  cosigning for forensic protection (out of scope for v1).
- Mutual-area write approval flow when the contract requires it
  (likely re-uses the consent tier mechanism from contracts).

---

## 7a. Location sharing & presence — where they live

Today both controls live as discrete `ListItem`s on
`ConnectionDetailScreen` (Location Sharing toggle, Online Presence
3-state picker). Conceptually they're the same shape as every other
sharing decision — "do I share my X with this connection" — and the
Sharing screen exists to consolidate exactly that. Two-part answer:

**Canonical home: the share-policy.** Both become first-class entries
in `_share_policy.Items` keyed under a new prefix:

| Key                     | Replaces                               |
|---|---|
| `setting:location`      | `connections/{id}/_location_share_enabled` |
| `setting:presence`      | `connections/{id}/_presence_override`      |

They get the full per-item treatment — `Allowed`, `Tier`, `Retention`,
`RateLimitPerHr`, `ExpiresAt`. This unlocks a few things the current
toggles can't express today:

- "Share my location with this peer for the next 4 hours" (ExpiresAt)
- "Allow this service to query location at most 1× per hour" (rate)
- "Always share with this peer; consent-prompt for everyone else"
  (per-item Tier override)

The Sharing screen's "Shared with this connection" section renders
them as two rows alongside the data/secrets/wallets/handlers/actions
rows, with the same editor sheet.

**Quick toggle stays on the detail screen.** For frequent users the
binary "share location: on/off" toggle on the detail screen is
faster than navigating into Sharing. Keep it as a shortcut — tapping
it writes through to the same `_share_policy` entry. The toggle's
visible state always reflects `share_policy.items["setting:location"].Allowed`,
and the supporting line shows any non-default policy ("Until 6pm",
"Max 1/hr") so the user knows when the simple toggle is hiding more
nuance.

Same for the Presence picker — keep the 3-state segmented control on
detail (Follow account / Always shared / Never shared), but it's a
view onto `setting:presence` in the policy. The Sharing-screen editor
adds the time-window + rate-limit knobs.

**Migration**: on first read of a connection that has the legacy
`_location_share_enabled` or `_presence_override` keys but no
`setting:location` / `setting:presence` entries in `_share_policy`,
copy the values over and write back. Phase 2 already plans
read-through fallbacks for handler-grants; this is the same pattern
for these two.

---

## 8. Out of scope (for now)

- **Multi-party sandboxes** (3+ vaults). Doc only covers two-party.
- **Cross-service sharing** (service A asks for data the user got
  from service B). Audit-log is enough surface to make this visible
  to the user; explicit cross-service mediation is a separate
  problem.
- **Contract negotiation**. The doc is explicit: take it or leave
  it. Optional fields are the only flexibility.
- **Service-vault hosting infrastructure**. The contract document
  format and enforcement work; how `vettid-service-vault` actually
  serves them is its own track.

---

## 9. Sequencing summary

| Phase | Code scope | Vault op surface | Risk | Time |
|---|---|---|---|---|
| 1 — Sharing screen + read side | small UI | none new | low | 2-3 days |
| 2 — Peer share-policy unification | medium (vault + UI) | `connection.share-policy.{get,set}` | medium — touches grants/actions/discoverability | 1-2 weeks |
| 3 — Contract enforcement engine | large vault | `contract.{publish,get,accept,decline,diff}` | high — every peer subject changes path | 2-3 weeks |
| 4 — Contract review + update flow | medium UI | minor | low after Phase 3 | 1 week |
| 5 — Shared sandbox | extra-large | `sandbox.*` | high — needs design doc first | TBD |

Phases 1-2 give you the unified Sharing screen experience for peer
connections (today's primary use case) without committing to the
full contract enforcement runtime. Phase 3 is where the architectural
muscle goes in and the service-vault story becomes real.

---

## 10. Where the docs go

- This plan: `vettid-dev/docs/SHARING-AND-CONTRACTS-PLAN.md`
- (Phase 5) Shared-sandbox design: `vettid-dev/docs/SHARED-SANDBOX-DESIGN.md`
- Source material:
  - `https://github.com/vettid/zero-knowledge-trust/blob/main/shared-table.md`
  - `https://github.com/vettid/zero-knowledge-trust/blob/main/the-contract.md`
