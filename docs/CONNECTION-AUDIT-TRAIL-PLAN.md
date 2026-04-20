# Connection Audit Trail Plan

Last updated: 2026-04-20.

## Problem

The Connection History screen (app-side) is meant to show a user's complete
interaction record with a peer: messages, calls (voice + video, including
missed), BTC transfers, connection lifecycle events, key rotations, security
alerts. Today it fishes events out of the global feed cache filtered by
`connection_id` (or a handful of related metadata keys).

Two gaps make this insufficient:

1. The global feed **doesn't carry every interaction.** Messages live in
   `messages/` storage addressed via `message.list`. Call events are only
   emitted into the feed for specific outcomes (`call.missed`,
   `call.completed`) and not for every lifecycle transition. Certain events
   (key rotation, crypto changes) don't emit feed events at all.
2. The feed has **retention and pagination pressure.** It's a dashboard
   stream, capped at `MAX_CACHED_EVENTS = 500` on the app and trimmed over
   time on the vault. A 2-year-old conversation will not survive in the feed
   cache even if the messages themselves are retained elsewhere.

Result: "Interaction History" is a best-effort dashboard view, not an audit
trail. We promise completeness in the UI copy; we don't deliver it.

## Goal

A durable, per-connection audit trail owned by the vault, queryable by the
app, covering every user-visible interaction with that peer. The
`ConnectionHistoryScreen` becomes a faithful projection of this trail.

Non-goals:

- Replacing the message store (`message.list` continues to serve conversation
  rendering — the audit references messages by id, doesn't duplicate bodies).
- Replacing the global feed (dashboard + cross-connection events stay there).
- Server-side log aggregation or compliance export (a later layer can build
  on this; not in scope).

## Current State (as of 2026-04-20)

- `connections/<id>/` namespace on the vault holds the connection record,
  `_peer_profile`, `_connection_keys`, and a handful of related blobs.
- Message preview + last-message-at are computed by
  `getMessagePreview(connID)` at list time by scanning the message store.
- Feed events with `metadata.connection_id` or `sourceId == connectionId`
  are the only events the app can correlate to a connection today.
- No per-connection event log exists; no vault handler exposes one.

## Design

### 1. Storage layout

New subtree under each connection:

```
connections/<connection_id>/audit/index         → []audit_entry_id sorted desc by created_at
connections/<connection_id>/audit/<entry_id>    → JSON AuditEntry
```

`entry_id` is a ULID so ordering is natural and the index can be kept
append-only (new entries go to the head).

### 2. `AuditEntry` schema

```go
type AuditEntry struct {
    EntryID      string            `json:"entry_id"`        // ULID
    ConnectionID string            `json:"connection_id"`
    PeerGUID     string            `json:"peer_guid"`
    EventType    string            `json:"event_type"`      // see taxonomy
    Direction    string            `json:"direction,omitempty"` // "outbound"|"inbound"|"internal"
    Title        string            `json:"title"`           // human-readable
    Body         string            `json:"body,omitempty"`  // message preview, call summary, etc.
    CreatedAt    int64             `json:"created_at"`      // epoch seconds
    // Event-specific payload. Kept small — bodies reference IDs that the
    // app can resolve on detail view (message_id, call_id, transfer_id).
    Refs         map[string]string `json:"refs,omitempty"`
    Metadata     map[string]string `json:"metadata,omitempty"`
}
```

Taxonomy (initial):

- `message.sent`, `message.received` — `refs.message_id`
- `call.voice.started`, `call.voice.completed`, `call.voice.missed`
- `call.video.started`, `call.video.completed`, `call.video.missed`
- `call.rejected` — `metadata.reason`
- `transfer.btc.sent`, `transfer.btc.received` — `refs.tx_id`, `metadata.amount_sats`
- `connection.created`, `connection.accepted`, `connection.revoked`,
  `connection.rotated`
- `security.key.rotated`
- `security.alert` — `metadata.severity`, `metadata.detail_key`

### 3. Write points (vault-side)

Writes happen inline with the operations that produce the event, not as a
background scan. One helper to keep each call site small:

```go
auditLog.Append(ctx, AuditEntry{...})
```

Write points:

- `HandleSendMessage` → `message.sent` (refs.message_id = generated id)
- Incoming message processor → `message.received`
- `CallHandler` state transitions → `call.<kind>.<outcome>`
- `WalletHandler.HandleSendToConnection` success → `transfer.btc.sent`
- `WalletHandler.HandleIncomingPayment` success → `transfer.btc.received`
- `HandleCreateConnection` / `HandleAcceptConnection` / `HandleRevoke` /
  `HandleRotateKeys` → the corresponding `connection.*` entry
- Security handlers when a per-connection alert fires →
  `security.alert`

Writes are fire-and-forget with an error log on failure: the primary
operation must not fail because the audit log is unavailable.

### 4. Query handlers

#### `connection.audit.list`

Request:

```json
{
  "connection_id": "conn-…",
  "limit": 50,
  "cursor": "<entry_id>",         // optional, from previous page
  "since_epoch": 1730000000,       // optional, exclude older
  "event_types": ["message.", "call."]  // optional, prefix filter
}
```

Response:

```json
{
  "entries": [ AuditEntry, … ],
  "next_cursor": "<entry_id>",  // null if end
  "total_estimate": 1234        // from index length, not strict
}
```

Reads the index, walks the keys lazily in page-sized chunks. Filter
pushdown is simple prefix match on event_type.

#### `connection.audit.search`

Agents can append entries faster than a human user — tens of
`agent.action.executed` events in a single session — so the trail for an
agent connection can grow into the thousands of entries quickly. A
client-only filter over a paged list makes search laggy once a trail is
that deep. First-class server-side search from day one.

Backing store: a SQLite FTS5 virtual table inside the vault's encrypted
storage, indexed on `title` and `body`. Populated synchronously in the same
transaction as `auditLog.Append`. Search returns IDs; the handler
hydrates the full `AuditEntry` records via the key-value lookups.

Request:

```json
{
  "connection_id": "conn-…",
  "query": "invoice",          // FTS5 MATCH query
  "limit": 50,
  "cursor": "<entry_id>",        // optional
  "event_types": ["message."]    // optional
}
```

Response shape matches `connection.audit.list`. Empty `query` degrades
to a plain list (same code path as `.list`).

### 5. App integration

- `ConnectionHistoryViewModel` switches its data source from
  `FeedRepository` to a new `ConnectionAuditClient.list(connectionId, …)`.
- Paginated scroll replaces the "load everything up front" pattern.
- Event → screen routing (the user's follow-up ask) uses `Refs`:
  - `message.*` + `refs.message_id` → navigate to `ConversationScreen` with
    a scroll target, or open a message detail dialog.
  - `call.*` + `refs.call_id` + metadata.duration_seconds → open a compact
    call-detail sheet (duration, outcome, video/voice, start/end time).
  - `transfer.btc.*` + `refs.tx_id` → open wallet-tx detail / explorer.
- Search box calls `connection.audit.search` with the user's query; results
  paginate via the same cursor protocol as `.list`. No client-side filter
  fallback — agent trails grow large enough that naive filtering lags.

### 6. Backfill

On first read after the feature ships, the vault sees an empty `audit/index`
for existing connections. One-shot reconstruction:

1. Enumerate messages in `messages/<connection_id>/*` → emit
   `message.sent` / `message.received` entries with original timestamps.
2. Scan the global feed for `connection_id`-tagged events matching the
   audit taxonomy → emit synthesized entries.
3. Pull the connection record's lifecycle timestamps (`CreatedAt`,
   `KeyExchangeAt`, `LastRotatedAt`) → emit lifecycle entries.

Marker key `connections/<id>/audit/_backfilled` = true after success so the
reconstruction doesn't rerun.

Backfill runs lazily on the first `connection.audit.list` for that
connection, not eagerly at enclave startup. Keeps vault restart cheap.

### 7. Rollout

1. Land schema + `auditLog.Append` helper + write points (no new handler
   yet). Entries start accruing; nothing reads them yet.
2. Deploy enclave. Observe size growth; confirm no perf regression on the
   happy paths.
3. Land `connection.audit.list` handler + backfill. Deploy.
4. App flips `ConnectionHistoryViewModel` to the new client. Keep the
   feed-filter path as a fallback behind a remote-config flag for the
   rollout week.
5. Remove the fallback once telemetry shows audit coverage is complete.

### 8. Security / Privacy

- Audit entries live inside the vault's DEK-encrypted storage — same trust
  boundary as messages. No new crypto surface.
- Entries never leave the vault in plaintext; only the owner can read them.
- Bodies are kept short (message preview only, not full body). Messages
  remain the source of truth for content.
- Retention: capped per connection (proposed 10,000 entries or 2 years,
  whichever first). Trimming by oldest `created_at` on every write that
  crosses the threshold.

### 9. Resolved design decisions

- **Preview length.** Body stores the first 120 chars of the message —
  matches the feed-event preview length. Longer content forces navigation
  to the conversation.
- **Cross-device sync.** Not applicable — the audit log lives in the
  vault, which is the single source of truth across a user's devices.
  No per-device state.
- **Agent connections.** Same schema as peer connections. Agent-specific
  event types (`agent.action.executed`, `agent.secret.accessed`) extend
  the taxonomy; the underlying append / list / search handlers treat
  them identically.
- **Search.** Server-side FTS5 (see `connection.audit.search` above).
  Built in from day one rather than deferred — agent connections can
  accrue thousands of entries in a session and a client-only filter
  doesn't scale to that.

### 10. Cost estimate

- Vault-side implementation: helper file (~80 lines) for append + FTS index
  maintenance, six to eight write-point edits (one line each), two new
  handler files (`audit.list` ~100 lines, `audit.search` ~150 lines with
  FTS5 wiring), backfill routine (~120 lines). Unit tests throughout.
- App-side: new `ConnectionAuditClient` (~120 lines — list + search),
  rewrite `ConnectionHistoryViewModel` (~180 lines with paginated scroll
  + debounced search), new detail screens for call / transfer refs
  (~200 lines).
- Rollout: 3-4 enclave deploys (code land, handler land, flag flip, flag
  remove).

Rough effort: 3-4 focused days of vault work (FTS5 integration adds a day)
+ 1-2 days of app work, plus testing and the rollout cadence.

## Summary

- Move per-connection interaction history from "filter the global feed" to
  "read the connection's own audit log."
- Storage, handler, app client all scoped to `connections/<id>/audit/*`.
- Backfill from existing message + feed data on first read so existing
  connections aren't empty.
- Phased rollout with a feed-filter fallback behind a flag during cutover.
