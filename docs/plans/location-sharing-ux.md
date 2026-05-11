# Plan: Location-sharing UX

## Problem

The vault-to-vault location-update pipe already works (`location.go: pushToSharedConnections`). Sharer's app calls `location.sharing.add`, sharer's vault publishes a `forVault.location-update` to each peer's owner-space, peer's vault receives via `HandleIncomingLocationUpdate`.

But the viewer side stops there: the incoming update is forwarded once to `forApp.location-update` and discarded. There's no persistent peer-location cache, no "X started sharing with you" event, no UI surface where the viewer sees the shared location, and no way to *request* a peer's location.

This plan adds three layered signals (event, glance, detail) plus a "request location" verb.

## Out of scope

- Continuous background tracking on the viewer's device (we render whatever the sharer's vault pushes; the viewer doesn't subscribe-and-render-live).
- Map tile authorization. The map view uses an existing tile provider; this plan does not touch that.
- Location precision policy. Sharer-side precision settings (`getSettings`) are unchanged.
- Group sharing. One-to-one only.

---

## Vault-side changes

### V1. Stamp `from_owner_space` on outgoing peer location-updates

`pushToSharedConnections` builds `IncomingLocationUpdate{...}` with the sender's local `ConnectionID` — useless to the receiver (each vault assigns its own connection ID). Same shape of bug we fixed for `ProfileUpdateNotification.FromOwnerSpace`. Receiver needs `from_owner_space` to find the matching local connection via `FindConnectionByPeerGUID`.

**Edit** `enclave/vault-manager/location.go: IncomingLocationUpdate`:
```go
type IncomingLocationUpdate struct {
    EventID        string   `json:"event_id,omitempty"`
    ConnectionID   string   `json:"connection_id"`           // sender's id, kept for backwards compat
    FromOwnerSpace string   `json:"from_owner_space"`        // NEW: sender's owner GUID
    Latitude       float64  `json:"latitude"`
    Longitude      float64  `json:"longitude"`
    Accuracy       *float32 `json:"accuracy,omitempty"`
    Timestamp      int64    `json:"timestamp"`
    UpdatedAt      string   `json:"updated_at"`
}
```

**Edit** `pushToSharedConnections` line ~725:
```go
update := IncomingLocationUpdate{
    EventID:        fmt.Sprintf("loc:%s:%d", h.ownerSpace, point.Timestamp),
    ConnectionID:   connID,
    FromOwnerSpace: h.ownerSpace,                 // NEW
    Latitude:       lat,
    Longitude:      lon,
    Accuracy:       point.Accuracy,
    Timestamp:      point.Timestamp,
    UpdatedAt:      now.Format(time.RFC3339),
}
```

Add a wire-contract test in `peer_wire_contract_test.go`: `TestLocationUpdateWire_FromOwnerSpace` marshal sender → unmarshal receiver, assert `FromOwnerSpace` survives.

### V2. Cache the latest peer location on receipt

Today's `HandleIncomingLocationUpdate` forwards to app and forgets. We need the latest point pinned in storage so Connection Detail can render it without subscribing to live broadcasts.

**Storage key**: `connections/<connID>/_peer_location` — single JSON object overwritten on each update. Mirrors the existing `connections/<id>/_peer_profile` pattern from the profile-update broadcast handler.

**Schema** (per connection):
```json
{
  "latitude": 37.7749,
  "longitude": -122.4194,
  "accuracy": 12.5,
  "timestamp": 1715369336,
  "updated_at": "2026-05-11T14:00:00Z",
  "first_received_at": "2026-05-09T18:22:00Z"
}
```

`first_received_at` is set on the initial write and never overwritten — it's the transition marker for V3.

**Edit** `HandleIncomingLocationUpdate`:
1. After replay check, call `notificationsHandler.FindConnectionByPeerGUID(update.FromOwnerSpace)` to resolve the LOCAL connID.
2. If connID resolved, marshal a `CachedPeerLocation` and write to `connections/<connID>/_peer_location` via `storage.Put`.
3. On first write (key didn't previously exist), set `first_received_at = now()` AND emit a notification (V3).
4. Continue with the existing `PublishToApp` forward.

### V3. Emit a "started sharing" notification on transition

When `connections/<connID>/_peer_location` is being written for the first time AFTER any prior absence — either no key, or a prior `stopped_at` marker (V5 unshare flow):

```go
notif := PeerLocationShareStartedNotification{
    ConnectionID:   connID,
    FromOwnerSpace: update.FromOwnerSpace,
    StartedAt:      now.Format(time.RFC3339),
    DisplayName:    conn.DisplayName, // from ConnectionRecord
}
data, _ := json.Marshal(notif)
publisher.PublishToApp(ctx, "connection.peer-location-share-started", data)
```

Android subscribes to this in OwnerSpaceClient (existing pattern from `forApp.connection.peer-accepted`); on receipt:
- Inserts a system-card row in the activity feed: "Al started sharing their location with you" (tap → connection detail).
- Re-fetches `connection.list` so the connection card picks up the new indicator.

### V4. New op `location.peer.get` — pull cached peer location

Mobile app needs a way to read the cached point for a given connection without subscribing to broadcasts (e.g., on app open, on connection-detail open).

**Request**: `{ connection_id: string }`
**Response**:
```json
{ "shared": true, "location": {... cached struct ...} }
{ "shared": false }
```

Implementation: small handler in `location.go` that reads `connections/<connID>/_peer_location` and unmarshals.

### V5. Sharer-side: notify on share toggle off

Current `location.sharing.remove` (or whatever the toggle-off path is — verify name during implementation) silently stops pushing updates. The viewer's cache goes stale but no event fires.

**Two options:**

- **(a) Explicit unshare event** — sharer's vault publishes a one-shot `connection.peer-location-share-stopped` notification to the now-ex-recipient. Viewer's vault deletes `connections/<connID>/_peer_location` and emits a system-card row "X stopped sharing their location."
- **(b) Mark stale on viewer's clock** — viewer's app shows "Last updated 12 min ago" and grays out when older than, say, 30 min. No explicit unshare event.

**Pick (a).** It's a small symmetric counterpart to V3, gives the same activity-feed clarity, and prevents the "did they unshare or did the network drop?" ambiguity. The shape mirrors `MessageSpace.<peer>.forVault.location-update-stopped`.

### V6. New op `location.request` — one-time ping (action-button verb)

Distinct verb from "view shared location". The viewer asks the peer's vault to forward a one-shot location point.

**Wire flow:**
1. Viewer's app sends `location.request { connection_id }` to its own vault.
2. Viewer's vault publishes `forVault.location-request` to the peer's owner-space carrying `{ from_owner_space: viewer_guid, request_id }`.
3. Peer's vault receives, runs the peer-gate against the `location` handler catalog entry (already exists). If approved:
   - Peer's vault prompts the peer's app via `forApp.location-request-incoming` (UI shows "Mesmer is asking for your location. Share once / Cancel.")
   - On Share once: peer's app calls `location.respond { request_id }`, peer's vault publishes a single location-update back via the existing channel.
4. Viewer's vault receives the update (V2 caches it; treat as a one-shot — don't trip V3's "started sharing" notification since it's request-driven, not subscription-driven).

**Open question (R1):** does "Share once" grant a single point or a 5-minute window? Recommend single point for simplest mental model; can add a window option later.

---

## Android-side changes

### A1. ConnectionDetailViewModel — peer-location state

Add to state:
```kotlin
data class PeerLocationState(
    val latitude: Double,
    val longitude: Double,
    val accuracy: Float?,
    val updatedAt: Instant,
    val firstReceivedAt: Instant,
)

data class State(
    ...
    val peerLocation: PeerLocationState? = null,   // null = peer is not sharing
)
```

On `loadConnectionDetail`, after fetching the connection record, call new `location.peer.get`. Subscribe to `forApp.location-update` already-existing dispatcher: on receipt for this connection_id, update `state.peerLocation` in place.

### A2. Connection-detail "Location" row

Above the existing "Data" section, add a Location row:

- **Sharing with you, fresh (≤ 5 min):** green dot + "Sharing location · 2 min ago" → tap opens map
- **Sharing with you, stale (> 5 min, ≤ 30 min):** yellow dot + "Last update 12 min ago" → tap opens map showing last known
- **Sharing with you, very stale (> 30 min):** gray dot + "Last update 2 h ago" → tap opens map (still functional, just signaled stale)
- **Not sharing:** no row at all (don't show "Not sharing" — that's noise)

### A3. Connection-card list indicator

In the list of connections, when `peerLocation != null` AND `updatedAt > now - 30 min`, render a small location pin glyph next to the peer's name. Hide when stale or absent. Matches the existing presence-dot pattern (`ConnectionListItem.kt` already has a status-dot slot).

### A4. Activity-feed system-card row

Subscribe to `forApp.connection.peer-location-share-started` and `forApp.connection.peer-location-share-stopped` in `OwnerSpaceClient`. Each emits a `PendingRow.PeerLocationEvent` for the system-vettid card. Mirrors the existing `connection.peer-accepted` pattern from the §12 feed unification work.

### A5. Map view

New screen `MapScreen.kt` rendering the single peer point. Use the existing `coil-compose` tile provider if available; otherwise a minimal `WebView` with OpenStreetMap is fine for V1. Show:
- The single point with a styled marker
- "Last updated <relative time>" in the toolbar
- Back button → Connection Detail

Tile-provider authentication and offline behavior are out of scope (per "Out of scope").

### A6. "Request location" action

Add to the connection-detail action button menu (existing FAB pattern in `ConnectionDetailScreen.kt`). Visible always (handler-catalog enforces sharability and the peer side enforces the actual decision).

Tap → sends `location.request`. UI shows a "Waiting…" state with a 30-second timeout. On response (location-update), opens the map view directly.

On the peer side, an inbound `location-request-incoming` shows a system dialog: "Mesmer is asking for your location. [Share once] [Cancel]." No persistent state — declining or timing out just drops the request.

---

## Storage schema summary

| Key | Owner | Purpose | Lifetime |
|---|---|---|---|
| `connections/<connID>/_peer_location` | viewer vault | Latest cached point from sharer | Overwritten on each update; deleted on V5 stop |
| `connections/<connID>/_peer_location_first` | viewer vault | First-seen timestamp (transition marker) | Set once; cleared with `_peer_location` |
| `location/sharing/_index` | sharer vault | Existing: list of connIDs to push to | Updated on toggle |
| `location/_settings` | sharer vault | Existing: precision / interval settings | Long-lived |

(`_peer_location_first` can also live as a field inside `_peer_location`; a separate key just lets V3 do an atomic-create check without re-reading the main blob.)

---

## Files to touch

**vettid-dev:**
- `enclave/vault-manager/location.go` — V1 stamp, V2 cache, V3 emit, V4 `location.peer.get`, V5 unshare event, V6 `location.request`
- `enclave/vault-manager/messages.go` — route new operations
- `enclave/vault-manager/peer_wire_contract_test.go` — pin `FromOwnerSpace` on the wire
- `enclave/vault-manager/handler_authorization.go` — verify `location` catalog entry already covers the new `location-request` peer subject
- `enclave/vault-manager/notifications.go` — small helper for the start/stop notifications (or inline in location.go)

**vettid-android:**
- `app/src/main/java/com/vettid/app/core/nats/OwnerSpaceClient.kt` — subscribe to the new `forApp.*` topics, dispatch flows
- `app/src/main/java/com/vettid/app/features/connections/ConnectionDetailViewModel.kt` — load + render peer location state
- `app/src/main/java/com/vettid/app/features/connections/ConnectionDetailScreen.kt` — Location row, request-location action
- `app/src/main/java/com/vettid/app/features/connections/components/ConnectionListItem.kt` — pin-icon indicator
- `app/src/main/java/com/vettid/app/features/map/MapScreen.kt` — new file
- `app/src/main/java/com/vettid/app/features/feed/...` — system-card row for share-started / share-stopped events
- `app/src/main/java/com/vettid/app/VettIDApp.kt` — navigation entry for the map screen

---

## Test plan

**Vault-side unit tests (Tier-1):**
- `TestLocationUpdateWire_FromOwnerSpace` — wire contract for V1
- `TestHandleIncomingLocationUpdate_FirstWriteEmitsNotification` — V3 transition detection (mock the publisher, assert one `peer-location-share-started` was published)
- `TestHandleIncomingLocationUpdate_SubsequentWriteDoesNotEmit` — second update doesn't fire the notification again
- `TestHandleIncomingLocationUpdate_UnknownPeer` — `FindConnectionByPeerGUID` returns "" → cache write skipped, no panic
- `TestLocationPeerGet_NotShared` — returns `{shared: false}` when no cache entry

**Vault-side integration (Tier-2 docker harness, once landed):**
- happy-path: enable sharing → peer cache populated → start-notif emitted once → disable sharing → stop-notif emitted, cache cleared

**Android UI:**
- ConnectionDetailViewModel test: state transitions on incoming location-update broadcast match expected `peerLocation` values
- Snapshot test for the three Location-row states (fresh / stale / very-stale)

---

## Rollout sequence

1. **V1 stamp** + wire-contract test. Backwards-compatible — old viewers ignore the new field; new viewers see the field on new updates only.
2. **V2 cache + V4 read op** — viewer caches and can be queried without UI yet.
3. **V3 notification emit + V5 stop emit** — vault publishes events; Android still ignores them until A4 lands.
4. **A1-A4 Android** — surfaces appear in the UI as soon as new updates flow in.
5. **V6 + A6 request-location** — separate verb, separate test pass.

Each step ships independently. Steps 1-4 are zero-cost for users who haven't toggled sharing on. Step 5 is opt-in via the new action button.

---

## Open questions

- **R1**: "Share once" grants a single point or a 5-min window? Recommend single point for V1.
- **R2**: Stale thresholds (5 min / 30 min) — pulled from gut. Worth instrumenting to see actual update cadence before pinning.
- **R3**: Sharer-side mute. Does the sharer need to know the viewer has viewed the cached location? Recommend no — feels too much like read receipts; out of scope.
- **R4**: Should the cached peer location survive vault-decommission? Recommend yes (it's stored in the encrypted SQLite which is wiped on decommission anyway).

---

## Effort estimate

- V1+V2+V4: ~3 hours (small surgical adds)
- V3+V5: ~2 hours (transition detection + 2 new notification types)
- V6: ~3 hours (new verb + peer-side approval prompt UX)
- A1-A4: ~4 hours (existing patterns; mostly wiring)
- A5 (map): ~3-4 hours depending on tile provider choice
- A6: ~2 hours
- Tests: ~3 hours

**Total: ~1.5-2 working days**, splittable across the five rollout steps.
