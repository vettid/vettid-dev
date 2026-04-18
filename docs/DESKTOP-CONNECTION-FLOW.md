# Desktop Connection Flow

Canonical design for pairing a VettID desktop client to a user's vault, authorizing a time-bound session, extending via key rotation, and revoking.

Supersedes prior references to `https://vett.id/<code>` and `https://vettid.dev/<code>` HTTP resolvers — those endpoints were never built and the code referencing them is stale.

Last updated: 2026-04-18.

---

## Design goals

1. **User remains in control.** The pairing code alone never grants data access. A second, physical-proximity action (QR scan on the phone) is required to authorize a session.
2. **Short-lived by default.** Pairing invites expire in 2 min; sessions default to 1 hour; expired sessions require re-authorization.
3. **Cryptographic session expiry.** On expiry, the desktop's session key is wiped — it cannot decrypt data until a new key rotation is authorized, even if it still has NATS connectivity.
4. **Multiple desktops per user.** Each desktop is a separate device connection, revocable independently.
5. **NATS only.** No HTTP broker. The pairing invite rides the same JetStream `INVITATIONS` stream used by peer-to-peer connections.

---

## Actors

- **User** — holds the phone and physically controls both devices during pairing.
- **App** — the VettID mobile app (Android/iOS), authenticated to the user's vault.
- **Desktop** — the VettID desktop client (Tauri/Rust/Svelte). Not registered until stage 1 completes.
- **Vault** — the user's Nitro Enclave-backed vault-manager, reached via NATS on the user's OwnerSpace.
- **Guest account** — the pre-provisioned read-only NATS account (`cdk/scripts/init-nats-operator.ts`, `generateGuestUserCredentials`). Used identically to how it would be used for cross-environment peer invite resolution: read `invite.<code>` from JetStream, then switch to the scoped creds from the payload. Desktop builds embed these guest creds.

---

## Stages

### Stage 1 — Pairing invite (NATS entry)

**Goal:** give the desktop a scoped NATS channel into the user's OwnerSpace. Grants no decryption capability.

```
User     App                              Vault                 JetStream              Desktop (guest)
 |        |                                 |                       |                       |
 | tap "Connect Desktop"                    |                       |                       |
 |------->|                                 |                       |                       |
 |        | connection.device.create-invite |                       |                       |
 |        |-------------------------------->|                       |                       |
 |        |                                 | generate 8-char code  |                       |
 |        |                                 | generate scoped creds |                       |
 |        |                                 | publish invite.<code> ----->|                 |
 |        |                                 | (payload + 2-min exp) |                       |
 |        |         { invite_code, expires_at }                     |                       |
 |        |<--------------------------------|                       |                       |
 |<-------| show 8-char code on screen      |                       |                       |
 |                                                                                          |
 | type code into desktop ----------------------------------------------------------------> |
 |                                                                  |   read invite.<code>  |
 |                                                                  |<----------------------|
 |                                                                  |   (as guest account)  |
 |                                                                  |---------------------->|
 |                                                                                          |
 |                                          desktop reconnects to NATS using scoped creds from invite payload
 |                                                                                          |
```

**Invite payload on JetStream** (same shape as peer invites):
```json
{
  "type": "vettid_device",
  "connection_id": "conn-<hex>",
  "jwt":  "<scoped NATS user JWT>",
  "seed": "<scoped NATS user seed>",
  "nats_endpoint": "tls://nats.vettid.dev:443",
  "owner_space": "<user-guid>",
  "message_space": "MessageSpace.<user-guid>.forOwner.>",
  "expires_at": "<ISO-8601, +2 min>",
  "label": "Desktop"
}
```

**Invite code format:** 8 characters, alphanumeric excluding ambiguous glyphs (no `0`, `O`, `1`, `l`, `I`). Case-insensitive on the backend; displayed uppercase in the app.

**NATS creds scope:** the JWT in the payload permits only:
- PUB on `MessageSpace.<owner-guid>.forOwner.device.>` (for desktop to send stage-2 request)
- SUB on `MessageSpace.<owner-guid>.forApp.device.<connection-id>.>` (for desktop to receive stage-2 response)
No broader vault access, no read of user messages or profile.

**At end of stage 1:** desktop has a NATS channel into the user's OwnerSpace scoped to this single pending connection. No keys to decrypt anything.

---

### Stage 2 — Session authorization (key exchange)

**Goal:** the user physically authorizes this specific desktop for a specific duration. Key exchange happens here, not in stage 1.

```
Desktop                                   Vault                              App
  |                                         |                                 |
  | generate ephemeral X25519 keypair       |                                 |
  | generate 32-byte approval_token         |                                 |
  | render session-auth QR                  |                                 |
  | display QR on screen                    |                                 |
  |                                                                           |
  |                            User scans QR with app                         |
  |                                                                         <-|
  |                                         |           app shows:            |
  |                                         |           - device fingerprint  |
  |                                         |           - time picker (1h)    |
  |                                         |           - Approve / Deny      |
  |                                         |                                 |
  |                                         |    device.authorize-session     |
  |                                         |<--------------------------------|
  |                                         |    { connection_id,             |
  |                                         |      approval_token,            |
  |                                         |      desktop_pubkey,            |
  |                                         |      duration_seconds }         |
  |                                         |                                 |
  |                                         | generate vault X25519 keypair   |
  |                                         | compute shared_secret           |
  |                                         | derive session_key via HKDF     |
  |                                         | store DeviceSession             |
  |                                         |                                 |
  |   device.session-activated              |                                 |
  |<----------------------------------------|                                 |
  |   { session_id, vault_pubkey,           |                                 |
  |     expires_at, session_key_id }        |                                 |
  |                                                                           |
  | compute shared_secret                                                     |
  | derive session_key via HKDF                                               |
  | session active — begin feed sync                                          |
```

**Session-auth QR payload** (~80 bytes):
```json
{"t":"<approval_token>","c":"<connection_id>","k":"<desktop_pubkey_hex>"}
```

**HKDF session-key derivation:**
```
session_key = HKDF-SHA256(
  ikm = X25519(desktop_priv, vault_pub),
  salt = <connection_id>,
  info = "vettid-device-session-v1" || <session_id>
)
```
Distinct domain from `vettid-connection-v1` (peer) and `vettid-transport-v1` (app↔vault) to prevent key reuse.

**Duration:** user-selected via a time picker (freeform, not fixed presets). Default 1 hour. **Hard cap 24 hours** — enforced by both the app UI and the vault handler.

**DeviceSession record** (stored in vault alongside the device ConnectionRecord):
```go
type DeviceSession struct {
    SessionID      string    // uuid
    Status         string    // "active" | "expired" | "revoked"
    CreatedAt      int64
    ExpiresAt      int64     // CreatedAt + duration
    KeyRotationCount int     // incremented on each extension
    SessionKeyID   string    // identifies current session key for message auth
}
```
Remove `TTLHours`, `MaxExtensions`, `LastPhoneHeartbeat` from the existing struct — not used in this design.

---

### Stage 3 — Active session

Desktop now has:
- NATS connectivity (scoped invitation creds, upgraded by vault to full device creds on activation)
- `session_key` — wiped on expiry
- `session_id` + `expires_at`

**What desktop syncs:**
- **Feed events** — anything requiring user attention: new messages, incoming call signaling, new connection requests, connection status changes
- **Connections list** — read-only view, same as the app's feed home
- **Per-connection message history and profile** — on demand, decrypted client-side with the connection's shared secret (requested from vault, delivered encrypted under the session key)
- **Calls** — voice and video, full signaling via vault → WebRTC with TURN (same infra as phone)

**Write capabilities:** same as the app — send messages, place calls, accept/reject connection requests, etc. Every outgoing write is signed/encrypted with the session key.

**What the vault enforces:**
- Every device-originated request must be encrypted under a session key matching the current `session_id`
- After `expires_at`, the vault rejects all requests from this device until a new session is activated

### Stage 4 — Expiry and extension

**On expiry (desktop side):**
1. Desktop zeroes `session_key` in memory
2. UI hides all user data (no cached plaintext persists)
3. Desktop generates a new ephemeral keypair and a new approval token
4. Desktop renders an **extension QR** (same shape as stage-2 auth QR)
5. QR is shown on every launch until scanned or until user taps Logout

**On extension (app side):**
- User scans extension QR → app shows the same time picker
- App publishes `device.extend-session` with the new `desktop_pubkey` and `duration_seconds`
- Vault generates a new vault keypair, derives a new `session_key`, increments `KeyRotationCount`, updates `ExpiresAt`
- Old session key is invalidated — any in-flight messages encrypted under it are rejected

Extension is cryptographically identical to a fresh stage-2 authorization, just reusing the existing `connection_id` and `DeviceSession` record.

### Stage 5 — Session controls

**Exit** (desktop button):
- Close the NATS connection
- Keep on disk: encrypted connection credentials (connection_id, NATS creds, device keypair passphrase-wrapped — same as today)
- **Do not keep on disk:** any user data, any decrypted plaintext, `session_key`
- Next launch: if `expires_at` has passed, show extension QR; otherwise attempt to resume session

**Logout** (desktop button):
- Publish `device.revoke` to vault via NATS (while still connected)
- Vault marks the ConnectionRecord as revoked and removes from user's active device list
- Desktop wipes all local files under its config dir
- UI returns to the unregistered state (code-entry screen)

**User-initiated revocation** (from app):
- App shows a list of active devices for this user (from `connections.list` filtered by `connection_type: "device"`)
- User taps Revoke → app publishes `device.revoke` with the target `connection_id`
- Vault marks revoked and publishes a revocation event on the device's MessageSpace
- Desktop receives the event, zeroes session key, wipes local storage, returns to unregistered state

---

## NATS subjects — reference

| Subject | Direction | Purpose | Stage |
|---------|-----------|---------|-------|
| `invite.<code>` (JetStream INVITATIONS) | Vault publish → Desktop read (as guest) | Invite payload | 1 |
| `MessageSpace.<owner>.forOwner.device.<conn-id>.request-session` | Desktop → Vault | Desktop posts approval-token + pubkey | 2 |
| `MessageSpace.<owner>.forApp.device.<conn-id>.pending` | Vault → App | Notify app that a device is awaiting session authorization | 2 |
| `MessageSpace.<owner>.forOwner.device.<conn-id>.authorize` | App → Vault | User approves with duration | 2 |
| `MessageSpace.<owner>.forApp.device.<conn-id>.activated` | Vault → Desktop | Session key exchange response | 2 |
| `MessageSpace.<owner>.forOwner.device.<conn-id>.extend` | App → Vault | Extension request (via QR scan) | 4 |
| `MessageSpace.<owner>.forOwner.device.<conn-id>.revoke` | Desktop or App → Vault | Logout or user-initiated revoke | 5 |
| `MessageSpace.<owner>.forApp.device.<conn-id>.revoked` | Vault → Desktop | Notify desktop it's been revoked | 5 |

Feed/message/call subjects in stage 3 reuse the existing OwnerSpace/MessageSpace patterns — the device's scoped JWT permits the same subject set as the app, gated at the vault-handler level by session-key validation.

---

## Vault handlers

To be added/modified in `vettid-dev/enclave/vault-manager/`:

| Handler | Purpose | Status |
|---------|---------|--------|
| `HandleCreateDeviceInvite` | Stage 1: 8-char code, scoped creds, JetStream publish | **Rework** — current impl at `connections.go:2489` returns a raw token and doesn't publish to broker |
| `HandleDeviceRequestSession` | Stage 2: desktop posts approval_token + pubkey, vault waits for app to authorize | **New** |
| `HandleDeviceAuthorizeSession` | Stage 2: app approves with duration, vault does key exchange, publishes activation | **New** |
| `HandleDeviceExtendSession` | Stage 4: extension via QR scan, key rotation | **New** |
| `HandleDeviceRevoke` | Stage 5: logout or user-initiated revoke | **New** |
| `HandleListDevices` | List active devices for this user | Likely exists under peer `connection.list` filtering by type; confirm during impl |

Session-key validation happens in every device-originated handler (message send, call, etc.) — reuse the existing `deriveTransportKey` pattern but bind to the current `session_id`.

---

## Invite delivery — same pattern as peer connections

Scoped NATS creds (JWT + seed) are **dropped in the invite channel** — published by the vault to `invite.<code>` on JetStream INVITATIONS, same as peer invitations today. The desktop reads the invite using the existing pre-provisioned guest NATS account, then switches to the scoped creds from the payload for stage-2 onwards. No new provisioning is needed — this reuses the infrastructure set up by `cdk/scripts/init-nats-operator.ts`.

**Threat model:** guest creds are public. A leaked/extracted guest JWT allows an attacker to read any pending invite on the INVITATIONS stream — but invitations are addressed by random 8-char codes, each valid for only 2 minutes. Absent the code, the attacker cannot target a specific invitation. Combined with the stage-2 key exchange requiring the user's physical action on their phone, this is acceptable.

---

## Security properties

1. **Pairing code alone grants no data access.** Even if intercepted, the code only opens a NATS channel; the user must still scan the stage-2 QR.
2. **Stage-2 QR is useless without proximity.** The QR contains an ephemeral pubkey and random token; intercepting it lets an attacker send an authorization request, but the user sees the request on their phone and approves or denies.
3. **Session expiry is cryptographic, not just UI.** An expired desktop cannot decrypt any new vault responses because the session key is wiped and new responses use the next key_id.
4. **Extension requires user physical action.** No silent auto-renewal.
5. **Revocation is immediate.** Vault rejects all requests from a revoked device; the device receives a revocation event and wipes local state.
6. **Multiple devices are isolated.** Each has its own `connection_id`, `DeviceSession`, and session key; revoking one does not affect others.

---

## Device naming and fingerprint

The user assigns a **name** for each desktop from the app at stage-2 authorization time (e.g., "Work laptop", "Home iMac"). This name is stored in `DeviceMetadata.Label` and displayed in the connections list for revocation/management.

The desktop collects a **comprehensive fingerprint** sent in the stage-2 request and shown to the user before they approve:
- `hostname` — system hostname
- `platform` — `linux-x86_64`, `darwin-arm64`, `windows-x86_64`, etc.
- `os_name` / `os_version` — e.g., `Fedora 43`, `macOS 14.4`, `Windows 11`
- `binary_fingerprint` — SHA-256 of the desktop binary (first 8 hex chars shown in UI; full value stored)
- `machine_fingerprint` — HMAC-SHA256 over stable machine attributes (CPU ID, board UUID, primary MAC, etc.) — used to detect subsequent hardware change
- `app_version` — desktop app version string
- `client_ip` — IP address seen by NATS at connection time (vault-observed, not client-reported)
- `first_seen_at` — timestamp

The full set is shown collapsibly in the authorize dialog so the user can verify they're approving the correct machine. The 8-char binary fingerprint prefix is shown prominently in the device list for quick visual matching.

---

## Open items for implementation

1. **Agent flow alignment** — the agent connector (`vettid-agent`) has the same broken HTTP-broker issue as the desktop. Out of scope for Connect Desktop but should follow the same two-stage pattern with its own session model. Track separately.
