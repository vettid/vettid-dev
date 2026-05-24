# Desktop Pairing Debug Pass — Plan

Status: planned (2026-05-21). A cluster of failures pairing the desktop
client with a phone, independent of the enclave persist wedge.

## Symptoms

Observed pairing the desktop with mesmer (`af44310d`, Pixel 7):

1. **No device details** — hostname, OS, IP of the pairing desktop are
   not shown (the phone's authorize screen has nothing to display).
2. **QR screen didn't open** — after the desktop pairing code was
   entered, the phone's QR/authorize screen never opened.
3. **"no pending authorization for this device"** — the attempt ended
   with the phone reporting no pending authorization.

## Approach — trace a clean attempt, then fix

This is a debugging plan, not a known-fix plan: instrument and capture
**one clean pairing attempt** across all three components, localize each
of the three failures to a specific hop, then fix.

### Capture setup

- Desktop: fresh `cargo tauri dev`, capture stdout (Rust log). Confirm
  `Connected to NATS` before starting — the desktop has had repeated
  stale-NATS-client bugs today; rule that out first.
- Phone (mesmer, Pixel 7): `adb -s <pixel-7-serial> logcat -c`, then
  capture `-v threadtime`.
- Enclave: `aws ssm` journal pull for owner-space `af44310d` over the
  attempt window.

### The flow, and which hop each symptom implicates

Desktop pairing — `registration/pairing.rs` `complete_pairing`
(Stage 1, then Stage 2 `device.request-session` → await
`device.session.activated`):

1. Desktop generates a pairing code/QR + collects the device
   fingerprint (`fingerprint/`, `collect_device_fingerprint()`).
2. Desktop publishes the pairing/connection request to the vault.
3. Vault (`vault-manager/device_handler.go`) receives it, creates a
   **pending-authorization** record, stores the device metadata,
   notifies the phone.
4. Phone receives a `devicePendingAuth`-type event → navigates to the
   DeviceAuthorize / QR screen.
5. User authorizes on the phone → vault activates the session →
   desktop notified (`forApp.device.{conn}.activated`).

Symptom → suspect hop:

- **#1 no device details** — steps 1–2: is `collect_device_fingerprint()`
  populating hostname/OS, and is that metadata in the request payload?
  Step 3: does the vault store it on the connection record
  (`DeviceMetadata`)? Step 4: does the phone's authorize screen
  read+render it? `device_handler.go` already references
  `conn.DeviceMetadata.Hostname`, so the field exists — trace where the
  value is lost.
- **#2 QR screen didn't open** — step 4: did the phone receive the
  pending-auth event at all? Was the desktop's request published to the
  correct subject / owner-space? (mesmer = `af44310d` — verify the
  owner-space routing; a desktop paired against the wrong owner-space
  would explain both #2 and #3.)
- **#3 "no pending authorization"** — step 3: the vault never created
  the pending-authorization record (or it expired, or it was keyed
  under a different owner-space/connection than the phone queried).

### Files to investigate

- Desktop: `src-tauri/src/registration/pairing.rs` (`complete_pairing`,
  the request-session payload), `src-tauri/src/commands/auth.rs`
  (register/pair commands), `src-tauri/src/fingerprint/`
  (`collect_device_fingerprint`).
- Vault: `enclave/vault-manager/device_handler.go` — the device
  connection-request / pending-authorization handlers; how
  `DeviceMetadata` is captured, stored, and surfaced.
- Android: the DeviceAuthorize screen + pairing-code entry + the
  `devicePendingAuth` NATS event handling (`VettIDApp.kt` and the
  device-authorize ViewModel).

### Steps

1. Set up the three captures; verify the desktop NATS connection is
   fresh.
2. One clean pairing attempt; note wall-clock at each user action.
3. Pull all three logs; build a per-hop timeline.
4. Localize each of the three failures to a specific hop.
5. Fix; re-test.

### Notes

- Rule out stale desktop state first — today's pairing failures were
  repeatedly caused by a stale NATS client / listener respawn, not the
  pairing logic itself. A fresh `cargo tauri dev` before the attempt is
  mandatory.
- #2 and #3 may share one root cause (wrong owner-space / no pending
  record). Confirm or split them early in the trace.

---

## FINDINGS — 2026-05-21 trace (enclave 2026-05-21-v2)

Traced a failed pairing of the desktop to al (eb8472f6). Enclave log:

    09:41:52  device.connection.request          conn-c31b4e8f… (code generated)
    09:42:15  Device pairing invite cancelled     conn-c31b4e8f…  ← phone cancelled
    09:42:17  request-session                     conn-c31b4e8f…  (desktop — 2s too late)
    09:42:21  device.authorize-session → "no pending authorization"

Root cause of "no pending authorization": the **phone cancelled its own
invite mid-pairing**. `HandleCancelDeviceInvite` (connections.go:4121)
is triggered by the phone's `DevicePairingViewModel.cancel()`, and
`cancel()` is wired to the pairing screen's **Back button**
(DevicePairingScreen.kt:41-43: `viewModel.cancel(); onNavigateBack()`).
The cancel fired at 23s — NOT the 120s `inviteTtlSeconds` countdown —
so it was a Back press, not a code timeout.

Why the user pressed Back: device pairing has **no phone-side QR scan**
— the phone shows a code, the user types it on the desktop, and the
phone screen auto-advances (`DevicePairingState.DevicePending` →
`onNavigateToAuthorize`, DevicePairingScreen.kt:29-34) when the
desktop's request-session arrives. The desktop's Stage-1 is slow
(~6s: NATS connect + INVITATIONS-consumer fetch — desktop log
09:42:11→09:42:17), so the auto-advance hadn't happened yet; the user,
not seeing it, backed out to find a (nonexistent) scanner and the Back
press cancelled the invite. The later request-session/authorize then
found nothing.

### Fixes (in priority order)

1. **Back must not silently kill the invite.** DevicePairingScreen Back
   while in `ShowingCode` should confirm ("Cancel pairing?") or just
   navigate without `cancel()` — a mid-pairing Back press should not
   destroy a live invite. (Android.)
2. **The code screen must read as "waiting".** While `ShowingCode`,
   say plainly "Enter this code on your desktop, then keep this screen
   open — it advances automatically." Removes the impulse to go look
   for a scanner. (Android.)
3. **Desktop Stage-1 latency** (~6s to show the QR/code-accepted
   state): reuse the live NATS connection instead of a fresh
   connect + consumer fetch. (Desktop — overlaps the session-start
   latency item.)
4. **Device metadata** (#1 original symptom) — re-evaluate on a
   correct-path attempt: does the DeviceAuthorize screen render
   hostname/OS once pairing actually reaches it? Trace
   collect_device_fingerprint → request-session payload → vault
   DeviceMetadata → authorize screen only if it's still blank.

### Immediate workaround (no code change)

Generate the code, type it on the desktop, then **stay on the phone's
pairing-code screen and wait** — it auto-advances to the approve
screen. Do not press Back; there is no QR scanner step. The code is
valid 120s, ample for the round-trip.
