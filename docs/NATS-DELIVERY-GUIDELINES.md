# NATS Delivery Guidelines

When to use JetStream, when to use core NATS, and how to avoid the reconnect-race class of bugs we've been hitting repeatedly.

Last updated: 2026-04-19.

## TL;DR for reviewers

For any message where the caller **waits for a reply** — use **JetStream**
(`OwnerSpaceClient.sendAndAwaitResponse(...)` on Android, JetStream consumer
on the vault side). Never publish + wait for the reply on a plain
`forApp.>` subscription — reconnect races will silently drop replies.

For push notifications where the app must not miss a single event (incoming
call, new message, device pending authorization) — use JetStream with a
durable consumer, not core NATS.

Core NATS is fine for truly fire-and-forget signals (ICE candidates during
an active call, heartbeats, session-rotation pings) where one drop out of
many is harmless.

---

## The failure mode we keep hitting

App calls `sendToVault("foo", payload)` → returns a requestId. App then
awaits `ownerSpaceClient.vaultResponses.first { it.requestId == requestId }`
with a timeout.

Under the hood:
1. `sendToVault` publishes on `OwnerSpace.<guid>.forVault.foo` (core NATS,
   fire-and-forget).
2. Vault handles it and publishes the reply on
   `OwnerSpace.<guid>.forApp.foo.response` (core NATS).
3. App's `forApp.>` subscription, established once at startup, is supposed
   to catch the reply. The reply goes into `vaultResponses` MutableSharedFlow.
4. Caller's `.first { it.requestId == ... }` picks it up.

**Where it breaks:** if the subscription isn't warm when the reply arrives,
the reply is lost. Concretely:
- Just after `NatsConnectionManager.reconnect()` — the `forApp.>` subscription
  has to be re-established; there's a window (tens of ms to seconds) where
  no subscriber is listening on the server.
- Just after `subscribeToVault()` is re-called — same race, brief gap.
- Any transient network blip that triggers an async resubscribe.

Core NATS has **no replay**. Miss the window, miss the message. The
`sendAndAwaitResponse` caller sees a timeout.

JetStream doesn't have this problem — it persists the reply subject for a
retention window and serves it to an ephemeral consumer created per-request.
Even if the consumer is created after the reply was published, it still gets
delivered.

## Decision tree

When adding a new NATS handler or touching an existing one, ask:

```
1. Is this a request, where the caller uses the reply to proceed?
   → YES: JetStream. Use OwnerSpaceClient.sendAndAwaitResponse on the app;
          the vault-manager's existing JetStream response publisher handles
          the reply side automatically.
   → NO:  Go to 2.

2. Is this an app-should-never-miss-it push notification?
   (incoming call, new peer message, pending device auth, call SDP answer,
   credential rotation, agent approval request, security alert)
   → YES: JetStream with a durable consumer on the app side. (See
          "Push notification upgrade path" below — most of these are
          still on core NATS today.)
   → NO:  Go to 3.

3. Is this a signal that fires frequently where one drop is harmless?
   (ICE candidates during active call, session-rotation ping, heartbeat,
   audit log line, read receipt, typing indicator, location update)
   → YES: Core NATS is fine — sendToVault / publishDirect.
   → NO:  Default to JetStream.
```

## Android-side recipes

### Request-response (the common case)

```kotlin
// RIGHT — JetStream; reliable even across reconnects.
val response = ownerSpaceClient.sendAndAwaitResponse(
    messageType = "some.handler",
    payload = payload,
    timeoutMs = 10_000L,
)
when (response) {
    is VaultResponse.HandlerResult -> if (response.success) {
        handle(response.result)
    } else {
        handleError(response.error)
    }
    is VaultResponse.Error -> handleError(response.message)
    null -> handleTimeout()
    else -> {}
}
```

```kotlin
// WRONG — core NATS + flow subscription. Reconnect race drops replies.
val requestId = ownerSpaceClient.sendToVault("some.handler", payload)
    .getOrThrow()
val response = withTimeoutOrNull(10_000L) {
    ownerSpaceClient.vaultResponses.first { it.requestId == requestId }
}
```

### Fire-and-forget signal

```kotlin
// Only for things where loss is acceptable. Don't wait for a reply.
ownerSpaceClient.sendToVault("call.video-state", payload)
```

### Subscribing to push events

Right now all `forApp.*` push notifications flow through
`OwnerSpaceClient.handleVaultResponse` on a single core-NATS subscription.
That's fragile — any event that fires during a reconnect window is lost.
See the upgrade path below.

## Current path inventory (2026-04-19 audit)

**Reliable (already JetStream request-response):**
- All `ConnectionsClient.kt` methods (`connection.create-invite`, `.list`,
  `.respond`, `.revoke`, `.store-credentials`, etc.)
- All `CallSignalingClient.kt` except `call.video-state` (intentionally
  fire-and-forget signal)
- All `NatsMessagingClient.kt` methods (`message.send`, `message.list`,
  `profile.broadcast`, etc.)
- All wallet operations (`WalletClient.kt`)
- All profile photo operations (OwnerSpaceClient.kt:613 / 652 / 688)
- `pin.change`, `credential.password-change`, `app.bootstrap`,
  `app.authenticate`, `personal-data.update-sort-order`
- **Fixed 2026-04-19** — `profile.get` (PinUnlockViewModel),
  `NatsCredentialClient` wrapper, `ContractSigningViewModel.sign`

**Best-effort (intentionally core NATS):**
- `call.video-state` (CallSignalingClient.kt:312) — idempotent UI signal,
  fine to drop one
- `call.signal` ICE candidates under 5 s timeout — fire-and-forget payloads
- `session.rotate` — periodic; next rotation covers a drop
- Personal-data / secrets worker optimistic updates — worker handles
  retries and local sync state

**Review candidates (mixed — some expect replies, some don't):**
- `VaultEventClient.kt:46, 93` — generic event publisher used by multiple
  features; should inspect each caller and decide per-call
- `EnrollmentWizardViewModel.kt:330, 365, 1246` — enrollment one-shot flows;
  likely OK since enrollment has explicit retry UI
- `VaultProtectionService.kt:551, 581` — background job; verify retry

## Push notification upgrade path (future work)

`OwnerSpaceClient.handleVaultResponse` routes ~18 event categories over
core-NATS `forApp.>`. If the subscription isn't warm at fire time, they
drop. Impact varies:

**Critical — migrate to JetStream consumer with per-client durable name:**
- `forApp.new-message` (missed → silent message)
- `forApp.call.incoming`, `.offer`, `.answer` (missed → call never rings
  or never connects)
- `forApp.connection.peer-accepted`, `.activated`, `.key-exchanged` (missed
  → E2E keys out of sync)
- `forApp.device.pending-authorization` (missed → desktop pairing stuck)
- `forApp.agent.secret.request`, `.action.request` (missed → agent request
  never surfaces)
- `forApp.credentials.rotate` (missed → UTK pool exhausted)

**Medium — migrate, or add explicit catch-up poll on reconnect:**
- `forApp.call.rejected`, `.ended` (UI consistency)
- `forApp.connection.rejected`, `connection-revoked`
- `forApp.recovery.*`, `forApp.transfer.*`, `forApp.security.*`

**Keep as core NATS:**
- `forApp.profile-update` (informational; user refreshes explicitly)
- `forApp.read-receipt` (next message sync catches up)
- `forApp.location-update` (periodic)
- `forApp.feed.updated` (next sync catches up)
- `forApp.call.candidate` (during active call; ICE retransmits)

This is bigger work — requires a durable JetStream stream for push events
plus a consumer per device with its own name, plus start-from-last-ack
semantics so a cold launch replays missed events. Defer unless the
reliability of core-NATS push becomes a real operational issue.

## Vault-side notes

Vault handlers on `vettid-dev/enclave/vault-manager` don't need changes for
the Tier-1 migration — the parent process already publishes responses via
JetStream when the app made the request via JetStream (because the request
itself was JetStream-delivered, the response is too).

For the push-notification migration (future work), vault handlers that call
`publisher.PublishToApp(ctx, type, payload)` → `PublishRaw` would need to
target a new JetStream stream (`APP_EVENTS` or similar) with per-user filter
subjects. The Android app would then create a durable consumer on this
stream at startup, keyed by device ID, with deliver_policy=last or
start_seq from the last acked sequence.

## Testing guidance

If you're unsure which path a handler uses, the cleanest way to verify:

1. Run the flow with a clean NATS reconnect mid-call. Pattern:
   `adb shell cmd netpolicy add restrict-background-blacklist <uid>` for a
   few seconds, then remove. The core-NATS subscription will drop and
   re-subscribe — any replies that fired during the window are lost.
2. Grep for "timed out" in logcat. Any `sendAndAwaitResponse` returning
   `null` after this test without a real network issue = the reply was
   lost in the race.

## How this doc gets maintained

Update this file when:
- Adding a new NATS subject — classify it in the decision tree.
- Moving a subject between core NATS and JetStream — record the change.
- Discovering a new race pattern — add it to "the failure mode we keep hitting".
