# Device-approval ~30s stall — diagnosis + debug plan

_Started 2026-05-21. Updated 2026-05-21 (later): live-journal re-trace +
diagnostic build. Updated 2026-05-22: earlier "FIX SHIPPED" attempts.
**Updated 2026-05-22 (later): TRUE ROOT CAUSE FOUND + FIXED — read the
final section "✅ ROOT CAUSE — DEFINITIVE" FIRST; everything between
"⚠️ STILL NOT FIXED" and that section is superseded.**_

## Symptom

Desktop "request sensitive data access" consistently takes ~30s to
register, even on a fresh session. Reproducible.

## What it is NOT

Traced end-to-end on the live enclave `2026-05-21-v3` (instance
`i-0c104dd5c24398b4e`, journal unit `vettid-parent`) plus Pixel 9
logcat. Phone clock is UTC-4.

- **Not the app / not the user.** Phone receives the request instantly,
  user approves in ~3s, phone publishes `forVault.device.approval`
  instantly, phone receives the result ~27s later.
- **Not the phone-notification path.**
- **Not a dropped pipe response.** The whole journal has **zero**
  `"no pending op"` warnings — the supervisor↔subprocess PipeID
  correlation is healthy; no op response was lost/misrouted.
- **Not the supervisor's `ProcessMessage` timing out.** The whole
  journal has **zero** `"Timeout waiting for vault-manager response"`.
  Whatever held things up returned a real response within the 30s op
  deadline; nothing was force-released by a timeout.

## What it IS — a ~27s stall, and the diagnosis premise that was wrong

Live journal, owner `eb8472f6` (the Pixel 9 user), 2026-05-21:

- Two device-approval cycles, **both ~30s to the second**:
  `20:34:58` requested → `20:35:28` granted, and
  `20:49:39` requested → `20:50:09` granted.
- For the second: parent created the `device.approval` op
  (`request_id 9653a706…`) at `20:49:42`; the vault-manager subprocess
  did not log `Handling message` for it until `20:50:09`. It then
  completed instantly and every other queued `eb8472f6` op
  (`location.peer.get` ×N, `feed.sync`, `connection.list`,
  `forOwner.device`, …) drained in the same second.

### The earlier conclusion ("between-op stall") was not proven

The first pass concluded "the stall-watchdog never fired ⟹ no op ran
>25s ⟹ it is a between-op stall." **That inference is unsound.** The
in-subprocess watchdog (`vault-manager/main.go runStallWatchdog`) ticked
every **10s** and fired only at `elapsed ≥ 25s`. A ~27–30s op started at
an unlucky phase relative to the ticker is *stepped over*: ticks land at
~op+20s (too early) and ~op+30s (op already done, `opStartedAt` reset to
0). For a ~30s op the watchdog has only ~50% odds to catch it; for ~27s,
~20%. So **"watchdog silent" does NOT rule out an in-op stall.**

Two hypotheses remain open, and the journal cannot separate them:

- **(A) In-op stall** — one `HandleMessage` in the subprocess runs ~27s;
  the coarse watchdog missed it.
- **(B) Delivery stall** — the op sits in the *supervisor* (per-user
  `procMu`, a slow `GetOrCreate`, a wedged `ProcessMessage`) before it
  is ever written to the subprocess. The supervisor was a journal
  **blind spot** — its zerolog goes only to the enclave console, so a
  supervisor-side stall is invisible in production.

Pinning it needs a goroutine dump captured at the moment of stall.
There is no pprof/signal path into the enclave, so the dump mechanism
must be code already in the build.

## Diagnostic build (2026-05-21)

Shipped to localise the stall and to make future stalls localisable.
All in `enclave/`:

1. **Supervisor stall watchdog** — new `supervisor/stall_watchdog.go`.
   Tracks every in-flight `handleVaultOp`; if one runs past
   `supervisorOpStallThreshold` (12s) it dumps EVERY supervisor
   goroutine stack, routed through `Supervisor.SendLog` so it lands in
   the parent journal. The dump shows exactly what each `ProcessMessage`
   goroutine is parked on — `procMu.Lock`, the `respCh` select, a pipe
   write. Covers hypothesis B.
2. **Tightened vault-manager watchdog** — `vault-manager/main.go`:
   tick 10s→2s, `opStallThreshold` 25s→12s. Now reliably catches a
   ~27–30s in-op stall and dumps goroutines. Covers hypothesis A.
3. **Supervisor zerolog → journal tee** — new `supervisor/journal_log.go`.
   Every supervisor log line (`handleVaultOp received`, `Processing
   message`, the new `DIAG:` `ProcessMessage` breadcrumbs) now reaches
   `journalctl -u vettid-parent`. Closes the blind spot permanently.
4. **`DIAG:` breadcrumbs in `ProcessMessage`** — logs `procMu` wait time
   when contended, and "wrote op to subprocess" with the write
   duration, so an op's timeline can be attributed to a segment.

Strip/tune before tech-preview: the watchdog thresholds (restore 25s /
10s), the `// DIAG` breadcrumbs, and the journal tee (remove or gate to
WARN+ — DEBUG-level forwarding is high mux volume). The watchdogs
themselves are keepable hygiene.

## ROOT CAUSE FOUND — 2026-05-22 (hypothesis B, refined)

Two diagnostic builds were deployed and reproduced:

- Build 1 (`eda50bc`, enclave `2026-05-21-v4`): supervisor stall
  watchdog + tightened vault-manager watchdog + journal tee.
- Build 2 (`5f9660e`, enclave `2026-05-22-v1`): adds a SIGUSR1
  goroutine-dump handler in the vault-manager; the supervisor stall
  watchdog SIGUSR1s the stalled owner's subprocess so the subprocess
  dumps its OWN goroutines (the supervisor dump cannot see inside it).

Both reproductions caught the stall cleanly. Findings:

1. **Confirmed hypothesis B — a per-user `procMu` pile-up.** The
   supervisor watchdog showed ~10 ops for owner `eb8472f6` all parked
   at `stage=process-message`. One "holder" `ProcessMessage` parked in
   the `respCh` select; the rest blocked on `procMu.Lock`. The holder
   waits its full 30s `opTimeout` and then the queue drains in a burst
   — that 30s is the stall.

2. **The persist is NOT the cause.** The `store_vault_state` sealer
   round-trip (1.7 MB) completes in <1s; ruled out.

3. **ROOT CAUSE: the op never reaches the subprocess.** The SIGUSR1
   subprocess goroutine dump shows the vault-manager subprocess
   **completely idle** — main loop parked in `select` (`main.go:222`),
   `receiveMessages` blocked in `syscall.read` on an **empty stdin
   pipe**. The supervisor's `ProcessMessage` reports it wrote the op,
   but the bytes never arrive at the subprocess's stdin. The holder
   `ProcessMessage` then waits out the 30s `opTimeout` holding `procMu`.

   So it is a **supervisor↔subprocess pipe-delivery failure** — the op
   write and the subprocess's stdin read are not connected to the same
   pipe (or the write silently does not land).

4. **Secondary anomaly:** the supervisor goroutine dump shows ~2
   `startPipeReader` goroutines per subprocess (should be 1) —
   duplicate pipe readers. Points at a `VaultProcess` / `ManagedProcess`
   **lifecycle bug**: the two-layer process tracking
   (`ProcessManager.processes` vs `VaultManager.vaults[].process`) can
   drift; `VaultManager.evictVault` calls `processManager.Kill(ownerSpace)`
   which kills whatever is in `pm.processes[ownerSpace]`, not the
   specific `*exec.Cmd` the evicted `VaultProcess` wrapped.

Target for the fix: `enclave/supervisor` — `pipe_ipc.go`,
`vault_lifecycle.go`, `process_manager.go`. The op-write must reach the
*same* subprocess the supervisor believes it spawned; the
`ProcessManager` / `VaultManager` process handles must not diverge;
duplicate `startPipeReader`s must not happen. Race-prone area — design
deliberately. Strip the `// DIAG` instrumentation and restore the
watchdog thresholds when fixing.

## Evidence pointers

- Build-2 reproduction: enclave `2026-05-22-v1`, instance
  `i-073a13807706d4c7f`, journal unit `vettid-parent`, stall at
  `01:03:47`–`01:04:17 UTC`. Supervisor watchdog fired ×4; SIGUSR1
  sent ×4; subprocess `SIGUSR1 GOROUTINE DUMP` in `vault-manager
  stderr` lines.
- Build-1 reproduction: enclave `2026-05-21-v4`, instance
  `i-07f7a5d0e52a18a33`, stall at `22:30:17`–`22:30:47 UTC`.
- Same family as `device-approval-reliability` memory /
  `SUPERVISOR-ALWAYS-DRAIN-PLAN.md` — the always-drain refactor fixed
  the persist *pipe-write* wedge; this is a distinct stall.

## FIX SHIPPED — 2026-05-22

### Root cause, restated precisely

The supervisor tracked each vault subprocess in **two** places:
`ProcessManager.processes` (a map keyed by owner space) and
`VaultManager.vaults[owner].process` (the handle cached on the
`VaultProcess`). The op-write, the kill, and the SIGUSR1 each
re-resolved "the subprocess for this owner" *by key* instead of
acting on the handle the supervisor actually spawned —
`evictVault` called `ProcessManager.Kill(ownerSpace)`, which killed
whatever sat in `pm.processes[ownerSpace]`, not necessarily the
`*exec.Cmd` the evicted `VaultProcess` wrapped.

Once those two views drifted, an op could be written into an
**orphaned** subprocess's stdin pipe. The write *succeeds* — the
orphan's pipe still has an open read end, so the bytes land in the
64 KB kernel buffer — but nothing drains them, while a freshly
spawned subprocess sits idle (exactly what the SIGUSR1 dump showed).
The holder `ProcessMessage` then parks its full 30 s `opTimeout`;
every queued op for that user serializes behind it. That is the
~30 s stall, and the duplicate `startPipeReader` goroutines were one
reader per orphaned (but still-alive) `VaultProcess`.

### The fix — one source of truth, by construction

Rather than patch one interleaving, the bug class is removed: there
is now a single owner of each subprocess.

- **`ProcessManager` is a stateless factory.** No `processes` map,
  no mutex. `Spawn` builds + starts a subprocess, kicks off stderr
  logging and an OS-reaper goroutine, and returns the handle —
  storing nothing. There is no reuse-by-key path (it was unreachable
  from `GetOrCreate` anyway, and was the only thing that could hand
  back a process the caller didn't already own).
- **`ManagedProcess` owns `kill()` / `signal()` methods** that act on
  *that exact handle*. `kill()` is idempotent (`sync.Once`): closing
  the pipe first makes the owning `VaultProcess`'s reader see EOF and
  exit, then SIGKILL drops the subprocess.
- **The `VaultProcess` is the sole owner of its `*ManagedProcess`**
  for the subprocess's whole life. `evictVault` kills
  `vault.process` directly; the stall watchdog signals through the
  one `VaultProcess` (`VaultManager.SignalSubprocess`). Nothing
  re-resolves by owner key, so the two views can no longer drift.
- **Liveness is read from `readerClosed`** — set by the pipe reader
  under `pendingMu` when the pipe dies — via `isAlive()`. The old
  check read `Cmd.ProcessState`, written by the reaper goroutine with
  no happens-before to the reader: a data race that could also report
  "alive" during the post-exit-before-`Wait()` window.
- **Bonus fix:** `OrgVaultManager.GetOrCreate` built its
  `VaultProcess` inline and skipped both the `pending`-map init and
  `startPipeReader`. The first org-vault op would therefore
  nil-map-panic the supervisor (assignment to a nil map in
  `ProcessMessage`), and with no reader no response would ever be
  delivered. Both managers now construct via the shared
  `newVaultProcess`, which wires both. Org `GetOrCreate` also gained
  the `isAlive()` liveness check + by-handle eviction.

Files: `enclave/supervisor/process_manager.go` (rewritten),
`vault_lifecycle.go`, `org_vault_lifecycle.go`, `supervisor.go`.

### Verification

`go build` + `go vet` clean for supervisor / vault-manager /
org-vault-manager. `go test -race ./supervisor/...` and the
vault-manager + storage suites pass. Tier-2 Docker harness: every
scenario passes in the run where it applies — single-parent sweep
green (incl. `concurrent-load`, `concurrent-multiuser`,
`persist-idle-no-stall`); two-parent (`--with-new`) sweep green incl.
`migration-handoff`. (`concurrent-multiuser` fails only under
`--with-new` — the pre-existing two-parent `ClaimForEnrollment`
attestation-key race, unrelated to this fix.)

### Still TODO — after a verification deploy

The `// DIAG` instrumentation is deliberately left in so a deploy
that verifies this fix keeps its diagnostics. Once a live deploy
confirms the stall is gone, strip: the `// DIAG` breadcrumbs in
`ProcessMessage` + `vault-manager/main.go`, the supervisor journal
tee (`journal_log.go` — or gate to WARN+), the SIGUSR1 dump handler,
and restore the watchdog thresholds (vault-manager 25 s / 10 s tick;
the supervisor watchdog at 12 s is keepable hygiene — retune if
noisy). The watchdogs themselves stay.

## ⚠️ STILL NOT FIXED — live test 2026-05-22, v2 + v3 (CHECKPOINT HANDOFF)

The "FIX SHIPPED" section above (v2 / `4aea334`) and the v3 fixes below
were both **deployed and live-tested with the user. The stall still
reproduces.** This section is the authoritative current state — read it
first.

### Two real bugs were found and fixed (neither eliminated the symptom)

1. **`4aea334` (enclave `2026-05-22-v2`)** — supervisor process-handle
   refactor (the section above). Real cleanup, correct, KEEP — but it
   was **not** the stall cause. Live test on v2 reproduced the ~30 s
   stall unchanged.

2. **`0aa49e9` (enclave `2026-05-22-v3`)** — *the* fix for the v2-shape
   stall. Root cause of THAT shape: a `forOwner.device` op (desktop
   device-op request) is handled by `DeviceHandler.handleDeviceOpRequest`,
   which delivers its real result straight to the desktop via
   `publishDeviceResponse` (raw NATS publish) and returns `(nil, nil)`.
   The vault-manager main loop's `if response != nil` guard then sent
   **nothing** back to the supervisor, so the always-drain
   `ProcessMessage` waited out its full 30 s `opTimeout` holding
   `procMu`. Fix: the main loop now sends a response for **every** op —
   synthesizes a minimal `PipeID`-stamped ack when `HandleMessage`
   returns nil. **Confirmed live on v3:** the synthesized acks
   (`length=87 type=response`) are visible in the v3 journal; the 30 s
   *timeout* path is gone.

3. **`462a95f`** — org-vault-manager had the same class, worse (its main
   loop never stamped `PipeID` and the message structs lacked the
   field). Fixed for parity. Org vaults are pre-launch so this was
   latent.

### The v3 stall is a DIFFERENT shape — burst backlog, not a wedge

Live test on v3 (instance `i-090355f5f1a8c2d4c`, owner `eb8472f6` =
Pixel 9 / al): desktop sensitive-data request still "stalls" ~25-30 s.
But the journal signature changed:

- **No watchdog fired. No op timed out.** On v2 the holder op got no
  response and timed out at exactly 30 s. On v3 every op *completes* —
  they are just **queued**.
- The v3 journal shows a **burst of 30+ ops** for `eb8472f6` per
  request — `profile.broadcast`, `pin-unlock`, `profile.get-published`,
  `personal-data.get`, `connection.list`, `feed.sync` ×6,
  `location.peer.get` ×10, `wallet.list` ×several, `profile.photo.get`,
  `guide.sync`, `vote.list`, `device.approval-pending`,
  `device.request-session`, `device.authorize-session`,
  `forOwner.device` ×8 — all serialized one-at-a-time through the
  single per-user `procMu`.
- The op that logged `procmu_wait=25561` (ms) waited ~25 s because
  ~25 s of *other ops* were ahead of it in the `procMu` queue. The
  desktop's sensitive-data result is one of the queued ops → ~25 s
  spinner.
- A desktop device **session re-pair** runs mid-burst:
  `Device stage-2 request stored; awaiting app authorization`,
  `forVault.device.request-session` / `device.authorize-session`.

**Leading hypothesis: op-burst backlog through the serial per-user
`procMu`.** Not a wedged op — a throughput collapse under a ~30-op
burst that the desktop+phone fire per sensitive-data request.

**Alternative not yet ruled out:** one device/pairing op
(`handleDeviceOpRequest` for a phone-required `secret.get`, or
`HandleDeviceRequestSession` "awaiting app authorization") genuinely
blocks the single main loop ~25 s waiting on the phone. The two have
completely different fixes — must be distinguished before fixing.

### Why it could not be settled live

The vault-manager + supervisor run **inside the Nitro enclave** — no
shell, no on-demand `pprof`/signal. Goroutine dumps come *only* from
the supervisor stall-watchdog's SIGUSR1, and on v3 the watchdog is
**not firing** (consistent with "no single op > 12 s" — i.e. backlog,
not a wedge — but also unverified: confirm the watchdog still works).

### NEXT SESSION — do this, deliberately, not as a hot-patch

1. **Instrument to distinguish the two hypotheses.** Add per-`HandleMessage`
   duration logging in `vault-manager/main.go` AND a per-op `procMu`
   queue-depth counter in `supervisor/vault_lifecycle.go`
   `ProcessMessage` (how many ops are waiting on `procMu` when this one
   arrives). One diagnostic build settles it: a single op at ~25 s ⇒
   blocking handler; 30 ops at <1 s each ⇒ burst backlog.
2. **If burst backlog (likely):**
   - Reduce op volume — desktop fires ~30 ops per sensitive-data
     request; the Android in-flight dedup work
     (`device-approval-reliability` memory) has prior art. Find why the
     desktop re-syncs everything + re-pairs the device session on every
     request.
   - Consider relaxing the strict one-op-at-a-time per-user `procMu`.
     The always-drain `PipeID` correlation already supports
     out-of-order responses, so `procMu` could allow N in-flight ops
     pipelined to one subprocess (the subprocess main loop is still
     serial, but the supervisor would stop blocking op N+1's *write*
     on op N's *response*). Design carefully — the subprocess main
     loop, persist, and self-evict assume serial ops.
3. **If a blocking handler:** make the device-op / request-session
   path not block the main loop — return immediately, deliver the
   result asynchronously (the desktop already gets its real answer via
   `publishDeviceResponse`).
4. **Verify the supervisor watchdog actually fires** (it didn't on v3).
5. Then strip the `// DIAG` instrumentation (see section above).

### Current deployed state (as of checkpoint)

- Enclave **`2026-05-22-v3`** live — PCR0 `7bab66cacdab47b4f7bc0043…`,
  AMI `ami-0d8b032cb4271cff8`, instance `i-090355f5f1a8c2d4c`. Migration
  v2→v3 active (KMS AnyOf[v2,v3], ASG=2, deadline `2026-05-25T14:35:47Z`)
  — auto-finalizes when both users migrate.
- vettid-dev `main` HEAD **`462a95f`**. All three fixes committed +
  pushed. Working tree clean.
- `// DIAG` instrumentation is LIVE in v3 — **keep it** until this is
  fixed.
- Enclave journal: SSM `aws ssm send-command` to `i-090355f5f1a8c2d4c`,
  unit `vettid-parent`. Pixel 9 = `4B081FDAP004V0` (al / `eb8472f6`),
  Pixel 7 = `28121FDH2009C5` (mesmer / `af44310d`). `af44310d` never
  stalls (no desktop → no `forOwner.device` burst).
- Code map: `supervisor/vault_lifecycle.go` `ProcessMessage` (procMu
  ~432, select ~493); `vault-manager/main.go` main loop (the `0aa49e9`
  fix); `vault-manager/device_handler.go` `handleDeviceOpRequest`
  (~289); `vault-manager/messages.go` `HandleMessage` dispatch (~863),
  forOwner routing (~961-1058).

### Separate open bug (do not conflate)

Desktop credit-card minor-secret reveal shows "managed on your phone" /
"no value to reveal" for alias-grouped fields (e.g. Expiration). It is
a `secret.get` path issue, not the stall — though `secret.get` queued
behind the 25 s backlog could also make it *look* failed. See
`secrets-data-ui-followups.md` memory.

## ✅ ROOT CAUSE — DEFINITIVE (2026-05-22, later)

Everything above this section is superseded. The "burst backlog" and
"pipe-delivery failure" diagnoses were both wrong. The live v3 journal
(enclave `2026-05-22-v3`, instance `i-090355f5f1a8c2d4c`) settled it.

### Evidence

The stalling op was `op#171` — a `forOwner.device` op, pipe_id
`661960e626511ce7ab265c612e178534`, the desktop's phone-required
"request sensitive data" device op. The journal proves:

- It **was delivered** to the subprocess and **was handled**:
  `Received message from supervisor length=1284` → `Handling message
  forOwner.device` → `Received device message … device_op_request` →
  `Event logged device.approval.requested` → publishes. (So neither a
  pipe-delivery failure nor a wedged handler.)
- The supervisor's `ProcessMessage` for it then sat in its `respCh`
  select for **exactly 30 s** (`48.079` → `14:43:18.079`), hit
  `opTimeout`, and released `procMu` — draining ~11 queued ops.
- **No `"Pipe response with no pending op"` warning** ever fired — so
  the op's response was not *dropped* by `deliverResponse`; it never
  reached `deliverResponse` at all.

### The bug

`vault-manager/device_handler.go` `handleDeviceOpRequest`, the
**phone-required** branch, did:

```go
pubMsg := &OutgoingMessage{Type: MessageTypeNATSPublish, Subject: approvalTopic, …}
…
return pubMsg, nil          // ← returns a nats_publish AS the op response
```

The vault-manager main loop stamps `pubMsg.PipeID = msg.PipeID` and
sends it down the pipe. The supervisor's pipe reader
(`supervisor/vault_lifecycle.go` `startPipeReader`) demuxes **by
`Type`**: `MessageTypeNATSPublish` → `forwardToParent`, **not**
`deliverResponse`. So op#171's "response" was forwarded to the parent
as a vault-initiated publish (which is *why device approval still
works* — the phone does receive the approval request), and the
`ProcessMessage` waiting on pipe_id `661960…` **never got a
PipeID-correlated response**. It waited out the full 30 s `opTimeout`
holding the single per-user `procMu`; every queued op for that user
serialized behind it. That is the ~30 s stall.

`0aa49e9` fixed the sibling `return nil, nil` path (synthesize an ack
when a handler returns nil) but missed this `return pubMsg, nil` path —
a non-nil, wrong-Type return value.

### The fix (vettid-dev, this session)

1. **`handleDeviceOpRequest`** — publish the approval request via
   `dh.publisher.PublishRaw(approvalTopic, approvalBytes)` (the exact
   primitive `publishDeviceResponse` already uses in the same function)
   and `return nil, nil`, so the forOwner router synthesizes a proper
   PipeID-correlated `MessageTypeResponse` ack.
2. **`vault-manager/main.go` main loop — defensive backstop.** If
   `HandleMessage` ever returns a `MessageTypeNATSPublish`-typed
   message, forward it as the standalone publish it was meant to be
   (PipeID cleared), log a `Warn`, and synthesize a real ack. This
   makes the bug class structurally dead — a future handler that makes
   the same mistake degrades to a logged warning, not a 30 s stall.

Verified: `go build` / `go vet` / `go test` (vault-manager,
supervisor, storage) clean; Tier-2 harness single-parent sweep green
(`concurrent-load`, `concurrent-multiuser`, `persist-idle-no-stall`).

### ✅ VERIFIED LIVE — 2026-05-22, enclave v4

Deployed as enclave `2026-05-22-v4` (PCR0 `53b4ba1e301f41c71a405f98…`,
AMI `ami-0385fd53dc61c3d05`, instance `i-07a3bd93759f0c92f`); both
users migrated. Live test by the user: desktop "request sensitive
data" now completes in **milliseconds**. v4 journal over the test
window: worst `procmu_wait` **296 ms** (was 29 748 ms), **zero**
`WATCHDOG(supervisor)`, **zero** `Timeout waiting for vault-manager`,
**zero** `nats_publish as the op response` Warn (the backstop was
never needed — the handler now returns cleanly). The ~30 s
device-approval stall is fixed.

**Remaining follow-up:** strip the `// DIAG` instrumentation (still
live in v4) and restore the watchdog thresholds — see the
"Diagnostic build" section above. Needs one more enclave deploy.
