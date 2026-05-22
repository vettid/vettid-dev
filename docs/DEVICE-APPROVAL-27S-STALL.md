# Device-approval ~30s stall — diagnosis + debug plan

_Started 2026-05-21. Updated 2026-05-21 (later): live-journal re-trace +
diagnostic build. **Updated 2026-05-22: FIX SHIPPED — see last section.**_

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
