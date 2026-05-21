# Device-approval ~30s stall — diagnosis + debug plan

_Started 2026-05-21. Updated 2026-05-21 (later): live-journal re-trace +
diagnostic build._

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

## Next session — reproduce + read the dump

1. Deploy the diagnostic build (`enclave/scripts/deploy.sh` — an enclave
   migration).
2. Reproduce: desktop "request sensitive data access", let it stall
   ~30s.
3. Pull the journal and read the dump:
   - `WATCHDOG(supervisor)` present → hypothesis B. Read which
     `ProcessMessage` goroutine holds `procMu` and what it is blocked
     on; everything else is piled on `procMu.Lock`.
   - `WATCHDOG: vault op exceeded stall threshold` (vault-manager)
     present → hypothesis A. Read the wedged `HandleMessage` stack.
   - The `DIAG:` `procMu_wait` / `write_dur` lines give the per-segment
     timeline either way.
4. Root-cause fix once the dump pins the stuck stack.

## Evidence pointers

- Enclave instance `i-0c104dd5c24398b4e`, journal unit `vettid-parent`.
- Request id `2b687986ba08d87f46448ed680ca54c8`; the journal's
  `device.approval` op `request_id 9653a706-2dca-476a-af37-3bafc0d81270`.
- Same family as `device-approval-reliability` memory /
  `SUPERVISOR-ALWAYS-DRAIN-PLAN.md` — the always-drain refactor fixed
  the persist *pipe-write* wedge; this is a distinct stall.
