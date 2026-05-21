# Supervisor Always-Drain Refactor — Plan

Status: planned (2026-05-21). The real fix for the recurring vault-manager
persist wedge that three incremental fixes today only reshaped.

## Problem

The vault-manager subprocess and the supervisor talk over stdin/stdout
pipes. `VaultProcess.ProcessMessage` (`enclave/supervisor/vault_lifecycle.go`)
is the **only** code that reads the subprocess's stdout, and it reads
**only while it is actively processing one op**:

1. write the op to subprocess stdin
2. loop: read stdout — service `sealer_request` (S3/KMS), forward
   `nats_publish`, return on the final `response`

The subprocess emits a `store_vault_state` persist (~0.5–1.3 MB sealer
request) as part of op handling. If that persist lands at a moment when
no `ProcessMessage` is mid-read — `ProcessMessage` already hit its 30s
deadline and returned, or the persist falls between ops — nothing
services it. The subprocess's `sealer_proxy` then blocks on its own 30s
timeout (`SECURITY: Sealer proxy timeout waiting for supervisor
response`); the op loop is single-threaded so the whole vault stalls; a
retry finally goes through.

Confirmed in production (2026-05-21, owner `eb8472f6`):
`store_vault_state` `msg-1779323179` sent 00:26:19 → sealer-proxy
timeout 00:26:49 (30s) → retry succeeded in **1s**. The S3 write is ~1s;
the 30s is purely "supervisor wasn't reading the pipe."

Three fixes today — mux reader/writer split, persist-before-response,
evict-on-read-timeout tuning — each changed the *shape* of the stall
without removing it, because none addressed the structural cause.

## Root cause

The subprocess↔supervisor pipe is treated as strictly synchronous
request/response owned by `ProcessMessage`. But the subprocess
legitimately emits messages (sealer requests, `nats_publish`,
`routing_handoff`) at times not bracketed by a `ProcessMessage` read.
Any such message stalls until the next op's `ProcessMessage` reads it.

## Fix — a persistent reader for the subprocess pipe

Mirror the `MuxConn` design (already proven for the vsock transport) one
level down, on the subprocess pipe:

- **One dedicated reader goroutine per `VaultProcess`**, started at
  spawn, reading subprocess stdout forever (until the subprocess dies)
  and demuxing:
  - `sealer_request` → dispatch to a worker that runs
    `HandleSealerRequest` (S3/KMS) and writes the `sealer_response`
    back — off the reader goroutine, so a slow S3 op never blocks
    draining.
  - `vault_op` response (`response`/`error`, correlated by request ID)
    → deliver to the waiting `ProcessMessage` via a pending-map channel.
  - `nats_publish` / `audit_event` / `log` / `routing_handoff` →
    forward to the parent as today.
- **`ProcessMessage` becomes**: register `pending[requestID] = chan`,
  write the op to stdin, `select` on the response channel vs. a
  deadline. It no longer reads — the persistent reader routes responses.
- **stdin writes** serialized with a write mutex (the subprocess's
  `receiveMessages` goroutine always drains stdin, so a write never
  stalls). Optional: a writer goroutine + outbound channel exactly like
  `MuxConn` — defer unless contention shows.
- **Subprocess death**: reader exits → fail every pending entry so
  `ProcessMessage` callers return promptly (mirror `MuxConn.shutdown`).

### Why this fixes it

A persist `store_vault_state` — or any subprocess-initiated message — is
serviced the instant it lands, regardless of whether an op is "active".
The 30s sealer-proxy timeout path is never hit; the op loop never stalls
waiting on the supervisor.

## What it lets us simplify (after it lands and is verified)

- The `read timeout` failure mode in `ProcessMessage` largely
  disappears; `isSubprocessGone` (dead pipe) remains the real failure
  signal.
- The persist-before-response reorder (`vault-manager/main.go`,
  `0f7adb9`) becomes belt-and-suspenders, not load-bearing — keep it.
- The stall watchdog (`runStallWatchdog`) stays as a diagnostic; with
  the always-reader it should simply stop firing.
- `procMu` (per-user op serialization on the supervisor side) can later
  be relaxed — the subprocess already serializes ops via its single
  `msgChan` consumer, so the supervisor could pipeline ops and let the
  reader correlate responses. Separate, optional follow-up; the
  always-reader fix does NOT require it.

## Files

- `enclave/supervisor/vault_lifecycle.go` — `VaultProcess`,
  `ProcessMessage`, spawn path: add the reader goroutine + pending map.
- `enclave/supervisor/pipe_ipc.go` — pipe framing; plain blocking
  `readFrame` for the reader, mutex-guarded write.
- `enclave/supervisor/supervisor.go` — `handleVaultOp` (the
  read-timeout branch is already removed).
- the `HandleSealerRequest` site — now invoked from the reader's worker
  dispatch.

## Steps

1. Add `pipeReader` goroutine + `pending map[string]chan *Message` +
   `pendingMu` to `VaultProcess`.
2. Reader loop: `readFrame` → demux (response → pending;
   `sealer_request` → `go handleSealer`; else → forward).
3. Rewrite `ProcessMessage`: register pending, write op,
   `select { resp; ctx.Done }`.
4. stdin write mutex.
5. Reader-exit teardown: fail all pending.
6. `go test ./supervisor/...`; Tier-2 harness sweep + `migration-handoff`.
   Add a scenario: enroll a vault, idle it past the persist-debounce
   window, fire one op, assert no 30s stall — directly exercises
   "sealer request emitted between ops".
7. Deploy via `enclave/scripts/deploy.sh` (migration).

## Risks / rollback

- Most critical path in the system — but `MuxConn` is a working
  template for exactly this pattern.
- Request-ID correlation must be airtight: audit that the subprocess
  always echoes the op's request ID on its response.
- Rollback: revert the commit, redeploy; pre-refactor `ProcessMessage`
  behavior is unchanged.
