# Device-approval ~30s stall — diagnosis + debug plan (2026-05-21)

## Symptom

Desktop "request sensitive data access" consistently takes ~30s to
register, even on a fresh session. Reproducible.

## What it is NOT

Traced one occurrence end-to-end (enclave journal on `i-0c104dd5c24398b4e`
/ enclave `2026-05-21-v3`, plus Pixel 9 logcat). Phone clock is UTC-4.

- **Not the app / not the user.** Pixel 9 logcat:
  - `16:49:40` phone receives the request (`OwnerSpaceClient: Device
    approval request … op=secret.unlock-session`) — instant.
  - `16:49:42.9` phone publishes the approval (`forVault.device.approval`,
    244 bytes) — user tapped Approve in ~3s.
  - `16:50:10.4` phone receives the result (`approved:true`).
- **Not the phone-notification path.** The request reaches the phone
  instantly and the approval is published instantly.
- **Not an enclave op-wedge.** The stall-watchdog never fired (no op
  ran >25s); vault-state persists are sub-second (always-drain holds).

## What it IS — a ~27s between-op stall inside the enclave

Enclave journal for owner `eb8472f6` (the Pixel 9 user):

- `20:49:42` — parent receives the approval op:
  `Created enclave message … forVault.device.approval` +
  `Extracted inner payload … type=device.approval`. Two more
  `eb8472f6` ops (`forOwner.device`, `feed.sync`) arrive the same second.
- `20:49:42 → 20:50:09` — **the `eb8472f6` vault-manager subprocess
  handles nothing for ~27s.** All three queued ops sit unprocessed.
- `20:50:09` — `Handling message … forVault.device.approval` →
  `device.approval.granted` → response published. The other queued ops
  drain in the same burst.

So the approval op reaches the enclave instantly, then the per-user
vault-manager subprocess sits **idle/blocked for ~27s** with ops queued
behind it, then processes them all at once. The stall-watchdog misses
it because the watchdog only times *in-op* execution — a subprocess
idle/blocked *between* ops is invisible to it.

## Debug plan (next focused session — do deliberately, not a hot-patch)

1. **Extend the watchdog to cover between-op stalls.** Today it stamps
   `opStartedAt` per op and dumps goroutines if an op runs >25s. Add a
   second check: an op *received* (`Created enclave message`) but not
   *handled* within ~10s → dump every goroutine stack. This is the
   missing diagnostic — it'll show exactly what the subprocess (or the
   parent's deliver-to-subprocess path) is blocked on.
2. **Reproduce** with that build: desktop request-sensitive-data, let
   it stall ~30s, pull the journal `WATCHDOG:` goroutine dump.
3. **Likely suspects to confirm against the dump:**
   - Parent → subprocess delivery: the op is parsed in the parent at
     T+0 but not written to the subprocess until T+27 (per-user send
     queue / `procMu` held).
   - Subprocess main loop blocked between ops on a channel/lock — e.g.
     a `store_vault_state` sealer round-trip, or the JetStream consumer
     ack/pull cadence (persist cadence is ~30s — suspiciously close).
   - JetStream consumer: the op is consumed but redelivered/stalled —
     check `num_delivered` and AckWait on the `forVault.>` consumer.
4. Root-cause fix once the dump pins the stuck stack.

## Evidence pointers

- Enclave instance `i-0c104dd5c24398b4e`, journal unit `vettid-parent`.
- Request id `2b687986ba08d87f46448ed680ca54c8`; the journal's
  `device.approval` op event_id `9653a706-2dca-476a-af37-3bafc0d81270`.
- This sits in the same family as `device-approval-reliability.md` /
  `SUPERVISOR-ALWAYS-DRAIN-PLAN.md` — the always-drain refactor fixed
  the persist *pipe-write* wedge; this is a distinct between-op stall.
