# Migration — Target Architecture

## Executive summary

The brief's PIN-unlock-coupled migration design is **accepted with modifications**. The core decision — fold migration consent and re-seal into PIN unlock and remove the gratuitous `persistVaultStateToS3` call — is correct and eliminates the class of bug behind both incidents. However, three design weaknesses remain that the brief does not fully resolve: (1) NATS round-robin can route the `pin-unlock` request to the OLD enclave on a multi-instance ASG, in which case the request must NOT re-seal but must succeed normally, and the **OLD enclave must not write `sealed_material.bin` either**; (2) the per-version migration marker should be the single source of truth — `migration_state` in vault data must go away to eliminate split-state bugs; (3) the storage layer needs three invariants (not just `vaultDataLoaded`): a generation counter on `sealed_material.bin`, a never-shrink rule on `vault_state.enc`, and a refusal to write any user-data object before a successful cold-load proves PIN. The recommended architecture below describes a re-seal that is fully idempotent and locally atomic, an explicit "this enclave attests to NEW PCR0" gate at the top of the re-seal path, and a test plan grounded in a Docker pair that simulates NATS load-balancing across two PCR0s. **Auto-migration remains off.**

---

## 1. Validation of the brief

### Accepted

- **Couple consent + re-seal to PIN unlock.** Right call. The current architecture has three steps (config fetch → consent dialog → start-migration request) that can each land on different instances and use different in-memory state. Folding to one request with one auth gate is the only way to make the protocol stateless across enclave instances.
- **Remove the `persistFn` call from the migration path.** This is the single change that prevents both incidents from recurring. The migration re-seal touches `sealed_material.bin` and `sealed_ecies.bin` only — it has no business writing the 220 KB `vault_state.enc`.
- **`vaultDataLoaded` flag.** Defense-in-depth, ship it. But it is not sufficient on its own (see below).
- **`migrate_consent: true` field on `pin-unlock`.** Right shape.
- **KMS attestation as the cryptographic gate.** Genuinely sufficient: `kms:Decrypt` of the OLD-sealed material with attestation succeeds on either OLD or NEW (KMS policy is `AnyOf`); `kms:Encrypt` against the NEW PCR0 attestation only the NEW enclave can produce. So a malicious OLD enclave running re-seal cannot hand the user a NEW-bound ciphertext.

### Modifications

#### M1. The `migrate_consent` request still needs to be safe on the OLD enclave

Today, `pin-unlock` requests are published to `OwnerSpace.<guid>.forVault.pin-unlock`. The vault-routing KV decides which instance owns the user's subscription, and only that instance receives the request. **However**, ownership in `vault-routing` is leased; during a migration window with two enclaves running, the user's owner is whichever enclave currently holds the lease — which on first contact post-deploy is likely the OLD one (it heartbeated before NEW came up). Cold-restart of any single instance also re-elects.

So the message can land on EITHER PCR0. The handler must:

1. Decrypt PIN, verify auth, complete a normal unlock — **regardless of which PCR0 the running enclave is on**.
2. ONLY attempt re-seal if `running PCR0 == config.NewPCRs.PCR0`. If `migrate_consent=true` arrives at an OLD enclave: complete unlock normally, do NOT re-seal, and emit a routing handoff to release-for-reclaim by NEW. The user's app then re-issues unlock; NATS routing reclaim brings it to NEW; the second unlock re-seals.
3. The OLD enclave must **never** write `sealed_material.bin`, `sealed_ecies.bin`, or `vault_state.enc` during this flow. Its only write to S3 in the migration window is the routing handoff signal (which goes through NATS KV, not S3).

Concretely, that means `migrate_consent=true` on OLD is a no-op for storage; it only triggers a routing handoff. The brief implicitly assumes the request always lands on NEW. It will not.

#### M2. Eliminate `migration_state` from vault data

The current `MigrationState` struct (`migration_handler.go:146`) is stored in `EncryptedStorage` (DEK-encrypted, persisted in `vault_state.enc`). It carries `Status`, `MigratedAt`, `ToPCRVersion`, etc. **Every write to it requires `persistVaultStateToS3` to land** — exactly the path that destroyed user data twice. The per-version S3 marker (`_migration/completed/{version}/{ownerSpace}.json`) is already KMS-Verify-signed and is the source of truth for the auto-finalize Lambda. Keeping both is split state; one of them will lie.

**Decision:** delete `migration_state` from vault data. The marker is the only record. `MigrationStatusResponse` (the user-facing status) reads the marker via the parent (or just returns `{available: bool}` from the config-vs-marker comparison in-memory).

This also removes the `HandleAcknowledge` flow entirely — its only purpose was to write `UserAcknowledged=true` into the in-vault state, which was never load-bearing.

#### M3. Generation counter on `sealed_material.bin`

`sealed_material.bin` and `sealed_ecies.bin` are independently overwritable S3 objects. After a successful re-seal there is a window where the next unlock might run on an enclave that hasn't yet seen the new bytes (S3 is read-after-write consistent for new keys but not for overwrites in some legacy semantics; with strong consistency since 2020 this is no longer the issue, but eventual visibility through any caching layer remains). More importantly, the existing structure has no version field — a re-seal that races a concurrent re-seal from another enclave (e.g., both OLD and NEW receive a `migrate_consent` and both decide to write — should never happen given M1, but defensive) silently last-writer-wins.

**Decision:** add a generation counter and a precondition.

```json
// sealed_material.bin (JSON wrapper, current shape)
{
  "version": 1,
  "sealed_material": "<KMS ciphertext>",
  "owner_id": "...",
  "created_at": 1714000000,
  "generation": 7,                  // NEW: incremented on every write
  "sealed_to_pcr0": "abc123...",    // NEW: PCR0 the inner blob was sealed against
  "sealed_to_version": "2026-05-09-v3"  // NEW: human-readable migration version
}
```

`StoreSealedMaterial` writes use S3's conditional writes (If-Match on ETag, available 2024) when overwriting. The handler reads `current generation`, increments, writes with the conditional. A concurrent overwrite by another enclave gets PreconditionFailed and the handler retries (re-load, re-derive, re-write). If retry fails twice the handler logs and bails — the user gets an error, no corruption.

`sealed_to_pcr0` lets any enclave determine on cold-load whether the material is OLD or NEW without trusting an S3 sidecar. If `sealed_to_pcr0 == running PCR0`, normal unlock. If it doesn't match, KMS attestation alone tells us we have an `AnyOf` policy and unsealing will succeed if the running PCR0 is in policy — but we now know whether re-seal has already run.

#### M4. Drop the in-vault `vault_state.enc` write from the migration path entirely

Already in the brief. Stating again here because it's the load-bearing change. After M2 is in, there is no `migration_state` to write, and the migration handler never modifies vault data, so there is literally no reason for `persistFn` to be invoked from migration code. **Remove the wiring at `messages.go:422`**; `migrationHandler.SetPersistFn` becomes dead code and the field comes off the struct.

---

## 2. Failure-mode walkthrough

| # | Scenario | Expected behavior | Mechanism |
|---|---|---|---|
| F1 | User on OLD enclave, never approves; uses app normally | App unlocks normally on OLD via PIN. KMS policy still has `AnyOf [OLD, NEW]` during window so OLD-sealed material decrypts. App shows the migration card on every session but user keeps tapping "Remind me later." | OLD enclave's `pin-unlock` handler runs unchanged; `migrate_consent` not in request; no re-seal attempted. |
| F2 | User taps Cancel on the PIN screen | App sends no vault request. PIN screen closes. User remains logged in on the previous session if any; otherwise the lock screen returns and they can try again later. | Pure UI action; no NATS publish happens. `migrationConsentTracker` is not consulted because nothing was approved. |
| F3 | KMS encrypt succeeds (NEW-bound ciphertext produced) but S3 write of `sealed_material.bin` fails | Handler returns error to app. **No marker is written.** App displays "Update failed, please try again." Next unlock attempt: cold-load reads OLD `sealed_material.bin` (unchanged), re-tries the whole re-seal. KMS still has `AnyOf`, so OLD-bound decrypt still works. Idempotent. | Re-seal sequence is: (a) load OLD `sealed_material.bin`; (b) KMS Unseal; (c) KMS Encrypt with NEW; (d) write `sealed_material.bin` (conditional on generation N+1); (e) write `sealed_ecies.bin`; (f) write marker. Failure between (c) and (d) is no-op. Failure of (d) after (c) is no-op (in-memory NEW ciphertext is discarded, S3 unchanged). |
| F4 | S3 write of `sealed_material.bin` succeeded, then crash before marker | User's material is now NEW-bound. Next unlock lands on either PCR0 via routing. If on NEW: cold-load reads NEW `sealed_material.bin`, KMS Unseal works, normal unlock completes — and because the handler reads `sealed_to_pcr0` from the wrapper and sees it matches running PCR0, it knows re-seal already happened, just writes the missing marker (`WriteMigrationMarker`). If on OLD: cold-load reads NEW `sealed_material.bin`, KMS Unseal **fails** on OLD because the inner ciphertext was sealed under NEW PCR0 attestation and OLD's attestation document contains OLD's PCR0 — KMS rejects. Handler emits routing release-for-reclaim and returns error to app; app retries; routing brings them to NEW; resume. | M3's `sealed_to_pcr0` field plus the marker-write-after-re-seal-only-if-missing pattern handle this. Marker write is idempotent (same content, same key). |
| F5 | Marker write fails after re-seal succeeded | User is "migrated but unmarked." Next unlock recognizes via `sealed_to_pcr0 == NEW_PCR0` that re-seal is complete; writes marker; returns success. Auto-finalize Lambda treats this user as not-yet-migrated until the marker lands, which delays finalize by at most one unlock cycle. | Idempotency rule: handler always reconciles. The fix is "if material is NEW-sealed and marker is missing, write marker." |
| F6 | Two enclaves running, request lands on OLD vs NEW | OLD: complete normal unlock; if `migrate_consent=true`, emit routing handoff (release-for-reclaim) so NEW reclaims; do NOT re-seal. App receives unlock success, then on the next session retries against NEW. NEW: complete unlock; if `migrate_consent=true` AND material is OLD-sealed, run re-seal; write marker. | M1. The handler's first action after PIN verify is `if running_pcr0 == config.NewPCRs.PCR0 { do_reseal() } else { handoff() }`. |
| F7 | App sends `migrate_consent=true` but no migration config is published in S3 | Handler refuses to re-seal: `fetchAndVerifyMigrationConfig` returns nil. Treats as normal unlock. Returns success without re-seal. App's `MigrationConfig?` was already null from an earlier call so this branch is not normally reached; but if it is (replay, race), no harm. | Existing config-verification gate. |
| F8 | App sends `migrate_consent=true` with a forged config (signature invalid) | The vault never trusts the app's claim; it always re-fetches and KMS-verifies the signed config from S3. Handler refuses to re-seal on signature failure. | `fetchAndVerifyMigrationConfig` is the single chokepoint. |
| F9 | User has migrated; OLD instance still in service; KMS removes OLD from policy mid-session | OLD enclave loses ability to sign new attestations against KMS — any subsequent operation fails because the parent's KMS calls require attestation. Routing lease expires; NEW reclaims. User experiences a brief connectivity hiccup. | Auto-finalize Lambda's KMS tightening is independent of routing; users actively on OLD when finalize fires get cut off mid-session. **This is acceptable** but should be logged. |
| F10 | User is on OLD enclave when finalize runs; vault auto-save ticker fires after KMS tightens | OLD enclave's `persistVaultStateToS3` calls `kms:Encrypt` (or actually doesn't — the wrapper is DEK-encrypted, so only S3 PutObject). PutObject still works (IAM unchanged). User's OLD-PCR0-sealed `sealed_material.bin` is **not rewritten** by this path. So the worst case is the user's `vault_state.enc` is updated by an OLD enclave that still has DEK in memory — that's safe; it's the same DEK they've been using. | This is a corner case but is benign because the DEK is still valid in the OLD enclave's memory; data is consistent. Once finalize completes and OLD is terminated, new unlocks land on NEW which has the NEW-sealed material. |
| F11 | App was on OLD enclave for hours, then tries unlock right as `MinSize` was already restored to 1 by finalize and OLD has been terminated | Routing reclaim by NEW happens automatically; cold-load reads `sealed_material.bin`. If material is still OLD-sealed (user never approved): NEW attempts KMS unseal of OLD-bound ciphertext — **after** finalize tightened KMS, OLD PCR0 is no longer in policy, so the unseal **fails**. User must re-enroll. | Documented as "missed-deadline" outcome. The 72-hour window plus the visible "Update Required after X" prompt is the user's protection. |
| F12 | Concurrent re-seal attempts (same user, two enclaves) | Should never happen under M1 (only NEW re-seals). But if it did: M3's generation+ETag conditional means the second writer's `If-Match` fails; handler bails. No corruption. | Defense in depth via M3. |

---

## 3. Storage-layer invariants

### `vault_state.enc` (DEK-encrypted SQLite + crypto carve-outs)

| Property | Rule |
|---|---|
| Who may write | The **owning** enclave (per `vault-routing` lease) for the OwnerSpace, **and only after** that instance has loaded the user's data into memory via cold-unlock or fresh enrollment. |
| `vaultDataLoaded` flag | Required `true` precondition. (Already implemented.) |
| Migration path writes | **Forbidden.** The migration re-seal must not call `persistVaultStateToS3`. Remove the `SetPersistFn` wiring. |
| Shrink guard | Before write, if existing object `>= 50 KB` and new payload `< 50% of existing`, **refuse** and emit a CloudWatch error metric. This is a sanity check for "we somehow got here without `vaultDataLoaded` set" or memory state was wiped mid-session. |
| Versioning | S3 versioning ON (already), 30-day noncurrent retention (already). Add CloudWatch alarm on `NumberOfNoncurrentVersions` per object exceeding 5/day for any single key — that's a write storm and indicates a bug. |
| Encryption | AES-GCM with DEK; DEK is derived from PIN + sealed material. |

### `sealed_material.bin` (KMS-sealed PIN-derivation material)

| Property | Rule |
|---|---|
| Who may write | (a) The PIN-setup handler at fresh enrollment; (b) the PIN-change handler; (c) the migration re-seal path **only on the enclave whose PCR0 matches the migration config's NewPCRs.PCR0**. No other path. |
| Wrapper format | Add `generation` (monotonic), `sealed_to_pcr0` (hex), `sealed_to_version` (string). |
| Conditional writes | All overwrites use S3 If-Match on ETag from the read. PreconditionFailed → re-read, re-verify generation increments by exactly 1, retry once, then bail. |
| Idempotency | If a writer reads `sealed_to_pcr0 == its own running PCR0` and is about to re-seal to the same PCR0, **abort** — it's a no-op and indicates a logic error. |
| Cold-load behavior | Any enclave reading `sealed_material.bin` checks `sealed_to_pcr0` against its running PCR0. If different, KMS Unseal will either succeed (PCR in `AnyOf`) or fail (PCR no longer in policy); handler returns appropriate error to app. |

### `sealed_ecies.bin` (KMS-sealed ECIES keypair for cold-PIN-decrypt)

Same rules as `sealed_material.bin`. Add the same `generation` / `sealed_to_pcr0` fields. Re-seal is part of the same atomic re-seal sequence.

### `_migration/completed/{version}/{ownerSpace}.json` (per-user migration marker)

| Property | Rule |
|---|---|
| Who may write | The enclave (any), via `WriteMigrationMarker` after a successful re-seal **OR** after detecting via `sealed_to_pcr0` that re-seal already happened but the marker is missing (recovery path for F5). |
| Format | `{version, owner_space, completed_at, signature}`; signature is KMS-Sign over canonical JSON. (Already.) |
| Idempotent | Yes — same content, same key, overwrite is fine. |
| Refuse-write | If the marker for `(version, ownerSpace)` already exists with a valid signature for the same `completed_at`, skip the write. Otherwise overwrite to refresh `completed_at`. |
| Size cap | Markers should be < 1 KB; refuse writes > 4 KB. |

### `_migration/config.json` (signed migration config)

| Property | Rule |
|---|---|
| Who may write | Operator via `deploy.sh`; KMS-signed by the PCR-signing key. |
| Verification | Every read by the enclave goes through `fetchAndVerifyMigrationConfig`. Single chokepoint. |
| Time gate | `valid_from <= now <= mandatory_after + grace`. After grace, treat as expired. |

### Cross-cutting: per-user lock during re-seal

NATS routing already gives us **single-owner-per-user** ownership via the `vault-routing` KV with a 45-second lease. That's the existing ownership lock; we should not add another. The ownership lock is enforced at the **subscription** layer — only the owner's enclave receives the message. So a re-seal does not need an additional in-process mutex beyond the existing per-handler mutex on `VaultState.mu`. **Trade-off accepted:** ownership eventual consistency on the order of a lease (45 s) is fine because re-seal is idempotent under M3 + F4.

---

## 4. Per-user state ownership on a multi-instance ASG

### Trade-offs

| Option | Pros | Cons |
|---|---|---|
| **A. Keep NATS routing ownership; make re-seal idempotent (recommended)** | Already implemented; no new concurrency primitive. M3's S3 conditional writes plus `sealed_to_pcr0` check make concurrent re-seals safe. | Brief 45-second window on lease expiry where two enclaves could believe they own the user. M3 closes that window for storage. |
| B. Add an explicit S3-based migration lock (write `_migration/lock/{ownerSpace}` before re-seal, delete after) | Belt-and-suspenders. | Operationally fragile: lock leaks on crash, requires TTL via lifecycle (5-min granularity), introduces failure modes around lock acquisition. |
| C. Pin migration handling to a single coordinator instance (one-of) | Conceptually simple. | Requires leader election in the ASG; adds an outage mode if leader dies; doesn't compose with NATS routing. Rejected. |
| D. Eliminate routing ownership; allow any enclave to serve any user | Simpler subscription topology. | Requires every operation to be safe under multiple writers, which the codebase is nowhere near today (DEK in memory, vault state cached, etc.). Massive refactor. Rejected. |

**Pick A.** The existing routing ownership combined with M3's storage invariants makes re-seal safe even if the lease expires mid-flight: at most one writer ever wins. The other writer either (a) fails the conditional (PreconditionFailed) and aborts cleanly, or (b) reads the new state on retry and recognizes it as already-done.

### What NEEDS to be added on the routing side

The existing routing handoff (`MessageTypeRoutingHandoff` with empty `TargetInstanceID`) emits AFTER re-seal completes. With M1, we additionally need: **OLD enclave receiving `migrate_consent=true` emits a routing handoff *without* re-sealing**, so NEW can take over. Today the handoff is wired to the success path of `HandleStart`. With the redesign it's wired into `HandlePINUnlock` after a successful unlock when `migrate_consent=true && running_pcr0 != new_pcr0`.

---

## 5. CPU autoscaling vs migration

The `MinSize=2` pin in `deploy.sh` Phase 4 is **necessary but not sufficient**.

### The remaining gap

The CPU target-tracking policy at `nitro-stack.ts:736` (target 70%, cooldown 5 min) tracks group-level CPU. With two instances at low CPU during a migration window, the policy emits scale-down alarms. `MinSize=2` prevents the alarm from terminating an instance, which is correct. But there are two residual issues:

1. **The auto-finalize Lambda restores `MinSize=1, MaxSize=1` and `DesiredCapacity=1`** (`migrationFinalize.ts:128-132`). If users are mid-flight (actively unlocking) the moment finalize runs, the OLD instance is terminated. M1 + F11 say they get cut off and have to re-enroll if past deadline. That's the design. But **there is no quiescence check** before finalize fires — Lambda just decides "all markers in" or "deadline passed" and tightens. A user who is in the middle of typing their PIN at the exact moment Lambda fires can land in an awkward state. This is rare but worth handling.
2. **Scale-up during migration is essentially capped at 2** since `MaxSize=2`. If load spikes mid-migration, no headroom. For 2-instance migration this is fine, but worth documenting.

### Recommendation

- **Quiescence delay** before terminating: when the auto-finalize Lambda decides to scale down, it should first put the OLD instance into `Standby` (drains routing ownership, stops accepting new subscriptions) for 60 seconds, then terminate. The `vault-routing` watcher on NEW will reclaim users with active sessions; users mid-PIN see a transient error and the Android `MigrationClient.startMigration` retry loop (5 retries × 1.5s) covers it.
- **Suspend the CPU scale-out (not scale-in) policy during migration** to avoid spawning a 3rd instance that doesn't make sense in the AnyOf-PCR0 world. Alternatively, leave it on — KMS allows both, the new instance attests to NEW PCR0, and it just adds capacity. Acceptable.
- **Don't suspend scale-in via custom logic; keep `MinSize=2`.** That's the simplest and the script already does this.

### Conclusion

`MinSize=2` is the load-bearing fix. Add the 60-second `Standby` quiescence on finalize. Otherwise no autoscaling-policy changes needed.

---

## 6. Migration flow on the existing enclave that users are stuck on after a deploy

### When the re-seal happens

A user logs in to a NEW enclave (post-deploy) for the first time:

1. **App resumes.** PCR manifest fetch from CloudFront → notices PCR0 has changed and is not in `trustedPcr0Set`.
2. **PIN screen shows** with "VettID has been updated" framing, a [Review details] link, the PIN keypad, and `[Approve & Unlock] [Cancel]`.
3. User types PIN, taps Approve.
4. App sends `pin-unlock { utk_id, encrypted_payload, migrate_consent: true }` to `OwnerSpace.<guid>.forVault.pin-unlock`.
5. NATS delivers to whichever enclave currently owns the user's subscription. Per the routing scheme, the OLD instance was the owner (it heartbeated through the deploy). NEW is on standby to reclaim once OLD releases.
6. **Branch A: request landed on OLD.** OLD enclave decrypts PIN, performs cold-load if needed, verifies auth, completes normal unlock. Sees `migrate_consent=true` AND `running_pcr0 != config.new_pcr0`. Emits routing release-for-reclaim. Returns `{status: "unlocked", new_utks, ..., migration_status: "pending_new_enclave"}`. App treats this as a successful unlock but knows to retry migration on the next session (or immediately re-publishes a second `pin-unlock` if it sees `migration_status: pending_new_enclave`, with a 1-second backoff).
7. **NEW reclaims** via routing watcher. App's second `pin-unlock { migrate_consent: true }` lands on NEW.
8. NEW decrypts PIN, cold-loads (reads OLD-bound `sealed_material.bin` from S3, KMS Unseal succeeds because OLD is still in `AnyOf`), verifies auth. Sees `migrate_consent=true` AND `running_pcr0 == config.new_pcr0`. **Re-seal:**
   - KMS Unseal already done as part of cold-load; we have the inner secret in memory.
   - KMS Encrypt the inner secret using the running enclave's attestation. KMS uses the attestation document to enforce the new policy: the resulting ciphertext is bound to `kms:RecipientAttestation:PCR0=NEW`. Same for ECIES.
   - Read `sealed_material.bin` to get current generation & ETag. Build new wrapper with `generation+1`, `sealed_to_pcr0=NEW`, `sealed_to_version=...`. Conditional PUT.
   - Same for `sealed_ecies.bin`.
   - Write `_migration/completed/{version}/{ownerSpace}.json` (KMS-signed).
   - Return `{status: "unlocked", new_utks, ..., migration_status: "completed"}`.
9. App sees `migration_status: completed`, marks `KEY_COMPLETED_VERSION`, adds NEW PCR0 to `trustedPcr0Set`, dismisses any feed entries.

### What the response conveys

The response shape is the existing `PINUnlockResponse` plus one new field:

```go
type PINUnlockResponse struct {
    Status              string                 `json:"status"`           // "unlocked" or "vault_ready"
    NewUTKs             []string               `json:"new_utks"`
    NatsCredentials     string                 `json:"nats_credentials"`
    NatsEndpoint        string                 `json:"nats_endpoint,omitempty"`
    OwnerSpace          string                 `json:"owner_space,omitempty"`
    MessageSpace        string                 `json:"message_space,omitempty"`
    CredentialsTTL      int                    `json:"credentials_ttl_seconds,omitempty"`
    EncryptedCredential string                 `json:"encrypted_credential,omitempty"`
    MigrationStatus     string                 `json:"migration_status,omitempty"`  // NEW
    MigrationVersion    string                 `json:"migration_version,omitempty"` // NEW
}
```

`MigrationStatus` is one of: `"completed"`, `"pending_new_enclave"`, `"not_requested"` (no `migrate_consent`), `""` (no migration in flight). The app uses this as the single signal — no separate `credential.migration.config` polling needed once unlock completes.

The existing `credential.migration.config` request remains, but only for the **detection** path (pre-PIN, before any unlock). The Android app's `VaultUpdateViewModel.checkForUpdate()` becomes a no-op after the redesign — the consent + completion are entirely in the unlock flow.

---

## 7. Test plan

The single biggest gap: there are **zero migration tests in the repo today** (`grep -l Migration enclave/vault-manager/*_test.go` returns nothing). The test plan must address that gap before any redesign ships.

### Tier 1 — Go unit tests (vault-manager)

These run under `make test` and need to land before merging the redesign.

1. **`migration_handler_reseal_test.go`** — table-driven over the re-seal state machine:
   - `TestReseal_FreshUnlock_NoConsent` — `pin-unlock` without `migrate_consent`, current PCR0 in trusted set, no migration config: returns success, no S3 writes to sealed material.
   - `TestReseal_ConsentOnNewEnclave_Success` — mocks: running PCR0 = NewPCRs.PCR0, OLD-bound `sealed_material.bin` in S3 (mock). Asserts: KMS Unseal called with OLD ciphertext, KMS Encrypt called with NEW attestation context, `StoreSealedMaterial` called with new wrapper containing `generation+1, sealed_to_pcr0=NEW`, `WriteMigrationMarker` called once. Asserts: `StoreVaultState` (persistFn) NOT called.
   - `TestReseal_ConsentOnOldEnclave_NoReseal` — running PCR0 = OldPCRs.PCR0. Asserts: no KMS Encrypt, no `StoreSealedMaterial`, no marker write, but routing handoff IS sent.
   - `TestReseal_AlreadyMigrated_Idempotent` — `sealed_to_pcr0 == running PCR0` already. Re-seal step skipped. If marker missing, marker is still written.
   - `TestReseal_MarkerWriteFails_ReturnsErrorButResealStands` — re-seal succeeds, marker write fails. Handler returns success to user (re-seal landed) but logs the marker failure. Next unlock writes the marker.
   - `TestReseal_S3PreconditionFailed_RetriesOnce` — first conditional PUT fails (concurrent writer), handler reloads, retries, succeeds.
   - `TestReseal_S3PreconditionFailedTwice_Bails` — second retry also fails. Handler returns error; no partial state.
   - `TestReseal_KMSEncryptFails_NoS3Write` — KMS Encrypt errors out; nothing in S3 changes; user gets error.
   - `TestReseal_KMSUnsealFails_NoOpReturnsError` — OLD ciphertext doesn't decrypt; user sees error; no further action.

2. **`pin_handler_migrate_consent_test.go`** — covers the `migrate_consent: true` integration into `HandlePINUnlock`:
   - `TestPinUnlock_MigrateConsent_TriggersResealOnly_OnNewPCR0`
   - `TestPinUnlock_MigrateConsent_OnOldPCR0_HandsOffOnly`
   - `TestPinUnlock_MigrateConsent_FalseOrAbsent_NeverReseals`
   - `TestPinUnlock_MigrateConsent_WithoutPublishedConfig_RefusesReseal`
   - `TestPinUnlock_MigrateConsent_WithForgedConfig_RefusesReseal`

3. **`storage_invariants_test.go`** — `persistVaultStateToS3` regressions:
   - `TestPersist_RefusesWhenVaultNotLoaded` — `vaultDataLoaded=false`, no DEK loaded → no write.
   - `TestPersist_RefusesShrinkUnderThreshold` — mock S3 HeadObject returns 220 KB; create test where new payload is 12 KB → write refused, error logged.
   - `TestPersist_AllowsNormalShrink` — existing 50 KB, new 30 KB (60%) → write allowed.
   - `TestPersist_AllowsBelowThreshold` — existing 30 KB, new 12 KB → write allowed (existing was already small).

4. **`sealed_material_generation_test.go`** — wrapper format:
   - `TestSealedMaterial_GenerationIncrementsOnPinChange`
   - `TestSealedMaterial_PCR0FieldPersists`
   - `TestSealedMaterial_LegacyWrapperWithoutGenerationStillReadable`

### Tier 2 — Local Docker pair (the real test harness gap)

Build a `docker-compose.migration.yml` that brings up:
- One LocalStack (S3 + KMS + SSM)
- One in-memory NATS with JetStream
- Two `vettid-parent` containers built with **different fake PCR0s** baked in (since real Nitro attestation isn't available locally; the parent's KMS client is patched in test mode to substitute attestation conditions with a header). Each runs the supervisor + vault-manager binaries.
- A test driver that publishes `pin-unlock`, `credential.migration.config`, etc. against NATS as if it were the Android app.

Tests:
1. **`migration_e2e_happy_path.sh`** — both containers up, OLD on `pcr0=AAA...`, NEW on `pcr0=BBB...`. Test driver: enroll a user against OLD, write a `_migration/config.json` for NEW, send `pin-unlock { migrate_consent: true }`, verify it lands on OLD via routing, gets the handoff, retries, lands on NEW, re-seal completes, marker written.
2. **`migration_e2e_concurrent_load.sh`** — same setup; while `pin-unlock` is in flight, run 5 concurrent requests for unrelated operations on the same user (event list, profile read, message send). Verify none of them write `vault_state.enc` while re-seal is in progress; verify no `vault_state.enc` shrinkage.
3. **`migration_e2e_kill_during_reseal.sh`** — start re-seal, `docker kill` the NEW container after KMS Encrypt but before S3 write. Restart container. Send another `pin-unlock`. Verify recovery: `sealed_material.bin` is still OLD-bound, re-seal retries cleanly.
4. **`migration_e2e_kill_after_reseal_before_marker.sh`** — kill after S3 write but before marker. Restart. Verify: cold-load reads NEW-bound `sealed_material.bin`, recognizes `sealed_to_pcr0 == NEW`, writes the missing marker.
5. **`migration_e2e_routing_lease_expiry.sh`** — kill OLD mid-session before it can hand off. Wait 60s. NEW reclaims. App retry succeeds. No data loss.
6. **`migration_e2e_persistFn_regression.sh`** — run `migration.start` (legacy path, kept for the rollout window per §8). Assert via `aws s3api list-object-versions --prefix vaults/{guid}/vault_state.enc` that no new version was created during the migration. **This is the test that would have caught both incidents.**

These run in CI on every PR that touches `migration_handler.go`, `pin_handler.go`, or `messages.go`.

### Tier 3 — Staging AWS account smoke test

Once a PR passes Tier 1+2, deploy to a dedicated `vettid-stg` account (small ASG, no real users) and run:
- `enclave/scripts/deploy.sh --summary "stg test"` to trigger a real PCR0-change deploy.
- Two test phones (or two emulators with mocked Keystore) enrolled before the deploy.
- After deploy: PIN unlock on phone 1, observe re-seal completes, observe marker in S3, observe sealed material changed.
- PIN unlock on phone 2 with "Cancel" first, then "Approve" — observe both UI paths.
- Wait for auto-finalize, observe ASG → 1, KMS → single PCR0, `_migration/config.json` deleted.

Document this as `docs/runbooks/migration-staging-smoke.md`.

### Tier 4 — Chaos test (recommended, not blocking)

Add to the staging smoke: `aws ec2 terminate-instances` against the OLD instance mid-migration window. Verify users still on OLD (mid-PIN) get a clean retry path on NEW.

### What would have caught the 2026-05-08 / 2026-05-09 incidents

- **Tier 2 test #6** (`migration_e2e_persistFn_regression.sh`) directly catches it. It asserts `vault_state.enc` is not rewritten during a migration. Both incidents would have produced new noncurrent versions, which the test would flag.
- **Tier 1 `TestReseal_*` tests** catch the architectural class of bug (`persistFn` shouldn't be called in migration) at unit level.
- **Tier 1 `TestPersist_RefusesShrinkUnderThreshold`** catches the symptom (220 KB → 12 KB shrink) regardless of root cause.

These three layers give us defense in depth against any future bug that resembles the same shape.

---

## 8. Migration of existing deployed state

Two user populations to consider:

### Population P1: users currently enrolled, **never migrated** (the parked state today)

The brief and checkpoint indicate both phones were decommissioned and need fresh enrollment regardless. So P1 = empty for the immediate rollout. Future enrollments after the redesign ships are P2 directly.

### Population P2: users enrolled fresh against the new enclave (post-redesign)

Their `sealed_material.bin` will be written by the new PIN-setup handler with the new wrapper format including `generation=1, sealed_to_pcr0=<current>, sealed_to_version=<current>`. No migration needed for them on this version.

### Population P3 (hypothetical): if there were users who completed an OLD-style migration before the redesign

Their `sealed_material.bin` would be in the legacy wrapper (no `generation`, no `sealed_to_pcr0`). The handler must:
- Read legacy wrapper → infer `generation=0`, `sealed_to_pcr0` unknown.
- On first cold-unlock under the new code, **rewrite** the wrapper in the new format using the running PCR0 (assuming the cold-unlock succeeds, the running PCR0 IS what the inner blob is bound to). This is a one-time silent upgrade write to `sealed_material.bin` at unlock time.
- The shrink guard does NOT trigger because `sealed_material.bin` is small (~1 KB).
- This rewrite uses S3 conditional write on ETag.

### Rollout sequence

1. Land Tier 1 tests (Go unit) and Tier 2 tests (Docker pair) in CI. Block deploys until green.
2. **Code-only deploy first** (PCR0 unchanged). The new vault-manager code runs on the existing enclave; this validates the new wrapper-format handling on real users without triggering any migration. `simple-refresh` path in `deploy.sh`. P3 users (none today) get their `sealed_material.bin` upgraded silently.
3. **Validate** in production: monitor CloudWatch for the new metrics (re-seal attempts, idempotent skips, conditional PUT failures, shrink-guard refusals). Wait at least 7 days.
4. **First migrating deploy** (PCR0 changes). The new flow exercises end-to-end. Use a deliberate small change to minimize blast radius.
5. **Auto-finalize as designed.** Add the 60-second `Standby` quiescence.

### One-time concerns

- Existing `migration_state` records in user vaults can be left in place; they're harmless. The new code stops reading and stops writing them. They get garbage-collected on the next vault-state rotation (i.e., never, but they're tiny).
- `_migration/completed/{version}/{ownerSpace}.json` markers from prior migrations remain valid; the new auto-finalize Lambda continues to verify them the same way.
- The Android app needs the new `MigrationStatus` field handling. Ship the redesigned vault and a coordinated app version. **Do NOT** ship the redesigned vault while old apps are in the wild that don't know about `migrate_consent` — the old apps will continue to use `credential.migration.start` which still exists for backward compatibility (deprecated but functional). Plan deprecation: keep the old endpoint working for at least 30 days post-app-release, then remove.

---

## Open questions (resolved 2026-05-11)

1. **NATS routing race window during a fresh deploy. [RESOLVED]** Resolution: implement explicit Phase 4.6 force-reclaim in `deploy.sh`. After Phase 4.5 confirms NEW is healthy, `deploy.sh` calls `/internal/reclaim-from-pcr0?pcr0=<OLD>` on NEW. NEW walks the routing KV and force-claims every entry whose PCR0 matches OLD's. This bypasses the "wait for OLD's M1 handoff" dependency entirely — important because OLD's vault-manager may have bugs that prevent it from emitting the handoff (2026-05-11 incidents). KMS AnyOf during the migration window means NEW can decrypt user material; routing is just a NATS subscription target. See `enclave/parent/routing.go: ReclaimUsersFromPCR0` and `enclave/scripts/deploy.sh: Phase 4.6`.

2. **Android app retry semantics on `migration_status: pending_new_enclave`. [RESOLVED]** Resolution: 3 retries × 1.5s = up to 4.5s of automatic retry in `PinUnlockViewModel`. Confirmed acceptable UX in practice — users don't perceive the delay. The `_pendingMigrationApproval` flag stays armed across retries; consumed only on `"completed"` (see `vettid-android 129f101`).

3. **Quiescence on auto-finalize. [RESOLVED]** 60s is in production (`migrationFinalize.ts`). Lambda timeout bumped 2 → 3 min to cover the new sleep. Order is now scale-down → 60s quiescence → KMS tighten → config delete, which lets in-flight unlocks complete on OLD before OLD becomes KMS-denied.

4. **`MaxSize=2` cap during migration. [DEFERRED]** No load issues observed in 2-user testing. Revisit when fleet > 100 users. Recommendation when needed: bump MaxSize to 3 during the migration window, keep MinSize=2.

5. **PCR1 / PCR2 changes without PCR0 change. [RESOLVED — PCR0 is sufficient]**
   - Our EIF build process bundles kernel (PCR1) and init (PCR2) into the same Docker image hash that becomes PCR0. Any change to either also changes PCR0 by construction.
   - The only realistic way PCR1/PCR2 could change WITHOUT PCR0 changing would be a runtime kernel hot-patch (e.g., kpatch/livepatch), which our enclave doesn't support.
   - KMS policy keys off PCR0 only. This is sufficient: an attacker who could alter PCR1/PCR2 without altering PCR0 would already have arbitrary code execution inside the enclave, well past the trust boundary we're defending.
   - Decision: **PCR0 stays as the sole migration trigger.** Document this assumption breaks if we ever add kernel hot-patching to the enclave runtime.

6. **Emergency recovery (`HandleEmergencyRecovery`). [DECIDED — REMOVE]**
   - The handler is a stub with no real behavior. Keeping it around suggests a recovery path exists; in practice there is none.
   - Real recovery today is: `scripts/decommission-vault.sh <user_guid>` + re-enroll. User loses any data not backed up out-of-band.
   - Designing a proper recovery escape hatch would require: stamping a recovery secret at enrollment, accepting it as an alternative to PIN, deriving a fresh DEK, letting the user reset their PIN. That's a feature, not a bug fix — call it out as a separate plan when prioritized.
   - **Action:** remove the stub handler. The migration redesign doesn't depend on it.

7. **PCR signing key compromise. [RESOLVED — accept]** Confirmed acceptable: compromising the IAM principal that can `kms:Sign` against `alias/vettid-pcr-signing` is roughly equivalent to compromising the deployer (same blast radius). Dual-signature would harden against a partial breach, but the cost/complexity isn't justified for the current threat model. Flag if compliance ever requires it.

---

### Critical Files for Implementation

- /home/al/VettID/vettid-dev/enclave/vault-manager/pin_handler.go
- /home/al/VettID/vettid-dev/enclave/vault-manager/migration_handler.go
- /home/al/VettID/vettid-dev/enclave/vault-manager/messages.go
- /home/al/VettID/vettid-android/app/src/main/java/com/vettid/app/features/unlock/PinUnlockViewModel.kt
- /home/al/VettID/vettid-dev/cdk/lambda/handlers/scheduled/migrationFinalize.ts
