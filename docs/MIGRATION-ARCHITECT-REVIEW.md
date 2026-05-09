# Migration — Architect Review Brief

## Background

Two data-loss incidents in 24 hours (2026-05-08 and 2026-05-09). Same
root cause both times: a `persistVaultStateToS3` call from an enclave
instance that hadn't fully loaded the user's vault state overwrote a
~220KB `vault_state.enc` in S3 with a ~12KB stub. The migration flow
on a multi-instance ASG with NATS load balancing has fundamental
fragility — patches keep moving the failure mode without eliminating
the class.

We need an architect to validate (or reshape) the proposed target
architecture below and call out anything we're missing.

## Hard constraints

1. **User consent is required for every migration.** A malicious
   operator could otherwise deploy a rogue enclave and silently re-seal
   users' material against PCR0s the user never agreed to. Auto-
   migration is OFF the table.
2. **No plaintext user data leaves the enclave.** Re-sealing happens
   inside the enclave; KMS Encrypt/Decrypt with PCR-attestation
   conditions binds policy enforcement to the enclave's PCR0.
3. **Eventual KMS tightening** — after deadline or all users migrated,
   OLD PCR0 is removed from KMS so a leaked OLD-PCR0 attestation can't
   be replayed.

The prompt timing is flexible — it can move to wherever makes the
flow safest.

## Target architecture (single recommended path)

**Couple migration to PIN unlock itself. Eliminate the separate
`credential.migration.start` request.**

### Detection (app-side)

When the app fetches the signed PCR manifest after a deploy, it sees
that the current PCR0 isn't in the user's trusted set. Instead of
showing a post-unlock card, the app shows ONE screen at the PIN
prompt:

```
  ┌─────────────────────────────────────────┐
  │   VettID has been updated.              │
  │                                         │
  │   [Review details]                      │
  │                                         │
  │   Enter your PIN to approve and unlock: │
  │   _ _ _ _ _ _                           │
  │                                         │
  │   [Approve & Unlock]  [Cancel]          │
  └─────────────────────────────────────────┘
```

Approval and PIN entry are the same gesture. There is no separate
"approve migration" screen, no consent token to track between screens,
no race between PIN success and migration arming.

### Re-seal (vault-side)

The app sends a single request:

```
pin-unlock {
  utk_id: "...",
  encrypted_payload: "...",
  migrate_consent: true   // new field
}
```

`HandlePINUnlock` performs everything atomically:

1. Decrypt PIN (existing).
2. Cold-load sealed material from S3, derive DEK, decrypt
   `vault_state.enc` (existing).
3. Verify PIN auth hash (existing).
4. **If `migrate_consent` is true AND the running enclave's PCR0
   differs from the PCR0 the existing `sealed_material.bin` was bound
   to**:
   - KMS-unseal the existing material (works because OLD PCR0 is still
     in the KMS policy during the window).
   - KMS-encrypt with NEW PCR0 in the attestation condition. This only
     succeeds when running on an enclave attesting to NEW PCR0 —
     **the cryptographic check enforces that re-sealing happens on a
     NEW enclave; a malicious OLD enclave cannot complete it**.
   - Replace `sealed_material.bin` and `sealed_ecies.bin` in S3 (each
     is a single atomic object write, no relation to `vault_state.enc`).
   - Write per-version migration marker
     (`_migration/completed/{version}/{ownerSpace}.json`).
5. Return success.

**The vault never calls `persistVaultStateToS3` during this flow.**
The vault state was just LOADED; nothing was modified. Removing the
gratuitous persist eliminates the single largest failure mode.

### Cancel path

User taps Cancel: the PIN entry screen closes without a vault call.
Their material stays sealed against OLD PCR0. KMS still allows OLD
during the window, so they can keep using the app on the old enclave.

After deadline, KMS tightens to NEW only — users who never approved
must re-enroll. The auto-finalize Lambda handles this transition.

### Auto-finalize (existing, mostly unchanged)

EventBridge cron polls every 5 minutes:
- Counts `_migration/completed/{version}/*` markers vs enrolled
  ownerSpaces.
- If all users migrated OR deadline passed: tighten KMS to single PCR0,
  scale ASG back to 1, delete migration config, clean up markers.

### Storage-layer guards (defense in depth, ship regardless)

Even with the migration redesign, `persistVaultStateToS3` should be
hardened so that no future bug can silently destroy data:

1. **`vaultDataLoaded` flag** (already implemented locally, not yet
   deployed): refuse to write unless this enclave instance has loaded
   the user's vault state via cold-unlock or fresh enrollment.

2. **Shrink guard**: before writing, fetch existing object size via S3
   HeadObject. If existing > 50KB and new < 50% of existing, refuse.

3. **S3 versioning** is already enabled — recovery from any future
   corruption is possible, but only if we notice quickly.

## Operational failure mode added 2026-05-09 afternoon

A third failure surfaced after the brief was first drafted — not a migration-flow bug but a deploy-script footgun that takes down the entire vault:

`deploy.sh` writes the new PCR0 to SSM `/vettid/enclave/pcr/pcr0` (and the JSON `/vettid/enclave/pcr/current`) early in Phase 2, after the EIF build completes but BEFORE any new instance has been launched and verified. The parent process on the EXISTING running instance reads SSM to know what PCR0 to expect during its vsock attestation handshake.

When the deploy is aborted (operator Ctrl-C, build instance killed, instance refresh fails) AFTER the SSM write but BEFORE a new instance with the matching AMI is in service, SSM is now pointing at a PCR0 that nothing in the fleet attests to. The parent process on the still-running OLD instance starts failing every handshake at startup. systemd restarts vettid-parent. It crash-loops every ~5 seconds — silently, with no monitoring alert.

We hit this 2026-05-09: parent crash-looped ~10,000 times over several hours before the operator tried to enroll and noticed everything was broken.

The architect should consider:
- Move the SSM PCR0 write to AFTER a new instance is fully healthy (post-Phase-4, before Phase 5).
- OR change parent to read PCR0 from a per-instance source (`/vettid/enclave/pcr/{instance-id}/pcr0`, or NSM, or instance metadata) instead of a global SSM parameter — the global parameter becomes informational only.
- OR add a CloudWatch alarm on `vettid-parent` restart count exceeding N per hour, paging the operator.

## What this redesign eliminates

| Failure mode | Today | After |
|---|---|---|
| Stale enclave overwrites vault_state via migration `persistFn` | Possible (two incidents) | Impossible — no `persistFn` in migration path |
| Pre-PIN consent armed by wrong-PIN attempt | Patched today | Architecturally impossible — consent and PIN are the same gesture |
| Migration request lands on different enclave than PIN unlock | Possible | Impossible — same single request |
| CPU autoscaling kills migration source | Patched today (MinSize=2) | Less critical — re-seal is local to one PIN unlock, not a multi-step dance |
| Migration completion requires writing 220KB vault_state | Yes | No — only re-seals (separate small files) and marker write |

## What still needs care

1. **Trusted PCR0 set on the app side** — when does it get updated?
   Currently `approveEnclaveUpdate()` adds the new PCR0 to the trusted
   set BEFORE PIN succeeds. Should move to AFTER successful unlock
   (already partly addressed in today's Android fix).

2. **Re-seal idempotency under crash** — if the enclave dies after KMS
   re-seal but before marker write, the user is still on OLD PCR0 in
   their app's view but their material is bound to NEW. Next unlock
   would re-attempt: `sealed_material` already re-sealed (unsealable
   only by NEW), so the KMS unseal step would fail on OLD enclave but
   succeed on NEW. Design needs to handle this gracefully.

3. **Marker write semantics** — currently markers are created by the
   enclave via `WriteMigrationMarker`. They're signed (good). Order of
   operations: re-seal → write marker. If marker write fails after
   re-seal succeeds, user is "migrated but not marked". Auto-finalize
   would think they haven't migrated. Acceptable, just retries on
   next unlock.

4. **Test harness** — multi-instance enclave staging that simulates
   user actions during migration. Today this only gets exercised in
   real production deploys.

## Questions for the architect

1. Does coupling migration to PIN unlock create any new auth/consent
   weaknesses we're not seeing?
2. Is the KMS-encrypt-with-NEW-PCR0 attestation condition genuinely
   sufficient as the "only NEW enclave can complete re-seal" check?
3. Should `migration_state` in the user's vault be eliminated entirely
   (the per-version S3 marker is the source of truth), or is there a
   reason to keep both?
4. What's the right multi-instance test fidelity? Local Docker pair
   with mocked KMS + S3? Or a scratch AWS account with a small ASG?

## Suggested deliverables from the architect

- Validation (or rejection) of the PIN-coupled migration design.
- Specific failure-mode analysis for the cancel path and the
  partial-failure-mid-re-seal cases.
- Storage-layer invariants doc.
- Test plan covering at least: deploy + concurrent user activity,
  cancel-then-retry, partial-failure recovery.

---

*Drafted 2026-05-09. Today's defensive patches (Android pre-PIN
consent timing, vault `vaultDataLoaded` guard, deploy.sh MinSize=2)
are committed locally — not yet pushed pending the architectural
direction. See `feedback-migration-source.md` for the 2026-05-06
incident pattern.*
