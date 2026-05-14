# Tier-2 Docker Pair Migration Tests

## Purpose

End-to-end tests for the enclave migration redesign without requiring
real Nitro hardware or live AWS. Catches the class of bug we hit
repeatedly in real deploys this week (canonicalization mismatch,
missing IAM grants, broken handoffs) at CI-time instead of
production-time.

The Tier-1 unit tests in `enclave/vault-manager/migration_handler_test.go`
cover input validation + idempotency without KMS. This directory's
job is the **happy path through KMS Seal/Unseal/Sign** which Tier-1
intentionally can't exercise.

## What's missing today

This README + the empty scaffolding files in this directory are the
**design checkpoint** at the end of the 2026-05-11 migration-redesign
push. The actual harness wasn't built because:

1. The supervisor has a TCP-instead-of-vsock dev mode (`supervisor.Config.DevMode`)
   but **no KMS bypass**. Real KMS requires `kms:RecipientAttestation:PCR0`
   in the resource policy, and only Nitro instances can produce
   attestation documents. LocalStack KMS doesn't enforce attestation
   conditions, but the parent's KMS client still calls
   `kms.Sign`/`Encrypt`/`Decrypt` with attestation parameters that
   LocalStack ignores rather than fakes — so the call succeeds but
   the resulting ciphertext isn't actually PCR-bound. That's fine
   for testing logic, dangerous if we ever forget to flip the test
   flag in production.

2. A "fake PCR0 from env var" hook needs to land in the supervisor
   so each container can attest to a different PCR0 (the architect
   spec's "two parents with different fake PCR0s baked in"). That's
   a 30-line change in `supervisor/sealer_handler.go` gated on
   `DevMode`, but it materially changes the trust model — needs
   careful review before merging.

3. The test driver needs to publish NATS messages as if it were the
   Android app. A small Go program in `tests/migration/driver/` would
   do this. The shape: enroll → publish migration config → pin-unlock
   → assert marker / re-seal state.

## Required harness components

```
tests/migration/
├── README.md                      # this file
├── docker-compose.yml             # LocalStack + NATS + 2 parent containers
├── Dockerfile.parent-dev          # dev-mode parent image (KMS bypass + fake PCR0 env)
├── driver/                        # Go test driver
│   ├── main.go                    # publishes pin-unlock, observes state
│   ├── scenarios.go               # one func per test scenario
│   └── go.mod
├── fixtures/
│   ├── localstack-init.sh         # creates the KMS keys, S3 bucket, SSM params
│   └── parent.yaml.tmpl           # parent config template
└── run.sh                         # entry point: docker compose up + driver
```

## Required dev-mode hooks

Before this can be built, these production-code changes need to land:

1. **`enclave/supervisor/config.go`**
   - Add `FakePCR0 string` field (gated on `DevMode`).
   - Load from `FAKE_PCR0_HEX` env var if `DevMode == true`.
   - Use it whenever real code asks for the running PCR0.

2. **`enclave/supervisor/sealer_handler.go`**
   - In `DevMode`, route KMS calls to a local in-process "fake KMS"
     that supports:
     - Encrypt/Decrypt with no attestation enforcement
     - Sign with ECDSA P-256 (real crypto, fake key)
     - Verify with the same key
     - Stable key IDs so multiple parents share the same "KMS".

3. **`enclave/parent/parent.go`**
   - Skip the vsock attestation handshake when `DevMode`. Already
     half-done in `parent/vsock_client.go: NewVsockClient` for TCP
     mode; extend for the no-attestation case.

## Scenarios to implement

From `docs/MIGRATION-TARGET-ARCHITECTURE.md` §7:

1. **happy-path** — both containers up, OLD on PCR0=AAA, NEW on PCR0=BBB.
   Enroll a user against OLD; write a `_migration/config.json` for NEW;
   send `pin-unlock { migrate_consent: true }`; verify it lands on OLD
   via routing, gets the M1 handoff, retries, lands on NEW, re-seal
   completes, marker written. Assert: marker file exists, signed by
   the fake-KMS PCR-signing key.

2. **concurrent-load** — same setup; while `pin-unlock` is in flight,
   run 5 concurrent requests for unrelated ops on the same user
   (event.list, profile.get, message.send). Assert: none of them
   write `vault_state.enc` while re-seal is in progress; no
   `vault_state.enc` shrinkage.

3. **kill-during-reseal** — start re-seal; `docker kill` the NEW
   container after KMS Encrypt but before S3 write. Restart container.
   Send another `pin-unlock`. Assert: `sealed_material.bin` is still
   OLD-bound, re-seal retries cleanly.

4. **kill-after-reseal-before-marker** — kill after S3 write but
   before marker. Restart. Assert: cold-load reads NEW-bound
   `sealed_material.bin`, recognizes `sealed_to_pcr0 == NEW`, writes
   the missing marker via F5 self-heal.

5. **routing-lease-expiry** — kill OLD mid-session before it can hand
   off. Wait 60s. NEW reclaims via lease expiry. App retry succeeds.
   No data loss.

6. **persistFn-regression** — run the legacy `migration.start` path
   (kept for the rollout window). Assert via container-local S3 inspection
   that no new version was created for `vault_state.enc` during the
   migration. **This is the test that would have caught the 2026-05-08
   and 2026-05-09 data-loss incidents.**

7. **canonicalization-regression** *(added 2026-05-11)* — publish a
   migration config; assert that the signer's `jq -cS` output and the
   verifier's `signedPayload` produce byte-identical SHA-256. Catches
   the canonical-form drift that broke today's v1 deploy. (Already
   partly covered by Tier-1 `pcr_config_signing_test.go`; Tier-2
   exercises the full sign→S3→fetch→verify cycle.)

8. **split-brain-eviction** *(added 2026-05-14)* — the test that would
   have caught the 2026-05-13 audit-chain corruption. Enroll a user on
   OLD and keep a warm subprocess there. Bring up NEW and run
   `ReclaimUsersFromPCR0(OLD_PCR0)` so NEW force-claims the routing
   entry. Assert: (a) the parent on OLD sends `evict_vault` and the
   supervisor kills OLD's vault-manager subprocess; (b) OLD writes
   **zero** new `vault_state.enc` versions after the reclaim — even if
   a request was in flight on OLD at reclaim time, the `revoke_ownership`
   message fences `flushVaultStateToS3` and `HandleMessage`; (c) the
   surviving `vault_state.enc` is the generation NEW cold-loaded, with
   the UTK pool and `credential/sealed_blob` intact. Tier-1 already
   pins the unit-level pieces (`parent/routing_release_test.go`,
   `vault-manager/ownership_revoked_test.go`); this scenario exercises
   the full parent→supervisor→subprocess eviction path end-to-end.
   The known sub-millisecond residual race on a single final in-flight
   flush is intentionally left for D3 (generation-stamp + S3 CAS) — a
   tracked fast-follow.

## How to run (once built)

```bash
cd enclave/tests/migration
./run.sh                      # full sweep
./run.sh happy-path           # single scenario
./run.sh --keep                # leave containers up for debugging
```

## CI integration

Once the harness is stable, wire into `enclave/scripts/deploy.sh`
Phase 1.5 alongside `go test`:

```bash
log_step "Phase 1.5: Running tier-1 + tier-2 tests"
(cd "$enclave_dir" && go test ./vault-manager/ ./supervisor/ ./parent/ -count=1)
(cd "$enclave_dir/tests/migration" && ./run.sh --short)
```

`--short` runs only the happy-path + canonicalization scenarios in
under 60 s; the kill-during scenarios are reserved for nightly runs.

## Related

- `docs/MIGRATION-TARGET-ARCHITECTURE.md` §7 — full test plan
- `docs/runbooks/migration-recovery.md` — operator recovery procedures
- `enclave/vault-manager/migration_handler_test.go` — Tier-1 tests
- `enclave/vault-manager/peer_wire_contract_test.go` — peer-broadcast tests
- `enclave/vault-manager/shrink_guard_test.go` — shrink-guard policy test
