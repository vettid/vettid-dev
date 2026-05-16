# Tech-Preview Execution Order

> **Current state (2026-05-16):** Phase 0 done (#9 closed; #10 deferred by user pending comprehensive testing). Phase 1 in progress: #11 closed by vettid-dev `326acf0` (parent loads PCR0 from local EIF, SSM transitional fallback).
>
> **What just landed:** v8 enclave with the unified self-heal fix; both phones on APK `d652bef`; both users decommissioned for a clean re-enrollment test pass. User GUID stripped from four info-level logs (closes M35). Parent now reads PCR0 from `nitro-cli describe-eif` against the local EIF, falling back to the existing SSM parameter — fixes the v6→v7 crash-loop root cause from 2026-05-15.
>
> **Where we are in this doc:** Phase 1 in progress. #11 done. Next up in Phase 1: **#13** (`deploy.sh` preserve historical PCR0s in KMS AnyOf — the recovery-day discovery), then **#12** (D3 generation-stamp + S3 CAS on `vault_state.enc`), **#14** (Android retry PCR manifest fetch on attestation rejection), **#17** (verify v7→v8 routing reclaim cleanup), **#18** (deploy.sh Phase 4.6 benign curl cleanup).
>
> **Immediate next steps when resuming:**
> 1. **#13** — `deploy.sh` preserves historical PCR0s in KMS AnyOf so future migrations can decrypt material sealed against any prior enclave that has any un-migrated vault.
> 2. Then **#12** D3, **#14**, **#17**, **#18** in that order — Phase 1 gate is one round-trip migration test (v8 → vN+1 → vN+2) without operator intervention.
>
> Companion doc: `TECH-PREVIEW-TRIAGE.md` holds every triage call with rationale on the deferred items.

---

Sequence for the 114 PREVIEW-NOW items + 8 PREVIEW-HOLD items from
`TECH-PREVIEW-TRIAGE.md`. Ordered so that:

1. The load-bearing architecture lands first (so everything else can deploy reliably).
2. A test harness lands next (so subsequent refactors get regression coverage).
3. After Phase 2, four independent tracks open up — they can be parallelized
   across contributors with minimal coordination.
4. PREVIEW-HOLD items strip just before launch.

Rough scope estimates are calendar-days for one focused contributor;
actual wall-clock with parallel work is much shorter.

---

## Phase 0 — Finish current test pass (½ day)

Wraps up the v8-unified-self-heal validation already in flight.

- ~~**#9** — finish stripping User GUID logging (`CredentialStore.kt`)~~ ✅ vettid-android `1af33e5` (extended to `VaultLifecycleClient.kt` + `ProteanCredentialManager.kt` to fully close M35)
- **#10** — verify audit-log stale entries don't reappear after fresh re-enrollment

**Gate to Phase 1**: clean fresh-enrollment test pass with no regressions.

---

## Phase 1 — Migration architecture (~1 week)

These are the items that make future enclave deploys reliable. Until
they land, every other backend change is risky to ship.

- ~~**#11** — `#236` parent loads PCR0 from local enclave, not global SSM ⚡ *the v6 crash-loop root cause*~~ ✅ vettid-dev `326acf0` (EIF primary, SSM transitional fallback)
- **#13** — `deploy.sh` preserve historical PCR0s in KMS AnyOf ⚡ *the recovery-day discovery*
- **#12** — D3 generation-stamp + S3 CAS on `vault_state.enc` ⚡ *closes the sub-ms split-brain race*
- **#14** — `#234` Android retry PCR manifest fetch on attestation rejection
- **#17** — `#237` verify v7→v8 routing reclaim cleanup (likely just verify + close)
- **#18** — `deploy.sh` Phase 4.6 benign `curl: (7)` cleanup

**Gate to Phase 2**: one round-trip migration test (v8 → vN+1 → vN+2) succeeds without operator intervention.

---

## Phase 2 — Test harness (~1 week)

So the rest of the work has automated regression coverage.

- **#19** — `#112` Tier-2 Docker pair migration harness ⚡ *would have caught the 2026-05-08 + 2026-05-09 data-loss incidents*
  - 3 dev-mode hooks (`supervisor/config.go`, `supervisor/sealer_handler.go`, `parent/parent.go`) + 6 scenarios
- **#136** — `DisallowUnknownFields` in tests so schema drift fails CI
- **#118** — `L54` dependency hygiene sweep — `govulncheck` (backend + agent), gradle dependency-updates (android)

**Gate to Phase 3+**: Tier-2 scenario #6 (persistFn-regression) passes green.

---

## After Phase 2 — Four parallel tracks open

The next ~25 working days of focused work split into four tracks that
can run independently. Each one has its own internal order.

### Track A — Backend security (Lambda + parent + CDK)

**A1 — Fail-closed perimeter (~2 days)**
- **#27** `M7` request signing fail-open → fail-closed
- **#28** `M8` nonce check fail-open → fail-closed
- **#29** `M9` rate limiting fail-open → fail-closed
- **#30** `M10` `DISABLE_*` env vars → gate by build type or remove
- **#26** `M6` `DEVICE_ATTESTATION_SECRET` empty fallback → fail-closed
- **#25** `M5` dev-mode bypass for control command signing
- **#81** `L11` control command verification allows unsigned in dev mode
- **#74** `L4` supervisor dev-mode S3 bypass

**A2 — Backend injection + memory hygiene (~2 days)**
- **#21** `M1` SQL column injection in `importData()`
- **#80** `L10` `exportData`/`importData` `fmt.Sprintf` table names (companion to #21)
- **#22** `M2` NATS subject injection in parent
- **#84** `L14` `defer rows.Close()` inside loop
- **#34** `M14` brute-force ECIES lookup
- **#35** `M15` connection private keys `json.Marshal` GC copies
- **#83** `L13` ECIES low-order X25519 point validation

**A3 — AEAD / crypto strengthening (~1 day)**
- **#72** `L2` no AD in ChaCha20-Poly1305 AEAD
- **#82** `L12` 60s clock skew → 5-10s
- **#95** `L26` HKDF empty salt → domain-separation
- **#96** `L27` cache `SecureRandom` instance
- **#71** `L1` test API key constant-time comparison

**A4 — Rate limiting / DoS / replay (~2 days)**
- **#31** `M11` `pendingApprovals` unbounded map
- **#32** `M12` no rate limit in agent handler
- **#33** `M13` replay cache fails open under pressure
- **#73** `L3` NATS message channel overflow silent drop
- **#75** `L5` replay timestamp skip (no-timestamp bypass)
- **#85** `L15` `aggressiveCleanupLocked` O(n*k) under DoS

**A5 — Internal API auth + endpoint hygiene (~1 day)**
- **#23** `M3` `/vault/internal/*` auth (`/health` stays public)
- **#24** `M4` test endpoints gated on `TEST_API_KEY` build flag
- **#76** `L6` public NATS account JWT lookup endpoint

**A6 — AWS infra hardening (~3-4 days)**
- **#36** `M16` S3 SSE-S3 → SSE-KMS CMK
- **#37** `M17` DynamoDB `removalPolicy: RETAIN` for production
- **#41** `M21` enclave instance role narrowing
- **#42** `M22` enclave ASG `minInstancesInService` ≥ 1
- **#44** `M25` NLB SG `anyIpv4:4222` → scope tighter
- **#70** `L24` AWS managed policies → least-privilege sweep
- **#77** `L7` NATS monitoring port 8222 → scope to ops subnet
- **#78** `L8` `PassRole` wildcard `vettid-vault-*` → pin ARNs
- **#86** `L16` NATS role broad EC2/ASG describe
- **#87** `L17` Cognito PostAuth Lambda wildcard userpool ARN
- **#88** `L18` broad monitoring permissions (accept-with-note)
- **#89** `L19` broad log group `DescribeLogGroups` (accept-with-note)
- **#90** `L20` 30-day refresh token (tighten admin)
- **#92** `L22` SGs allow all outbound → tighten egress
- **#38** `M18` WAF for HTTP API v2 (CloudFront-front)

**A7 — Operational + PII (~½ day)**
- **#40** `M20` SNS security alert topic wire to email/Slack
- **#117** `L52` internal NATS URLs exposed in config files/docs
- **#68** `M24/M52` personal email in script docs
- **#69** `M53` Route53 hosted zone ID exposed

Track A total: ~12 days

### Track B — Android hardening (~3-4 days)

Independent of Track A work; touches only `vettid-android`.

- **#97** `L28` no app-level PIN rate limiting
- **#45** `M26` recovery phrase memory clear
- **#46** `M27` location data in unencrypted `SharedPreferences` → vault-only
- **#47** `M28` LAT comparison constant-time
- **#48** `M30` `ApiSecurity` interceptors wired into OkHttp chain
- **#49** `M31` app tamper check verify pinned signature hash
- **#50** `M32` password as `char[]` / `SecureString`
- **#51** `M33` PIN as `char[]` / `SecureString`
- **#52** `M37` `security-crypto` alpha dependency decision
- **#53** `M54` all-zeros PCR fallback → fail-closed
- **#98** `L29` deep link origin validation
- **#99** `L30` base64 deep link size limit
- **#100** `L32` background location permission conditional
- **#101** `L33` debug CA trust gated on debug build type only
- **#102** `L34` BouncyCastle update sweep
- **#103** `L35` Retrofit / OkHttp CVE check

Track B total: ~3-4 days

### Track C — Agent hardening (~5-7 days)

Largest single track; mostly mechanical Go fixes. Independent of A & B.

**C1 — Agent fail-closed + auth (~2 days)**
- **#56** `M40` inbound sequence number validation
- **#57** `M41` inbound timestamp validation
- **#60** `M44` passphrase strength validation
- **#61** `M45` WebSocket token in URL → header
- **#62** `M46` request body size limit
- **#63** `M47` REST API auth in TCP mode
- **#64** `M48` mTLS fields → implement or remove
- **#110** `L43` no rate limiting on local API
- **#114** `L47` unchecked `json.Encode` error
- **#109** `L42` `http.DefaultClient` no timeout
- **#111** `L44` config file permissions validation

**C2 — Agent crypto + memory (~2 days)**
- **#54** `M38` X25519 low-order public key validation
- **#55** `M39` Argon2 params from disk → hard-code or sign
- **#67** `M51` secret value zeroing reliability
- **#104** `L37` `ZeroBytes` compiler dead-store elision
- **#106** `L39` ECIES AAD
- **#107** `L40` envelope integrity check
- **#108** `L41` `json.Unmarshal` sensitive data into GC heap
- **#105** `L38` HKDF salt vs info — document as design decision

**C3 — Agent process / container hygiene (~2 days)**
- **#65** `M49` machine fingerprint spoofable by root — document threat decision
- **#66** `M50` Dockerfile `USER nonroot`
- **#58** `M42` shortlink HTTP downgrade (mooted if shortlink resolver removed)
- **#59** `M43` unbounded HTTP response body (companion to #58)
- **#112** `L45` fingerprint tolerance threshold decision
- **#113** `L46` WebSocket handler goroutine leak
- **#115** `L48` external commands relative PATH → absolute / `LookPath`
- **#116** `L49` `govulncheck` on agent deps

Track C total: ~5-7 days

### Track D — Product polish + UX (~6-8 days)

Visibility / UX work. Independent of A/B/C.

**D1 — Product visibility (~3 days)**
- **#123** `#188` in-app feed card for shared-data events
- **#124** `#189` connection-card last-history-entry preview
- **#125** `#198` Android B6 per-connection audit chain verification + render
- **#126** self-preview Data/Secrets/Handlers → `PublishedProfileBadges` (dedup)
- **#128** "Connect Desktop" placeholder → wired (depends on desktop work)
- **#129** "New Request" stub → wired
- **#130** connection-flow events vs unified card — verify no regression
- **#139** minor lint sweep before external eyes

**D2 — UX/perf wins (~5 days)**
- **#141** UX-1 speculative pre-fetch on connection-card tap
- **#142** UX-2 pre-warm common data after PIN unlock
- **#143** UX-3 optimistic rendering from existing `FeedRepository` cache
- **#144** UX-4 encrypted persistent message cache *(needs architect review for wipe lifecycle)*
- **#145** UX-5 combine round-trips at the vault layer

Track D total: ~6-8 days

---

## Phase 3 — Final strip before launch (½ day)

The PREVIEW-HOLD items. Do these last because they're kept around as
debugging aids during agent + desktop testing.

- **#1** re-enable `FLAG_SECURE` in `MainActivity.kt:54`
- **#2** strip enclave DIAG logs (`08a7d08`, `198e359`)
- **#3** remove `VaultUpdateViewModel.checkForUpdate` debug log
- **#4** strip vsock hex-dump in `parent/vsock_client.go` + `supervisor/vsock.go`
- **#5** strip NATS endpoint + ownerSpace logging (`CredentialStore.kt`)
- **#6** strip plaintext session-ID log (`SessionCrypto.kt`)
- **#7** `M29` full HTTP body logging in debug builds (`NetworkConfig.kt`)
- **#8** `M36` credential diagnostics at startup (`PinUnlockViewModel.kt`)

**Gate to tech preview launch**: log-grep for any of the diag patterns
returns zero hits across deployed enclave + APK.

---

## Estimated wall-clock

| Sequence | Best case (parallel tracks) | Solo |
|---|---|---|
| Phase 0 | ½ day | ½ day |
| Phase 1 | 1 week | 1 week |
| Phase 2 | 1 week | 1 week |
| Tracks A+B+C+D in parallel | longest single track (~12d) | sum of tracks (~28d) |
| Phase 3 | ½ day | ½ day |
| **Total** | **~5 weeks** | **~9 weeks** |

The 5-week parallel number assumes 4 contributors. With 2 contributors,
you're closer to ~7 weeks. With just you, ~9-10 weeks.

The biggest single risk in this plan is **Track A's #19 (Tier-2 harness)**
landing in Phase 2 — if it stalls, every subsequent backend change ships
without automated regression coverage. Worth pairing with a second
contributor or scope-cutting to scenarios #1 + #6 only.

---

## Open coordination questions

1. **Track ordering inside A**: A1-A5 can run in parallel within Track A if you have multiple backend contributors. A6 (AWS infra) needs serial CDK work — one contributor at a time.
2. **Track D's #144 (encrypted persistent message cache)**: explicitly flagged as needing architect review for the wipe-lifecycle paths. Don't ship without that review.
3. **Phase 3 timing**: ideally strip the diag logs on the *same* APK + enclave build that ships to preview testers, not piecemeal. One coordinated cleanup PR.
