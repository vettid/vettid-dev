# VettID Technical Preview Triage

Source: all open items captured across `MEMORY.md`, task list (#112-#237 pending),
medium/low-findings files, resume notes, ui-refinements-pending, ux-perf-improvements,
calling-progress follow-ups, photo-upload-debug, desktop-connection-design,
checkpoints, and org-vault plan.

Four buckets being filled in as we triage:
- **PREVIEW-NOW** — must do, do soon
- **PREVIEW-HOLD** — must do before tech-preview launch, hold for now (often: kept around because still useful for debug, e.g. while agent/desktop work continues)
- **NEXT-PHASE** — defer past the preview
- **CLOSED** — not doing; removed from the backlog

---

## Triage decisions

### PREVIEW-NOW
- **#9** — finish stripping User GUID logging in `CredentialStore.kt`
- **#10** — verify audit-log stale entries don't reappear after fresh re-enrollment
- **#11** — `#236` parent loads PCR0 from local enclave, not global SSM
- **#12** — D3 generation-stamp + S3 CAS on `vault_state.enc`
- **#13** — `deploy.sh` preserve historical PCR0s in KMS AnyOf
- **#14** — `#234` Android retry PCR manifest fetch on attestation rejection
- **#17** — `#237` verify v7→v8 routing reclaim and close
- **#18** — `deploy.sh` Phase 4.6 benign `curl: (7)` cleanup
- **#19** — `#112` Tier-2 Docker harness (3 dev-mode hooks + 6 scenarios, ~4–5 days)
- **#21** — `M1` SQL column injection in `importData()`
- **#22** — `M2` NATS subject injection — parent publishes to any subject enclave requests
- **#23** — `M3` unauthenticated internal API endpoints (`/vault/internal/ready`, `/health`)
- **#24** — `M4` test endpoints always deployed (not gated on `TEST_API_KEY`)
- **#25** — `M5` dev mode bypass for control command signing
- **#26** — `M6` `DEVICE_ATTESTATION_SECRET` falls back to empty string
- **#27** — `M7` request signing validation silently passes when not configured
- **#28** — `M8` nonce checking fails open on DynamoDB errors
- **#29** — `M9` rate limiting fails open on DynamoDB errors
- **#30** — `M10` security features disablable via `DISABLE_*` env vars
- **#31** — `M11` `pendingApprovals` map unbounded with no auto-cleanup
- **#32** — `M12` no rate limiting enforcement in agent handler
- **#33** — `M13` replay cache fails open under pressure
- **#34** — `M14` `findPendingAgentInvitationForECIES` brute-forces all invitations
- **#35** — `M15` connection private keys stored via `json.Marshal` (GC copies)
- **#36** — `M16` S3 buckets using SSE-S3 instead of SSE-KMS CMK
- **#37** — `M17` DynamoDB `removalPolicy: DESTROY` on all tables
- **#38** — `M18` WAF cannot protect HTTP API v2 directly
- **#41** — `M21` enclave instance role uses broad AWS managed policies
- **#42** — `M22` enclave ASG `minInstancesInService: 0`
- **#44** — `M25` NLB security group allows `anyIpv4` on port 4222
- **#45** — `M26` recovery phrase not cleared from memory
- **#46** — `M27` location data in unencrypted `SharedPreferences`
- **#47** — `M28` LAT comparison not constant-time in `CredentialStore.kt`
- **#48** — `M30` `ApiSecurity` interceptors defined but never applied
- **#49** — `M31` app tamper check doesn't verify known signature hash
- **#50** — `M32` password held as `String`, not securely clearable
- **#51** — `M33` PIN stored as `String`, not securely clearable
- **#52** — `M37` `security-crypto` alpha version dependency
- **#53** — `M54` all-zeros PCR fallback in Android `PcrConfigManager.kt`
- **#54** — `M38` no X25519 low-order public key validation (agent)
- **#55** — `M39` Argon2 parameters controllable from stored file (agent)
- **#56** — `M40` no inbound sequence number validation (agent)
- **#57** — `M41` no inbound timestamp validation (agent)
- **#58** — `M42` shortlink resolution allows HTTP downgrade (agent)
- **#59** — `M43` unbounded HTTP response body read (agent)
- **#60** — `M44` no passphrase strength validation (agent)
- **#61** — `M45` WebSocket token in URL query string (agent)
- **#62** — `M46` no request body size limits on REST API (agent)
- **#63** — `M47` REST API has no authentication for TCP mode (agent)
- **#64** — `M48` mTLS config fields exist but not implemented (agent)
- **#65** — `M49` machine fingerprint spoofable by root (agent)
- **#66** — `M50` Dockerfile runs as root (agent)
- **#67** — `M51` secret value zeroing unreliable in agent string types
- **#68** — `M24/M52` personal email in script docs (`cdk/scripts/reset-enrollment.ts`)
- **#69** — `M53` Route53 hosted zone ID exposed (`cdk/cdk.context.json`)
- **#70** — `L24` AWS managed policies → least-privilege sweep
- **#71** — `L1` test API key comparison not constant-time
- **#72** — `L2` no AD in ChaCha20-Poly1305 AEAD (`authenticate.go`)
- **#73** — `L3` NATS message channel overflow (silent drop)
- **#74** — `L4` supervisor dev mode S3 bypass
- **#75** — `L5` replay timestamp skip (no-timestamp bypass)
- **#76** — `L6` public NATS account JWT lookup endpoint (enumeration)
- **#77** — `L7` NATS monitoring port 8222 open to entire VPC CIDR
- **#78** — `L8` IAM `PassRole` wildcard `vettid-vault-*`
- **#80** — `L10` `exportData`/`importData` use `fmt.Sprintf` for table names
- **#81** — `L11` control command verification allows unsigned in dev mode
- **#82** — `L12` handshake timestamp allows 60s future clock skew
- **#83** — `L13` ECIES decryption does not validate low-order X25519 points
- **#84** — `L14` `defer rows.Close()` inside loop
- **#85** — `L15` `aggressiveCleanupLocked` O(n*k) under DoS
- **#86** — `L16` NATS role broad EC2/ASG describe permissions
- **#87** — `L17` Cognito PostAuthentication Lambda wildcard userpool ARN
- **#88** — `L18` broad monitoring permissions (AWS API limitation — likely accept-with-note)
- **#89** — `L19` broad log group `DescribeLogGroups` permissions (likely accept-with-note)
- **#90** — `L20` 30-day refresh token validity (tighten admin path)
- **#92** — `L22` security groups allow all outbound (tighten egress)
- **#95** — `L26` HKDF with empty salt in some crypto ops
- **#96** — `L27` new `SecureRandom` instance per nonce generation
- **#97** — `L28` no app-level rate limiting on PIN attempts
- **#98** — `L29` no deep link origin validation
- **#99** — `L30` base64 decode without size limit on deep link data
- **#100** — `L32` background location permission declared unconditionally
- **#101** — `L33` debug override trusts user-installed CA certificates
- **#102** — `L34` BouncyCastle 1.77 — update sweep
- **#103** — `L35` Retrofit 2.9.0 / OkHttp 4.12.0 — CVE check
- **#104** — `L37` `ZeroBytes` not guaranteed by Go compiler (agent)
- **#105** — `L38` HKDF uses domain as salt, not info (agent — likely document-as-design-decision)
- **#106** — `L39` ECIES does not use AAD (agent)
- **#107** — `L40` no integrity check on `EncryptedStore` envelope (agent)
- **#108** — `L41` `json.Unmarshal` copies sensitive data into GC heap (agent)
- **#109** — `L42` `http.DefaultClient` no timeout in shortlink (mooted if shortlink removed)
- **#110** — `L43` no rate limiting on local API endpoints (agent)
- **#111** — `L44` config file permissions not validated (agent)
- **#112** — `L45` 4-of-5 fingerprint tolerance reduces binding strength (agent)
- **#113** — `L46` goroutine leak in WebSocket handler on disconnect (agent)
- **#114** — `L47` unchecked error on `json.Encode` write (agent)
- **#115** — `L48` external commands use relative PATH (fingerprint) (agent)
- **#116** — `L49` `golang.org/x/crypto v0.31.0` — `govulncheck` (agent)
- **#117** — `L52` internal NATS URLs exposed in config files/docs
- **#118** — `L54 (new)` dependency hygiene sweep — backend, android, agent
- **#123** — `#188` create in-app feed card for shared-data events
- **#124** — `#189` connection-card last-history-entry preview
- **#125** — `#198` Android B6: verify chain + render verified state on Connection History
- **#126** — self-preview Data/Secrets/Handlers row → shared `PublishedProfileBadges`
- **#128** — "Connect Desktop" feed-FAB placeholder → real flow (depends on desktop work)
- **#129** — "New Request" feed-FAB stub → wired through
- **#130** — connection-flow events vs unified card — verify no regression after feed unification
- **#136** — test hardening: `DisallowUnknownFields` in tests so schema drift fails CI
- **#139** — minor lint sweep before external eyes (~½ day)
- **#141** — UX-1 speculative pre-fetch on connection-card tap (~½ day)
- **#142** — UX-2 pre-warm common data after PIN unlock (~1 day)
- **#143** — UX-3 optimistic rendering from existing `FeedRepository` cache (~1 day)
- **#144** — UX-4 encrypted persistent message cache (~2-3 days, needs architect review for wipe lifecycle)
- **#145** — UX-5 combine round-trips at the vault layer (~1-2 days per screen)

### PREVIEW-HOLD
- **#1** — re-enable `FLAG_SECURE` (kept off while agent + desktop testing runs)
- **#2** — strip enclave DIAG logs (`08a7d08`, `198e359`)
- **#3** — remove `VaultUpdateViewModel.checkForUpdate` debug log
- **#4** — remove vsock hex-dump diag in parent + supervisor
- **#5** — strip NATS endpoint + ownerSpace logging (`CredentialStore.kt`)
- **#6** — strip plaintext session-ID log (`SessionCrypto.kt`)
- **#7** — `M29` full HTTP body logging in debug builds (`NetworkConfig.kt`)
- **#8** — `M36` credential diagnostics at startup (`PinUnlockViewModel.kt`)

### CLOSED
- **#121** — `#186` highlight Verify row when notif → ConnectionDetail opens *(not pursuing)*
- **#122** — `#187` clear bolded connection-card unread state after grant approval *(not pursuing)*
- **#127** — scanner connection preview match inviter's review card style *(not pursuing)*
- **#131** — secrets metadata display *(not pursuing)*
- **#133** — backup status display *(verified done — close)*
- **#134** — photo upload vsock EOF *(verified done — close)*
- **#135** — audit-log stale unverified entries *(verified done — close)*
- **#137** — slow connection loading wheel *(close — no repro; reopen if it recurs)*
- **#138** — drop second TURN server *(rejected — keep `turn-b.vettid.dev`. CDK comment in `turn-stack.ts:147` documents the two-server design as a workaround for the libwebrtc same-server `CREATE_PERMISSION` bug that affects symmetric-NAT pairs. Cost $8/mo. Revisit only if there's strong evidence the bug doesn't affect us in practice.)*
- **#140** — public NATS JWT lookup scoping *(duplicate of #76 / L6)*

### NEXT-PHASE
- **#238** — **Decommission should release the parent's routing claim.** Discovered while verifying #17 (2026-05-16): both decommissioned users (`eb8472f6…`, `af44310d…`) still had live routing entries in the `vault-routing` KV — `instance_id` and `pcr0` both pointing at the live v8 enclave and `lease_until` still advancing every ~15s. The vault data was wiped (S3 + DynamoDB cleared via decommission Lambda) but the parent's RoutingManager has no signal to release the in-memory claim, so it keeps heartbeating "I own user X" for a user whose vault no longer exists. Self-heals on parent restart (entries expire after 45s without heartbeat) but until then re-enrollment with the same user_guid lands in a fragile state. Fix: wire a release path from the decommission flow back to RoutingManager.Release(userGuid).
- **#15** — `#161` multi-party approval gate for KMS policy changes
- **#16** — `#178` drop identity-key TTL cache for action invocations + contract signing
- **#20** — `#113` Tier-1 SealerProxy handler tests
- **#39** — `M19` member Cognito user pool has no MFA
- **#40** — `M20` SNS security alert topic has no subscribers
- **#43** — `M23` SES permissions use `resources: ['*']` *(prior fix attempts broke things; revisit later)*
- **#91** — `L21` no Cognito advanced security mode (Plus tier cost trade-off)
- **#93** — `L23` no secret rotation configured for Secrets Manager
- **#94** — `L25` most Lambdas not in VPC (accept-with-note)
- **#132** — session TTL needs fixing — reproduce on current build first
- **#146** — vettid-agent Phase 1 steps 8+
- **#147** — desktop client — 8-phase plan per `vettid-desktop/DEVELOPMENT-PLAN.md`
- **#148** — desktop pairing flow per `desktop-connection-design.md` (remove stale HTTP shortlink code; implement NATS-only two-stage pairing)
- **#149** — org vault + healthcare demo (plan `peppy-frolicking-corbato.md`)
- **#150** — service vault (design phase only)
- **#79** — `L9` internal NLB uses plain TCP (no TLS) — VPC peering only.
  *Rationale for deferring:* the realistic threat (intra-VPC packet capture) is already mitigated by (1) private VPC + tight security groups, (2) NATS JWT + NKEY challenge-response auth at the application layer, (3) end-to-end encryption of peer broadcasts (#160) so payloads are unintelligible even with raw wire access, and (4) signed audit chain that records anything that does land. No untrusted workloads share this VPC. When revisited: TLS **pass-through** at NLB (not termination), NATS instance certs from AWS Private CA with 90-day auto-rotate, parent pins the CA root not the leaf, CloudWatch alarm on `<14d` expiry, feature-flag rollout (NATS accepts both TLS and plain during bake, parent prefers TLS with fallback, then NATS flips TLS-only). Prior breakage was cert/SAN mismatches and silent rotation failures — pin the CA root and the rotation problem goes away.

---

## Group 1 — Release blockers (low-effort, high-impact hygiene)

1. **Re-enable `FLAG_SECURE`** in `MainActivity.kt:54` (currently disabled for demo screen recording). Prevents screenshots/recording of vault content.
2. **Strip DIAG logs** in v8 enclave — `08a7d08` (`verifyPasswordAgainstCredential`, `HandleApproveVerify`), `198e359` (audit.query response). Diagnostic spew left in production.
3. **Remove diagnostic log** in `VaultUpdateViewModel.checkForUpdate` (from migration silent-path debugging).
4. **Remove diagnostic logging in vsock** — `parent/vsock_client.go` writeMessage hex dump + `supervisor/vsock.go` readMessage hex dump (photo-upload 32KB-boundary debug residue).
5. **L36 fix**: NATS endpoint and ownerSpace logged in `CredentialStore.kt` — strip.
6. **L31 fix**: Session ID logged in plaintext in `SessionCrypto.kt`.
7. **M29 fix**: Full HTTP body logging in debug builds (`NetworkConfig.kt`).
8. **M36 fix**: Credential diagnostics logged at startup (`PinUnlockViewModel.kt`).
9. **M35 fix**: User GUID logged in multiple locations (`CredentialStore.kt`, partially fixed — finish it).
10. **Audit log housekeeping** — clear pre-audit-chain stale unverified entries from any test vault before any external eyes (handled automatically by fresh decommission).

---

## Group 2 — Core primitives: enclave + migration architecture

11. **#236 — Parent loads PCR0 from local enclave, not global SSM**. Caused the v6 crash-loop during v8 deploy. Architectural bug; release-blocker for self-serve migration.
12. **D3 — generation-stamp + S3 CAS on `vault_state.enc`**. Closes the last sub-ms split-brain race after D1+D2. Acceptance gate: Tier-2 scenario #8.
13. **deploy.sh — preserve historical PCR0s in KMS AnyOf** so future migrations can decrypt material sealed against any prior enclave that has any un-migrated vault.
14. **#234 — Android retry PCR manifest fetch on attestation rejection**. Today a transient fetch failure can permanently sour an enclave the user could otherwise trust.
15. **#161 — Multi-party approval gate for KMS policy changes (attestation guard)**. Today a single AWS principal can rotate KMS AnyOf and break attestation; multi-party gate is the operational defense.
16. **#178 — Drop identity-key TTL cache for action invocations + contract signing**. TTL cache lets stale identity keys sign for the cache window; bound it tighter or remove.
17. **#237 — v7→v8 routing reclaim from dead v6** (mostly self-resolved by lease expiry; verify clean state and close).
18. **deploy.sh Phase 4.6 — benign `curl: (7) connection refused`** in warm-up window at 0 users. Either suppress or wait properly.
19. **Tier-2 Docker harness blocked** on supervisor dev-mode fake-KMS hooks (#112). Without it, migration regressions only surface in production.
20. **#113 — Tier-1 SealerProxy handler tests** (deferred since handler tests need the SealerProxy interface).

---

## Group 3 — Backend / enclave security: medium findings (1/2)

21. **M1** SQL column injection in `importData()` — `vault-manager/storage/sqlite.go`.
22. **M2** NATS subject injection — parent publishes to any subject the enclave requests — `parent/parent.go`.
23. **M3** Unauthenticated internal API endpoints (`/vault/internal/ready`, `/health`) — `cdk/lib/vault-stack.ts`.
24. **M4** Test endpoints always deployed (not conditional on `TEST_API_KEY`) — `cdk/lib/vault-stack.ts`.
25. **M5** Dev mode bypass for control command signing — `parent/control_verification.go`.
26. **M6** `DEVICE_ATTESTATION_SECRET` falls back to empty string — `cdk/lib/vault-stack.ts`.
27. **M7** Request signing validation silently passes when not configured — `lambda/common/security.ts`.
28. **M8** Nonce checking fails open on DynamoDB errors — `lambda/common/security.ts`.
29. **M9** Rate limiting fails open on DynamoDB errors — `lambda/common/rateLimit.ts`.
30. **M10** Security features disablable via `DISABLE_*` env vars — `lambda/common/securityConfig.ts`.

---

## Group 4 — Backend / enclave security: medium findings (2/2)

31. **M11** `pendingApprovals` map unbounded with no auto-cleanup — `vault-manager/agent_handler.go`.
32. **M12** No rate limiting enforcement in agent handler — `vault-manager/agent_handler.go`.
33. **M13** Replay cache fails open under pressure — `parent/message_replay.go`.
34. **M14** `findPendingAgentInvitationForECIES` brute-forces all invitations — `vault-manager/connections.go`.
35. **M15** Connection private keys stored via `json.Marshal` (GC copies) — `vault-manager/connections.go`.
36. **M16** S3 buckets using SSE-S3 instead of SSE-KMS CMK (8 buckets).
37. **M17** DynamoDB `removalPolicy: DESTROY` on all tables — `infrastructure-stack.ts`.
38. **M18** WAF cannot protect HTTP API v2 directly — `vettid-stack.ts`.
39. **M19** Member Cognito user pool has no MFA — `infrastructure-stack.ts`.
40. **M20** SNS security alert topic has no subscribers — `vettid-stack.ts`.

---

## Group 5 — AWS infra medium + Android medium security

41. **M21** Enclave instance role uses broad AWS managed policies — `nitro-stack.ts`.
42. **M22** Enclave ASG `minInstancesInService: 0` — `nitro-stack.ts`.
43. **M23** SES permissions use `resources: ['*']` — admin/governance stacks.
44. **M25** NLB security group allows anyIpv4 on port 4222 — `nats-stack.ts`.
45. **M26** Recovery phrase not cleared from memory — Crypto operations.
46. **M27** Location data in unencrypted `SharedPreferences` — `AppPreferencesStore.kt`.
47. **M28** LAT comparison not constant-time in `CredentialStore.kt`.
48. **M30** `ApiSecurity` interceptors defined but never applied — `ApiSecurity.kt`.
49. **M31** App tamper check doesn't verify known signature hash — `RuntimeProtection.kt`.
50. **M32** Password held as `String`, not securely clearable — `AuthenticationViewModel.kt`.

---

## Group 6 — Android medium + Agent medium security

51. **M33** PIN stored as `String`, not securely clearable — `PinUnlockViewModel.kt`.
52. **M37** `security-crypto` alpha version dependency — `build.gradle.kts`.
53. **M54** All-zeros PCR fallback in Android — `PcrConfigManager.kt`.
54. **M38** No X25519 low-order public key validation — `internal/crypto/keys.go` (agent).
55. **M39** Argon2 parameters controllable from stored file — `internal/credential/store.go` (agent).
56. **M40** No inbound sequence number validation — `cmd/vettid-agent/main.go`.
57. **M41** No inbound timestamp validation — `cmd/vettid-agent/main.go`.
58. **M42** Shortlink resolution allows HTTP downgrade — `internal/registration/shortlink.go` (agent).
59. **M43** Unbounded HTTP response body read — `internal/registration/shortlink.go` (agent).
60. **M44** No passphrase strength validation — `internal/registration/flow.go` (agent).

---

## Group 7 — Agent medium + PII findings

61. **M45** WebSocket token in URL query string — `internal/api/websocket.go` (agent).
62. **M46** No request body size limits on REST API — `internal/api/handlers.go` (agent).
63. **M47** REST API has no authentication for TCP mode — `internal/api/server.go` (agent).
64. **M48** mTLS config fields exist but not implemented — `internal/config/config.go` (agent).
65. **M49** Machine fingerprint spoofable by root — `internal/fingerprint/` (agent).
66. **M50** Dockerfile runs as root — agent `Dockerfile`.
67. **M51** Secret value zeroing unreliable (string type) — `internal/api/handlers.go` (agent).
68. **M24/M52** Personal email in script docs — `cdk/scripts/reset-enrollment.ts`.
69. **M53** Route53 hosted zone ID exposed — `cdk/cdk.context.json`.
70. **L24** AWS managed policies still in places where least-privilege replacements would tighten without breaking — sweep pass.

---

## Group 8 — Low findings: backend + CDK

71. **L1** Test API key comparison not constant-time (`===`) — test endpoints.
72. **L2** No associated data (AD) in ChaCha20-Poly1305 AEAD — `authenticate.go`.
73. **L3** NATS message channel overflow (100-msg buffer, silent drop) — `parent/nats_client.go`.
74. **L4** Supervisor dev mode S3 bypass (pretend PUT works) — `supervisor/sealer_handler.go`.
75. **L5** Replay timestamp skip — messages without timestamp bypass check — `parent/message_replay.go`.
76. **L6** Public NATS account JWT lookup endpoint (enumeration risk) — `vault-stack.ts`.
77. **L7** NATS monitoring port 8222 open to entire VPC CIDR — `nats-stack.ts`.
78. **L8** IAM PassRole uses wildcard pattern `vettid-vault-*` — `vault-stack.ts`.
79. **L9** Internal NLB uses plain TCP (no TLS) — VPC peering only — `nats-stack.ts`.
80. **L10** `exportData`/`importData` use `fmt.Sprintf` for table names (hardcoded list) — `vault-manager/storage/sqlite.go`.

---

## Group 9 — Low findings: backend (continued)

81. **L11** Control command verification allows unsigned in dev mode — `parent/control_verification.go`.
82. **L12** Handshake timestamp allows 60-second future clock skew — `parent/vsock_client.go`.
83. **L13** ECIES decryption does not validate low-order X25519 points — `vault-manager/crypto.go`.
84. **L14** `defer rows.Close()` inside loop (all result sets open simultaneously) — `vault-manager/storage/sqlite.go`.
85. **L15** `aggressiveCleanupLocked` has O(n*k) complexity under DoS — `parent/message_replay.go`.
86. **L16** NATS role broad EC2/ASG describe permissions (`resources: ['*']`) — `nats-stack.ts`.
87. **L17** Cognito PostAuthentication Lambda has wildcard userpool ARN — `infrastructure-stack.ts`.
88. **L18** Broad monitoring permissions (read-only, AWS API limitation) — `extensibility-monitoring-stack.ts`.
89. **L19** Broad log group `DescribeLogGroups` permissions — `extensibility-monitoring-stack.ts`.
90. **L20** 30-day refresh token validity (especially for admin) — `infrastructure-stack.ts`.

---

## Group 10 — Low findings: CDK + Android

91. **L21** No Cognito advanced security mode (cost: requires Plus tier) — `infrastructure-stack.ts`.
92. **L22** Security groups allow all outbound (`allowAllOutbound: true`) — `nitro-stack.ts`, `nats-stack.ts`.
93. **L23** No secret rotation configured for Secrets Manager secrets — Infrastructure stacks.
94. **L25** Most Lambdas not in VPC (acceptable for DDB/S3 access pattern) — accept or note.
95. **L26** HKDF with empty salt in some crypto ops — Android `CryptoManager.kt`.
96. **L27** New `SecureRandom` instance per nonce generation — `CryptoManager.kt`.
97. **L28** No app-level rate limiting on PIN attempts — `PinUnlockViewModel.kt`.
98. **L29** No deep link origin validation (custom scheme `vettid://`) — `MainActivity.kt`.
99. **L30** Base64 decode without size limit on deep link data — `MainActivity.kt`.
100. **L32** Background location permission declared unconditionally — `AndroidManifest.xml`.

---

## Group 11 — Low findings: Android + agent

101. **L33** Debug override trusts user-installed CA certificates — `network_security_config.xml`.
102. **L34** BouncyCastle 1.77 — check for updates — `build.gradle.kts`.
103. **L35** Retrofit 2.9.0 / OkHttp 4.12.0 — check for CVEs — `build.gradle.kts`.
104. **L37** `ZeroBytes` not guaranteed by Go compiler (dead-store elimination) — agent.
105. **L38** HKDF uses domain as salt, not info (matches enclave pattern) — design decision, document.
106. **L39** ECIES does not use AAD (`additionalData`) — agent.
107. **L40** No integrity check on `EncryptedStore` envelope (JSON fields) — agent.
108. **L41** `json.Unmarshal` copies sensitive data into GC-managed memory — agent.
109. **L42** `http.DefaultClient` has no timeout in shortlink resolution — agent.
110. **L43** No rate limiting on local API endpoints — agent.

---

## Group 12 — Low findings: agent + ops

111. **L44** Config file permissions not validated — agent.
112. **L45** 4-of-5 fingerprint tolerance reduces binding strength — agent.
113. **L46** Goroutine leak in WebSocket handler on disconnect — agent.
114. **L47** Unchecked error on `json.Encode` write — agent.
115. **L48** External commands use relative PATH (fingerprint collection) — agent.
116. **L49** Dependency `golang.org/x/crypto v0.31.0` — run `govulncheck` — agent.
117. **L52** Internal NATS URLs exposed in config files/docs.
118. **L54 (new)** Dependency hygiene sweep — backend `go.mod`, android `build.gradle.kts`, agent `go.mod` — `govulncheck`/`gradle dependencyUpdates`.
119. **CDK deploy IaC cleanup** — `vettid-migration-finalize-schedule` EventBridge rule provisioned in CDK code but not yet `cdk deploy`'d.
120. **CDK deploy.sh standing issues** — unspecified failure mode; needs user to capture next failure.

---

## Group 13 — App polish + flow correctness

121. **#186** Highlight Verify row when notif → ConnectionDetail opens.
122. **#187** Clear bolded connection-card unread state after grant approval.
123. **#188** Create in-app feed card for shared-data events.
124. **#189** Connection-card last-history-entry preview.
125. **#198** Android B6: verify chain + render verified state on Connection History (per-connection audit chain).
126. **Self-preview Data/Secrets/Handlers row** — migrate to shared `PublishedProfileBadges` composable (dedup duplicate inline Row).
127. **Scanner connection preview** should match inviter's review card style.
128. **"Connect Desktop"** — placeholder in feed FAB → real flow (depends on desktop work).
129. **"New Request" flow** — stub in feed FAB → wired through.
130. **Connection-flow events vs unified card** (from 2026-04-12 note) — verify no regression after the feed unification work.

---

## Group 14 — App fixes from MEMORY.md "Other Pending"

131. **Secrets metadata display** not showing correctly (open since 2026-03-15).
132. **Session TTL** needs fixing (open since 2026-03-15).
133. **Backup status display** not showing correctly (open since 2026-03-15).
134. **Photo upload vsock EOF** — 16KB chunking deployed; verify fully resolved on current enclave or close.
135. **Audit log: stale unverified entries** observed last session — verify they don't reappear on fresh re-enrollment.
136. **Test hardening** — Consider `DisallowUnknownFields` in tests so schema drift fails CI, not just prod logs.
137. **Slow connection / loading wheel (#2 last round)** — not root-caused; likely cold profile-fetch + NATS handshake. Pull logs if it recurs.
138. **Calling: drop one TURN server** — `turn-b.vettid.dev` ~$8/mo redundancy; decide keep/drop.
139. **Decide: minor lint sweep** — clean up unused imports / dead emergency-recovery refs / TODO breadcrumbs across the codebase before external eyes.
140. **Public NATS account JWT lookup endpoint scoping** (L6 dup) — restrict or remove.

---

## Group 15 — UX/perf + feature follow-ups

141. **UX-1** Speculative pre-fetch on connection-card tap (~½ day).
142. **UX-2** Pre-warm common data after PIN unlock (~1 day).
143. **UX-3** Optimistic rendering with existing `FeedRepository` cache (~1 day).
144. **UX-4** Encrypted persistent message cache (~2-3 days, needs architect review for wipe lifecycle).
145. **UX-5** Combine round-trips at the vault layer — `conversation.open` style ops (~1-2 days per screen).
146. **Vettid-agent Phase 1 steps 8+** — Steps 1-7 done; remainder TBD.
147. **Desktop client** — 8-phase plan per `vettid-desktop/DEVELOPMENT-PLAN.md`; core crypto + NATS working, UI mostly TODO.
148. **Desktop pairing flow** — per `desktop-connection-design.md`: two-stage NATS-only, remove stale HTTP shortlink in `vettid-desktop/src-tauri/src/registration/shortlink.rs` + `vettid-agent/internal/registration/shortlink.go` + deprecated `createAgentShortlink.ts` / `resolveAgentShortlink.ts` Lambdas.
149. **Org vault + healthcare demo** — plan `peppy-frolicking-corbato.md`; new vault type + demo at `demo.vettid.dev/healthcare/`.
150. **Service vault** — design phase only; defer.

---

## Notes / known-completed-or-stale to verify (not numbered)

- M34 (deep-link plaintext logging) — marked FIXED in source memo.
- Photo-upload chunking — applied 2026-03-11 per `photo-upload-debug.md`.
- D1/D2 (split-brain dual-writer) — shipped in `33f7a1e`; D3 is the remaining gap.
- DEK divergence on cold-unlock — shipped in `79df610`.
- NATS concurrency garbling (mutex + UUIDs) — shipped during 2026-03-22/23 round.
- `forOwner` ack RequestID — shipped `ba6bd7f` 2026-05-12.
- Diagnostic vsock cleanup (#6 in old memory list) — verified 2026-05-12, item is stale.
- Audit chain (anchor, signing, chain rendering) — A1-A5 + B1-B5 shipped (B6 still open as #125 above).
- Action invocations (grants, verify, voting, BTC, location) — all shipped through current head.

---

**Total live items: 150** spread across 15 groups of 10.
