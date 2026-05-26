# VettID Pre-Tech-Preview Security Review

**Date:** 2026-05-25
**Scope:** vettid-dev (enclave + CDK + Lambdas + frontend + packer), vettid-desktop, vettid-agent, vettid-android
**Out of scope:** vettid-ios (still in active development)
**Posture:** High-confidence findings only. Each finding cites a specific file:line. Speculative or "could-be-tightened" notes were excluded by design.

---

## Executive Summary

| Repo / Surface              | CRIT | HIGH | MED | LOW |
|-----------------------------|:----:|:----:|:---:|:---:|
| vettid-dev (vault/enclave)  |  1   |  3   |  6  |  5  |
| vettid-dev (CDK/Lambda)     |  0   |  4   |  7  |  6  |
| vettid-desktop              |  0   |  3   |  5  |  6  |
| vettid-agent                |  0   |  2   |  4  |  5  |
| vettid-android              |  0   |  2   |  3  |  5  |
| **TOTAL**                   |**1** |**14**|**25**|**27**|

### Pre-tech-preview blockers (recommended fix-before-ship)

The following items would be the minimum bar to clear before the tech preview goes wide. Everything else can ship with a follow-up tracked.

1. **CRIT — Supervisor sealer-handler does not enforce ownerSpace isolation** (vault). One compromised or buggy vault-manager subprocess can read/overwrite any user's sealed material. The supervisor is supposed to be the per-user isolation seam; today it's self-attested.
2. **HIGH — `HandleAppApprovalResponse` SharedSecret vs. AgentSession bug** (vault). Same family as the 2026-05-25 chat fix; silently breaks every agent secret/action approval round-trip.
3. **HIGH — Bootstrap attestation-binding verification fails open + ships with dev-default secret** (vault). One missing env var = no MITM defence on bootstrap key exchange.
4. **HIGH — GitHub OIDC role accepts any `mesmerverse/*` repo, any ref** (CDK). Any new or forked repo under the org can sign + publish enclave handlers and read the signing key.
5. **HIGH — `api.vettid.dev` HTTP API has no WAF.** All LEASH public endpoints + registration + bootstrap pairing are reachable directly without any rate-based / managed rule set.
6. **HIGH — vsock shared secret persists in Docker layers on the AMI** (packer). Compromise of one enclave-host EC2 yields the parent↔enclave mutual-auth secret.
7. **HIGH — Notification "Approve transfer" action skips biometric** (android). Anyone with momentary physical access can approve full credential migration from the lock-screen shade.
8. **HIGH — Dead `AppLockScreen` accepts any 4-digit PIN and is still in the nav graph** (android). One accidental nav reference = trivially defeated lock.
9. **HIGH — WebSocket auth in agent daemon is permanently broken** (`WSToken` never populated; every upgrade returns 401). Functional-but-fail-closed today, but the same plumbing also gates REST auth — fix coherently before someone wires it backwards.
10. **HIGH — Agent's pairing/extend ECDH skips small-order point check on `vault_pubkey`** (`safeX25519` exists but is only used in the ECIES path).
11. **HIGH — Desktop ships with Tauri `devtools` feature enabled unconditionally** in release. Local-process attacker can open devtools, hook `invoke`, and replay any vault op after auto-unlock.

The remaining HIGH findings (desktop's overly-broad `shell:allow-open` regex, desktop auto-unlock not bound to binary/machine fingerprint, CDK bootstrap-pairing leaking internal error messages, vault `pendingApprovals` map missing mutex + unbounded growth) are also recommended for fix-before-ship but each has either a partial mitigation or narrow exploit path.

---

## Cross-Cutting Themes

A handful of patterns repeated across the five review streams — worth lifting out so they don't recur:

- **"Trusts the subprocess / trusts the wire field"** — supervisor accepts `OwnerSpace` from vault-manager (CRIT-1), vault accepts envelope `Sequence` without inbound validation (vault MED-1), agent accepts `vault_pubkey` without small-order check (agent HIGH). The pattern is "the field is supposed to be trusted because the caller is authenticated" — fix is to validate the field regardless of trust posture.
- **SharedSecret vs. AgentSession key confusion** — the 2026-05-25 fix cluster found this in `HandleAgentMessage` / `HandleAgentMessageReply`; `HandleAppApprovalResponse` still has the bug (vault HIGH-1). Worth a one-time grep for any other handler that calls `deriveConnectionKey(conn.SharedSecret)` without an `IsAgent()` check.
- **Envelope `Sequence` stamping is inconsistent on outbound** — agent path got fixed last week; device path (`publishDeviceResponse`) and the connection-accept path (`HandleAcceptAgentConnection`) still omit it (vault MED-2, MED-4). Won't bite until the matching validator is tightened, but lines up another silent-drop bug.
- **Public-facing surface lacks rate limiting** — LEASH demo mint, demo session, registration, bootstrap pairing all reachable from internet without WAF (CDK HIGH-1) and most without per-IP rate limit (CDK MED-1, MED-2). Combined with wildcard CORS, drive-by abuse is trivially scriptable.
- **Best-effort failure modes log + continue** — bootstrap binding verify (vault HIGH-2), agent session-key delete on extend (vault MED-3), AEAD legacy-AAD fallback (vault LOW-1 + agent LOW). Each is individually small; the family is "warn-and-proceed" eating security defences silently.
- **Local-process attacker not modeled tightly** — desktop's no-passphrase auto-unlock (desktop HIGH-3), Tauri devtools enabled (desktop HIGH-1), agent `/tmp` creds file (agent MED-1), android `PinAttemptTracker` in unencrypted SharedPreferences (android LOW-3). Each individually defensible; together "anyone on this user account can act as you" is closer to true than memory's `desktop-no-passphrase.md` note implies.

---

## vettid-dev: Vault / Enclave / Crypto

### CRITICAL

#### V-CRIT-1. Supervisor sealer-handler does not enforce ownerSpace isolation across pipe IPC

- **Location:** `enclave/supervisor/vault_lifecycle.go:576` (`handlePipeSealer`) → `enclave/supervisor/sealer_handler.go:241` (`HandleSealerRequest`); S3 keys at `sealer_handler.go:488,492,496`.
- **Issue:** Supervisor spawns one `vault-manager` per owner bound to `vp.OwnerSpace`. When that subprocess writes `MessageTypeSealerRequest` down the pipe, `handlePipeSealer` forwards unchanged. `HandleSealerRequest` reads `req.OwnerSpace` from the subprocess-supplied JSON to build S3 keys (`vaults/{ownerSpace}/sealed_material.bin`, `vault_state.enc`, `sealed_ecies.bin`). No check that `req.OwnerSpace == vp.OwnerSpace`.
- **Impact:** A compromised/buggy vault-manager (memory corruption in JSON parse, or any future bug controlling that one field) can read or overwrite **any** user's sealed material, vault state, and ECIES keys. The subprocess boundary is supposed to be the per-user isolation seam.
- **Fix:** In `handlePipeSealer`, reject when `req.OwnerSpace != vp.OwnerSpace`, or strip the wire field and inject `vp.OwnerSpace` server-side.

### HIGH

#### V-HIGH-1. `HandleAppApprovalResponse` still uses `SharedSecret` for agent connections

- **Location:** `enclave/vault-manager/agent_handler.go:1212`.
- **Issue:** Same bug shape as the 2026-05-25 `HandleAgentMessage` / `HandleAgentMessageReply` cluster. Agent connections have no peer `SharedSecret`; session key lives at `agent_session_keys/{conn}/{sessionKeyID}`. This handler calls `deriveConnectionKey(conn.SharedSecret)` unconditionally before `publishAgentResponse`.
- **Impact:** Owner approves/denies an agent secret/action request → vault tries to derive a key from empty `SharedSecret` → `deriveConnectionKey` returns "shared secret must not be empty" → handler logs and returns success to the app → agent never receives the envelope. Owner sees a successful approval; agent hangs.
- **Fix:** Mirror `HandleAgentMessage`/`HandleAgentMessageReply` — when `conn.IsAgent() && conn.AgentSession != nil`, look up `agent_session_keys/{conn}/{conn.AgentSession.SessionKeyID}`.

#### V-HIGH-2. Bootstrap binding verification fails open + dev-default secret in production path

- **Location:** `enclave/vault-manager/bootstrap_handler.go:24-29` and `:95-110`.
- **Issue:** `attestationBindingSecret` defaults to `"default-dev-secret-replace-in-production"` when `ATTESTATION_BINDING_SECRET` is unset. `HandleBootstrap` calls `verifyBindingToken`, but on failure (or absent binding fields) it logs and continues with `bindingVerified=false`.
- **Impact:** Misconfigured production deploy silently downgrades every bootstrap to legacy mode; any client omitting binding fields gets keys with no MITM protection.
- **Fix:** When `VETTID_PRODUCTION=true`, require a non-default secret and fail-closed when verification fails or fields are absent.

#### V-HIGH-3. `pendingApprovals` map has no mutex and an unbounded-growth path

- **Location:** `enclave/vault-manager/agent_handler.go:57,548,642,833,1195,1202,1369`. `CleanExpiredApprovals` defined at `:1367` but never invoked.
- **Issue:** Plain `map[string]*PendingApproval` accessed by three insert paths, two cleanup paths, no mutex (contrast `DeviceHandler.mu`). Today's per-owner dispatch is serial via `procMu`, but the design is fragile. Cleanup goroutine isn't wired — entries leak forever when owner doesn't answer.
- **Impact:** Unbounded memory growth from a paired agent that abandons approvals; map-race risk on any future goroutine touching it.
- **Fix:** Add `sync.Mutex` to `AgentHandler`, wire `CleanExpiredApprovals` into the lifecycle (mirror `DeviceHandler.cleanExpiredSessions`).

### MEDIUM

#### V-MED-1. No inbound replay/sequence validation on agent or device envelopes

- **Location:** `agent_handler.go:265-465`, `device_handler.go:305-386`.
- **Issue:** Vault stamps `Sequence: time.Now().UnixNano()` on outbound but reads inbound `envelope.Sequence` only into a debug log. XChaCha20-Poly1305 keys are stable across the session; an attacker with the agent's scoped NATS creds can replay captured envelopes.
- **Impact:** Replayed `agent_message` re-pops owner phone; replayed `agent_secret_request` re-prompts; replayed `leash_mint_request` re-stages a leash row. Bounded by needing the agent's NATS JWT (already game-over) but defence is one-sided.
- **Fix:** Per-connection `lastSeqSeen` persisted with session record + strictly-increasing check, or apply the parent's `MessageReplayCache` at the vault layer too.

#### V-MED-2. `HandleAcceptAgentConnection` outbound envelope omits `Sequence`

- **Location:** `enclave/vault-manager/connections.go:3973-3978`.
- **Issue:** First envelope an agent receives on `forOwner.agent.invitation.{inv}` is published without `Sequence`. If agent's `EnvelopeValidator` is engaged at that point, it's silently dropped (matches the `Sequence: 0` bug shape from 2026-05-25).
- **Fix:** Add `Sequence: uint64(time.Now().UnixNano())` to the envelope literal.

#### V-MED-3. Agent session-key rotation is non-atomic

- **Location:** `agent_pairing.go:503-508` (`HandleAgentExtendSession`); device equivalent `device_pairing.go:478-485`.
- **Issue:** `storage.Delete(oldKeyPath)` is best-effort with a `log.Warn` on failure; new key is then written. If Delete fails (transient SQLite), old key remains decryptable while ConnectionRecord no longer references it.
- **Impact:** Forward-secrecy regression — rotation isn't atomic.
- **Fix:** Treat Delete failure as fatal and roll back, or defer-write the new key.

#### V-MED-4. `publishDeviceResponse` outbound envelope omits `Sequence`

- **Location:** `device_handler.go:952-957`.
- **Issue:** Same shape as V-MED-2 but on the device path. Desktop doesn't enforce inbound sequence today, so dormant — but diverges from `publishAgentResponse` and the documented contract.
- **Fix:** Stamp `Sequence` to match.

#### V-MED-5. Mock attestation accepted unless `VETTID_PRODUCTION=true`

- **Location:** `enclave/supervisor/attestation.go:408-425` (`verifyMockAttestation`); `vsock.go:506-508` (`isProductionMode`).
- **Issue:** Short-circuits on `MOCK_ATTESTATION:` prefix unless `VETTID_PRODUCTION=true`. PCR validation also skipped non-production (`vsock.go:742-744`). Missing env var = no enclave identity verification.
- **Fix:** Default to strict; require explicit `VETTID_DEV_MODE=true` to relax. Fail startup if running on `/dev/nsm`-bearing hardware with mock attestation enabled.

#### V-MED-6. Goroutine + message-misorder bug in `PipeConnection.ReadMessageWithTimeout`

- **Location:** `enclave/supervisor/pipe_ipc.go:113-132`.
- **Issue:** On timeout, the inner goroutine continues and eats the next pipe message intended for the next caller. Every subsequent response on the connection is mis-correlated by one.
- **Impact:** Not live — appears unused (the vault subprocess pipe path uses the persistent-reader/`pending` map design at `vault_lifecycle.go:498-552`, which is robust). Flag-and-remove before re-use.
- **Fix:** Delete `ReadMessageWithTimeout`, or back it with a single-reader + pending-map.

### LOW

- **V-LOW-1.** `aeadOpenWithLegacyFallback` permanently accepts ciphertexts without AAD — `crypto.go:73-88` used at `:210` and `:467`. Add a metric counting fallback-path hits; drop the helper at zero. (Sibling finding in agent below.)
- **V-LOW-2.** Comment/code drift on Stage-1 agent default scope — `connections.go:3905-3911,2327`. Empty scope reads as "all categories allowed" in the comment but `HasCapability` returns false. Fail-closed-safe but misleading.
- **V-LOW-3.** `pendingApprovals` map key collision on `req.RequestID` — `agent_handler.go:548,642,833`. Same key used by `handleSecretRequest`, `handleActionRequest`, and `handleAgentMessage` approval path with no collision check. Confused/hostile agent can overwrite its own pending entries.
- **V-LOW-4.** Stage-2 `HandleAgentRequestSession` clobbers active `AgentPendingAuth` without rate-limit — `agent_pairing.go:137-145`. A buggy retrying agent can spam the owner with phone prompts.
- **V-LOW-5.** Parent replay cache is local-disk only (`parent/message_replay.go:38-47`). Documented design — across-ASG-refresh widens replay window to whatever the freshness gate allows (~5 min). Acknowledged layering.

### Coverage (vault stream)

**Read in full:** `agent_handler.go`, `agent_pairing.go`, `agent_capabilities.go`, `agent_rate_limit.go`, `device_handler.go`, `device_pairing.go`, `messages.go`, `handler_authorization.go`, `peer_envelope.go`, `connections.go` (relevant handlers), `crypto.go`, `bootstrap_handler.go`, `audit_key.go`, `storage_adapter.go`, `storage/sqlite.go`, `nats_credentials.go`, `unmarshal_request.go`. Supervisor: `attestation.go`, `vsock.go` (mutual handshake section), `pipe_ipc.go`, `vault_lifecycle.go`, `sealer_handler.go`, `supervisor.go`, `nitro_sealing.go`, `org_vault_lifecycle.go`. Parent: `vote_validator.go`, `dynamodb_client.go` SubmitSignedVote path, `message_replay.go`. Migration: `migrate.go`, `verify.go`. Org-vault: `connection_crypto.go`.

**Gaps (recommended follow-up):** `calls.go` (WebRTC E2EE), `wallet_handler.go` / `bitcoin.go`, `credential_*.go` (Protean), `backup.go`, `parent/kms_client.go` full Decrypt/Generate paths, `parent/routing.go` + `routing_reclaim_test.go` (split-brain invariants), `parent/control_verification.go`, `migration/pcr_config.go` + `pcr_config_signing.go`, `org-vault-manager/{audit_handler,credential_proxy,credential_store}.go`.

---

## vettid-dev: CDK / Lambda / Public Endpoints

### HIGH

#### C-HIGH-1. `api.vettid.dev` HTTP API has no WAF protection

- **Location:** `cdk/lib/vettid-stack.ts:541-564` (deliberate removal documented), `:448-457` (custom domain → HTTP API stage).
- **Issue:** WAFv2 is attached only to the CloudFront `vettid.dev` distribution. The API runs on its own custom domain `api.vettid.dev` (A record at `:460`), NOT fronted by CloudFront. All `/v1/public/leash/*` endpoints + `submitRegistration`, `submitHelpRequest`, `submitWaitlist`, `bootstrapDevicePairing` are reachable directly with no managed rule sets, rate-based rules, or IP-reputation block. Comment at `:552` ("clients are expected to reach the API through CloudFront") contradicted by the `api.vettid.dev` A record and frontends like `leash.js:27` that hardcode it.
- **Impact:** Demo-mint flooding, brute-force on invite shortcodes, spam on `/help`/`/waitlist`, 16KB-request flooding — all bypass WAF. Per-stage throttle (200 burst / 100 RPS, `:2008-2009`) is the only edge defence and isn't per-IP.
- **Fix:** Attach a regional WAFv2 ACL to the HTTP API v2 stage (recent re:Invent added support — verify), or front `api.vettid.dev` with CloudFront + reject direct API-GW hits via resource policy.

#### C-HIGH-2. GitHub OIDC role accepts any `mesmerverse/*` repo and any ref

- **Location:** `cdk/lib/infrastructure-stack.ts:1571`.
- **Issue:** `'token.actions.githubusercontent.com:sub': 'repo:mesmerverse/*:*'` matches every repo under the org and every ref (branch, tag, PR head, environment). Role has `handlersBucket.grantReadWrite` + `handlerManifest.grantReadWriteData` + `handlerSigningKeySecret.grantRead`.
- **Impact:** Anyone pushing a workflow to any repo under `mesmerverse` (typo-squat, forked-PR `pull_request_target` misuse, compromised contributor with tag-push) can sign and publish a malicious WASM handler into the enclave's dynamic-handler pipeline AND extract the production handler-signing private key.
- **Fix:** Pin to specific repo + protected branch: `'repo:mesmerverse/vettid-dev:ref:refs/heads/main'`, or use a GitHub Environment claim with required reviewers.

#### C-HIGH-3. vsock shared secret persists in Docker layers on the enclave-host AMI

- **Location:** `packer/nitro-enclave-host.pkr.hcl:168-172, 174-178, 211-212`; `enclave/Dockerfile.enclave:60`.
- **Issue:** Packer fetches `vettid/vsock-shared-secret` from Secrets Manager into `/tmp/enclave/vsock-secret.hex`, builds an image that `COPY`s it to `/etc/vettid/vsock-secret`, converts to EIF. Cleanup at `:211` only does `docker rmi` (untag) — does NOT prune underlying layers from `/var/lib/docker`.
- **Impact:** Compromise of one enclave-host EC2 or its instance role yields the vsock secret used for parent↔enclave mutual auth, weakening the enclave isolation boundary.
- **Fix:** `docker system prune -af` + `shred` the temp file before final cleanup; ideally use a build-time-only secret mount (BuildKit `--mount=type=secret`) so the secret never lands in a layer, or fetch the secret inside the enclave runtime over vsock.

#### C-HIGH-4. `bootstrapDevicePairing` leaks internal error messages to unauthenticated callers

- **Location:** `cdk/lambda/handlers/vault/bootstrapDevicePairing.ts:189`.
- **Issue:** `return internalError(\`failed to mint credentials: ${msg}\`, origin);` where `msg` is the raw SDK exception. Can leak Secrets Manager secret ID, NATS account internals, AWS request IDs.
- **Fix:** Constant string in the body; log `msg` to CloudWatch only.

### MEDIUM

#### C-MED-1. LEASH demo `mint` endpoint has no rate limit

- **Location:** `cdk/lambda/handlers/public/demoMintLeash.ts:155-244`; route `vettid-stack.ts:1774-1778`.
- **Issue:** No `checkRateLimit()`, no captcha. Writes one `LeashIssued` row per call (PAY_PER_REQUEST DDB), each TTLs `now + durationSecs` (max 600s). At the per-stage cap (100 RPS), ~60k rows live simultaneously.
- **Fix:** Call `checkRateLimit(event, 'public:default')` — helper is already configured for 60 RPM / 120 per-IP.

#### C-MED-2. LEASH demo `session` creation unauthenticated + unbounded

- **Location:** `cdk/lambda/handlers/public/demoSession.ts:38-80`; `vettid-stack.ts:1784-1787`.
- **Issue:** Creates a 30-min DDB row per call. Verify endpoint then appends to `results` list per session via `list_append` — list growth is unbounded inside each item (DDB 400KB cap eventually fails inserts).
- **Fix:** Rate-limit session-create by IP (5/hr); cap `results` length (reject when > 100).

#### C-MED-3. `testCreateInvitation` uses `Math.random()` for invitation code

- **Location:** `cdk/lambda/handlers/test/testCreateInvitation.ts:87-95`.
- **Issue:** `Math.random()` is not CSPRNG. Gated by `VETTID_DEPLOY_TEST_ENDPOINTS=true` and the Secrets-Manager-loaded x-test-api-key, but the generation primitive is wrong for an auth artifact.
- **Fix:** `crypto.randomBytes()` + base32, matching the production invite generator.

#### C-MED-4. `getPcrConfig` returns raw SDK error message

- **Location:** `cdk/lambda/handlers/vault/getPcrConfig.ts:191`.
- **Issue:** Same family as C-HIGH-4 but smaller blast radius (mobile attestation flow).
- **Fix:** Log internally; constant message in body.

#### C-MED-5. `submitRegistration` Cognito-existence timing oracle

- **Location:** `cdk/lambda/handlers/public/submitRegistration.ts:209-251`.
- **Issue:** Returns identical generic message strings, but response time differs between (invalid invite) / (valid invite, new email) / (valid invite, existing email) — `AdminGetUserCommand` only runs in the last path.
- **Impact:** Email/account enumeration by timing.
- **Fix:** Always execute all three checks regardless of intermediate failures, or add randomized response delay.

#### C-MED-6. AWS account ID hardcoded as bucket-name fallback

- **Location:** `cdk/lambda/handlers/backup/getCredentialBackupStatus.ts:12`.
- **Issue:** `process.env.VAULT_DATA_BUCKET || "vettid-vault-data-449757308783"` — hardcoded account ID, contradicts the policy noted at `vettid-stack.ts:434` ("Certificate ARN stored in cdk.context.json … to avoid exposing account ID").
- **Fix:** Drop the fallback; require env var, fail-fast if absent.

#### C-MED-7. Wildcard CORS on all LEASH public endpoints

- **Location:** `demoMintLeash.ts:51`, `demoRevokeLeash.ts:27`, `demoSession.ts:32`, `verifyLeash.ts:14`, `getLeashKeys.ts:31`, `getLeashStatus.ts:32`, `listPublicServices.ts` (via `ok()`).
- **Issue:** `Access-Control-Allow-Origin: *`. No `Allow-Credentials: true`, so CSRF surface is limited to the endpoints' own actions — but combined with the missing rate limits (C-MED-1, C-MED-2), drive-by abuse from any malicious page is trivial.
- **Fix:** Restrict to `https://vettid.dev`, `https://www.vettid.dev`; or accept the trade-off and add per-IP rate-limit.

### LOW

- **C-LOW-1.** Hardcoded packer build bucket/manifest table defaults in `scripts/handler-deploy/main.go:57-58`. Make env vars required.
- **C-LOW-2.** `AWS_REGION=us-east-1` baked into systemd unit in `packer/nitro-enclave-host.pkr.hcl:294`. Portability, not security.
- **C-LOW-3.** `ec2:DescribeInstances` / `ec2:DescribeTags` granted with `Resource: '*'` in `cdk/lib/nitro-stack.ts:637-648`. Action-API limitation; mitigated by `ec2:ResourceTag/Application=vettid-enclave` condition.
- **C-LOW-4.** SES IAM grants with `Resource: '*'` in `admin-management-stack.ts:388-396,451-454,457-460`. Common pattern; constrained at SES identity layer. Worth verifying SES identity policies separately.
- **C-LOW-5.** `cdk/scripts/leash-smoke-test.sh:26,34,46` echoes bodies to stdout — fine today (fake data) but pattern could leak in future ops scripts.
- **C-LOW-6.** Test API-key secret loaded as module-level `cached` singleton in `cdk/lambda/common/testApiKey.ts:11-40`. Container reuse keeps it warm — Lambda-standard behaviour, flagged for awareness.

### Coverage (CDK stream)

**Read:** `vettid-stack.ts`, `infrastructure-stack.ts`, `nitro-stack.ts`, `vault-stack.ts` (partial), `admin-management-stack.ts`, `business-governance-stack.ts` (partial), `turn-stack.ts`, `audit-grants.ts`, `canonical-json.ts`. All public-handler Lambdas (LEASH bundle, registration, help, waitlist, services, votes). `bootstrapDevicePairing.ts`, `getPcrConfig.ts`. Test handlers. `getCredentialBackupStatus.ts`. `common/{testApiKey,rateLimit,util}.ts`. Frontend `leash.js` + XSS sweep across `admin/`, `account/`, `shared/`. `cdk/scripts/{deploy,deploy-frontend,leash-smoke-test}.sh`. `scripts/handler-deploy/main.go`. `packer/nitro-enclave-host.pkr.hcl` + `enclave/Dockerfile.enclave`. Confirmed `cdk.context.json` is not git-tracked.

**Confirmed clean:** `VETTID_TEST_API_KEY` migration to Secrets Manager — no committed test-key value in source or `cdk.context.json`; only ARN references remain.

**Gaps:** Did not deep-read every admin/member handler (~150+ files) — sampled high-risk ones around IAM grants and external-trust boundaries. `nats-stack.ts` IAM only spot-checked. Did not run/test LEASH endpoints live; static review only.

---

## vettid-desktop (Tauri 2 / Svelte 5)

### HIGH

#### D-HIGH-1. `devtools` Tauri feature enabled unconditionally in production builds

- **Location:** `src-tauri/Cargo.toml:12`.
- **Issue:** `tauri = { version = "2", features = ["tray-icon", "image-png", "devtools"] }` — no `cfg(debug_assertions)` gate. Tauri docs: `devtools` exposes WebView devtools regardless of debug/release.
- **Impact:** Local-process attacker (escaped browser extension, dev tool, anything as the user) can open devtools on the shipped binary, hook the JS↔Rust `invoke` bridge, and call any Tauri command after the auto-unlock has populated `AppState.credentials` / `connection_key`. Read any secret the user retrieves, mint arbitrary signed vault ops.
- **Fix:** Move `devtools` behind a debug-only feature flag (`[target.'cfg(debug_assertions)'.dependencies]` or `[features] devtools = ["tauri/devtools"]` enabled only in debug profile). Verify Inspect Element is gone from the release context menu.

#### D-HIGH-2. `shell:allow-open` regex permits attacker-controlled URLs through peer messages

- **Location:** `src-tauri/tauri.conf.json:57`, `src-tauri/capabilities/default.json:13`, `src/lib/views/vault/Conversation.svelte:458`.
- **Issue:** Scope is `^https://(vett\.id|api\.vettid\.dev|vettid\.org)/.*` — `.*` matches any path/query/fragment, and `Conversation.svelte` calls `await open(href)` with URLs parsed out of unstructured peer message text. `Conversation.svelte:446` also rewrites bare `www.foo` tokens to `https://www.foo`, so peer-provided strings can be coerced into the allowed shape.
- **Impact:** A peer can include a link in chat that, when clicked, drives the default browser to an attacker-influenced URL on the vetted host (open redirects on those landing pages would amplify). Lower than RCE but it's the most user-visible click-through surface.
- **Fix:** Tighten scope to known marketing paths (`^https://(vettid\.org|vett\.id)/(?:about|blog|security|legal)(/|$)` etc.), or render the parsed hostname in the UI and require an explicit click on it before calling `open()`. Add a URL-host re-check in `openLink()`.

#### D-HIGH-3. Auto-unlock binds only to the OS keyring; no presence factor + no AAD binding to binary/machine

- **Location:** `src-tauri/src/credential/{keystore,store}.rs`, `src-tauri/src/commands/auth.rs:317-381`, `src/App.svelte:64-71`.
- **Issue:** On launch the frontend calls `invoke('unlock')` which transparently fetches the 32-byte master key from `keyring::Entry::new("vettid-desktop", "master-key-v1")`. On Linux: Secret Service `login` collection unlocked at login — any process as same UID can read it. On macOS: Keychain entry created without `SecAccessControl` requiring user-presence — no Touch ID prompt, no app-identity scoping. The on-disk blob at `store.rs:312-328` is XChaCha20-Poly1305 with no associated data — not bound to binary fingerprint or machine fingerprint.
- **Impact:** Co-resident process on the same user account can: read `~/.config/vettid-desktop/connection.enc` + the keyring entry, decrypt the blob, obtain `connection_key` and NATS JWT/seed, publish any DeviceIndependentCapabilities op as the user (list connections/secrets/messages/personal-data, send messages, `get_secret`, grants).
- **Fix:** Three layered changes:
  1. Pass binary fingerprint + machine fingerprint as AEAD AAD in `encrypt_xchacha20`/`decrypt_xchacha20`.
  2. macOS: create Keychain entry with `SecAccessControl` requiring `kSecAccessControlUserPresence`.
  3. Linux: set `application=vettid-desktop` attribute on the Secret Service item; consider a separate locked collection.
- **Docs:** Make the threat model explicit in user-facing README — "anyone on this Linux user account can use your vault as you" matches `desktop-no-passphrase.md` but is currently buried.

### MEDIUM

- **D-MED-1.** `shell:default` + `shell:allow-open` both listed in `capabilities/default.json:12-13` — redundant in v2 and inherits silently if defaults expand. Replace with `shell:allow-open` + explicit `shell:deny-execute`, `shell:deny-spawn`, `shell:deny-stdin-write`.
- **D-MED-2.** CSP `connect-src` includes `wss://*.nats.io` in `tauri.conf.json:26`. WebView never connects to NATS (Rust does, not subject to CSP). Drop. While there, switch to `default-src 'none'` and explicit per-directive sources (`font-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`).
- **D-MED-3.** No enclave attestation verification on desktop — entire `src-tauri/src/` has no PCR/COSE/NSM parsing; `Cargo.toml` has no `aws-nitro-attestation-doc-validation`. `registration/pairing.rs:269-411` simply trusts `vault_pubkey` from `device.session.activated`. Phone clients verify PCR0 against pinned set in KMS; desktop doesn't. This is the largest single security regression vs the phone client. Fix: attach Nitro attestation doc inside `device.session.activated`; verify on desktop against pinned PCR0 allow-list.
- **D-MED-4.** macOS entitlements substantially weaken Hardened Runtime — `entitlements.plist:5-14`. `app-sandbox=false`, `network.server=true` (unused — desktop is a NATS client), `disable-library-validation=true`, `allow-unsigned-executable-memory=true`, `allow-dyld-environment-variables=true`. Remove `network.server`, `allow-unsigned-executable-memory`, `disable-library-validation`, `allow-dyld-environment-variables`. JIT entitlement alone is enough for WebKit.
- **D-MED-5.** `extract_bytes` (`nats/listener.rs:427-448`) has no length cap on the JSON-array path — `Vec::with_capacity(arr.len())` pre-allocates to `usize::MAX`. Cap at 4 MiB.

### LOW

- **D-LOW-1.** NATS connect logs endpoint URL + "with JWT credentials" at INFO (`nats/client.rs:109,142`). Downgrade the JWT-credentials line.
- **D-LOW-2.** `VETTID_BOOTSTRAP_URL` env-var override accepted in any build (`registration/pairing.rs:61-62`). Gate behind `#[cfg(debug_assertions)]`.
- **D-LOW-3.** `handle_response_message` routes purely by `request_id`, not also by `connection_id`/`session_id` (`nats/listener.rs:173-214`). Add a `connection_id` field comparison as defence-in-depth.
- **D-LOW-4.** `extract_bytes` u64 0-255 runtime check — fine as-is.
- **D-LOW-5.** `ConnectionCredentials.connection_key` round-trips through `Vec<u8>` → `[u8;32]` (`credential/store.rs:122-124`, `commands/auth.rs:142-144,327-330`). On length mismatch the code silently skips populating `state.connection_key` but leaves credentials loaded — robustness, not security.
- **D-LOW-6.** Confirm `cargo tauri build` substitutes `frontendDist` and doesn't carry `devUrl` (`tauri.conf.json:8`) into the bundle. Tauri 2's behaviour is correct here; flagged for confirmation.

### Coverage (desktop stream)

**Read in full:** `tauri.conf.json`, `capabilities/default.json`, `Cargo.toml`, `entitlements.plist`, `Info.plist`, `src-tauri/src/{main,lib,state}.rs`, `credential/{store,keystore,mod}.rs`, `fingerprint/{platform_linux,platform_macos,platform_key,binary,mod}.rs`, `nats/{client,operations,listener,messages,mod}.rs`, `registration/{pairing,flow}.rs`, `session/{capabilities,manager,heartbeat}.rs`, `commands/{auth,vault,calls,mod}.rs`, `crypto/{encrypt,keys}.rs`. `App.svelte`, `index.html`, `package.json`, `Conversation.svelte` (link-open path).

**Gaps:** `src-tauri/src/webrtc/*` not deep-reviewed (frame_cryptor, session, audio, turn) — check per-call shared-secret handling for IV reuse and that the cryptor refuses zero-key state. `session/delegation.rs` race conditions in pending-request map. `crypto/{ecies,hkdf,argon2,frame_cryptor}.rs`. `src/lib/notifications.ts`, `src/lib/stores/*.ts` for localStorage persistence. Auto-updater is not configured (no `updater` block in `tauri.conf.json`) — no signed-update mechanism today, worth a separate decision before tech preview.

---

## vettid-agent (Go daemon + LEASH)

### HIGH

#### A-HIGH-1. WebSocket endpoint is unauthenticatable (`WSToken` never populated)

- **Location:** `cmd/vettid-agent/main.go:372-394` (`api.ServerConfig{}` literal) vs. `internal/api/websocket.go:177`, `internal/api/server.go:111`.
- **Issue:** `ServerConfig.WSToken` is never set anywhere in production code. Handler at `websocket.go:177` checks `if token == "" || token != s.wsToken { reject }` — when `s.wsToken == ""`, every upgrade is rejected with 401.
- **Impact:** Fail-closed today (so not a remote-code-exec class issue), but it's a HIGH-severity correctness break masquerading as security: owner→agent realtime via `BroadcastEvent` never reaches AI tooling; AI falls back to polling `/v1/messages/inbox`. Same plumbing also gates REST auth via `restAuthMiddleware` — a partial fix that wires `WSToken` without auditing the shared middleware could regress REST.
- **Fix:** Generate a random `WSToken` at start (32 random bytes hex), write to `{configDir}/agent.token` mode 0600, expose to local clients alongside the socket path. Wire through `ServerConfig.WSToken`.

#### A-HIGH-2. Pairing/extend ECDH skips small-order point check on `vault_pubkey`

- **Location:** `internal/crypto/keys.go:64` (`ComputeSharedSecret`) — uses raw `curve25519.X25519`, NOT `safeX25519`. Called from `internal/registration/pairing_stage2.go:439` and `pairing_stage3.go:238`.
- **Issue:** `safeX25519` (`internal/crypto/low_order.go:53`) exists and rejects the 7 well-known small-order points, but is only wired into the ECIES decrypt path (`crypto/ecies.go:108`). Pairing/extend ECDH against `vault_pubkey` (from `sessionActivatedPayload.VaultPubKey`) accepts any 32-byte point.
- **Impact:** A vault impostor (or anyone able to write to `forApp.agent.{conn}.activated` — guarded by NATS scoped JWT, but defence-in-depth) can publish a small-order pubkey to force a known shared secret → predictable HKDF→ChaCha key → decrypt all subsequent agent ops + forge owner replies. Vault already enforces the check on the agent pubkey (per memory); agent must mirror it.
- **Fix:** Replace `curve25519.X25519(privateKey, peerPublicKey)` with `safeX25519(privateKey, peerPublicKey)` in `ComputeSharedSecret`. One line.

### MEDIUM

- **A-MED-1.** NATS temp-creds file under `/tmp/vettid-agent-{pid}.creds` (`internal/nats/client.go:39-42`) — PID is guessable, `/tmp` is sticky-but-world-writable. Symlink-pre-creation by a co-resident attacker → `os.WriteFile` follows the symlink → JWT/seed lands at attacker-chosen path. Switch to `{configDir}` (already 0700) or, better, use `nats.UserJWTAndSeed(jwt, seed)` inline (no file) — the bootstrap path already does this.
- **A-MED-2.** Unbounded `io.ReadAll` on validator/mint responses — `internal/leash/validator.go:97`, `mint.go:71`. Bootstrap path correctly caps with `LimitReader(resp.Body, 64*1024)` (`registration/pairing.go:171`). Wrap both with `io.LimitReader(resp.Body, 256*1024)`.
- **A-MED-3.** `VETTID_BOOTSTRAP_URL` has no scheme validation — `registration/pairing.go:135-140`. Env-var injection downgrades bootstrap from HTTPS to HTTP, leaks single-use invite code + delivers the freshly-generated agent X25519 pubkey to attacker NATS. Restrict to `https://`, or require `--bootstrap-url` flag (visible in `ps`).
- **A-MED-4.** `handleSendMessage` + `handleLeashMint` don't nil-check `s.natsClient` — `internal/api/handlers.go:564,929`. Every other publish handler guards `if s.natsClient == nil { 503 }` (`:208,388,445`). Add the same guard. (Not currently reachable, but a sharp edge under future refactor.)

### LOW

- **A-LOW-1.** `s.agentPriv` / `agentPub` / `vaultPub` read at `handlers.go:665-667` outside the `sessionMu` they're written under (`:722-726`). Two concurrent `/v1/pair/extend` (burst 120) can race. Read via the same `Snapshot()` surface or serialise extends.
- **A-LOW-2.** `internal/leash/keypair.go:54-58` writes at 0600 but doesn't verify mode on load. `config.Load` does (`config.go:117`). Mirror it for the LEASH key file.
- **A-LOW-3.** Argon2 envelope decrypt accepts legacy-no-AAD ciphertexts indefinitely — `internal/credential/store.go:265-271`. Track re-seal-on-next-Save; plan removal of the fallback. (Sibling of vault V-LOW-1.)
- **A-LOW-4.** `http.Server` has no `ReadHeaderTimeout` / `ReadTimeout` / `IdleTimeout` (`internal/api/server.go:177`). Add 5s / 30s / 60s respectively. Mitigated by Unix-socket-only default but becomes important if TCP listen is configured.
- **A-LOW-5.** Empty `Origin` on WS upgrade is accepted (`internal/api/websocket.go:21-24`). Moot today (WSToken broken); after A-HIGH-1 is fixed, optionally require Origin or a User-Agent allowlist when token is also missing.

### Coverage (agent stream)

**Read:** `cmd/vettid-agent/{main,demo,leash}.go`, `internal/api/{server,handlers,websocket,tracker,catalog,inbox,messagelog,rate_limit}.go`, `internal/leash/{keypair,mint,validator}.go`, `internal/registration/{pairing,pairing_stage2,pairing_stage3,flow}.go`, `internal/credential/{store,passphrase}.go`, `internal/crypto/{keys,encrypt,ecies,low_order}.go`, `internal/nats/{client,messages}.go`, `internal/config/config.go`, `internal/fingerprint/platform_key.go`, `Dockerfile`, `go.mod`, `scripts/build.sh`.

**Gaps:** `internal/crypto/{hkdf,argon2}.go` parameter floors (grep-checked only). `internal/fingerprint/machine_*.go`. Test files (`*_test.go`).

---

## vettid-android

### HIGH

#### N-HIGH-1. Notification "Approve transfer" action skips biometric/PIN re-auth

- **Location:** `app/src/main/java/com/vettid/app/core/notifications/VaultProtectionService.kt:544-571` (`handleApproveTransfer`); action button at `:488-491`; PendingIntent at `:434-439`. In-app code's own TODO at `:549` says "Require biometric authentication before approving".
- **Issue:** `ACTION_APPROVE_TRANSFER` from the foreground-service notification fires `ownerSpaceClient.sendToVault("transfer.approve", {transfer_id, approved:true})` directly from the service handler. The in-app `TransferApprovalScreen` does gate on PIN/biometric (`features/transfer/TransferModels.kt:221` `AwaitingBiometric`), but the notification-tap bypass goes around that path entirely.
- **Impact:** Anyone with brief physical access to an unlocked phone (or even from the lock-screen shade depending on OS settings) can approve a credential transfer to a hostile device — the single most sensitive op in the app — without ever entering the PIN.
- **Fix:** Replace `PendingIntent.getService(ACTION_APPROVE_TRANSFER)` with `PendingIntent.getActivity(...)` that deep-links to `TransferApprovalScreen`. Remove `ACTION_APPROVE_TRANSFER`/`handleApproveTransfer` from the service. `ACTION_CANCEL_RECOVERY` (`:358-386`) has the same shape but fail-closed (cancel) so lower priority.

#### N-HIGH-2. Dead `AppLockScreen` accepts any 4-digit PIN, still wired into the nav graph

- **Location:** `app/src/main/java/com/vettid/app/features/applock/AppLockScreen.kt:40-46` (comment: `// For demo, accept any 4-digit PIN`). Composable registered at `VettIDApp.kt:1571-1576`; `PinSetupScreen` at `:1577-1585` is a similar stub.
- **Issue:** Demo-grade code that grants unlock on any 4-digit input. Route `Screen.AppLock.route` exists in the nav graph and is reachable via `navController.navigate(Screen.AppLock.route)`. No live caller found, but `PinSetupScreen` stub similarly returns success without persisting a PIN, leaving users believing they've set a PIN they never actually set.
- **Impact:** One accidental nav reference (or fuzzed deep link) reaches the screen → app unlocks on any input. Latent unlock-bypass.
- **Fix:** Delete `AppLockScreen.kt`, remove `composable(Screen.AppLock.route)` / `composable(Screen.PinSetup.route)` / `composable(Screen.FirstTimeSetup.route)` from `VettIDApp.kt`, and the `onNavigateToPinSetup` call at `:1050-1052`. If kept as placeholders, replace body with `throw IllegalStateException("not implemented")` so any accidental reference crashes loudly.

### MEDIUM

- **N-MED-1.** Notification-tap intents are matched on extras before the `ACTION_VIEW + CATEGORY_BROWSABLE` guard; `MainActivity` is `android:exported="true"` — `MainActivity.kt:142-164` + manifest `:74`. Any installed app can `startActivity(Intent(...).setComponent(MainActivity).putExtra(EXTRA_OPEN_FEED, true)...)` and navigate the user to approval screens with attacker-supplied IDs. Real auth still happens server-side (vault rejects mismatched IDs) but the confused-deputy UX hazard is real. Fix: check `getCallingPackage()` matches own package after consuming notification extras, or route notification-extras through an `exported="false"` activity-alias.
- **N-MED-2.** NATS TLS chain pinned by SPKI but no hostname verification — `core/nats/AndroidNatsClient.kt:202-228`, `verifyNatsCertificateChain` `:525-547`. `SSLSocketFactory.getDefault().createSocket()` returns a socket without `SSLParameters.endpointIdentificationAlgorithm = "HTTPS"`. SPKI pin defends against substituted keys, but a same-pinned cert issued for a different host could still be accepted from a misrouted intermediary. Fix: set `params.endpointIdentificationAlgorithm = "HTTPS"` at `:220-222`, or explicit `getDefaultHostnameVerifier().verify(host, session)` post-handshake.
- **N-MED-3.** `HardwareAttestationManager.generateMockAttestation` gated by `BuildConfig.SKIP_ATTESTATION` (`HardwareAttestationManager.kt:47-49,162-199,270`). False for `production` flavor, true for `automation`. Build refuses `automationRelease` — good. Defence-in-depth: in production-flavor code, `throw` on the SKIP_ATTESTATION branch so a misconfigured CI env crashes loudly. Also recommend confirming server-side rejects `attestation_type=test` in production.

### LOW

- **N-LOW-1.** Committed test-fixture API key in `test-fixtures/test-config.json:3` is a clearly-marked placeholder; real key loaded from env (`app/build.gradle.kts:149`). No action.
- **N-LOW-2.** Secret IDs logged at INFO in `features/secrets/SecretsViewModel.kt:359,373,426,521`, `CriticalSecretsViewModel.kt:287`. Release-stripped via ProGuard `-assumenosideeffects` (`proguard-rules.pro:15-22`). Optional consistency: downgrade to `Log.d`.
- **N-LOW-3.** `PinAttemptTracker` lockout counters in plain `MODE_PRIVATE` SharedPreferences (`features/unlock/PinAttemptTracker.kt:31-32`). Server-side rate-limit covers this; defence-in-depth would back with `EncryptedSharedPreferences`.
- **N-LOW-4.** `tools:targetApi="31"` in `AndroidManifest.xml:58` is a lint-suppression hint; `targetSdk=34` (`build.gradle.kts:19`) is what runs. No security impact.
- **N-LOW-5.** `ALLOWED_VETTID_HOSTS` (`MainActivity.kt:347-349`) includes `"transfer"` but no manifest intent-filter routes `vettid://transfer/*`. Allow-list / manifest drift — remove or add the intent-filter to keep them in lock-step.

### Coverage (android stream)

**Read:** `AndroidManifest.xml`, `res/xml/{data_extraction_rules,network_security_config}.xml`, `build.gradle.kts` (top + app), `gradle.properties`, `local.properties`, `proguard-rules.pro`, `test-fixtures/test-config.json`. Source: `MainActivity.kt`, `VettIDApplication.kt`, regions of `VettIDApp.kt` (deep-link + nav). Core: `CryptoManager`, `RecoveryPhraseManager`, `SessionCrypto`, `SecureRandomProvider`, `HardwareAttestationManager`, parts of `NitroAttestationVerifier`, `CredentialStore` (partial), `AppPreferencesStore` (partial), `InMemoryPrefs`, `NetworkConfig`, `AndroidNatsClient` (TLS+connection), `VaultProtectionService`, `SecureActivity`, parts of `RuntimeProtection`, `QrRecoveryClient`. Features: `AppLockScreen`, `PinUnlockScreen` (+ ViewModel + `PinAttemptTracker`), `AuthorizeAgentScreen`/`ViewModel`, `LeashApprovalViewModel`, `FeedNotificationService`, `FeedActionReceiver`. Confirmed via grep: no `setUserAuthenticationRequired` or `BiometricPrompt` usage — consistent with biometrics removed in favor of PIN + enclave-side gate.

**Gaps:** Full bodies of every ViewModel (only auth/approval ones inspected). `core/calling/*` (WebRTC frame crypto) and `core/audit/*` (audit chain) — grep-summary only, no deep dive. `app/src/test` and `app/src/androidTest`.

---

## Recommended Next Steps

1. **Land the 11 blockers in section "Pre-tech-preview blockers".** Each has a one-paragraph fix in this report and a citable file:line.
2. **Spawn a follow-up review** on the coverage gaps marked above — most consequential: vault `calls.go` (WebRTC E2EE-key derivation), `parent/routing.go` (split-brain), `parent/kms_client.go`, `cdk/lib/nats-stack.ts` NATS account policies, desktop `webrtc/frame_cryptor.rs` for IV reuse.
3. **Add invariants to CI** that would have caught two of these statically:
   - grep for `deriveConnectionKey(conn.SharedSecret)` without a preceding `IsAgent()` guard — would have caught V-HIGH-1 and the 2026-05-25 cluster.
   - grep for outbound `AgentEnvelope{` literals without `Sequence:` — would have caught V-MED-2 and V-MED-4.
4. **Threat-model the local-process attacker** explicitly. Several findings (desktop auto-unlock, agent `/tmp` creds, android PIN tracker storage) make sense individually but together suggest "co-resident process on the user's account" deserves a first-class section in `docs/THREAT-MODEL.md` rather than being implicit per-component.

