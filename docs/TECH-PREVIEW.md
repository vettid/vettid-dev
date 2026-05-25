# VettID Technical Preview

VettID is a privacy-first digital identity platform. Your data lives in an
AWS Nitro Enclave — a hardware-isolated environment that even the operator
(this dev) cannot see into. Sensitive operations happen inside the enclave,
attested by hardware. Your **vault is your root of trust** — you
control it using your phone and your credential.

The **Technical Preview** is the first round of external testing. You'll
pair your phone, optionally a desktop or AI agent, exchange data with
connections, sign with credentials, and tell us where it breaks.

---

## Before you start

A few things to know up front:

- **Data loss is possible**, though not expected. Treat anything you put
  in the vault during the preview as recoverable from another source.
  A Backup feature exists in Settings (mobile) — it produces an encrypted
  blob and a recovery codeword — but the **end-to-end restore path
  hasn't been verified through the tech-preview cycle yet**, so don't
  treat it as a guaranteed safety net. Verification of the restore
  flow is itself an open preview workstream; reports welcome.
- **This is the result of one person working in their spare time**
  alongside a full-time job. The cryptographic primitives and enclave
  isolation are solid; the surrounding UX has rough edges. Expect to
  hit dialogs that don't auto-dismiss, screens that refresh on a 30-second
  delay, and the occasional log-and-retry.
- **No SLA, no support contract.** Best-effort response to bug reports.
- **Privacy posture, in writing:** the enclave host (operator side, AWS
  EC2) journals NATS routing metadata — your `owner_space` GUID, the
  operations you run, timing. **No payload content is ever logged.** The
  journal default is WARN+; the on-call can elevate to debug for
  incident triage. The enclave itself logs nothing externally.
- **Security findings: do NOT file public issues.** Email
  `security@vettid.org`. PGP encryption is supported — fingerprint
  `E23A 83D6 7828 2CD7 9E95 E5F7 1523 8C03 B404 DAEB`, full ASCII-armored
  key on the [security page](https://vettid.dev/security). Responsible
  disclosure is required for anything that affects confidentiality,
  integrity, or availability of user data.

---

## How to sign up

1. Visit **[vettid.dev/help](https://vettid.dev/help)** and fill in the
   volunteer form.
2. If accepted, you'll receive an email with a **registration code**.
   Each code is good for **two unique users** (e.g. you + one family
   member or colleague).
3. Capacity is rate-limited — single-developer support means cohorts
   roll out gradually. Expect a delay between signup and acceptance.

---

## What you get after acceptance

- Your registration code (good for 2 enrollments).
- Access to the [GitHub Discussions](https://github.com/vettid) for
  preview-cohort announcements and Q&A.
- Build artifacts on each repo's Releases page (where signing makes
  pre-builds possible — see Install below).

---

## Install

### Android (pre-built APK)

Pre-built signed APKs ship on the
[vettid-android releases](https://github.com/vettid/vettid-android/releases)
page.

1. Download the latest `vettid-app-production-debug.apk` from
   the release.
2. Sideload to your phone (Play Store distribution is not yet wired up).
3. On any browser, go to **[vettid.dev/register](https://vettid.dev/register)**,
   enter your registration code, and create your account. This kicks
   off vault enrollment.
4. When the registration flow asks you to continue on your phone, open
   the installed app and follow the enrollment wizard the rest of the
   way through.

Tested on Pixel 7+ running Android 14+. Older devices may work; not
verified.

### Desktop — Linux

```bash
git clone https://github.com/vettid/vettid-desktop
cd vettid-desktop
npm install
cargo tauri dev   # or `cargo tauri build` for a release bundle
```

Requires Rust 1.75+, Node 18+, and the Tauri v2 system dependencies
(webkit2gtk-4.1 on most distros). See the repo's README for full
prerequisites.

After launch, scan the desktop pairing code from your phone (Settings
→ Connections → Add desktop).

### Desktop — macOS

Build from source until a signed `.dmg` ships:

```bash
git clone https://github.com/vettid/vettid-desktop
cd vettid-desktop
brew install opus pkg-config cmake   # WebRTC deps for voice calls
./scripts/install-local.sh           # builds + installs to /Applications
```

The script strips the macOS quarantine attribute so Gatekeeper doesn't
block the unsigned bundle. Signed builds are a roadmap item; until then,
build it yourself.

### iOS

Build from source via Xcode. Pre-built `.ipa` is not available during
the preview (TestFlight pipeline not yet set up).

```bash
git clone https://github.com/vettid/vettid-ios
cd vettid-ios
open VettID.xcodeproj
# In Xcode: set your team in Signing & Capabilities, target your device,
# Cmd-R to run.
```

iOS Simulator runs the UI but cannot pair (no Keystore-equivalent hardware
attestation).

### Agent connector (Linux / macOS)

For programmatic access from an AI agent or scripting host. Pre-built
binaries are posted on the
[vettid-agent releases](https://github.com/vettid/vettid-agent/releases)
page **when available** — the release pipeline is currently manual
(GitHub Actions doesn't have the build environment we need for the
cross-compile path), so a release might lag a few days behind the
mobile + desktop builds. If the release page doesn't have a binary
for your platform yet, build from source:

```bash
git clone https://github.com/vettid/vettid-agent
cd vettid-agent
make build   # produces ./vettid-agent for your current platform
# or `make release` for the cross-platform set
./vettid-agent init <invite-code> --type my-agent
./vettid-agent start
```

Requires Go 1.22+. From a downloaded release:

```bash
chmod +x vettid-agent
./vettid-agent init <invite-code> --type my-agent
./vettid-agent start
```

Invite codes are minted from the phone (Settings → Agent Connections →
Create Invitation). See the `vettid-agent leash` subcommand for
delegated capability tokens (LEASH JWTs scoped to specific resources).

---

## What works today vs. what's churning

| Capability | Status |
|---|---|
| Enrollment + identity setup | **Stable** |
| Phone ↔ phone messaging | **Stable** |
| Phone ↔ desktop pairing + sessions | **Stable** |
| Secret storage + retrieval (minor secrets) | **Stable** |
| Critical secrets (seed phrases, signing keys) | **Stable** |
| BTC wallet | **Stable** |
| Backup creation | **Beta** |
| Backup restore | **Beta** — end-to-end restore flow not yet verified through a preview cycle; please don't rely on it as a sole copy until it has been |
| Audio calling | **Beta** — works, occasional reconnect issues |
| Agent connector pairing | **Beta** — recent refactor; expect breaking changes |
| Agent → owner chat | **Beta** |
| LEASH delegation tokens | **Alpha** — new flow; mint + verify works, scope vocabulary may still shift |
| Video calling (phone ↔ phone) | **Beta** — works; desktop client not yet wired |
| Cross-device sync (multi-phone) | **Not planned** — a single phone is the control point by design |

If a capability marked Beta or Alpha breaks for you, that's a useful
report — file it. If a Stable capability breaks, that's a higher-priority
report.

---

## Logging and visibility

The enclave host (AWS EC2 parent process) writes the following to
`journalctl`:

- NATS subjects of every operation routed to/from the enclave
- `owner_space` GUID (your pseudonymous user ID)
- Message types, response sizes, timing
- Migration + deployment events

It does **not** log:

- Decrypted payloads
- Plaintext secret values
- Vault contents
- Connection-key or session-key bytes

The default level is **WARN+** (errors and worse). For incident triage the
on-call can elevate to **DEBUG** via SIGUSR1 to the parent process; that
remains in effect until the next instance refresh or another signal.

The enclave itself (where your plaintext lives) has no external log
output. Goroutine-stack diagnostics only fire on a detected stall and
contain no buffer contents — see the `vettid-dev/enclave` source for the
runtime watchdog.

---

## Feedback

Three channels — please use the right one:

- **Bugs, feature requests, UX issues**: file a GitHub issue in the
  relevant repo:
  - [vettid-android/issues](https://github.com/vettid/vettid-android/issues)
  - [vettid-desktop/issues](https://github.com/vettid/vettid-desktop/issues)
  - [vettid-agent/issues](https://github.com/vettid/vettid-agent/issues)
  - [vettid-dev/issues](https://github.com/vettid/vettid-dev/issues) for backend / enclave / infrastructure
- **Security vulnerabilities**: email `security@vettid.org`
  ([PGP key](https://vettid.dev/security)). **Do not** file public issues
  for confidentiality, integrity, or attestation defects.
- **Design discussion, "what landed this week," questions for the dev**:
  [GitHub Discussions](https://github.com/vettid). Cohort announcements
  (planned outages, breaking changes, new release notes) post here.

---

## Looking for collaborators

The preview is also a call for contributors in two specific areas:

### Zero-knowledge proof schemes

The current ZK story is narrow — selective disclosure on identity
attributes, and a handful of attestation primitives. If you've worked
with Groth16 / PLONK / Bulletproofs / Halo2 / proof-carrying data and
want to land a new scheme inside the enclave, please open a Discussion.
The integration contract is roughly: implement the prover/verifier in
Go as an enclave handler and bundle it into the enclave build —
handlers are Go-only today and ship as part of the attested enclave
image, not as runtime-loadable plugins.

See [Zero-Knowledge-Trust](https://github.com/vettid/Zero-Knowledge-Trust)
for the design notes.

### Enclave handlers (TEE work)

The vault-manager is extensible — new operations (think: signing a
custom credential format, deriving a domain-specific key, gating a
specific resource) are written as Go handlers inside the enclave. If you
have a workload that needs to run inside hardware isolation, the handler
contract is in `vettid-dev/enclave/vault-manager/CLAUDE.md` and the
PCR-attestation requirements are in `docs/PCR-HANDLING-GUIDE.md`. Open a
Discussion to propose a handler; PRs welcome.

---

## Network requirements

The apps need outbound access to:

- `api.vettid.dev` (HTTPS, port 443) — enrollment, public endpoints, LEASH
  verifier
- `nats.vettid.dev` (TLS, port 443) — encrypted message bus to the
  enclave
- (Agent only) the same two endpoints

Corporate firewalls that intercept TLS will break the TLS-pinned NATS
connection. There is no workaround for that during the preview; if
that's your environment, run the apps from a network that doesn't.

---

## Versioning + updates

- **No auto-update during the preview.** Watch the relevant repo's
  Releases page or subscribe to the Discussion for announcements.
- **Breaking changes are possible.** Re-pairing after a major version
  bump is expected; backup before updating.
- Repos are versioned with date-tagged releases (e.g.
  `2026-05-25-v6`) — the date is the enclave deploy that matches the
  client build.

When an update is required (vault protocol change), the previous client
will start failing operations with a clear error. Update from the
release page; re-pair if needed.

---

## About the developer

VettID is currently one person working on it alongside a full-time job.
That means:

- Cryptographic primitives, enclave isolation, attestation, and storage
  layers are designed conservatively and security-reviewed.
- Surrounding code (UI, error handling, edge-case polish) is honest
  alpha-quality. Expect rough edges; please report them.
- Response times to issues vary. Security reports take priority over
  feature requests over UX polish.
- If you'd like to contribute code, the door is open — see the
  contributor sections above.

Thanks for trying it.
