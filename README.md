# vettid-dev (archived)

This repository is the first VettID implementation (2025-12 to 2026-08),
which ran at vettid.dev on a NATS message bus with vaults in AWS Nitro
Enclaves. It is **archived and read-only**. vettid.dev now redirects to
vettid.org and none of the infrastructure described here is running.

VettID continues at:

- **https://vettid.org** - the project site
- **github.com/vettid/vettid.org** - website, member and admin services,
  and the design docs (`docs/`). Start with `docs/ARCHITECTURE.md`, the
  system overview and index of every doc. Others include VAULT-MESSAGING
  (the vault spec), VAULT-PLAN, VAULT-ITEMS, PROTEAN-CREDENTIAL,
  RELEASE-UPDATES, RELAY-PROTOCOL, PUSH-GATEWAY, CALLING-SERVICE,
  PQC-MIGRATION, MEMBER-API and TECH-PREVIEW
- **github.com/vettid/vettid-vault** - the enclave vault (one process per
  vault, hybrid post-quantum messaging)
- **github.com/vettid/vettid-relay** - the relay that replaced NATS
- **github.com/vettid/LEASH** - the agent secret-handling standard

Documents in `docs/` here describe the old design and are kept for
history. Where they disagree with vettid.org, vettid.org is correct. In
particular:

| Here (vettid-dev) | Now (vettid.org `docs/`) |
|---|---|
| `docs/protean_credential_system_design.md` | PROTEAN-CREDENTIAL.md (design and rationale); normative in VAULT-MESSAGING §3.5 |
| `docs/vettid-architecture-diagram.md` | ARCHITECTURE.md |
| `docs/SECURITY-UPDATES.md` | RELEASE-UPDATES.md (member approval, no deadlines) |
| `docs/TECH-PREVIEW.md` | TECH-PREVIEW.md |
| NATS docs and specs | RELAY-PROTOCOL.md, VAULT-MESSAGING.md |

Some operational notes and debugging diaries were removed from this final
revision; they remain in the history.

Please report security issues for current VettID code as described at
https://vettid.org/security (not in this repository).

License: unchanged (see LICENSE).
