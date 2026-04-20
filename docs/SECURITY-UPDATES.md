# Vault Security Updates

VettID's user vaults run inside AWS Nitro Enclaves. Because the enclave's
measurement (PCR0) is part of the cryptographic identity that protects your
vault, any update to the enclave requires your explicit consent — the new
enclave cannot access your data until you approve the transition.

This page lists every enclave update VettID has shipped, what it contains,
and the deadline by which the transition must complete.

## How approval works

When an update is available you will see a **Vault Security Update
Available** card in your activity feed. Tapping it gives you three choices:

- **Update Now** — your device re-seals your vault under the new enclave's
  measurement. Takes a few seconds. After this you are on the new enclave.
- **Review Details** — opens this page.
- **Remind Me Later** — defers the prompt until you reopen the app. Hidden
  once the deadline passes.

The old and new enclaves run side-by-side during the transition window
(typically 72 hours). After the deadline or once everyone has migrated,
the old enclave is retired automatically.

## Update log

### 2026-04-20-v1 — Per-connection interaction history

**Deadline:** 2026-04-23

Adds a durable audit trail of your interactions with each connection:
messages sent and received, voice and video calls (including missed),
Bitcoin transfers, and connection-lifecycle events. Accessible from each
connection's Interaction History view, with search and chronological
pagination.

No behavior change for existing flows — this is an additive record that
lives inside your vault. Only you can read it.

### 2026-04-19-v4 — Self-hosted TURN rollout

**Deadline:** 2026-04-22 (superseded by 2026-04-20-v1)

Moved the TURN relay used for voice and video calls onto VettID-managed
infrastructure so no third-party relay sees call metadata. Hardened the
coturn configuration and switched the base image to Ubuntu 24.04.
