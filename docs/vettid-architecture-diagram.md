# VettID System Architecture

This document diagrams the major components of the VettID platform and how they
interact. Every arrow represents a real communication path in the system.

---

## 1. High-Level Overview

```
                        ┌─────────────────────────────────────────────────┐
                        │                  THE INTERNET                    │
                        └──┬────────┬────────┬────────┬────────┬──────────┘
                           │        │        │        │        │
                           ▼        ▼        ▼        ▼        ▼
            ┌──────────┐┌────────┐┌──────┐┌──────────┐┌──────────────────┐
            │ vettid.  ││ admin. ││ api. ││ Mobile   ││ Desktop App      │
            │ dev      ││ vettid.││vettid││ App      ││ (Tauri/Rust/     │
            │ (Portal) ││ dev    ││ dev  ││ (iOS /   ││  Svelte)         │
            │          ││(Admin) ││      ││ Android) ││                  │
            └────┬─────┘└───┬────┘└──┬───┘└──┬───┬───┘└────┬────┬───────┘
                 │          │        │       │   │         │    │
                 │          │        │       │   │         │    │
                 ▼          ▼        ▼       ▼   │         │    │
             ┌──────────────────────────────────┐│         │    │
             │      AWS BACKEND SERVICES        ││         │    │
             │  API Gateway · Lambda · Cognito  ││         │    │
             │  DynamoDB · S3 · KMS · SES       ││         │    │
             │  CloudFront · WAF · CloudWatch   ││         │    │
             └──────────────────────────────────┘│         │    │
                                                 │         │    │
                             ┌───────────────────┘         │    │
                             │    NATS connections          │    │
                             │    (OwnerSpace +             │    │
                             │     MessageSpace)            │    │
                             │         ┌────────────────────┘    │
                             │         │    ┌────────────────────┘
                             ▼         ▼    ▼
             ┌──────────────────────────────────────────────────┐
             │           CENTRAL NATS CLUSTER                    │
             │         os.vettid.dev (OwnerSpace)                │
             │         ms.vettid.dev (MessageSpace)              │
             └──────────────────┬───────────────────────────────┘
                                │
                  ┌─────────────┼─────────────────┐
                  │             │                  │
                  ▼             ▼                  ▼
     ┌────────────────┐ ┌──────────────┐ ┌────────────────────┐
     │ NITRO ENCLAVE  │ │ Agent        │ │ Service Vault      │
     │ HOSTS          │ │ Connector    │ │ (Third-party       │
     │ (vault manager │ │ (Go sidecar  │ │  services)         │
     │  per member)   │ │  for AI      │ │                    │
     │ Only reachable │ │  agents)     │ │ Own NATS cluster   │
     │ via NATS — no  │ │              │ │ (ServiceSpace) for │
     │ direct access  │ │ localhost API│ │ inbound from users │
     └────────────────┘ │ for AI agent │ └────────────────────┘
                        └──────────────┘
```

---

## 2. vettid.dev — Web Portal

The public-facing website hosted via CloudFront + S3 static site.
This is the member's account management hub.

```
┌─────────────────────────────────────────────────────────────────────┐
│  vettid.dev (CloudFront + S3 Static Site)                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  /register      User registration (name, email → Cognito)          │
│  /enroll        Enrollment page (displays QR code for mobile scan) │
│  /signin        Member sign-in (Cognito magic link auth)           │
│  /account       Account dashboard                                   │
│                   ├── Profile (name, email — read after vault up)  │
│                   ├── Subscription management                       │
│                   ├── Vault status & controls (start/stop/delete)  │
│                   ├── Backup settings                               │
│                   ├── Credential recovery                           │
│                   └── Delete vault confirmation                     │
│  /donate        Donation page                                       │
│  /votes         Governance proposals & voting                       │
│  /help          Support / help requests                             │
│  /pcr           PCR value verification (enclave attestation)       │
│                                                                     │
│  Auth: Cognito Member User Pool (magic link, no passwords)         │
│        Optional PIN code for additional account security           │
│  API:  Calls api.vettid.dev Lambda endpoints                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. admin.vettid.dev — Admin Portal

Internal administration interface for VettID staff.

```
┌─────────────────────────────────────────────────────────────────────┐
│  admin.vettid.dev (CloudFront + S3 Static Site)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  /login         Admin sign-in (Cognito Admin User Pool)            │
│  /admin         Admin dashboard                                     │
│                   ├── Member management (lookup, support, status)   │
│                   ├── Invitation management (create, revoke)       │
│                   ├── Registration & waitlist management            │
│                   ├── Subscription oversight                        │
│                   ├── Service catalog management                    │
│                   │     ├── Add / update supported services        │
│                   │     └── Toggle service status                   │
│                   ├── Vault instance monitoring                     │
│                   ├── NATS account management                       │
│                   ├── Vote management (proposals, results)         │
│                   ├── Site management (health, metrics, comms)     │
│                   └── Audit log viewer                              │
│                                                                     │
│  Auth: Cognito Admin User Pool (separate from member pool)         │
│  API:  Calls api.vettid.dev /admin/* Lambda endpoints              │
│                                                                     │
│  Admin Types:                                                       │
│  ┌────────────────────┬────────────────────────────────────────┐   │
│  │ admin              │ Full access to all admin functions      │   │
│  ├────────────────────┼────────────────────────────────────────┤   │
│  │ user_admin         │ User & member management               │   │
│  ├────────────────────┼────────────────────────────────────────┤   │
│  │ subscriber_admin   │ Subscription & billing management      │   │
│  ├────────────────────┼────────────────────────────────────────┤   │
│  │ vote_admin         │ Governance proposals & vote management │   │
│  └────────────────────┴────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. AWS Backend Services

The serverless backbone that ties everything together.

```
┌─────────────────────────────────────────────────────────────────────┐
│  api.vettid.dev (API Gateway HTTP API)                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AUTHORIZERS                                                        │
│  ├── Member Authorizer (Cognito Member Pool JWT)                   │
│  ├── Admin Authorizer  (Cognito Admin Pool JWT)                    │
│  └── Enrollment Authorizer (session-based, cookie)                 │
│                                                                     │
│  LAMBDA HANDLER GROUPS                                              │
│  ├── /auth/*         Authentication (magic link challenge/verify)  │
│  ├── /admin/*        Admin operations (members, invites, services)  │
│  ├── /attestation/*  Device & enclave attestation verification     │
│  ├── /backup/*       Backup management (settings, restore flow)    │
│  ├── /calls/*        TURN credential generation (Cloudflare WebRTC) │
│  ├── /member/*       Member self-service (profile, settings)       │
│  ├── /nats/*         NATS account provisioning & token management  │
│  ├── /public/*       Public endpoints (register, waitlist, terms)  │
│  ├── /scheduled/*    Cron jobs (cleanup, subscription checks)      │
│  ├── /streams/*      DynamoDB stream processors                    │
│  └── /vault/*        Vault lifecycle                                │
│        ├── Enrollment (session, QR, NATS bootstrap, finalize)      │
│        ├── Attestation (Nitro PCR verify, device attestation)      │
│        ├── Health & status (vault heartbeat, health checks)        │
│        ├── Deletion (request → confirm → execute)                  │
│        ├── Transfer & recovery (device transfer, credential restore│
│        └── Agents (create/resolve shortlinks for AI agents)        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  DATA & INFRASTRUCTURE                                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Cognito                                                            │
│  ├── Member User Pool    (magic link auth, no passwords)           │
│  └── Admin User Pool     (separate pool, restricted access)        │
│                                                                     │
│  DynamoDB (25+ tables)                                              │
│  ├── Core:     invites, registrations, subscriptions, profiles     │
│  ├── Auth:     actionTokens, enrollmentSessions, magicLinkTokens   │
│  ├── Vault:    vaultInstances, vaultDeletionRequests               │
│  ├── NATS:     natsAccounts, natsTokens                            │
│  ├── Services: supportedServices                                   │
│  ├── Backup:   backups, credentialBackups, backupSettings          │
│  │             credentialRecoveryRequests, credentialTransfers      │
│  ├── Govern:   proposals, votes, membershipTerms                   │
│  └── Ops:      audit, sentEmails, commandIdempotency, helpRequests │
│                                                                     │
│  S3                                                                 │
│  ├── Static sites    (vettid.dev, admin.vettid.dev via CloudFront) │
│  ├── Terms bucket    (membership terms documents)                  │
│  └── Vault backups   (per-member encrypted backup storage)         │
│                                                                     │
│  KMS                                                                │
│  └── Backup encryption (vault backup key management)               │
│                                                                     │
│  SES                                                                │
│  ├── Magic link emails                                              │
│  ├── Enrollment invitations (with QR code)                         │
│  ├── Recovery notifications                                         │
│  └── Subscription alerts                                            │
│                                                                     │
│  CloudWatch / WAF / SNS                                             │
│  ├── API rate limiting & bot protection (WAF)                      │
│  ├── Lambda monitoring & alarms (CloudWatch)                       │
│  └── Alert notifications (SNS)                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. Central NATS Infrastructure

The messaging backbone. Handles OwnerSpace (app↔vault) and
MessageSpace (connections↔vault) communication.

```
┌─────────────────────────────────────────────────────────────────────┐
│  CENTRAL NATS CLUSTER                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  TRUST HIERARCHY (NKey / JWT Authentication)                       │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Operator: VettID                                             │ │
│  │  └── Issues Account JWTs for each member                     │ │
│  │      ├── Account: OwnerSpace.{member_guid}                   │ │
│  │      │   └── Vault holds Account NKey, issues User JWTs      │ │
│  │      └── Account: MessageSpace.{member_guid}                 │ │
│  │          └── Vault holds Account NKey, issues User JWTs      │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  os.vettid.dev — OWNERSPACE                                        │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  OwnerSpace.{member_guid}                                     │ │
│  │  ├── forVault      App → Vault    (commands, events)         │ │
│  │  ├── forApp        Vault → App    (responses, notifications) │ │
│  │  └── eventTypes    Read-only      (handler definitions)      │ │
│  │                                                               │ │
│  │  Access Control:                                              │ │
│  │  ┌────────────┬──────────┬──────────┬────────────┐           │ │
│  │  │ Actor      │ forVault │ forApp   │ eventTypes │           │ │
│  │  ├────────────┼──────────┼──────────┼────────────┤           │ │
│  │  │ Mobile App │ Write    │ Read     │ Read       │           │ │
│  │  │ Vault Mgr  │ Read     │ Write    │ Write      │           │ │
│  │  └────────────┴──────────┴──────────┴────────────┘           │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ms.vettid.dev — MESSAGESPACE                                      │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  MessageSpace.{member_guid}                                   │ │
│  │  ├── forOwner      Connections → Vault  (inbound messages)   │ │
│  │  └── ownerProfile  Vault → Public       (public profile JSON)│ │
│  │                                                               │ │
│  │  Access Control:                                              │ │
│  │  ┌──────────────────────┬──────────┬──────────────┐          │ │
│  │  │ Actor                │ forOwner │ ownerProfile  │          │ │
│  │  ├──────────────────────┼──────────┼──────────────┤          │ │
│  │  │ Vault Manager        │ Read     │ Write         │          │ │
│  │  │ Connections (w/token)│ Write    │ Read          │          │ │
│  │  └──────────────────────┴──────────┴──────────────┘          │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Nitro Enclave Host & Vault Managers

EC2 instances run a Nitro Enclave that hosts multiple vault managers.
Each member gets one vault manager process; a single enclave can
support many members. The enclave is a hardware-isolated VM with
no external network access.

```
┌─────────────────────────────────────────────────────────────────────┐
│  EC2 HOST                                                           │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  PARENT PROCESS (Go) — UNTRUSTED ZONE                        │ │
│  │  • Bridges enclave to external services via vsock            │ │
│  │  • Only sees encrypted blobs — never plaintext               │ │
│  │                                                               │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌────────────────────────┐ │ │
│  │  │ NATS Client  │ │ S3 Client   │ │ DynamoDB Client        │ │ │
│  │  │ (central)    │ │ (backups)   │ │ (identity, config)     │ │ │
│  │  └──────┬──────┘ └──────┬──────┘ └───────────┬────────────┘ │ │
│  │         │               │                     │              │ │
│  │         └───────────────┼─────────────────────┘              │ │
│  │                         │                                    │ │
│  │                   vsock (CID:16, Port:5000)                  │ │
│  │  ══════════════════════╪════════════ HARDWARE BOUNDARY ════  │ │
│  │                         │                                    │ │
│  │  ┌──────────────────────────────────────────────────────┐   │ │
│  │  │  NITRO ENCLAVE — TRUSTED ZONE (No network, no disk) │   │ │
│  │  │                                                      │   │ │
│  │  │  One enclave hosts MULTIPLE vault managers           │   │ │
│  │  │  (one per member). Each is fully isolated.           │   │ │
│  │  │                                                      │   │ │
│  │  │  ┌────────────────────────────────────────────────┐  │   │ │
│  │  │  │  VAULT MANAGER — Member A (Go)                 │  │   │ │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │   │ │
│  │  │  │  │  Core Logic                              │  │  │   │ │
│  │  │  │  │  • Authentication (protean credential)   │  │  │   │ │
│  │  │  │  │  • Personal data (CRUD, catalog)         │  │  │   │ │
│  │  │  │  │  • Secrets (minor + critical)            │  │  │   │ │
│  │  │  │  │  • Connections (invites, key exchange)    │  │  │   │ │
│  │  │  │  │  • Profile publishing (to MessageSpace)  │  │  │   │ │
│  │  │  │  │  • Messaging (E2EE text, voice/video)    │  │  │   │ │
│  │  │  │  │  • Backup orchestration (encrypt → S3)   │  │  │   │ │
│  │  │  │  │  • Event handlers (Go, sandboxed)        │  │  │   │ │
│  │  │  │  │  • Agent/AI secret handling (LEASH)      │  │  │   │ │
│  │  │  │  │  • Credential ops (CEK rotation)         │  │  │   │ │
│  │  │  │  │  • Device, location, PIN, services       │  │  │   │ │
│  │  │  │  └──────────────────────────────────────────┘  │  │   │ │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │   │ │
│  │  │  │  │  SQLite Database — Member A's data       │  │  │   │ │
│  │  │  │  │  Isolated from other members             │  │  │   │ │
│  │  │  │  │  • Personal data, minor secrets          │  │  │   │ │
│  │  │  │  │  • Connections, profile, settings, audit │  │  │   │ │
│  │  │  │  └──────────────────────────────────────────┘  │  │   │ │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │   │ │
│  │  │  │  │  Sealed Storage — Member A               │  │  │   │ │
│  │  │  │  │  PCR-bound, sealed to enclave            │  │  │   │ │
│  │  │  │  │  • CEK (Credential Encryption Key)       │  │  │   │ │
│  │  │  │  │  • Private keys (identity, connection)   │  │  │   │ │
│  │  │  │  │  • Credential blob (protean credential — │  │  │   │ │
│  │  │  │  │    contains critical secrets; only the   │  │  │   │ │
│  │  │  │  │    vault can decrypt and read them)      │  │  │   │ │
│  │  │  │  └──────────────────────────────────────────┘  │  │   │ │
│  │  │  └────────────────────────────────────────────────┘  │   │ │
│  │  │                                                      │   │ │
│  │  │  ┌────────────────────────────────────────────────┐  │   │ │
│  │  │  │  VAULT MANAGER — Member B (Go)                 │  │   │ │
│  │  │  │  (Same structure: core logic, SQLite, sealed   │  │   │ │
│  │  │  │   storage — fully isolated from Member A)      │  │   │ │
│  │  │  └────────────────────────────────────────────────┘  │   │ │
│  │  │                                                      │   │ │
│  │  │  ┌────────────────────────────────────────────────┐  │   │ │
│  │  │  │  VAULT MANAGER — Member N ...                  │  │   │ │
│  │  │  └────────────────────────────────────────────────┘  │   │ │
│  │  │                                                      │   │ │
│  │  │  ┌────────────────────────────────────────────────┐  │   │ │
│  │  │  │  EVENT HANDLERS (Go programs, sandboxed)       │  │   │ │
│  │  │  │  Included in the enclave build image           │  │   │ │
│  │  │  │  Executed in isolation per invocation:         │  │   │ │
│  │  │  │  • Read-only filesystem                       │  │   │ │
│  │  │  │  • No network (unless explicit egress)        │  │   │ │
│  │  │  │  • Resource limits (CPU, memory, time)        │  │   │ │
│  │  │  │  • Input: JSON payload only                   │  │   │ │
│  │  │  │  • Output: JSON response only                 │  │   │ │
│  │  │  └────────────────────────────────────────────────┘  │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  S3 BACKUP STORAGE (per member, separate prefix per vault mgr)     │
│  ├── Encrypted with backup key (public key on vault, private in    │
│  │   member's credential — member controls recovery)               │
│  ├── Contains: SQLite database snapshot, sealed storage snapshot   │
│  └── Triggered: manual via app, auto on vault stop, scheduled      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. VettID Mobile App (Android / iOS)

The member's primary interface. Communicates with the backend API
and with their vault via NATS OwnerSpace.

```
┌─────────────────────────────────────────────────────────────────────┐
│  VettID Mobile App (Kotlin/Compose · Swift/SwiftUI)                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LOCAL STORAGE (EncryptedSharedPreferences / Keychain)              │
│  ├── Protean Credential (encrypted blob — cannot decrypt locally)  │
│  ├── UTK pool (User Transaction Key public keys)                   │
│  ├── Device attestation (hardware-backed, serves as mutual auth)   │
│  ├── Password salt (for Argon2id hashing)                          │
│  ├── NATS connection credentials (OwnerSpace tokens)               │
│  └── Personal data cache (synced from vault)                       │
│                                                                     │
│  FEATURES                                                           │
│  ├── Enrollment                                                     │
│  │   ├── QR code scan (vettid://enroll?code=...&email=...)         │
│  │   ├── Device attestation + NATS bootstrap + connect             │
│  │   ├── Enclave attestation verification (PCR validation)         │
│  │   ├── Confirm identity (review registration profile)            │
│  │   ├── Vault PIN + DEK creation (via NATS to supervisor)        │
│  │   ├── Password setup (via NATS to vault manager)                │
│  │   ├── Credential verification (test password works)             │
│  │   └── Post-enrollment personal data collection                  │
│  │                                                                  │
│  ├── Authentication                                                 │
│  │   ├── PIN unlock (vault PIN, not device PIN)                    │
│  │   └── Protean credential cycle (CEK/TK rotation per auth)      │
│  │                                                                  │
│  ├── Personal Data (Three Locks: Personal / Secrets / Critical)    │
│  │   ├── View / add / edit personal data (synced to vault)         │
│  │   ├── Single-field & multi-field templates                      │
│  │   ├── Public profile toggle (per field)                         │
│  │   └── Category-based organization                               │
│  │                                                                  │
│  ├── Secrets (Two-Tier: Minor Secrets + Critical Secrets)          │
│  │   ├── Minor: passwords, cards, licenses, etc. (viewable in     │
│  │   │   app, only used/acted upon in the vault)                   │
│  │   ├── Critical: private keys, seed phrases (stored in           │
│  │   │   credential, only the vault can read them)                 │
│  │   └── Template-based entry (credit card, passport, etc.)       │
│  │                                                                  │
│  ├── Connections                                                    │
│  │   ├── Create invitation (QR code / deep link)                  │
│  │   ├── Scan invitation (camera → connect to MessageSpace)       │
│  │   ├── Profile review & mutual accept                            │
│  │   ├── Per-connection key exchange (stored in vault)             │
│  │   └── Contact list (synced from vault)                          │
│  │                                                                  │
│  ├── Messaging                                                      │
│  │   ├── E2EE text (per-connection keys via MessageSpace)          │
│  │   ├── E2EE voice & video calls (SFU signaling)                 │
│  │   └── Feed (notifications, audit events)                        │
│  │                                                                  │
│  ├── Services                                                       │
│  │   ├── Service directory (browse available services)             │
│  │   ├── Contract signing (review terms, sign, manage)             │
│  │   ├── Data requests (approve/deny per-field sharing)            │
│  │   └── Agent management (AI agent approvals & secret access)    │
│  │                                                                  │
│  ├── Location                                                       │
│  │   ├── Location sharing (per-connection, privacy-preserving)    │
│  │   └── Location history                                          │
│  │                                                                  │
│  └── Governance                                                     │
│      ├── View proposals                                             │
│      └── Vote on proposals                                          │
│                                                                     │
│  COMMUNICATION PATHS                                                │
│  ├── api.vettid.dev   HTTPS (enrollment, auth)                     │
│  └── os.vettid.dev    NATS  (OwnerSpace: app ↔ vault commands)    │
│  (App never connects to MessageSpace — vault handles that)         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 8. VettID Desktop App (macOS / Windows / Linux)

Desktop companion built with Tauri v2 (Rust backend, Svelte frontend).
Sessions are time-limited and capability-scoped — the phone stays
in control.

```
┌─────────────────────────────────────────────────────────────────────┐
│  VettID Desktop (Tauri v2 / Rust / Svelte)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PAIRING (one-time setup)                                           │
│  ├── QR code or short-link from mobile app                         │
│  ├── Machine fingerprinting (binary hash + platform key)           │
│  ├── X25519 key exchange with vault                                 │
│  └── Credentials encrypted at rest (ECIES + Argon2id + platform)   │
│                                                                     │
│  SESSION MODEL                                                      │
│  ├── Time-bounded sessions (auto-expiry, suspend, resume)          │
│  ├── Capability tiers:                                              │
│  │   ├── INDEPENDENT (no phone needed):                            │
│  │   │   Browse connections, read feed, view audit logs,           │
│  │   │   read messages, view secrets catalog (metadata only)       │
│  │   └── PHONE-REQUIRED (delegated approval via NATS):             │
│  │       Retrieve secrets, update credentials, approve agents,     │
│  │       modify connections, sign contracts                        │
│  └── Session token scoped to granted capabilities                  │
│                                                                     │
│  CRYPTO STACK                                                       │
│  ├── X25519          (ECDH key exchange)                           │
│  ├── XChaCha20-Poly1305 (AEAD symmetric encryption)               │
│  ├── HKDF-SHA256     (domain-separated key derivation)             │
│  ├── Argon2id        (passphrase hashing, OWASP params)            │
│  └── Zeroize         (all intermediate keys scrubbed from memory)  │
│                                                                     │
│  ARCHITECTURE                                                       │
│  Phone → NATS (E2E encrypted) → Vault Manager → NATS → Desktop    │
│  Desktop never holds the vault master key.                          │
│                                                                     │
│  COMMUNICATION PATHS                                                │
│  └── os.vettid.dev   NATS (OwnerSpace: session, commands)         │
│  (Desktop never connects to MessageSpace — vault handles that)     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. VettID Agent Connector (AI Agent Sidecar)

A Go binary that runs alongside an AI agent as a sidecar process.
The agent never touches encryption keys, NATS credentials, or raw
vault tokens.

```
┌─────────────────────────────────────────────────────────────────────┐
│  VettID Agent Connector (Go binary)                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  DEPLOYMENT MODEL                                                   │
│  ┌────────────┐  localhost     ┌──────────────┐    TLS+E2E         │
│  │            │ (Unix socket   │              │   encrypted         │
│  │  AI Agent  │  or :7443)     │ Agent        │   via NATS          │
│  │  (any LLM) │◄─────────────▶│ Connector    │◄──────────────▶     │
│  │            │ REST / WS      │ (this binary)│          Owner's   │
│  └────────────┘                └──────────────┘          Vault     │
│                                                          (Enclave) │
│  REGISTRATION FLOW                                                  │
│  1. Owner taps "Connect Agent" in mobile app                       │
│  2. Short-link generated (2-minute TTL)                            │
│  3. Operator runs: vettid-agent init vettid.dev/a/K7x9Qm          │
│  4. Connector resolves shortlink, performs key exchange             │
│  5. Owner reviews agent details in app, sets permissions           │
│  6. Owner approves → connector starts operating                    │
│                                                                     │
│  LOCAL API (for the AI agent to call)                               │
│  ├── POST /v1/secrets/request    Request a secret from the vault   │
│  ├── GET  /v1/status             Connector health check            │
│  ├── GET  /v1/requests/{id}      Poll pending request status       │
│  ├── POST /v1/connection/disconnect  Disconnect from vault         │
│  └── WS   /v1/ws                 Full-duplex for browser agents    │
│                                                                     │
│  SECURITY MODEL                                                     │
│  ├── Zero-trust for the agent   (never holds keys or NATS creds)  │
│  ├── Platform binding           (Argon2id + machine fingerprint)   │
│  ├── E2E encryption             (connection-specific X25519 keys)  │
│  ├── Owner sovereignty          (all permissions via mobile app)   │
│  ├── No secret caching          (secrets pass through, not stored) │
│  └── Instant revocation         (owner revokes from app anytime)   │
│                                                                     │
│  OWNER CONTROLS (set via mobile app)                                │
│  ├── Scope         Which secret types/names the agent can access   │
│  ├── Approval mode Auto-approve vs. manual per request             │
│  └── Rate limits   How often the agent can request secrets         │
│                                                                     │
│  CLI COMMANDS                                                       │
│  ├── vettid-agent init <shortlink>  Register with a vault          │
│  ├── vettid-agent start             Start connector + local API    │
│  ├── vettid-agent status            Show connection health         │
│  ├── vettid-agent rebind            Re-bind after hardware changes │
│  ├── vettid-agent revoke            Disconnect and clean up        │
│  └── vettid-agent version           Show version + binary hash     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Service Vault (Third-Party Integration)

The Go-based integration layer that allows external services to
connect with VettID members. Services never access the vault
directly — they communicate through NATS MessageSpaces.

```
┌─────────────────────────────────────────────────────────────────────┐
│  vettid-service-vault (Go)                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  SERVICE IDENTITY                                                   │
│  ├── Self-sovereign cryptographic identity                         │
│  │   service_id = base58(sha256(public_key))                       │
│  ├── Ed25519 signing key + X25519 encryption key                   │
│  ├── Provider-generated and controlled (no VettID dependency)      │
│  ├── Optional domain validation via DNS                            │
│  └── Optional registry registration for discoverability            │
│                                                                     │
│  COMMUNICATION MODEL                                                │
│  ┌─────────────┐                              ┌─────────────┐      │
│  │ User Vault  │                              │Service Vault│      │
│  └──────┬──────┘                              └──────┬──────┘      │
│         │                                            │             │
│         ▼                                            ▼             │
│  ┌──────────────┐        NATS Layer          ┌──────────────┐      │
│  │ VettID NATS  │◄──────────────────────────▶│ Service NATS │      │
│  │(MessageSpace)│                            │(ServiceSpace)│      │
│  └──────────────┘                            └──────────────┘      │
│                                                                     │
│  Service → User: via VettID MessageSpace (user vault controls)     │
│  User → Service: via Service's own NATS cluster (ServiceSpace)     │
│                                                                     │
│  USER CONNECTION FLOW                                               │
│  1. Service provides invitation (QR code, deep link, etc.)         │
│  2. User scans invitation in mobile app                            │
│  3. User reviews service profile and contract options              │
│  4. User accepts or rejects terms                                   │
│  5. On accept: per-connection key exchange (forward secrecy)       │
│  6. User profile shared with service per contract terms            │
│  7. User-controlled revocation at any time                          │
│                                                                     │
│  CAPABILITIES (per vault instance)                                  │
│  ├── Connection management  (invite, accept, maintain, revoke)     │
│  ├── Contract management    (terms, capabilities, signing)         │
│  ├── Data requests          (request fields per contract terms)    │
│  ├── Profile manager        (service's public profile)             │
│  └── User connection state  (tokens, key IDs, cached profiles)     │
│                                                                     │
│  KEY DIFFERENCES FROM USER VAULTS                                   │
│  ├── Handles MANY users per vault instance (not 1:1)               │
│  ├── Provides a secure API for backend integration                 │
│  ├── Event-driven communication via NATS                           │
│  └── User-controlled authorization for ALL data access             │
│                                                                     │
│  SDK (Go package for service developers)                            │
│  ├── Connection lifecycle helpers                                   │
│  ├── Crypto primitives (key exchange, encryption, signing)         │
│  ├── NATS client wrapper                                            │
│  └── Contract template builder                                      │
│  Future SDKs planned: Node.js, Python                               │
│                                                                     │
│  SECURITY PRINCIPLES                                                │
│  ├── Zero knowledge    (never accesses user credentials directly)  │
│  ├── User consent      (all data access requires explicit authz)   │
│  ├── Capability-based  (only granted actions are permitted)        │
│  ├── Message-level E2E (X25519 + XChaCha20-Poly1305)              │
│  └── Audit trail       (tamper-evident signed operation logs)      │
│                                                                     │
│  Example services:                                                  │
│  ├── Merchant    (request payment credentials per transaction)     │
│  ├── Verifier    (request government ID for KYC)                   │
│  ├── Exchange    (request crypto keys for signing)                 │
│  └── Healthcare  (request insurance ID, allergies for visit)       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. Communication Flow Diagram

How the major components talk to each other:

```
┌─────────┐        ┌──────────────┐        ┌──────────────────┐
│ Mobile   │─HTTPS─▶│ API Gateway  │─invoke─▶│ Lambda Handlers  │
│ App      │        │ api.vettid.  │        │                  │
│          │        │ dev          │        │ ┌──────────────┐ │
│          │        └──────────────┘        │ │ Cognito      │ │
│          │                                │ │ (auth)       │ │
│          │                                │ ├──────────────┤ │
│          │                                │ │ DynamoDB     │ │
│          │                                │ │ (state)      │ │
│          │                                │ ├──────────────┤ │
│          │                                │ │ KMS          │ │
│          │                                │ │ (crypto)     │ │
│          │                                │ ├──────────────┤ │
│          │                                │ │ S3           │ │
│          │                                │ │ (backups)    │ │
│          │                                │ ├──────────────┤ │
│          │                                │ │ SES          │ │
│          │                                │ │ (email)      │ │
│          │                                │ └──────────────┘ │
│          │                                └──────────────────┘
│          │
│          │        ┌──────────────────────────────────────────┐
│          │─NATS──▶│ os.vettid.dev (OwnerSpace)               │
│          │ write  │                                          │
│          │ forVlt │   OwnerSpace.{guid}.forVault              │
│          │        │         │                                 │
│          │◀─NATS──│         ▼                                 │
│          │ read   │  ┌─────────────┐                         │
│          │ forApp │  │ Vault Mgr   │──reads──▶ processes     │
│          │        │  │ (enclave)   │                         │
│          │        │  │             │──writes──▶ forApp       │
│          │        │  └──────┬──────┘                         │
│          │        └─────────┼────────────────────────────────┘
│          │                  │
│          │                  │  Vault reads & writes MessageSpace
│          │                  │  (app never connects to MessageSpace)
│          │                  │
│          │        ┌─────────┼────────────────────────────────┐
│          │        │ ms.vettid.dev (MessageSpace)             │
│          │        │         │                                │
│          │        │         ▼                                │
│          │        │  ┌─────────────┐                        │
│          │        │  │ Vault Mgr   │──writes─▶ ownerProfile │
│          │        │  │             │──reads───▶ forOwner    │
│          │        │  └─────────────┘                        │
│          │        │         ▲              ▲                 │
│          │        │         │              │                 │
│          │        │  ┌──────┴──────┐ ┌────┴──────────────┐  │
│          │        │  │ Connection  │ │ Service Vault     │  │
│          │        │  │ (other user)│ │ (merchant, etc.)  │  │
│          │        │  └─────────────┘ └───────────────────┘  │
│          │        └──────────────────────────────────────────┘
└─────────┘


Desktop App                        Agent Connector
    │                                    │
    │─NATS──▶ os.vettid.dev            │ (no direct NATS access)
    │  (OwnerSpace: session,             │
    │   scoped capabilities)             │  localhost only
    │                                    │  (Unix socket / :7443)
    │  Does NOT connect to               │         │
    │  MessageSpace (vault               │         ▼
    │  handles that)                     │  ┌──────────────┐
    │                                    │  │ AI Agent     │
    │  Phone approval required for:      │  │ (any LLM)    │
    │  secrets, credentials, agents      │  └──────────────┘
    │                                    │
    │  Independent operations:           │  Agent Connector talks to
    │  feed, connections, audit          │  vault via NATS (E2E encrypted)
    │                                    │  Agent only sees the local API


Web Portal (vettid.dev)        Admin Portal (admin.vettid.dev)
         │                              │
         │─HTTPS──▶ api.vettid.dev ◀─HTTPS──│
         │        (same API Gateway)        │
         │        (different authorizer)     │
```

---

## 12. Enrollment Flow (End to End)

```
Admin/System          vettid.dev      Mobile App     API/Lambda    Enclave/Vault
    │                    │               │               │               │
    │  1. Create invite  │               │               │               │
    │───────────────────▶│               │               │               │
    │                    │  2. POST      │               │               │
    │                    │  /admin/invite│               │               │
    │                    │──────────────────────────────▶│               │
    │                    │               │  3. Store     │               │
    │                    │               │  invite, send │               │
    │                    │               │  QR via SES   │               │
    │                    │               │               │               │
    │                    │               │  4. User scans│               │
    │                    │               │  QR code      │               │
    │                    │               │──────────────▶│               │
    │                    │               │               │               │
    │                    │               │  5. Authenticate session      │
    │                    │               │◀─────────────▶│               │
    │                    │               │  (enrollment JWT issued)      │
    │                    │               │               │               │
    │                    │               │  6. Device    │               │
    │                    │               │  attestation  │               │
    │                    │               │──────────────▶│               │
    │                    │               │               │               │
    │                    │               │  7. NATS bootstrap            │
    │                    │               │  (get credentials)            │
    │                    │               │──────────────▶│               │
    │                    │               │               │ Provision     │
    │                    │               │               │ NATS accounts │
    │                    │               │◀─────────────│ (OwnerSpace + │
    │                    │               │               │  MessageSpace)│
    │                    │               │               │               │
    │                    │               │  8. Connect to NATS           │
    │                    │               │──── via OwnerSpace ──────────▶│
    │                    │               │               │               │
    │                    │               │  9. Verify enclave attestation│
    │                    │               │◀──── via NATS ───────────────▶│
    │                    │               │  (PCR validation)             │
    │                    │               │               │               │
    │                    │               │  10. Confirm identity         │
    │                    │               │  (review name, email from     │
    │                    │               │   registration)               │
    │                    │               │               │               │
    │                    │               │  11. Create vault PIN + DEK   │
    │                    │               │──── via NATS (to supervisor) ▶│
    │                    │               │               │               │
    │                    │               │  12. Set password             │
    │                    │               │──── via NATS (to vault mgr) ─▶│
    │                    │               │  (Argon2id, encrypted w/ UTK) │
    │                    │               │               │ Create protean│
    │                    │               │               │ credential    │
    │                    │               │               │               │
    │                    │               │  13. Verify credential        │
    │                    │               │──── via NATS ────────────────▶│
    │                    │               │  (test password works)        │
    │                    │               │◀──── via NATS ───────────────│
    │                    │               │               │               │
    │                    │               │  14. Personal data collection │
    │                    │               │  (post-enrollment setup)      │
    │                    │               │               │               │
    │                    │               │  15. Finalize │               │
    │                    │               │──────────────▶│               │
    │                    │               │               │ Mark session  │
    │                    │               │               │ COMPLETED     │
    │                    │               │               │               │
    │                    │               │  ✓ ENROLLED   │               │
    │                    │               │  App connected │               │
    │                    │               │  to OwnerSpace │               │

Note: Steps 9-13 go directly between app and enclave via NATS.
Lambda never sees PIN, password, or credential data — only
receives phase-completion status updates for tracking/audit.
```

---

## 13. Connection Flow (User to User)

```
Member A (App)     MessageSpace A     MessageSpace B     Member B (App)
     │                   │                  │                  │
     │  1. Create invite │                  │                  │
     │  (QR code with    │                  │                  │
     │   URI + token)    │                  │                  │
     │                   │                  │                  │
     │  ── QR scan or link share ────────────────────────────▶│
     │                   │                  │                  │
     │                   │                  │  2. B connects  │
     │                   │  3. B reads A's  │  to MS-A        │
     │                   │◀─────────────────│◀─────────────────│
     │                   │  profile         │                  │
     │                   │                  │                  │
     │                   │  4. B delivers   │                  │
     │                   │  counter-invite  │                  │
     │  5. A reads B's   │  (URI + token    │                  │
     │  profile via MS-B │  for MS-B)       │                  │
     │──────────────────────────────────────▶                  │
     │                   │                  │                  │
     │  6. Both review profiles             │                  │
     │  7. Both accept connection           │                  │
     │                   │                  │                  │
     │  8. Key exchange (unique per-connection keypair)        │
     │◀═══════════════════════════════════════════════════════▶│
     │                   │                  │                  │
     │  9. Keys stored in respective vaults with shared keyID │
     │  10. Contact list updated in both vaults               │
     │  11. Periodic: key rotation, token refresh, profile sync│
```

---

## 14. Data Tier Summary (Three Locks)

```
┌─────────────────────────────────────────────────────────────────────┐
│  LOCK 1: PERSONAL DATA (describes you)                              │
│  Storage:  SQLite database in enclave                               │
│  Access:   PIN + contract enforcement                               │
│  Sharing:  Per-field, per-connection granularity                    │
│  Examples: Name, email, phone, address, employment, education       │
├─────────────────────────────────────────────────────────────────────┤
│  LOCK 2: SECRETS (acts on your behalf)                              │
│  Storage:  SQLite database in enclave                               │
│  Access:   PIN + contract enforcement (gated per request)           │
│  Sharing:  Connections must request access each time                │
│  Usage:    Viewable in mobile app, only used/acted upon in vault   │
│  Examples: Credit cards, driver's license, passport, bank accounts, │
│            API keys, passwords, insurance, WiFi credentials         │
├─────────────────────────────────────────────────────────────────────┤
│  LOCK 3: CRITICAL SECRETS (irreversible if exposed)                 │
│  Storage:  Inside the protean credential (encrypted blob)           │
│  Access:   Only the vault can decrypt and read them                 │
│  Sharing:  NEVER leaves the vault in plaintext                      │
│  Examples: Private keys, signing keys, seed phrases                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 15. Repository Map

```
github.com/vettid/
├── vettid-dev               Backend infrastructure
│   ├── cdk/                   AWS CDK stacks (9 stacks)
│   │   ├── lib/                 infrastructure, vettid, nats, nitro,
│   │   │                        vault, admin-management, monitoring,
│   │   │                        business-governance, extensibility
│   │   ├── lambda/              Lambda handlers (11 groups)
│   │   ├── frontend/            Static sites (vettid.dev, admin)
│   │   ├── scripts/             Deployment & ops scripts
│   │   └── tests/               CDK & Lambda tests
│   ├── enclave/               Nitro Enclave components (Go)
│   │   ├── vault-manager/       Core vault logic (auth, data,
│   │   │                        connections, messaging, secrets,
│   │   │                        agents, services)
│   │   ├── service-vault-mgr/   Service vault manager process
│   │   ├── parent/              EC2 host parent (vsock bridge)
│   │   ├── supervisor/          Enclave process supervisor
│   │   └── migration/           Data migration tooling
│   ├── packer/                AMI build (Packer + HCL)
│   ├── docs/                  Architecture docs (20+ documents)
│   └── scripts/               Ops scripts
│
├── vettid-android           Android app (Kotlin / Jetpack Compose)
│   ├── app/src/
│   │   ├── core/                crypto, storage, network, nats
│   │   ├── features/            auth, enrollment, personaldata,
│   │   │                        secrets, connections, messaging,
│   │   │                        services, agents, voting, etc.
│   │   └── ui/                  navigation, components, theme
│   └── docs/                  Mobile-specific architecture docs
│
├── vettid-ios               iOS app (Swift / SwiftUI)
│
├── vettid-desktop           Desktop companion (Tauri v2 / Rust)
│   ├── src-tauri/src/
│   │   ├── commands/            auth, session, vault IPC
│   │   ├── crypto/              argon2, ecies, hkdf, keys
│   │   ├── credential/          encrypted credential store
│   │   ├── fingerprint/         binary hash + platform key
│   │   ├── nats/                async-nats client, wire types
│   │   ├── registration/        pairing, shortlink resolution
│   │   └── session/             manager, capabilities, delegation
│   └── src/lib/               Svelte UI components
│
├── vettid-agent             Agent connector (Go sidecar)
│   ├── cmd/vettid-agent/      CLI (init, start, status, rebind,
│   │                          revoke, version)
│   └── internal/
│       ├── api/                 REST + WebSocket local API
│       ├── config/              Configuration management
│       ├── credential/          Platform-bound credential store
│       ├── crypto/              X25519, ChaCha20, Argon2id
│       ├── fingerprint/         Machine fingerprinting
│       ├── nats/                NATS client (E2E encrypted)
│       └── registration/        Shortlink, key exchange
│
├── vettid-service-vault     Third-party service integration (Go)
│   ├── vault/                 Service vault runtime
│   ├── sdk/                   Go SDK for service developers
│   ├── examples/              Example service implementations
│   ├── cdk/                   AWS CDK infrastructure (planned)
│   └── docs/                  SERVICE-VAULT-ARCHITECTURE.md
│
└── vettid-test-harness      E2E test suite (Playwright / TS)
```
