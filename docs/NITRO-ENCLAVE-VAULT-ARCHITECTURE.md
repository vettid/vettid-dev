# VettID Nitro Enclave Vault Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.2 Draft |
| Date | 2026-01-02 |
| Status | Proposal - Pending Review |
| Author | Architecture Team |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture](#2-current-architecture)
3. [Proposed Architecture](#3-proposed-architecture)
4. [Security Model](#4-security-model)
5. [Protean Credential & Trust Model](#5-protean-credential--trust-model)
6. [Component Design](#6-component-design)
7. [Data Storage & Encryption](#7-data-storage--encryption)
8. [Process Lifecycle Management](#8-process-lifecycle-management)
9. [Scaling & High Availability](#9-scaling--high-availability)
10. [Migration Strategy](#10-migration-strategy)
11. [Enclave Update & Key Migration](#11-enclave-update--key-migration)
12. [Cost Analysis](#12-cost-analysis)
13. [BYO Vault Considerations](#13-byo-vault-considerations)
14. [Implementation Phases](#14-implementation-phases)
15. [Risks & Mitigations](#15-risks--mitigations)
16. [Decision Log](#16-decision-log)

---

## 1. Executive Summary

### 1.1 Problem Statement

The current VettID vault architecture provisions a dedicated EC2 instance per user. While this provides strong isolation, it has significant drawbacks:

- **Cost**: ~$6/month per active vault (t4g.micro)
- **Resource waste**: Most vaults are idle most of the time
- **Scaling complexity**: Each vault is a separate infrastructure component
- **Startup latency**: 30-60 seconds to provision a new vault

### 1.2 Proposed Solution

Migrate to a multi-tenant vault architecture using AWS Nitro Enclaves:

- **Shared compute**: Multiple vault-manager processes run within a single Nitro Enclave
- **Per-user isolation**: Each vault has its own embedded NATS datastore with encrypted storage
- **Shared handlers**: WASM event handlers loaded once, executed in isolated contexts
- **Hardware attestation**: Users can cryptographically verify the code handling their data

### 1.3 Key Benefits

| Metric | Current | Proposed | Improvement |
|--------|---------|----------|-------------|
| Cost per vault (100 users) | $6.00/mo | $1.20/mo | **80% reduction** |
| Cost per vault (500 users) | $6.00/mo | $0.48/mo | **92% reduction** |
| Vault startup time | 30-60s | 300-500ms | **99% faster** |
| Security model | Trust VettID infra | Hardware attestation | **Stronger** |

### 1.4 Core Security Property Preserved

> **VettID has no access to user vault data.**

This property is preserved through:
- End-to-end encryption (user app ↔ enclave)
- Per-user encryption keys that never leave enclave memory
- Attestation proving exact code running in enclave
- Parent process only sees encrypted blobs

---

## 2. Current Architecture

### 2.1 Overview

```
┌─────────────┐                                    ┌─────────────────────┐
│  User App   │                                    │  User's EC2 Vault   │
│  (iOS/      │         NATS (E2E encrypted)       │  (t4g.micro)        │
│   Android)  │◄──────────────────────────────────►│                     │
│             │                                    │  ┌───────────────┐  │
│  Holds:     │                                    │  │vault-manager  │  │
│  • Vault    │                                    │  │               │  │
│    creds    │                                    │  │• NATS server  │  │
│  • Session  │                                    │  │• JetStream    │  │
│    keys     │                                    │  │• WASM runtime │  │
│             │                                    │  └───────────────┘  │
└─────────────┘                                    └─────────────────────┘
```

### 2.2 Current Components

| Component | Description | Per-User |
|-----------|-------------|----------|
| EC2 Instance | t4g.micro running vault-manager | Yes |
| Embedded NATS | Message handling + JetStream storage | Yes |
| WASM Runtime | Executes event handlers | Yes |
| EBS Volume | Persistent storage for vault data | Yes |
| Security Group | Network isolation | Yes |

### 2.3 Current Security Model

1. **Credential-based access**: User holds NATS credentials for their vault
2. **E2E encryption**: X25519 key exchange establishes session keys
3. **Physical isolation**: Separate EC2 instance per user
4. **VettID is blind**: Infrastructure routes encrypted messages only

### 2.4 Current Limitations

- **Idle resource waste**: Most vaults active <1% of time
- **No attestation**: Users must trust VettID deployed correct code
- **Slow provisioning**: EC2 launch + configuration takes 30-60 seconds
- **Complex operations**: Each vault is separate infrastructure

---

## 3. Proposed Architecture

### 3.1 High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            Nitro Enclave                                  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                      Enclave Supervisor                             │  │
│  │  • Spawns/manages vault-manager processes                           │  │
│  │  • Routes vsock messages to correct vault                           │  │
│  │  • Manages shared WASM handler cache                                │  │
│  └──────────────────────────────────┬─────────────────────────────────┘  │
│                                     │                                     │
│         ┌───────────────────────────┼───────────────────────────┐        │
│         │                           │                           │        │
│         ▼                           ▼                           ▼        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ vault-manager   │  │ vault-manager   │  │ vault-manager   │   ...    │
│  │ (User A)        │  │ (User B)        │  │ (User C)        │          │
│  │                 │  │                 │  │                 │          │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │          │
│  │ │ Embedded    │ │  │ │ Embedded    │ │  │ │ Embedded    │ │          │
│  │ │ NATS +      │ │  │ │ NATS +      │ │  │ │ NATS +      │ │          │
│  │ │ JetStream   │ │  │ │ JetStream   │ │  │ │ JetStream   │ │          │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │          │
│  │        │        │  │        │        │  │        │        │          │
│  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │          │
│  │ │ Encrypted   │ │  │ │ Encrypted   │ │  │ │ Encrypted   │ │          │
│  │ │ Storage     │ │  │ │ Storage     │ │  │ │ Storage     │ │          │
│  │ │ Adapter     │ │  │ │ Adapter     │ │  │ │ Adapter     │ │          │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │          │
│  └────────┼────────┘  └────────┼────────┘  └────────┼────────┘          │
│           │                    │                    │                    │
│           └────────────────────┴────────────────────┘                    │
│                                │                                         │
│  ┌─────────────────────────────▼─────────────────────────────────────┐  │
│  │                    Shared WASM Handler Cache                       │  │
│  │  • Handlers loaded once, shared across all vaults (read-only)     │  │
│  │  • Each execution isolated with per-vault context                 │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│                              vsock                                        │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
           ════════════════════════╪════════════════════════
                    Hardware isolation boundary
           ════════════════════════╪════════════════════════
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                           Parent EC2 Instance                             │
│                                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ NATS Client     │  │ S3 Client       │  │ vsock Router    │          │
│  │ (central        │  │ (encrypted blob │  │ (msg dispatch)  │          │
│  │  cluster)       │  │  I/O)           │  │                 │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘          │
│                                                                          │
│  CANNOT ACCESS: vault keys, plaintext data, session keys                │
│  CAN ACCESS: encrypted blobs (opaque), message routing metadata         │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Summary

| Component | Location | Shared/Per-User | Description |
|-----------|----------|-----------------|-------------|
| Enclave Supervisor | Enclave | Shared | Manages vault lifecycle, routes messages |
| vault-manager | Enclave | Per-user | Handles user's vault operations |
| Embedded NATS | Enclave | Per-user | Local message bus + JetStream storage |
| Encrypted Storage Adapter | Enclave | Per-user | Encrypts data before externalization |
| WASM Handler Cache | Enclave | Shared | Compiled handlers, read-only |
| Parent Process | EC2 Host | Shared | External I/O (NATS, S3), no key access |
| Central NATS | External | Shared | Routes messages from apps to enclaves |
| S3 Storage | External | Per-user prefix | Encrypted vault data blobs |

### 3.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   TRUST BOUNDARY: User's App + Nitro Enclave                           │
│                                                                         │
│   ┌─────────────┐                      ┌─────────────────────────────┐ │
│   │  User App   │◄────────────────────►│  Nitro Enclave              │ │
│   │             │  E2E Encrypted       │  (attestation verified)     │ │
│   │  • Holds    │                      │                             │ │
│   │    master   │                      │  • Vault DEK                │ │
│   │    secret   │                      │  • Session keys             │ │
│   │  • Verifies │                      │  • Plaintext processing     │ │
│   │    attesta- │                      │                             │ │
│   │    tion     │                      │                             │ │
│   └─────────────┘                      └─────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
          ══════════════════════════╪══════════════════════════
                      UNTRUSTED BOUNDARY
          ══════════════════════════╪══════════════════════════
                                    │
┌───────────────────────────────────▼─────────────────────────────────────┐
│                                                                         │
│   UNTRUSTED: VettID Infrastructure                                     │
│                                                                         │
│   • Parent EC2 process (routes encrypted blobs)                        │
│   • Central NATS cluster (routes encrypted messages)                   │
│   • S3 storage (stores encrypted blobs)                                │
│   • VettID operators                                                   │
│                                                                         │
│   CAN SEE: Ciphertext, metadata (user IDs, timestamps)                 │
│   CANNOT SEE: Plaintext data, encryption keys                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Model

### 4.1 Attestation Overview

AWS Nitro Enclaves provide hardware-backed attestation that cryptographically proves:

1. **Code identity**: Exact hash of code running in the enclave (PCR values)
2. **Isolation**: Code is running in a genuine Nitro Enclave
3. **Freshness**: Attestation document is recently generated

```
Attestation Document Contents:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  {                                                              │
│    "module_id": "enclave-abc123",                               │
│    "timestamp": 1704189600000,                                  │
│    "pcrs": {                                                    │
│      "0": "sha384-hash-of-enclave-image",                       │
│      "1": "sha384-hash-of-kernel",                              │
│      "2": "sha384-hash-of-application",                         │
│      "3": "sha384-hash-of-iam-role",                            │
│      ...                                                        │
│    },                                                           │
│    "public_key": "enclave-ephemeral-pubkey",                    │
│    "certificate": "aws-nitro-attestation-cert"                  │
│  }                                                              │
│                                                                 │
│  Signed by: AWS Nitro Attestation PKI                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Attestation Verification Flow

```
┌─────────────────┐                              ┌─────────────────────┐
│    User App     │                              │   Nitro Enclave     │
└────────┬────────┘                              └──────────┬──────────┘
         │                                                  │
         │  1. Bootstrap Request                            │
         │─────────────────────────────────────────────────►│
         │                                                  │
         │                                                  │ 2. Generate
         │                                                  │    attestation
         │                                                  │    document
         │                                                  │
         │  3. Attestation Document                         │
         │◄─────────────────────────────────────────────────│
         │     (signed by AWS Nitro)                        │
         │                                                  │
         │ 4. Verify:                                       │
         │    a. AWS signature valid                        │
         │    b. PCRs match expected                        │
         │       (published by VettID)                      │
         │    c. Timestamp recent                           │
         │                                                  │
         │ 5. If valid, encrypt session                     │
         │    key to enclave's pubkey                       │
         │                                                  │
         │  6. Encrypted Session Setup                      │
         │─────────────────────────────────────────────────►│
         │                                                  │
         │                                                  │ 7. Decrypt
         │                                                  │    (only this
         │                                                  │    enclave can)
         │                                                  │
         │  8. Session Established                          │
         │◄────────────────────────────────────────────────►│
         │     (E2E encrypted)                              │
         │                                                  │
```

### 4.3 PCR Publication

VettID publishes expected PCR values for each enclave release:

```
Published PCRs (example):
┌─────────────────────────────────────────────────────────────────┐
│  Release: v2.1.0                                                │
│  Date: 2026-01-15                                               │
│                                                                 │
│  PCR0: c7b2f3d8e9a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4  │
│  PCR1: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7  │
│  PCR2: d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0  │
│                                                                 │
│  Source: https://github.com/vettid/vault-enclave (auditable)   │
│  Signed: VettID Release Key                                     │
└─────────────────────────────────────────────────────────────────┘
```

User apps ship with:
- Expected PCR values for current release
- VettID's release signing key
- Ability to update PCRs via app update

### 4.4 What Attestation Guarantees

| Threat | Protected? | How |
|--------|------------|-----|
| VettID deploys malicious code | Yes | PCRs would differ, app rejects |
| VettID reads vault data | Yes | Keys only exist in enclave memory |
| AWS operator accesses data | Yes | Nitro hardware prevents memory access |
| Man-in-the-middle attack | Yes | Session encrypted to attested pubkey |
| Replay of old attestation | Yes | Timestamp + nonce validation |
| Compromised parent process | Yes | Parent never has keys, only ciphertext |

### 4.5 Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Key Hierarchy                                  │
│                                                                         │
│  User's Master Secret (held by user app only)                          │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Vault DEK = KDF(master_secret, vault_salt)                      │   │
│  │                                                                  │   │
│  │ Derived during bootstrap, stored sealed in S3                   │   │
│  │ Used to encrypt all vault data                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│         │                                                               │
│         ├──────────────────────┬──────────────────────┐                │
│         ▼                      ▼                      ▼                │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐          │
│  │ JetStream   │       │ Handler     │       │ Other vault │          │
│  │ data        │       │ state       │       │ data        │          │
│  │ (encrypted) │       │ (encrypted) │       │ (encrypted) │          │
│  └─────────────┘       └─────────────┘       └─────────────┘          │
│                                                                         │
│  Session Keys (per-connection, ephemeral)                              │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Session Key = X25519(app_ephemeral, enclave_ephemeral)          │   │
│  │                                                                  │   │
│  │ Established per-session via key exchange                        │   │
│  │ Used for E2E encryption of messages in transit                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.6 Sealed Storage

Vault DEKs must persist across enclave restarts. Nitro provides sealing:

```
Sealing (first bootstrap):

  vault_dek (32 bytes, plaintext)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Seal(vault_dek, attestation_doc)                      │
  │                                                                 │
  │ Encryption bound to:                                           │
  │   • PCR0, PCR1, PCR2 (code identity)                           │
  │                                                                 │
  │ NOT bound to:                                                   │
  │   • Instance ID                                                 │
  │   • Hardware serial number                                      │
  │   • IP address                                                  │
  │   • Time                                                        │
  └────────────────────────────────────────────────────────────────┘
       │
       ▼
  sealed_dek (ciphertext) → stored in S3


Unsealing (vault load):

  sealed_dek (from S3)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Unseal(sealed_dek)                                    │
  │                                                                 │
  │ Succeeds if and only if:                                       │
  │   • Running in genuine Nitro Enclave                           │
  │   • Current PCRs match sealed PCRs                             │
  │                                                                 │
  │ Fails if:                                                       │
  │   • Code has been modified (different PCRs)                    │
  │   • Running outside enclave                                     │
  │   • Running on non-Nitro hardware                               │
  └────────────────────────────────────────────────────────────────┘
       │
       ▼
  vault_dek (32 bytes, plaintext) → available in enclave memory
```

**Critical property**: Sealed data can be unsealed by ANY enclave running the SAME code, regardless of which physical machine or AWS account.

---

## 5. Protean Credential & Trust Model

### 5.1 The Vault as Secure Processing Environment

A critical insight drives the credential model: **the user's device is untrusted; the attested enclave is the secure environment.**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Reality Check: What's More Secure?                   │
│                                                                         │
│  Average User's Device                   Nitro Enclave                  │
│  ─────────────────────                   ─────────────                  │
│  • Outdated Android/iOS                  • Hardware-isolated memory     │
│  • Unpatched vulnerabilities             • Attested code (auditable)    │
│  • Potential malware/spyware             • No network access            │
│  • Apps with excessive permissions       • No persistent storage        │
│  • Screen readers, clipboard hijack      • Even AWS can't access        │
│  • Physical theft risk                   • Published, verifiable PCRs   │
│  • Social engineering attacks            • Code can be audited          │
│                                                                         │
│  LESS SECURE ◄─────────────────────────────────────────► MORE SECURE   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

The Protean Credential model leverages this by:
1. User holds an **encrypted credential blob** they cannot directly access
2. Credential is sent to the **attested vault** for processing
3. Vault decrypts, **challenges the user** to prove authorization
4. Vault performs **sensitive operations** (signing, key usage) in isolated memory
5. Only **results** are returned—never the raw secrets

### 5.2 Protean Credential Structure

The Protean Credential contains all user secrets, encrypted so only an attested enclave can access them:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Protean Credential                                   │
│                     (Encrypted blob user holds but can't access)         │
│                                                                         │
│  Encrypted with: Enclave's attestation-bound public key                 │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Contents (only readable inside attested enclave):              │   │
│  │                                                                  │   │
│  │  identity_keypair: {                                            │   │
│  │    private_key: [32 bytes],   // Ed25519 - vault authentication │   │
│  │    public_key: [32 bytes]     // Also serves as user identifier │   │
│  │  }                                                              │   │
│  │                                                                  │   │
│  │  vault_master_secret: [32 bytes]  // For vault DEK derivation   │   │
│  │                                                                  │   │
│  │  crypto_keys: [                   // User's critical secrets    │   │
│  │    {                                                            │   │
│  │      label: "btc_main",                                         │   │
│  │      type: "secp256k1",                                         │   │
│  │      private_key: [32 bytes]                                    │   │
│  │    },                                                           │   │
│  │    {                                                            │   │
│  │      label: "eth_primary",                                      │   │
│  │      type: "secp256k1",                                         │   │
│  │      private_key: [32 bytes]                                    │   │
│  │    },                                                           │   │
│  │    {                                                            │   │
│  │      label: "signing_key",                                      │   │
│  │      type: "ed25519",                                           │   │
│  │      private_key: [32 bytes]                                    │   │
│  │    }                                                            │   │
│  │  ]                                                              │   │
│  │                                                                  │   │
│  │  seed_phrases: [                                                │   │
│  │    {                                                            │   │
│  │      label: "wallet_backup",                                    │   │
│  │      words: "word1 word2 word3 ... word24"                      │   │
│  │    }                                                            │   │
│  │  ]                                                              │   │
│  │                                                                  │   │
│  │  challenge_config: {              // Authorization requirements │   │
│  │    pin_hash: [32 bytes],          // Argon2id hash of PIN       │   │
│  │    pin_salt: [16 bytes],                                        │   │
│  │    biometric_binding: [32 bytes], // Optional device binding    │   │
│  │    required_factors: 1,           // 1 = PIN only, 2 = PIN+bio  │   │
│  │    max_attempts: 5,                                             │   │
│  │    lockout_duration: 300          // Seconds                    │   │
│  │  }                                                              │   │
│  │                                                                  │   │
│  │  metadata: {                                                    │   │
│  │    version: 1,                                                  │   │
│  │    created_at: "2026-01-02T12:00:00Z",                          │   │
│  │    owner_space_id: "user-ABC123..."                             │   │
│  │  }                                                              │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  User's device sees: Opaque encrypted blob (cannot decrypt)            │
│  Attested enclave sees: All secrets (after user passes challenge)      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Why Device-Side Storage is Unsafe

Most users do not run hardened operating systems. Their devices are vulnerable:

| Threat | Device Risk | Vault (Enclave) Risk |
|--------|-------------|----------------------|
| Malware/spyware | Key stolen from memory/storage | Gets encrypted blob (useless) |
| Screen capture | Key visible during use | Only encrypted blob shown |
| Memory dump | Key extractable from RAM | Key never on device |
| Physical theft | Key accessible if device unlocked | Need to pass challenge |
| Fake/malicious app | Key stolen by impersonator | Attestation verification fails |
| Clipboard hijack | Key copied by malware | Key never in clipboard |
| Root exploit | Full key access | Blob encrypted, no key access |

**The vault is the "known good environment."** Secrets should only exist in plaintext inside the attested enclave.

### 5.4 Single Credential Model

The Protean Credential replaces multiple separate credentials:

| Old Model | New Model |
|-----------|-----------|
| NATS credentials (vault access) | Identity keypair in credential |
| Vault credential (master secret) | Vault master secret in credential |
| Separate BTC wallet | BTC keys in credential |
| Separate seed phrase backup | Seed phrases in credential |

**One credential holds everything**, encrypted so only the vault can access it.

### 5.5 Challenge Flow (User Authorization)

Before the vault uses any secrets, it challenges the user to prove authorization:

```
┌─────────────────┐                              ┌─────────────────────────┐
│  User's Device  │                              │   Nitro Enclave         │
│  (Untrusted)    │                              │   (Attested Vault)      │
└────────┬────────┘                              └────────────┬────────────┘
         │                                                    │
         │  1. Connect + request attestation                  │
         │───────────────────────────────────────────────────►│
         │                                                    │
         │  2. Attestation document                           │
         │◄───────────────────────────────────────────────────│
         │     (signed by AWS Nitro)                          │
         │                                                    │
         │  3. Verify attestation                             │
         │     • AWS signature valid?                         │
         │     • PCRs match published values?                 │
         │     • Timestamp recent?                            │
         │                                                    │
         │  4. Send encrypted credential + operation request  │
         │───────────────────────────────────────────────────►│
         │     {                                              │
         │       credential: <encrypted blob>,                │
         │       operation: "sign_btc_transaction",           │
         │       params: { tx_data: "..." }                   │
         │     }                                              │
         │                                                    │
         │                                      5. Decrypt credential
         │                                         Extract challenge_config
         │                                                    │
         │  6. Challenge request                              │
         │◄───────────────────────────────────────────────────│
         │     {                                              │
         │       type: "pin",                                 │
         │       nonce: "random-challenge-id",                │
         │       attempts_remaining: 5                        │
         │     }                                              │
         │                                                    │
         │  7. User enters PIN                                │
         │     (displayed on device, sent to enclave)         │
         │                                                    │
         │  8. Challenge response                             │
         │───────────────────────────────────────────────────►│
         │     {                                              │
         │       pin: "******",                               │
         │       nonce: "random-challenge-id"                 │
         │     }                                              │
         │                                                    │
         │                                      9. Verify PIN:
         │                                         hash = Argon2id(pin, salt)
         │                                         Compare to pin_hash
         │                                                    │
         │                                      10. If valid:
         │                                          • Load BTC key from cred
         │                                          • Sign transaction
         │                                          • Zero key from memory
         │                                          • Return signature
         │                                                    │
         │  11. Operation result                              │
         │◄───────────────────────────────────────────────────│
         │     {                                              │
         │       success: true,                               │
         │       signature: "3045022100..."                   │
         │     }                                              │
         │     (NOT the key, just the signature)              │
         │                                                    │
```

### 5.6 BTC Transaction Signing Example

```
Complete BTC Signing Flow:
──────────────────────────

1. User initiates transaction in app
   └─ App constructs unsigned transaction

2. App sends to vault:
   {
     credential: <encrypted protean credential>,
     operation: "sign_btc",
     params: {
       key_label: "btc_main",
       tx_hash: "abc123...",
       input_index: 0,
       sighash_type: "ALL"
     }
   }

3. Enclave decrypts credential
   └─ BTC private key now exists ONLY in enclave memory

4. Enclave sends challenge
   └─ { type: "pin", nonce: "xyz789" }

5. User enters PIN on device
   └─ PIN sent to enclave (not stored on device)

6. Enclave verifies PIN against credential's pin_hash
   └─ Argon2id(pin, salt) == pin_hash ?

7. If PIN valid:
   └─ Enclave signs transaction with BTC key
   └─ signature = secp256k1_sign(btc_private_key, tx_hash)

8. Enclave zeros BTC key from memory
   └─ Key existed only for milliseconds

9. Enclave returns signature
   └─ { signature: "3045022100..." }

10. App broadcasts signed transaction
    └─ Private key NEVER existed on device


What attacker gets if device is fully compromised:
──────────────────────────────────────────────────
• Encrypted credential blob → Useless without enclave
• Transaction data → Public anyway
• Cannot extract BTC key → Never on device
• Cannot forge signatures → Need to pass PIN challenge
• Cannot replay challenge → Nonce is single-use
```

### 5.7 Credential Creation & Encryption Model

**Critical**: The Protean Credential is created INSIDE the enclave, not on the device. The device cannot be trusted to generate cryptographic secrets.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  Credential Creation (Enrollment Flow)                   │
│                                                                         │
│  ┌─────────────────┐                        ┌─────────────────────────┐ │
│  │  User's Device  │                        │   Nitro Enclave         │ │
│  │  (Untrusted)    │                        │   (Trusted)             │ │
│  └────────┬────────┘                        └────────────┬────────────┘ │
│           │                                              │              │
│           │  1. Request attestation                      │              │
│           │─────────────────────────────────────────────►│              │
│           │                                              │              │
│           │  2. Attestation document                     │              │
│           │◄─────────────────────────────────────────────│              │
│           │     (signed by AWS Nitro, includes pubkey)   │              │
│           │                                              │              │
│           │  3. VERIFY attestation locally:              │              │
│           │     • AWS signature valid?                   │              │
│           │     • PCRs match published values?           │              │
│           │     • Timestamp recent?                      │              │
│           │                                              │              │
│           │  4. Send PIN (encrypted to attested pubkey)  │              │
│           │─────────────────────────────────────────────►│              │
│           │     { encrypted_pin: "..." }                 │              │
│           │                                              │              │
│           │                            5. ENCLAVE GENERATES ALL SECRETS:│
│           │                               • Identity keypair (Ed25519) │
│           │                               • Vault master secret        │
│           │                               • PIN hash = Argon2id(pin)   │
│           │                               • Empty crypto_keys[]        │
│           │                                              │              │
│           │                            6. ENCLAVE CREATES credential   │
│           │                                              │              │
│           │                            7. ENCLAVE SEALS credential     │
│           │                               (bound to PCRs)              │
│           │                                              │              │
│           │                            8. ENCLAVE INITIALIZES vault    │
│           │                               (derives DEK, creates streams)│
│           │                                              │              │
│           │  9. Return encrypted credential blob         │              │
│           │◄─────────────────────────────────────────────│              │
│           │     (opaque - device CANNOT decrypt)         │              │
│           │                                              │              │
│           │  10. Store blob locally                      │              │
│           │      (holding data you can't access)         │              │
│           │                                              │              │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  What device provides:     What enclave generates:                      │
│  ─────────────────────     ───────────────────────                      │
│  • PIN (user types it)     • Identity keypair                           │
│  • Cognito JWT (identity)  • Vault master secret                        │
│  • Operation requests      • All cryptographic keys                     │
│                            • PIN hash + salt                            │
│                            • Credential structure                       │
│                                                                         │
│  The device is a DUMB TRANSPORT for encrypted blobs and user inputs.   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.8 Adding Keys to Credential

When the user wants to add a new key (e.g., BTC private key), two options:

**Option A: Import existing key** (key briefly visible on device during import)
```
User sends: { credential, operation: "import_key", private_key: "..." }
Enclave:    Decrypts credential → challenges PIN → adds key → re-encrypts
Returns:    New encrypted credential blob (user replaces old blob)
```

**Option B: Generate key in enclave** (key NEVER leaves enclave - more secure)
```
User sends: { credential, operation: "generate_key", type: "secp256k1", label: "btc" }
Enclave:    Decrypts credential → challenges PIN → generates key internally → re-encrypts
Returns:    New encrypted credential blob + PUBLIC KEY/ADDRESS only
```

For maximum security, Option B is preferred - private keys are generated inside the enclave and never exist anywhere else.

### 5.9 Credential Sealing

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Credential Sealing                                   │
│                                                                         │
│  Sealing (after credential creation):                                   │
│  ────────────────────────────────────                                   │
│                                                                         │
│    credential (plaintext, in enclave memory)                           │
│         │                                                               │
│         ▼                                                               │
│    ┌────────────────────────────────────────────────────────────────┐  │
│    │ NitroKMS.Seal(credential, attestation_doc)                     │  │
│    │                                                                 │  │
│    │ Encryption bound to:                                           │  │
│    │   • PCR0, PCR1, PCR2 (code identity)                           │  │
│    │                                                                 │  │
│    │ NOT bound to:                                                   │  │
│    │   • Instance ID (any enclave with same code can unseal)        │  │
│    │   • User identity (credential itself has identity keypair)     │  │
│    └────────────────────────────────────────────────────────────────┘  │
│         │                                                               │
│         ▼                                                               │
│    sealed_credential (ciphertext) → returned to device                 │
│                                                                         │
│                                                                         │
│  Unsealing (on each vault operation):                                   │
│  ────────────────────────────────────                                   │
│                                                                         │
│    sealed_credential (from device)                                     │
│         │                                                               │
│         ▼                                                               │
│    ┌────────────────────────────────────────────────────────────────┐  │
│    │ NitroKMS.Unseal(sealed_credential)                             │  │
│    │                                                                 │  │
│    │ Succeeds if and only if:                                       │  │
│    │   • Running in genuine Nitro Enclave                           │  │
│    │   • Current PCRs match sealed PCRs                             │  │
│    │                                                                 │  │
│    │ Fails if:                                                       │  │
│    │   • Code has been modified                                      │  │
│    │   • Running outside enclave                                     │  │
│    │   • Credential was tampered with                                │  │
│    └────────────────────────────────────────────────────────────────┘  │
│         │                                                               │
│         ▼                                                               │
│    credential (plaintext) → available in enclave memory only           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.10 Security Properties

| Property | How Achieved |
|----------|--------------|
| **Secrets never on device** | Credential encrypted; only enclave decrypts |
| **VettID cannot access** | No access to enclave memory; attestation proves code |
| **User must authorize** | PIN/challenge required before secret use |
| **Replay protection** | Nonce in each challenge; single-use |
| **Brute force protection** | Argon2id + attempt limits + lockout |
| **Key usage is auditable** | Vault logs all operations (encrypted) |
| **Portable across devices** | Same credential works on any device |
| **Works with BYO vault** | Same model, user's own enclave |

### 5.11 Simplified Credential vs Two-Credential Model

The Protean Credential consolidates what was previously separate:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  OLD MODEL (Two Credentials)          NEW MODEL (Single Protean Cred)  │
│  ────────────────────────────          ───────────────────────────────  │
│                                                                         │
│  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
│  │ Vault Services Cred     │          │ Protean Credential          │  │
│  │ • NATS JWT              │          │                             │  │
│  │ • NATS NKey             │    ──►   │ Contains ALL:               │  │
│  │                         │          │ • Identity keypair          │  │
│  └─────────────────────────┘          │ • Vault master secret       │  │
│                                       │ • BTC/ETH keys              │  │
│  ┌─────────────────────────┐          │ • Seed phrases              │  │
│  │ Vault Credential        │          │ • Signing keys              │  │
│  │ • Master secret         │    ──►   │ • Challenge config          │  │
│  │                         │          │                             │  │
│  └─────────────────────────┘          │ Single encrypted blob       │  │
│                                       │ User holds but can't access │  │
│  + Separate wallet apps               └─────────────────────────────┘  │
│  + Separate seed backups                                               │
│                                                                         │
│  COMPLEXITY: High                      COMPLEXITY: Low                 │
│  SECURITY: Secrets on device           SECURITY: Secrets in vault only│
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Component Design

### 6.1 Enclave Supervisor

The supervisor is the main process inside the enclave:

```go
type EnclaveSupervisor struct {
    // Active vault-manager processes
    vaults map[string]*VaultProcess

    // Shared resources
    handlerCache *WASMHandlerCache

    // Configuration
    maxActiveVaults int

    // Communication
    vsock *VsockListener
}

// Main entry point
func (s *EnclaveSupervisor) Run() {
    // Listen for messages from parent
    for msg := range s.vsock.Messages() {
        switch msg.Type {
        case "vault_message":
            s.routeToVault(msg.OwnerSpace, msg.Payload)
        case "handler_update":
            s.handlerCache.Update(msg.HandlerID, msg.WASMBytes)
        case "health_check":
            s.respondHealthCheck(msg)
        }
    }
}

func (s *EnclaveSupervisor) routeToVault(ownerSpace string, payload []byte) {
    vault, exists := s.vaults[ownerSpace]

    if !exists {
        // Start new vault-manager
        vault = s.startVault(ownerSpace)
    }

    vault.HandleMessage(payload)
}
```

### 6.2 Vault Manager Process

Each user has a dedicated vault-manager:

```go
type VaultManager struct {
    ownerSpace     string

    // Per-user keys (never leave enclave)
    vaultDEK       [32]byte
    sessionKey     [32]byte

    // Per-user embedded NATS
    natsServer     *nats.Server
    jetStream      nats.JetStreamContext

    // Encrypted storage (data leaves enclave encrypted)
    storage        *EncryptedStorageAdapter

    // Reference to shared handler cache
    handlerCache   *WASMHandlerCache
}

func (vm *VaultManager) HandleMessage(encrypted []byte) {
    // 1. Decrypt with session key
    plaintext := vm.decrypt(encrypted)

    // 2. Parse event
    var event Event
    json.Unmarshal(plaintext, &event)

    // 3. Process based on event type
    result := vm.processEvent(event)

    // 4. Encrypt response
    response := vm.encrypt(result)

    // 5. Send back via vsock
    vm.respond(response)
}

func (vm *VaultManager) processEvent(event Event) []byte {
    // Get handler from shared cache
    handler := vm.handlerCache.Get(event.Type)

    // Create isolated WASM instance for execution
    instance := handler.NewInstance(WASMConfig{
        MemoryLimit: 128 * 1024 * 1024,
        CPULimit:    time.Second,
    })

    // Inject vault context (this vault only)
    instance.SetContext(VaultContext{
        OwnerSpace: vm.ownerSpace,
        NATS:       vm.jetStream,
        Storage:    vm.storage,
    })

    // Execute handler
    return instance.Call("handle", event)
}
```

### 6.3 Encrypted Storage Adapter

Bridges JetStream to external storage:

```go
type EncryptedStorageAdapter struct {
    vaultDEK   [32]byte
    ownerSpace string

    // In-memory cache for hot data
    cache      *LRUCache

    // vsock for external I/O
    vsock      *VsockConn
}

// Called by JetStream to persist data
func (e *EncryptedStorageAdapter) Put(key string, data []byte) error {
    // 1. Generate random nonce
    nonce := make([]byte, 12)
    rand.Read(nonce)

    // 2. Encrypt with vault DEK
    aead, _ := chacha20poly1305.New(e.vaultDEK[:])
    ciphertext := aead.Seal(nil, nonce, data, []byte(key))

    // 3. Prepend nonce
    blob := append(nonce, ciphertext...)

    // 4. Update local cache
    e.cache.Set(key, data)

    // 5. Send to parent for S3 storage
    return e.vsock.Send(StorageRequest{
        Op:         "PUT",
        OwnerSpace: e.ownerSpace,
        Key:        key,
        Data:       blob,
    })
}

// Called by JetStream to retrieve data
func (e *EncryptedStorageAdapter) Get(key string) ([]byte, error) {
    // 1. Check cache
    if data, ok := e.cache.Get(key); ok {
        return data, nil
    }

    // 2. Request from parent
    resp, err := e.vsock.Request(StorageRequest{
        Op:         "GET",
        OwnerSpace: e.ownerSpace,
        Key:        key,
    })
    if err != nil {
        return nil, err
    }

    // 3. Decrypt
    nonce := resp.Data[:12]
    ciphertext := resp.Data[12:]

    aead, _ := chacha20poly1305.New(e.vaultDEK[:])
    plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(key))
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }

    // 4. Cache and return
    e.cache.Set(key, plaintext)
    return plaintext, nil
}
```

### 6.4 Shared WASM Handler Cache

```go
type WASMHandlerCache struct {
    handlers map[string]*CompiledHandler
    mu       sync.RWMutex
    runtime  wazero.Runtime
}

type CompiledHandler struct {
    HandlerID  string
    Module     wazero.CompiledModule
    Signature  []byte  // Verified before adding to cache
    LoadedAt   time.Time
}

func (c *WASMHandlerCache) Get(handlerID string) *CompiledHandler {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.handlers[handlerID]
}

func (c *WASMHandlerCache) Update(handlerID string, wasmBytes []byte, signature []byte) error {
    // 1. Verify signature
    if !verifySignature(wasmBytes, signature, trustedSigningKey) {
        return errors.New("invalid handler signature")
    }

    // 2. Compile WASM module
    compiled, err := c.runtime.CompileModule(context.Background(), wasmBytes)
    if err != nil {
        return err
    }

    // 3. Add to cache
    c.mu.Lock()
    defer c.mu.Unlock()

    c.handlers[handlerID] = &CompiledHandler{
        HandlerID: handlerID,
        Module:    compiled,
        Signature: signature,
        LoadedAt:  time.Now(),
    }

    return nil
}

// NewInstance creates an isolated execution instance
func (h *CompiledHandler) NewInstance(config WASMConfig) *WASMInstance {
    // Each call gets isolated memory and state
    return &WASMInstance{
        module:      h.Module,
        memoryLimit: config.MemoryLimit,
        cpuLimit:    config.CPULimit,
    }
}
```

### 6.5 Parent Process

Runs on the EC2 host outside the enclave:

```go
type ParentProcess struct {
    // External connections
    natsConn    *nats.Conn     // To central NATS cluster
    s3Client    *s3.Client     // For blob storage

    // Enclave communication
    vsock       *VsockConn     // To enclave

    // Routing
    routingTable map[string]string  // ownerSpace → enclave vsock CID
}

func (p *ParentProcess) Run() {
    // Subscribe to vault messages from central NATS
    p.natsConn.Subscribe("vault.>", func(msg *nats.Msg) {
        // Extract owner space from subject
        ownerSpace := extractOwnerSpace(msg.Subject)

        // Forward to enclave (message is E2E encrypted, we can't read it)
        p.vsock.Send(EnclaveMessage{
            Type:       "vault_message",
            OwnerSpace: ownerSpace,
            Payload:    msg.Data,  // Opaque ciphertext
            ReplyTo:    msg.Reply,
        })
    })

    // Handle storage requests from enclave
    go p.handleStorageRequests()

    // Handle responses from enclave
    go p.handleEnclaveResponses()
}

func (p *ParentProcess) handleStorageRequests() {
    for req := range p.vsock.StorageRequests() {
        switch req.Op {
        case "PUT":
            // Store encrypted blob in S3
            key := fmt.Sprintf("vaults/%s/%s", req.OwnerSpace, req.Key)
            p.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
                Bucket: aws.String("vettid-vault-data"),
                Key:    aws.String(key),
                Body:   bytes.NewReader(req.Data),  // Opaque ciphertext
            })
        case "GET":
            // Retrieve encrypted blob from S3
            key := fmt.Sprintf("vaults/%s/%s", req.OwnerSpace, req.Key)
            result, _ := p.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
                Bucket: aws.String("vettid-vault-data"),
                Key:    aws.String(key),
            })
            data, _ := io.ReadAll(result.Body)
            p.vsock.SendStorageResponse(req.ID, data)  // Opaque ciphertext
        }
    }
}
```

---

## 7. Data Storage & Encryption

### 7.1 Storage Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            S3 Bucket                                     │
│                        vettid-vault-data                                 │
│                                                                         │
│  vaults/                                                                │
│  ├── user-ABC123/                                                       │
│  │   ├── sealed_dek.bin           # Sealed vault DEK                   │
│  │   ├── jetstream/                                                     │
│  │   │   ├── EVENTS/                                                    │
│  │   │   │   ├── 00000001.enc     # Encrypted stream data              │
│  │   │   │   ├── 00000002.enc                                          │
│  │   │   │   └── meta.enc         # Encrypted stream metadata          │
│  │   │   ├── VAULT_KV/                                                  │
│  │   │   │   ├── data.enc                                               │
│  │   │   │   └── meta.enc                                               │
│  │   │   └── HANDLERS/                                                  │
│  │   │       └── ...                                                    │
│  │   └── state/                                                         │
│  │       └── vault_state.enc      # Encrypted vault state              │
│  │                                                                      │
│  ├── user-DEF456/                                                       │
│  │   └── ...                                                            │
│  │                                                                      │
│  └── user-GHI789/                                                       │
│      └── ...                                                            │
│                                                                         │
│  handlers/                          # Shared, not encrypted             │
│  ├── backup.wasm                                                        │
│  ├── backup.wasm.sig                                                    │
│  ├── sync.wasm                                                          │
│  └── sync.wasm.sig                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Encryption Specification

| Data Type | Algorithm | Key | Nonce |
|-----------|-----------|-----|-------|
| Vault data (JetStream) | ChaCha20-Poly1305 | Vault DEK | Random 12 bytes per write |
| Sealed DEK | AWS Nitro KMS | Nitro Attestation | Internal |
| Session messages | ChaCha20-Poly1305 | Session Key | Random 12 bytes per message |

### 7.3 Blob Format

```
Encrypted Blob Format:
┌────────────────────────────────────────────────────────────────┐
│  Nonce (12 bytes)  │  Ciphertext (variable)  │  Tag (16 bytes) │
└────────────────────────────────────────────────────────────────┘

Additional Authenticated Data (AAD): Object key (path in S3)
```

### 7.4 S3 Configuration

```typescript
const vaultDataBucket = new s3.Bucket(this, 'VaultDataBucket', {
  bucketName: 'vettid-vault-data',

  // Server-side encryption (defense in depth, not primary protection)
  encryption: s3.BucketEncryption.S3_MANAGED,

  // Versioning for recovery
  versioned: true,

  // Lifecycle rules
  lifecycleRules: [
    {
      id: 'cleanup-old-versions',
      noncurrentVersionExpiration: Duration.days(30),
    },
  ],

  // Block public access
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,

  // Access logging
  serverAccessLogsBucket: logBucket,
  serverAccessLogsPrefix: 'vault-data-access/',
});
```

---

## 8. Process Lifecycle Management

### 8.1 Vault Lifecycle States

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Vault Lifecycle                                   │
│                                                                         │
│                           ┌─────────┐                                   │
│                           │ INITIAL │                                   │
│                           └────┬────┘                                   │
│                                │                                        │
│                    First bootstrap request                              │
│                                │                                        │
│                                ▼                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      BOOTSTRAPPING                              │   │
│   │                                                                 │   │
│   │  1. Generate vault DEK from master secret                      │   │
│   │  2. Seal DEK with Nitro attestation                            │   │
│   │  3. Store sealed DEK in S3                                     │   │
│   │  4. Initialize embedded NATS + JetStream                       │   │
│   │  5. Create initial streams                                     │   │
│   │  6. Establish session with app                                 │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                │                                        │
│                                ▼                                        │
│                          ┌──────────┐                                   │
│              ┌──────────►│  ACTIVE  │◄──────────┐                      │
│              │           └────┬─────┘           │                      │
│              │                │                 │                      │
│         Load from        Idle timeout      Message                    │
│         evicted          (optional)        received                   │
│              │                │                 │                      │
│              │                ▼                 │                      │
│              │          ┌──────────┐            │                      │
│              └──────────┤  EVICTED │────────────┘                      │
│                         └────┬─────┘                                   │
│                              │                                         │
│                         User deletes                                   │
│                           account                                      │
│                              │                                         │
│                              ▼                                         │
│                         ┌─────────┐                                    │
│                         │ DELETED │                                    │
│                         └─────────┘                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Active → Evicted Transition

```go
func (s *EnclaveSupervisor) evictVault(ownerSpace string) error {
    vault := s.vaults[ownerSpace]

    // 1. Stop accepting new messages
    vault.SetDraining(true)

    // 2. Wait for in-flight operations (with timeout)
    vault.WaitForDrain(5 * time.Second)

    // 3. Flush all pending writes to S3
    if err := vault.storage.Flush(); err != nil {
        return err
    }

    // 4. Shutdown embedded NATS gracefully
    vault.natsServer.Shutdown()

    // 5. Clear sensitive data from memory
    vault.ZeroizeKeys()

    // 6. Remove from active map
    delete(s.vaults, ownerSpace)

    log.Info().
        Str("owner_space", ownerSpace).
        Msg("Vault evicted successfully")

    return nil
}
```

### 8.3 Evicted → Active Transition (Cold Start)

```go
func (s *EnclaveSupervisor) loadVault(ownerSpace string) (*VaultManager, error) {
    startTime := time.Now()

    // 1. Load sealed DEK from S3 (via parent)
    sealedDEK, err := s.loadSealedDEK(ownerSpace)
    if err != nil {
        return nil, fmt.Errorf("failed to load sealed DEK: %w", err)
    }
    // Latency: ~50-100ms

    // 2. Unseal DEK using Nitro KMS
    vaultDEK, err := nitro.Unseal(sealedDEK)
    if err != nil {
        return nil, fmt.Errorf("failed to unseal DEK: %w", err)
    }
    // Latency: ~5-10ms

    // 3. Create encrypted storage adapter
    storage := NewEncryptedStorageAdapter(vaultDEK, ownerSpace, s.vsock)

    // 4. Start embedded NATS with custom storage backend
    natsServer, err := startEmbeddedNATS(storage)
    if err != nil {
        return nil, fmt.Errorf("failed to start NATS: %w", err)
    }
    // Latency: ~20-50ms

    // 5. Load JetStream metadata and indexes
    js, err := natsServer.JetStream()
    if err != nil {
        return nil, fmt.Errorf("failed to get JetStream context: %w", err)
    }
    // Latency: ~100-300ms (depends on stream count)

    // 6. Create vault manager
    vault := &VaultManager{
        ownerSpace:   ownerSpace,
        vaultDEK:     vaultDEK,
        natsServer:   natsServer,
        jetStream:    js,
        storage:      storage,
        handlerCache: s.handlerCache,
        lastActivity: time.Now(),
    }

    // 7. Add to active map
    s.vaults[ownerSpace] = vault

    log.Info().
        Str("owner_space", ownerSpace).
        Dur("cold_start_ms", time.Since(startTime)).
        Msg("Vault loaded successfully")

    return vault, nil
    // Total latency: ~300-500ms
}
```

### 8.4 Memory Management

```go
const (
    // Memory budget
    EnclaveMemory      = 12 * 1024 * 1024 * 1024  // 12 GB
    SupervisorOverhead = 200 * 1024 * 1024         // 200 MB
    HandlerCacheSize   = 500 * 1024 * 1024         // 500 MB
    PerVaultMemory     = 70 * 1024 * 1024          // 70 MB

    // Calculated max vaults
    AvailableForVaults = EnclaveMemory - SupervisorOverhead - HandlerCacheSize
    MaxActiveVaults    = AvailableForVaults / PerVaultMemory  // ~161
)

type MemoryManager struct {
    currentUsage   int64
    maxUsage       int64
    vaultSizes     map[string]int64
}

func (m *MemoryManager) CanLoadVault() bool {
    return m.currentUsage + PerVaultMemory < m.maxUsage
}

func (m *MemoryManager) ShouldEvict() bool {
    return m.currentUsage > m.maxUsage * 0.9  // 90% threshold
}
```

---

## 9. Scaling & Deployment

### 9.1 Initial Deployment (Single Region, Minimal Cost)

For development and early testing, we use a simplified single-region deployment with minimal infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AWS Region (us-east-1)                          │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                       Enclave ASG                                │   │
│  │                       min: 1, max: 3                             │   │
│  │                                                                  │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │              Enclave Instance (c6a.xlarge)              │    │   │
│  │  │                                                         │    │   │
│  │  │  ┌───────────────────────────────────────────────────┐  │    │   │
│  │  │  │              Nitro Enclave                        │  │    │   │
│  │  │  │                                                   │  │    │   │
│  │  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │  │    │   │
│  │  │  │  │ Vault A     │ │ Vault B     │ │ Vault C     │  │  │    │   │
│  │  │  │  │ (user-123)  │ │ (user-456)  │ │ (user-789)  │  │  │    │   │
│  │  │  │  └─────────────┘ └─────────────┘ └─────────────┘  │  │    │   │
│  │  │  │                       ...                         │  │    │   │
│  │  │  └───────────────────────────────────────────────────┘  │    │   │
│  │  │                                                         │    │   │
│  │  │  Parent Process ◄──► vsock ◄──► Enclave                │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │
│  │ S3 (vault data) │  │ Lambda (routing)│  │ Central NATS    │        │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Initial Auto-Scaling Configuration

```typescript
const enclaveASG = new autoscaling.AutoScalingGroup(this, 'EnclaveASG', {
  vpc,
  instanceType: ec2.InstanceType.of(ec2.InstanceClass.C6A, ec2.InstanceSize.XLARGE),
  machineImage: enclaveAMI,

  minCapacity: 1,  // Single instance for dev/testing
  maxCapacity: 3,  // Allow scaling for load testing

  healthCheck: autoscaling.HealthCheck.ec2({
    grace: Duration.minutes(5),
  }),
});

// Simple CPU-based scaling for initial deployment
enclaveASG.scaleOnCpuUtilization('CPUScaling', {
  targetUtilizationPercent: 70,
  cooldown: Duration.minutes(5),
});
```

### 9.3 Scaling Path

As user count grows, the infrastructure can be expanded:

| Stage | Users | Configuration | Monthly Cost |
|-------|-------|---------------|--------------|
| **Dev/Test** | 1-50 | 1× c6a.xlarge, single AZ | ~$125 |
| **Early Production** | 50-200 | 1-2× c6a.xlarge, single AZ | ~$125-250 |
| **Growth** | 200-500 | 2-3× c6a.xlarge, multi-AZ | ~$250-375 |
| **Scale** | 500+ | 3+× c6a.2xlarge, multi-AZ, NLB | ~$750+ |

### 9.4 Failover Behavior (Single Instance)

With min=1, there's a brief outage during instance failure:

```
Scenario: Enclave instance failure (single instance mode)

Time 0:00 - Enclave fails
          - Active vaults become unavailable
          - In-flight requests: lost (client retries)

Time 0:01 - Health check detects failure
          - ASG launches replacement instance

Time 2:00 - New instance boots + enclave starts
          - ~2 minutes for EC2 + enclave initialization

Time 2:05 - Service restored
          - Clients reconnect
          - Vaults cold-start on demand (~300-500ms each)

Total outage: ~2-3 minutes
```

**Acceptable for dev/testing**. For production with uptime requirements, increase to min=2 across multiple AZs.

### 9.5 Future: Multi-AZ High Availability

When uptime requirements increase, expand to multi-AZ:

```typescript
// Production configuration (future)
const enclaveASG = new autoscaling.AutoScalingGroup(this, 'EnclaveASG', {
  vpc,
  instanceType: ec2.InstanceType.of(ec2.InstanceClass.C6A, ec2.InstanceSize.XLARGE2),
  machineImage: enclaveAMI,

  minCapacity: 3,  // One per AZ
  maxCapacity: 15,

  // Distribute across AZs
  vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
});
```

**No code changes required** - same enclave image, just more instances. Vaults can load on any enclave since sealed credentials are bound to PCRs (code identity), not instance identity.

---

## 10. Migration Strategy

### 10.1 Migration Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Migration Timeline                                │
│                                                                         │
│  Phase 1          Phase 2          Phase 3          Phase 4            │
│  Preparation      Parallel Run     Gradual Migrate  Decommission       │
│                                                                         │
│  ┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐       │
│  │ Build & │      │ Run both│      │ Migrate │      │ Shutdown│       │
│  │ Test    │      │ systems │      │ users   │      │ old EC2 │       │
│  │ Enclave │      │         │      │ in waves│      │ vaults  │       │
│  └─────────┘      └─────────┘      └─────────┘      └─────────┘       │
│                                                                         │
│  Duration:        Duration:        Duration:        Duration:          │
│  2-3 weeks        1-2 weeks        2-4 weeks        1 week             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Phase 1: Preparation

**Objective**: Build and validate enclave infrastructure

Tasks:
1. Develop enclave vault-manager
2. Build enclave image and publish PCRs
3. Update mobile apps with attestation verification
4. Deploy enclave infrastructure to staging
5. End-to-end testing with test accounts

```bash
# Build enclave image
nitro-cli build-enclave \
  --docker-uri vettid/vault-enclave:v1.0.0 \
  --output-file vault-enclave.eif

# Get PCRs
nitro-cli describe-eif --eif-path vault-enclave.eif

# Publish PCRs
aws ssm put-parameter \
  --name /vettid/enclave/pcrs/v1.0.0 \
  --value '{"PCR0":"abc...","PCR1":"def...","PCR2":"ghi..."}' \
  --type SecureString
```

### 10.3 Phase 2: Parallel Run

**Objective**: Run both systems simultaneously, route new users to enclave

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Parallel Architecture                             │
│                                                                         │
│                    ┌───────────────────────────┐                        │
│                    │     Central NATS          │                        │
│                    │     (message router)      │                        │
│                    └─────────────┬─────────────┘                        │
│                                  │                                      │
│              ┌───────────────────┴───────────────────┐                 │
│              │                                       │                 │
│              ▼                                       ▼                 │
│  ┌───────────────────────┐           ┌───────────────────────┐        │
│  │   Enclave Fleet       │           │   Legacy EC2 Vaults   │        │
│  │   (new users)         │           │   (existing users)    │        │
│  │                       │           │                       │        │
│  │   Routes:             │           │   Routes:             │        │
│  │   vault.enclave.>     │           │   vault.ec2.>         │        │
│  └───────────────────────┘           └───────────────────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Routing logic:
```go
func routeVaultMessage(ownerSpace string, msg []byte) {
    userConfig := getUserConfig(ownerSpace)

    if userConfig.VaultType == "enclave" {
        publishToEnclave(ownerSpace, msg)
    } else {
        publishToEC2(ownerSpace, msg)
    }
}
```

### 10.4 Phase 3: Gradual Migration

**Objective**: Migrate existing users from EC2 to enclave

Migration per user:
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Per-User Migration Flow                               │
│                                                                         │
│  1. Mark user for migration                                             │
│     └─ Set flag in user config: migration_pending = true                │
│                                                                         │
│  2. Wait for user's next app session                                    │
│     └─ App detects migration flag                                       │
│                                                                         │
│  3. App initiates migration bootstrap                                   │
│     ├─ Connect to enclave                                               │
│     ├─ Verify attestation                                               │
│     ├─ Establish new session                                            │
│     └─ Provide master secret for DEK derivation                         │
│                                                                         │
│  4. Enclave creates new vault                                           │
│     ├─ Derive vault DEK                                                 │
│     ├─ Seal DEK with attestation                                        │
│     └─ Initialize empty JetStream                                       │
│                                                                         │
│  5. Data migration (user-initiated)                                     │
│     ├─ App reads data from EC2 vault (decrypts locally)                │
│     ├─ App writes data to enclave vault (encrypts locally)             │
│     └─ Progress tracked in app                                          │
│                                                                         │
│  6. Switchover                                                          │
│     ├─ Update routing to enclave                                        │
│     ├─ Mark migration complete                                          │
│     └─ Schedule EC2 vault for deletion                                  │
│                                                                         │
│  7. Cleanup                                                             │
│     └─ Terminate EC2 vault after 7-day grace period                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Wave strategy:
```
Wave 1: Internal team accounts (10 users)
        Duration: 1 week

Wave 2: Beta users who opt-in (100 users)
        Duration: 1 week

Wave 3: 10% of remaining users
        Duration: 1 week

Wave 4: 50% of remaining users
        Duration: 1 week

Wave 5: All remaining users
        Duration: 1 week
```

### 10.5 Phase 4: Decommission

**Objective**: Shut down legacy EC2 vault infrastructure

Tasks:
1. Verify all users migrated
2. Final backup of any unmigrated data
3. Terminate EC2 vault instances
4. Delete EC2-related infrastructure
5. Update documentation

---

## 11. Enclave Update & Key Migration

### 11.1 The Challenge

When enclave code is updated, PCRs change. Sealed DEKs bound to old PCRs cannot be unsealed by new code.

```
Old Enclave (PCR: abc123)     New Enclave (PCR: def456)
├─ Can unseal old keys        ├─ CANNOT unseal old keys
└─ Running                    └─ Running

Problem: How to transition without losing access to user data?
```

### 11.2 Solution: Key Migration During Rolling Update

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Key Migration Process                                 │
│                                                                         │
│  Step 1: Deploy new enclave alongside old                               │
│  ─────────────────────────────────────────                              │
│                                                                         │
│      Old Enclave Fleet          New Enclave Fleet                       │
│      ┌───────────────┐          ┌───────────────┐                      │
│      │ PCR: abc123   │          │ PCR: def456   │                      │
│      │ Serving users │          │ Idle          │                      │
│      └───────────────┘          └───────────────┘                      │
│                                                                         │
│  Step 2: Migrate keys (in old enclave)                                  │
│  ─────────────────────────────────────                                  │
│                                                                         │
│      For each user vault:                                               │
│        a. Unseal DEK with old PCRs                                     │
│        b. Re-seal DEK with new PCRs                                    │
│           (Nitro KMS allows sealing for different PCRs)                │
│        c. Store new sealed DEK in S3 (keep old as backup)              │
│                                                                         │
│      S3:                                                                │
│      └── user-ABC123/                                                   │
│          ├── sealed_dek.bin         (old PCRs)                         │
│          └── sealed_dek.v2.bin      (new PCRs) ← NEW                   │
│                                                                         │
│  Step 3: Switch traffic to new enclave                                  │
│  ─────────────────────────────────────                                  │
│                                                                         │
│      Old Enclave Fleet          New Enclave Fleet                       │
│      ┌───────────────┐          ┌───────────────┐                      │
│      │ Draining      │   ───►   │ Serving users │                      │
│      └───────────────┘          └───────────────┘                      │
│                                                                         │
│  Step 4: Terminate old enclave, cleanup                                 │
│  ───────────────────────────────────────                                │
│                                                                         │
│      S3:                                                                │
│      └── user-ABC123/                                                   │
│          └── sealed_dek.bin      (new PCRs, renamed)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 11.3 Key Migration Implementation

```go
// Run in OLD enclave during migration
func migrateKeysToNewPCRs(newPCRs PCRValues) error {
    // Get list of all users
    users, err := listAllUsers()
    if err != nil {
        return err
    }

    for _, userID := range users {
        // Load current sealed DEK
        sealedDEK, err := loadSealedDEK(userID)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to load sealed DEK")
            continue
        }

        // Unseal with current (old) attestation
        vaultDEK, err := nitro.Unseal(sealedDEK)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to unseal DEK")
            continue
        }

        // Re-seal for new PCRs
        newSealedDEK, err := nitro.SealForPCRs(vaultDEK, newPCRs)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to re-seal DEK")
            continue
        }

        // Store new sealed DEK (alongside old)
        err = storeSealedDEK(userID, "sealed_dek.v2.bin", newSealedDEK)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to store new sealed DEK")
            continue
        }

        // Zero out plaintext DEK from memory
        zeroize(vaultDEK)

        log.Info().Str("user", userID).Msg("Key migrated successfully")
    }

    return nil
}
```

### 11.4 Rollback Strategy

If issues are discovered after switching to new enclave:

```
Rollback Steps:
───────────────

1. Route traffic back to old enclave fleet
   (old enclave can still unseal old keys)

2. Investigate and fix issue in new enclave code

3. Build new enclave image with fix (PCR: ghi789)

4. Re-run key migration from old enclave
   (migrate from abc123 → ghi789)

5. Attempt switch again

Key insight: Keep old enclave running until new enclave is verified stable
```

### 11.5 Emergency Recovery

If both old and new enclaves are unavailable:

```
Emergency Recovery (requires user action):
─────────────────────────────────────────

1. User provides master secret via app

2. New enclave derives vault DEK from master secret
   (same derivation function as original bootstrap)

3. New enclave seals DEK with current PCRs

4. Vault data in S3 is still accessible
   (encrypted with vault DEK, which was just re-derived)

Note: This works because vault DEK is deterministically derived
from master secret + salt. The salt is stored unencrypted in S3.
```

---

## 12. Cost Analysis

### 12.1 Current Costs (EC2 Model)

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| t4g.micro (vault) | $6.05/mo | 100 | $605 |
| EBS (10GB per vault) | $0.80/mo | 100 | $80 |
| Data transfer | ~$0.50/vault | 100 | $50 |
| **Total (100 users)** | | | **$735/mo** |
| **Per-vault cost** | | | **$7.35** |

### 12.2 Enclave Model Costs (Phased)

**Phase 1: Dev/Testing (Single Instance)**

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| c6a.xlarge (enclave host) | $124/mo | 1 | $124 |
| S3 storage (1GB/vault) | $0.023/GB | 50 | $1.15 |
| S3 requests | ~$0.05/vault | 50 | $2.50 |
| Data transfer | ~$0.20/vault | 50 | $10 |
| **Total (50 users)** | | | **~$138/mo** |
| **Per-vault cost** | | | **$2.76** |

**Phase 2: Production (Multi-AZ)**

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| c6a.xlarge (enclave host) | $124/mo | 3 (multi-AZ) | $372 |
| S3 storage (1GB/vault) | $0.023/GB | 200 | $4.60 |
| S3 requests | ~$0.05/vault | 200 | $10 |
| Data transfer | ~$0.20/vault | 200 | $40 |
| **Total (200 users)** | | | **~$427/mo** |
| **Per-vault cost** | | | **$2.14** |

### 12.3 Cost Comparison by Phase

| Phase | Users | EC2 Model | Enclave Model | Savings |
|-------|-------|-----------|---------------|---------|
| Dev/Test | 10 | $73/mo | $125/mo | -71% (acceptable for features) |
| Dev/Test | 50 | $368/mo | $138/mo | **62%** |
| Early Prod | 100 | $735/mo | $152/mo | **79%** |
| Growth | 200 | $1,470/mo | $427/mo | **71%** |
| Scale | 500 | $3,675/mo | $500/mo | **86%** |
| Scale | 1,000 | $7,350/mo | $750/mo | **90%** |

### 12.4 Break-Even Analysis

```
Initial deployment (1 instance):
  Fixed costs (enclave): $124/mo
  Variable costs (enclave): ~$0.30/user

  Fixed costs (EC2): $0
  Variable costs (EC2): ~$7.35/user

Break-even point:
  124 + 0.30x = 7.35x
  124 = 7.05x
  x = 18 users

At 18+ users, enclave model is more cost-effective.
```

### 12.5 TCO Considerations

Beyond raw compute costs:

| Factor | EC2 Model | Enclave Model |
|--------|-----------|---------------|
| Operational complexity | High (manage 100s of instances) | Low (manage 1-3 instances) |
| Provisioning time | 30-60s | 300-500ms |
| Security guarantees | Trust-based | Attestation-based |
| Scaling events | Slow (launch EC2) | Fast (load vault) |
| Backup/DR | Per-instance EBS snapshots | Centralized S3 |

---

## 13. BYO Vault Considerations

### 13.1 BYO Options

Users who want to run their own vault infrastructure have three options:

| Option | Description | Complexity | Security |
|--------|-------------|------------|----------|
| **Self-hosted EC2** | Current model, user's AWS account | Low | Trust user's infra |
| **Self-hosted Enclave** | Nitro enclave in user's AWS account | Medium | Attestation |
| **On-premises** | User's own hardware/datacenter | High | Trust user's infra |

### 13.2 Self-Hosted Enclave

Users can run their own enclave with the same code:

```bash
# User downloads official enclave image
aws s3 cp s3://vettid-public/enclave/vault-enclave-v1.0.0.eif ./

# User verifies image hash matches published PCRs
sha384sum vault-enclave-v1.0.0.eif
# Compare with published PCR0

# User runs enclave on their own EC2
nitro-cli run-enclave \
  --eif-path vault-enclave-v1.0.0.eif \
  --memory 8000 \
  --cpu-count 4

# User configures their app to connect to their enclave
# App verifies attestation against same published PCRs
```

Benefits:
- Complete data sovereignty
- Same security guarantees (attestation)
- Compatible with VettID ecosystem

### 13.3 Configuration for BYO

```typescript
// User's app configuration
interface VaultConfig {
  type: 'vettid-hosted' | 'self-hosted-enclave' | 'self-hosted-ec2';

  // For self-hosted
  endpoint?: string;

  // For enclave (self-hosted or VettID)
  expectedPCRs?: {
    pcr0: string;
    pcr1: string;
    pcr2: string;
  };
}
```

---

## 14. Implementation Phases

### 14.1 Phase Overview

| Phase | Duration | Focus | Deliverables |
|-------|----------|-------|--------------|
| 1 | 3-4 weeks | Core enclave | Working enclave vault-manager |
| 2 | 2-3 weeks | Integration | Parent process, S3, NATS |
| 3 | 2-3 weeks | Mobile apps | Attestation verification |
| 4 | 2-3 weeks | Operations | Deployment, monitoring, scaling |
| 5 | 3-4 weeks | Migration | User migration tooling |

### 14.2 Phase 1: Core Enclave

**Objective**: Port vault-manager to run inside Nitro Enclave

Tasks:
- [ ] Set up enclave development environment
- [ ] Create minimal enclave image with vault-manager
- [ ] Implement vsock communication layer
- [ ] Implement sealed storage for vault DEK
- [ ] Implement encrypted storage adapter
- [ ] Port embedded NATS to use custom storage backend
- [ ] Unit tests for all enclave components
- [ ] Generate and document PCRs

### 14.3 Phase 2: Integration

**Objective**: Connect enclave to external systems

Tasks:
- [ ] Implement parent process (vsock ↔ NATS ↔ S3)
- [ ] Set up S3 bucket structure
- [ ] Integrate with central NATS cluster
- [ ] Implement supervisor process
- [ ] Implement vault lifecycle management
- [ ] Integration tests with mock external services
- [ ] End-to-end tests with real infrastructure

### 14.4 Phase 3: Mobile Apps

**Objective**: Update iOS and Android apps to support attestation

Tasks:
- [ ] Implement attestation document parsing
- [ ] Implement PCR verification
- [ ] Update bootstrap flow for attestation
- [ ] Store expected PCRs in app configuration
- [ ] Support for PCR updates via app update
- [ ] Fallback handling for attestation failures
- [ ] QA testing on both platforms

### 14.5 Phase 4: Operations

**Objective**: Production-ready deployment and monitoring

Tasks:
- [ ] CDK stack for enclave infrastructure
- [ ] Auto-scaling configuration
- [ ] CloudWatch metrics and dashboards
- [ ] Alerting for enclave health
- [ ] Runbook for common operations
- [ ] Disaster recovery procedures
- [ ] Load testing and performance validation
- [ ] Security review

### 14.6 Phase 5: Migration

**Objective**: Migrate existing users from EC2 to enclave

Tasks:
- [ ] Migration flag infrastructure
- [ ] Mobile app migration flow
- [ ] Data migration tooling
- [ ] Rollback procedures
- [ ] Wave migration execution
- [ ] Monitoring during migration
- [ ] Post-migration validation
- [ ] EC2 decommission automation

---

## 15. Risks & Mitigations

### 15.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave memory insufficient | High | Low | Test with realistic vault counts; implement eviction |
| Cold start latency unacceptable | Medium | Low | Optimize loading; pre-warm predicted vaults |
| NATS JetStream incompatible with custom storage | High | Medium | Prototype early; have fallback storage design |
| Attestation verification complex on mobile | Medium | Medium | Use existing libraries; thorough testing |
| vsock throughput bottleneck | Medium | Low | Load test; optimize batching |

### 15.2 Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave update causes key inaccessibility | Critical | Low | Key migration process; keep old enclave running during transition |
| Multi-AZ failure | High | Very Low | Regional failover; S3 cross-region replication |
| S3 outage | High | Very Low | Local caching; graceful degradation |
| Migration causes data loss | Critical | Low | User-driven migration; keep EC2 until verified |

### 15.3 Security Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Attestation bypass | Critical | Very Low | Hardware-backed; AWS Nitro security |
| Side-channel attacks in shared enclave | High | Low | Process isolation; constant-time crypto |
| Compromised enclave build | Critical | Very Low | Reproducible builds; third-party audit |
| PCR collision | Critical | Very Low | SHA-384 collision-resistant |

---

## 16. Decision Log

### 16.1 Key Decisions

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| 1 | Use Nitro Enclaves over alternatives | Hardware attestation; AWS native; well-documented | 2026-01-02 |
| 2 | Per-user vault-manager process | Preserves current architecture; simpler migration | 2026-01-02 |
| 3 | Per-user embedded NATS + JetStream | Maintains data isolation; proven storage | 2026-01-02 |
| 4 | Shared WASM handler cache | Memory efficiency; consistent handler versions | 2026-01-02 |
| 5 | S3 for encrypted blob storage | Durability; cross-AZ replication; cost-effective | 2026-01-02 |
| 6 | User-driven data migration | User controls their data; no VettID access to plaintext | 2026-01-02 |

### 16.2 Open Questions

| # | Question | Status | Owner |
|---|----------|--------|-------|
| 1 | What is actual memory footprint per vault? | Needs profiling | TBD |
| 2 | Can NATS JetStream use custom storage backend? | Needs PoC | TBD |
| 3 | What is attestation verification latency on mobile? | Needs testing | TBD |
| 4 | How to handle vault during enclave restart? | Needs design | TBD |
| 5 | Cross-region DR strategy? | Needs design | TBD |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Attestation** | Cryptographic proof of code identity and enclave integrity |
| **DEK** | Data Encryption Key - symmetric key used to encrypt vault data |
| **Enclave** | Isolated compute environment with hardware-protected memory |
| **JetStream** | NATS persistence layer for message storage |
| **Nitro** | AWS hardware security platform for EC2 |
| **PCR** | Platform Configuration Register - hash of enclave components |
| **Sealed storage** | Encryption bound to specific enclave code identity |
| **vsock** | Virtual socket for enclave ↔ parent communication |
| **WASM** | WebAssembly - portable bytecode for event handlers |

---

## Appendix B: References

1. AWS Nitro Enclaves Documentation: https://docs.aws.amazon.com/enclaves/
2. NATS JetStream: https://docs.nats.io/nats-concepts/jetstream
3. Wazero (Go WASM runtime): https://wazero.io/
4. ChaCha20-Poly1305: RFC 8439
5. X25519 Key Exchange: RFC 7748

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-02 | Architecture Team | Initial draft |
| 1.1 | 2026-01-02 | Architecture Team | Added Section 5: Protean Credential & Trust Model. Corrected security model to establish vault (Nitro Enclave) as the secure processing environment rather than user devices. All user secrets now stored in single encrypted Protean Credential that only attested enclaves can decrypt. |
| 1.2 | 2026-01-02 | Architecture Team | Critical fix: Credential creation now happens INSIDE the enclave (Section 5.7-5.9). Device only provides PIN, enclave generates all secrets. Simplified scaling to single-region ASG min=1 for dev/testing (Section 9). Updated cost analysis for phased deployment (Section 12). Break-even now at 18 users. |
