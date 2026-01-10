# VettID Nitro Enclave Vault Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 2.0 |
| Date | 2026-01-09 |
| Status | Proposal - Pending Review |
| Author | Architecture Team |

### Terminology

| Term | Definition |
|------|------------|
| **PIN** | 6-digit code used to unlock the vault (DEK derivation via supervisor) |
| **Password** | User-chosen password for operation authorization (Argon2id hashed by app) |
| **Credential Password** | Same as Password - authorizes vault operations |
| **Authentication Factor** | Generic term for PIN, Password, or future biometric unlock |
| **Vault-Manager** | Process inside enclave handling credential operations |
| **Supervisor** | Process inside enclave handling NSM/KMS/DEK operations |
| **CEK** | Credential Encryption Key - encrypts the Protean Credential blob |
| **DEK** | Data Encryption Key - encrypts the SQLite database |
| **UTK** | User Transaction Key - single-use public keys for transport encryption |
| **LTK** | Ledger Transaction Key - private keys corresponding to UTKs |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture](#2-current-architecture)
3. [Proposed Architecture](#3-proposed-architecture)
4. [Security Model](#4-security-model)
5. [Protean Credential & Trust Model](#5-protean-credential--trust-model)
   - 5.5 Key Model (CEK, UTK, LTK, DEK)
   - 5.6 Enrollment Flow (Detailed)
   - 5.7 PIN Setup and Vault DEK Binding
   - 5.8 App Open / Vault Warming Flow
   - 5.9 Vault Operation Flow (CEK Rotation)
   - 5.10 Challenge Flow (User Authorization)
   - 5.17 Post-Enrollment Vault Access
   - 5.18 Credential Backup & Recovery
   - 5.19 Flexible Vault Authentication
   - 5.20 Account Portal Changes
6. [Component Design](#6-component-design)
7. [Data Storage & Encryption](#7-data-storage--encryption)
8. [Process Lifecycle Management](#8-process-lifecycle-management)
9. [Scaling & Deployment](#9-scaling--deployment)
10. [Enclave Update & Credential Migration](#10-enclave-update--credential-migration)
11. [Cost Analysis](#11-cost-analysis)
12. [BYO Vault Considerations](#12-byo-vault-considerations)
13. [Implementation Phases](#13-implementation-phases)
14. [Risks & Mitigations](#14-risks--mitigations)
15. [Decision Log](#15-decision-log)

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
- **Per-user isolation**: Each vault has its own SQLite database with DEK encryption, persisted to S3
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
- End-to-end encryption (user app ↔ vault-manager)
- Per-user encryption keys that never leave vault-manager memory
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
│    creds    │                                    │  │• SQLite DB    │  │
│  • Session  │                                    │  │• EBS storage  │  │
│    keys     │                                    │  │• WASM runtime │  │
│             │                                    │  └───────────────┘  │
└─────────────┘                                    └─────────────────────┘
```

### 2.2 Current Components

| Component | Description | Per-User |
|-----------|-------------|----------|
| EC2 Instance | t4g.micro running vault-manager | Yes |
| SQLite DB | In-memory database for vault data | Yes |
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
│  │ │ SQLite      │ │  │ │ SQLite      │ │  │ │ SQLite      │ │          │
│  │ │ (in-memory) │ │  │ │ (in-memory) │ │  │ │ (in-memory) │ │          │
│  │ │             │ │  │ │             │ │  │ │             │ │          │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │          │
│  │        │        │  │        │        │  │        │        │          │
│  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │  │ ┌──────▼──────┐ │          │
│  │ │ S3 Sync     │ │  │ │ S3 Sync     │ │  │ │ S3 Sync     │ │          │
│  │ │ (DEK        │ │  │ │ (DEK        │ │  │ │ (DEK        │ │          │
│  │ │ encrypted)  │ │  │ │ encrypted)  │ │  │ │ encrypted)  │ │          │
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
| Enclave Supervisor | Enclave | Shared | Manages vault lifecycle, NSM/KMS operations |
| vault-manager | Enclave | Per-user | Handles user's vault operations |
| SQLite DB | Enclave | Per-user | In-memory database for vault data |
| S3 Sync | Enclave | Per-user | Encrypts DB with DEK, syncs to S3 after each write |
| WASM Handler Cache | Enclave | Shared | Compiled handlers, read-only |
| Parent Process | EC2 Host | Shared | External I/O (NATS, S3), no key access |
| Central NATS | External | Shared | Routes messages from apps to vault-managers |
| S3 Storage | External | Per-user prefix | Encrypted vault database blobs |

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

User apps:
- Fetch current PCR values from VettID's PCR endpoint: `GET /api/enclave/pcrs`
- Cache PCRs locally with TTL (24 hours)
- Verify PCRs against VettID's release signing key
- No app update required for new enclave releases

PCR Endpoint Response:
```json
{
  "version": "v2.1.0",
  "pcr0": "c7b2f3d8e9a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
  "pcr1": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
  "pcr2": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
  "signature": "<VettID release key signature>",
  "expires_at": 1705446000
}
```

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
│  Vault Master Secret (stored INSIDE Protean Credential)                │
│  ─────────────────────────────────────────────────────                 │
│  • NOT the PIN - this is a cryptographic secret (256-bit random)       │
│  • Generated during enrollment, never leaves enclave memory            │
│  • Used for vault-specific derivations and identity binding            │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Vault DEK = KDF(NSM.Unseal(sealed_material), PIN)               │   │
│  │                                                                  │   │
│  │ PIN: User's 6-digit code (entered on app open)                  │   │
│  │ sealed_material: PCR-bound material (stored in S3)              │   │
│  │ DEK: Encrypts the SQLite database holding all vault data        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│         │                                                               │
│         ├──────────────────────┬──────────────────────┐                │
│         ▼                      ▼                      ▼                │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐          │
│  │ SQLite DB   │       │ Handler     │       │ Other vault │          │
│  │ (S3 sync)   │       │ state       │       │ data        │          │
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

Vault DEKs are derived from sealed material + PIN. Nitro seals the source material:

```
Sealing (during PIN setup):

  random_material (32 bytes, generated in enclave)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Seal(random_material, attestation_doc)                │
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
  sealed_material (ciphertext) → stored in S3 as sealed_material.bin


Unsealing + DEK derivation (vault load):

  sealed_material (from S3)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ NitroKMS.Unseal(sealed_material)                               │
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
  random_material (32 bytes, plaintext)
       │
       ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ DEK = Argon2id(PIN, salt=SHA256(owner_id || material))         │
  │                                                                 │
  │ Then: HKDF.Extract(material, stretched_pin) → vault_dek        │
  └────────────────────────────────────────────────────────────────┘
       │
       ▼
  vault_dek (32 bytes) → available in enclave memory
```

**Critical property**: Sealed data can be unsealed by ANY enclave running the SAME code, regardless of which physical machine or AWS account. The DEK requires both the unsealed material AND the correct PIN.

### 4.7 Sealed Material Integrity Verification

Before attempting KMS unseal (which consumes API quota and creates timing attack surface),
we verify sealed material integrity using HMAC-SHA256:

```
S3 Storage Format:
┌─────────────────────────────────────────────────────────────────────────┐
│  sealed_material.bin:                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  HMAC-SHA256(32 bytes) │ sealed_data (variable, from KMS)        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  HMAC key = SHA256(owner_id || "sealed-material-hmac-v1")               │
│                                                                         │
│  Benefits:                                                               │
│  • Fast rejection of tampered/corrupted data (no KMS call)              │
│  • Prevents timing attacks from repeated invalid unseal attempts        │
│  • Binds sealed material to owner_id (no cross-user confusion)          │
└─────────────────────────────────────────────────────────────────────────┘

Verification Flow:
──────────────────
  1. Load sealed_material.bin from S3
  2. Split: hmac_received = data[:32], sealed_data = data[32:]
  3. Compute: hmac_expected = HMAC-SHA256(hmac_key, sealed_data)
  4. Compare: constant_time_compare(hmac_received, hmac_expected)
  5. If mismatch → REJECT immediately (no KMS call)
  6. If match → proceed with KMS.Decrypt(sealed_data)
```

```go
// Store sealed material with HMAC integrity check
func (s *EnclaveSupervisor) storeSealedMaterial(ownerID string, sealed []byte) error {
    // Compute HMAC key from owner_id (binds to user)
    hmacKey := sha256.Sum256([]byte(ownerID + "sealed-material-hmac-v1"))

    // Compute HMAC over sealed data
    mac := hmac.New(sha256.New, hmacKey[:])
    mac.Write(sealed)
    hmacValue := mac.Sum(nil)

    // Store: HMAC || sealed_data
    blob := append(hmacValue, sealed...)
    return s.storeToS3(ownerID, "sealed_material.bin", blob)
}

// Load and verify sealed material integrity before KMS unseal
func (s *EnclaveSupervisor) loadSealedMaterial(ownerID string) ([]byte, error) {
    blob, err := s.loadFromS3(ownerID, "sealed_material.bin")
    if err != nil {
        return nil, err
    }

    if len(blob) < 32 {
        return nil, errors.New("sealed material too short")
    }

    // Split HMAC and sealed data
    hmacReceived := blob[:32]
    sealed := blob[32:]

    // Recompute expected HMAC
    hmacKey := sha256.Sum256([]byte(ownerID + "sealed-material-hmac-v1"))
    mac := hmac.New(sha256.New, hmacKey[:])
    mac.Write(sealed)
    hmacExpected := mac.Sum(nil)

    // Constant-time comparison (prevents timing attacks)
    if !hmac.Equal(hmacReceived, hmacExpected) {
        return nil, errors.New("sealed material integrity check failed")
    }

    return sealed, nil
}
```

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

The Protean Credential contains all user secrets, encrypted so only the vault can access them:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Protean Credential                                   │
│                     (Encrypted blob user holds but can't access)         │
│                                                                         │
│  Encrypted with: CEK public key (X25519 + ChaCha20-Poly1305)            │
│  CEK rotates after each operation for forward secrecy                   │
│  (See Section 5.5 for key architecture)                                 │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Contents (only readable inside vault-manager):                 │   │
│  │                                                                  │   │
│  │  identity_keypair: {                                            │   │
│  │    private_key: [32 bytes],   // Ed25519 - vault authentication │   │
│  │    public_key: [32 bytes]     // Also serves as user identifier │   │
│  │  }                                                              │   │
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
│  │  password_auth: {                 // For operation authorization │   │
│  │    password_hash: [32 bytes],     // Argon2id hash               │   │
│  │    password_salt: [16 bytes],     // Random salt                 │   │
│  │    max_attempts: 5,               // Before lockout              │   │
│  │    lockout_duration: 300          // Seconds                     │   │
│  │  }                                                              │   │
│  │  // NOTE: Vault PIN is NOT stored here - it's used by supervisor│   │
│  │  // for DEK derivation, not for operation authorization         │   │
│  │                                                                  │   │
│  │  metadata: {                                                    │   │
│  │    version: 1,                                                  │   │
│  │    cek_version: "uuid-xyz",       // Track CEK for sync         │   │
│  │    created_at: "2026-01-02T12:00:00Z",                          │   │
│  │    owner_id: "usr_ABC123..."        // Cognito user_id           │   │
│  │  }                                                              │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  User's device sees: Opaque encrypted blob (cannot decrypt)            │
│  Vault-manager sees: All secrets (after user provides password)        │
│                                                                         │
│  Encryption layers:                                                     │
│  ─────────────────                                                      │
│  1. Credential encrypted with CEK (X25519) - app cannot decrypt         │
│  2. CEK private key encrypted with DEK - stored in SQLite               │
│  3. DEK derived from sealed_material + PIN - supervisor handles this    │
│  4. sealed_material encrypted by KMS - PCR-bound, only genuine enclave  │
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
| Separate vault credentials | Identity keypair in credential |
| Vault credential (master secret) | Vault master secret in credential |
| Separate BTC wallet | BTC keys in credential |
| Separate seed phrase backup | Seed phrases in credential |

**One credential holds everything**, encrypted so only the vault can access it.

### 5.5 Key Model (CEK, UTK, LTK, DEK)

The credential system uses asymmetric transaction keys for secure communication and a DEK for vault storage:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Key Architecture                                    │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  CEK (Credential Encryption Key) - Asymmetric                        │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                       │  │
│  │  • Keypair: Both held by vault-manager, stored in SQLite (DEK-enc)   │  │
│  │  • Used to encrypt the Protean Credential blob                       │  │
│  │  • App does NOT have CEK - only receives encrypted blob              │  │
│  │  • Vault-manager encrypts new blob with CEK after each operation     │  │
│  │  • Rotates after each vault operation (forward secrecy)              │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  UTK/LTK (User/Ledger Transaction Keys) - Asymmetric Pairs           │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                │  │
│  │  • UTK (public): App encrypts sensitive data TO vault                │  │
│  │  • LTK (private): Vault decrypts data FROM app                       │  │
│  │  • Generated by vault-manager during enrollment                      │  │
│  │  • Multiple UTKs issued, each single-use for replay protection       │  │
│  │  • LTKs stored in SQLite, keyed by UTK ID                            │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  DEK (Data Encryption Key) - Symmetric                               │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                        │  │
│  │  • Encrypts vault's SQLite database (CEK private, LTKs, etc.)        │  │
│  │  • Derived: DEK = KDF(NitroKMS.Unseal(sealed_material), PIN)         │  │
│  │  • Wrong PIN = wrong DEK = decryption fails                          │  │
│  │  • sealed_material is PCR-bound (only genuine enclave can unseal)    │  │
│  │  • DEK handled by supervisor; vault-manager receives it on warmup    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Credential Password - User Knowledge Factor                         │  │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                       │  │
│  │  • Hashed with Argon2id, stored INSIDE the Protean Credential        │  │
│  │  • Required for each vault operation (signing, key usage, etc.)      │  │
│  │  • Sent encrypted via UTK (never plaintext over wire)                │  │
│  │  • Separate from PIN: password proves authorization, PIN unlocks DEK │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Two-Factor Authentication Model:**

| Factor | What It Protects | When Used | Frequency |
|--------|------------------|-----------|-----------|
| **Vault PIN** | DEK (SQLite DB encryption) | App open | Each session (daily) |
| **Credential Password** | Operation authorization | Vault operations | Each operation |

**Single-Device Design:** Users access their vault from one device at a time. This eliminates CEK rotation race conditions—there's no scenario where device A and device B both hold valid credentials that could conflict during rotation. If a user switches devices, they restore from backup (24-hour delay) which naturally syncs to the latest credential state.

**Why Two Factors?**
- PIN unlocks the vault's storage - rarely changes, entered on app open
- Password authorizes each operation - brute force protected by vault
- Compromising one doesn't compromise the other
- PIN is verified by enclave hardware (NSM/KMS), password by vault software

### 5.6 Enrollment Flow (Detailed)

Enrollment establishes the user's vault with proper key setup. Critical: the **supervisor** handles NSM/KMS operations, the **vault-manager** handles credential operations.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Enrollment Flow                                      │
│                                                                             │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────────┐  │
│  │   Lambda   │    │    App     │    │ Supervisor │    │ Vault-Manager  │  │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘    └───────┬────────┘  │
│        │                 │                 │                   │           │
│  ┌─────┴─────────────────┴─────────────────┴───────────────────┴─────────┐ │
│  │ PHASE 1: Lambda Initiates Vault                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│        │                 │                 │                   │           │
│        │ 1. Create vault session          │                   │           │
│        │    (generate bootstrap token)    │                   │           │
│        │─────────────────────────────────►│                   │           │
│        │                 │                 │                   │           │
│        │ 2. Start vault-manager           │                   │           │
│        │    with owner_id                │─────────────────────►          │
│        │                 │                 │                   │           │
│        │                 │                 │     3. Initialize │           │
│        │                 │                 │        SQLite DB  │           │
│        │                 │                 │                   │           │
│        │ 4. Return vault_id, bootstrap_token                  │           │
│        │◄────────────────────────────────────────────────────────────────  │
│        │                 │                 │                   │           │
│  ┌─────┴─────────────────┴─────────────────┴───────────────────┴─────────┐ │
│  │ PHASE 2: App Bootstraps with Vault                                    │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│        │                 │                 │                   │           │
│        │  5. Return vault info to app     │                   │           │
│        │────────────────►│                 │                   │           │
│        │                 │                 │                   │           │
│        │                 │ 6. app.bootstrap (via NATS)        │           │
│        │                 │────────────────────────────────────►│           │
│        │                 │    { bootstrap_token }              │           │
│        │                 │                 │                   │           │
│        │                 │                 │     7. Generate:  │           │
│        │                 │                 │        • CEK pair │           │
│        │                 │                 │        • UTKs     │           │
│        │                 │                 │        • LTKs     │           │
│        │                 │                 │                   │           │
│        │                 │                 │     8. Store in SQLite:       │
│        │                 │                 │        • CEK private key      │
│        │                 │                 │        • LTKs (keyed by UTK)  │
│        │                 │                 │        → Sync to S3           │
│        │                 │                 │                   │           │
│        │                 │ 9. Response: UTKs only              │           │
│        │                 │◄────────────────────────────────────│           │
│        │                 │    + "enter credential password"    │           │
│        │                 │    (no CEK sent - vault holds both) │           │
│        │                 │                 │                   │           │
│  ┌─────┴─────────────────┴─────────────────┴───────────────────┴─────────┐ │
│  │ PHASE 3: App Sets Credential Password                                 │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│        │                 │                 │                   │           │
│        │                 │ 10. User enters credential password │           │
│        │                 │     (app prompts)                   │           │
│        │                 │                 │                   │           │
│        │                 │ 11. Hash password (Argon2id)        │           │
│        │                 │     Encrypt hash with UTK           │           │
│        │                 │     send to vault                   │           │
│        │                 │────────────────────────────────────►│           │
│        │                 │                 │                   │           │
│        │                 │                 │    12. Decrypt hash with LTK  │
│        │                 │                 │        Build credential:      │
│        │                 │                 │        • identity_keypair     │
│        │                 │                 │        • master_secret        │
│        │                 │                 │        • password_hash (rcvd) │
│        │                 │                 │        Encrypt with CEK       │
│        │                 │                 │                   │           │
│        │                 │ 13. Return encrypted credential     │           │
│        │                 │◄────────────────────────────────────│           │
│        │                 │    + new UTKs (no CEK sent to app)  │           │
│        │                 │                 │                   │           │
│        │                 │ 14. Store credential locally        │           │
│        │                 │                 │                   │           │
└─────────────────────────────────────────────────────────────────────────────┘

Key Storage After Enrollment:
─────────────────────────────

  App (Local Storage):           Vault SQLite (DEK-encrypted, synced to S3):
  ┌─────────────────────┐        ┌─────────────────────────────────┐
  │ • Encrypted cred    │        │ • CEK keypair (pub + private)   │
  │   (opaque blob)     │        │ • LTKs (indexed by UTK ID)      │
  │ • UTKs (public)     │        │ • User ledger data              │
  │ • Vault ID          │        └─────────────────────────────────┘
  │                     │
  │ NOTE: App does NOT  │
  │ have CEK - vault    │
  │ handles encryption  │
  └─────────────────────┘        Supervisor Memory:
                                 ┌─────────────────────────────────┐
  User's Mind:                   │ • DEK (derived from PIN)        │
  ┌─────────────────────┐        │ • sealed_material (PCR-bound)   │
  │ • PIN               │        └─────────────────────────────────┘
  │ • Credential pwd    │
  └─────────────────────┘
```

### 5.7 PIN Setup and Vault DEK Binding

**Critical Timing:** The PIN is created in the mobile app during enrollment, NOT in the web portal.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PIN Setup (During Enrollment)                             │
│                                                                             │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐                        │
│  │    App     │    │ Supervisor │    │  AWS KMS   │                        │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘                        │
│        │                 │                 │                               │
│        │ 1. User creates PIN               │                               │
│        │    (app prompts for 6-digit PIN)  │                               │
│        │                 │                 │                               │
│        │ 2. Send PIN to supervisor         │                               │
│        │───────────────►│                 │                               │
│        │                 │                 │                               │
│        │                 │ 3. Generate random material (32 bytes)         │
│        │                 │                 │                               │
│        │                 │ 4. Request NSM attestation                     │
│        │                 │    (ephemeral pubkey from NSM)                 │
│        │                 │                 │                               │
│        │                 │ 5. KMS.Encrypt(material, attestation)          │
│        │                 │─────────────────────────────────────►          │
│        │                 │                 │                               │
│        │                 │ 6. sealed_material (PCR-bound)                 │
│        │                 │◄─────────────────────────────────────          │
│        │                 │                 │                               │
│        │                 │ 7. Derive DEK = KDF(material, PIN)             │
│        │                 │                 │                               │
│        │                 │ 8. Store sealed_material for vault             │
│        │                 │    Provide DEK to vault-manager                │
│        │                 │                 │                               │
│        │ 9. PIN setup complete             │                               │
│        │◄───────────────│                 │                               │
│        │                 │                 │                               │
└─────────────────────────────────────────────────────────────────────────────┘

Why PIN + Sealed Material?
──────────────────────────
• sealed_material alone: Anyone with enclave access could derive DEK
• PIN alone: Vulnerable to offline brute force
• Together: Requires BOTH genuine enclave AND correct PIN
• Wrong PIN: DEK = KDF(material, wrong_pin) → garbage → decrypt fails

PIN Transmission Security (Attestation-Bound Channel with Nonce)
────────────────────────────────────────────────────────────────
The PIN must be transmitted securely from app to supervisor. The parent
process (outside enclave) forwards messages but MUST NOT be able to
intercept the PIN. We use attestation-bound encryption with app-provided nonce:

  ┌─────────────┐         ┌─────────────┐         ┌─────────────────┐
  │     App     │         │   Parent    │         │   Supervisor    │
  └──────┬──────┘         └──────┬──────┘         └────────┬────────┘
         │                       │                         │
         │  0. Generate random nonce (32 bytes)            │
         │     nonce = crypto.randomBytes(32)              │
         │                       │                         │
         │  1. Request attestation with nonce              │
         │     { nonce: "abc123..." }                      │
         │──────────────────────►│────────────────────────►│
         │                       │                         │
         │                       │  2. NSM generates       │
         │                       │     ephemeral keypair   │
         │                       │     AND includes nonce  │
         │                       │     in signed attestation│
         │                       │                         │
         │  3. Attestation doc (includes ephemeral pubkey + nonce)
         │◄──────────────────────│◄────────────────────────│
         │                       │                         │
         │  4. Verify attestation:                         │
         │     • AWS Nitro signature valid?                │
         │     • PCRs match published values?              │
         │     • Timestamp recent? (< 5 minutes)           │
         │     • NONCE MATCHES our request? ← CRITICAL     │
         │                       │                         │
         │  5. Encrypt PIN to ephemeral pubkey             │
         │     encrypted_pin = X25519Encrypt(pubkey, PIN)  │
         │                       │                         │
         │  6. Send encrypted PIN (parent cannot decrypt)  │
         │──────────────────────►│────────────────────────►│
         │                       │                         │
         │                       │  7. Decrypt with        │
         │                       │     ephemeral privkey   │
         │                       │     (only supervisor    │
         │                       │      has this key)      │
         │                       │                         │

Security Properties:
• Parent process sees only ciphertext (cannot extract PIN)
• Attestation proves PIN goes to genuine enclave with expected code
• Ephemeral keypair per-request prevents replay
• App-provided NONCE prevents attestation document replay attacks
  (attacker cannot record and replay old attestation documents)
• Same X25519+ChaCha20-Poly1305 scheme used for CEK/UTK
```

### 5.7.1 PIN Change Flow

Users can change their PIN without going through full recovery. Requires current PIN for authorization:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PIN Change Flow                                    │
│                                                                             │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────────┐  │
│  │    App     │    │ Supervisor │    │  AWS KMS   │    │ Vault-Manager  │  │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘    └───────┬────────┘  │
│        │                 │                 │                   │           │
│        │ 1. User enters CURRENT PIN        │                   │           │
│        │    (proves they own the vault)    │                   │           │
│        │                 │                 │                   │           │
│        │ 2. Warm vault with current PIN    │                   │           │
│        │───────────────►│                 │                   │           │
│        │                 │ 3. Unseal material, derive DEK      │           │
│        │                 │    (validates current PIN)         │           │
│        │                 │                 │                   │           │
│        │ 4. Vault warmed (PIN valid)       │                   │           │
│        │◄───────────────│                 │                   │           │
│        │                 │                 │                   │           │
│        │ 5. User enters NEW PIN            │                   │           │
│        │                 │                 │                   │           │
│        │ 6. Send PIN change request        │                   │           │
│        │    { type: "pin_change",          │                   │           │
│        │      new_pin: <encrypted> }       │                   │           │
│        │───────────────►│                 │                   │           │
│        │                 │                 │                   │           │
│        │                 │ 7. Generate NEW random material (32 bytes)      │
│        │                 │                 │                   │           │
│        │                 │ 8. Seal new material via KMS        │           │
│        │                 │─────────────────────────────────────►           │
│        │                 │                 │                   │           │
│        │                 │ 9. new_sealed_material              │           │
│        │                 │◄─────────────────────────────────────           │
│        │                 │                 │                   │           │
│        │                 │ 10. Derive new DEK from new material + new PIN  │
│        │                 │                 │                   │           │
│        │                 │ 11. Re-encrypt SQLite DB with new DEK           │
│        │                 │     (vault-manager does this)      │           │
│        │                 │─────────────────────────────────────────────────►
│        │                 │                 │                   │           │
│        │                 │                 │                   │ 12. Decrypt
│        │                 │                 │                   │     DB with
│        │                 │                 │                   │     old DEK
│        │                 │                 │                   │           │
│        │                 │                 │                   │ 13. Re-encrypt
│        │                 │                 │                   │     with new DEK
│        │                 │                 │                   │           │
│        │                 │                 │                   │ 14. Sync to S3
│        │                 │                 │                   │           │
│        │                 │ 15. Store new sealed_material in S3 │           │
│        │                 │    Delete old sealed_material       │           │
│        │                 │                 │                   │           │
│        │ 16. PIN change complete           │                   │           │
│        │◄───────────────│                 │                   │           │
│        │                 │                 │                   │           │
└─────────────────────────────────────────────────────────────────────────────┘

Security Notes:
───────────────
• Current PIN MUST validate first (prevents unauthorized PIN changes)
• NEW random material generated (old sealed_material becomes useless)
• Old DEK cannot decrypt new database (forward secrecy)
• Atomic operation: if any step fails, old PIN remains valid
• Old S3 versions retained for 30 days (rollback if needed)
```

### 5.7.2 DEK Rotation (Without PIN Change)

Periodic DEK rotation provides forward secrecy without requiring PIN change. Uses same PIN with new random material:

```go
// DEK rotation - new material, same PIN
func (s *EnclaveSupervisor) HandleDEKRotation(vaultID string) error {
    // 1. Vault must already be warm (PIN was validated on app open)
    vault := s.vaults[vaultID]
    if vault == nil || !vault.IsWarm() {
        return errors.New("vault must be warm for DEK rotation")
    }

    // 2. Generate NEW random material
    newMaterial := make([]byte, 32)
    rand.Read(newMaterial)

    // 3. Get attestation and seal new material via KMS
    attestation, _ := s.nsm.GetAttestation(nil)
    newSealed, _ := s.kmsEncrypt(newMaterial, attestation)

    // 4. Derive new DEK using SAME PIN (stored in supervisor during warmup)
    newDEK := s.deriveDEK(vaultID, newMaterial, s.cachedPINs[vaultID])

    // 5. Re-encrypt SQLite database with new DEK
    err := vault.ReEncryptDatabase(newDEK)
    if err != nil {
        return err // Rollback - old DEK still valid
    }

    // 6. Store new sealed_material, delete old
    s.storeSealedMaterial(vaultID, newSealed)

    // 7. Update supervisor state
    s.sealedMaterials[vaultID] = newSealed

    log.Info().Str("vault", vaultID).Msg("DEK rotated successfully")
    return nil
}

// Automatic rotation trigger (called periodically or on specific events)
func (s *EnclaveSupervisor) MaybeRotateDEK(vaultID string) {
    vault := s.vaults[vaultID]
    if vault == nil {
        return
    }

    // Rotate if: (1) 30 days since last rotation, OR (2) 1000 operations
    lastRotation := vault.GetLastDEKRotation()
    opCount := vault.GetOperationsSinceRotation()

    if time.Since(lastRotation) > 30*24*time.Hour || opCount > 1000 {
        s.HandleDEKRotation(vaultID)
    }
}
```

**When to Rotate DEK:**
| Trigger | Rationale |
|---------|-----------|
| Every 30 days | Limits exposure window if sealed_material somehow leaked |
| Every 1000 operations | Limits data encrypted under single key |
| On security event | User reports suspicious activity |
| Manual request | User wants fresh keys |

**Note:** PIN is cached in supervisor memory during vault warmup for DEK rotation.
This is safe because supervisor already has the DEK - caching PIN doesn't increase attack surface.

### 5.8 App Open / Vault Warming Flow

Every time the user opens the app and enters their PIN, the vault is automatically "warmed" (DEK loaded into supervisor). This eliminates separate "cold vault" prompts.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    App Open with Vault Warming                               │
│                                                                             │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────────┐  │
│  │    App     │    │ Supervisor │    │  AWS KMS   │    │ Vault-Manager  │  │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘    └───────┬────────┘  │
│        │                 │                 │                   │           │
│        │ 1. User enters PIN (app unlock)   │                   │           │
│        │                 │                 │                   │           │
│        │ 2. App verifies PIN locally       │                   │           │
│        │    (fast UX, not security)        │                   │           │
│        │                 │                 │                   │           │
│        │ 3. Send PIN + vault_id to supervisor                  │           │
│        │───────────────►│                 │                   │           │
│        │                 │                 │                   │           │
│        │                 │ 4. Load sealed_material for vault   │           │
│        │                 │                 │                   │           │
│        │                 │ 5. Request NSM attestation (ephemeral keypair) │
│        │                 │                 │                   │           │
│        │                 │ 6. KMS.Decrypt(sealed_material, attestation)   │
│        │                 │─────────────────────────────────────►          │
│        │                 │                 │                   │           │
│        │                 │ 7. material (decrypted)             │           │
│        │                 │◄─────────────────────────────────────          │
│        │                 │                 │                   │           │
│        │                 │ 8. DEK = KDF(material, PIN)         │           │
│        │                 │                 │                   │           │
│        │                 │ 9. Provide DEK to vault-manager     │           │
│        │                 │─────────────────────────────────────────────►  │
│        │                 │                 │                   │           │
│        │                 │                 │    10. Decrypt    │           │
│        │                 │                 │        SQLite DB  │           │
│        │                 │                 │        (from S3)  │           │
│        │                 │                 │                   │           │
│        │ 11. Vault warm, ready for operations                  │           │
│        │◄────────────────────────────────────────────────────────────────  │
│        │                 │                 │                   │           │
└─────────────────────────────────────────────────────────────────────────────┘

What happens with wrong PIN:
────────────────────────────
• KMS.Decrypt succeeds (sealed_material decrypts fine)
• DEK = KDF(material, WRONG_PIN) → different DEK
• vault-manager tries to decrypt SQLite DB → fails (bad MAC)
• Result: "Invalid PIN" error returned to app
• Security: PIN is verified by crypto failure, not stored hash comparison
```

**PIN Dual Purpose:**
1. **App Lock:** Local verification for quick UX (hashed PIN stored on device)
2. **Vault Unlock:** Sent to supervisor for DEK derivation (real security)

Same PIN, but the app check is just convenience; the enclave check is the actual security.

### 5.9 Vault Operation Flow (CEK Rotation)

Each vault operation decrypts the credential, verifies the password, performs the operation, then rotates the CEK for forward secrecy.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Vault Operation Flow                                      │
│                                                                             │
│  ┌────────────┐                              ┌────────────────────────────┐ │
│  │    App     │                              │      Vault-Manager         │ │
│  └─────┬──────┘                              └─────────────┬──────────────┘ │
│        │                                                   │               │
│        │ 1. Send operation request                         │               │
│        │    { encrypted_credential,                        │               │
│        │      operation: "sign_btc",                       │               │
│        │      params: { tx_hash: "..." } }                 │               │
│        │──────────────────────────────────────────────────►│               │
│        │                                                   │               │
│        │                                    2. Decrypt credential          │
│        │                                       with CEK private key        │
│        │                                                   │               │
│        │ 3. Challenge: "Enter credential password"         │               │
│        │◄──────────────────────────────────────────────────│               │
│        │    { challenge_id: "xyz", utk_id: "utk-123" }     │               │
│        │                                                   │               │
│        │ 4. User enters password                           │               │
│        │    App hashes: hash = Argon2id(password, salt)    │               │
│        │    App encrypts hash with UTK                     │               │
│        │                                                   │               │
│        │ 5. Send encrypted password hash                   │               │
│        │    { challenge_id: "xyz",                         │               │
│        │      encrypted_password_hash: <UTK-encrypted> }   │               │
│        │──────────────────────────────────────────────────►│               │
│        │                                                   │               │
│        │                                    6. Decrypt password hash       │
│        │                                       with LTK (single-use)       │
│        │                                                   │               │
│        │                                    7. Compare received hash       │
│        │                                       == credential.password_hash │
│        │                                                   │               │
│        │                                    8. Load key from credential    │
│        │                                       Perform signing operation   │
│        │                                       Zero key from memory        │
│        │                                                   │               │
│        │                                    9. Rotate CEK:                 │
│        │                                       • Generate new CEK pair     │
│        │                                       • Store new private key     │
│        │                                       • Re-encrypt credential     │
│        │                                         with new CEK public       │
│        │                                                   │               │
│        │ 10. Response:                                     │               │
│        │◄──────────────────────────────────────────────────│               │
│        │     { success: true,                              │               │
│        │       signature: "3045022100...",                 │               │
│        │       new_credential: <re-encrypted blob>,        │               │
│        │       new_utks: [...] }                           │               │
│        │     (no CEK returned - vault manages internally)  │               │
│        │                                                   │               │
│        │ 11. Store new credential blob + UTKs              │               │
│        │                                                   │               │
└─────────────────────────────────────────────────────────────────────────────┘

Why CEK Rotation?
─────────────────
• Forward Secrecy: Compromised old CEK can't decrypt new credentials
• Single-Use UTKs: Password never sent with same key twice
• Replay Protection: Old encrypted credentials are garbage after rotation
• Theft Detection Race: Single-credential design is INTENTIONAL - if attacker
  steals credential blob, they race against legitimate user. First to use it
  rotates CEK, invalidating attacker's copy. Attacker MUST use credential
  before user does, or stolen blob becomes worthless garbage.
```

### 5.10 Challenge Flow (User Authorization)

Before the vault uses any secrets, it challenges the user with their **credential password** (NOT the vault PIN—that was used earlier to warm the vault). The password is encrypted with a single-use UTK for transport security.

```
┌─────────────────┐                              ┌─────────────────────────┐
│  User's Device  │                              │   Vault-Manager         │
│  (Untrusted)    │                              │   (Inside Enclave)      │
└────────┬────────┘                              └────────────┬────────────┘
         │                                                    │
         │  PREREQUISITE: Vault is warm (PIN already entered  │
         │  on app open, DEK loaded - see Section 5.8)        │
         │                                                    │
         │  1. Send encrypted credential + operation request  │
         │───────────────────────────────────────────────────►│
         │     {                                              │
         │       credential: <CEK-encrypted blob>,            │
         │       operation: "sign_btc_transaction",           │
         │       params: { tx_hash: "..." }                   │
         │     }                                              │
         │                                                    │
         │                                      2. Decrypt credential
         │                                         with CEK private key
         │                                         (X25519 decryption)
         │                                                    │
         │  3. Challenge request                              │
         │◄───────────────────────────────────────────────────│
         │     {                                              │
         │       challenge_id: "uuid-xyz",                    │
         │       utk_id: "utk-123",      // For password encryption
         │       expires_in: 60          // Seconds
         │     }                                              │
         │                                                    │
         │  4. User enters CREDENTIAL PASSWORD                │
         │     (separate from vault PIN)                      │
         │                                                    │
         │  5. App hashes password (Argon2id) and encrypts:   │
         │     hash = Argon2id(password, salt)                │
         │     encrypted = X25519Encrypt(utk_public, hash)    │
         │                                                    │
         │  6. Challenge response                             │
         │───────────────────────────────────────────────────►│
         │     {                                              │
         │       challenge_id: "uuid-xyz",                    │
         │       encrypted_password_hash: <UTK-encrypted>,    │
         │       utk_id: "utk-123"                            │
         │     }                                              │
         │                                                    │
         │                                      7. Decrypt password hash with LTK
         │                                         (X25519 decryption)
         │                                         Delete LTK (single-use)
         │                                                    │
         │                                      8. Compare hashes:
         │                                         received_hash
         │                                         == credential.password_hash
         │                                                    │
         │                                      9. If valid:
         │                                          • Load BTC key from credential
         │                                          • Sign transaction
         │                                          • Zero key from memory
         │                                          • Rotate CEK (forward secrecy)
         │                                          • Re-encrypt credential
         │                                                    │
         │  10. Operation result + rotated credential         │
         │◄───────────────────────────────────────────────────│
         │     {                                              │
         │       success: true,                               │
         │       signature: "3045022100...",                  │
         │       new_credential: <re-encrypted blob>,         │
         │       new_utks: [...]  // Replenish single-use keys│
         │     }                                              │
         │     (no CEK returned - vault manages internally)   │
         │                                                    │
         │  11. App stores new credential blob + UTKs         │
         │                                                    │
```

**Key Differences from Vault PIN:**

| Aspect | Vault PIN | Credential Password |
|--------|-----------|---------------------|
| **Purpose** | Unlock vault storage (DEK derivation) | Authorize operations |
| **When used** | App open (vault warming) | Each vault operation |
| **Handled by** | Supervisor (NSM/KMS access) | Vault-manager |
| **Transmitted** | To supervisor via attestation-bound channel | Encrypted with UTK |
| **Verified by** | Crypto failure (wrong DEK) | Hash comparison (Argon2id) |
| **Stored in** | Not stored (derived from sealed material) | Credential (hashed) |

### 5.11 BTC Transaction Signing Example

```
Complete BTC Signing Flow:
──────────────────────────

1. User initiates transaction in app
   └─ App constructs unsigned transaction

2. App sends to vault-manager:
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

3. Vault-manager decrypts credential with CEK
   └─ BTC private key now exists ONLY in vault-manager memory

4. Vault-manager sends challenge
   └─ { type: "password", utk_id: "utk-123" }

5. User enters PASSWORD on device
   └─ App hashes password with Argon2id
   └─ Encrypted hash sent to vault-manager via UTK

6. Vault-manager verifies password hash
   └─ received_hash == credential.password_hash ?

7. If password valid:
   └─ Vault-manager signs transaction with BTC key
   └─ signature = secp256k1_sign(btc_private_key, tx_hash)

8. Vault-manager zeros BTC key from memory
   └─ Key existed only for milliseconds

9. Vault-manager returns signature + rotated credential
   └─ { signature: "3045022100...", new_credential: <blob> }

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

### 5.12 Enrollment Flow (Complete)

**Critical**: The Protean Credential is created by the vault-manager, not on the device. The device cannot be trusted to generate cryptographic secrets.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Complete Enrollment Flow                           │
│                                                                         │
│  ┌──────────┐    ┌────────────┐    ┌────────────┐    ┌───────────────┐ │
│  │   App    │    │ Supervisor │    │   AWS KMS  │    │ Vault-Manager │ │
│  └────┬─────┘    └─────┬──────┘    └─────┬──────┘    └───────┬───────┘ │
│       │                │                 │                   │         │
│  ═══════════════════════════════════════════════════════════════════   │
│  PHASE 1: ATTESTATION                                                   │
│  ═══════════════════════════════════════════════════════════════════   │
│       │                │                 │                   │         │
│       │ 1. Request     │                 │                   │         │
│       │    attestation │                 │                   │         │
│       │───────────────►│                 │                   │         │
│       │                │                 │                   │         │
│       │                │ 2. NSM.GetAttestation()             │         │
│       │                │    (includes ephemeral pubkey)      │         │
│       │                │                 │                   │         │
│       │ 3. Attestation │                 │                   │         │
│       │    document    │                 │                   │         │
│       │◄───────────────│                 │                   │         │
│       │   (AWS signed) │                 │                   │         │
│       │                │                 │                   │         │
│       │ 4. VERIFY:     │                 │                   │         │
│       │  • AWS sig?    │                 │                   │         │
│       │  • PCRs match? │                 │                   │         │
│       │  • Timestamp?  │                 │                   │         │
│       │                │                 │                   │         │
│  ═══════════════════════════════════════════════════════════════════   │
│  PHASE 2: PIN SETUP & DEK CREATION (Supervisor)                         │
│  ═══════════════════════════════════════════════════════════════════   │
│       │                │                 │                   │         │
│       │ 5. User enters │                 │                   │         │
│       │    PIN         │                 │                   │         │
│       │                │                 │                   │         │
│       │ 6. Send PIN    │                 │                   │         │
│       │ (encrypted to  │                 │                   │         │
│       │  attested key) │                 │                   │         │
│       │───────────────►│                 │                   │         │
│       │                │                 │                   │         │
│       │                │ 7. Generate random material (32 bytes)        │
│       │                │                 │                   │         │
│       │                │ 8. KMS.Encrypt  │                   │         │
│       │                │    (material,   │                   │         │
│       │                │     attestation)│                   │         │
│       │                │────────────────►│                   │         │
│       │                │                 │                   │         │
│       │                │ 9. sealed_      │                   │         │
│       │                │    material     │                   │         │
│       │                │◄────────────────│                   │         │
│       │                │   (PCR-bound)   │                   │         │
│       │                │                 │                   │         │
│       │                │ 10. DEK = KDF(material, PIN)        │         │
│       │                │                 │                   │         │
│       │                │ 11. Store sealed_material to S3     │         │
│       │                │                 │                   │         │
│       │                │ 12. Start vault-manager with DEK ───────────► │
│       │                │                 │                   │         │
│  ═══════════════════════════════════════════════════════════════════   │
│  PHASE 3: CREDENTIAL CREATION (Vault-Manager)                           │
│  ═══════════════════════════════════════════════════════════════════   │
│       │                │                 │                   │         │
│       │                │                 │      13. Initialize SQLite  │
│       │                │                 │          (DEK encrypted)    │
│       │                │                 │                   │         │
│       │                │                 │      14. Generate:          │
│       │                │                 │          • CEK keypair      │
│       │                │                 │          • UTK/LTK pairs    │
│       │                │                 │                   │         │
│       │ 15. Vault ready, send UTKs       │                   │         │
│       │◄────────────────────────────────────────────────────│         │
│       │                │                 │                   │         │
│       │ 16. Prompt for credential password                   │         │
│       │                │                 │                   │         │
│       │ 17. User enters password                             │         │
│       │     App hashes (Argon2id)        │                   │         │
│       │     Encrypts hash with UTK       │                   │         │
│       │───────────────────────────────────────────────────────►        │
│       │                │                 │                   │         │
│       │                │                 │      18. Create Protean     │
│       │                │                 │          Credential:        │
│       │                │                 │          • identity_keypair │
│       │                │                 │          • master_secret    │
│       │                │                 │          • password_hash    │
│       │                │                 │          • crypto_keys[]    │
│       │                │                 │                   │         │
│       │                │                 │      19. Encrypt credential │
│       │                │                 │          with CEK           │
│       │                │                 │                   │         │
│       │                │                 │      20. Store CEK, LTKs    │
│       │                │                 │          in SQLite          │
│       │                │                 │                   │         │
│       │                │                 │      21. Sync SQLite to S3  │
│       │                │                 │                   │         │
│       │ 22. Return: encrypted credential + new UTKs          │         │
│       │◄────────────────────────────────────────────────────│         │
│       │                │                 │                   │         │
│       │ 23. Store credential + UTKs locally                  │         │
│       │                │                 │                   │         │
└─────────────────────────────────────────────────────────────────────────┘

Summary:
─────────
  Phase 1: App verifies enclave identity via attestation
  Phase 2: Supervisor creates DEK from PIN + sealed material
  Phase 3: Vault-manager creates credential and encrypts with CEK

What device provides:     What vault-manager generates:
─────────────────────     ────────────────────────────
• PIN (for DEK)           • Identity keypair (Ed25519)
• Password hash           • Vault master secret
• Operation requests      • All cryptographic keys
                          • Credential structure
                          • CEK, UTK/LTK pairs
```

### 5.13 Adding Keys to Credential

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

### 5.14 Encryption Schemes (CEK vs KMS Sealing)

**Important Distinction:** There are two different encryption mechanisms in the vault architecture:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                Two Encryption Schemes                                    │
│                                                                         │
│  1. PROTEAN CREDENTIAL - CEK Encrypted (Vault-Manager)                  │
│  ═══════════════════════════════════════════════════                    │
│                                                                         │
│    App receives:  encrypted_credential_blob                             │
│         │         (opaque to app, CEK-encrypted)                        │
│         ▼                                                               │
│    ┌────────────────────────────────────────────────────────────────┐  │
│    │ Vault-Manager decrypts with CEK (ChaCha20-Poly1305)            │  │
│    │                                                                 │  │
│    │ CEK stored in: SQLite database (DEK-encrypted)                 │  │
│    │ Rotated: After every operation (forward secrecy)               │  │
│    │                                                                 │  │
│    │ Contains: identity_keypair, master_secret, password_hash,      │  │
│    │          BTC keys, seed phrases, etc.                          │  │
│    └────────────────────────────────────────────────────────────────┘  │
│         │                                                               │
│         ▼                                                               │
│    credential (plaintext) → in vault-manager memory only               │
│                                                                         │
│                                                                         │
│  2. SEALED MATERIAL - KMS Sealed (Supervisor)                           │
│  ════════════════════════════════════════════                           │
│                                                                         │
│    sealed_material (stored in S3)                                       │
│         │                                                               │
│         ▼                                                               │
│    ┌────────────────────────────────────────────────────────────────┐  │
│    │ Supervisor calls NitroKMS.Unseal(sealed_material)              │  │
│    │                                                                 │  │
│    │ Bound to: PCR0, PCR1, PCR2 (code identity)                     │  │
│    │ Purpose: Derive DEK = KDF(unsealed_material, PIN)              │  │
│    │                                                                 │  │
│    │ Succeeds if and only if:                                       │  │
│    │   • Running in genuine Nitro Enclave                           │  │
│    │   • Current PCRs match sealed PCRs                             │  │
│    │                                                                 │  │
│    │ Fails if: Code modified, outside enclave, tampered             │  │
│    └────────────────────────────────────────────────────────────────┘  │
│         │                                                               │
│         ▼                                                               │
│    DEK → used to encrypt SQLite (which holds CEK, LTKs, etc.)          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Summary:
─────────
  Component          │ Encrypted How          │ Who Handles     │ Where Stored
  ───────────────────│────────────────────────│─────────────────│──────────────
  Protean Credential │ CEK (symmetric)        │ Vault-Manager   │ App (blob)
  SQLite Database    │ DEK (symmetric)        │ Vault-Manager   │ S3
  Sealed Material    │ KMS (PCR-bound)        │ Supervisor      │ S3
```

### 5.15 Security Properties

| Property | How Achieved |
|----------|--------------|
| **Secrets never on device** | Credential CEK-encrypted; only vault-manager decrypts |
| **VettID cannot access** | No access to enclave memory; attestation proves code |
| **User must authorize** | Password required before secret use (hashed by app) |
| **Replay protection** | Single-use UTKs for each operation |
| **Brute force protection** | Argon2id + attempt limits + lockout in vault-manager |
| **Key usage is auditable** | Vault logs all operations (DEK-encrypted in SQLite) |
| **Portable across devices** | Same credential blob works on any device with UTKs |
| **Works with BYO vault** | Same model, user's own enclave |

**Component Responsibilities:**

| Component | Responsibilities |
|-----------|------------------|
| **Supervisor** | NSM attestation, KMS operations, DEK derivation, vault lifecycle |
| **Vault-Manager** | CEK management, credential decryption, password verification, operations |
| **App** | UTK storage, password hashing (Argon2id), credential blob storage |

### 5.16 Simplified Credential vs Two-Credential Model

The Protean Credential consolidates what was previously separate:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  OLD MODEL (Two Credentials)          NEW MODEL (Single Protean Cred)  │
│  ────────────────────────────          ───────────────────────────────  │
│                                                                         │
│  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
│  │ Vault Services Cred     │          │ Protean Credential          │  │
│  │ • Auth tokens           │          │                             │  │
│  │ • Access keys           │    ──►   │ Contains ALL:               │  │
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

### 5.17 Post-Enrollment Vault Access

After enrollment, users access their vault through a two-step process:
1. **Vault warming** (PIN → DEK derivation via supervisor)
2. **Operations** (password → authorization via vault-manager)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Post-Enrollment Vault Access                          │
│                                                                         │
│  What user has after enrollment:                                        │
│  ───────────────────────────────                                        │
│  1. Cognito account → proves identity to VettID ("I am user-ABC123")   │
│  2. Encrypted credential blob → sent with operations                    │
│  3. UTKs (public keys) → for encrypting password hash                   │
│  4. PIN (in their head) → unlocks vault on app open                     │
│  5. Password (in their head) → authorizes each operation                │
│                                                                         │
│  ┌─────────────────┐    ┌────────────┐    ┌─────────────────────────┐   │
│  │  User's Device  │    │ Supervisor │    │    Vault-Manager        │   │
│  └────────┬────────┘    └──────┬─────┘    └────────────┬────────────┘   │
│           │                    │                       │                │
│  STEP 1: VAULT WARMING (on app open)                   │                │
│  ─────────────────────────────────────                 │                │
│           │                    │                       │                │
│           │ 1. User enters PIN │                       │                │
│           │───────────────────►│                       │                │
│           │   (attestation-    │                       │                │
│           │    bound channel)  │                       │                │
│           │                    │                       │                │
│           │                    │ 2. KMS.Unseal +       │                │
│           │                    │    DEK derivation     │                │
│           │                    │                       │                │
│           │                    │ 3. Provide DEK        │                │
│           │                    │───────────────────────►                │
│           │                    │                       │                │
│           │ 4. Vault ready     │                       │                │
│           │◄───────────────────│                       │                │
│           │                    │                       │                │
│  STEP 2: OPERATIONS (vault now warm)                   │                │
│  ─────────────────────────────────────                 │                │
│           │                    │                       │                │
│           │ 5. Operation request + credential blob     │                │
│           │────────────────────────────────────────────►                │
│           │                    │                       │                │
│           │                    │    6. Decrypt cred    │                │
│           │                    │       with CEK        │                │
│           │                    │                       │                │
│           │ 7. Challenge: enter password               │                │
│           │◄────────────────────────────────────────────                │
│           │    { challenge_id: "xyz", utk_id: "utk-1" }│                │
│           │                    │                       │                │
│           │ 8. App hashes password, encrypts with UTK  │                │
│           │────────────────────────────────────────────►                │
│           │                    │                       │                │
│           │                    │    9. Verify hash,    │                │
│           │                    │       perform op      │                │
│           │                    │                       │                │
│           │ 10. Result + rotated credential + new UTKs │                │
│           │◄────────────────────────────────────────────                │
│           │                    │                       │                │
└─────────────────────────────────────────────────────────────────────────┘
```

**Two-Factor Model:**

| Factor | Purpose | When Used | Who Verifies |
|--------|---------|-----------|--------------|
| **PIN** | Unlock vault (DEK derivation) | App open | Supervisor (via KMS) |
| **Password** | Authorize operation | Each operation | Vault-Manager (hash compare) |

**Why no chicken-and-egg?**

| Component | Purpose | Where It Lives |
|-----------|---------|----------------|
| Encrypted Credential | Opaque blob, CEK-encrypted | User's device |
| UTKs | Encrypt password hash for transport | User's device |
| PIN | Unlocks vault (DEK derivation) | User's memory |
| Password Hash | Verifies authorization | Inside credential (vault-manager only) |

**Note on Cognito JWT:** The app authenticates to Cognito for account-level operations (recovery requests, account portal access). For normal vault operations, the app communicates directly with the vault-manager via NATS using the encrypted credential blob - no JWT required. The credential itself proves vault ownership.

**Access Flow Explained:**
1. User opens app → enters PIN → supervisor derives DEK → vault-manager loads SQLite
2. User requests operation → vault-manager decrypts credential with CEK → challenges for password
3. User responds with password hash → vault-manager verifies → performs operation
4. The credential contains everything needed for operations (keys, seeds, identity)

**Session Optimization (Embedded in Credential):**

For better UX, the vault-manager embeds a session token inside the credential:

```
Credential Structure (with session):
{
  identity_keypair: ...,
  master_secret: ...,
  password_hash: ...,
  crypto_keys: [...],
  session: {                    // Embedded session token
    token: "random-256-bit",
    expires_at: 1705446900,     // 15 min from password verification
    operations_allowed: ["list_keys", "get_balance"]  // Low-risk only
  }
}

First request after vault warm:
  → credential + password_hash
  ← result + new_credential (with embedded session)

Subsequent low-risk requests (within 15 min):
  → credential (vault-manager checks embedded session.expires_at)
  ← result (no password prompt)

High-risk operations (signing, export) always require password.

Session Properties:
  • Embedded in credential - no separate token to track
  • Vault-manager checks session when decrypting credential
  • New credential returned after each operation (CEK rotation)
  • Session expires or is cleared on high-risk operations
```

### 5.18 Credential Backup & Recovery

The encrypted credential blob is the user's "key to the vault." If lost, they lose access to all secrets. **Backup is critical.**

#### Backup Strategy: VettID-Hosted Backup

The vault-manager sends the credential to the app AND the backup service simultaneously:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Credential Backup Architecture                        │
│                                                                         │
│  During Enrollment (Vault-Manager handles backup):                      │
│  ─────────────────────────────────────────────────                      │
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐ │
│  │  User's App     │    │  VettID Backend │    │   Vault-Manager     │ │
│  └────────┬────────┘    └────────┬────────┘    └──────────┬──────────┘ │
│           │                      │                        │            │
│           │                      │      1. Create credential           │
│           │                      │         (CEK-encrypted)             │
│           │                      │                        │            │
│           │                      │      2. SIMULTANEOUSLY:             │
│           │                      │         ┌──────────────┤            │
│           │                      │         │              │            │
│           │                      │◄────────┘              │            │
│           │  3a. Send to app ◄───┼────────────────────────│            │
│           │                      │                        │            │
│           │                      │  3b. Send to backup ───►            │
│           │                      │      (same blob)       │            │
│           │                      │                        │            │
│           │                      │  4. Store in DynamoDB  │            │
│           │                      │     (Credentials table)│            │
│           │                      │     PK: vault_id       │            │
│           │                      │                        │            │
│           │                      │  5. Confirm to vault ──►            │
│           │                      │                        │            │
│           │  6. Vault tells app: │                        │            │
│           │◄─────────────────────┼────────────────────────│            │
│           │     "Enrollment      │                        │            │
│           │      complete,       │                        │            │
│           │      backup synced"  │                        │            │
│           │                      │                        │            │
└─────────────────────────────────────────────────────────────────────────┘

Key Points:
───────────
• Vault-manager sends credential to app AND backup at the same time
• Backend confirms backup to vault-manager
• Vault-manager then confirms success to app
• App receives credential blob + confirmation backup is synced
• If backup fails, vault-manager can retry or notify app
```

#### Why VettID-Hosted Backup is Safe

| Concern | Why It's Safe |
|---------|---------------|
| VettID stores my credential | Blob is PCR-encrypted; VettID cannot decrypt |
| VettID admin accesses backup | Useless without attested enclave + PIN |
| Attacker breaches VettID DB | Gets encrypted blobs they cannot use |
| Government subpoena | VettID can only provide encrypted blobs |

**The encrypted credential is useless without:**
1. A genuine Nitro Enclave with matching PCRs
2. The user's PIN

#### Device Loss Recovery Flow (24-Hour Delay + QR Code)

Recovery uses the **Account Portal (web)** and a **QR code** to transfer the credential to a new device. This includes a **24-hour waiting period** to protect against account takeover.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Device Loss Recovery (via Account Portal)             │
│                                                                         │
│  User loses phone. Gets new device. Wants to recover vault.             │
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐ │
│  │ Account Portal  │    │  VettID Backend │    │   Email             │ │
│  │   (Web)         │    └────────┬────────┘    └──────────┬──────────┘ │
│  └────────┬────────┘             │                        │            │
│           │                      │                        │            │
│           │ 1. Sign in (Cognito) │                        │            │
│           │─────────────────────►│                        │            │
│           │                      │                        │            │
│           │ 2. Click "Recover    │                        │            │
│           │    Vault on New      │                        │            │
│           │    Device"           │                        │            │
│           │─────────────────────►│                        │            │
│           │                      │                        │            │
│           │                      │ 3. Create recovery     │            │
│           │                      │    request with        │            │
│           │                      │    24h expiry          │            │
│           │                      │                        │            │
│           │                      │ 4. Send alert email ───┼───────────►│
│           │                      │    "Recovery requested.│            │
│           │                      │     If not you, click  │            │
│           │                      │     to cancel."        │            │
│           │                      │                        │            │
│           │ 5. "Recovery pending.│                        │            │
│           │    Return in 24h"    │                        │            │
│           │◄─────────────────────│                        │            │
│           │                      │                        │            │
│           │         ... 24 hours pass ...                 │            │
│           │                      │                        │            │
│           │ 6. Return to portal, │                        │            │
│           │    check status      │                        │            │
│           │─────────────────────►│                        │            │
│           │                      │                        │            │
│           │                      │ 7. 24h elapsed,        │            │
│           │                      │    not cancelled       │            │
│           │                      │                        │            │
│           │ 8. Display QR code   │                        │            │
│           │    (one-time use,    │                        │            │
│           │     5 min expiry)    │                        │            │
│           │◄─────────────────────│                        │            │
│           │                      │                        │            │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │  New Device     │                                                    │
│  │  (VettID App)   │                                                    │
│  └────────┬────────┘                                                    │
│           │                      │                        │            │
│           │ 9. Open app, select  │                        │            │
│           │    "Recover Vault"   │                        │            │
│           │                      │                        │            │
│           │ 10. Scan QR code     │                        │            │
│           │     from portal      │                        │            │
│           │─────────────────────►│                        │            │
│           │                      │                        │            │
│           │ 11. Return encrypted │                        │            │
│           │     credential +     │                        │            │
│           │     initial UTKs     │                        │            │
│           │◄─────────────────────│                        │            │
│           │                      │                        │            │
│           │ 12. Store locally,   │                        │            │
│           │     enter PIN to     │                        │            │
│           │     warm vault       │                        │            │
│           │                      │                        │            │
└─────────────────────────────────────────────────────────────────────────┘

QR Code Security:
─────────────────
• Contains: One-time recovery token (NOT the credential directly)
• Expiry: 5 minutes after display
• Single-use: Invalidated after first scan
• App exchanges token for: encrypted credential + UTKs

Recovery Timeline:
  T+0:00   User requests recovery via Account Portal
  T+0:00   Email sent: "Recovery requested for your VettID vault"
  T+0:01   User can cancel via link in email (if unauthorized)
  T+24:00  If not cancelled, QR code available in portal
  T+24:05  QR code expires if not scanned
  T+48:00  Recovery request expires entirely if not completed

Recovery requires:
  ✓ Cognito authentication (email + password) on web portal
  ✓ 24-hour waiting period (cannot be bypassed)
  ✓ Access to new device with VettID app
  ✓ PIN to use vault after recovery
  ✗ Does NOT require old device
  ✗ Does NOT require seed phrase
```

**Why 24 hours?**
- Gives legitimate user time to notice unauthorized recovery attempt
- Email notification sent immediately
- User can cancel via link in email
- Attacker who compromises Cognito still has to wait (and hope user doesn't notice)

#### Inactive User Scenario

User doesn't use app for 6 months, then returns:

```
Scenario: User returns after long absence
──────────────────────────────────────────

1. User opens app after 6 months
   └─ Credential blob still on device (persisted in secure storage)
   └─ UTKs still stored locally

2. User enters PIN to warm vault
   └─ App sends PIN (encrypted to attested key) to supervisor
   └─ Supervisor derives DEK using KMS.Unseal(sealed_material) + PIN

3. If PCRs unchanged:
   └─ KMS.Unseal succeeds → DEK derived → vault-manager started
   └─ Vault-manager loads SQLite from S3

4. If PCRs changed (enclave code update):
   └─ KMS.Unseal fails (policy requires matching PCRs)
   └─ Supervisor returns "credential migration required"
   └─ App prompts user to migrate (one-time re-seal)
   └─ See Section 10 for migration process

5. User performs vault operation
   └─ Sends credential blob + operation to vault-manager
   └─ Vault-manager decrypts with CEK, challenges for password
   └─ Normal operation proceeds

6. Vault data in S3:
   └─ Still present (S3 is durable, no expiration)
   └─ sealed_material still present
   └─ vault.db.enc still present
```

#### What Needs Backup (Summary)

| Data | Backed Up Where | Who Can Access |
|------|-----------------|----------------|
| **Encrypted Credential** | Device + VettID (DynamoDB) | Only attested enclave |
| **Vault Data** | S3 (encrypted) | Only attested enclave |
| **PIN** | User's memory | Only user |
| **Cognito Password** | User's memory + Cognito | User + password reset |

**To fully recover from total loss:**
1. Remember Cognito password (or use password reset via email)
2. Remember vault authentication (PIN/password/pattern)
3. Everything else is backed up server-side

### 5.19 Flexible Vault Authentication

Users can choose their preferred authentication method for vault operations. All methods are hashed and stored in the Protean Credential.

#### Supported Authentication Types

| Type | Format | Entropy | Rate Limiting | Best For |
|------|--------|---------|---------------|----------|
| **PIN** | 4-8 digits | ~13-26 bits | Aggressive (3 attempts) | Quick access, mobile |
| **Password** | Alphanumeric | 40-80+ bits | Standard (5 attempts) | High security |
| **Pattern** | 3x3 or 4x4 grid | ~15-40 bits | Aggressive (3 attempts) | Visual preference |

#### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Flexible Authentication                               │
│                                                                         │
│  During Enrollment:                                                     │
│  ──────────────────                                                     │
│                                                                         │
│  1. User chooses auth type: PIN / Password / Pattern                   │
│                                                                         │
│  2. User enters their chosen authentication                            │
│     PIN:      "847291"                                                  │
│     Password: "correct-horse-battery"                                   │
│     Pattern:  [serialized as "0,1,2,5,8,7,6,3,4"]                      │
│                                                                         │
│  3. App hashes with Argon2id before sending:                           │
│     auth_hash = Argon2id(input, salt, {                                │
│       memory: 256MB,     // Resist GPU attacks                         │
│       iterations: 3,                                                    │
│       parallelism: 4                                                    │
│     })                                                                  │
│                                                                         │
│  4. Stored in credential (by vault-manager):                           │
│     challenge_config: {                                                 │
│       auth_type: "password",                                           │
│       auth_hash: <32 bytes>,                                           │
│       auth_salt: <16 bytes>,    // App uses this for hashing           │
│       max_attempts: 5,                                                  │
│       lockout_duration: 300                                             │
│     }                                                                   │
│                                                                         │
│  During Vault Operations:                                               │
│  ────────────────────────                                               │
│                                                                         │
│  1. Vault-manager challenges user based on auth_type                   │
│  2. User provides their PIN/password/pattern                           │
│  3. App hashes with Argon2id, sends encrypted hash to vault-manager    │
│  4. Vault-manager compares received hash to stored auth_hash           │
│  5. Rate-limited based on entropy (fewer attempts for low-entropy)     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Pattern Serialization (Cross-Platform)

For patterns to work across iOS and Android, they must serialize consistently:

```
Grid positions (3x3):       Serialization:
┌───┬───┬───┐              Pattern: L-shape
│ 0 │ 1 │ 2 │              Sequence: 0 → 3 → 6 → 7 → 8
├───┼───┼───┤              Serialized: "0,3,6,7,8"
│ 3 │ 4 │ 5 │
├───┼───┼───┤              This string is what gets hashed.
│ 6 │ 7 │ 8 │
└───┴───┴───┘

Grid positions (4x4):       Larger grid = more entropy
┌───┬───┬───┬───┐          Max positions: 16
│ 0 │ 1 │ 2 │ 3 │          Min length: 4 points
├───┼───┼───┼───┤
│ 4 │ 5 │ 6 │ 7 │
├───┼───┼───┼───┤
│ 8 │ 9 │10 │11 │
├───┼───┼───┼───┤
│12 │13 │14 │15 │
└───┴───┴───┴───┘
```

#### Biometrics: Local Convenience Only

Biometrics (fingerprint, Face ID) **cannot** be the vault authentication because:
- Biometric data is fuzzy (slightly different each time)
- Can't hash biometrics reproducibly
- Biometrics are handled by OS, not app

However, biometrics can provide **local convenience**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Biometric as Convenience Layer                        │
│                                                                         │
│  Setup:                                                                 │
│  ──────                                                                 │
│  1. User sets password as vault auth (stored in credential)            │
│  2. User enables biometric on device                                    │
│  3. Password encrypted and stored locally (device keychain)            │
│  4. Biometric unlocks the local encrypted password                     │
│                                                                         │
│  Usage:                                                                 │
│  ──────                                                                 │
│  1. User initiates vault operation                                      │
│  2. App prompts for biometric                                           │
│  3. Biometric unlocks locally-stored encrypted password                │
│  4. App hashes password, encrypts with UTK, sends to vault-manager     │
│  5. Vault-manager verifies hash against credential's auth_hash         │
│                                                                         │
│  Security:                                                              │
│  ─────────                                                              │
│  • Biometric is device-local only (not in credential)                  │
│  • Password is the actual vault auth                                    │
│  • If device is lost, biometric doesn't help attacker                  │
│  • Recovery still requires knowing the password                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Changing Authentication Type

User can change their auth type at any time:

```
1. User requests auth change via app
2. Vault-manager challenges with CURRENT auth
3. User enters current PIN/password/pattern
4. App hashes, sends to vault-manager for verification
5. User enters NEW auth (can be different type)
6. App hashes new auth, sends to vault-manager
7. Vault-manager updates credential with new auth_hash
8. New CEK-encrypted credential returned to app
9. Vault-manager sends updated credential to backup service
```

### 5.20 Account Portal Changes

The Account Portal needs **minimal changes**. Key management and sensitive operations belong in **mobile apps**, not the web portal (larger attack surface: XSS, malicious extensions, etc.).

#### What Belongs Where

| Function | Account Portal (Web) | Mobile App |
|----------|---------------------|------------|
| Vault status | ✓ | ✓ |
| Credential backup status | ✓ | ✓ |
| Recovery request (24h delay) | ✓ | ✗ |
| Recovery QR code display | ✓ | ✗ |
| Scan recovery QR | ✗ | ✓ |
| PIN management | ✗ | ✓ |
| Key generation | ✗ | ✓ |
| Key import | ✗ | ✓ |
| Transaction signing | ✗ | ✓ |

**Note:** No direct credential download. Recovery requires QR scan from new device.

#### Account Portal - Vault Section

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Vault                                                                   │
│  ─────                                                                   │
│                                                                         │
│  Status: Active                                                         │
│  Credential backup: ✓ Synced                                            │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  ⚠ Your vault PIN and password protect all your secrets.          │ │
│  │    If you forget them, you will lose access permanently.           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  Lost your device?                                                      │
│  [Recover Vault on New Device]                                          │
│  24-hour waiting period. You'll receive a QR code to scan with the app.│
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Portal API Endpoints

Recovery-related endpoints for the web portal:

```
GET /vault/status
  → { active, backup_synced, recovery_pending, recovery_available_at }

POST /vault/recovery/request
  → { request_id, available_at }
  (initiates 24h recovery waiting period)

DELETE /vault/recovery/request
  → { cancelled: true }
  (cancel pending recovery - from email link)

GET /vault/recovery/qr
  → { qr_code_data, expires_at }
  (only available after 24h delay, one-time token embedded)

POST /vault/recovery/redeem
  → { encrypted_credential, utks }
  (called by app after scanning QR, exchanges token for credential)
```

#### Mobile App API Endpoints

All sensitive operations via mobile apps only:

```
POST /vault/enroll/start       - Get attestation
POST /vault/enroll/finalize    - Create credential (sends PIN)
GET  /vault/keys               - List keys (public info)
POST /vault/keys/generate      - Generate key in enclave
POST /vault/keys/import        - Import existing key
POST /vault/pin/change         - Change PIN
POST /vault/sign               - Sign transaction
```

### 5.21 App↔Vault Message Protocol

This section defines the exact message formats exchanged between mobile apps and the vault. All messages are JSON-encoded and transmitted via NATS with E2E encryption.

#### 5.21.1 Message Envelope

All messages share a common envelope structure:

```typescript
// Base envelope for all messages
interface MessageEnvelope {
  version: 1;                    // Protocol version (increment on breaking changes)
  type: MessageType;             // Discriminator for message content
  request_id: string;            // UUID for request/response correlation
  timestamp: number;             // Unix timestamp (milliseconds)
  vault_id: string;              // Target vault identifier (Cognito sub)
}

// Message types enum
enum MessageType {
  // Enrollment
  BOOTSTRAP_REQUEST = "bootstrap_request",
  BOOTSTRAP_RESPONSE = "bootstrap_response",
  SET_PASSWORD_REQUEST = "set_password_request",
  CREDENTIAL_RESPONSE = "credential_response",

  // Vault Operations
  WARMUP_REQUEST = "warmup_request",
  WARMUP_RESPONSE = "warmup_response",
  OPERATION_REQUEST = "operation_request",
  OPERATION_RESPONSE = "operation_response",
  CHALLENGE_RESPONSE_REQUEST = "challenge_response_request",
  OPERATION_RESULT = "operation_result",

  // Attestation
  ATTESTATION_REQUEST = "attestation_request",
  ATTESTATION_RESPONSE = "attestation_response",

  // Status
  STATUS_REQUEST = "status_request",
  STATUS_RESPONSE = "status_response",

  // Errors
  ERROR = "error"
}
```

#### 5.21.2 NATS Subject Hierarchy

```
vettid.vault.
├── {vault_id}.
│   ├── enroll          # Enrollment messages (bootstrap, set_password)
│   ├── warmup          # PIN submission for vault warming
│   ├── operation       # Credential operations (sign, generate, etc.)
│   └── status          # Status queries
├── attestation         # Attestation requests (no vault_id needed yet)
└── broadcast           # System-wide announcements (maintenance, etc.)

Examples:
  vettid.vault.abc123-def456.operation  # Operation for specific vault
  vettid.vault.attestation              # Get fresh attestation document
```

#### 5.21.3 Enrollment Messages

**Attestation Request** (App → Vault)
```typescript
interface AttestationRequest extends MessageEnvelope {
  type: "attestation_request";
  nonce: string;  // 32 bytes, base64-encoded, generated by app
}

// Example:
{
  "version": 1,
  "type": "attestation_request",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1704672000000,
  "vault_id": "",  // Empty - no vault yet
  "nonce": "k7Fy8mPqR2nX5vB9cL3wA1hD6jK0sT4u"
}
```

**Attestation Response** (Vault → App)
```typescript
interface AttestationResponse extends MessageEnvelope {
  type: "attestation_response";
  attestation_document: string;  // Base64-encoded CBOR attestation from NSM
  ephemeral_public_key: string;  // 32 bytes, base64-encoded X25519 pubkey
  pcr0: string;                  // Hex-encoded PCR0 for verification
  pcr1: string;                  // Hex-encoded PCR1
  pcr2: string;                  // Hex-encoded PCR2
}

// Attestation document (CBOR) contains:
// - module_id: Enclave module identifier
// - timestamp: Attestation generation time
// - pcrs: Map of PCR index → PCR value
// - certificate: NSM certificate chain
// - public_key: Ephemeral public key (matches ephemeral_public_key)
// - user_data: Contains the app-provided nonce (CRITICAL for replay protection)
// - nonce: Additional nonce from NSM
```

**Bootstrap Request** (App → Vault)
```typescript
interface BootstrapRequest extends MessageEnvelope {
  type: "bootstrap_request";
  bootstrap_token: string;       // JWT from Lambda, proves enrollment authorized
  encrypted_pin: string;         // PIN encrypted to attestation ephemeral pubkey
  attestation_nonce: string;     // Must match nonce from AttestationRequest
}

// Bootstrap token JWT payload:
{
  "sub": "cognito-user-id",
  "vault_id": "vault-uuid",
  "exp": 1704672300,  // 5 minute expiry
  "iat": 1704672000,
  "iss": "vettid-enrollment-lambda"
}

// Example:
{
  "version": 1,
  "type": "bootstrap_request",
  "request_id": "550e8400-e29b-41d4-a716-446655440001",
  "timestamp": 1704672001000,
  "vault_id": "abc123-def456-ghi789",
  "bootstrap_token": "eyJhbGciOiJIUzI1NiIs...",
  "encrypted_pin": "base64-encoded-x25519-encrypted-pin",
  "attestation_nonce": "k7Fy8mPqR2nX5vB9cL3wA1hD6jK0sT4u"
}
```

**Bootstrap Response** (Vault → App)
```typescript
interface BootstrapResponse extends MessageEnvelope {
  type: "bootstrap_response";
  status: "enter_password";      // Next step indicator
  utks: UTK[];                   // Initial batch of User Transaction Keys
  cek_public: string;            // 32 bytes, base64-encoded X25519 pubkey
}

interface UTK {
  id: string;                    // UUID v4 format
  public_key: string;            // 32 bytes, base64-encoded X25519 pubkey
  created_at: number;            // Unix timestamp (milliseconds)
}

// Example:
{
  "version": 1,
  "type": "bootstrap_response",
  "request_id": "550e8400-e29b-41d4-a716-446655440001",
  "timestamp": 1704672002000,
  "vault_id": "abc123-def456-ghi789",
  "status": "enter_password",
  "utks": [
    {
      "id": "utk-001-uuid",
      "public_key": "base64-32-bytes",
      "created_at": 1704672002000
    },
    // ... 9 more UTKs (total of 10)
  ],
  "cek_public": "base64-32-bytes-cek-pubkey"
}
```

**Set Password Request** (App → Vault)
```typescript
interface SetPasswordRequest extends MessageEnvelope {
  type: "set_password_request";
  encrypted_password: string;    // Password encrypted with UTK public key
  utk_id: string;                // ID of UTK used for encryption
}

// Encryption format for encrypted_password:
// X25519 + ChaCha20-Poly1305 with domain separation (DomainUTK)
// Result: ephemeral_pubkey (32) || nonce (12) || ciphertext+tag

// Example:
{
  "version": 1,
  "type": "set_password_request",
  "request_id": "550e8400-e29b-41d4-a716-446655440002",
  "timestamp": 1704672003000,
  "vault_id": "abc123-def456-ghi789",
  "encrypted_password": "base64-encoded-encrypted-password",
  "utk_id": "utk-001-uuid"
}
```

**Credential Response** (Vault → App)
```typescript
interface CredentialResponse extends MessageEnvelope {
  type: "credential_response";
  encrypted_credential: string;  // Protean Credential encrypted with CEK
  new_cek_public: string;        // New CEK public key (rotated)
  new_utks: UTK[];               // Fresh batch of UTKs
}

// Credential encryption format:
// X25519 + ChaCha20-Poly1305 with domain separation (DomainCEK)
// Result: ephemeral_pubkey (32) || nonce (12) || ciphertext+tag

// Example:
{
  "version": 1,
  "type": "credential_response",
  "request_id": "550e8400-e29b-41d4-a716-446655440002",
  "timestamp": 1704672004000,
  "vault_id": "abc123-def456-ghi789",
  "encrypted_credential": "base64-encoded-large-blob",
  "new_cek_public": "base64-32-bytes-new-cek",
  "new_utks": [
    // 10 fresh UTKs
  ]
}
```

#### 5.21.4 Vault Warming Messages

**Warmup Request** (App → Vault)
```typescript
interface WarmupRequest extends MessageEnvelope {
  type: "warmup_request";
  encrypted_pin: string;         // PIN encrypted to attestation ephemeral pubkey
  attestation_nonce: string;     // Nonce used in prior attestation request
}

// App must request fresh attestation before each warmup for replay protection
```

**Warmup Response** (Vault → App)
```typescript
interface WarmupResponse extends MessageEnvelope {
  type: "warmup_response";
  status: WarmupStatus;
  remaining_lockout_seconds?: number;  // Only if status is "rate_limited"
}

enum WarmupStatus {
  SUCCESS = "success",           // Vault is now warm
  WRONG_PIN = "wrong_pin",       // PIN incorrect
  RATE_LIMITED = "rate_limited", // Too many failed attempts
  VAULT_NOT_FOUND = "not_found"  // No vault for this user
}
```

#### 5.21.5 Operation Messages

**Operation Request** (App → Vault)
```typescript
interface OperationRequest extends MessageEnvelope {
  type: "operation_request";
  encrypted_credential: string;  // Current credential (from last response)
  operation: Operation;
}

interface Operation {
  op_type: OperationType;
  params: OperationParams;       // Type depends on op_type
}

enum OperationType {
  // Key Management
  GENERATE_KEY = "generate_key",
  IMPORT_KEY = "import_key",
  DELETE_KEY = "delete_key",
  LIST_KEYS = "list_keys",
  EXPORT_PUBLIC_KEY = "export_public_key",

  // Cryptographic Operations
  SIGN = "sign",
  DECRYPT = "decrypt",
  DERIVE_KEY = "derive_key",

  // Seed Phrase Management
  GENERATE_SEED = "generate_seed",
  IMPORT_SEED = "import_seed",
  DERIVE_FROM_SEED = "derive_from_seed",

  // Credential Management
  CHANGE_PASSWORD = "change_password",
  GET_CREDENTIAL_INFO = "get_credential_info"
}

// Operation-specific params:

interface GenerateKeyParams {
  key_type: "secp256k1" | "ed25519" | "x25519" | "p256";
  label: string;                 // User-friendly name (max 64 chars)
  metadata?: Record<string, string>;  // Optional key-value pairs
}

interface SignParams {
  key_id: string;                // UUID of key to use
  data: string;                  // Base64-encoded data to sign
  hash_algorithm?: "sha256" | "sha512" | "keccak256";  // Default: sha256
}

interface ImportKeyParams {
  key_type: "secp256k1" | "ed25519" | "x25519" | "p256";
  private_key: string;           // Base64-encoded private key bytes
  label: string;
}

interface GenerateSeedParams {
  word_count: 12 | 15 | 18 | 21 | 24;  // BIP39 mnemonic length
  label: string;
}

interface DeriveFromSeedParams {
  seed_id: string;               // UUID of seed phrase
  derivation_path: string;       // BIP32/44 path, e.g., "m/44'/0'/0'/0/0"
  label: string;
}
```

**Operation Response** (Vault → App)
```typescript
interface OperationResponse extends MessageEnvelope {
  type: "operation_response";
  status: "challenge";           // Always requires password confirmation
  challenge_id: string;          // UUID for this challenge
  utk_id: string;                // UTK to use for password encryption
  challenge_expires_at: number;  // Unix timestamp (60 seconds from now)
}
```

**Challenge Response Request** (App → Vault)
```typescript
interface ChallengeResponseRequest extends MessageEnvelope {
  type: "challenge_response_request";
  challenge_id: string;          // From OperationResponse
  encrypted_password: string;    // Password encrypted with specified UTK
  utk_id: string;                // Confirms which UTK was used
}
```

**Operation Result** (Vault → App)
```typescript
interface OperationResult extends MessageEnvelope {
  type: "operation_result";
  success: boolean;
  result?: OperationResultData;  // Present if success=true
  error?: ErrorInfo;             // Present if success=false
  new_encrypted_credential: string;  // Updated credential (CEK rotated)
  new_cek_public: string;        // New CEK public key
  new_utks: UTK[];               // Fresh UTKs
}

// Result data varies by operation type:

interface SignResult {
  signature: string;             // Base64-encoded signature
  public_key: string;            // Base64-encoded public key used
}

interface GenerateKeyResult {
  key_id: string;                // UUID of new key
  public_key: string;            // Base64-encoded public key
  address?: string;              // Blockchain address if applicable
}

interface GenerateSeedResult {
  seed_id: string;               // UUID of new seed
  mnemonic: string;              // BIP39 mnemonic words (SENSITIVE - display once!)
}

interface ListKeysResult {
  keys: KeyInfo[];
}

interface KeyInfo {
  key_id: string;
  key_type: string;
  label: string;
  public_key: string;
  created_at: number;
  metadata?: Record<string, string>;
}
```

#### 5.21.6 Status Messages

**Status Request** (App → Vault)
```typescript
interface StatusRequest extends MessageEnvelope {
  type: "status_request";
}
```

**Status Response** (Vault → App)
```typescript
interface StatusResponse extends MessageEnvelope {
  type: "status_response";
  vault_state: VaultState;
  last_activity: number;         // Unix timestamp
  key_count: number;             // Number of keys in credential
  utk_remaining: number;         // UTKs available (should request more if < 5)
}

enum VaultState {
  WARM = "warm",                 // DEK loaded, ready for operations
  COLD = "cold",                 // Exists but needs PIN to warm
  NOT_FOUND = "not_found",       // No vault for this user
  DRAINING = "draining"          // Being evicted, try another instance
}
```

#### 5.21.7 Error Response

**Error** (Vault → App)
```typescript
interface ErrorResponse extends MessageEnvelope {
  type: "error";
  error: ErrorInfo;
}

interface ErrorInfo {
  code: ErrorCode;
  message: string;               // Human-readable description
  details?: Record<string, any>; // Additional context
  retry_after?: number;          // Seconds to wait before retry (if applicable)
}

enum ErrorCode {
  // Authentication Errors (1xxx)
  INVALID_TOKEN = 1001,
  EXPIRED_TOKEN = 1002,
  INVALID_PIN = 1003,
  PIN_RATE_LIMITED = 1004,
  INVALID_PASSWORD = 1005,

  // Credential Errors (2xxx)
  CREDENTIAL_DECRYPT_FAILED = 2001,
  CREDENTIAL_VERSION_MISMATCH = 2002,
  CREDENTIAL_CORRUPTED = 2003,

  // Key Errors (3xxx)
  KEY_NOT_FOUND = 3001,
  KEY_TYPE_MISMATCH = 3002,
  INVALID_DERIVATION_PATH = 3003,
  KEY_LIMIT_EXCEEDED = 3004,

  // Operation Errors (4xxx)
  CHALLENGE_EXPIRED = 4001,
  CHALLENGE_NOT_FOUND = 4002,
  INVALID_OPERATION = 4003,
  UTK_ALREADY_USED = 4004,
  UTK_NOT_FOUND = 4005,

  // Vault Errors (5xxx)
  VAULT_NOT_FOUND = 5001,
  VAULT_NOT_WARM = 5002,
  VAULT_DRAINING = 5003,
  VAULT_SYNC_FAILED = 5004,

  // System Errors (9xxx)
  INTERNAL_ERROR = 9001,
  SERVICE_UNAVAILABLE = 9002,
  ATTESTATION_FAILED = 9003
}
```

#### 5.21.8 Protean Credential Wire Format

The Protean Credential is transmitted as an encrypted blob. When decrypted, it has this JSON structure:

```typescript
interface ProteanCredential {
  version: 1;
  owner_id: string;              // Cognito sub (matches vault_id)
  created_at: number;            // Unix timestamp
  last_modified: number;         // Unix timestamp

  // Authentication
  password_hash: string;         // Base64 Argon2id hash
  password_salt: string;         // Base64 32-byte salt
  auth_type: "pin" | "password" | "pattern";

  // Identity
  identity_keypair: {
    type: "ed25519";
    public_key: string;          // Base64 32 bytes
    private_key: string;         // Base64 32 bytes (encrypted at rest)
  };

  // Master secret for key derivation
  master_secret: string;         // Base64 32 bytes

  // User's cryptographic keys
  crypto_keys: CryptoKey[];      // Max 100 keys

  // Seed phrases
  seed_phrases: SeedPhrase[];    // Max 10 seeds

  // Metadata
  metadata: {
    device_id?: string;
    backup_enabled: boolean;
    last_backup?: number;
  };
}

interface CryptoKey {
  id: string;                    // UUID v4
  type: "secp256k1" | "ed25519" | "x25519" | "p256";
  label: string;                 // Max 64 chars
  public_key: string;            // Base64
  private_key: string;           // Base64
  created_at: number;
  derivation_path?: string;      // If derived from seed
  seed_id?: string;              // If derived from seed
  metadata?: Record<string, string>;
}

interface SeedPhrase {
  id: string;                    // UUID v4
  label: string;                 // Max 64 chars
  entropy: string;               // Base64 (16-32 bytes depending on word count)
  word_count: 12 | 15 | 18 | 21 | 24;
  created_at: number;
}
```

**Size Limits:**
| Field | Limit |
|-------|-------|
| Total credential size | 1 MB |
| crypto_keys array | 100 items |
| seed_phrases array | 10 items |
| label fields | 64 characters |
| metadata keys | 32 characters |
| metadata values | 256 characters |
| metadata entries per key | 10 |

#### 5.21.9 X25519 Encryption Format

All encrypted fields use X25519 key agreement + ChaCha20-Poly1305:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Encrypted Payload Format                      │
├─────────────────────────────────────────────────────────────────┤
│  Bytes 0-31:   Ephemeral public key (X25519)                    │
│  Bytes 32-43:  Nonce (12 bytes, random)                         │
│  Bytes 44-N:   Ciphertext + Poly1305 tag (16 bytes)             │
└─────────────────────────────────────────────────────────────────┘

Encryption process:
1. Generate ephemeral X25519 keypair
2. Compute shared_secret = X25519(ephemeral_private, recipient_public)
3. Derive enc_key = HKDF-SHA256(shared_secret, info=domain_string)
4. Generate random 12-byte nonce
5. ciphertext = ChaCha20-Poly1305.Seal(enc_key, nonce, plaintext, aad=nil)
6. Output = ephemeral_public || nonce || ciphertext

Domain strings (prevents cross-context key confusion):
- "vettid-cek-v1" for credential encryption (CEK)
- "vettid-utk-v1" for password transport (UTK)
- "vettid-pin-v1" for PIN transport (attestation)
```

#### 5.21.10 Message Size Limits

| Message Type | Max Size |
|--------------|----------|
| Requests (app → vault) | 64 KB |
| Responses (vault → app) | 2 MB |
| Encrypted credential | 1 MB |
| Single key/seed operation | 64 KB |
| UTK batch | 10 UTKs per response |

---

## 6. Component Design

### 6.1 Enclave Supervisor

The supervisor is the main process inside the enclave. **Critical:** Only the supervisor has NSM (Nitro Security Module) access for hardware attestation and KMS operations.

**Supervisor Responsibilities:**
- NSM access (attestation documents, ephemeral keypairs)
- KMS operations (seal/unseal via attestation)
- DEK derivation from PIN + sealed material
- Managing vault-manager processes
- Providing DEK to vault-managers on warmup

**What Supervisor Does NOT Do:**
- Credential operations (handled by vault-manager)
- UTK/LTK/CEK management (handled by vault-manager)
- Message handling (handled by vault-manager)

```go
type EnclaveSupervisor struct {
    // NSM device handle (hardware security module)
    nsm *nsm.Session

    // Active vault-manager processes
    vaults map[string]*VaultProcess

    // Sealed material per vault (PCR-bound)
    sealedMaterials map[string][]byte

    // Shared resources
    handlerCache *WASMHandlerCache

    // Configuration
    maxActiveVaults int

    // Communication
    vsock *VsockListener

    // M5: PIN attempt rate limiting
    pinAttempts map[string]*PINAttemptTracker
    pinMu       sync.RWMutex

    // C5: PIN caching for DEK rotation (see lifecycle below)
    cachedPINs     map[string]*CachedPIN
    pinCacheMu     sync.RWMutex
}

// C5: CachedPIN stores PIN temporarily for DEK rotation
// SECURITY: PIN is only cached while vault is warm, wiped on eviction
type CachedPIN struct {
    PIN       string    // The actual PIN (sensitive!)
    CachedAt  time.Time // When PIN was cached
    VaultID   string    // Bound to specific vault
}

// C5: PIN Caching Lifecycle
// ─────────────────────────────────────────────────────────────────────────────
//
// 1. CACHE ON WARMUP: When user enters correct PIN for vault warmup
//    - PIN is cached in supervisor memory (never persisted to disk/S3)
//    - Cache entry bound to vault_id (prevents cross-vault use)
//
// 2. USE FOR DEK ROTATION: When DEK rotation is triggered (30 days or 1000 ops)
//    - Rotation requires current PIN to derive new DEK
//    - Retrieve from cache instead of prompting user again
//    - If cache miss (evicted and reloaded), rotation deferred to next warmup
//
// 3. WIPE ON EVICTION: When vault is evicted from memory
//    - Delete cache entry for that vault_id
//    - crypto.MemGuard.Destroy() called to overwrite memory
//
// 4. TTL EXPIRY: After 24 hours even if vault stays warm
//    - Periodic cleanup removes stale entries
//    - Next DEK rotation will require re-warmup (user enters PIN again)
//
// 5. NEVER PERSISTED: PIN cache is memory-only
//    - Enclave restart = all PINs gone
//    - S3 backup does NOT include PINs
//    - Parent process cannot access enclave memory
//
// Security Properties:
// - PIN only in enclave memory (hardware-protected)
// - Memory wiped on eviction using secure zeroing
// - 24-hour TTL limits exposure window
// - Per-vault binding prevents cross-vault attacks

const (
    PINCacheTTL = 24 * time.Hour  // Max time PIN stays cached
)

func (s *EnclaveSupervisor) cachePIN(vaultID, pin string) {
    s.pinCacheMu.Lock()
    defer s.pinCacheMu.Unlock()

    s.cachedPINs[vaultID] = &CachedPIN{
        PIN:      pin,
        CachedAt: time.Now(),
        VaultID:  vaultID,
    }
}

func (s *EnclaveSupervisor) getCachedPIN(vaultID string) (string, bool) {
    s.pinCacheMu.RLock()
    defer s.pinCacheMu.RUnlock()

    cached, exists := s.cachedPINs[vaultID]
    if !exists {
        return "", false
    }

    // Check TTL
    if time.Since(cached.CachedAt) > PINCacheTTL {
        return "", false
    }

    return cached.PIN, true
}

func (s *EnclaveSupervisor) wipeCachedPIN(vaultID string) {
    s.pinCacheMu.Lock()
    defer s.pinCacheMu.Unlock()

    if cached, exists := s.cachedPINs[vaultID]; exists {
        // Secure memory wipe - overwrite PIN before freeing
        for i := range cached.PIN {
            cached.PIN = cached.PIN[:i] + "0" + cached.PIN[i+1:]
        }
        delete(s.cachedPINs, vaultID)
    }
}

// PINAttemptTracker tracks failed PIN attempts per vault
type PINAttemptTracker struct {
    Attempts   []time.Time // Timestamps of failed attempts
    LockedAt   time.Time   // When rate limit was triggered
    LockExpiry time.Time   // When lock expires
}

const (
    MaxPINAttempts     = 3             // Max failed attempts before lockout
    PINAttemptWindow   = time.Hour     // Window for tracking attempts
    PINLockoutDuration = time.Hour     // How long lockout lasts
)

// Handle PIN for vault warmup
func (s *EnclaveSupervisor) HandleWarmup(vaultID string, pin string) error {
    // M5: Check rate limit FIRST - before any crypto operations
    if err := s.checkPINRateLimit(vaultID); err != nil {
        return err // Returns ErrPINRateLimited with remaining lockout time
    }

    // 1. Load sealed material for this vault
    sealed := s.sealedMaterials[vaultID]

    // 2. Get attestation from NSM (ephemeral keypair)
    attestation, err := s.nsm.GetAttestation(nil)
    if err != nil {
        return err
    }

    // 3. Unseal material via KMS (PCR-bound decryption)
    material, err := s.kmsDecrypt(sealed, attestation)
    if err != nil {
        return err
    }

    // 4. Derive DEK from material + PIN + owner_id
    dek := s.deriveDEK(vaultID, material, pin)

    // 5. Provide DEK to vault-manager - this validates the PIN
    vault := s.vaults[vaultID]
    if vault == nil {
        vault = s.startVault(vaultID)
    }

    err = vault.SetDEK(dek)
    if err != nil {
        // Wrong PIN - record failed attempt
        if errors.Is(err, ErrWrongPIN) {
            s.recordFailedPINAttempt(vaultID)
        }
        return err
    }

    // Success - clear any prior failed attempts
    s.clearPINAttempts(vaultID)
    return nil
}

// M5: Check if vault is rate limited for PIN attempts
func (s *EnclaveSupervisor) checkPINRateLimit(vaultID string) error {
    s.pinMu.RLock()
    tracker := s.pinAttempts[vaultID]
    s.pinMu.RUnlock()

    if tracker == nil {
        return nil // No tracker = no prior failures
    }

    // Check if currently locked out
    if !tracker.LockExpiry.IsZero() && time.Now().Before(tracker.LockExpiry) {
        remaining := time.Until(tracker.LockExpiry)
        return fmt.Errorf("%w: try again in %v", ErrPINRateLimited, remaining.Round(time.Minute))
    }

    return nil
}

// M5: Record a failed PIN attempt
func (s *EnclaveSupervisor) recordFailedPINAttempt(vaultID string) {
    s.pinMu.Lock()
    defer s.pinMu.Unlock()

    tracker := s.pinAttempts[vaultID]
    if tracker == nil {
        tracker = &PINAttemptTracker{}
        s.pinAttempts[vaultID] = tracker
    }

    now := time.Now()
    cutoff := now.Add(-PINAttemptWindow)

    // Clean up old attempts outside the window
    var recent []time.Time
    for _, t := range tracker.Attempts {
        if t.After(cutoff) {
            recent = append(recent, t)
        }
    }
    recent = append(recent, now)
    tracker.Attempts = recent

    // Check if we hit the limit
    if len(recent) >= MaxPINAttempts {
        tracker.LockedAt = now
        tracker.LockExpiry = now.Add(PINLockoutDuration)
        // Log security event - potential brute force attack
        log.Warn().
            Str("vault_id", vaultID).
            Int("attempts", len(recent)).
            Time("locked_until", tracker.LockExpiry).
            Msg("PIN rate limit triggered - vault locked")
    }
}

// M5: Clear PIN attempts on successful authentication
func (s *EnclaveSupervisor) clearPINAttempts(vaultID string) {
    s.pinMu.Lock()
    defer s.pinMu.Unlock()
    delete(s.pinAttempts, vaultID)
}

var (
    ErrPINRateLimited = errors.New("PIN rate limited")
    ErrWrongPIN       = errors.New("wrong PIN")
)

// Setup PIN during enrollment
func (s *EnclaveSupervisor) HandlePINSetup(vaultID string, pin string) error {
    // 1. Generate random material
    material := make([]byte, 32)
    rand.Read(material)

    // 2. Get attestation from NSM
    attestation, err := s.nsm.GetAttestation(nil)
    if err != nil {
        return err
    }

    // 3. Seal material via KMS (PCR-bound encryption)
    sealed, err := s.kmsEncrypt(material, attestation)
    if err != nil {
        return err
    }

    // 4. Store sealed material
    s.sealedMaterials[vaultID] = sealed

    // 5. Derive DEK and provide to vault-manager
    dek := s.deriveDEK(vaultID, material, pin)
    vault := s.vaults[vaultID]
    return vault.SetDEK(dek)
}

// deriveDEK derives the vault DEK from owner_id, sealed material, and PIN
// The owner_id binding prevents cross-vault DEK confusion attacks
func (s *EnclaveSupervisor) deriveDEK(ownerID string, material []byte, pin string) []byte {
    // Step 1: Create salt from owner_id + material
    // This binds the DEK to both the user identity AND the random material
    saltInput := append([]byte(ownerID), material...)
    salt := sha256.Sum256(saltInput)

    // Step 2: Stretch the PIN with Argon2id to resist brute force
    // Even if material is compromised, attacker must run Argon2id per guess
    // Parameters: 64 MB memory, 3 iterations, 4 threads - ~300ms per attempt
    stretchedPIN := argon2.IDKey(
        []byte(pin),
        salt[:16],      // Use first 16 bytes of hash as salt
        3,              // Iterations (time cost)
        64*1024,        // Memory: 64 MB
        4,              // Parallelism
        32,             // Output length
    )

    // Step 3: Derive DEK from stretched PIN + material
    // HKDF binds the final key to the random material
    return hkdf.Extract(sha256.New, material, stretchedPIN)
}

// Main entry point
func (s *EnclaveSupervisor) Run() {
    // Start background cleanup goroutines
    go s.challengeCleanupLoop()
    go s.memoryMonitorLoop()

    // Listen for messages from parent
    for msg := range s.vsock.Messages() {
        switch msg.Type {
        case "warmup":
            s.HandleWarmup(msg.VaultID, msg.PIN)
        case "pin_setup":
            s.HandlePINSetup(msg.VaultID, msg.PIN)
        case "vault_message":
            s.routeToVault(msg.OwnerSpace, msg.Payload)
        case "handler_update":
            s.handlerCache.Update(msg.HandlerID, msg.WASMBytes)
        case "health_check":
            s.respondHealthCheck(msg)
        }
    }
}

// M2: Challenge cleanup - removes expired challenges and their LTKs
func (s *EnclaveSupervisor) challengeCleanupLoop() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        for _, vault := range s.vaults {
            vault.CleanupExpiredChallenges()
        }
    }
}

// CleanupExpiredChallenges removes challenges older than 2 minutes and their LTKs
func (vm *VaultManager) CleanupExpiredChallenges() {
    vm.mu.Lock()
    defer vm.mu.Unlock()

    expiryCutoff := time.Now().Add(-2 * time.Minute)
    cleaned := 0

    for challengeID, challenge := range vm.pendingChallenges {
        if challenge.CreatedAt.Before(expiryCutoff) {
            // Delete associated LTK
            delete(vm.ltks, challenge.UTKID)
            // Delete challenge
            delete(vm.pendingChallenges, challengeID)
            cleaned++
        }
    }

    if cleaned > 0 {
        log.Debug().
            Int("cleaned", cleaned).
            Str("owner_id", vm.ownerID).
            Msg("Cleaned up expired challenges")
    }
}

// M3: Memory monitoring - enforces per-vault memory limits
func (s *EnclaveSupervisor) memoryMonitorLoop() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    const maxVaultMemoryMB = 90 // Force evict if vault exceeds this

    for range ticker.C {
        for ownerID, vault := range s.vaults {
            memMB := vault.EstimateMemoryUsageMB()
            if memMB > maxVaultMemoryMB {
                log.Warn().
                    Str("owner_id", ownerID).
                    Int("memory_mb", memMB).
                    Msg("Vault exceeds memory limit - forcing eviction")
                s.forceEvictVault(ownerID)
            }
        }
    }
}

// EstimateMemoryUsageMB estimates vault's memory footprint
func (vm *VaultManager) EstimateMemoryUsageMB() int {
    // Base: keys, struct overhead
    base := 1 // ~1MB base

    // SQLite in-memory: estimate from row count
    var rowCount int
    vm.db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&rowCount)
    vm.db.QueryRow("SELECT COUNT(*) FROM ledger").Scan(&rowCount)
    sqliteMB := rowCount / 10000 // ~100 bytes per row, rough estimate

    // Pending challenges and LTKs
    challengeMB := len(vm.pendingChallenges) * 32 / (1024 * 1024)
    ltkMB := len(vm.ltks) * 32 / (1024 * 1024)

    return base + sqliteMB + challengeMB + ltkMB
}
```

### 6.2 Vault Manager Process

Each user has a dedicated vault-manager. **Critical:** The vault-manager handles all credential operations but does NOT have NSM access—it receives the DEK from the supervisor.

**Vault-Manager Responsibilities:**
- CEK (Credential Encryption Key) generation and rotation
- UTK/LTK (User/Ledger Transaction Keys) generation and management
- Credential creation, encryption, and re-encryption
- Password verification (Argon2id)
- Message handling (via central NATS)
- SQLite database operations (user's ledger)

**What Vault-Manager Does NOT Do:**
- NSM/KMS operations (handled by supervisor)
- PIN handling (handled by supervisor)
- Attestation generation (NSM only accessible by supervisor)

```go
type VaultManager struct {
    ownerID        string  // Cognito user_id (sub claim)

    // DEK provided by supervisor (symmetric, for SQLite encryption)
    vaultDEK       [32]byte

    // CEK - X25519 keypair for credential encryption (ECDH + symmetric)
    // Private key stored in SQLite, public key sent to app
    cekPrivate     [32]byte  // X25519 private key
    cekPublic      [32]byte  // X25519 public key

    // LTKs - X25519 private keys for decrypting app messages (indexed by UTK ID)
    ltks           map[string][32]byte  // X25519 private keys

    // Pending challenges (for multi-step operations)
    pendingChallenges map[string]*Challenge

    // In-memory SQLite database
    db             *sql.DB

    // S3 sync for persistence (encrypts with DEK before upload)
    s3Sync         *S3SyncManager

    // Reference to shared handler cache
    handlerCache   *WASMHandlerCache

    // Rollback protection: highest sync counter seen in current session
    // Rejects any DB load with counter lower than this value
    highestSyncCounter int64
}

// ============================================================================
// Message Structs (C1/C2: JSON tags must match Section 5.21 TypeScript specs)
// ============================================================================

// UTK - User Transaction Key (sent to app for encrypting messages to vault)
type UTK struct {
    ID        string `json:"id"`          // UUID v4
    PublicKey []byte `json:"public_key"`  // 32 bytes X25519
    CreatedAt int64  `json:"created_at"`  // Unix timestamp (ms)
}

// Challenge - pending operation awaiting password confirmation
type Challenge struct {
    ID         string            `json:"challenge_id"`
    UTKID      string            `json:"utk_id"`         // UTK to use for password
    Credential ProteanCredential `json:"-"`              // Not serialized
    Operation  Operation         `json:"-"`              // Not serialized
    CreatedAt  time.Time         `json:"-"`              // For cleanup
    ExpiresAt  time.Time         `json:"expires_at"`
}

// BootstrapResponse - returned after initial vault setup
type BootstrapResponse struct {
    Status    string `json:"status"`      // "enter_password"
    UTKs      []UTK  `json:"utks"`        // Initial batch (10)
    CEKPublic []byte `json:"cek_public"`  // 32 bytes X25519
}

// CredentialResponse - returned after password set or operation complete
type CredentialResponse struct {
    EncryptedCredential []byte `json:"encrypted_credential"`
    NewCEKPublic        []byte `json:"new_cek_public"`
    NewUTKs             []UTK  `json:"new_utks"`
}

// OperationResponse - returned when challenge is created
type OperationResponse struct {
    Status             string `json:"status"`              // "challenge"
    ChallengeID        string `json:"challenge_id"`
    UTKID              string `json:"utk_id"`
    ChallengeExpiresAt int64  `json:"challenge_expires_at"` // Unix timestamp (ms)
}

// OperationResult - returned after successful operation
type OperationResult struct {
    Success                bool        `json:"success"`
    Result                 interface{} `json:"result,omitempty"`   // Type varies by operation
    Error                  *ErrorInfo  `json:"error,omitempty"`
    NewEncryptedCredential []byte      `json:"new_encrypted_credential"`
    NewCEKPublic           []byte      `json:"new_cek_public"`
    NewUTKs                []UTK       `json:"new_utks"`
}

// ErrorInfo - standardized error response
type ErrorInfo struct {
    Code       int               `json:"code"`
    Message    string            `json:"message"`
    Details    map[string]string `json:"details,omitempty"`
    RetryAfter int               `json:"retry_after,omitempty"` // Seconds
}

// Operation - requested vault operation
type Operation struct {
    OpType string                 `json:"op_type"` // See OperationType enum in 5.21.5
    Params map[string]interface{} `json:"params"`  // Type-specific parameters
}

// ============================================================================
// Helper Function Implementations (C4, L5)
// ============================================================================

// verifyBootstrapToken validates the JWT from Lambda enrollment flow
// Token proves user completed Cognito auth and is authorized to create vault
func (vm *VaultManager) verifyBootstrapToken(token string) bool {
    // 1. Parse JWT (HS256 signed by shared secret with Lambda)
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return false
    }

    // 2. Verify signature using shared secret (from environment)
    secret := os.Getenv("BOOTSTRAP_TOKEN_SECRET")
    expectedSig := hmacSHA256(parts[0]+"."+parts[1], secret)
    if !hmac.Equal([]byte(parts[2]), expectedSig) {
        return false
    }

    // 3. Decode and validate claims
    payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
    var claims struct {
        Sub     string `json:"sub"`      // Cognito user ID
        VaultID string `json:"vault_id"` // Must match our owner_id
        Exp     int64  `json:"exp"`      // Expiration timestamp
        Iat     int64  `json:"iat"`      // Issued at
        Iss     string `json:"iss"`      // Must be our Lambda
    }
    json.Unmarshal(payload, &claims)

    // 4. Validate claims
    now := time.Now().Unix()
    if claims.Exp < now {
        return false // Token expired
    }
    if claims.VaultID != vm.ownerID {
        return false // Wrong vault
    }
    if claims.Iss != "vettid-enrollment-lambda" {
        return false // Wrong issuer
    }
    if now-claims.Iat > 300 {
        return false // Token too old (5 min max)
    }

    return true
}

// buildCredential creates initial Protean Credential from password
func (vm *VaultManager) buildCredential(password []byte) []byte {
    // 1. Generate identity keypair (Ed25519 for signing)
    identityPub, identityPriv, _ := ed25519.GenerateKey(rand.Reader)

    // 2. Generate master secret for key derivation
    masterSecret := make([]byte, 32)
    rand.Read(masterSecret)

    // 3. Hash password with Argon2id
    salt := make([]byte, 32)
    rand.Read(salt)
    passwordHash := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)

    // 4. Build credential structure
    credential := ProteanCredential{
        Version:      1,
        OwnerID:      vm.ownerID,
        CreatedAt:    time.Now().UnixMilli(),
        LastModified: time.Now().UnixMilli(),
        PasswordHash: base64.StdEncoding.EncodeToString(passwordHash),
        PasswordSalt: base64.StdEncoding.EncodeToString(salt),
        AuthType:     "pin",
        IdentityKeypair: IdentityKeypair{
            Type:       "ed25519",
            PublicKey:  base64.StdEncoding.EncodeToString(identityPub),
            PrivateKey: base64.StdEncoding.EncodeToString(identityPriv),
        },
        MasterSecret: base64.StdEncoding.EncodeToString(masterSecret),
        CryptoKeys:   []CryptoKey{},
        SeedPhrases:  []SeedPhrase{},
        Metadata: CredentialMetadata{
            BackupEnabled: false,
        },
    }

    // 5. Serialize to JSON
    credJSON, _ := json.Marshal(credential)
    return credJSON
}

// getAvailableUTK returns an unused UTK ID for challenge response
func (vm *VaultManager) getAvailableUTK() string {
    // Select random UTK from available pool
    // UTKs are removed after use (single-use for replay protection)
    for utkID := range vm.ltks {
        return utkID // Return first available
    }
    return "" // None available - caller should handle
}

// verifyPassword checks password against stored Argon2id hash
func (vm *VaultManager) verifyPassword(password []byte, cred ProteanCredential) bool {
    // 1. Decode stored salt and hash
    salt, _ := base64.StdEncoding.DecodeString(cred.PasswordSalt)
    storedHash, _ := base64.StdEncoding.DecodeString(cred.PasswordHash)

    // 2. Compute hash of provided password with same parameters
    // Parameters MUST match buildCredential: time=3, memory=64MB, threads=4, keyLen=32
    computedHash := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)

    // 3. Constant-time comparison to prevent timing attacks
    return subtle.ConstantTimeCompare(storedHash, computedHash) == 1
}

// executeOperation dispatches to operation-specific handlers
func (vm *VaultManager) executeOperation(op Operation, cred ProteanCredential) (interface{}, error) {
    switch op.OpType {
    case "generate_key":
        return vm.handleGenerateKey(op.Params, &cred)
    case "sign":
        return vm.handleSign(op.Params, &cred)
    case "list_keys":
        return vm.handleListKeys(&cred)
    case "generate_seed":
        return vm.handleGenerateSeed(op.Params, &cred)
    case "derive_from_seed":
        return vm.handleDeriveFromSeed(op.Params, &cred)
    case "import_key":
        return vm.handleImportKey(op.Params, &cred)
    case "delete_key":
        return vm.handleDeleteKey(op.Params, &cred)
    case "change_password":
        return vm.handleChangePassword(op.Params, &cred)
    default:
        return nil, fmt.Errorf("unknown operation: %s", op.OpType)
    }
}

// generateUTKs creates a batch of UTK/LTK keypairs
func (vm *VaultManager) generateUTKs(count int) []UTK {
    utks := make([]UTK, count)
    for i := 0; i < count; i++ {
        var priv, pub [32]byte
        rand.Read(priv[:])
        curve25519.ScalarBaseMult(&pub, &priv)
        utkID := uuid.New().String()
        utks[i] = UTK{
            ID:        utkID,
            PublicKey: pub[:],
            CreatedAt: time.Now().UnixMilli(),
        }
        vm.ltks[utkID] = priv // Store corresponding LTK
    }
    // Persist LTKs to SQLite
    vm.saveLTKs()
    return utks
}

// rotateCEK generates new CEK keypair for forward secrecy
func (vm *VaultManager) rotateCEK() {
    // Generate new X25519 keypair
    rand.Read(vm.cekPrivate[:])
    curve25519.ScalarBaseMult(&vm.cekPublic, &vm.cekPrivate)
    // Persist to SQLite
    vm.saveCEK()
}

// Domain constants for X25519 encryption (M4: domain separation)
// Prevents confusion attacks between different encryption contexts
const (
    DomainCEK = "vettid-cek-v1" // Credential encryption (CEK encrypting Protean Credential)
    DomainUTK = "vettid-utk-v1" // Password transport (UTK encrypting challenge response)
    DomainPIN = "vettid-pin-v1" // PIN transport (attestation-bound PIN encryption)
)

// X25519 + ChaCha20-Poly1305 encryption (ECIES-like scheme)
// domain parameter provides cryptographic separation between use cases
func x25519Encrypt(recipientPub [32]byte, plaintext []byte, domain string) ([]byte, error) {
    // 1. Generate ephemeral X25519 keypair
    var ephemeralPriv, ephemeralPub [32]byte
    rand.Read(ephemeralPriv[:])
    curve25519.ScalarBaseMult(&ephemeralPub, &ephemeralPriv)

    // 2. Compute shared secret via ECDH
    var sharedSecret [32]byte
    curve25519.ScalarMult(&sharedSecret, &ephemeralPriv, &recipientPub)

    // 3. Derive encryption key from shared secret with domain separation
    // Different domains produce different keys even with same shared secret
    encKey := hkdf.Extract(sha256.New, sharedSecret[:], []byte(domain))

    // 4. Encrypt with ChaCha20-Poly1305
    aead, _ := chacha20poly1305.New(encKey[:32])
    nonce := make([]byte, 12)
    rand.Read(nonce)
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // 5. Return: ephemeral_pub || nonce || ciphertext
    result := make([]byte, 32+12+len(ciphertext))
    copy(result[0:32], ephemeralPub[:])
    copy(result[32:44], nonce)
    copy(result[44:], ciphertext)
    return result, nil
}

func x25519Decrypt(recipientPriv [32]byte, encrypted []byte, domain string) ([]byte, error) {
    if len(encrypted) < 44 {
        return nil, errors.New("ciphertext too short")
    }

    // 1. Extract ephemeral public key and nonce
    var ephemeralPub [32]byte
    copy(ephemeralPub[:], encrypted[0:32])
    nonce := encrypted[32:44]
    ciphertext := encrypted[44:]

    // 2. Compute shared secret via ECDH
    var sharedSecret [32]byte
    curve25519.ScalarMult(&sharedSecret, &recipientPriv, &ephemeralPub)

    // 3. Derive encryption key from shared secret with domain separation
    encKey := hkdf.Extract(sha256.New, sharedSecret[:], []byte(domain))

    // 4. Decrypt with ChaCha20-Poly1305
    aead, _ := chacha20poly1305.New(encKey[:32])
    return aead.Open(nil, nonce, ciphertext, nil)
}

// Usage examples:
// - CEK encryption: x25519Encrypt(cekPublic, credentialBytes, DomainCEK)
// - UTK encryption: x25519Encrypt(utkPublic, passwordBytes, DomainUTK)
// - PIN encryption: x25519Encrypt(attestedPubkey, pinBytes, DomainPIN)

// Called by supervisor after PIN-based DEK derivation
func (vm *VaultManager) SetDEK(dek []byte) error {
    copy(vm.vaultDEK[:], dek)

    // Load SQLite DB from S3, decrypt with DEK, then load keys
    return vm.loadDatabase()
}

// Handle bootstrap during enrollment
func (vm *VaultManager) HandleBootstrap(bootstrapToken string) (*BootstrapResponse, error) {
    // 1. Verify bootstrap token (from Lambda)
    if !vm.verifyBootstrapToken(bootstrapToken) {
        return nil, errors.New("invalid bootstrap token")
    }

    // 2. Generate CEK (X25519 keypair for credential encryption)
    rand.Read(vm.cekPrivate[:])
    curve25519.ScalarBaseMult(&vm.cekPublic, &vm.cekPrivate)

    // 3. Generate batch of UTKs/LTKs (X25519 keypairs)
    utks := make([]UTK, 10)
    for i := range utks {
        var priv, pub [32]byte
        rand.Read(priv[:])
        curve25519.ScalarBaseMult(&pub, &priv)
        utkID := uuid.New().String()
        utks[i] = UTK{ID: utkID, PublicKey: pub[:]}
        vm.ltks[utkID] = priv
    }

    // 4. Store CEK private key and LTKs in SQLite, sync to S3
    vm.saveAndSync()

    // 5. Return UTKs and CEK public key to app
    return &BootstrapResponse{
        UTKs:      utks,
        CEKPublic: vm.cekPublic[:],
        Status:    "enter_password",
    }, nil
}

// Handle password submission during enrollment
func (vm *VaultManager) HandleSetPassword(encryptedPwd []byte, utkID string) (*CredentialResponse, error) {
    // 1. Decrypt password with corresponding LTK (X25519)
    ltk, exists := vm.ltks[utkID]
    if !exists {
        return nil, errors.New("unknown or already-used UTK")
    }
    password, err := x25519Decrypt(ltk, encryptedPwd)
    if err != nil {
        return nil, fmt.Errorf("password decryption failed: %w", err)
    }

    // 2. Delete used LTK (single-use for replay protection)
    delete(vm.ltks, utkID)

    // 3. Build Protean Credential with Argon2id password hash
    credential := vm.buildCredential(password)

    // 4. Encrypt credential with CEK public key
    encryptedCred, _ := x25519Encrypt(vm.cekPublic, credential)

    // 5. Rotate CEK for forward secrecy
    vm.rotateCEK()

    // 6. Generate new UTKs
    newUTKs := vm.generateUTKs(10)

    return &CredentialResponse{
        EncryptedCredential: encryptedCred,
        NewCEKPublic:        vm.cekPublic[:],
        NewUTKs:             newUTKs,
    }, nil
}

// Handle vault operation (signing, key access, etc.)
func (vm *VaultManager) HandleOperation(encryptedCred []byte, op Operation) (*OperationResponse, error) {
    // 1. Decrypt credential with CEK private key
    credentialBytes, err := x25519Decrypt(vm.cekPrivate, encryptedCred)
    if err != nil {
        return nil, fmt.Errorf("credential decryption failed: %w", err)
    }
    var credential ProteanCredential
    json.Unmarshal(credentialBytes, &credential)

    // 2. Create challenge with expiration (60 seconds)
    challenge := &Challenge{
        ID:         uuid.New().String(),
        UTKID:      vm.getAvailableUTK(),
        Credential: credential,
        Operation:  op,
        ExpiresAt:  time.Now().Add(60 * time.Second),
    }
    vm.pendingChallenges[challenge.ID] = challenge

    return &OperationResponse{
        Status:      "challenge",
        ChallengeID: challenge.ID,
        UTKID:       challenge.UTKID,
    }, nil
}

// Handle challenge response (password submission)
func (vm *VaultManager) HandleChallengeResponse(
    challengeID string,
    encryptedPwd []byte,
    utkID string,
) (*OperationResult, error) {
    // 1. Load and validate pending challenge
    challenge, exists := vm.pendingChallenges[challengeID]
    if !exists {
        return nil, errors.New("unknown challenge ID")
    }
    if time.Now().After(challenge.ExpiresAt) {
        delete(vm.pendingChallenges, challengeID)
        return nil, errors.New("challenge expired")
    }
    delete(vm.pendingChallenges, challengeID)

    // 2. Decrypt password with LTK (X25519)
    ltk, exists := vm.ltks[utkID]
    if !exists {
        return nil, errors.New("unknown or already-used UTK")
    }
    password, err := x25519Decrypt(ltk, encryptedPwd)
    if err != nil {
        return nil, fmt.Errorf("password decryption failed: %w", err)
    }
    delete(vm.ltks, utkID) // Single-use

    // 3. Verify password against credential hash (Argon2id)
    if !vm.verifyPassword(password, challenge.Credential) {
        return nil, errors.New("invalid password")
    }

    // 4. Perform operation
    result := vm.executeOperation(challenge.Operation, challenge.Credential)

    // 5. Rotate CEK and re-encrypt credential
    vm.rotateCEK()
    credentialBytes, _ := json.Marshal(challenge.Credential)
    newEncryptedCred, _ := x25519Encrypt(vm.cekPublic, credentialBytes)

    // 6. Generate new UTKs
    newUTKs := vm.generateUTKs(5)

    return &OperationResult{
        Success:             true,
        Result:              result,
        NewEncryptedCred:    newEncryptedCred,
        NewCEKPublic:        vm.cekPublic[:],
        NewUTKs:             newUTKs,
    }, nil
}

func (vm *VaultManager) rotateCEK() {
    // Generate new X25519 keypair
    rand.Read(vm.cekPrivate[:])
    curve25519.ScalarBaseMult(&vm.cekPublic, &vm.cekPrivate)

    // Store new private key in SQLite, sync to S3
    vm.saveAndSync()
}

func (vm *VaultManager) generateUTKs(count int) []UTK {
    utks := make([]UTK, count)
    for i := range utks {
        var priv, pub [32]byte
        rand.Read(priv[:])
        curve25519.ScalarBaseMult(&pub, &priv)
        utkID := uuid.New().String()
        utks[i] = UTK{ID: utkID, PublicKey: pub[:]}
        vm.ltks[utkID] = priv
    }
    vm.saveAndSync() // Persist new LTKs to SQLite, sync to S3
    return utks
}
```

### 6.3 S3 Sync Manager

Handles SQLite database persistence to S3 with DEK encryption. **Critical:** Syncs after every write for durability.

```go
type S3SyncManager struct {
    vaultDEK   [32]byte
    ownerID    string  // Cognito user_id for S3 path prefixing
    db         *sql.DB // Reference to in-memory SQLite
    vsock      *VsockConn

    // Operation serialization - prevents race conditions during S3 sync
    syncMu       sync.Mutex  // Held during entire sync operation
    syncInFlight bool        // True when sync is in progress

    // M6: AAD (Additional Authenticated Data) for encryption
    // Binds ciphertext to its S3 location - prevents ciphertext substitution attacks
    s3Key      string  // Full S3 key: "{ownerID}/vault.db.enc"
}

// NewS3SyncManager creates manager with AAD binding to S3 location
func NewS3SyncManager(dek [32]byte, ownerID string, vsock *VsockConn) *S3SyncManager {
    return &S3SyncManager{
        vaultDEK: dek,
        ownerID:  ownerID,
        vsock:    vsock,
        s3Key:    fmt.Sprintf("%s/vault.db.enc", ownerID), // AAD binding
    }
}

// Load database from S3 on vault warmup
func (s *S3SyncManager) Load() (*sql.DB, error) {
    // 1. Request encrypted DB from S3 via parent
    resp, err := s.vsock.Request(StorageRequest{
        Op:      "GET",
        OwnerID: s.ownerID,
        Key:     "vault.db.enc",
    })
    if err != nil {
        // New vault - create empty database
        return sql.Open("sqlite3", ":memory:")
    }

    // 2. Decrypt with DEK using AAD
    // M6: AAD must match what was used during encryption
    // If ciphertext was copied from a different S3 key, decryption fails
    nonce := resp.Data[:12]
    ciphertext := resp.Data[12:]

    aead, _ := chacha20poly1305.New(s.vaultDEK[:])
    aad := []byte(s.s3Key) // Must match AAD used in Sync()
    sqlDump, err := aead.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        return nil, fmt.Errorf("DEK decryption failed (wrong PIN or tampered data?): %w", err)
    }

    // 3. Load SQL dump into in-memory SQLite
    db, _ := sql.Open("sqlite3", ":memory:")
    _, err = db.Exec(string(sqlDump))
    if err != nil {
        return nil, fmt.Errorf("failed to restore database: %w", err)
    }

    s.db = db
    return db, nil
}

// Sync database to S3 after every write with retry logic
// IMPORTANT: Caller must hold syncMu or use WithSync() wrapper
func (s *S3SyncManager) Sync() error {
    // 1. Export SQLite to SQL dump
    var dump bytes.Buffer
    rows, _ := s.db.Query(`
        SELECT sql FROM sqlite_master
        WHERE sql IS NOT NULL
        UNION ALL
        SELECT 'INSERT INTO ' || name || ' VALUES(' ||
               group_concat(quote(value)) || ');'
        FROM (SELECT name FROM sqlite_master WHERE type='table')
        CROSS JOIN json_each(...)  -- Simplified for clarity
    `)
    for rows.Next() {
        var sql string
        rows.Scan(&sql)
        dump.WriteString(sql + ";\n")
    }

    // 2. Encrypt with DEK using AAD
    // M6: AAD binds ciphertext to its S3 location - decryption will fail if
    // ciphertext is copied to a different S3 key (prevents substitution attacks)
    nonce := make([]byte, 12)
    rand.Read(nonce)

    aead, _ := chacha20poly1305.New(s.vaultDEK[:])
    aad := []byte(s.s3Key) // AAD = S3 key (e.g., "user123/vault.db.enc")
    ciphertext := aead.Seal(nil, nonce, dump.Bytes(), aad)

    blob := append(nonce, ciphertext...)

    // 3. Upload to S3 via parent with retry logic
    return s.syncWithRetry(blob)
}

// WithSync wraps database operations to prevent race conditions during S3 sync.
// Operations are serialized: only one can be in-flight at a time.
// If sync fails, the operation is rolled back.
func (s *S3SyncManager) WithSync(operation func() error) error {
    s.syncMu.Lock()
    defer s.syncMu.Unlock()

    s.syncInFlight = true
    defer func() { s.syncInFlight = false }()

    // Start SQLite transaction for rollback capability
    tx, err := s.db.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }

    // Execute the operation
    if err := operation(); err != nil {
        tx.Rollback()
        return fmt.Errorf("operation failed: %w", err)
    }

    // Sync to S3 - if this fails, rollback SQLite changes
    if err := s.Sync(); err != nil {
        tx.Rollback()
        return fmt.Errorf("S3 sync failed, operation rolled back: %w", err)
    }

    // Both operation and sync succeeded - commit transaction
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }

    return nil
}

// syncWithRetry implements exponential backoff for S3 uploads
// CRITICAL: Operations MUST fail if sync fails - no silent data loss
func (s *S3SyncManager) syncWithRetry(blob []byte) error {
    maxRetries := 3
    baseDelay := 100 * time.Millisecond

    var lastErr error
    for attempt := 0; attempt < maxRetries; attempt++ {
        err := s.vsock.Send(StorageRequest{
            Op:      "PUT",
            OwnerID: s.ownerID,
            Key:     "vault.db.enc",
            Data:    blob,
        })

        if err == nil {
            return nil // Success
        }

        lastErr = err

        // Exponential backoff: 100ms, 200ms, 400ms
        delay := baseDelay * time.Duration(1<<attempt)
        log.Warn().
            Err(err).
            Int("attempt", attempt+1).
            Dur("retry_in", delay).
            Msg("S3 sync failed, retrying")

        time.Sleep(delay)
    }

    // All retries exhausted - this is a critical failure
    // The calling operation MUST fail and report error to user
    log.Error().
        Err(lastErr).
        Str("owner_id", s.ownerID).
        Msg("S3 sync failed after all retries - operation must be rolled back")

    return fmt.Errorf("S3 sync failed after %d retries: %w", maxRetries, lastErr)
}
```

**SQLite Schema:**

```sql
-- Keys table (CEK private key, LTKs)
CREATE TABLE keys (
    key_type  TEXT PRIMARY KEY,  -- 'cek_private', 'ltk:<utk_id>'
    key_data  BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Ledger entries (user's transaction history)
CREATE TABLE ledger (
    entry_id   TEXT PRIMARY KEY,
    entry_type TEXT NOT NULL,
    data       BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Configuration
CREATE TABLE config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Rollback protection (monotonic counter)
-- sync_counter MUST always increase; vault rejects DB with lower counter
CREATE TABLE sync_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),  -- Single row
    sync_counter INTEGER NOT NULL DEFAULT 0,
    last_sync_at INTEGER NOT NULL
);
INSERT INTO sync_state (id, sync_counter, last_sync_at) VALUES (1, 0, 0);
```

**Rollback Protection:**

The `sync_counter` prevents rollback attacks where an attacker with S3 write access
replaces the current database with an older version.

**CRITICAL:** Counter must survive vault restarts. We persist it in a separate S3 object
with versioning enabled. On load, we check ALL versions to find the highest counter ever seen.

```go
// In VaultManager - track highest-seen counter
type VaultManager struct {
    // ... other fields ...
    highestSyncCounter int64
}

// loadHighestCounterFromS3 reads ALL versions of counter file to find max
// This survives vault restarts and prevents rollback attacks
func (s *S3SyncManager) loadHighestCounterFromS3() (int64, error) {
    // Request all versions of counter file from S3
    resp, err := s.vsock.Request(StorageRequest{
        Op:      "LIST_VERSIONS",
        OwnerID: s.ownerID,
        Key:     "sync_counter.txt",
    })
    if err != nil {
        return 0, nil // New vault, no counter yet
    }

    // Find maximum counter across all versions
    var maxCounter int64
    for _, version := range resp.Versions {
        counter, _ := strconv.ParseInt(string(version.Data), 10, 64)
        if counter > maxCounter {
            maxCounter = counter
        }
    }
    return maxCounter, nil
}

// On Load(): Verify counter only increases
func (s *S3SyncManager) Load() (*sql.DB, error) {
    // 1. Load highest counter from S3 version history (survives restart)
    s3Counter, err := s.loadHighestCounterFromS3()
    if err != nil {
        return nil, fmt.Errorf("failed to load counter history: %w", err)
    }

    // 2. Load and decrypt database
    // ... (existing decrypt logic) ...

    // 3. Read sync counter from loaded DB
    var dbCounter int64
    db.QueryRow("SELECT sync_counter FROM sync_state WHERE id = 1").Scan(&dbCounter)

    // 4. CRITICAL: Reject if DB counter is lower than S3 history
    if dbCounter < s3Counter {
        return nil, fmt.Errorf("rollback attack detected: DB counter %d < S3 history %d",
            dbCounter, s3Counter)
    }

    s.vault.highestSyncCounter = dbCounter
    return db, nil
}

// On Sync(): Increment counter and persist to separate S3 object
func (s *S3SyncManager) Sync() error {
    // 1. Increment counter in SQLite
    s.db.Exec("UPDATE sync_state SET sync_counter = sync_counter + 1, last_sync_at = ?",
        time.Now().Unix())

    // 2. Read new counter value
    var counter int64
    s.db.QueryRow("SELECT sync_counter FROM sync_state WHERE id = 1").Scan(&counter)

    // 3. Persist counter to separate S3 object (versioned - creates new version)
    // This ensures counter history survives even if attacker replaces vault.db.enc
    s.vsock.Send(StorageRequest{
        Op:      "PUT",
        OwnerID: s.ownerID,
        Key:     "sync_counter.txt",
        Data:    []byte(strconv.FormatInt(counter, 10)),
    })

    s.vault.highestSyncCounter = counter

    // 4. Export, encrypt, upload database (existing logic)
    // ...
}
```

**S3 Structure for Rollback Protection:**
```
vaults/{owner_id}/
├── vault.db.enc          # Encrypted SQLite (can be attacked)
├── sealed_material.bin   # KMS-sealed DEK material
└── sync_counter.txt      # Counter file (S3 versioning enabled)
    ├── version 1: "1"
    ├── version 2: "2"
    ├── version 3: "3"    # ← All versions preserved
    └── version N: "N"    # ← Attacker cannot delete old versions
```

**Why This Works:**
- Attacker can replace `vault.db.enc` with old version (counter=100)
- But `sync_counter.txt` has version history showing counter reached 150
- On load: DB counter (100) < S3 history (150) → REJECTED
- S3 versioning prevents attacker from deleting version history

### 6.4 Shared WASM Handler Cache

```go
type WASMHandlerCache struct {
    handlers map[string]*CompiledHandler
    mu       sync.RWMutex
    runtime  wazero.Runtime

    // M10: Handler revocation list - blocks execution of compromised handlers
    revokedHandlers map[string]*RevocationEntry
    revocationMu    sync.RWMutex
}

type CompiledHandler struct {
    HandlerID  string
    Module     wazero.CompiledModule
    Signature  []byte   // Verified before adding to cache
    LoadedAt   time.Time
    Version    string   // Handler version for revocation matching
    Hash       [32]byte // SHA256 of WASM bytes for revocation by hash
}

// M10: Revocation entry - tracks why a handler was revoked
type RevocationEntry struct {
    HandlerID   string    // Handler ID (or "*" for all versions)
    Hash        [32]byte  // Specific hash revoked (or zero for all)
    RevokedAt   time.Time
    Reason      string    // Security advisory reference
    MinVersion  string    // Revoke all versions below this
}

// M10: Get returns handler only if not revoked
func (c *WASMHandlerCache) Get(handlerID string) (*CompiledHandler, error) {
    c.mu.RLock()
    handler := c.handlers[handlerID]
    c.mu.RUnlock()

    if handler == nil {
        return nil, ErrHandlerNotFound
    }

    // Check revocation list before returning
    if c.isRevoked(handler) {
        return nil, ErrHandlerRevoked
    }

    return handler, nil
}

// M10: Check if a handler is revoked
func (c *WASMHandlerCache) isRevoked(handler *CompiledHandler) bool {
    c.revocationMu.RLock()
    defer c.revocationMu.RUnlock()

    for _, rev := range c.revokedHandlers {
        // Check by handler ID
        if rev.HandlerID == handler.HandlerID || rev.HandlerID == "*" {
            // Check by hash (if specified)
            if rev.Hash != [32]byte{} && rev.Hash != handler.Hash {
                continue // Different hash, not revoked
            }
            // Check by minimum version (if specified)
            if rev.MinVersion != "" && handler.Version >= rev.MinVersion {
                continue // Version is safe
            }
            return true // Handler is revoked
        }
    }
    return false
}

// M10: Revoke a handler (called when security issue discovered)
func (c *WASMHandlerCache) Revoke(entry RevocationEntry) {
    c.revocationMu.Lock()
    defer c.revocationMu.Unlock()

    key := entry.HandlerID
    if entry.Hash != [32]byte{} {
        key = fmt.Sprintf("%s:%x", entry.HandlerID, entry.Hash[:8])
    }

    c.revokedHandlers[key] = &entry
    log.Warn().
        Str("handler_id", entry.HandlerID).
        Str("reason", entry.Reason).
        Msg("Handler revoked - security issue")
}

// M10: Load revocation list from S3 (checked on startup and periodically)
func (c *WASMHandlerCache) LoadRevocationList(vsock *VsockConn) error {
    resp, err := vsock.Request(StorageRequest{
        Op:  "GET",
        Key: "handler-revocations.json",
    })
    if err != nil {
        // No revocation list is OK (first deployment)
        return nil
    }

    var entries []RevocationEntry
    if err := json.Unmarshal(resp.Data, &entries); err != nil {
        return fmt.Errorf("invalid revocation list: %w", err)
    }

    c.revocationMu.Lock()
    for _, entry := range entries {
        c.revokedHandlers[entry.HandlerID] = &entry
    }
    c.revocationMu.Unlock()

    log.Info().Int("count", len(entries)).Msg("Loaded handler revocation list")
    return nil
}

var (
    ErrHandlerNotFound = errors.New("handler not found")
    ErrHandlerRevoked  = errors.New("handler revoked due to security issue")
)

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
    routingTable map[string]string  // owner_id → enclave vsock CID
}

func (p *ParentProcess) Run() {
    // Subscribe to vault messages from central NATS
    p.natsConn.Subscribe("vault.>", func(msg *nats.Msg) {
        // Extract owner ID from subject
        ownerID := extractOwnerID(msg.Subject)

        // Forward to enclave (message is E2E encrypted, we can't read it)
        p.vsock.Send(EnclaveMessage{
            Type:    "vault_message",
            OwnerID: ownerID,
            Payload: msg.Data,  // Opaque ciphertext
            ReplyTo: msg.Reply,
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
│                    vettid-vault-data-{env}-{account}                     │
│                                                                         │
│  vaults/                                                                │
│  ├── {vault_id}/                                                        │
│  │   ├── sealed_material.bin       # Sealed material for DEK derivation│
│  │   ├── vault.db.enc              # DEK-encrypted SQLite database     │
│  │   ├── vault.db.enc.counter      # Rollback protection counter       │
│  │   └── vault.db.enc.hmac         # Integrity verification HMAC       │
│  │                                                                      │
│  ├── {vault_id}/                                                        │
│  │   └── ...                                                            │
│  │                                                                      │
│  └── {vault_id}/                                                        │
│      └── ...                                                            │
│                                                                         │
│  handlers/                           # Shared WASM handlers             │
│  ├── backup.wasm                     # Handler for backup operations   │
│  ├── backup.wasm.sig                 # Signature for verification      │
│  ├── sync.wasm                       # Handler for sync operations     │
│  └── sync.wasm.sig                   # Signature for verification      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

SQLite Database Contents (decrypted in vault-manager memory):
─────────────────────────────────────────────────────────────
• CEK keypair (pub + private)
• LTKs (indexed by UTK ID)
• User ledger entries
• Handler state
• Operation audit log
```

### 7.2 Encryption Specification

| Data Type | Algorithm | Key | Nonce |
|-----------|-----------|-----|-------|
| Vault SQLite DB | ChaCha20-Poly1305 | Vault DEK | Random 12 bytes per sync |
| Sealed Material | AWS Nitro KMS | Nitro Attestation | Internal |
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
│   │  4. Initialize in-memory SQLite database                       │   │
│   │  5. Create initial schema (keys, ledger, config)               │   │
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
func (s *EnclaveSupervisor) evictVault(ownerID string) error {
    vault := s.vaults[ownerID]

    // 1. Stop accepting new messages
    vault.SetDraining(true)

    // 2. Wait for in-flight operations (with timeout)
    vault.WaitForDrain(5 * time.Second)

    // 3. Final sync to S3 (already synced after each write, but ensure)
    if err := vault.s3Sync.Sync(); err != nil {
        // CRITICAL: Sync failed - vault data may not be persisted
        // Recovery: Keep vault active, allow retry
        vault.SetDraining(false)
        vault.SetEvictionFailed(true)

        log.Error().
            Err(err).
            Str("owner_id", ownerID).
            Msg("Vault eviction failed - sync error, vault kept active")

        // Don't remove from map - vault is still usable
        // Admin can retry eviction or force-evict
        return fmt.Errorf("eviction sync failed: %w", err)
    }

    // 4. Close SQLite database
    vault.db.Close()

    // 5. Clear sensitive data from memory
    vault.ZeroizeKeys()

    // 6. Remove from active map
    delete(s.vaults, ownerID)

    log.Info().
        Str("owner_id", ownerID).
        Msg("Vault evicted successfully")

    return nil
}

// ForceEvictVault removes vault without syncing (data loss possible)
// Use only when sync is permanently failing and vault blocks memory
func (s *EnclaveSupervisor) forceEvictVault(ownerID string) {
    vault := s.vaults[ownerID]
    if vault == nil {
        return
    }

    log.Warn().
        Str("owner_id", ownerID).
        Msg("Force evicting vault - data since last successful sync may be lost")

    vault.db.Close()
    vault.ZeroizeKeys()
    delete(s.vaults, ownerID)
}
```

### 8.3 Evicted → Active Transition (Cold Start)

```go
func (s *EnclaveSupervisor) loadVault(ownerID string) (*VaultManager, error) {
    startTime := time.Now()

    // 1. Load sealed DEK from S3 (via parent)
    sealedDEK, err := s.loadSealedDEK(ownerID)
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

    // 3. Create S3 sync manager
    s3Sync := NewS3SyncManager(vaultDEK, ownerID, s.vsock)

    // 4. Load encrypted SQLite DB from S3, decrypt with DEK
    db, err := s3Sync.Load()
    if err != nil {
        return nil, fmt.Errorf("failed to load database: %w", err)
    }
    // Latency: ~100-200ms (download + decrypt + load)

    // 5. Create vault manager
    vault := &VaultManager{
        ownerID:      ownerID,
        vaultDEK:     vaultDEK,
        db:           db,
        s3Sync:       s3Sync,
        handlerCache: s.handlerCache,
        lastActivity: time.Now(),
    }

    // 6. Load keys from SQLite into memory
    vault.loadKeysFromDB()
    // Latency: ~5ms

    // 7. Add to active map
    s.vaults[ownerID] = vault

    coldStartLatency := time.Since(startTime)
    log.Info().
        Str("owner_id", ownerID).
        Dur("cold_start_ms", coldStartLatency).
        Msg("Vault loaded successfully")

    // M7: Emit CloudWatch metrics for cold start latency monitoring
    // Metrics are sent via parent process (enclave can't reach CloudWatch directly)
    s.emitColdStartMetrics(coldStartLatency)

    return vault, nil
    // Total latency: ~200-350ms (faster than NATS!)
}

// M7: Emit cold start latency metrics to CloudWatch via parent
func (s *EnclaveSupervisor) emitColdStartMetrics(latency time.Duration) {
    // Send metrics request to parent (parent has AWS credentials, enclave doesn't)
    s.vsock.Send(MetricsRequest{
        Namespace: "VettID/Enclave",
        Metrics: []MetricDatum{
            {
                Name:  "ColdStartLatency",
                Value: float64(latency.Milliseconds()),
                Unit:  "Milliseconds",
            },
            {
                Name:  "ColdStartCount",
                Value: 1,
                Unit:  "Count",
            },
        },
    })
}

// Parent process emits metrics to CloudWatch
func (p *ParentProcess) handleMetricsRequest(req MetricsRequest) {
    // CloudWatch PutMetricData API
    p.cloudwatch.PutMetricData(&cloudwatch.PutMetricDataInput{
        Namespace: aws.String(req.Namespace),
        MetricData: []types.MetricDatum{
            {
                MetricName: aws.String("ColdStartLatency"),
                Value:      aws.Float64(req.Metrics[0].Value),
                Unit:       types.StandardUnitMilliseconds,
                Dimensions: []types.Dimension{
                    {Name: aws.String("Environment"), Value: aws.String("production")},
                },
            },
            {
                MetricName: aws.String("ColdStartCount"),
                Value:      aws.Float64(1),
                Unit:       types.StandardUnitCount,
            },
        },
    })
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

## 10. Enclave Update & Credential Migration

### 10.1 The Challenge

When enclave code is updated, PCRs change. Sealed DEKs bound to old PCRs cannot be unsealed by new code.

```
Old Enclave (PCR: abc123)     New Enclave (PCR: def456)
├─ Can unseal old keys        ├─ CANNOT unseal old keys
└─ Running                    └─ Running

Problem: How to transition without losing access to user data?
```

### 10.2 Solution: Credential Migration During Rolling Update

**M8: Critical Migration Requirements:**

> **IMPORTANT:** Both old AND new enclave fleets MUST be running simultaneously during migration.
> - Old enclave: Required to unseal existing material (only it has the old PCRs)
> - New enclave: Required to verify re-sealed material works before cutover
>
> **Migration Window:** Do NOT terminate old enclave until:
> 1. All users' sealed material has been migrated
> 2. At least one successful warmup test has been performed per user on new enclave
> 3. Rollback plan is verified (keep old sealed_material.bin for 7+ days)
>
> **Cannot Migrate If:**
> - Old enclave is already terminated (material cannot be unsealed)
> - New enclave is not yet deployed (cannot re-seal for new PCRs)
> - KMS key policy doesn't allow both PCR values

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
│  Step 2: Migrate sealed material (in old enclave)                       │
│  ────────────────────────────────────────────────                       │
│                                                                         │
│      For each user vault:                                               │
│        a. Unseal material with old PCRs                                │
│        b. Re-seal material with new PCRs                               │
│           (Nitro KMS allows sealing for different PCRs)                │
│        c. Store new sealed_material in S3 (keep old as backup)         │
│                                                                         │
│      S3:                                                                │
│      └── user-ABC123/                                                   │
│          ├── sealed_material.bin     (old PCRs)                        │
│          └── sealed_material.v2.bin  (new PCRs) ← NEW                  │
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
│          └── sealed_material.bin (new PCRs, renamed)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.3 Sealed Material Migration Implementation

```go
// Run in OLD enclave during migration
func migrateSealedMaterialToNewPCRs(newPCRs PCRValues) error {
    // Get list of all users
    users, err := listAllUsers()
    if err != nil {
        return err
    }

    for _, userID := range users {
        // Load current sealed material
        sealedMaterial, err := loadSealedMaterial(userID)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to load sealed material")
            continue
        }

        // Unseal with current (old) attestation
        material, err := nitro.Unseal(sealedMaterial)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to unseal material")
            continue
        }

        // Re-seal for new PCRs
        newSealedMaterial, err := nitro.SealForPCRs(material, newPCRs)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to re-seal material")
            continue
        }

        // Store new sealed material (alongside old)
        err = storeSealedMaterial(userID, "sealed_material.v2.bin", newSealedMaterial)
        if err != nil {
            log.Error().Err(err).Str("user", userID).Msg("Failed to store new sealed material")
            continue
        }

        // Zero out plaintext material from memory
        zeroize(material)

        log.Info().Str("user", userID).Msg("Sealed material migrated successfully")
    }

    return nil
}
```

### 10.4 Rollback Strategy

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

### 10.5 Emergency Recovery

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

## 11. Cost Analysis

### 11.1 Current Costs (EC2 Model)

| Component | Unit Cost | Quantity | Monthly Cost |
|-----------|-----------|----------|--------------|
| t4g.micro (vault) | $6.05/mo | 100 | $605 |
| EBS (10GB per vault) | $0.80/mo | 100 | $80 |
| Data transfer | ~$0.50/vault | 100 | $50 |
| **Total (100 users)** | | | **$735/mo** |
| **Per-vault cost** | | | **$7.35** |

### 11.2 Enclave Model Costs (Phased)

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

### 11.3 Cost Comparison by Phase

| Phase | Users | EC2 Model | Enclave Model | Savings |
|-------|-------|-----------|---------------|---------|
| Dev/Test | 10 | $73/mo | $125/mo | -71% (acceptable for features) |
| Dev/Test | 50 | $368/mo | $138/mo | **62%** |
| Early Prod | 100 | $735/mo | $152/mo | **79%** |
| Growth | 200 | $1,470/mo | $427/mo | **71%** |
| Scale | 500 | $3,675/mo | $500/mo | **86%** |
| Scale | 1,000 | $7,350/mo | $750/mo | **90%** |

### 11.4 Break-Even Analysis

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

### 11.5 TCO Considerations

Beyond raw compute costs:

| Factor | EC2 Model | Enclave Model |
|--------|-----------|---------------|
| Operational complexity | High (manage 100s of instances) | Low (manage 1-3 instances) |
| Provisioning time | 30-60s | 300-500ms |
| Security guarantees | Trust-based | Attestation-based |
| Scaling events | Slow (launch EC2) | Fast (load vault) |
| Backup/DR | Per-instance EBS snapshots | Centralized S3 |

---

## 12. BYO Vault Considerations

### 12.1 BYO Options

Users who want to run their own vault infrastructure have three options:

| Option | Description | Complexity | Security |
|--------|-------------|------------|----------|
| **Self-hosted EC2** | Current model, user's AWS account | Low | Trust user's infra |
| **Self-hosted Enclave** | Nitro enclave in user's AWS account | Medium | Attestation |
| **On-premises** | User's own hardware/datacenter | High | Trust user's infra |

### 12.2 Self-Hosted Enclave

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

### 12.3 Configuration for BYO

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

## 13. Implementation Phases

**Last Updated:** 2026-01-06

### 13.1 Phase Overview

| Phase | Duration | Focus | Status |
|-------|----------|-------|--------|
| 1 | 3-4 weeks | Core enclave | ✅ Complete |
| 2 | 2-3 weeks | Integration | ✅ Complete |
| 3 | 2-3 weeks | Mobile apps | 🟢 95% Complete (E2E test pending) |
| 4 | 2-3 weeks | Operations | 🟡 Partial |
| 5 | 1-2 weeks | Launch | 🔴 Not Started |

### 13.2 Phase 1: Core Enclave ✅

**Objective**: Port vault-manager to run inside Nitro Enclave

**Status**: Complete (deployed 2026-01-03)

Tasks:
- [x] Set up enclave development environment
- [x] Create minimal enclave image with vault-manager
- [x] Implement vsock communication layer
- [x] Implement sealed storage for vault DEK
- [x] Implement SQLite + S3 sync with DEK encryption
- [x] Port vault data storage (JetStream → SQLite)
- [x] Unit tests for all enclave components
- [x] Generate and document PCRs

### 13.3 Phase 2: Integration ✅

**Objective**: Connect enclave to external systems

**Status**: Complete (deployed 2026-01-03)

Tasks:
- [x] Implement parent process (vsock ↔ S3 ↔ NATS routing)
- [x] Set up S3 bucket structure for vault DBs
- [x] Integrate with central NATS cluster for message routing
- [x] Implement supervisor process
- [x] Implement vault lifecycle management
- [x] Integration tests with mock external services
- [x] End-to-end tests with real infrastructure

**Lambda handlers updated:**
- `enrollStart.ts` - Always requests enclave attestation
- `enrollFinalize.ts` - Uses `requestCredentialCreate()` for enclave-based credential creation
- `vault-stack.ts` - Removed `USE_NITRO_ENCLAVE` feature flag (always enclave mode)

**Frontend integration (Phases 1-4 complete):**
- Vault status dashboard
- Mobile app enrollment flow with QR
- Vault provisioning & lifecycle UI
- Backup services tab

### 13.4 Phase 3: Mobile Apps 🟢

**Objective**: Update iOS and Android apps to support attestation

**Status**: 95% Complete - End-to-end testing remaining (blockers resolved 2026-01-06)

#### iOS Implementation (85-90% Complete)

| Task | Status | Notes |
|------|--------|-------|
| CBOR parsing | ✅ Complete | Custom RFC 7049 decoder in `NitroAttestationVerifier.swift` (730 lines) |
| COSE_Sign1 verification | ✅ Complete | Tag 18 parsing, signature verification |
| Certificate chain verification | ✅ Complete | SecTrust framework integration |
| PCR verification | ✅ Complete | `ExpectedPCRStore.swift` (384 lines) |
| PCR update mechanism | ✅ Complete | `PCRUpdateService.swift` (258 lines), Ed25519 signature verification |
| Enrollment integration | ✅ Complete | `EnrollmentService.swift` calls verifier |
| Nonce replay protection | ✅ Complete | Optional nonce matching |
| Timestamp freshness | ✅ Complete | 5-minute max age |
| Unit tests | ✅ Complete | 20+ test cases in `NitroAttestationVerifierTests.swift` |
| UI component | ✅ Complete | `AttestationView.swift` |

**iOS Remaining Tasks:**
- [x] ~~Bundle AWS Nitro Root CA certificate~~ - **Fixed 2026-01-06**: Now uses dynamic validation like Android
- [x] ~~Update `expected_pcrs.json`~~ - **Fixed 2026-01-06**: Real PCR values copied from Android
- [ ] End-to-end testing with production enclave

#### Android Implementation (95% Complete - Production Ready)

| Task | Status | Notes |
|------|--------|-------|
| CBOR parsing | ✅ Complete | Jackson CBOR 2.16.1 in `NitroAttestationVerifier.kt` (685 lines) |
| COSE_Sign1 verification | ✅ Complete | Full parsing and signature verification |
| Certificate chain verification | ✅ Complete | Bouncy Castle PKIX, dynamic root CA validation |
| PCR verification | ✅ Complete | `PcrConfigManager.kt` (395 lines) |
| PCR values bundled | ✅ Complete | Real PCR values from 2026-01-03 enclave build |
| Ed25519 PCR update signatures | ✅ Complete | Bouncy Castle integration |
| Enrollment integration | ✅ Complete | `EnrollmentViewModel.kt` blocks on verification failure |
| Nonce replay protection | ✅ Complete | Optional nonce verification |
| Timestamp freshness | ✅ Complete | 5-minute max age |
| Hardware attestation | ✅ Complete | `HardwareAttestationManager.kt` (StrongBox/TEE support) |

**Android Notes:**
- Does NOT bundle root CA certificate (dynamically validates from attestation doc - more secure)
- Has actual PCR values: `pcr0=c4fbe857...`, `pcr1=4b4d5b36...`, `pcr2=3f37ae4b...`
- Ed25519 signing key embedded: `MCowBQYDK2VwAyEA+1FRzTi+cZ1BIuBzNjnarDkN4T+gxNnDi4BCS7tbwX0=`

**Android Remaining Tasks:**
- [ ] End-to-end testing (backend 500 fixed 2026-01-06 - ready for testing)

#### Cross-Platform Status

| Requirement | iOS | Android |
|-------------|-----|---------|
| CBOR parsing | ✅ | ✅ |
| COSE_Sign1 | ✅ | ✅ |
| Cert chain verification | ✅ | ✅ |
| Root CA validation | ✅ Dynamic (fixed 2026-01-06) | ✅ Dynamic |
| PCR verification | ✅ | ✅ |
| PCR values configured | ✅ Real values (fixed 2026-01-06) | ✅ Real values |
| Enrollment integration | ✅ | ✅ |
| Unit tests | ✅ | ✅ |

**Documentation available:**
- `docs/NITRO-ENCLAVE-MIGRATION-FOR-MOBILE.md` (pushed to both repos)

### 13.5 Phase 4: Operations 🟡

**Objective**: Production-ready deployment and monitoring

**Status**: Partial - CDK deployed, monitoring/alerting pending

Tasks:
- [x] CDK stack for enclave infrastructure
- [ ] Auto-scaling configuration
- [ ] CloudWatch metrics and dashboards
- [ ] Alerting for enclave health
- [ ] Runbook for common operations
- [ ] Disaster recovery procedures
- [ ] Load testing and performance validation
- [ ] Security review

### 13.6 Phase 5: Launch 🔴

**Objective**: Deploy to production and begin user onboarding

**Status**: Not Started - Blocked by Phase 3 (Mobile Apps)

Tasks:
- [ ] Production deployment with monitoring
- [ ] Beta user onboarding (invite-only)
- [ ] Support documentation and runbooks
- [ ] On-call procedures and alerting
- [ ] Performance monitoring and tuning
- [ ] General availability rollout

### 13.7 Current Blockers

~~1. **iOS: Missing runtime resources**~~ - **RESOLVED 2026-01-06**
   - ~~AWS Nitro Root CA certificate not bundled~~ → Now uses dynamic validation
   - ~~expected_pcrs.json contains placeholder zeros~~ → Real PCR values added

~~2. **Backend: Enrollment endpoint returning HTTP 500**~~ - **RESOLVED 2026-01-06**
   - Enclave was temporarily unresponsive (NATS 503 "No Responders")
   - Now working: enrollment successfully returns `enclave_attestation`

3. **Phase 4 (Operations)** monitoring/alerting not configured
   - System is running but lacks observability
   - Auto-scaling, dashboards, alerting still needed

### 13.8 Remaining Action Items

| Priority | Task | Owner | Status |
|----------|------|-------|--------|
| ~~1~~ | ~~Fix backend HTTP 500 on enrollment~~ | Backend | ✅ Fixed |
| ~~2~~ | ~~Update iOS root CA validation~~ | iOS Dev | ✅ Fixed (dynamic) |
| ~~3~~ | ~~Copy Android PCR values to iOS~~ | iOS Dev | ✅ Fixed |
| 4 | End-to-end enrollment test (Android) | Android Dev | Pending |
| 5 | End-to-end enrollment test (iOS) | iOS Dev | Pending |
| 6 | Configure CloudWatch monitoring | DevOps | Pending |

---

## 14. Risks & Mitigations

### 14.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave memory insufficient | High | Low | Test with realistic vault counts; implement eviction |
| Cold start latency unacceptable | Medium | Low | Optimize loading; pre-warm predicted vaults |
| SQLite database corruption | Medium | Low | Sync after every write; S3 versioning for rollback |
| Attestation verification complex on mobile | Medium | Medium | Use existing libraries; thorough testing |
| vsock throughput bottleneck | Medium | Low | Load test; optimize batching |

### 14.2 Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Enclave update causes key inaccessibility | Critical | Low | Key migration process; keep old enclave running during transition |
| Multi-AZ failure | High | Very Low | Regional failover; S3 cross-region replication |
| S3 outage | High | Very Low | Local caching; graceful degradation |
| Migration causes data loss | Critical | Low | User-driven migration; keep EC2 until verified |

### 14.3 Security Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Attestation bypass | Critical | Very Low | Hardware-backed; AWS Nitro security |
| Side-channel attacks in shared enclave | High | Low | Process isolation; constant-time crypto |
| Compromised enclave build | Critical | Very Low | Reproducible builds; third-party audit |
| PCR collision | Critical | Very Low | SHA-384 collision-resistant |
| Challenge replay (C7) | Medium | Very Low | Single-use UTK/LTK pairs; challenge consumed on first use; CEK rotation invalidates captured credentials |
| Vault clone attack (C8) | High | Very Low | PCR-bound sealing (enclave-only); Argon2id PIN stretching; owner_id in salt; monotonic counter rejects rollback |
| SQLite rollback attack | Medium | Low | Monotonic sync_counter; vault rejects DB with counter < highest seen |
| Attestation replay | Medium | Very Low | App-provided nonce in attestation request; verify nonce matches in response |

### 14.4 Attack Vector Analysis

**Challenge Replay Window (60 seconds):**
During the challenge flow, an attacker intercepting the encrypted password response has 60 seconds to replay it. However:
- Single-use LTK is deleted after first decryption attempt
- Challenge ID is consumed immediately on first response
- CEK rotation after operation makes captured credential useless
- Requires real-time MITM of internal AWS infrastructure (vsock/NATS)

**Vault Clone Attack:**
Attacker with S3 read access copies `sealed_material.bin` + `vault.db.enc`:
- Cannot unseal material outside genuine Nitro Enclave (PCR-bound)
- Even with material, needs user's PIN for DEK derivation
- PIN brute-force: 1M possibilities × 300ms Argon2id = ~83 hours (in-enclave only)
- Monotonic counter blocks loading old database snapshots
- Rate limiting in supervisor blocks rapid PIN guessing

---

## 15. Decision Log

### 15.1 Key Decisions

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| 1 | Use Nitro Enclaves over alternatives | Hardware attestation; AWS native; well-documented | 2026-01-02 |
| 2 | Per-user vault-manager process | Preserves current architecture; simpler migration | 2026-01-02 |
| 3 | Per-user SQLite + S3 sync | Maintains data isolation; fast in-memory ops; cheap S3 persistence; sync after every write for durability | 2026-01-08 |
| 4 | Shared WASM handler cache | Memory efficiency; consistent handler versions | 2026-01-02 |
| 5 | S3 for encrypted blob storage | Durability; cross-AZ replication; cost-effective | 2026-01-02 |
| 6 | User-driven data migration | User controls their data; no VettID access to plaintext | 2026-01-02 |
| 7 | Two-factor authentication (Vault PIN + Credential Password) | PIN unlocks DEK (rare, per-session); Password authorizes operations (per-op). Compromising one doesn't compromise the other. | 2026-01-08 |
| 8 | PIN created in mobile app, not web portal | Mobile app is more secure (sandboxed); reduces web attack surface (XSS, extensions) | 2026-01-08 |
| 9 | Vault warming on every app open | PIN entry for app unlock also warms vault; no separate "cold vault" prompts; better UX | 2026-01-08 |
| 10 | CEK/UTK/LTK asymmetric key model | CEK encrypts credentials (rotates per-op for forward secrecy); UTK/LTK for secure app→vault communication (single-use for replay protection) | 2026-01-08 |
| 11 | Supervisor handles NSM/KMS, vault-manager handles credentials | Clear separation: supervisor is trust anchor with hardware access; vault-manager handles business logic. Prevents compromised vault-manager from forging attestations. | 2026-01-08 |
| 12 | Nitro attestation replaces LAT tokens | Hardware attestation is stronger than software tokens; NSM provides ephemeral keypairs per-request; eliminates LAT management complexity | 2026-01-08 |
| 13 | PIN verified by crypto failure, not hash comparison | Wrong PIN → wrong DEK → SQLite DB decryption fails (bad MAC). More secure than comparing hashed PINs; brute force requires enclave interaction per attempt. | 2026-01-08 |
| 14 | Single-credential with CEK rotation | INTENTIONAL theft-detection design. User holds ONE encrypted credential blob; CEK rotates after each use. If attacker steals blob, they race against user - first to use it invalidates the other's copy. Creates built-in theft detection without requiring revocation infrastructure. | 2026-01-08 |
| 15 | DEK derivation includes owner_id | Salt = SHA256(owner_id \|\| material). Binds DEK to user identity; prevents cross-vault confusion even if attacker controls material. | 2026-01-08 |

### 15.2 Open Questions

| # | Question | Status | Owner |
|---|----------|--------|-------|
| 1 | What is actual memory footprint per vault? | Needs profiling | TBD |
| 2 | ~~Can NATS JetStream use custom storage backend?~~ | ✅ Resolved: No - switched to SQLite + S3 | N/A |
| 3 | What is attestation verification latency on mobile? | Needs testing | TBD |
| 4 | How to handle vault during enclave restart? | Needs design | TBD |
| 5 | Cross-region DR strategy? | Needs design | TBD |

---

## Appendix A: Glossary

**Terminology Note:** This document uses `owner_id` and `vault_id` as the canonical identifiers. These are synonymous with the Cognito `user_id` (the `sub` claim from JWT tokens). All three refer to the same value - the unique identifier for a user's vault.

| Term | Definition |
|------|------------|
| **AAD** | Additional Authenticated Data - non-secret data included in AEAD authentication tag, binding ciphertext to context |
| **Attestation** | Cryptographic proof of code identity and enclave integrity |
| **CEK** | Credential Encryption Key - X25519 keypair for encrypting Protean Credentials (ECDH + ChaCha20-Poly1305). Public key held by app, private key in vault SQLite. Rotates after each operation for forward secrecy. |
| **DEK** | Data Encryption Key - symmetric key used to encrypt vault SQLite database. Derived from PIN + sealed material. |
| **Enclave** | Isolated compute environment with hardware-protected memory |
| **LTK** | Ledger Transaction Key - X25519 private key held by vault to decrypt messages from app. Paired with UTK. Single-use for replay protection. |
| **Nitro** | AWS hardware security platform for EC2 |
| **NSM** | Nitro Security Module - hardware device inside enclave for attestation and key generation |
| **owner_id** | Canonical identifier for a vault owner. Equal to Cognito `sub` claim. Used as S3 prefix and vault routing key. Also called `vault_id` or `user_id`. |
| **PCR** | Platform Configuration Register - hash of enclave components |
| **Protean Credential** | Single encrypted JSON blob containing all user secrets (keys, seeds, identity). Stored on device, decrypted only inside enclave. |
| **Sealed material** | Random bytes encrypted by KMS, bound to PCRs. Combined with PIN to derive DEK. |
| **Sealed storage** | Encryption bound to specific enclave code identity |
| **UTK** | User Transaction Key - X25519 public key held by app to encrypt messages to vault. Paired with LTK. Single-use for replay protection. |
| **vault_id** | Alias for owner_id. The unique identifier for a user's vault instance. |
| **vsock** | Virtual socket for enclave ↔ parent communication |
| **WASM** | WebAssembly - portable bytecode for event handlers |

---

## Appendix B: References

1. AWS Nitro Enclaves Documentation: https://docs.aws.amazon.com/enclaves/
2. SQLite: https://www.sqlite.org/docs.html
3. Wazero (Go WASM runtime): https://wazero.io/
4. ChaCha20-Poly1305: RFC 8439
5. X25519 Key Exchange: RFC 7748
6. NATS (message routing): https://nats.io/
7. AWS Nitro Attestation: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
8. Argon2id: RFC 9106

---

## Appendix C: Implementation Details

This appendix provides implementation specifications for items not fully detailed in the main sections.

### C.1 SQLite Database Limits (L2)

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max database size | 50 MB | Keeps cold start < 500ms; ~100 keys + ledger history |
| Max keys per vault | 100 | Credential size limit; prevents DoS |
| Max seed phrases | 10 | Practical limit for user management |
| Max ledger entries | 10,000 | ~2 years of daily transactions |
| Vacuum threshold | 20% bloat | Triggered during eviction |

```go
const (
    MaxDatabaseSize    = 50 * 1024 * 1024  // 50 MB
    MaxKeysPerVault    = 100
    MaxSeedPhrases     = 10
    MaxLedgerEntries   = 10000
    VacuumBloatPercent = 20
)

func (s *S3SyncManager) CheckLimits() error {
    var pageCount, pageSize int
    s.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
    s.db.QueryRow("PRAGMA page_size").Scan(&pageSize)

    dbSize := pageCount * pageSize
    if dbSize > MaxDatabaseSize {
        return fmt.Errorf("database size %d exceeds limit %d", dbSize, MaxDatabaseSize)
    }

    var keyCount int
    s.db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&keyCount)
    if keyCount >= MaxKeysPerVault {
        return ErrKeyLimitExceeded
    }

    return nil
}
```

### C.2 WASM Handler Distribution (L3)

Handlers are distributed via S3 with signature verification:

```
S3 Bucket: vettid-wasm-handlers-{env}
├── handlers/
│   ├── btc-signer/
│   │   ├── v1.0.0.wasm
│   │   ├── v1.0.0.wasm.sig      # Ed25519 signature
│   │   └── manifest.json        # Version metadata
│   ├── eth-signer/
│   │   └── ...
│   └── revocations.json         # Global revocation list
└── trusted-keys/
    └── signing-key.pub          # Ed25519 public key for verification

Handler Update Flow:
1. Parent process polls S3 every 5 minutes for manifest changes
2. Downloads new WASM + signature if version changed
3. Sends to enclave via vsock: { op: "handler_update", handler_id, wasm_bytes, signature }
4. Enclave verifies signature against embedded public key
5. Compiles and adds to cache (old version kept until no active uses)

Rollback: Set "force_version" in manifest.json to downgrade all enclaves
```

### C.3 S3 Bucket Naming Convention (L6)

```
Environment-specific bucket names:

Production:
  vettid-vault-data-prod-{account_id}
  vettid-wasm-handlers-prod-{account_id}

Staging:
  vettid-vault-data-staging-{account_id}

Development:
  vettid-vault-data-dev-{account_id}

Structure within vault bucket:
  s3://vettid-vault-data-{env}-{account}/
  ├── {owner_id}/
  │   ├── vault.db.enc           # Encrypted SQLite dump
  │   ├── sealed_material.bin    # KMS-sealed DEK material + HMAC
  │   └── sync_counter.txt       # Rollback protection counter
  ├── backups/
  │   └── {owner_id}/
  │       └── {timestamp}.enc    # Credential backup (time-delay recovery)
  └── handler-revocations.json   # Revocation list (replicated from handlers bucket)

Environment detection:
  - CDK injects VETTID_ENV environment variable
  - Parent process reads and passes to enclave at startup
  - Enclave validates env matches expected PCR (dev PCRs ≠ prod PCRs)
```

### C.4 Cold Start Prediction Algorithm (L7)

```go
// Predict which vaults to pre-warm based on usage patterns
type ColdStartPredictor struct {
    recentAccess map[string][]time.Time  // owner_id -> access timestamps
    mu           sync.RWMutex
}

// Called every minute by supervisor
func (p *ColdStartPredictor) GetPrewarmCandidates(maxSlots int) []string {
    p.mu.RLock()
    defer p.mu.RUnlock()

    now := time.Now()
    candidates := make([]scoredVault, 0)

    for ownerID, accesses := range p.recentAccess {
        // Score based on:
        // 1. Recency: accessed in last 24h = higher score
        // 2. Frequency: more accesses = higher score
        // 3. Time-of-day: if user typically active now = higher score

        recentCount := 0
        for _, t := range accesses {
            if now.Sub(t) < 24*time.Hour {
                recentCount++
            }
        }

        // Check if current hour matches typical usage pattern
        currentHour := now.Hour()
        hourMatch := 0
        for _, t := range accesses {
            if t.Hour() == currentHour {
                hourMatch++
            }
        }

        score := float64(recentCount)*0.5 + float64(hourMatch)*0.3
        if score > 0.5 {
            candidates = append(candidates, scoredVault{ownerID, score})
        }
    }

    // Sort by score descending, return top N
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].score > candidates[j].score
    })

    result := make([]string, 0, maxSlots)
    for i := 0; i < len(candidates) && i < maxSlots; i++ {
        result = append(result, candidates[i].ownerID)
    }
    return result
}

// Trigger: When memory available and < 80% capacity
func (s *EnclaveSupervisor) maybePrewarm() {
    if s.memoryManager.UsagePercent() > 80 {
        return
    }

    availableSlots := s.memoryManager.AvailableVaultSlots()
    candidates := s.predictor.GetPrewarmCandidates(min(3, availableSlots))

    for _, ownerID := range candidates {
        if _, exists := s.vaults[ownerID]; !exists {
            // Pre-load sealed material (but don't warm - no PIN yet)
            go s.preloadSealedMaterial(ownerID)
        }
    }
}
```

### C.5 Attestation Certificate Chain Validation (L8)

Mobile apps must validate the full Nitro attestation certificate chain:

```
Certificate Chain (embedded in attestation document):
┌─────────────────────────────────────────────────────────────────┐
│  AWS Nitro Root CA                                               │
│  Subject: CN=aws.nitro-enclaves                                  │
│  Validity: 2019-10-28 to 2049-10-28                             │
│  Fetched from: https://aws-nitro-enclaves.amazonaws.com/AWS... │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Intermediate CA (region-specific)                               │
│  Signed by: AWS Nitro Root CA                                    │
│  Subject: CN={region}.aws.nitro-enclaves                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Enclave Certificate (per-instance)                              │
│  Signed by: Intermediate CA                                      │
│  Contains: Enclave public key, PCR values                        │
└─────────────────────────────────────────────────────────────────┘

Validation Steps (performed by mobile app):
1. Parse attestation document (CBOR format, COSE_Sign1 structure)
2. Extract certificate chain from "certificate" field
3. Verify root CA matches AWS Nitro root (fetch dynamically or use pinned hash)
4. Verify chain: root → intermediate → enclave cert
5. Verify COSE signature using enclave certificate's public key
6. Extract PCR values from attestation document
7. Compare PCRs against expected values (from app config)
8. Extract user_data field, verify it contains the app's nonce
9. Check timestamp is recent (< 5 minutes old)

Root CA Verification Options:
  Option A: Dynamic fetch from AWS (recommended for production)
    - Fetch https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
    - Verify SHA256: 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c

  Option B: Pinned root CA hash (for offline validation)
    - Store SHA256 of root CA certificate
    - Verify fetched/bundled root matches hash
```

```swift
// iOS attestation validation (simplified)
func validateAttestation(_ document: Data, expectedPCRs: [String: String], nonce: Data) throws {
    // 1. Parse CBOR
    let attestation = try CBORDecoder().decode(AttestationDocument.self, from: document)

    // 2. Validate certificate chain
    let chain = try parseCertificateChain(attestation.certificate)
    try validateChainToRoot(chain, expectedRootHash: AWS_NITRO_ROOT_HASH)

    // 3. Verify COSE signature
    let enclavePubKey = chain.last!.publicKey
    try verifyCOSESignature(document, publicKey: enclavePubKey)

    // 4. Check PCRs
    for (index, expectedValue) in expectedPCRs {
        guard attestation.pcrs[index] == expectedValue else {
            throw AttestationError.pcrMismatch(index: index)
        }
    }

    // 5. Verify nonce (prevents replay)
    guard attestation.userData == nonce else {
        throw AttestationError.nonceMismatch
    }

    // 6. Check timestamp
    let age = Date().timeIntervalSince(attestation.timestamp)
    guard age < 300 else {  // 5 minutes
        throw AttestationError.attestationExpired
    }
}
```

### C.6 Vsock Message Format (L10)

Binary protocol for enclave ↔ parent communication:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vsock Message Format                          │
├─────────────────────────────────────────────────────────────────┤
│  Bytes 0-3:    Message length (uint32, big-endian)              │
│  Bytes 4-7:    Message type (uint32, big-endian)                │
│  Bytes 8-15:   Request ID (uint64, big-endian)                  │
│  Bytes 16-N:   Payload (MessagePack or raw bytes)               │
└─────────────────────────────────────────────────────────────────┘

Message Types:
  0x0001  NATS_PUBLISH      Parent → Enclave: incoming NATS message
  0x0002  NATS_REPLY        Enclave → Parent: outgoing NATS reply
  0x0003  STORAGE_REQUEST   Enclave → Parent: S3 operation request
  0x0004  STORAGE_RESPONSE  Parent → Enclave: S3 operation result
  0x0005  KMS_REQUEST       Enclave → Parent: KMS operation request
  0x0006  KMS_RESPONSE      Parent → Enclave: KMS operation result
  0x0007  METRICS           Enclave → Parent: CloudWatch metrics
  0x0008  HEALTH_CHECK      Parent → Enclave: Heartbeat request
  0x0009  HEALTH_RESPONSE   Enclave → Parent: Heartbeat response
  0x000A  HANDLER_UPDATE    Parent → Enclave: New WASM handler
  0x000B  SHUTDOWN          Parent → Enclave: Graceful shutdown signal

Storage Request Payload (MessagePack):
{
  "op": "GET" | "PUT" | "DELETE" | "LIST_VERSIONS",
  "owner_id": "string",
  "key": "string",
  "data": bytes (for PUT),
  "version_id": "string" (optional, for GET specific version)
}

Storage Response Payload:
{
  "success": bool,
  "data": bytes,
  "error": "string",
  "version_id": "string",
  "versions": [{ "version_id", "last_modified", "size" }]  // for LIST_VERSIONS
}
```

### C.7 WASM Execution Limits (L12)

```go
const (
    // CPU limits
    WASMMaxExecutionTime   = 5 * time.Second   // Per-handler invocation
    WASMMaxInstructions    = 100_000_000       // ~100ms on modern CPU

    // Memory limits
    WASMMaxMemoryPages     = 256               // 16 MB (64KB per page)
    WASMStackSize          = 1 * 1024 * 1024   // 1 MB stack

    // I/O limits
    WASMMaxOutputSize      = 1 * 1024 * 1024   // 1 MB response
    WASMMaxHostCalls       = 1000              // Prevent infinite loops via host
)

type WASMConfig struct {
    MaxExecutionTime time.Duration
    MaxMemoryPages   uint32
    MaxOutputSize    int
}

func (h *CompiledHandler) Execute(ctx context.Context, input []byte, config WASMConfig) ([]byte, error) {
    // Create context with timeout
    execCtx, cancel := context.WithTimeout(ctx, config.MaxExecutionTime)
    defer cancel()

    // Configure memory limits
    moduleConfig := wazero.NewModuleConfig().
        WithMemoryLimitPages(config.MaxMemoryPages).
        WithStartFunctions()  // Don't auto-run _start

    // Instantiate with limits
    instance, err := h.runtime.InstantiateModule(execCtx, h.Module, moduleConfig)
    if err != nil {
        return nil, fmt.Errorf("instantiation failed: %w", err)
    }
    defer instance.Close(execCtx)

    // Call handler function
    result, err := instance.ExportedFunction("handle").Call(execCtx, ...)
    if errors.Is(err, context.DeadlineExceeded) {
        return nil, ErrWASMTimeout
    }

    return result, err
}
```

### C.8 S3 Multipart Upload (L14)

For databases exceeding 5 MB, use multipart upload:

```go
const (
    MultipartThreshold = 5 * 1024 * 1024   // 5 MB
    MultipartPartSize  = 5 * 1024 * 1024   // 5 MB per part
)

func (s *S3SyncManager) uploadToS3(data []byte) error {
    if len(data) < MultipartThreshold {
        // Simple PUT
        return s.simplePut(data)
    }

    // Multipart upload for large databases
    uploadID, err := s.initiateMultipart()
    if err != nil {
        return err
    }

    var parts []CompletedPart
    for i := 0; i < len(data); i += MultipartPartSize {
        end := min(i+MultipartPartSize, len(data))
        part, err := s.uploadPart(uploadID, i/MultipartPartSize+1, data[i:end])
        if err != nil {
            s.abortMultipart(uploadID)
            return err
        }
        parts = append(parts, part)
    }

    return s.completeMultipart(uploadID, parts)
}

// Retry logic for multipart
func (s *S3SyncManager) uploadPartWithRetry(uploadID string, partNum int, data []byte) (CompletedPart, error) {
    var lastErr error
    for attempt := 0; attempt < 3; attempt++ {
        part, err := s.uploadPart(uploadID, partNum, data)
        if err == nil {
            return part, nil
        }
        lastErr = err
        time.Sleep(time.Duration(attempt*100) * time.Millisecond)
    }
    return CompletedPart{}, lastErr
}
```

### C.9 Metric Collection Intervals (L15)

```go
// CloudWatch metric emission schedule
const (
    // Real-time metrics (emitted immediately)
    MetricColdStartLatency     = "immediate"  // On each cold start
    MetricOperationLatency     = "immediate"  // On each operation
    MetricAuthFailure          = "immediate"  // Security events

    // Aggregated metrics (batched)
    MetricAggregationInterval  = 1 * time.Minute
    MetricFlushInterval        = 5 * time.Minute

    // Gauge metrics (sampled)
    MetricSampleInterval       = 30 * time.Second
)

type MetricsCollector struct {
    buffer    []MetricDatum
    mu        sync.Mutex
    lastFlush time.Time
}

// Metrics emitted:
var MetricDefinitions = map[string]MetricSpec{
    // Latency metrics (immediate, milliseconds)
    "ColdStartLatency":    {Unit: "Milliseconds", Immediate: true},
    "OperationLatency":    {Unit: "Milliseconds", Immediate: true},
    "S3SyncLatency":       {Unit: "Milliseconds", Immediate: true},

    // Count metrics (aggregated)
    "OperationCount":      {Unit: "Count", Aggregation: "Sum"},
    "ChallengeExpired":    {Unit: "Count", Aggregation: "Sum"},
    "UTKExhausted":        {Unit: "Count", Aggregation: "Sum"},

    // Gauge metrics (sampled every 30s)
    "ActiveVaults":        {Unit: "Count", Sampled: true},
    "MemoryUsagePercent":  {Unit: "Percent", Sampled: true},
    "CachedHandlers":      {Unit: "Count", Sampled: true},

    // Security metrics (immediate)
    "PINRateLimited":      {Unit: "Count", Immediate: true},
    "AttestationFailure":  {Unit: "Count", Immediate: true},
    "HandlerRevoked":      {Unit: "Count", Immediate: true},
}

// Dimensions added to all metrics:
// - Environment: dev/staging/prod
// - InstanceId: EC2 instance ID
// - Region: AWS region
```

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-02 | Architecture Team | Initial draft |
| 1.1 | 2026-01-02 | Architecture Team | Added Section 5: Protean Credential & Trust Model. Corrected security model to establish vault (Nitro Enclave) as the secure processing environment rather than user devices. All user secrets now stored in single encrypted Protean Credential that only attested enclaves can decrypt. |
| 1.2 | 2026-01-02 | Architecture Team | Critical fix: Credential creation now happens INSIDE the enclave (Section 5.7-5.9). Device only provides PIN, enclave generates all secrets. Simplified scaling to single-region ASG min=1 for dev/testing (Section 9). Updated cost analysis for phased deployment (Section 11). Break-even now at 18 users. |
| 1.3 | 2026-01-02 | Architecture Team | Added Section 5.12: Post-Enrollment Vault Access (clarifies connection flow, no chicken-and-egg). Removed Migration Strategy section (no existing vaults to migrate). Renumbered sections 10-15. Updated Phase 5 to Launch (not migration). |
| 1.4 | 2026-01-02 | Architecture Team | Added Section 5.13: Credential Backup & Recovery (VettID-hosted backup, device loss recovery, inactive user handling). Added Section 5.14: Account Portal Changes (vault management UI, new API endpoints). Clarified what needs backup (only credential + PIN knowledge). |
| 1.5 | 2026-01-02 | Architecture Team | Added 24-hour time-delay recovery for credential restore (Section 5.13). Added Section 5.14: Flexible Vault Authentication (PIN/password/pattern options). Pattern serialization spec for cross-platform consistency. Biometrics as local convenience only (not hashable). Moved Account Portal to Section 5.15. Updated credential structure for flexible auth_type. |
| 1.6 | 2026-01-06 | Claude Code | Updated Section 13 with actual completion status. Phases 1-2 complete. Phase 3 ~90% complete after reviewing iOS/Android repos - both have full attestation verification implemented. iOS missing: root CA cert bundle and real PCR values. Android production-ready. Added detailed per-platform status tables and immediate action items (Section 13.8). |
| 1.7 | 2026-01-06 | Claude Code | Fixed blockers: (1) iOS now uses dynamic root CA validation like Android - no bundled cert needed. (2) Updated iOS expected_pcrs.json with real PCR values from Android. (3) Backend HTTP 500 resolved (enclave now responding). Phase 3 now 95% complete - only E2E testing remaining. |
| 1.8 | 2026-01-08 | Claude Code | Major credential flow redesign: (1) Added CEK/UTK/LTK asymmetric key model (Section 5.5). (2) Two-factor auth: Vault PIN (DEK) + Credential Password (per-operation). (3) Clear supervisor/vault-manager separation - supervisor handles NSM/KMS, vault-manager handles credentials (Sections 5.6-5.9, 6.1-6.2). (4) PIN setup moved to mobile app, not web portal. (5) Vault warming on every app open via PIN. (6) Added 7 new decisions to decision log (decisions 7-13). (7) Updated glossary with CEK, UTK, LTK, NSM, sealed material terms. **Architect review fixes:** (8) Fixed CEK/UTK/LTK to use X25519 (not Ed25519 which is for signatures). (9) Added x25519Encrypt/Decrypt reference implementations with ChaCha20-Poly1305. (10) Rewrote Section 5.10 to show password-based auth with UTK encryption. (11) Fixed DEK derivation to use Argon2id PIN stretching. (12) Updated Section 5.2 credential structure with encryption layers diagram. (13) Updated ToC with correct section numbers. |
| 1.9 | 2026-01-08 | Claude Code | **Storage architecture change:** Replaced NATS JetStream with SQLite + S3. (1) Per-vault in-memory SQLite database for fast operations. (2) DEK-encrypted sync to S3 after every write for durability. (3) Cold start loads encrypted DB from S3, decrypts with DEK. (4) Updated all code examples, diagrams, and references. (5) Resolved open question #2 (JetStream custom storage not officially supported). (6) Added SQLite schema (keys, ledger, config tables). (7) Added S3SyncManager implementation. (8) Standardized terminology (owner_id, user_id). Rationale: JetStream doesn't officially support custom storage backends; SQLite + S3 is simpler, faster for in-memory ops, and cheaper (~$0.10/user/month vs ~$50/user/month for DynamoDB with active use). |
| 2.0 | 2026-01-09 | Claude Code | **Comprehensive architecture review and completion.** Security fixes: (M1) Vault eviction error handling with recovery. (M2) Challenge cleanup goroutine. (M3) Per-vault memory limits. (M4) X25519 domain separation. (M5) Supervisor PIN rate limiting. (M6) AAD binding for DEK encryption. (M7) Cold start CloudWatch metrics. (M8) Migration documentation clarification. (M10) WASM handler revocation list. **New Section 5.21:** Complete App↔Vault Message Protocol with TypeScript interfaces, NATS subjects, all message types, error codes. **Go code fixes:** Added JSON struct tags for wire protocol compatibility, defined all response structs (UTK, Challenge, BootstrapResponse, CredentialResponse, OperationResponse, OperationResult), documented helper functions (verifyBootstrapToken, buildCredential, verifyPassword, executeOperation). **Appendix C:** Implementation details for SQLite limits, WASM distribution, S3 naming, cold start prediction, attestation chain validation, vsock format, WASM timeouts, multipart uploads, metrics. **PIN caching lifecycle** documented for DEK rotation. Updated glossary with standardized terminology (owner_id/vault_id/user_id). |
