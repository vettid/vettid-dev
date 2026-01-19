# Nitro Enclave Enrollment - NATS API Specification

**Status:** CURRENT (Nitro Architecture)
**Last Updated:** 2026-01-18
**Supersedes:** REST-based enrollment flow (EC2 model - deprecated)
**Reference:** See [NITRO-ENCLAVE-VAULT-ARCHITECTURE.md](../../../docs/NITRO-ENCLAVE-VAULT-ARCHITECTURE.md) Section 5.6 for the complete enrollment flow

---

## Overview

This document specifies the NATS-based enrollment flow for the Nitro Enclave architecture. Mobile apps communicate directly with the enclave via NATS messaging for attestation verification and credential creation.

> **Note:** This replaces the old REST-based `/vault/enroll/*` endpoints which were used in the EC2-per-user model. Those endpoints are **deprecated** and should not be used.

---

## Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────────────────┐
│  Mobile App │◄─NATS──►│ NATS Cluster│◄─NATS──►│  Nitro Enclave          │
│             │         │ (JetStream) │         │  ┌───────────────────┐  │
│ Attestation │         │             │         │  │ Parent Process    │  │
│ Verification│         │ ENROLLMENT  │         │  │  (nats_client.go) │  │
│             │         │ Stream      │         │  └─────────┬─────────┘  │
└─────────────┘         └─────────────┘         │            │ vsock     │
                                                │  ┌─────────▼─────────┐  │
                                                │  │ Supervisor        │  │
                                                │  │ (NSM/KMS/DEK)     │  │
                                                │  └─────────┬─────────┘  │
                                                │            │            │
                                                │  ┌─────────▼─────────┐  │
                                                │  │ Vault Manager     │  │
                                                │  │ (CEK, Credential) │  │
                                                │  └───────────────────┘  │
                                                └─────────────────────────┘
```

**Key Components:**
- **Supervisor**: Handles NSM attestation, KMS operations, DEK derivation
- **Vault-Manager**: Handles CEK keypair, Protean Credential operations

---

## Handler Responsibilities

### PIN Handler (`pin_handler.go`)

**Purpose:** Create DEK and initialize vault. Does NOT create the Protean Credential.

| Step | Action | Component |
|------|--------|-----------|
| 1 | Decrypt PIN (ECIES with attestation key) | Supervisor |
| 2 | Generate random material (32 bytes) | Supervisor |
| 3 | KMS.Encrypt(material) → sealed_material | Supervisor → KMS |
| 4 | DEK = KDF(sealed_material, PIN) | Supervisor |
| 5 | Store sealed_material to S3 | Supervisor |
| 6 | Start vault-manager with DEK | Supervisor → Vault-Manager |
| 7 | Initialize SQLite (DEK-encrypted) | Vault-Manager |
| 8 | Generate CEK keypair | Vault-Manager |
| 9 | Generate UTK/LTK pairs | Vault-Manager |
| 10 | Return `{ status: "vault_ready", utks }` | → App |

**Returns:** `vault_ready` + UTKs. **No credential yet.**

### Credential Handler (`credential_handler.go`)

**Purpose:** Create the Protean Credential with user's password.

| Step | Action | Component |
|------|--------|-----------|
| 1 | Receive encrypted password hash + UTK ID | From App |
| 2 | Decrypt password hash with LTK | Vault-Manager |
| 3 | Mark UTK as used | Vault-Manager |
| 4 | Generate identity keypair (Ed25519) | Vault-Manager |
| 5 | Generate vault master secret | Vault-Manager |
| 6 | Create Protean Credential struct | Vault-Manager |
| 7 | Encrypt credential with CEK | Vault-Manager |
| 8 | Store CEK, LTKs in SQLite | Vault-Manager |
| 9 | Sync SQLite to S3 | Vault-Manager |
| 10 | Return `{ status: "created", encrypted_credential, new_utks }` | → App |

**Returns:** `encrypted_credential` + new UTKs.

---

## Enrollment Flow (Complete)

The enrollment flow has **three phases** after NATS connection:

1. **Attestation** - Verify enclave identity, get ephemeral public key
2. **PIN Setup** - Create DEK, initialize vault, get UTKs
3. **Credential Creation** - User creates credential password, Protean Credential generated

```
┌─────────────┐                           ┌─────────────────┐
│  Mobile App │                           │  Nitro Enclave  │
└──────┬──────┘                           └────────┬────────┘
       │                                           │
       │  1. POST /nats/account (REST)             │
       │─────────────────────────────────────────► │
       │     { owner_space, nats_url, jwt, seed }  │
       │◄─────────────────────────────────────────│
       │                                           │
       │  2. Connect to NATS                       │
       │─────────────────────────────────────────► │
       │                                           │
═══════════════════════════════════════════════════════════════
 PHASE 1: ATTESTATION
═══════════════════════════════════════════════════════════════
       │                                           │
       │  3. Generate random nonce (32 bytes)      │
       │                                           │
       │  4. forVault.attestation                  │
       │     { nonce }                             │
       │─────────────────────────────────────────► │
       │                                           │
       │                                   5. Supervisor:
       │                                      NSM.GetAttestation()
       │                                      (ephemeral pubkey + nonce)
       │                                           │
       │  6. forApp.attestation.response           │
       │     { attestation_document,               │
       │       enclave_public_key }                │
       │◄─────────────────────────────────────────│
       │                                           │
       │  7. VERIFY:                               │
       │     • AWS Nitro signature valid?          │
       │     • PCRs match published values?        │
       │     • Nonce matches ours?                 │
       │     • Extract enclave public key          │
       │                                           │
═══════════════════════════════════════════════════════════════
 PHASE 2: PIN SETUP (DEK Creation + Vault Initialization)
═══════════════════════════════════════════════════════════════
       │                                           │
       │  8. User creates PIN (4-8 digits)         │
       │                                           │
       │  9. Encrypt PIN to enclave pubkey (ECIES) │
       │                                           │
       │ 10. forVault.pin                          │
       │     { type: "pin.setup", payload: {...} } │
       │─────────────────────────────────────────► │
       │                                           │
       │                                  11. Supervisor:
       │                                      - Decrypt PIN
       │                                      - Generate random material
       │                                      - KMS.Encrypt(material) → sealed
       │                                      - DEK = KDF(material, PIN)
       │                                      - Store sealed_material
       │                                           │
       │                                  12. Supervisor → Vault-Manager:
       │                                      - Start with DEK
       │                                      - Initialize SQLite (DEK-encrypted)
       │                                      - Generate CEK keypair
       │                                      - Generate UTK/LTK pairs
       │                                           │
       │ 13. forApp.pin.response                   │
       │     { status: "vault_ready",              │
       │       utks: [...] }                       │
       │◄─────────────────────────────────────────│
       │                                           │
═══════════════════════════════════════════════════════════════
 PHASE 3: CREDENTIAL CREATION (Protean Credential)
═══════════════════════════════════════════════════════════════
       │                                           │
       │ 14. User creates credential password      │
       │     (different from PIN!)                 │
       │                                           │
       │ 15. App hashes password (Argon2id)        │
       │     Encrypts with UTK                     │
       │                                           │
       │ 16. forVault.credential.create            │
       │     { encrypted_password_hash,            │
       │       utk_id }                            │
       │─────────────────────────────────────────► │
       │                                           │
       │                                  17. Vault-Manager:
       │                                      - Decrypt with LTK
       │                                      - Generate identity_keypair
       │                                      - Generate master_secret
       │                                      - Create Protean Credential:
       │                                        {
       │                                          identity_private_key,
       │                                          identity_public_key,
       │                                          vault_master_secret,
       │                                          password_hash (Argon2id),
       │                                          auth_salt,
       │                                          crypto_keys: []
       │                                        }
       │                                      - Encrypt credential with CEK
       │                                      - Store CEK, LTKs in SQLite
       │                                      - Sync SQLite to S3
       │                                           │
       │ 18. forApp.credential.response            │
       │     { status: "created",                  │
       │       encrypted_credential,               │
       │       new_utks: [...] }                   │
       │◄─────────────────────────────────────────│
       │                                           │
       │ 19. Store encrypted_credential locally    │
       │     + UTKs for future operations          │
       │                                           │
═══════════════════════════════════════════════════════════════
 PHASE 4: VERIFY ENROLLMENT
═══════════════════════════════════════════════════════════════
       │                                           │
       │ 20. Send test operation (e.g., get_info)  │
       │─────────────────────────────────────────► │
       │                                           │
       │                                  21. Decrypt credential
       │                                      Verify password hash
       │                                      Return info
       │                                           │
       │ 22. Success! Enrollment verified          │
       │◄─────────────────────────────────────────│
       │                                           │
```

---

## Key Concepts

### PIN vs Credential Password

| | PIN | Credential Password |
|---|-----|---------------------|
| **Purpose** | Unlock vault (DEK derivation) | Authorize operations |
| **Format** | 4-8 digits | User-chosen string |
| **Hashing** | KDF with KMS-sealed material | Argon2id (app-side) |
| **Storage** | Not stored (derived each time) | Hash in Protean Credential |
| **When Used** | Vault unlock, credential restore | Every vault operation |

### UTK/LTK System

- **UTK (User Transaction Key)**: Public keys held by app for encrypting requests
- **LTK (Ledger Transaction Key)**: Private keys held by vault for decrypting
- UTKs are single-use and rotated after each operation
- New UTKs returned with each response

### Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                        Key Hierarchy                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PIN (user's mind)                                               │
│    + KMS-sealed material                                         │
│    ────────────────────                                          │
│           │                                                      │
│           ▼                                                      │
│    ┌─────────────┐                                               │
│    │     DEK     │  Data Encryption Key                          │
│    │ (volatile)  │  - Derived each time from PIN + sealed mat    │
│    └──────┬──────┘  - Never stored, only in enclave memory       │
│           │         - Encrypts SQLite database                   │
│           │                                                      │
│           ▼                                                      │
│    ┌─────────────────────────────────────────────────────┐       │
│    │              SQLite Database (DEK-encrypted)         │       │
│    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │       │
│    │  │ CEK Keypair │  │  LTK Store  │  │ Vault Data  │  │       │
│    │  │ (X25519)    │  │ (per UTK)   │  │             │  │       │
│    │  └──────┬──────┘  └─────────────┘  └─────────────┘  │       │
│    └─────────┼───────────────────────────────────────────┘       │
│              │                                                   │
│              ▼                                                   │
│    ┌───────────────────────────────────────────────────┐         │
│    │           Protean Credential (CEK-encrypted)       │         │
│    │  - identity_private_key (Ed25519)                  │         │
│    │  - identity_public_key                             │         │
│    │  - vault_master_secret                             │         │
│    │  - password_hash (Argon2id)                        │         │
│    │  - crypto_keys[]                                   │         │
│    └───────────────────────────────────────────────────┘         │
│              │                                                   │
│              ▼                                                   │
│         Stored on App (encrypted blob)                           │
│         Backed up to Cloud Storage                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- **DEK** encrypts the SQLite database (where CEK and LTKs are stored)
- **CEK** encrypts the Protean Credential (which app stores locally)
- **PIN** is never stored - DEK is derived fresh each time
- **Password hash** is stored inside the Protean Credential for operation authorization

---

## NATS Topics

### Attestation

| Direction | Topic | Purpose |
|-----------|-------|---------|
| App → Enclave | `OwnerSpace.{guid}.forVault.attestation` | Request attestation doc |
| Enclave → App | `OwnerSpace.{guid}.forApp.attestation.response` | Attestation response |

### PIN Operations

| Direction | Topic | Purpose |
|-----------|-------|---------|
| App → Enclave | `OwnerSpace.{guid}.forVault.pin` | PIN setup/unlock/change |
| Enclave → App | `OwnerSpace.{guid}.forApp.pin.response` | PIN operation response |

### Credential Operations

| Direction | Topic | Purpose |
|-----------|-------|---------|
| App → Enclave | `OwnerSpace.{guid}.forVault.credential.create` | Create Protean Credential |
| Enclave → App | `OwnerSpace.{guid}.forApp.credential.response` | Credential response |

---

## Message Formats

### Attestation Request

```json
{
  "id": "<uuid>",
  "type": "attestation.request",
  "nonce": "<base64-32-bytes>",
  "timestamp": "<ISO8601>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique request ID for correlation |
| `type` | string | Yes | Must be `"attestation.request"` |
| `nonce` | string | Yes | 32-byte random nonce (base64) for freshness |
| `timestamp` | string | Yes | ISO8601 timestamp |

### Attestation Response

```json
{
  "id": "<uuid>",
  "status": "success",
  "attestation_document": "<base64-CBOR>",
  "enclave_public_key": "<base64-X25519-32-bytes>",
  "module_id": "<enclave-module-id>",
  "timestamp": "<ISO8601>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Correlates to request ID |
| `status` | string | `"success"` or `"error"` |
| `attestation_document` | string | AWS Nitro attestation doc (CBOR, base64) |
| `enclave_public_key` | string | X25519 public key for ECIES encryption |
| `module_id` | string | Enclave module identifier |
| `timestamp` | string | ISO8601 timestamp |

### PIN Setup Request

```json
{
  "id": "<uuid>",
  "type": "pin.setup",
  "payload": {
    "encrypted_pin": "<base64>",
    "ephemeral_public_key": "<base64-X25519-32-bytes>",
    "nonce": "<base64-12-bytes>"
  },
  "timestamp": "<ISO8601>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique request ID |
| `type` | string | Yes | Must be `"pin.setup"` |
| `payload.encrypted_pin` | string | Yes | ECIES-encrypted PIN payload |
| `payload.ephemeral_public_key` | string | Yes | App's ephemeral X25519 public key |
| `payload.nonce` | string | Yes | 12-byte nonce for ChaCha20-Poly1305 |
| `timestamp` | string | Yes | ISO8601 timestamp |

**Encrypted PIN Payload Format:**

The `encrypted_pin` field contains the ChaCha20-Poly1305 ciphertext of:
```json
{"pin": "123456"}
```

**Encryption Process (ECIES):**
1. App generates ephemeral X25519 keypair
2. Compute shared secret: `ECDH(ephemeral_private, enclave_public_key)`
3. Derive key: `HKDF-SHA256(shared_secret, "vettid-pin-encryption-v1")`
4. Encrypt: `ChaCha20-Poly1305(derived_key, nonce, plaintext={"pin": "123456"})`

### PIN Setup Response

```json
{
  "status": "vault_ready",
  "utks": [
    { "id": "<utk-id>", "public_key": "<base64>" },
    ...
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"vault_ready"` on success |
| `utks` | array | User Transaction Keys for credential creation |

**Note:** PIN setup does NOT return the credential. The vault is initialized and ready, but the Protean Credential is created in the next step.

### Credential Create Request

```json
{
  "id": "<uuid>",
  "type": "credential.create",
  "utk_id": "<utk-id>",
  "encrypted_payload": "<base64>",
  "timestamp": "<ISO8601>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique request ID |
| `type` | string | Yes | Must be `"credential.create"` |
| `utk_id` | string | Yes | UTK used for encryption |
| `encrypted_payload` | string | Yes | UTK-encrypted password hash |
| `timestamp` | string | Yes | ISO8601 timestamp |

**Encrypted Payload (before encryption):**
```json
{
  "password_hash": "<base64-argon2id-hash>"
}
```

The app hashes the credential password with Argon2id before encrypting with UTK.

### Credential Create Response

```json
{
  "status": "created",
  "encrypted_credential": "<base64>",
  "new_utks": [
    { "id": "<utk-id>", "public_key": "<base64>" },
    ...
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"created"` on success |
| `encrypted_credential` | string | CEK-encrypted Protean Credential |
| `new_utks` | array | Fresh UTKs for future operations |

---

## Protean Credential Format

The `encrypted_credential` contains the user's Protean Credential, encrypted with the CEK.

**Decrypted Structure:**
```json
{
  "identity_private_key": "<base64-Ed25519>",
  "identity_public_key": "<base64-Ed25519>",
  "vault_master_secret": "<base64-32-bytes>",
  "password_hash": "<base64-argon2id>",
  "auth_salt": "<base64>",
  "auth_type": "password",
  "crypto_keys": [],
  "created_at": 1705555555,
  "version": 1
}
```

| Field | Description |
|-------|-------------|
| `identity_private_key` | User's Ed25519 signing key |
| `identity_public_key` | User's public identity |
| `vault_master_secret` | Seed for deriving sub-keys |
| `password_hash` | Argon2id hash of credential password |
| `auth_salt` | Salt used for password verification |
| `auth_type` | Always `"password"` for new credentials |
| `crypto_keys` | Additional derived keys (populated later) |

---

## Error Responses

All operations can return errors:

```json
{
  "status": "error",
  "error": "<error-message>",
  "timestamp": "<ISO8601>"
}
```

**Common Errors:**

| Error | Cause |
|-------|-------|
| `"attestation key required"` | Attestation not done or expired (5 min) |
| `"invalid payload format"` | Malformed request |
| `"PIN must be 4-8 digits"` | PIN validation failed |
| `"decryption failed"` | ECIES decryption error |
| `"invalid UTK"` | UTK not found or already used |
| `"vault not initialized"` | PIN setup not completed |

---

## JetStream Configuration

Responses are delivered via JetStream for guaranteed delivery:

**Stream:** `ENROLLMENT`
**Subjects:** `OwnerSpace.*.forApp.>`

**Consumer Configuration (for mobile apps):**
```kotlin
ConsumerConfiguration.builder()
    .filterSubject("OwnerSpace.{guid}.forApp.>")
    .deliverPolicy(DeliverPolicy.New)
    .ackPolicy(AckPolicy.None)
    .build()
```

**Why JetStream?**
- Responses may arrive before subscription is established
- Messages persist for 30 minutes
- Survives brief network disconnections

---

## Security Considerations

### Attestation Key Lifetime
- Attestation keys are held in enclave memory for **5 minutes**
- PIN setup must occur within this window
- If expired, request a new attestation

### PIN vs Password Security
- PIN protects DEK derivation (combined with KMS-sealed material)
- Password protects operation authorization (Argon2id hashed)
- Both are required for full vault access

### UTK Single-Use Policy
- Each UTK can only be used once
- Always use fresh UTK from previous response
- Reusing UTKs will fail

---

## Migration from EC2 Model

| Old (EC2) | New (Nitro) |
|-----------|-------------|
| `POST /vault/enroll/start` | NATS: `forVault.attestation` |
| `POST /vault/enroll/set-password` | NATS: `forVault.pin` + `forVault.credential.create` |
| `POST /vault/enroll/finalize` | Not needed |
| Poll for vault status | Not needed - enclave always ready |
| `encrypted_blob` | `encrypted_credential` |

---

## Changelog

- **2026-01-18**: Initial specification for Nitro architecture
- Added complete three-phase enrollment flow (Attestation → PIN → Credential)
- Documented PIN vs Credential Password distinction
- Added credential.create message format
- Documented JetStream consumer requirements
