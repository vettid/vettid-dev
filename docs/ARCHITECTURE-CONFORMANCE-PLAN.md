# Architecture Conformance Plan

## Overview

This document outlines the changes required to make the VettID codebase conform with the Nitro Enclave Vault Architecture v2.0.

## Gap Analysis

### 1. Enrollment Flow (HIGH PRIORITY)

**Architecture v2.0 (Section 5.12):**
- Phase 1: Attestation (app verifies enclave via NSM)
- Phase 2: PIN Setup & DEK Creation (supervisor handles KMS sealing)
- Phase 3: Credential Creation (vault-manager creates credential)

**Current Implementation:**
- Enrollment via Lambda (`enrollFinalize.ts`) provisions EC2 instance
- Vault-manager generates identity keypair and stores credential
- No clear separation between supervisor (DEK) and vault-manager (credential)
- PIN stored as SHA-256 hash in DynamoDB, not used for DEK derivation

**Changes Required:**
- [ ] Implement 3-phase enrollment in supervisor + vault-manager
- [ ] Move DEK derivation to supervisor using KMS sealing
- [ ] Update Lambda to orchestrate new enrollment flow
- [ ] Update mobile apps for new enrollment protocol

---

### 2. Two-Factor Authentication Model (HIGH PRIORITY)

**Architecture v2.0 (Section 5.17):**
- PIN: Unlocks vault (DEK derivation via supervisor/KMS)
- Password: Authorizes operations (hash compared by vault-manager)

**Current Implementation:**
- Single PIN system stored in DynamoDB (SHA-256)
- Password hash stored in credential blob
- No separation of PIN (DEK) vs Password (operations)

**Changes Required:**
- [ ] Implement PIN → DEK derivation in supervisor
- [ ] Implement Password → operation authorization in vault-manager
- [ ] Update mobile apps for two-factor model
- [ ] Remove DynamoDB PIN storage (move to sealed material)

---

### 3. Password Hashing Location (HIGH PRIORITY)

**Architecture v2.0 (Sections 5.6, 5.9, 5.10):**
- App ALWAYS hashes password with Argon2id before sending
- Vault-manager compares received hash to stored hash

**Current Implementation:**
- Android: CryptoManager has Argon2id, but unclear if always used client-side
- Vault-manager: Also has Argon2id (crypto.go) - may be hashing server-side
- Need to verify and standardize

**Changes Required:**
- [ ] Ensure Android always hashes before sending
- [ ] Ensure iOS always hashes before sending
- [ ] Vault-manager should only compare, not hash
- [ ] Document salt exchange protocol (app needs salt from credential)

---

### 4. CEK Model (MEDIUM PRIORITY)

**Architecture v2.0 (Section 5.5):**
- CEK keypair: Both held by vault-manager in SQLite
- App does NOT have CEK - only receives encrypted blob

**Current Implementation:**
- CredentialStore.kt stores `cekVersion` but not CEK itself (correct)
- Need to verify vault-manager properly manages CEK rotation

**Changes Required:**
- [ ] Verify CEK rotation after each operation
- [ ] Ensure app never receives CEK public key
- [ ] Update any code that sends CEK to app

---

### 5. Storage: JetStream → SQLite (HIGH PRIORITY)

**Architecture v2.0 (Section 7.1):**
- SQLite database (DEK-encrypted) synced to S3
- Contains: CEK keypair, LTKs, user ledger entries, handler state

**Current Implementation:**
- Uses NATS JetStream for storage
- Multiple streams (EVENTS, VAULT_KV, HANDLERS)

**Changes Required:**
- [ ] Replace JetStream storage with SQLite in vault-manager
- [ ] Implement DEK encryption for SQLite
- [ ] Implement S3 sync with rollback protection counter
- [ ] Add HMAC integrity verification

---

### 6. Session Tokens (MEDIUM PRIORITY)

**Architecture v2.0 (Section 5.17):**
- Session token embedded IN credential structure
- Not a separate token

**Current Implementation:**
- Uses separate NATS JWTs for session management
- Bootstrap credentials for initial connection

**Changes Required:**
- [ ] Embed session in credential structure
- [ ] Update vault-manager to check embedded session on decrypt
- [ ] Remove separate session token management

---

### 7. Backup Flow (MEDIUM PRIORITY)

**Architecture v2.0 (Section 5.18):**
- Vault-manager sends to app AND backup simultaneously
- Backend confirms to vault-manager
- Vault-manager confirms success to app

**Current Implementation:**
- App uploads backup to S3 via Lambda
- Metadata stored in DynamoDB
- Vault doesn't handle backup directly

**Changes Required:**
- [ ] Move backup responsibility to vault-manager
- [ ] Implement simultaneous send (app + backend)
- [ ] Add confirmation flow (backend → vault → app)

---

### 8. Recovery Flow (MEDIUM PRIORITY)

**Architecture v2.0 (Section 5.18):**
- Account Portal (web) initiates recovery
- QR code displayed after 24h delay
- App scans QR to receive credential

**Current Implementation:**
- Direct download via Lambda (`downloadRecoveredCredential.ts`)
- No QR code mechanism
- 24h delay exists (correct)

**Changes Required:**
- [ ] Implement QR code generation in Account Portal
- [ ] Add QR code scanning to mobile apps
- [ ] Remove direct credential download endpoint
- [ ] Add recovery token exchange endpoint

---

### 9. PCR Endpoint (LOW PRIORITY)

**Architecture v2.0 (Section 4.3):**
- `GET /api/enclave/pcrs` endpoint
- Apps fetch PCRs dynamically (no app update needed)
- 24h cache TTL

**Current Implementation:**
- No PCR endpoint exists
- PCRs would be hardcoded in apps

**Changes Required:**
- [ ] Create Lambda handler for PCR endpoint
- [ ] Store PCRs in Parameter Store or DynamoDB
- [ ] Add PCR signing with release key
- [ ] Update mobile apps to fetch PCRs

---

### 10. Nitro KMS Sealing (HIGH PRIORITY)

**Architecture v2.0 (Section 5.14):**
- sealed_material KMS-sealed by supervisor
- PCR-bound (only matching enclave can unseal)
- Used for DEK derivation

**Current Implementation:**
- `sealed_storage.go` has dev mode (ChaCha20-Poly1305 with fixed key)
- Production KMS integration marked as TODO

**Changes Required:**
- [ ] Implement actual Nitro KMS sealing in supervisor
- [ ] Implement KMS key policy with PCR conditions
- [ ] Add sealed_material storage to S3
- [ ] Implement DEK derivation: KDF(unsealed_material, PIN)

---

### 11. Account Portal Updates (MEDIUM PRIORITY)

**Architecture v2.0 (Section 5.20):**
- Remove direct credential download
- Add recovery request initiation
- Add QR code display for recovery

**Current Implementation:**
- Has credential backup download
- No recovery QR code generation

**Changes Required:**
- [ ] Remove `/vault/backup` download endpoint from portal
- [ ] Add `/vault/recovery/request` endpoint
- [ ] Add `/vault/recovery/qr` endpoint
- [ ] Update portal UI for recovery flow

---

### 12. iOS App (HIGH PRIORITY)

**Architecture v2.0:**
- Must implement same protocol as Android
- Argon2id client-side hashing
- UTK encryption for transport
- QR code scanning for recovery

**Current Implementation:**
- iOS source not in repository
- Need to verify/implement conformance

**Changes Required:**
- [ ] Implement/verify Argon2id client-side hashing
- [ ] Implement UTK pool management
- [ ] Implement QR code recovery scanning
- [ ] Implement two-factor (PIN + Password) flow
- [ ] Implement PCR fetching and verification

---

## Implementation Phases

### Phase 1: Core Enclave Changes (Weeks 1-3)
1. Supervisor: Implement Nitro KMS sealing
2. Supervisor: Implement DEK derivation from sealed_material + PIN
3. Vault-manager: Replace JetStream with SQLite
4. Vault-manager: Implement proper CEK rotation

### Phase 2: Enrollment Flow (Weeks 4-5)
1. Implement 3-phase enrollment (attestation → PIN/DEK → credential)
2. Update Lambda handlers for new flow
3. Update mobile apps for new enrollment protocol

### Phase 3: Two-Factor Auth (Weeks 6-7)
1. Implement PIN → DEK (supervisor)
2. Implement Password → operations (vault-manager)
3. Ensure app-side Argon2id hashing
4. Update mobile apps

### Phase 4: Backup & Recovery (Weeks 8-9)
1. Move backup to vault-manager
2. Implement QR code recovery flow
3. Update Account Portal
4. Update mobile apps

### Phase 5: Polish & Security (Weeks 10-11)
1. Add PCR endpoint
2. Embed sessions in credential
3. Add HMAC integrity verification
4. Security audit

---

## GitHub Issues Summary

| Priority | Component | Issue Title |
|----------|-----------|-------------|
| HIGH | Enclave | Implement Nitro KMS sealing in supervisor |
| HIGH | Enclave | Replace JetStream with SQLite in vault-manager |
| HIGH | Enclave | Implement 3-phase enrollment flow |
| HIGH | Enclave | Implement two-factor auth (PIN/DEK + Password/ops) |
| HIGH | Backend | Update enrollment Lambda handlers for new flow |
| HIGH | Android | Ensure client-side Argon2id hashing |
| HIGH | iOS | Implement conformant credential handling |
| MEDIUM | Enclave | Implement CEK rotation on every operation |
| MEDIUM | Enclave | Embed session tokens in credential |
| MEDIUM | Enclave | Move backup to vault-manager |
| MEDIUM | Backend | Implement QR code recovery endpoints |
| MEDIUM | Backend | Update Account Portal for recovery flow |
| MEDIUM | Android | Implement QR code recovery scanning |
| MEDIUM | iOS | Implement QR code recovery scanning |
| LOW | Backend | Add PCR publication endpoint |
| LOW | Android | Implement PCR fetching |
| LOW | iOS | Implement PCR fetching |
