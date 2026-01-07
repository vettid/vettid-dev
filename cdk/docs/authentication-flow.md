# VettID Authentication Flow

## Document Purpose

This document provides a consolidated view of the VettID authentication and enrollment flow, from the web account portal through the Nitro-based vault to the mobile app. It covers how NATS messaging is used and which Lambda handlers are involved at each stage.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Key Components](#2-key-components)
3. [Enrollment Flow](#3-enrollment-flow)
4. [Session Authentication Flow](#4-session-authentication-flow)
5. [Credential Restore Flow](#5-credential-restore-flow)
6. [NATS Topic Structure](#6-nats-topic-structure)
7. [Lambda Handlers Reference](#7-lambda-handlers-reference)
8. [Data Storage](#8-data-storage)
9. [Security Model](#9-security-model)

---

## 1. Architecture Overview

VettID uses a **Nitro Enclave** architecture where:

- **Lambdas** serve as the **control plane** (enrollment, NATS setup, status)
- **Vault-manager** (in Nitro enclave) serves as the **data plane** (credential operations, data storage)
- **NATS** provides secure **app-to-vault** communication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VettID Architecture                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐                      ┌──────────────────────────────┐ │
│  │   Web Portal     │                      │      AWS Nitro Enclave       │ │
│  │   vettid.dev/    │                      │  ┌────────────────────────┐  │ │
│  │     account      │                      │  │   vault-manager        │  │ │
│  └────────┬─────────┘                      │  │   - Decryption keys    │  │ │
│           │                                │  │   - NATS account keys  │  │ │
│           │ 1. Create Session              │  │   - JetStream storage  │  │ │
│           ▼                                │  └──────────┬─────────────┘  │ │
│  ┌──────────────────┐                      │             │                │ │
│  │   Lambda APIs    │                      └─────────────┼────────────────┘ │
│  │  (Control Plane) │◄──────────────────────────────────┘                   │
│  │                  │        6. Health updates                              │
│  │  - Enrollment    │                                                       │
│  │  - NATS Setup    │                      ┌──────────────────────────────┐ │
│  │  - Status        │                      │       NATS Cluster           │ │
│  └────────┬─────────┘                      │     nats.vettid.dev:443      │ │
│           │                                │                              │ │
│           │ 2. Return QR Code              │   OwnerSpace.{guid}/         │ │
│           │    & Session Token             │   ├── forVault (app → vault) │ │
│           ▼                                │   ├── forApp (vault → app)   │ │
│  ┌──────────────────┐                      │   └── control (lambda→vault) │ │
│  │   Mobile App     │                      │                              │ │
│  │   (iOS/Android)  │                      │   MessageSpace.{guid}/       │ │
│  │                  │───────────────────┐  │   └── (vault-to-vault msgs)  │ │
│  │  3. Scan QR      │                   │  └──────────────┬───────────────┘ │
│  │  4. Connect NATS │                   │                 │                 │
│  └──────────────────┘                   │                 │                 │
│           │                             │                 │                 │
│           │ 5. App ↔ Vault via NATS     │                 │                 │
│           └─────────────────────────────┼─────────────────┤                 │
│                                         │                 │                 │
│                                         │    ┌────────────┘                 │
│                                         │    │ Vault connects to NATS       │
│                                         │    │ on startup (OwnerSpace +     │
│                                         │    │ MessageSpace)                │
│                                         │    │                              │
│                                         └────┴──────────────────────────────│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

| Principle | Implementation |
|-----------|----------------|
| **User Holds Credential** | Protean Credential (encrypted blob) stored on user's mobile device |
| **Vault Holds Keys** | Decryption key for credential stored in vault's JetStream |
| **No Central Database** | Legacy PostgreSQL/DynamoDB credential tables removed |
| **Per-User Namespace** | Each user has dedicated NATS OwnerSpace and MessageSpace |
| **Bootstrap Credentials** | Temporary NATS creds for initial connection, full creds from vault |

---

## 2. Key Components

### 2.1 Protean Credential

The **Protean Credential** is a single encrypted blob containing:

- User GUID
- Password hash (Argon2id)
- Vault access secrets
- Policy information

**Storage Model**:

| Component | Location | Purpose |
|-----------|----------|---------|
| **Encrypted Credential Blob** | Mobile App (user's device) | User holds their credential |
| **Decryption Key** | Vault JetStream | Only vault can decrypt the blob |
| **NATS Account Keys** | Vault JetStream | For generating user JWTs |

**Created By**: vault-manager when app calls `app.bootstrap`

**How It Works**:
1. User's app holds the encrypted Protean Credential blob
2. When app needs vault operations, it sends the encrypted blob to the vault
3. Vault decrypts using its stored key, performs operation
4. Vault always re-encrypts with a **new key** (constant key rotation after every use)
5. Updated encrypted blob + new key ID returned to app for storage

### 2.2 NATS Accounts

Each vault manages two NATS accounts on behalf of the user:

| Account | Used By | Purpose | Topics |
|---------|---------|---------|--------|
| **OwnerSpace** | App + Vault | App ↔ Vault private communication | `forVault`, `forApp`, `control` |
| **MessageSpace** | Vault only | Vault-to-vault communication with other users | `forOwner`, `ownerProfile`, `call` |

**Note**: The mobile app only connects to OwnerSpace. The vault uses MessageSpace for communicating with other users' vaults (messaging, calls, etc.).

### 2.3 DynamoDB Tables (Control Plane)

| Table | Purpose |
|-------|---------|
| `NatsAccounts` | Maps user_guid → NATS account (seed, public key, JWT) |
| `EnrollmentSessions` | Tracks web-to-mobile enrollment handoff |
| `Invites` | Invitation codes for new members |
| `CredentialRecoveryRequests` | 24-hour delay recovery requests |
| `CredentialBackups` | Backup metadata (encrypted data in S3/vault) |

---

## 3. Enrollment Flow

### 3.1 Web-Initiated Enrollment (QR Code Flow)

This is the primary enrollment flow for new users.

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Web Portal │    │   Lambda    │    │  Mobile App │    │    NATS     │    │   Enclave   │
│ vettid.dev/ │    │   APIs      │    │             │    │             │    │vault-manager│
│   account   │    │             │    │             │    │             │    │             │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │                  │
       │ 1. POST /vault/enroll/session       │                  │                  │
       │─────────────────►│                  │                  │                  │
       │                  │ Create session   │                  │                  │
       │                  │ (status: WEB_    │                  │                  │
       │                  │  INITIATED)      │                  │                  │
       │◄─────────────────│                  │                  │                  │
       │ {session_token,  │                  │                  │                  │
       │  qr_data}        │                  │                  │                  │
       │                  │                  │                  │                  │
       │ 2. Display QR code                  │                  │                  │
       │====================                 │                  │                  │
       │                  │                  │                  │                  │
       │                  │ 3. Scan QR, extract session_token   │                  │
       │                  │                  │                  │                  │
       │                  │ 4. POST /vault/enroll/authenticate  │                  │
       │                  │◄─────────────────│                  │                  │
       │                  │ Validate token,  │                  │                  │
       │                  │ return JWT       │                  │                  │
       │                  │─────────────────►│                  │                  │
       │                  │ {enrollment_token}                  │                  │
       │                  │                  │                  │                  │
       │                  │ 5. (Optional) POST /vault/attestation/nitro           │
       │                  │◄─────────────────│                  │                  │
       │                  │ Verify enclave   │                  │                  │
       │                  │─────────────────►│                  │                  │
       │                  │ {valid, pcr_ver} │                  │                  │
       │                  │                  │                  │                  │
       │                  │ 6. POST /vault/enroll/finalize      │                  │
       │                  │◄─────────────────│                  │                  │
       │                  │ Create NATS      │                  │                  │
       │                  │ account, return  │                  │                  │
       │                  │ bootstrap creds  │                  │                  │
       │                  │─────────────────►│                  │                  │
       │                  │ {vault_bootstrap}│                  │                  │
       │                  │                  │                  │                  │
       │                  │                  │ 7. Connect to NATS                  │
       │                  │                  │─────────────────►│                  │
       │                  │                  │                  │                  │
       │                  │                  │ 8. Publish to forVault.app.bootstrap│
       │                  │                  │─────────────────►│─────────────────►│
       │                  │                  │                  │                  │
       │                  │                  │                  │ Create Protean   │
       │                  │                  │                  │ Credential blob, │
       │                  │                  │                  │ store decrypt    │
       │                  │                  │                  │ key in JetStream │
       │                  │                  │                  │                  │
       │                  │                  │ 9. forApp.app.bootstrap.{id}        │
       │                  │                  │◄─────────────────│◄─────────────────│
       │                  │                  │ {encrypted_credential, full_creds}  │
       │                  │                  │                  │                  │
       │                  │                  │ 10. Reconnect with full credentials │
       │                  │                  │─────────────────►│                  │
       │                  │                  │                  │                  │
       │                  │                  │ ✓ ENROLLED       │                  │
       │                  │                  │                  │                  │
```

### 3.2 Lambda Handlers for Enrollment

| Step | Endpoint | Handler | Auth | Purpose |
|------|----------|---------|------|---------|
| 1 | `POST /vault/enroll/session` | `createEnrollmentSession` | Member JWT | Create session, return QR data |
| 4 | `POST /vault/enroll/authenticate` | `authenticateEnrollment` | None (public) | Exchange session_token for enrollment JWT |
| 5 | `POST /vault/attestation/nitro` | `verifyNitroAttestation` | None (public) | Verify enclave integrity |
| 6 | `POST /vault/enroll/finalize` | `enrollFinalize` | Enrollment JWT | Create NATS account, return bootstrap creds |

### 3.3 Enrollment Response Structure

**enrollFinalize** returns:

```json
{
  "status": "enrolled",
  "vault_status": "ENCLAVE_READY",
  "vault_bootstrap": {
    "credentials": "-----BEGIN NATS USER JWT-----\n...",
    "owner_space": "OwnerSpace.abc123def456...",
    "message_space": "MessageSpace.abc123def456...",
    "nats_endpoint": "tls://nats.vettid.dev:443",
    "bootstrap_topic": "OwnerSpace.{guid}.forVault.app.bootstrap",
    "response_topic": "OwnerSpace.{guid}.forApp.app.bootstrap.>",
    "credentials_ttl_seconds": 3600
  }
}
```

---

## 4. Session Authentication Flow

After enrollment, the mobile app communicates directly with the vault via NATS.

### 4.1 Normal Session Flow

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│  Mobile App │                    │    NATS     │                    │   Enclave   │
│             │                    │             │                    │vault-manager│
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │ 1. Connect with stored NATS creds                                   │
       │─────────────────────────────────►│                                  │
       │                                  │                                  │
       │ 2. Subscribe: OwnerSpace.{guid}.forApp.>                            │
       │─────────────────────────────────►│                                  │
       │                                  │                                  │
       │ 3. Publish: OwnerSpace.{guid}.forVault.{event_type}                 │
       │─────────────────────────────────►│─────────────────────────────────►│
       │                                  │                                  │
       │                                  │     Process event (may need      │
       │                                  │     password unlock for secrets) │
       │                                  │                                  │
       │ 4. Response: OwnerSpace.{guid}.forApp.{event_type}.{request_id}     │
       │◄─────────────────────────────────│◄─────────────────────────────────│
       │                                  │                                  │
```

### 4.2 Event Message Format

**App → Vault** (forVault topic):

```json
{
  "event_id": "uuid",
  "event_type": "handler.action",
  "timestamp": "2024-01-15T10:30:00Z",
  "encrypted_payload": "base64...",
  "encryption": {
    "algorithm": "X25519+XChaCha20-Poly1305",
    "key_id": "k_abc123def456",
    "ephemeral_public_key": "base64..."
  }
}
```

**Vault → App** (forApp topic):

```json
{
  "response_id": "uuid",
  "event_id": "uuid",
  "timestamp": "2024-01-15T10:30:01Z",
  "status": "success",
  "encrypted_payload": "base64...",
  "encryption": {
    "algorithm": "X25519+XChaCha20-Poly1305",
    "key_id": "k_xyz789abc012",
    "ephemeral_public_key": "base64..."
  }
}
```

**Key ID Usage**:
- Each key pair is assigned a unique `key_id` known to both parties
- Enables graceful key rotation (receiver can look up correct key)
- Previous keys retained briefly for in-flight messages during rotation

### 4.3 Credential Usage During Sessions

**Key Point**: The user holds the encrypted credential, not the vault:

- App connects to NATS with stored NATS credentials
- For operations requiring the credential, app sends encrypted blob to vault
- Vault decrypts using its stored key, performs operation
- Vault **always** re-encrypts with a new key (constant rotation after every use)
- App stores the newly encrypted credential locally

### 4.4 No Lambda Involvement

**Key Point**: Normal session operations do NOT touch Lambda or DynamoDB:

- App communicates directly with vault via NATS
- All data operations handled by vault-manager
- Decryption key stored in vault's JetStream (not AWS)
- Lambdas only used for control plane operations (enrollment, recovery, backup coordination)

---

## 5. Credential Restore Flow

### 5.1 Device Transfer (Old Device Available)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  New Device │    │   Lambda    │    │  Old Device │    │   Enclave   │
│             │    │   APIs      │    │             │    │vault-manager│
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │ 1. POST /vault/credentials/restore/request             │
       │─────────────────►│                  │                  │
       │                  │ Create recovery  │                  │
       │                  │ request          │                  │
       │◄─────────────────│                  │                  │
       │ {recovery_id}    │                  │                  │
       │                  │                  │                  │
       │                  │ 2. Old device sees pending request  │
       │                  │                  │                  │
       │                  │ 3. POST /vault/credentials/restore/approve
       │                  │◄─────────────────│                  │
       │                  │ Approve transfer │                  │
       │                  │─────────────────►│                  │
       │                  │                  │                  │
       │ 4. POST /vault/credentials/restore/confirm             │
       │─────────────────►│                  │                  │
       │                  │ Return bootstrap │                  │
       │                  │ credentials      │                  │
       │◄─────────────────│                  │                  │
       │ {vault_bootstrap}│                  │                  │
       │                  │                  │                  │
       │ 5. Connect NATS, call app.restore   │                  │
       │────────────────────────────────────────────────────────►
       │                  │                  │                  │
       │ 6. Receive full credentials         │ Transfer creds   │
       │◄───────────────────────────────────────────────────────│
       │                  │                  │                  │
```

### 5.2 Lost Device Recovery (24-Hour Delay)

**Simplified Backup Model**:
- Vault-manager automatically backs up encrypted credential to S3 after every use (when backups enabled)
- No recovery phrase needed - user authenticates to vault with their password
- The 24-hour delay protects against account takeover (email compromise)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  New Device │    │   Lambda    │    │   Enclave   │
│             │    │   APIs      │    │vault-manager│
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       │ 1. POST /restore/request {lost_device: true}
       │─────────────────►│                  │
       │                  │ Create request,  │
       │                  │ set 24hr timer   │
       │◄─────────────────│                  │
       │ {ready_at: +24h} │                  │
       │                  │                  │
       │    ... 24 hours pass ...            │
       │                  │                  │
       │ 2. POST /restore/confirm            │
       │─────────────────►│                  │
       │                  │ Fetch backup from│
       │                  │ S3, return with  │
       │                  │ NATS bootstrap   │
       │◄─────────────────│                  │
       │ {credential_backup, vault_bootstrap}│
       │                  │                  │
       │ 3. Connect NATS, authenticate with credential + password
       │────────────────────────────────────►│
       │                  │                  │ Verify password
       │                  │                  │ against credential
       │ 4. Authentication success, full NATS credentials returned
       │◄───────────────────────────────────│
       │                  │                  │
```

**Security**: Even if attacker compromises Cognito account and waits 24 hours, they cannot authenticate to the vault without knowing the user's password.

### 5.3 Lambda Handlers for Restore

| Endpoint | Handler | Auth | Purpose |
|----------|---------|------|---------|
| `POST /vault/credentials/restore/request` | `restoreRequest` | Member JWT | Initiate restore (transfer or lost device) |
| `POST /vault/credentials/restore/approve` | `restoreApprove` | Enrollment JWT | Old device approves transfer |
| `POST /vault/credentials/restore/deny` | `restoreDeny` | Enrollment JWT | Old device denies transfer |
| `POST /vault/credentials/restore/cancel` | `restoreCancel` | Member JWT | Cancel pending request |
| `POST /vault/credentials/restore/confirm` | `restoreConfirm` | Member JWT | Complete restore after approval/timer |
| `GET /vault/credentials/restore/status` | `restoreStatus` | Member JWT | Check restore request status |

---

## 6. NATS Topic Structure

### 6.1 OwnerSpace (App ↔ Vault)

```
OwnerSpace.{member_guid}/
├── forVault            # App → Vault: Commands from mobile app
│   ├── app.bootstrap   # Initial bootstrap after enrollment
│   ├── app.restore     # Credential restore
│   ├── vault.unlock    # Unlock vault with password
│   ├── secrets.get     # Get secrets (requires unlock)
│   └── {handler}.{action}  # Custom handler events
│
├── forApp              # Vault → App: Responses and notifications
│   ├── app.bootstrap.{id}  # Bootstrap response
│   ├── app.restore.{id}    # Restore response
│   └── {handler}.{action}.{id}  # Handler responses
│
├── eventTypes          # Vault → App: Available event definitions
│
└── control             # Lambda → Vault: System commands
    ├── prepare_backup
    ├── execute_backup
    ├── health_check
    └── shutdown
```

### 6.2 MessageSpace (Connections)

```
MessageSpace.{member_guid}/
├── forOwner            # Connections → Vault: Inbound messages
└── ownerProfile        # Vault → Connections: Public profile
```

### 6.3 NATS JWT Permissions

**App Credentials** (generated by vault-manager after bootstrap):

```json
{
  "pub": { "allow": ["OwnerSpace.{guid}.forVault.>"] },
  "sub": { "allow": ["OwnerSpace.{guid}.forApp.>", "OwnerSpace.{guid}.eventTypes"] }
}
```

**Bootstrap Credentials** (temporary, from Lambda):

```json
{
  "pub": { "allow": ["OwnerSpace.{guid}.forVault.app.bootstrap"] },
  "sub": { "allow": ["OwnerSpace.{guid}.forApp.app.bootstrap.>"] }
}
```

---

## 7. Lambda Handlers Reference

### 7.1 Enrollment Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `createEnrollmentSession` | `vault/createEnrollmentSession.ts` | Create web-initiated session |
| `authenticateEnrollment` | `vault/authenticateEnrollment.ts` | Exchange session token for JWT |
| `enrollFinalize` | `vault/enrollFinalize.ts` | Create NATS account, return bootstrap creds |
| `cancelEnrollmentSession` | `vault/cancelEnrollmentSession.ts` | Cancel pending enrollment |

### 7.2 NATS Management Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `natsCreateAccount` | `vault/natsCreateAccount.ts` | Create NATS account for member |
| `natsGenerateToken` | `vault/natsGenerateToken.ts` | Generate new user JWT |
| `natsRevokeToken` | `vault/natsRevokeToken.ts` | Revoke existing token |
| `natsGetStatus` | `vault/natsGetStatus.ts` | Get NATS account status |
| `natsLookupAccountJwt` | `vault/natsLookupAccountJwt.ts` | URL resolver for NATS server |

### 7.3 Attestation Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `verifyNitroAttestation` | `vault/verifyNitroAttestation.ts` | Verify enclave attestation document |
| `getPcrConfig` | `vault/getPcrConfig.ts` | Get current PCR values |

### 7.4 Restore/Recovery Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `restoreRequest` | `vault/restoreRequest.ts` | Start restore flow |
| `restoreApprove` | `vault/restoreApprove.ts` | Approve transfer (old device) |
| `restoreDeny` | `vault/restoreDeny.ts` | Deny transfer (old device) |
| `restoreCancel` | `vault/restoreCancel.ts` | Cancel pending request |
| `restoreConfirm` | `vault/restoreConfirm.ts` | Complete restore |
| `restoreStatus` | `vault/restoreStatus.ts` | Check status |

### 7.5 Vault Lifecycle Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `initializeVault` | `vault/initializeVault.ts` | Initialize new vault instance |
| `getVaultHealth` | `vault/getVaultHealth.ts` | Get vault health status |
| `vaultReady` | `vault/vaultReady.ts` | Vault-manager reports ready |
| `updateVaultHealth` | `vault/updateVaultHealth.ts` | Vault-manager health updates |
| `deleteVaultRequest` | `vault/deleteVaultRequest.ts` | Request vault deletion |
| `deleteVaultConfirm` | `vault/deleteVaultConfirm.ts` | Confirm deletion |
| `deleteVaultCancel` | `vault/deleteVaultCancel.ts` | Cancel deletion |

### 7.6 Test Automation Handlers

| Handler | File | Purpose |
|---------|------|---------|
| `testHealth` | `test/testHealth.ts` | E2E test health check |
| `testCreateInvitation` | `test/testCreateInvitation.ts` | Create test invitation |
| `testCleanup` | `test/testCleanup.ts` | Clean up test data |

---

## 8. Data Storage

### 8.1 What's Stored Where

| Data | Location | Access |
|------|----------|--------|
| **Protean Credential (encrypted blob)** | Mobile App | User holds on device |
| **Credential decryption key** | Vault JetStream | vault-manager only |
| **NATS account keys (seed, JWT)** | Vault JetStream | vault-manager (for signing user JWTs) |
| **User secrets & datastore** | Vault JetStream | vault-manager only |
| **NATS account metadata** | DynamoDB (NatsAccounts) | Lambda (control plane, for bootstrap/restore) |
| **Enrollment sessions** | DynamoDB (EnrollmentSessions) | Lambda (control plane) |
| **Recovery requests** | DynamoDB (CredentialRecoveryRequests) | Lambda (control plane) |
| **Encrypted credential backups** | S3 | Auto-created by vault-manager after every use (when enabled) |

### 8.2 Vault JetStream Contents

The vault's embedded JetStream stores operational data (NOT the Protean Credential):

```
Vault JetStream Storage
├── credentials/
│   ├── decryption_key         # Key to decrypt user's Protean Credential
│   └── nats_account_seed      # Account seed for generating user JWTs
│
├── datastore/
│   ├── private_data           # User's personal information
│   ├── contacts               # Connection profiles
│   ├── handlers               # Installed event handlers
│   └── feed                   # Event feed for user
│
└── vault_identity/
    └── vault_nats_creds       # Vault's own NATS credentials
```

### 8.3 Removed Legacy Tables

The following tables were removed with the Nitro architecture:

| Table | Former Purpose | Replacement |
|-------|----------------|-------------|
| `Credentials` | Credential metadata | User holds encrypted blob on device |
| `CredentialKeys` | CEK keys | Decryption key in vault JetStream |
| `TransactionKeys` | UTK/LTK pairs | Simplified - no transaction keys needed |
| `LedgerAuthTokens` | LAT tokens | NATS JWT auth |

---

## 9. Security Model

### 9.1 Trust Hierarchy

```
Operator (VettID)
├── Signs Account JWTs
│
Account (per member)
├── Signs User JWTs (app, vault)
│
User (connection)
└── Connects to NATS with JWT
```

### 9.2 Security Properties

| Property | Implementation |
|----------|----------------|
| **Forward Secrecy** | Ephemeral keys for each message |
| **User-Held Credential** | Encrypted blob stays on user's device, never stored centrally |
| **Key Isolation** | Decryption key stored only in Nitro enclave's JetStream |
| **Namespace Isolation** | Each member has unique NATS account |
| **JWT Expiration** | Account: 30 days, User: 24 hours max, Bootstrap: 1 hour |
| **Rate Limiting** | Per-endpoint limits on Lambda handlers |
| **Attestation** | Verify Nitro enclave before enrollment |

### 9.3 Authentication Layers

1. **Web Portal**: Cognito JWT (member user pool)
2. **Enrollment**: Short-lived enrollment JWT
3. **NATS**: Ed25519-signed JWT (nkeys)
4. **Vault Operations**: Password-based unlock for sensitive data

---

## Appendix: Quick Reference

### Enrollment Flow Summary

1. **Web** → `POST /vault/enroll/session` → QR code
2. **App** → Scan QR → `POST /vault/enroll/authenticate` → Enrollment JWT
3. **App** → (Optional) `POST /vault/attestation/nitro` → Verify enclave
4. **App** → `POST /vault/enroll/finalize` → Bootstrap credentials
5. **App** → Connect NATS → Publish to `forVault.app.bootstrap`
6. **Vault** → Create encrypted credential blob + store decryption key in JetStream
7. **Vault** → Return encrypted credential + full NATS credentials to app
8. **App** → Store encrypted credential locally → Reconnect with full credentials → Enrolled!

### Session Flow Summary

1. **App** → Connect NATS with stored NATS credentials
2. **App** → Publish event to `OwnerSpace.{guid}.forVault.{event_type}` (include encrypted credential if needed)
3. **Vault** → Decrypt credential → Process event → Re-encrypt with **new key** (always rotates)
4. **Vault** → Publish response to `forApp.{event_type}.{id}` (include newly encrypted credential)
5. **App** → Store newly encrypted credential → Update UI
6. **Vault** → Auto-backup encrypted credential to S3 (if backups enabled)

### Restore Flow Summary

**Device Transfer (old device available):**
1. **New Device** → `POST /vault/credentials/restore/request`
2. **Old Device** → `POST /vault/credentials/restore/approve`
3. **New Device** → `POST /vault/credentials/restore/confirm` → Get credential backup + NATS bootstrap
4. **New Device** → Connect NATS → Authenticate with credential + password
5. **Vault** → Verify password → Return full NATS credentials → Restored!

**Lost Device (24-hour delay):**
1. **New Device** → `POST /vault/credentials/restore/request` {lost_device: true}
2. Wait 24 hours...
3. **New Device** → `POST /vault/credentials/restore/confirm` → Get credential backup + NATS bootstrap
4. **New Device** → Connect NATS → Authenticate with credential + password
5. **Vault** → Verify password → Return full NATS credentials → Restored!
