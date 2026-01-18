# VettID Vault Services - Development Plan

**Version:** 2.1
**Last Updated:** 2026-01-18
**Status:** Active - Updated for Nitro Enclave Architecture

---

## Executive Summary

This document outlines the development plan for the VettID Vault Services system. The architecture has evolved from the original per-user EC2 vault model to a **multi-tenant Nitro Enclave architecture** that provides hardware-backed security, improved cost efficiency, and faster vault access.

### Architecture Overview

| Component | Description |
|-----------|-------------|
| **Nitro Enclave** | Hardware-isolated environment running vault-manager processes |
| **Central NATS** | OwnerSpace/MessageSpace for app↔vault and cross-vault messaging |
| **S3 + SQLite** | Per-user encrypted SQLite databases synced to S3 |
| **Protean Credential** | User-held encrypted blob containing identity keys |

### Key Security Properties

- **VettID has no access to user vault data** - all processing happens inside attested enclaves
- **Hardware attestation** - mobile apps cryptographically verify enclave code before trusting it
- **Per-user encryption** - DEK derived from PIN + sealed material (only enclave can decrypt)
- **Two-factor vault access** - PIN unlocks vault, Password authorizes operations

---

## Current State (2026-01-17)

### Deployed Infrastructure

| Stack | Status | Purpose |
|-------|--------|---------|
| VettID-Infrastructure | ✅ Deployed | DynamoDB tables (19 tables) |
| VettIDStack | ✅ Deployed | Core infrastructure (S3, CloudFront, Cognito, API Gateway) |
| VettID-Admin | ✅ Deployed | Admin Lambda functions (40+) |
| VettID-Vault | ✅ Deployed | Vault enrollment and auth Lambda functions |
| VettID-NATS | ✅ Deployed | Central NATS cluster (OwnerSpace/MessageSpace) |
| VettID-Nitro | ✅ Deployed | Nitro Enclave infrastructure (EC2 + ASG) |

### Implementation Progress

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1: Core Enclave | ✅ Complete | Vault-manager in Nitro Enclave |
| Phase 2: Integration | ✅ Complete | NATS, S3, Lambda integration |
| Phase 3: Mobile Apps | 🟢 95% | Attestation verification working |
| Phase 4: Operations | 🟡 Partial | CDK deployed, monitoring pending |
| Phase 5: Vault Features | 🟡 In Progress | Voting system implementation |
| Phase 6: Launch | 🔴 Not Started | Production deployment |

### Open Issues

| Repo | Issue | Priority | Description |
|------|-------|----------|-------------|
| vettid-dev | #135 | Medium | NATS topic naming conventions and documentation |
| vettid-dev | #132 | Medium | Add device attestation binding to enrollment sessions |
| vettid-android | #50 | High | Vault-Based Voting: Android Implementation |
| vettid-ios | #16 | High | Vault-Based Voting: iOS Implementation |

---

## Architecture Components

### 1. Nitro Enclave Architecture

The vault system runs inside AWS Nitro Enclaves, providing hardware-isolated execution:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Nitro Enclave                                  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                      Enclave Supervisor                             │  │
│  │  • Spawns/manages vault-manager processes                           │  │
│  │  • Handles NSM/KMS operations (PIN → DEK derivation)               │  │
│  │  • Routes vsock messages to correct vault                          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│         ┌───────────────────────────────────────────────────┐           │
│         │                                                   │           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │ vault-manager   │  │ vault-manager   │  │ vault-manager   │   ...   │
│  │ (User A)        │  │ (User B)        │  │ (User C)        │         │
│  │                 │  │                 │  │                 │         │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │         │
│  │ │ SQLite DB   │ │  │ │ SQLite DB   │ │  │ │ SQLite DB   │ │         │
│  │ │ (DEK enc.)  │ │  │ │ (DEK enc.)  │ │  │ │ (DEK enc.)  │ │         │
│  │ └──────┬──────┘ │  │ └──────┬──────┘ │  │ └──────┬──────┘ │         │
│  └────────┼────────┘  └────────┼────────┘  └────────┼────────┘         │
│           └────────────────────┴────────────────────┘                   │
│                                │                                        │
│                             vsock                                       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
          ════════════════════════════════════════════════
                     Hardware Isolation Boundary
          ════════════════════════════════════════════════
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          Parent EC2 Instance                             │
│                                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ NATS Client     │  │ S3 Client       │  │ vsock Router    │          │
│  │ (encrypted      │  │ (encrypted      │  │ (msg dispatch)  │          │
│  │  msg routing)   │  │  blob I/O)      │  │                 │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘          │
│                                                                          │
│  CANNOT ACCESS: vault keys, plaintext data, session keys                │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2. Key Hierarchy

```
PIN (6-digit, entered on app open)
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DEK = KDF(NSM.Unseal(sealed_material), PIN)                            │
│  Purpose: Encrypts SQLite database                                       │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ├─── Encrypts: SQLite DB (synced to S3)
    │
    └─── Contains:
         ├── CEK (Credential Encryption Key) - X25519 keypair
         ├── UTKs (User Transaction Keys) - single-use public keys
         ├── LTKs (Ledger Transaction Keys) - private keys for UTKs
         └── identity_keypair (Ed25519) - for signing operations

Password (user-chosen, hashed with Argon2id)
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Authorizes vault operations (vote signing, sensitive actions)          │
│  Encrypted to UTK, verified inside vault-manager                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3. NATS Messaging Architecture

```
Central NATS (os.vettid.dev / ms.vettid.dev)
│
├── OwnerSpace.{member_guid}/
│   ├── forVault.>        # App → Vault: Commands
│   ├── forApp.>          # Vault → App: Responses
│   ├── eventTypes        # Handler definitions
│   └── forServices.>     # Vault → Backend: Health/status
│
├── MessageSpace.{member_guid}/
│   ├── forOwner.>        # Connections → Vault: Messages
│   ├── ownerProfile      # Public profile
│   └── call.>            # Call signaling
│
├── Control/
│   ├── global.>          # Operations for ALL enclaves
│   ├── enclave.{id}.>    # Operations for specific enclave
│   └── user.{guid}.>     # User-specific operations
│
└── Broadcast/
    ├── system.*          # System announcements
    └── security.*        # Security alerts
```

### 4. Resource Allocation

The enclave is optimized for **native Go handlers** (no WASM runtime overhead), allowing maximum resource allocation:

**Instance Type**: `c6a.2xlarge` (8 vCPUs, 16 GB RAM)

| Resource | Enclave | Parent/OS | Rationale |
|----------|---------|-----------|-----------|
| **Memory** | 12 GB (75%) | 4 GB | Native Go handlers are memory-efficient; parent only routes encrypted blobs |
| **vCPUs** | 6 (75%) | 2 | Maximum allocation; parent is I/O-bound (2 is AWS minimum) |

**Capacity Estimates** (with 12 GB enclave memory):
- ~100-150 active vaults simultaneously in memory
- ~50-100 MB per active vault-manager process
- ~5-10 MB per in-memory SQLite database

**Configuration Files**:
- `enclave/enclave.json` - Enclave build configuration
- `packer/nitro-enclave-host.pkr.hcl` - AMI build defaults
- `lib/nitro-stack.ts` - Runtime configuration in user data

**Scaling**: When memory pressure increases, the enclave supervisor evicts least-recently-used vaults to S3. Cold start latency (~500ms-2s) is acceptable for inactive users.

---

## Development Phases

### Phase 1: Core Enclave ✅ COMPLETE

**Objective**: Port vault-manager to run inside Nitro Enclave

**Completed Tasks**:
- [x] Enclave development environment setup
- [x] Minimal enclave image with vault-manager
- [x] Vsock communication layer
- [x] Sealed storage for vault DEK (KMS + NSM)
- [x] SQLite + S3 sync with DEK encryption
- [x] PCR generation and documentation
- [x] Unit tests for enclave components

**Key Files**:
- `enclave/supervisor/` - Enclave supervisor process
- `enclave/vault-manager/` - Vault-manager process
- `enclave/parent/` - Parent process (NATS, S3, vsock routing)

---

### Phase 2: Integration ✅ COMPLETE

**Objective**: Connect enclave to external systems

**Completed Tasks**:
- [x] Parent process implementation (vsock ↔ S3 ↔ NATS routing)
- [x] S3 bucket structure for vault databases
- [x] Central NATS integration (OwnerSpace/MessageSpace)
- [x] Supervisor process implementation
- [x] Vault lifecycle management
- [x] Lambda handlers updated for enclave mode
- [x] Control topic architecture (multi-tenant)
- [x] Signed control commands (Ed25519)

**Lambda Handler Updates**:
- `enrollStart.ts` - Always requests enclave attestation
- `enrollFinalize.ts` - Uses enclave-based credential creation
- `enrollNatsBootstrap.ts` - Issues NATS credentials
- `vault-stack.ts` - Removed `USE_NITRO_ENCLAVE` flag

---

### Phase 3: Mobile Apps 🟢 95% COMPLETE

**Objective**: Update iOS and Android apps to support attestation

#### iOS Implementation (90% Complete)

| Component | Status | Notes |
|-----------|--------|-------|
| CBOR parsing | ✅ | Custom RFC 7049 decoder |
| COSE_Sign1 verification | ✅ | Tag 18 parsing, signature verification |
| Certificate chain verification | ✅ | SecTrust framework |
| PCR verification | ✅ | Dynamic validation with Ed25519 signed updates |
| Enrollment integration | ✅ | Blocks on verification failure |
| NATS client | ✅ | TLS on port 443 |
| PIN setup flow | ✅ | Enclave-based DEK derivation |
| E2E testing | 🔴 | Pending |

#### Android Implementation (95% Complete)

| Component | Status | Notes |
|-----------|--------|-------|
| CBOR parsing | ✅ | Jackson CBOR 2.16.1 |
| COSE_Sign1 verification | ✅ | Bouncy Castle |
| Certificate chain verification | ✅ | Dynamic root CA validation |
| PCR verification | ✅ | Real PCR values bundled |
| Enrollment integration | ✅ | Full flow implemented |
| NATS client | ✅ | TLS on port 443 |
| PIN setup flow | ✅ | Enclave-based DEK derivation |
| Hardware attestation | ✅ | Play Integrity API |
| E2E testing | 🔴 | Pending |

**Remaining Tasks**:
- [ ] End-to-end enrollment test (Android)
- [ ] End-to-end enrollment test (iOS)
- [ ] Device attestation binding (Issue #132)

---

### Phase 4: Operations 🟡 IN PROGRESS

**Objective**: Production-ready deployment and monitoring

**Completed**:
- [x] CDK stack for enclave infrastructure (VettID-Nitro)
- [x] ASG configuration (min=1 for dev)
- [x] Control command security (Ed25519 signing)
- [x] Runbooks created (enclave-restart, enclave-update, incident-response)

**Pending**:
- [ ] CloudWatch dashboards and metrics
- [ ] Alerting for enclave health
- [ ] Auto-scaling configuration (production)
- [ ] Load testing and performance validation
- [ ] Security review

**Key Metrics to Track**:
- `ColdStartLatency` - Time to load vault from S3
- `OperationLatency` - Per-operation timing
- `ActiveVaults` - Concurrent vaults in memory
- `MemoryUsagePercent` - Enclave memory pressure
- `PINRateLimited` - Security events

---

### Phase 5: Vault Features 🟡 IN PROGRESS

**Objective**: Implement vault-based features

#### 5.1 Vault-Based Voting System

**Status**: Implementation in progress (Issues #50, #16, #136)

**Backend Tasks** (vettid-dev):
- [ ] Create KMS key for proposal signing (`vettid-proposal-signing`)
- [ ] Update Proposals table schema (add signature fields)
- [ ] Update Votes table schema (add voting_public_key, signature, vote_hash)
- [ ] Create `receiveSignedVote.ts` Lambda
- [ ] Create `publishVoteList.ts` Lambda
- [ ] Create `getVoteMerkleProof.ts` Lambda
- [ ] Update `createProposal.ts` with KMS signing
- [ ] S3 bucket for published vote lists

**Vault-Manager Tasks**:
- [ ] Add `cast_vote` operation handler
- [ ] Implement voting keypair derivation (HKDF from identity + proposal_id)
- [ ] Add subscription verification
- [ ] Add proposal signature verification
- [ ] Return vote receipt with nonce

**Mobile App Tasks** (Android #50, iOS #16):
- [ ] Proposals list screen
- [ ] VettID signature verification on proposals
- [ ] Vote casting flow with password challenge
- [ ] Vote receipt storage
- [ ] "My Votes" screen
- [ ] Merkle proof verification

#### 5.2 Connections & Messaging

**Status**: Framework in place, handlers needed

**Tasks**:
- [ ] Connection invitation handler (vault-manager)
- [ ] Connection acceptance handler
- [ ] Profile publishing handler
- [ ] Message send/receive handlers
- [ ] Key exchange for E2EE calls (X25519 + HKDF)

#### 5.3 Credential Backup & Recovery

**Status**: Architecture defined, implementation pending

**Tasks**:
- [ ] `uploadCredentialBackup.ts` Lambda
- [ ] `downloadCredentialBackup.ts` Lambda
- [ ] 24-hour time-delay recovery mechanism
- [ ] Mobile UI for backup/restore

---

### Phase 6: Launch 🔴 NOT STARTED

**Objective**: Production deployment and user onboarding

**Prerequisites**:
- Phase 3 E2E testing complete
- Phase 4 monitoring configured
- Phase 5.1 voting system complete

**Tasks**:
- [ ] Production deployment with full monitoring
- [ ] Beta user onboarding (invite-only)
- [ ] Support documentation
- [ ] On-call procedures
- [ ] Performance monitoring and tuning
- [ ] General availability rollout

---

## Repository Structure

| Repository | Purpose |
|------------|---------|
| `vettid-dev` | Backend infrastructure (CDK), Lambda handlers, enclave code (native Go handlers) |
| `vettid-android` | Android mobile app |
| `vettid-ios` | iOS mobile app |
| `vettid.org` | Marketing website |
| `vettid-test-harness` | End-to-end testing infrastructure |

### Key Directories (vettid-dev)

```
vettid-dev/
├── cdk/
│   ├── lib/                    # CDK stack definitions
│   │   ├── infrastructure-stack.ts
│   │   ├── vettid-stack.ts
│   │   ├── admin-management-stack.ts
│   │   ├── vault-stack.ts
│   │   ├── nats-stack.ts
│   │   ├── nitro-stack.ts
│   │   ├── monitoring-stack.ts
│   │   ├── extensibility-monitoring-stack.ts
│   │   └── business-governance-stack.ts
│   ├── lambda/
│   │   ├── handlers/           # Lambda functions
│   │   │   ├── admin/          # Admin operations
│   │   │   ├── attestation/    # Device attestation verification
│   │   │   ├── auth/           # Authentication challenges
│   │   │   ├── backup/         # Credential backup/restore
│   │   │   ├── calls/          # TURN credentials
│   │   │   ├── connections/    # Connection management
│   │   │   ├── member/         # Member operations
│   │   │   ├── nats/           # NATS cluster management
│   │   │   ├── profile/        # Profile operations
│   │   │   ├── public/         # Public registration endpoints
│   │   │   ├── registry/       # Handler registry
│   │   │   ├── scheduled/      # Scheduled tasks
│   │   │   ├── streams/        # DynamoDB stream handlers
│   │   │   └── vault/          # Vault operations
│   │   └── common/             # Shared utilities
│   └── docs/                   # CDK documentation
├── enclave/
│   ├── supervisor/             # Enclave supervisor (NSM/KMS, vault lifecycle)
│   ├── vault-manager/          # Vault-manager process (native Go handlers)
│   │   ├── authenticate.go     # Authentication logic
│   │   ├── backup.go           # Backup operations
│   │   ├── bootstrap_handler.go # Initial vault bootstrap
│   │   ├── calls.go            # E2EE call signaling
│   │   ├── cek.go              # Credential encryption keys
│   │   ├── connections.go      # Connection management
│   │   ├── credential.go       # Credential operations
│   │   ├── messaging.go        # Encrypted messaging
│   │   ├── notifications.go    # Push notifications
│   │   ├── pin_handler.go      # PIN verification
│   │   ├── profile.go          # Profile management
│   │   ├── secrets.go          # Secrets storage
│   │   └── vote_handler.go     # Vault-signed voting
│   └── parent/                 # Parent process (NATS, S3, vsock routing)
└── docs/
    ├── NITRO-ENCLAVE-VAULT-ARCHITECTURE.md
    ├── NATS-MESSAGING-ARCHITECTURE.md
    └── vault-voting-design.md
```

---

## Technology Stack

### Backend
- **Infrastructure**: AWS CDK (TypeScript)
- **Compute**: AWS Nitro Enclaves (enclave), Lambda (API handlers)
- **Database**: DynamoDB (metadata), SQLite (vault data in enclave)
- **Storage**: S3 (encrypted vault databases, backups)
- **Messaging**: NATS with JWT authentication
- **Crypto**: X25519, ChaCha20-Poly1305, Ed25519, Argon2id

### Mobile
- **Android**: Kotlin, Jetpack Compose, Bouncy Castle (crypto)
- **iOS**: Swift, SwiftUI, CryptoKit
- **Storage**: EncryptedSharedPreferences (Android), Keychain (iOS)

### Enclave
- **Language**: Go (native handlers compiled into enclave image)
- **Database**: SQLite (in-memory, DEK-encrypted)
- **Communication**: vsock (binary MessagePack protocol)
- **Handlers**: Native Go (VoteHandler, CallHandler, SecretsHandler, MessagingHandler, ConnectionsHandler, ProfileHandler, CredentialHandler, PINHandler, BootstrapHandler, NotificationsHandler, BackupHandler)

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| VettID reads vault data | Hardware attestation; keys only in enclave |
| Compromised mobile device | Keys in vault, not on device; PIN + Password 2FA |
| Forged attestation | AWS Nitro PKI verification; PCR matching |
| Replay attacks | Event ID uniqueness; timestamp validation |
| PIN brute force | Rate limiting (3 attempts, 1-hour lockout) |
| Credential theft | CEK rotation on every operation |

### Security Implementations

- ✅ NATS message replay prevention (event_id tracking)
- ✅ Token revocation workflow
- ✅ Parent credential rotation (30-day lifetime)
- ✅ Multi-tenant control topic architecture
- ✅ Signed control commands (Ed25519)
- ✅ Device attestation (Android Play Integrity, iOS App Attest)
- ✅ Rate limiting on NATS bootstrap

---

## Cost Analysis

### Per-User Cost Comparison

| Model | 100 Users | 500 Users | 1000 Users |
|-------|-----------|-----------|------------|
| Per-User EC2 (old) | $600/mo | $3,000/mo | $6,000/mo |
| Multi-Tenant Nitro | $120/mo | $240/mo | $400/mo |
| **Savings** | **80%** | **92%** | **93%** |

### Nitro Infrastructure Cost Breakdown

| Component | Dev/Testing | Production |
|-----------|-------------|------------|
| EC2 (enclave host) | ~$60/mo (1x c5.xlarge) | ~$180/mo (3x c5.xlarge) |
| S3 storage | ~$0.10/user/mo | ~$0.10/user/mo |
| NATS cluster | ~$40/mo (single node) | ~$120/mo (3-node) |
| Data transfer | ~$10/mo | ~$30/mo |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-06 | Initial draft (per-user EC2 model) |
| 2.0 | 2026-01-17 | Complete rewrite for Nitro Enclave architecture. Removed per-user EC2 provisioning, Ledger (RDS), WASM Service Registry. Added multi-tenant enclave, SQLite+S3 storage, updated NATS architecture, vault-based voting phases. Reflects current implementation status. All vault operations use **native Go handlers** compiled into enclave image. Optimized enclave resource allocation to **12 GB / 6 vCPUs** (75% of c6a.2xlarge) - maximum allocation since parent is I/O-bound and only needs 2 vCPUs (AWS minimum). |
| 2.1 | 2026-01-18 | Updated repository structure (removed vettid-handlers). Expanded Lambda handler directory listing to reflect actual structure. Updated vault-manager handler file listing. Removed references to user-extensible WASM handlers. |

---

*This plan is actively maintained. See open GitHub issues for current work items.*
