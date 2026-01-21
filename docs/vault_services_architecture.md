# VettID Vault Services Architecture

> **Implementation Note (2026-01-21):** The production implementation uses **native Go handlers** in the vault-manager rather than the WASM-based event handler system described in Section 10. All vault operations are implemented directly in Go within the Nitro Enclave. References to WASM handlers reflect the original design proposal.

## Document Purpose

This document describes the Vault Services system - a secure personal data vault infrastructure that enables VettID members to deploy, manage, and interact with their own private vault instance. Vault Services builds upon the Protean Credential System for authentication and extends it with dedicated vault enrollment.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Component Architecture](#2-component-architecture)
3. [Member Journey](#3-member-journey)
4. [Protean Credential Integration](#4-protean-credential-integration)
5. [Vault Deployment](#5-vault-deployment)
6. [Vault Enrollment](#6-vault-enrollment)
7. [Namespace Architecture](#7-namespace-architecture)
8. [Connection Flow](#8-connection-flow)
9. [Data Storage Model](#9-data-storage-model)
10. [Event Handler System](#10-event-handler-system)
11. [Home Appliance Variant](#11-home-appliance-variant)
12. [Backup System](#12-backup-system)
13. [Vault Lifecycle](#13-vault-lifecycle)
14. [Security Model](#14-security-model)
15. [Service Registry Architecture](#15-service-registry-architecture)
16. [NATS Authentication Model](#16-nats-authentication-model)
17. [Backup Key Rotation](#17-backup-key-rotation)
18. [Connection Revocation](#18-connection-revocation)
19. [Open Questions](#19-open-questions)

---

## 1. System Overview

### What is a Personal Vault?

A personal vault is a secure virtual machine (EC2) or home appliance that:

- Stores the member's personal information, sensitive data, and secrets
- Performs actions using the member's data at the member's direction
- Communicates exclusively with the member's mobile app via secure namespaces
- Creates encrypted backups that only the member can decrypt

### Relationship to VettID

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           VettID Ecosystem                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐                                                  │
│  │   VettID Web     │  User/member registration, subscription mgmt    │
│  │   (Frontend)     ├──────────────────────┐                           │
│  │  vettid.dev      │                      │ Invite endpoint           │
│  └──────────────────┘                      │ (initiate credential      │
│                                            │  enrollment)              │
│                                            ▼                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Vault Services API                            │  │
│  │                    vault.vettid.dev                              │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │  Ledger (Secure RDS) - Protean Credential Management       │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│          ▲                                                              │
│          │                                                              │
│          │  ┌──────────────────┐    ┌──────────────────┐               │
│          │  │   OwnerSpace     │◄──►│  Member's Vault  │               │
│          │  │  (os.vettid.dev) │    │   (EC2/Home)     │               │
│          │  └──────────────────┘    └────────┬─────────┘               │
│          │            ▲                      │                         │
│          │            │                      │                         │
│          │            │                      ▼                         │
│          │            │             ┌──────────────────┐               │
│          │            │             │   MessageSpace   │               │
│          │            │             │  (ms.vettid.dev) │               │
│          │            │             └────────┬─────────┘               │
│          │            │                      │                         │
│          │            │        ┌─────────────┴─────────────┐           │
│          │            │        │                           │           │
│          │            │        ▼                           ▼           │
│          │            │  ┌────────────────┐    ┌────────────────────┐  │
│          │            │  │  Connections   │    │  Service Registry  │  │
│          │            │  │  (users, apps, │    │  (handler catalog, │  │
│          │            │  │   services)    │    │   signed packages) │  │
│          │            │  └────────────────┘    └────────────────────┘  │
│          │            │                                                │
│          ▼            ▼                                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      VettID Mobile App                           │  │
│  │  • Vault Services API (enrollment, lifecycle)                    │  │
│  │  • OwnerSpace (vault commands, events)                           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Service Registry: A special, mandatory connection that provides the vault with its 
event handler catalog and signed WASM packages. Each vault connects to exactly one 
Service Registry. Unlike regular connections, the Service Registry is established 
automatically during vault deployment.
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Vault Services Credential** | Protean credential for vault.vettid.dev API access; contains vault access key + backup decryption key |
| **Vault Credential** | Separate Protean credential for direct vault communication via NATS |
| **OwnerSpace** | NATS namespace for app↔vault communication (includes control topic for system commands) |
| **MessageSpace** | NATS namespace for receiving messages from connections and Service Registry |
| **Service Registry** | Special mandatory connection providing handler catalog, service catalog, and signed WASM packages |
| **Vault Manager** | Service running on vault that processes events |

---

## 2. Component Architecture

### 2.1 VettID Web Application (vettid.dev)

**Purpose:** Frontend portal for user/member management and subscription activation.

**Responsibilities:**
- User registration
- Member conversion
- Subscription management
- Vault services enrollment initiation (calls Vault Services invite endpoint, displays QR code)
- Status display (read-only after vault deployed)

### 2.2 VettID Admin Portal (admin.vettid.dev)

**Purpose:** Internal administration interface for VettID staff.

**Responsibilities:**
- Service Registry management (handler and service catalogs)
- Member support and troubleshooting
- System monitoring and operations

**Access Control:**

| Role | Capabilities |
|------|--------------|
| Full Admin | Full registry management, system operations, member support |
| Limited Admin | Member support, read-only system access |
| Support | Member lookup, read-only access |

See Section 15 (Registry Administration) for detailed registry management capabilities.

### 2.3 Vault Services API (vault.vettid.dev)

**Purpose:** Orchestration layer for vault lifecycle management.

**Responsibilities:**
- Request routing and endpoint assignment
- Token generation for endpoint access
- LAT verification
- Vault provisioning coordination
- Backup storage management (S3)
- System commands to vault (via OwnerSpace control topic)

**Communication with Vault:**
- All vault commands sent via OwnerSpace control topic
- No direct SSH or network access to vault instances
- Operator-signed JWT grants write-only access to control topic

**Key Endpoints:**

| Endpoint | Called By | Purpose |
|----------|-----------|---------|
| Invite | VettID Web | Initiate credential enrollment, returns QR code data |
| Request | Mobile App | Route requests, assign handlers, generate tokens |
| Lifecycle | Mobile App | Start, stop, terminate vault operations |
| Appliance Backup | Home Appliance | Upload/download encrypted backups to/from S3 |
| Credential Backup | Mobile App | Upload/download encrypted credentials (if enabled) |

**API Versioning Strategy:**

The Vault Services API is designed for the VettID mobile app (not third-party developers):

| Principle | Approach |
|-----------|----------|
| New features | Add new endpoints alongside existing ones |
| Breaking changes | Prompt user to update app before proceeding |
| Deprecation | Retire old endpoints when app usage drops off |
| Backward compatibility | Not guaranteed; app updates are expected |

Members are expected to keep their app updated. The app prompts for updates when new versions are available, and outdated apps may be blocked from accessing new API features.

### 2.4 Ledger (Internal RDS)

**Purpose:** Secure storage for Protean Credential system data (internal to Vault Services).

**Stores:**
- User data (e.g., user GUID)
- Keys and tokens (CEK, TK, LAT)
- Device information

**Note:** The Ledger does not store encrypted credential blobs—those are always held by the member's mobile app. The Ledger is a secure RDS deployment accessible only by Vault Services API. It has no external endpoint. All cryptographic operations (decryption, password verification, device attestation) are performed by Vault Services Lambda functions.

### 2.5 Member's Vault (EC2 or Home Appliance)

**Purpose:** Secure personal data store and action executor.

**Components:**
- **Local NATS Server** - Datastore and internal messaging
- **Vault Manager Service** - Event processor (all communication with users, apps, and services is performed via events through MessageSpaces)
- **Encrypted Storage** - Member's personal data and secrets

**Communication:** The vault communicates with the mobile app exclusively via events through OwnerSpace.

**Health Monitoring:**

The Vault Manager performs periodic health checks and reports status to the member:

| Check | Frequency | Action on Failure |
|-------|-----------|-------------------|
| Memory usage | Every 5 minutes | Alert if >80% used |
| Disk usage | Every 5 minutes | Alert if >80% used |
| CPU usage | Every 5 minutes | Alert if sustained >90% |
| Zombie processes | Every 5 minutes | Clean up failed handler processes |
| NATS connectivity | Every 1 minute | Queue operations, reconnect when available |
| Time synchronization | Every hour | Alert if drift detected |

Health status is visible in the mobile app's vault status screen.

**Time Synchronization:**

Accurate time is critical for TTL-based authentication. Vaults maintain time as follows:
- All vault operations use GMT/UTC
- Time synchronized via NTP from trusted source (AWS time service)
- Vault periodically verifies time consistency with mobile app
- Member notified if significant drift detected between vault and app

**Resource Limits:**

Since vaults serve a single member, strict limits are not enforced. Resources are managed dynamically:

| Resource | Expected Range | When Exceeded |
|----------|----------------|---------------|
| Datastore size | 10-20 GB typical | Member prompted to purge old feed events or archive |
| Connections | No hard limit | Limited by available resources |
| Installed handlers | No hard limit | Limited by available resources |
| Concurrent handler executions | 1-3 typical | Queued if resources constrained |

### 2.6 VettID Mobile App

**Purpose:** Member's primary interface for all vault operations.

**Responsibilities:**
- Vault Services enrollment (Protean credential creation)
- Vault enrollment (separate Protean credential)
- Event submission to vault
- Response handling from vault
- Backup key management
- Credential version management (see below)

**Single Device Policy:**

VettID supports a single mobile device per member by design. If a member gets a new device, they restore from backup (see Device Loss/Recovery below). Members may also use their device's native backup solutions (iCloud, Google Backup) to preserve credentials.

**Credential Versioning:**

The mobile app maintains multiple versions of credentials to ensure backup compatibility:

| Credential | Versions | Purpose |
|------------|----------|---------|
| Vault Services Credential | 1 | API authentication, backup decryption |
| Vault Credential | 4 (1 active + 3 backup) | Vault communication, backup compatibility |

When a new backup is created, the app:
1. Saves the current Vault Credential as the new "Backup 1" version
2. Shifts existing backup versions (1→2, 2→3)
3. Discards the oldest backup credential (former Backup 3)

**Device Loss / Recovery:**

If a member loses or breaks their device, they have two recovery options:

1. **Device Backup Restore** - Use native device backup (iCloud, Google Backup) to restore credentials to new device

2. **Credential Backup Service** - If enabled (see Section 2.7), member can recover credentials via VettID web portal:
   - Log into account on vettid.dev
   - Navigate to Credential Backup Services
   - Provide recovery phrase
   - Scan displayed QR code from mobile app on new device
   - App downloads credential versions from Vault Services endpoint
   - Resume normal vault operations

**Offline Operation:**

When the mobile app has no network connectivity:

| Capability | Offline Behavior |
|------------|------------------|
| View feed | Cached feed content available (read-only) |
| View contacts | Cached contact list available (read-only) |
| View secrets | Not available (requires vault connection) |
| Submit events | Not available (queued operations not supported) |
| New connections | Not available |

The app displays offline status and prompts member when connectivity is restored.

**App Distribution:**

The VettID mobile app is available through multiple channels:

| Platform | Primary Channel | Alternative Channels |
|----------|-----------------|----------------------|
| Android | Google Play Store | F-Droid, GitHub releases (APK) |
| iOS | Apple App Store | Build from source (GitHub) |

Source code is published on GitHub, allowing members to:
- Audit the app code
- Build their own version if app store access is unavailable
- Verify app store version matches published source

### 2.7 Credential Backup Service

**Purpose:** Optional cloud backup of member credentials for device loss recovery.

**Activation:**
- Member enables via account page on vettid.dev
- Member creates a recovery phrase (see requirements below)
- Service activated after confirmation

**Recovery Phrase Requirements:**

| Requirement | Specification |
|-------------|---------------|
| Format | BIP-39 style mnemonic (12 or 24 words from standard wordlist) |
| Generation | App generates phrase; member may regenerate until satisfied |
| Storage | Member must record phrase externally (not stored on device) |
| Verification | Member must re-enter phrase to confirm understanding |
| Key Derivation | Argon2id with aggressive parameters (memory: 64MB, iterations: 3, parallelism: 4) |

**How It Works:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Credential Backup Service                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Backup (Automatic when enabled):                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. App derives encryption key from phrase (Argon2id)         │  │
│  │  2. App encrypts credentials with derived key                 │  │
│  │  3. App uploads to Vault Services credential backup endpoint  │  │
│  │  4. Only required versions retained:                          │  │
│  │     • Vault Services Credential (1 version)                   │  │
│  │     • Vault Credential (4 versions)                           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Recovery (Device loss):                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Member logs into vettid.dev on any browser                │  │
│  │  2. Navigates to Credential Backup Services                   │  │
│  │  3. Provides recovery phrase                                  │  │
│  │  4. Portal displays QR code (contains download endpoint)      │  │
│  │  5. Member scans QR from mobile app on new device             │  │
│  │  6. App derives key from phrase, downloads and decrypts       │  │
│  │  7. Member can now access vault normally                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Vault Services Endpoints:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/credentials/backup` | POST | Upload encrypted credentials |
| `/v1/credentials/recover` | GET | Download encrypted credentials (via QR token) |

**Security Notes:**
- Credentials encrypted client-side with Argon2id-derived key before upload
- Vault Services cannot decrypt stored credentials (no access to phrase)
- Recovery phrase never transmitted to server
- QR code contains time-limited, single-use download token
- Recovery attempts are rate-limited (max 5 attempts per hour)

**Estate / Inheritance Access:**

VettID has no mechanism to grant access to a deceased member's vault. Members who wish to provide estate access should:
- Share recovery phrase with trusted person or include in estate documents
- Provide account credentials (email, password) to estate executor
- Consider including app unlock PIN/biometric enrollment instructions

This is consistent with VettID's security model where only the member can access their data.

---

## 3. Member Journey

### Phase 1: Onboarding

```
Step 1: Register as User
        └─► Create account on vettid.dev
        └─► Email verification
        └─► Basic profile setup

Step 2: Become a Member
        └─► Accept membership terms
        └─► Member status activated

Step 3: Activate Subscription
        └─► Select subscription tier
        └─► Payment processing
        └─► Subscription active → Vault Services eligible
```

### Phase 2: Vault Services Enrollment

```
Step 4: Enroll in Vault Services
        └─► User clicks "Enroll in Vault Services" in web portal
        └─► Web app calls Vault Services invite endpoint
        └─► Web app displays QR code with enrollment invitation
        └─► User scans QR with VettID mobile app
        └─► Mobile app completes Protean credential enrollment with Vault Services
        └─► Credential created containing:
            • Vault access key (for vault authentication)
            • Backup decryption private key
        └─► Corresponding backup encryption public key stored for vault use
```

### Phase 3: Vault Deployment

```
Step 5: Request Vault Deployment
        └─► Member uses mobile app to call vault.vettid.dev
        └─► Request API authenticates via Protean credential flow
        └─► If authenticated, deployment endpoint assigned
        └─► Vault provisioned (EC2 spun up or home appliance configured)
```

### Phase 4: Vault Initialization

```
Step 6: Initialize Vault
        └─► Mobile app prompts member to initialize vault
        └─► Key exchange between app and vault over TLS
        └─► Vault enrollment (separate Protean credential with vault)
        └─► Vault Manager starts and connects to OwnerSpace/MessageSpace
        └─► Connection credentials returned to mobile app
```

### Phase 5: Configuration

```
Step 7: Configure Personal Data
        └─► Add private data (address, phone, credit cards, certificates)
        └─► Data stored in local NATS datastore
        
Step 8: Configure Secrets
        └─► Add high-value secrets (Bitcoin keys, SSN, etc.)
        └─► Secrets stored in vault credential (metadata in NATS)

Step 9: Create Public Profile
        └─► Configure shareable profile (name, email, optional fields)
        └─► Profile published to MessageSpace ownerProfile topic

Step 10: Enable Event Handlers
        └─► Browse available handlers from service registry
        └─► Select and enable desired handlers
        └─► Handler definitions stored in local NATS datastore
        └─► Handler definitions published to OwnerSpace eventTypes topic
            (allows mobile app to know what events are supported)
```

### Phase 6: Operations

```
Step 11: Use Vault
        └─► Mobile app displays available event handlers
        └─► Member triggers events (properly formatted)
        └─► Events sent via OwnerSpace forVault topic
        └─► Vault Manager processes and invokes handler
        └─► Response returned via OwnerSpace forApp topic

Step 12: Automated Backups
        └─► Vault Manager periodically backs up NATS datastore
        └─► Backup encrypted with member's backup public key
        └─► Encrypted backup stored in member's private S3 directory
```

---

## 4. Protean Credential Integration

### Two Distinct Credentials

The system uses **two separate Protean credentials** per member:

#### Credential 1: Vault Services Credential

| Attribute | Value |
|-----------|-------|
| **Issuer** | Vault Services (via internal Ledger) |
| **Purpose** | Authenticate to Vault Services API |
| **Created** | During vault services enrollment (Step 4) |
| **Contains** | Vault access key, Backup decryption private key |

#### Credential 2: Vault Credential

| Attribute | Value |
|-----------|-------|
| **Issuer** | Member's Vault (local NATS) |
| **Purpose** | Authenticate directly to personal vault |
| **Created** | During vault initialization (Step 6) |
| **Contains** | NATS connection credentials, OwnerSpace keys |
| **Versions Stored** | 4 (1 active + 3 backup versions for restore compatibility) |

### Authentication Flow for Vault Services API

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│ Mobile App  │         │ Vault Svc   │         │   Ledger    │
│             │         │    API      │         │   (RDS)     │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │  1. Request action    │                       │
       ├──────────────────────►│                       │
       │                       │                       │
       │                       │  2. Validate request  │
       │                       │  3. Get LAT, assign   │
       │                       │     endpoint          │
       │                       ├──────────────────────►│
       │                       │◄──────────────────────┤
       │                       │                       │
       │  4. Return:           │                       │
       │  • Token              │                       │
       │  • Endpoint           │                       │
       │  • Current LAT        │                       │
       │◄──────────────────────┤                       │
       │                       │                       │
       │  5. Verify LAT        │                       │
       │  (local check)        │                       │
       │                       │                       │
       │  6. Full Protean Auth Flow:                   │
       │  ┌────────────────────────────────────────┐   │
       │  │ a. App sends encrypted blob + password │   │
       │  │ b. API decrypts blob with password     │   │
       │  │ c. API verifies device attestation     │   │
       │  │ d. API prompts user for password       │   │
       │  │    via app                             │   │
       │  │ e. User provides password in app,      │   │
       │  │    gets hashed and returned to API     │   │
       │  │ f. API verifies hash matches           │   │
       │  │    credential                          │   │
       │  │ g. If match, collect required data     │   │
       │  │    from credential for step 7          │   │
       │  │ h. API rotates CEK/TK                  │   │
       │  │ i. API returns new encrypted blob      │   │
       │  │ j. App stores updated blob locally     │   │
       │  └────────────────────────────────────────┘   │
       │                       │                       │
       │  7. Execute action    │                       │
       │◄──────────────────────┤                       │
       │                       │                       │
```

---

## 5. Vault Deployment

### Deployment Process

When a member requests vault deployment:

1. **Request Received** at vault.vettid.dev
2. **Authentication** via Protean credential flow
3. **Provisioning** begins:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Vault Deployment Process                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Spin up EC2 instance                                           │
│     └─► Instance ID: member's user GUID                            │
│     └─► AMI: Secure hardened image                                 │
│     └─► No direct access (no SSH, no passwords)                    │
│                                                                     │
│  2. Assign OwnerSpace namespace                                    │
│     └─► forVault topic (app → vault)                               │
│     └─► forApp topic (vault → app)                                 │
│     └─► eventTypes topic (handler definitions)                     │
│     └─► control topic (Vault Services → vault)                     │
│                                                                     │
│  3. Assign MessageSpace namespace                                  │
│     └─► forOwner topic (inbound connection messages)               │
│     └─► ownerProfile topic (member's public profile)               │
│                                                                     │
│  4. Start local NATS server                                        │
│     └─► Acts as datastore for member's vault                       │
│     └─► Stores OwnerSpace/MessageSpace credentials                 │
│     └─► Records member's basic info (name, email)                  │
│                                                                     │
│  5. Establish Service Registry connection                          │
│     └─► Auto-generate registry connection invitation               │
│     └─► Store registry public key for package verification         │
│     └─► Vault can now download signed handler packages             │
│                                                                     │
│  6. Start Vault Manager service                                    │
│     └─► Connects to OwnerSpace (watch for app events + control)    │
│     └─► Connects to MessageSpace (listen for connections)          │
│                                                                     │
│  7. Generate app credentials                                       │
│     └─► Write access to OwnerSpace forVault topic                  │
│     └─► Read access to OwnerSpace forApp topic                     │
│                                                                     │
│  8. Return connection details                                      │
│     └─► Vault connection info stored in member's credential        │
│     └─► Details sent to mobile app via deployment endpoint         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Instance Configuration

| Setting | Value |
|---------|-------|
| Instance Type | t4g.nano (or home appliance) |
| Access Method | No direct access (control topic only) |
| Network | Security group allows NATS egress + handler-specific egress (see below) |
| Storage | EBS encrypted with key from member's Vault Services credential |
| Memory | Graviton2 256-bit DRAM encryption |

**Network Egress Model:**

| Egress Type | Description |
|-------------|-------------|
| NATS (baseline) | Always allowed for OwnerSpace/MessageSpace communication |
| Handler-specific | Added when handler is installed based on manifest requirements |

Event handlers declare their egress requirements in their manifest (e.g., a BTC handler may require access to blockchain APIs). When a handler is installed, the Vault Manager updates the instance's security group to allow the specified egress destinations. When a handler is removed, its egress rules are also removed.

### Data Residency

**Current State:**

All cloud vaults are hosted in the United States on AWS infrastructure.

| Component | Location |
|-----------|----------|
| Cloud Vaults (EC2) | AWS US regions |
| Backups (S3) | AWS US regions |
| Central NATS | AWS US regions |
| Vault Services API | AWS US regions |

**Future Considerations:**

| Consideration | Status |
|---------------|--------|
| Additional AWS regions | Planned for production |
| Alternative cloud providers | Under evaluation |
| Data residency options | To be explored for regulatory requirements |
| Home appliances | Data remains in member's physical location |

Members requiring specific data residency may use the home appliance option, which keeps all data at the member's location.

---

## 6. Vault Enrollment

### Purpose

After deployment, the member must enroll with their vault directly. This creates a **second Protean credential** specifically for vault communication.

### Enrollment Flow

```
┌─────────────┐                              ┌─────────────┐
│ Mobile App  │                              │   Vault     │
│             │                              │  (via NATS) │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │  1. Initiate enrollment                    │
       │  (user agrees to initialize)               │
       │                                            │
       │  2. Key exchange over TLS                  │
       │◄──────────────────────────────────────────►│
       │                                            │
       │  3. All subsequent data encrypted          │
       │  with exchanged keys + TLS                 │
       │                                            │
       │  4. Protean credential enrollment          │
       │  (same as vault services enrollment)       │
       │◄──────────────────────────────────────────►│
       │                                            │
       │  5. Vault stores keys/tokens in            │
       │  local NATS                                │
       │                                            │
       │  6. Enrollment complete                    │
       │  App has vault credential                  │
       │                                            │
```

### Security Properties

- **Double encryption:** Data encrypted with exchanged keys, delivered over TLS
- **Key exchange:** Performed before any sensitive data transmitted
- **Credential isolation:** Vault credential separate from Vault Services credential
- **Local storage:** Vault uses local NATS for credential data storage

---

## 7. Namespace Architecture

### Dual NATS Architecture

The system uses **two distinct NATS deployments**:

1. **Local NATS (on vault)** - Private datastore for member data
2. **Central NATS (os.vettid.dev / ms.vettid.dev)** - Cross-vault communication

### 7.1 Local NATS Server

Each vault runs its own NATS server with JetStream enabled.

**Configuration:**
- Binds to `localhost` only (not exposed externally)
- JetStream enabled for persistent storage
- Only the Vault Manager service interacts with it

**Purpose:**
- Persistent datastore for member's private data
- Event archiving
- Contact list cache
- Handler registration
- Credential/key storage for vault operations

**Topic Structure:**
```
local.datastore
├── private_data        Member's personal information
├── secrets_metadata    Metadata for secrets (actual secrets in credential)
├── contacts            Cached connection profiles
├── revoked_connections Minimal identifiers for revoked connections (for history context)
├── handlers            Registered event handler definitions
├── handler_data        Handler-specific persistent data (e.g., UTXO details, transaction history)
├── feed                Handled events shown to user in app (can be deleted or archived)
└── archived_events     Historical event log (events archived from feed)

local.credentials
├── vault_identity    Vault's credential for central NATS
├── connection_keys   Per-connection encryption keys (by keyID)
└── member_keypair    Member's general-purpose public/private key
```

### 7.2 Central Namespace Services

OwnerSpace and MessageSpace are **centrally hosted**:

| Service | URL | Purpose |
|---------|-----|---------|
| OwnerSpace | `os.vettid.dev` | App ↔ Vault communication |
| MessageSpace | `ms.vettid.dev` | Connection messaging |

### 7.3 Vault Identity & Token Generation

Each vault has an **identity credential** that allows it to:
- Control its assigned OwnerSpace namespace
- Control its assigned MessageSpace namespace
- Generate tokens granting read or write access to specific topics

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Vault Identity Model                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Vault Identity Credential (stored in local NATS)                  │
│  ├── Allows vault to authenticate to os.vettid.dev                 │
│  ├── Allows vault to authenticate to ms.vettid.dev                 │
│  ├── Can generate tokens for:                                      │
│  │   ├── Mobile app (read/write to OwnerSpace topics)              │
│  │   └── Connections (read profile, write messages)                │
│  └── Namespace control (manage topics, permissions)                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.4 OwnerSpace Namespace (os.vettid.dev)

**Purpose:** Secure communication channel between member's app, their vault, and Vault Services.

```
OwnerSpace.{member_guid}
├── forVault     (App → Vault)           Member sends commands/events
├── forApp       (Vault → App)           Vault sends responses/notifications  
├── eventTypes   (Read-only)             Available event handler definitions
└── control      (Vault Services → Vault) System commands from Vault Services
```

**Access Control:**

| Actor | forVault | forApp | eventTypes | control |
|-------|----------|--------|------------|---------|
| Mobile App | Write | Read | Read | - |
| Vault Manager | Read | Write | Write | Read |
| Vault Services | - | - | - | Write |

**Token Generation:**
- Vault generates time-limited tokens for mobile app
- Tokens scoped to specific read/write permissions
- Refreshed as part of normal authentication flow

### 7.4.1 Control Topic

The control topic enables Vault Services Lambda functions to execute system commands on the vault on behalf of the member.

**Authorization Model:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Control Topic Authorization                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  NATS Trust Hierarchy:                                             │
│                                                                     │
│  Operator (VettID)                                                 │
│  └─► Holds operator signing key                                    │
│  └─► Can issue limited JWTs for system access                      │
│                                                                     │
│      ├── Account: OwnerSpace.{member_guid}                         │
│      │   └─► Member's vault holds Account NKey                     │
│      │   └─► Issues JWTs for mobile app (forVault, forApp)         │
│      │                                                              │
│      └─► Operator issues JWT for control topic only                │
│          └─► Used by Vault Services Lambda                         │
│          └─► Write-only to control topic                           │
│          └─► Cannot read forApp or write forVault                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Security Properties:**
- Vault Services can only write to control topic (cannot read member data)
- Member cannot spoof system commands (operator-signed JWT required)
- All control commands auditable through NATS

**System Commands:**

| Command | Description |
|---------|-------------|
| `prepare_backup` | Coalesce datastore, prepare for backup |
| `execute_backup` | Perform backup and upload to S3 |
| `update_handler` | Download and install new handler version |
| `rotate_namespace_keys` | Rotate NATS access tokens |
| `health_check` | Report vault status |
| `shutdown` | Graceful shutdown before stop |

**Example Command Flow (Stop Vault):**

```
1. Member requests "Stop Vault" in mobile app

2. Mobile app calls Vault Services API
   └─► Authenticates with Vault Services credential

3. Vault Services Lambda:
   └─► Obtains control topic JWT (operator-signed)
   └─► Writes "prepare_backup" command to control topic
   └─► Waits for acknowledgment

4. Vault Manager:
   └─► Receives command on control topic
   └─► Executes backup preparation
   └─► Writes acknowledgment (via separate response mechanism)

5. Vault Services Lambda:
   └─► Receives acknowledgment
   └─► Proceeds with backup upload coordination
   └─► Terminates EC2 instance
```

### 7.5 MessageSpace Namespace (ms.vettid.dev)

**Purpose:** Receive messages from connections and publish profile.

```
MessageSpace.{member_guid}
├── forOwner      (Connections → Vault)   Inbound messages from connections
└── ownerProfile  (Vault → Public)        Member's public profile (JSON)
```

**Access Control:**

| Actor | forOwner | ownerProfile |
|-------|----------|--------------|
| Vault Manager | Read | Write |
| Connections (with token) | Write | Read |

### 7.6 Profile Structure

Member profiles **must include a public key** for general-purpose encryption (private key stored in local NATS datastore).

```json
{
  "profile_version": "1.0",
  "updated_at": "2024-11-26T12:00:00Z",
  "public_key": "ed25519:base64encodedpublickey...",
  "public": {
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane.doe@example.com"
  },
  "optional": {
    "phone": "+1-555-0100",
    "city": "Denver",
    "company": "Acme Corp"
  }
}
```

**Key Usage:**
- Other users encrypt messages/events with this public key
- Only the member's vault can decrypt (private key in local NATS)
- Separate from per-connection keys (see Connection Flow)

---

## 8. Connection Flow

### Overview

Connections allow two VettID members to securely communicate through their vaults. The connection process establishes mutual trust, exchanges encryption keys, and enables ongoing secure messaging.

### 8.1 Connection Invitation

**Generating an Invitation:**

1. Member A opens "Connections" in mobile app
2. Selects "Invite New Connection"
3. Vault generates invitation containing:
   - MessageSpace URI (`ms.vettid.dev/{member_a_guid}`)
   - Access token (read profile, write messages)
4. Invitation delivered via:
   - QR code (in-person exchange)
   - Deep link (email, SMS, other apps)

**Invitation Structure:**
```json
{
  "type": "vettid_connection_invite",
  "version": "1.0",
  "messagespace_uri": "ms.vettid.dev/550e8400-e29b-41d4-a716-446655440000",
  "token": "eyJhbGciOiJFZDI1NTE5...",
  "expires_at": "2024-12-04T12:00:00Z",
  "inviter_hint": "Jane D."
}
```

### 8.2 Connection Establishment

```
┌─────────────┐                                           ┌─────────────┐
│  Member A   │                                           │  Member B   │
│  (Inviter)  │                                           │  (Invitee)  │
└──────┬──────┘                                           └──────┬──────┘
       │                                                         │
       │  1. Generate invitation                                 │
       │  (URI + token for A's MessageSpace)                     │
       │                                                         │
       │  2. Share via QR/link ─────────────────────────────────►│
       │                                                         │
       │                          3. B's app connects to         │
       │                          A's MessageSpace               │
       │                                                         │
       │                          4. B retrieves A's profile     │
       │                          (includes A's public key)      │
       │                                                         │
       │  5. B sends invitation  ◄───────────────────────────────│
       │  to B's MessageSpace                                    │
       │  (URI + token)                                          │
       │                                                         │
       │  6. A's vault receives                                  │
       │  B's invitation                                         │
       │                                                         │
       │  7. A retrieves B's profile                             │
       │  (includes B's public key)                              │
       │                                                         │
       ├─────────────────────────────────────────────────────────┤
       │              MUTUAL REVIEW PHASE                        │
       ├─────────────────────────────────────────────────────────┤
       │                                                         │
       │  8. Both members review                                 │
       │  each other's profiles                                  │
       │                                                         │
       │  9. Both must AGREE to                                  │
       │  allow connection                                       │
       │                                                         │
       ├─────────────────────────────────────────────────────────┤
       │              KEY EXCHANGE PHASE                         │
       ├─────────────────────────────────────────────────────────┤
       │                                                         │
       │  10. Unique key exchange                                │
       │  specific to this connection                            │
       │◄────────────────────────────────────────────────────────►│
       │                                                         │
       │  11. KeyID generated                                    │
       │  (known only to A and B)                                │
       │                                                         │
       │  12. Keys stored in                   Keys stored in    │
       │  A's local NATS                       B's local NATS    │
       │  (by keyID)                           (by keyID)        │
       │                                                         │
       │  13. B's profile cached               A's profile cached│
       │  in A's contact list                  in B's contact list
       │                                                         │
       │  ═══════════ CONNECTION ESTABLISHED ═══════════         │
       │                                                         │
```

### 8.3 Connection Key Management

Each connection has its own encryption keys, identified by a **keyID** known only to the two connected members.

**Key Storage (in local NATS):**
```
local.credentials.connection_keys
├── {keyID_1}
│   ├── connection_guid: "..."
│   ├── public_key: "..."      (other member's key)
│   ├── private_key: "..."     (my key for this connection)
│   ├── created_at: "..."
│   └── last_rotated: "..."
├── {keyID_2}
│   └── ...
```

**Key Properties:**
- Unique to each connection (not shared across connections)
- KeyID is opaque identifier (not derivable from member GUIDs)
- Periodically rotated by vault negotiation

### 8.4 Connection Maintenance

Vaults periodically perform maintenance for each connection:

| Task | Frequency | Purpose |
|------|-----------|---------|
| Key rotation | Configurable (e.g., weekly) | Forward secrecy |
| Token refresh | Before expiration | Maintain access |
| Profile sync | On change or periodic | Updated contact list |

**Maintenance Flow:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                  Connection Maintenance Cycle                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Key Rotation (periodic)                                        │
│     └─► Vaults negotiate new key exchange                          │
│     └─► New keys stored under same keyID                           │
│     └─► Old keys archived (for decrypting old messages)            │
│                                                                     │
│  2. Token Refresh (before expiration)                              │
│     └─► Request new MessageSpace access token                      │
│     └─► Update stored token                                        │
│                                                                     │
│  3. Profile Sync (on change or periodic)                           │
│     └─► Fetch latest profile from connection's MessageSpace        │
│     └─► Update cached profile in contact list                      │
│     └─► Update public key if changed                               │
│     └─► Result: Auto-updating contact list (see Section 15)        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.5 Messaging Flow (Example: Send Text Message)

Complete flow for Member A sending a text message to Member B:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  A's App    │    │ A's Vault   │    │  Messaging  │    │ B's Message │
│             │    │  Manager    │    │  Handler    │    │   Space     │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │  1. User selects │                  │                  │
       │  "Send Message"  │                  │                  │
       │                  │                  │                  │
       │  2. App retrieves│                  │                  │
       │  messaging handler                  │                  │
       │  event format    │                  │                  │
       │                  │                  │                  │
       │  3. User picks   │                  │                  │
       │  contact (B)     │                  │                  │
       │  from list       │                  │                  │
       │                  │                  │                  │
       │  4. User enters  │                  │                  │
       │  message text    │                  │                  │
       │                  │                  │                  │
       │  5. App encrypts │                  │                  │
       │  event with A's  │                  │                  │
       │  vault public key│                  │                  │
       │                  │                  │                  │
       │  6. Write to     │                  │                  │
       │  OwnerSpace      │                  │                  │
       │  forVault        │                  │                  │
       ├─────────────────►│                  │                  │
       │                  │                  │                  │
       │                  │  7. Receive &    │                  │
       │                  │  decrypt event   │                  │
       │                  │                  │                  │
       │                  │  8. Format for   │                  │
       │                  │  messaging handler                  │
       │                  │                  │                  │
       │                  │  9. Encrypt payload                 │
       │                  │  with B's public │                  │
       │                  │  key (from profile)                 │
       │                  │                  │                  │
       │                  │  10. Invoke handler                 │
       │                  │  with:           │                  │
       │                  │  • MS URI        │                  │
       │                  │  • MS token      │                  │
       │                  │  • keyID         │                  │
       │                  │  • encrypted payload                │
       │                  ├─────────────────►│                  │
       │                  │                  │                  │
       │                  │                  │  11. Handler     │
       │                  │                  │  writes to B's   │
       │                  │                  │  MessageSpace    │
       │                  │                  ├─────────────────►│
       │                  │                  │                  │
       │                  │  12. Success     │                  │
       │                  │◄─────────────────┤                  │
       │                  │                  │                  │
       │  13. Response    │                  │                  │
       │  to app          │                  │                  │
       │◄─────────────────┤                  │                  │
       │                  │                  │                  │
```

**Handler Payload Structure:**
```json
{
  "handler": "messaging.send_text",
  "target": {
    "messagespace_uri": "ms.vettid.dev/{member_b_guid}",
    "messagespace_token": "eyJhbGciOiJFZDI1NTE5...",
    "key_id": "conn_key_abc123"
  },
  "payload_encrypted": "base64_encrypted_with_B_public_key...",
  "sender": {
    "messagespace_uri": "ms.vettid.dev/{member_a_guid}",
    "key_id": "conn_key_abc123"
  }
}
```

### 8.6 Contact List

Each vault maintains a contact list in local NATS:

```json
{
  "contacts": [
    {
      "connection_id": "conn_abc123",
      "key_id": "key_xyz789",
      "profile": {
        "first_name": "Bob",
        "last_name": "Smith",
        "email": "bob@example.com",
        "public_key": "ed25519:..."
      },
      "messagespace": {
        "uri": "ms.vettid.dev/...",
        "token": "eyJ...",
        "token_expires": "2024-12-31T00:00:00Z"
      },
      "connected_at": "2024-11-01T12:00:00Z",
      "last_synced": "2024-12-04T08:00:00Z",
      "status": "active"
    }
  ]
}
```

---

## 9. Data Storage Model

### Data Classification

| Category | Storage Location | Examples |
|----------|-----------------|----------|
| **Private Data** | NATS Datastore | Address, phone, credit cards, certificates, lesser private keys |
| **Secrets** | Vault Credential (encrypted blob) | Bitcoin keys, SSN, critical private keys |
| **Secret Metadata** | NATS Datastore | Labels, categories, last-used timestamps |
| **Public Profile** | MessageSpace ownerProfile topic | Name, email, optional shared fields |
| **Configuration** | NATS Datastore | Enabled handlers, preferences, policies |
| **Handler Metadata** | NATS Datastore | Handler-specific persistent data (e.g., BTC wallet UTXO details, transaction history) |
| **Revoked Connections** | NATS Datastore | Minimal identifiers (guid, name, email) for revoked connections |

### Why Two Storage Locations?

**NATS Datastore (Private Data):**
- Searchable and queryable
- Faster access for frequent operations
- Suitable for data used by event handlers
- Backed up encrypted to S3

**Vault Credential (Secrets):**
- Never leaves the credential blob
- Requires full Protean auth to access
- Additional protection layer
- Secrets only accessible when explicitly requested

### Initialization Data

When vault starts, NATS is seeded with:
- OwnerSpace credentials
- MessageSpace credentials
- Member's first name, last name, email (from enrollment)

### Schema Versioning

The NATS JetStream datastore uses a flexible key-value model that accommodates schema evolution:

**Design Principles:**
- **Additive changes only** - New fields added, existing fields never removed or changed
- **Optional by default** - New fields are optional to maintain backward compatibility
- **Version metadata** - Each data type includes a schema version field

**Example Schema Evolution:**
```json
// v1.0 - Original contact structure
{
  "schema_version": "1.0",
  "first_name": "Bob",
  "email": "bob@example.com"
}

// v1.1 - Added optional phone field
{
  "schema_version": "1.1",
  "first_name": "Bob",
  "email": "bob@example.com",
  "phone": "+1-555-0123"
}
```

This approach avoids complex migrations and ensures older vault versions can read data written by newer versions (ignoring unknown fields).

---

## 10. Event Handler System

### Overview

Event handlers are **WebAssembly (WASM) modules** that execute locally on the member's vault. This unified model works identically for cloud vaults (EC2) and home appliances.

**Key Design Decisions:**
- **Local execution only** - No Lambda/serverless. Handlers run on the vault itself.
- **WASM sandboxing** - Handlers execute in a secure, isolated runtime.
- **Unified architecture** - Same model for EC2 and home appliances.
- **Capability-based security** - Handlers receive only explicitly granted permissions.

### 10.1 Why WASM?

| Benefit | Description |
|---------|-------------|
| **Security** | Sandboxed by design. No access to host unless explicitly granted. |
| **Lightweight** | Runtime uses ~5-10MB. Ideal for t4g.nano instances (512MB RAM). |
| **Portable** | Same binary runs on EC2 (ARM) and home appliance (ARM). |
| **Fast startup** | Millisecond cold starts vs. seconds for containers. |
| **Language flexible** | Handlers written in Rust, Go, C/C++, AssemblyScript, etc. |

### 10.2 WASM Runtime Architecture

The Vault Manager includes a WASM runtime (Wasmtime or WasmEdge) for handler execution.

```
┌─────────────────────────────────────────────────────────────────────┐
│                  WASM Handler Execution Model                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Vault Manager                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                                                               │ │
│  │  WASM Runtime (Wasmtime/WasmEdge)                            │ │
│  │  ┌─────────────────────────────────────────────────────────┐ │ │
│  │  │  handler.wasm                                           │ │ │
│  │  │                                                         │ │ │
│  │  │  Capabilities granted per manifest:                     │ │ │
│  │  │  ├── stdin:  JSON event payload                         │ │ │
│  │  │  ├── stdout: JSON response                              │ │ │
│  │  │  ├── network: [specific egress hosts only]              │ │ │
│  │  │  ├── filesystem: NONE                                   │ │ │
│  │  │  ├── env vars: NONE                                     │ │ │
│  │  │  └── time limit: configurable (default 30s)             │ │ │
│  │  │                                                         │ │ │
│  │  └─────────────────────────────────────────────────────────┘ │ │
│  │                                                               │ │
│  │  Resource limits enforced by runtime:                        │ │
│  │  • Max memory: per manifest (default 64MB)                   │ │
│  │  • Max CPU time: per manifest (default 30s)                  │ │
│  │  • Max response size: 1MB                                    │ │
│  │                                                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Vault Manager mediates ALL external access:                       │
│  • Handler cannot access local NATS directly                       │
│  • Handler cannot access vault filesystem                          │
│  • Handler only sees the JSON payload it receives                  │
│  • Network egress controlled by runtime (WASI)                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 10.3 Handler Package Structure

Handlers are distributed as signed packages via the Service Registry.

**Package Contents:**
```
messaging.send_text/
├── handler.wasm          # Compiled WASM module
├── manifest.json         # Permissions and metadata
└── signature.sig         # Ed25519 signature (registry private key)
```

**Manifest Example (First-Party Free Handler):**
```json
{
  "handler_id": "messaging.send_text",
  "name": "Send Text Message",
  "description": "Send encrypted text message to a connection",
  "version": "1.2.0",
  "category": "communication",
  "wasm_hash": "sha256:a1b2c3d4e5f6...",
  "publisher": null,
  "access": {
    "type": "free"
  },
  "compatibility": {
    "min_app_version": "2.1.0",
    "min_vault_version": "1.0.0"
  },
  "permissions": {
    "network_egress": ["ms.vettid.dev"],
    "max_memory_mb": 32,
    "max_runtime_seconds": 10
  },
  "event_schema": {
    "type": "object",
    "required": ["target_connection_id", "message_text"],
    "properties": {
      "target_connection_id": { "type": "string" },
      "message_text": { "type": "string", "maxLength": 10000 }
    }
  },
  "response_schema": {
    "type": "object",
    "properties": {
      "status": { "type": "string" },
      "message_id": { "type": "string" }
    }
  }
}
```

**Manifest Example (Third-Party Authorization Required):**
```json
{
  "handler_id": "acme.btc_wallet",
  "name": "ACME Bitcoin Wallet",
  "description": "Full-featured Bitcoin wallet with UTXO management",
  "version": "2.0.0",
  "category": "finance",
  "wasm_hash": "sha256:b2c3d4e5f6a7...",
  "publisher": {
    "name": "ACME Crypto Services",
    "publisher_id": "acme-crypto",
    "messagespace_guid": "abc123-def456-..."
  },
  "access": {
    "type": "authorization_required",
    "model": "subscription",
    "description": "Requires active subscription with ACME Crypto Services",
    "terms_url": "https://acme-crypto.com/terms"
  },
  "compatibility": {
    "min_app_version": "2.3.0",
    "min_vault_version": "1.1.0"
  },
  "permissions": {
    "network_egress": ["blockchain.info", "mempool.space"],
    "max_memory_mb": 64,
    "max_runtime_seconds": 30
  },
  "event_schema": { ... },
  "response_schema": { ... }
}
```

**Version Compatibility:**

The `compatibility` field ensures handlers only run on compatible infrastructure:

| Field | Purpose |
|-------|---------|
| `min_app_version` | Minimum mobile app version required |
| `min_vault_version` | Minimum Vault Manager version required |

When the mobile app reads the vault's handler list:
1. App compares each handler's `min_app_version` to its own version
2. If app version is too old, handler is marked as "requires app update"
3. User is prompted to update the app before using that handler

This allows handlers to introduce new event types or features without breaking older app versions.

### 10.4 Handler Installation Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Handler Installation Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Member browses available handlers                              │
│     └─► Vault retrieves catalog from registry (via connection)     │
│                                                                     │
│  2. Member selects handler to install                              │
│                                                                     │
│  3. Vault downloads handler package                                │
│     └─► handler.wasm + manifest.json + signature.sig               │
│                                                                     │
│  4. Vault verifies package                                         │
│     └─► Compute hash of handler.wasm                               │
│     └─► Verify hash matches manifest.wasm_hash                     │
│     └─► Verify signature using registry public key                 │
│     └─► If invalid → Reject, alert user                            │
│                                                                     │
│  5. Vault stores handler locally                                   │
│     └─► WASM binary stored in local filesystem                     │
│     └─► Manifest stored in local NATS                              │
│     └─► Handler added to eventTypes topic in OwnerSpace            │
│                                                                     │
│  6. Configure network egress (if required)                         │
│     └─► Read network_egress from manifest                          │
│     └─► Update instance security group with egress destinations    │
│     └─► (e.g., BTC handler adds blockchain API endpoints)          │
│                                                                     │
│  7. Handler ready for use                                          │
│     └─► Mobile app can now send events for this handler            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 10.5 Event Execution Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Mobile App  │    │ OwnerSpace  │    │   Vault     │    │ WASM Runtime│
│             │    │  forVault   │    │  Manager    │    │  (handler)  │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │                  │
       │  1. Post event   │                  │                  │
       │  (encrypted with │                  │                  │
       │  vault pub key)  │                  │                  │
       ├─────────────────►│                  │                  │
       │                  │                  │                  │
       │                  │  2. Receive      │                  │
       │                  │  event           │                  │
       │                  ├─────────────────►│                  │
       │                  │                  │                  │
       │                  │                  │  3. Decrypt      │
       │                  │                  │  event data      │
       │                  │                  │                  │
       │                  │                  │  4. Load handler │
       │                  │                  │  manifest        │
       │                  │                  │                  │
       │                  │                  │  5. Prepare      │
       │                  │                  │  payload JSON    │
       │                  │                  │  (add target     │
       │                  │                  │  keys, tokens)   │
       │                  │                  │                  │
       │                  │                  │  6. Configure    │
       │                  │                  │  WASM runtime    │
       │                  │                  │  with manifest   │
       │                  │                  │  permissions     │
       │                  │                  │                  │
       │                  │                  │  7. Execute      │
       │                  │                  │  handler.wasm    │
       │                  │                  ├─────────────────►│
       │                  │                  │                  │
       │                  │                  │                  │  8. Handler
       │                  │                  │                  │  processes
       │                  │                  │                  │  (sandboxed)
       │                  │                  │                  │
       │                  │                  │                  │  9. Handler
       │                  │                  │                  │  egress (if
       │                  │                  │                  │  permitted)
       │                  │                  │                  │
       │                  │                  │  10. Handler     │
       │                  │                  │  returns JSON    │
       │                  │                  │◄─────────────────┤
       │                  │                  │                  │
       │                  │  11. Post        │                  │
       │  12. Receive     │  response        │                  │
       │  response        │◄─────────────────┤                  │
       │◄─────────────────┤                  │                  │
       │                  │                  │                  │
```

### 10.6 Handler Input/Output

Handlers receive a JSON payload via stdin and return a JSON response via stdout.

**Input Payload Example (messaging handler):**
```json
{
  "event_id": "evt_abc123",
  "handler_id": "messaging.send_text",
  "timestamp": "2024-12-04T12:00:00Z",
  "target": {
    "messagespace_uri": "ms.vettid.dev/550e8400-...",
    "messagespace_token": "eyJhbGciOiJFZDI1NTE5...",
    "public_key": "ed25519:target_public_key_base64..."
  },
  "sender": {
    "messagespace_uri": "ms.vettid.dev/661f9511-...",
    "key_id": "conn_key_xyz789"
  },
  "payload": {
    "message_text": "Hello, how are you?"
  }
}
```

**Output Response Example:**
```json
{
  "status": "success",
  "message_id": "msg_def456",
  "delivered_at": "2024-12-04T12:00:01Z"
}
```

### 10.7 Security Model

**What handlers CAN do:**
- Read JSON payload from stdin
- Write JSON response to stdout
- Make network requests to explicitly allowed hosts (per manifest)
- Use memory up to the allowed limit

**What handlers CANNOT do:**
- Access vault filesystem
- Access local NATS datastore
- Access other handlers or processes
- Make network requests to non-allowed hosts
- Exceed memory or time limits
- Access environment variables or host information

**Enforcement:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                  WASM Security Layers                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Layer 1: WASM Sandbox                                             │
│  └─► Linear memory model (no pointer exploits)                     │
│  └─► No direct system calls                                        │
│  └─► Capability-based (WASI)                                       │
│                                                                     │
│  Layer 2: Runtime Configuration                                    │
│  └─► Memory limits enforced                                        │
│  └─► CPU/time limits enforced                                      │
│  └─► Network egress whitelist                                      │
│                                                                     │
│  Layer 3: Vault Manager Mediation                                  │
│  └─► Payload sanitization                                          │
│  └─► Response validation                                           │
│  └─► Logging and auditing                                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 10.8 Third-Party Handler Authorization

Third parties can create and distribute handlers through the Service Registry. Authorization and payment negotiation happens directly between the member and publisher via MessageSpace—VettID is not involved.

**Authorization Model Overview:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Third-Party Handler Authorization Model                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Handler Discovery                                              │
│     └─► Member browses registry, sees third-party handler          │
│     └─► Manifest indicates publisher and access requirements       │
│                                                                     │
│  2. Publisher Connection                                           │
│     └─► Member establishes connection with publisher               │
│     └─► (Standard connection flow via MessageSpace)                │
│     └─► Member now has publisher's public key                      │
│                                                                     │
│  3. Authorization Negotiation                                      │
│     └─► Member requests access via MessageSpace                    │
│     └─► Publisher and member negotiate (payment, terms, etc.)      │
│     └─► Payment could use BTC handler or other mechanism           │
│     └─► VettID is not involved in this negotiation                 │
│                                                                     │
│  4. Authorization Token Issued                                     │
│     └─► Publisher signs authorization token                        │
│     └─► Token sent to member via MessageSpace                      │
│     └─► Member's vault stores token in handler_data                │
│                                                                     │
│  5. Handler Installation/Use                                       │
│     └─► Vault verifies token signature (publisher's public key)    │
│     └─► Vault checks token validity (expiration, uses, etc.)       │
│     └─► If valid, handler can be installed/executed                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Access Types:**

| Type | Description |
|------|-------------|
| `free` | No authorization required (default for first-party handlers) |
| `authorization_required` | Must obtain token from publisher |

**Authorization Models (when `authorization_required`):**

| Model | Description |
|-------|-------------|
| `perpetual` | One-time authorization, never expires |
| `subscription` | Time-limited, must renew periodically |
| `per_use` | Limited number of executions |
| `permission` | Publisher grants/revokes at will |

**Authorization Token Structure:**

```json
{
  "token_id": "unique-token-id",
  "member_guid": "member's GUID",
  "handler_id": "acme.btc_wallet",
  "handler_versions": ">=2.0.0 <3.0.0",
  "model": "subscription",
  "issued_at": "2024-12-05T00:00:00Z",
  "expires_at": "2025-12-05T00:00:00Z",
  "uses_remaining": null,
  "terms_accepted": "v2.1",
  "signature": "ed25519:base64..."
}
```

**Token Verification Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Authorization Verification Flow                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Vault checks manifest.access.type                              │
│     └─► If "free" → proceed to install/execute                     │
│     └─► If "authorization_required" → continue verification        │
│                                                                     │
│  2. Vault retrieves authorization token from handler_data          │
│     └─► If no token → prompt member to obtain authorization        │
│                                                                     │
│  3. Vault verifies token                                           │
│     └─► Get publisher's public key from contacts (connection)      │
│     └─► Verify signature matches token contents                    │
│     └─► Check handler_id and version match manifest                │
│     └─► Check expiration (if subscription model)                   │
│     └─► Check uses_remaining (if per_use model)                    │
│                                                                     │
│  4. Authorization decision                                         │
│     └─► If valid → allow install/execute                           │
│     └─► If per_use → decrement uses_remaining                      │
│     └─► If invalid/expired → block and notify member               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Token Revocation:**

Publishers can revoke tokens by including a revocation list in their MessageSpace profile:

```json
{
  "profile_version": "1.0",
  "public_key": "ed25519:...",
  "public": {
    "name": "ACME Crypto Services"
  },
  "handler_revocations": [
    { "token_id": "revoked-token-1", "revoked_at": "2024-12-01T00:00:00Z" },
    { "token_id": "revoked-token-2", "revoked_at": "2024-12-03T00:00:00Z" }
  ]
}
```

Vault syncs publisher profile during update checks (see Section 10.9) and verifies stored tokens against the revocation list.

**Benefits:**

| Benefit | Description |
|---------|-------------|
| **VettID stays out of it** | All negotiation happens via MessageSpace between member and publisher |
| **Leverages existing infrastructure** | Connections, MessageSpace, key exchange all reused |
| **Flexible payment** | BTC handler, external payment, or any mechanism parties agree on |
| **Cryptographically secure** | Publisher's signature on token, verified with connection public key |
| **Offline verification** | Vault verifies token without contacting publisher each time |
| **Revocation support** | Publisher can revoke tokens via their MessageSpace profile |

### 10.9 Handler Update Checks

Vaults check for handler updates through a combination of push notifications and pull checks.

**Update Check Triggers:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Handler Update Check Model                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Trigger 1: Real-Time Notification (Push)                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Registry publishes update announcements to MessageSpace   │  │
│  │  • Vault receives notification when online                   │  │
│  │  • Immediate awareness of critical security updates          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Trigger 2: Startup Check (Pull)                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Vault checks for updates when starting                    │  │
│  │  • Catches any updates missed while stopped                  │  │
│  │  • Ensures vault starts with latest handlers                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Trigger 3: Manual Re-Sync (User-Initiated)                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Member triggers full refresh via app                      │  │
│  │  • Re-syncs registry profile, handler versions, revocations  │  │
│  │  • Troubleshooting tool if something seems off               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Registry Profile with Handler Versions:**

```json
{
  "profile_version": "1.0",
  "public_key": "ed25519:...",
  "public": {
    "name": "VettID Service Registry"
  },
  "handler_versions": {
    "messaging.send_text": "1.2.0",
    "messaging.receive": "1.1.0",
    "storage.backup": "2.0.1",
    "acme.btc_wallet": "2.0.0"
  },
  "last_updated": "2024-12-06T00:00:00Z"
}
```

**Update Announcement (via MessageSpace forOwner topic):**

```json
{
  "type": "handler_update",
  "handler_id": "messaging.send_text",
  "old_version": "1.1.0",
  "new_version": "1.2.0",
  "severity": "recommended",
  "changelog": "Added support for attachments",
  "published_at": "2024-12-06T00:00:00Z"
}
```

**Update Severity Levels:**

| Severity | Description | Default Behavior |
|----------|-------------|------------------|
| `critical` | Security vulnerability fix | Auto-update immediately |
| `required` | Breaking change, old version deprecated | Auto-update, notify member |
| `recommended` | Bug fixes, improvements | Notify member, prompt to update |
| `optional` | New features, enhancements | Show in available updates |

**Update Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Handler Update Flow                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Vault receives update notification or checks registry profile  │
│     └─► Compare handler_versions with installed handlers           │
│                                                                     │
│  2. For each handler with available update:                        │
│     └─► Check update severity                                      │
│     └─► critical/required → auto-update (per member preference)    │
│     └─► recommended/optional → add to pending updates list         │
│                                                                     │
│  3. If auto-update:                                                │
│     └─► Download new package from registry                         │
│     └─► Verify signature and hash                                  │
│     └─► Replace handler                                            │
│     └─► Update security group if egress changed                    │
│     └─► Log update in feed                                         │
│                                                                     │
│  4. If pending updates:                                            │
│     └─► Notify member via app                                      │
│     └─► Member reviews and approves updates                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Handler Version Selection and Rollback:**

The handler catalog maintains all supported versions of each handler, allowing members to select specific versions:

| Capability | Description |
|------------|-------------|
| Version selection | Member can install any supported version from catalog |
| Rollback | Member can revert to previous version if update causes issues |
| Critical revocation | VettID can revoke specific versions with critical vulnerabilities |

```
┌─────────────────────────────────────────────────────────────────────┐
│              Handler Version Management                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Catalog:                                                          │
│  messaging.send_text/                                              │
│  ├── 1.0.0 (supported)                                             │
│  ├── 1.1.0 (supported)                                             │
│  ├── 1.1.1 (revoked - critical vulnerability)                      │
│  └── 1.2.0 (latest)                                                │
│                                                                     │
│  Member Actions:                                                   │
│  • View all available versions in app                              │
│  • Select and install specific version                             │
│  • Rollback to previous version if issues encountered              │
│  • Cannot install revoked versions                                 │
│                                                                     │
│  Revocation:                                                       │
│  • Revoked versions removed from catalog downloads                 │
│  • Vaults with revoked version receive critical update notice      │
│  • Auto-update to nearest safe version                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Third-Party Handler Updates:**

For third-party handlers, the update flow is similar but:
- Publisher announces updates via their own MessageSpace
- Vault checks publisher's profile for version updates
- Authorization token validity is re-verified after update
- If token specifies version range (e.g., `>=2.0.0 <3.0.0`), major version updates may require re-authorization from the publisher

### 10.10 Handler Development

Handlers can be written in any language that compiles to WASM:

| Language | Toolchain | Notes |
|----------|-----------|-------|
| **Rust** | `wasm32-wasi` target | Recommended. Best WASM support. |
| **Go** | TinyGo | Good support, smaller binaries than standard Go. |
| **C/C++** | Emscripten or wasi-sdk | Low-level control. |
| **AssemblyScript** | Built-in | TypeScript-like syntax. |

**Example Handler (Rust pseudocode):**
```rust
use std::io::{self, Read, Write};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    target: Target,
    payload: Payload,
}

#[derive(Serialize)]
struct Output {
    status: String,
    message_id: String,
}

fn main() -> io::Result<()> {
    // Read JSON from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let event: Input = serde_json::from_str(&input)?;
    
    // Process event (e.g., send to target MessageSpace)
    let result = send_message(&event.target, &event.payload)?;
    
    // Write JSON to stdout
    let output = Output {
        status: "success".to_string(),
        message_id: result.id,
    };
    println!("{}", serde_json::to_string(&output)?);
    
    Ok(())
}
```

### 10.11 Response Types

| Type | Description |
|------|-------------|
| `success` | Action completed successfully |
| `failure` | Action failed with error details |
| `message` | Informational response |
| `action_required` | Member needs to perform some action |
| `confirmation` | Request member confirmation before proceeding |
| `authorization_required` | Third-party handler requires authorization token |

---

## 11. Home Appliance Variant

### Overview

The home appliance is an alternative to cloud-hosted EC2 vaults. It provides the same functionality but runs on member-owned hardware in their home network.

### 11.1 Hardware Specifications

| Component | Specification |
|-----------|---------------|
| **Processor** | ARM-based SoC |
| **Security** | TPM (Trusted Platform Module) |
| **OS** | Linux |
| **Network** | Ethernet port |
| **Input** | Touchscreen + Camera |
| **Form Factor** | Similar to smartphone with network port |

**Design Philosophy:** A secure, dedicated device that looks and feels like a phone but is designed to stay connected to the home network.

### 11.2 Network Configuration

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Home Appliance Network Model                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Home Network                                                       │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                                                               │ │
│  │  ┌─────────────────┐                                          │ │
│  │  │ Home Appliance  │                                          │ │
│  │  │     Vault       │                                          │ │
│  │  └────────┬────────┘                                          │ │
│  │           │                                                   │ │
│  │           │ Ethernet                                          │ │
│  │           ▼                                                   │ │
│  │  ┌─────────────────┐                                          │ │
│  │  │     Router      │                                          │ │
│  │  └────────┬────────┘                                          │ │
│  │           │                                                   │ │
│  └───────────┼───────────────────────────────────────────────────┘ │
│              │                                                     │
│              │ OUTBOUND ONLY                                       │
│              │ (no inbound/port forwarding required)               │
│              ▼                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                        Internet                               │ │
│  │                                                               │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │ │
│  │  │ os.vettid.dev│  │ ms.vettid.dev│  │ Event Handler Pkgs   │ │ │
│  │  │ (OwnerSpace) │  │ (MessageSpace)│  │ (Download/Install)   │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘ │ │
│  │                                                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Property:** No inbound network access required. All connections initiated outbound by the appliance.

### 11.3 Initial Setup Flow

The appliance touchscreen is only used for two purposes: initial namespace connection and local backup. All other configuration is done via the mobile app.

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Home Appliance Setup Process                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Physical Setup                                                 │
│     └─► Connect appliance to home network via ethernet             │
│     └─► Power on device                                            │
│     └─► Device boots to setup screen                               │
│                                                                     │
│  2. Claim Namespaces (via appliance touchscreen)                   │
│     └─► Member generates claim link in VettID web portal           │
│     └─► Link contains: OwnerSpace URI, MessageSpace URI, tokens    │
│     └─► Input method:                                              │
│         • Scan QR code with appliance camera                       │
│         • Enter link via touchscreen                               │
│     └─► Appliance claims assigned OwnerSpace and MessageSpace      │
│                                                                     │
│  3. Vault Credential Creation                                      │
│     └─► Appliance communicates with VettID via OwnerSpace          │
│     └─► Protean credential enrollment (same as cloud vault)        │
│     └─► Credential stored locally on appliance                     │
│     └─► TPM used to protect key material                           │
│                                                                     │
│  4. Initial Configuration (via mobile app)                         │
│     └─► All configuration done through mobile app                  │
│     └─► Add personal data, secrets, create profile                 │
│     └─► Enable event handlers                                      │
│     └─► Appliance touchscreen not used for configuration           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.4 Appliance Backup and Restore

Home appliances support both local and cloud backups, with corresponding restore capabilities.

#### 11.4.1 Local Backup

Local backup writes encrypted data to physical storage devices.

**Local Backup Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Local Backup Process                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Request Backup (via mobile app)                                │
│     └─► Member selects "Local Backup" in vault settings            │
│     └─► Choose encryption method:                                  │
│         • Use Vault Services backup key (from credential)          │
│         • Provide new password for this backup                     │
│     └─► App generates backup confirmation code                     │
│     └─► App displays code to member                                │
│                                                                     │
│  2. Prepare Storage                                                │
│     └─► Member inserts storage device into appliance               │
│         (SD card, USB stick, etc.)                                 │
│                                                                     │
│  3. Confirm Backup (via appliance touchscreen)                     │
│     └─► Member enters backup code from app into touchscreen        │
│     └─► This confirms the backup request is authorized             │
│                                                                     │
│  4. Execute Backup                                                 │
│     └─► Appliance formats storage device                           │
│     └─► Coalesces datastore                                        │
│     └─► Encrypts backup with selected key/password                 │
│     └─► Copies encrypted backup to storage device                  │
│     └─► Unmounts storage device                                    │
│     └─► Notifies member via app that backup is complete            │
│     └─► Member removes storage device                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 11.4.2 Cloud Backup

Appliances can upload encrypted backups to the member's private S3 directory via Vault Services.

**Cloud Backup Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Appliance Cloud Backup Process                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Request Backup (via mobile app)                                │
│     └─► Member selects "Cloud Backup" in vault settings            │
│     └─► Choose encryption method:                                  │
│         • Use Vault Services backup key (from credential)          │
│         • Provide new password for this backup                     │
│                                                                     │
│  2. Execute Backup                                                 │
│     └─► Appliance coalesces datastore                              │
│     └─► Encrypts backup with selected key/password                 │
│     └─► Calls Vault Services upload endpoint                       │
│     └─► Vault Services stores backup in member's S3 directory      │
│     └─► Notifies member via app that backup is complete            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Vault Services Backup Endpoints (for Appliances):**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/appliance/backup/upload` | POST | Upload encrypted backup to S3 |
| `/v1/appliance/backup/list` | GET | List available backups |
| `/v1/appliance/backup/download` | GET | Download backup for restore |

#### 11.4.3 Backup Encryption Options

| Option | Key Source | Recovery | Use Case |
|--------|------------|----------|----------|
| Vault Services key | Backup key from credential | Automatic (key in credential) | Recommended for most users |
| Custom password | Member-provided password | Manual (must enter password) | Additional security, offline restore |

#### 11.4.4 Restore from Cloud Backup

Appliances can restore from cloud backups stored in the member's S3 directory.

**Cloud Restore Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Appliance Cloud Restore Process                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Request Restore (via mobile app)                               │
│     └─► Member selects "Restore from Cloud" in vault settings      │
│     └─► App displays available backups with timestamps             │
│     └─► Member selects backup to restore                           │
│                                                                     │
│  2. Download Backup                                                │
│     └─► Appliance calls Vault Services download endpoint           │
│     └─► Encrypted backup retrieved from S3                         │
│                                                                     │
│  3. Decrypt Backup                                                 │
│     └─► If Vault Services key: Automatic decryption                │
│         (key available in credential)                              │
│     └─► If custom password: Prompt on appliance touchscreen        │
│         (member enters password to decrypt)                        │
│                                                                     │
│  4. Restore Data                                                   │
│     └─► Appliance validates backup integrity                       │
│     └─► Replaces local datastore with backup contents              │
│     └─► Restarts Vault Manager                                     │
│     └─► Notifies member via app that restore is complete           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 11.4.5 Restore from Local Backup

**Local Restore Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Appliance Local Restore Process                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Request Restore (via mobile app)                               │
│     └─► Member selects "Restore from Local" in vault settings      │
│     └─► App generates restore confirmation code                    │
│     └─► App displays code to member                                │
│                                                                     │
│  2. Prepare Storage                                                │
│     └─► Member inserts storage device with backup into appliance   │
│                                                                     │
│  3. Confirm Restore (via appliance touchscreen)                    │
│     └─► Member enters restore code from app into touchscreen       │
│     └─► If custom password: Member also enters password            │
│                                                                     │
│  4. Restore Data                                                   │
│     └─► Appliance reads backup from storage device                 │
│     └─► Decrypts with Vault Services key or entered password       │
│     └─► Validates backup integrity                                 │
│     └─► Replaces local datastore with backup contents              │
│     └─► Unmounts storage device                                    │
│     └─► Restarts Vault Manager                                     │
│     └─► Notifies member via app that restore is complete           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Security Notes:**
- Backup confirmation code prevents unauthorized backups
- Restore confirmation code prevents unauthorized restores
- Storage device is formatted during local backup to prevent data leakage
- Member controls encryption method and retains physical custody of local backups
- Cloud backups follow same retention policy as EC2 vaults (last 3 backups)

### 11.5 Unified Handler Model

With the WASM-based handler architecture, **cloud vaults and home appliances use identical execution models**:

| Aspect | Cloud Vault (EC2) | Home Appliance |
|--------|-------------------|----------------|
| Handler execution | Local WASM | Local WASM |
| Handler format | .wasm packages | .wasm packages |
| Handler delivery | Downloaded from registry | Downloaded from registry |
| Handler updates | Manual/prompted | Manual/prompted |
| Egress | Vault → Internet | Appliance → Internet |
| Sandboxing | WASM runtime | WASM runtime |

**Unified Execution Flow:**

```
Both Cloud and Appliance:
  App → OwnerSpace → Vault Manager → WASM Handler → External Service
```

This unified model provides:
- **Consistent behavior** across deployment types
- **Single codebase** for handler development
- **Portable binaries** (same .wasm runs on both ARM platforms)
- **Identical security model** (WASM sandboxing)

### 11.6 Appliance Security Model

| Control | Implementation |
|---------|----------------|
| **Boot Security** | Secure boot via TPM |
| **Key Storage** | TPM-protected key material |
| **Network Isolation** | Outbound-only connections |
| **Package Verification** | Signed handler packages |
| **Physical Security** | On-premises, under member control |
| **Updates** | Signed OS and handler updates |

**TPM Usage:**
- Secure boot attestation
- Storage of vault credential encryption keys
- Hardware-backed random number generation
- Key sealing to device state

### 11.7 Appliance vs. Cloud Comparison

| Feature | Cloud Vault (EC2) | Home Appliance |
|---------|-------------------|----------------|
| **Setup Complexity** | Lower (click to deploy) | Higher (physical setup) |
| **Ongoing Cost** | Included in subscription | One-time hardware cost |
| **Network Requirements** | None (cloud-hosted) | Home network + internet |
| **Physical Presence** | Not required | Required for hardware |
| **Handler Model** | Local WASM execution | Local WASM execution |
| **Data Location** | AWS datacenter | Member's home |
| **Uptime** | AWS SLA | Depends on home setup |
| **Power Outage** | No impact | Vault offline |
| **Portability** | Access from anywhere | Access from anywhere* |

*Both accessible via mobile app from anywhere with internet.

### 11.8 Hybrid Considerations

Future possibility: Members could have both a home appliance and a cloud vault for redundancy, with replication between them. This is not currently designed but could be a future enhancement.

---

## 12. Backup System

This section covers the primary backup system for cloud vaults (EC2). Home appliances have additional backup options including local storage; see Section 11.4 for appliance-specific backup and restore flows.

### Backup Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Backup Flow                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Vault Services Enrollment:                                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Generate backup key pair                                     │  │
│  │  • Private key → Member's Vault Services Credential           │  │
│  │  • Public key → Stored for vault to use                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Vault Deployment:                                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Vault receives backup public key                             │  │
│  │  (cannot decrypt backups - only encrypt)                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Backup (Daily or On-Demand):                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Vault Manager coalesces NATS datastore                    │  │
│  │  2. Data encrypted with member's backup public key            │  │
│  │  3. Encrypted backup uploaded to member's S3 directory        │  │
│  │  4. Status reported to mobile app (if manual trigger)         │  │
│  │  5. Only member can decrypt (private key in credential)       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Backup Triggers

| Trigger | Description |
|---------|-------------|
| **Daily** | Automatic backup once per day |
| **On-Demand** | Member-initiated via mobile app vault services section |
| **Pre-Stop** | Automatic backup before vault stop operation |
| **Pre-Expiry** | Automatic backup before subscription expiry auto-stop |

### On-Demand Backup Flow

```
1. Member opens Vault Services in mobile app
2. Selects "Backup Now"
3. Request sent to vault via OwnerSpace
4. Vault Manager:
   └─► Coalesces datastore (ensures consistency)
   └─► Exports data
   └─► Encrypts with backup public key
   └─► Uploads to S3
5. Status returned to mobile app
   └─► Success: timestamp, backup size
   └─► Failure: error details
```

### S3 Storage Structure

```
s3://vettid-vault-backups/
└── {member_guid}/
    ├── backup_2024-11-26T00-00-00Z.enc
    ├── backup_2024-11-25T00-00-00Z.enc
    └── backup_2024-11-24T00-00-00Z.enc
```

### Retention Policy

Only the **last 3 backups** are retained to conserve storage space. When a new backup is created, the oldest backup is deleted if there are already 3 backups stored.

| Policy | Value |
|--------|-------|
| Maximum backups retained (active subscription) | 3 |
| Backup types counted | Daily, on-demand, pre-stop, pre-expiry (all count toward limit) |
| Deletion timing | Oldest backup deleted after new backup successfully uploaded |
| Expired subscription retention | 30 days after subscription expiry (see Section 13) |

**Note:** Data corruption or issues should become evident quickly, so extended historical retention is unnecessary. Members who want additional backup copies can use the local backup feature on home appliances or manually download backups before they age out.

### Access Control

| Actor | Access |
|-------|--------|
| Member's Vault (EC2) | Write-only to own directory |
| Member's Appliance | Read/write to own directory (via Vault Services endpoints) |
| Vault Services API | List/manage for operational purposes |
| Member (via credential) | Decrypt capability (holds private key) |
| Anyone else | No access |

### Backup Recovery

To restore from backup:
1. Member authenticates with Vault Services credential
2. Backup file retrieved from S3
3. Member selects the backup to restore
4. App switches to the corresponding Vault Credential version (see Section 2.6)
5. Member's credential used to decrypt (private key in blob)
6. Decrypted data restored to new vault instance

**Credential Version Matching:**

The mobile app maintains 4 versions of the Vault Credential (1 active + 3 backup versions). When restoring from backup, the app automatically uses the credential version that matches the selected backup, ensuring the credential and backup data are compatible.

### Backup Verification

Backups are automatically validated to ensure they can be restored when needed.

**Verification Process:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Automatic Backup Verification                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Frequency: Every other backup (alternating)                       │
│                                                                     │
│  Process:                                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Spin up temporary vault instance                          │  │
│  │  2. Restore backup to temporary instance                      │  │
│  │  3. Start Vault Manager in verification mode                  │  │
│  │     └─► Special mode: integrity checks only, no operations    │  │
│  │  4. Perform datastore integrity checks                        │  │
│  │  5. Report results to Vault Services                          │  │
│  │  6. Destroy temporary instance                                │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Results:                                                          │
│  ├── Success: Backup marked as verified                            │
│  └── Failure: Member notified, next backup triggers verification  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Note:** Members cannot perform test-restores themselves. The automatic verification ensures backup integrity without requiring member action.

### Error Handling and Retry Logic

**Backup Failures:**

| Scenario | Action |
|----------|--------|
| Upload fails (1st attempt) | Mark failed, retry at next scheduled backup |
| Upload fails (2nd consecutive) | Alert member via app notification |
| Upload succeeds after failure | Clear failure state |

**Handler Execution Failures:**

| Scenario | Action |
|----------|--------|
| Handler timeout | Mark execution failed, notify member, allow manual retry |
| Handler crash (zombie) | Clean up process, log error, notify member |
| Handler returns error | Display error to member, allow retry if appropriate |

**Network Interruption Handling:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Network Interruption Recovery                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Vault Manager detects network unavailability                   │
│     └─► Central NATS (OwnerSpace/MessageSpace) unreachable         │
│     └─► External service (handler egress) unreachable              │
│                                                                     │
│  2. Queue impacted activities                                      │
│     └─► Pending messages queued in local.datastore                 │
│     └─► Pending handler requests queued                            │
│                                                                     │
│  3. Monitor resource availability                                  │
│     └─► Periodic connectivity checks                               │
│     └─► Exponential backoff to avoid hammering                     │
│                                                                     │
│  4. Resume when available                                          │
│     └─► Process queued items in order                              │
│     └─► Notify member of restored connectivity                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Portability

Members can export their data for portability to other VettID-compliant providers:

**Portable Backup:**
1. Member requests portable backup via mobile app
2. Member provides an export passphrase (separate from recovery phrase)
3. Vault creates backup encrypted with the export passphrase
4. Member downloads portable backup file

**Restoring at Another Provider:**
1. Member creates account with VettID-compliant provider
2. Uploads portable backup during onboarding
3. Provides export passphrase to decrypt
4. Data restored to new vault

**GDPR Considerations:**

VettID operates as a "safe deposit box" model—we provide secure storage infrastructure but have no access to member data:
- All data encrypted with member-controlled keys
- VettID cannot read, analyze, or process member data
- Member maintains full data sovereignty
- No data processing subject to GDPR data controller obligations

---

## 13. Vault Lifecycle

### Overview

Cloud vaults have three primary lifecycle states and operations. Understanding these is critical for members managing their vault.

### Lifecycle States

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Vault Lifecycle States                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐         │
│  │   RUNNING   │◄────►│   STOPPED   │─────►│ TERMINATED  │         │
│  │             │      │  (backup    │      │ (destroyed) │         │
│  │  • EC2 up   │      │   only)     │      │             │         │
│  │  • Usable   │      │  • No EC2   │      │  • No EC2   │         │
│  │  • Costs $  │      │  • No cost  │      │  • No backup│         │
│  └─────────────┘      └─────────────┘      └─────────────┘         │
│        │                    ▲                                       │
│        │                    │                                       │
│        └────────────────────┘                                       │
│          Stop (backup + delete EC2)                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Stop Operation

**What happens when a member stops their vault:**

```
1. Member initiates stop via mobile app

2. Mobile app calls Vault Services API
   └─► Authenticates with Vault Services credential

3. Vault Services sends commands via OwnerSpace control topic:
   └─► "prepare_backup" command
   └─► Vault Manager coalesces datastore
   └─► "execute_backup" command
   └─► Vault Manager encrypts and uploads to S3
   └─► Vault Manager confirms backup success

4. Vault Services terminates EC2 instance
   └─► EBS volume deleted
   └─► Security group retained
   └─► Namespace assignments retained

4. Vault state = STOPPED
   └─► Member sees "Stopped" in app
   └─► No ongoing costs
   └─► Backup available for restore
```

**Key Point:** A "stopped" vault is really just a backup. The EC2 instance is deleted to eliminate costs.

### Start Operation

**What happens when a member starts a stopped vault:**

```
1. Member initiates start via mobile app

2. Vault Services provisions new EC2 instance
   └─► Same configuration as before
   └─► New instance ID (but same member GUID)
   └─► Assigned to existing namespaces

3. Vault initialized with backup data
   └─► Latest backup retrieved from S3
   └─► Decrypted using backup key
   └─► NATS datastore restored
   └─► Handler packages re-installed

4. Vault Manager starts
   └─► Connects to OwnerSpace/MessageSpace
   └─► Reports ready status

5. Vault state = RUNNING
   └─► Member can use vault normally
```

### Terminate Operation

**⚠️ DESTRUCTIVE - IRREVERSIBLE**

Termination permanently destroys the vault and all associated data.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Terminate Flow                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Member initiates terminate in mobile app                       │
│     └─► Warning displayed: "This action is irreversible"           │
│     └─► Member confirms intent                                     │
│                                                                     │
│  2. Mobile app creates termination request                         │
│     └─► Request ID generated                                       │
│     └─► Pending confirmation via web                               │
│                                                                     │
│  3. Member must confirm in VettID web portal                       │
│     └─► Login to vettid.dev account                                │
│     └─► Navigate to Vault Services section                         │
│     └─► Final confirmation with warning                            │
│     └─► May require re-authentication                              │
│                                                                     │
│  4. Upon web confirmation - Connection Cleanup:                    │
│     └─► Vault Manager notified of pending termination              │
│     └─► Vault Manager triggers revocation for ALL connections      │
│     └─► Each connection receives revocation notification           │
│     └─► Connected vaults remove member from their contacts         │
│     └─► Wait for revocation confirmations (timeout: 5 min)         │
│                                                                     │
│  5. Vault Destruction:                                             │
│     └─► Vault Manager shuts down                                   │
│     └─► EC2 instance terminated                                    │
│     └─► All S3 backups deleted                                     │
│     └─► Namespace assignments released                             │
│     └─► Vault credential invalidated                               │
│                                                                     │
│  6. Vault state = TERMINATED                                       │
│     └─► Cannot be recovered                                        │
│     └─► Member may deploy new vault (fresh start)                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Two-Step Confirmation Required:**
1. Request termination in mobile app
2. Confirm termination in web portal

This prevents accidental termination from a compromised or misused mobile device.

**Connection Cleanup:**

All connections are properly revoked before vault destruction:
- Connected members receive revocation notifications
- Their vaults update contact status to "terminated"
- Prevents orphaned connections pointing to non-existent vault

### Subscription Expiry Auto-Stop

When a member's VettID subscription expires:

```
1. Subscription expires

2. 48-hour grace period begins
   └─► Member notified via app and email
   └─► Vault continues running normally
   └─► Member can renew subscription

3. After 48 hours (if not renewed):
   └─► Automatic backup performed
   └─► EC2 instance terminated
   └─► Vault state = STOPPED

4. Vault remains in STOPPED state
   └─► Backups retained for 30 days
   └─► Member can renew subscription and restart vault

5. 30-day backup retention after expiry
   └─► Member notified at 7 days and 1 day before deletion
   └─► After 30 days with no renewal, backups deleted
   └─► Member's vault data permanently removed
```

**Expired Subscription Timeline:**

| Day | Status | Action |
|-----|--------|--------|
| 0 | Subscription expires | Grace period begins, member notified |
| 2 | Grace period ends | Backup performed, vault terminated |
| 2-32 | Backups retained | Member can renew and restore |
| 25 | 7 days remaining | Reminder notification sent |
| 31 | 1 day remaining | Final warning notification sent |
| 32 | Retention expired | Backups deleted, data permanently removed |

### Billing Model

| Item | Cost |
|------|------|
| Active VettID subscription | Includes one vault or one appliance connection |
| Running vault (EC2) | Included in subscription |
| Stopped vault | No cost (backup storage minimal) |
| Backup storage (S3) | Included in subscription |
| Expired subscription backup retention | 30 days at no cost (grace period for renewal) |

**Note:** The VettID subscription covers all vault-related costs. There is no separate metering for vault runtime.

---

## 14. Security Model

### Defense Layers

| Layer | Protection |
|-------|-----------|
| **Network** | TLS for all communication (see TLS Configuration below) |
| **Application** | Additional encryption with exchanged keys |
| **Authentication** | Protean credentials (dual: services + vault) |
| **Authorization** | Namespace-based access control |
| **Storage** | Encrypted NATS, encrypted EBS (key in member's credential) |
| **Backup** | Asymmetric encryption (only member can decrypt) |
| **Instance** | No direct access (no SSH, no keys, no passwords) |

### TLS Configuration

All TLS connections must meet the following requirements:

| Setting | Requirement |
|---------|-------------|
| Minimum Version | TLS 1.3 (TLS 1.2 fallback only if required for compatibility) |
| TLS 1.3 Cipher Suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| TLS 1.2 Cipher Suites (fallback) | ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305 |
| Certificate Validation | Strict with OCSP stapling |
| HSTS | Enabled with minimum 1-year max-age |
| Certificate Pinning | Required for mobile app → Vault Services API, appliances → NATS |

### No Direct Access Model

Vault instances have **no direct access mechanism**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Vault Instance Security                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Blocked:                                                          │
│  ├── SSH (port 22 not open)                                        │
│  ├── No SSH keys installed                                         │
│  ├── No passwords configured                                       │
│  └── No SSM agent                                                  │
│                                                                     │
│  Allowed:                                                          │
│  ├── NATS connections (OwnerSpace, MessageSpace)                   │
│  ├── HTTPS egress (handler external calls, backups)                │
│  └── Control topic commands (Vault Services only)                  │
│                                                                     │
│  Recovery Model:                                                   │
│  └── Unresponsive vault? Restore from backup to new instance       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Zero attack surface for direct access attempts
- Nothing to steal (no credentials for access)
- Aligns with "cattle not pets" infrastructure model
- All actions auditable via NATS/control topic

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: Member's Mobile Device                            │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  VettID Mobile App                                            │ │
│  │  • Vault Services Credential (encrypted)                      │ │
│  │  • Vault Credential (encrypted, 4 versions: active + 3 backup)│ │
│  │  • LAT versions (for phishing detection)                      │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ TLS + App-layer encryption
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: VettID Cloud Services                             │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Vault Services API (with internal Ledger)                    │ │
│  │  • Request routing and token generation                       │ │
│  │  • Credential validation                                      │ │
│  │  • Can read secrets after user authenticates                  │ │
│  │    (for use in vault actions)                                 │ │
│  │  • Commands vault via control topic only                      │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ TLS + Namespace isolation
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: Member's Personal Vault                           │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Vault Instance (EC2 or Home Appliance)                       │ │
│  │  • NATS datastore with member's private data                  │ │
│  │  • Vault Manager processing events                            │ │
│  │  • Backup encryption key (public only)                        │ │
│  │  • No direct access (commands via control topic)              │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Security Properties

1. **Member-only decryption:** Backups encrypted so only member can decrypt
2. **Credential separation:** Vault Services and Vault use different credentials
3. **Namespace isolation:** Each member has dedicated OwnerSpace/MessageSpace
4. **No direct access:** All vault commands via OwnerSpace control topic
5. **Control topic security:** Operator-signed JWT required, write-only access
6. **WASM handler isolation:** Handlers sandboxed with explicit capability grants
7. **LAT phishing protection:** App verifies LAT version before proceeding

### Authentication TTL Model

Authentication uses a time-to-live (TTL) model rather than traditional sessions. All operations are atomic.

**Three Authentication Layers:**

| Layer | Scope | Default TTL | Purpose |
|-------|-------|-------------|---------|
| App Unlock | Mobile app access | N/A | PIN or biometric to open app |
| Vault Services Auth | API operations | 15 minutes | Actions via vault.vettid.dev |
| Vault Secret Access | Secret operations | 15 minutes | Handler access to secrets from credential |

**TTL Behavior:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Authentication TTL Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Vault Services API:                                               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. User authenticates with password                          │  │
│  │  2. TTL timer starts (default 15 minutes)                     │  │
│  │  3. User may perform API actions while TTL valid              │  │
│  │  4. After TTL expires, next API action requires re-auth       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Vault (via OwnerSpace):                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • App can communicate via OwnerSpace without authentication  │  │
│  │  • Vault may request authentication for sensitive operations: │  │
│  │    - Changing properties in datastore                         │  │
│  │    - Creating or accessing secrets                            │  │
│  │  • Secret access TTL starts when user authenticates to vault  │  │
│  │  • Handlers may request secrets while TTL valid               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Event Processing:                                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • If TTL valid when event received, vault processes event    │  │
│  │  • Next request requires re-authentication                    │  │
│  │  • No "session" state maintained between requests             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**User-Configurable Settings:**

| Setting | Default | Range | Location |
|---------|---------|-------|----------|
| Vault Services TTL | 15 min | 5-60 min | Account settings |
| Vault Secret TTL | 15 min | 5-60 min | Account settings |
| App unlock method | None | PIN / Biometric / None | App settings |

### Password Policy

All user passwords must meet the following requirements:

| Requirement | Value |
|-------------|-------|
| Minimum length | 12 characters |
| Strength test | Must pass reasonable strength evaluation (entropy check) |
| Common passwords | Rejected if found in common password lists |

### Audit Logging

VettID maintains three layers of audit logging:

**Layer 1: Member Activity Feed**

Members see their own activity in the mobile app feed:
- Handler executions and results
- Connection events (new, revoked)
- Backup completions
- Security events (authentication, secret access)

**Layer 2: VettID Operational Logging**

Internal logging for service operations:

| Event Category | Examples |
|----------------|----------|
| Admin Actions | "Admin X deprecated handler Y", "Admin Z approved service application" |
| System Health | "Vault ABC failed health check", "Backup service latency elevated" |
| Registry Operations | "Handler version 2.0.1 published", "Service XYZ suspended" |

**Layer 3: Security Event Logging**

Dedicated security monitoring for threat detection:

| Event Type | Purpose | Retention |
|------------|---------|-----------|
| Authentication failures | Detect brute force attempts | 90 days |
| Unusual access patterns | Detect compromised credentials | 90 days |
| Credential recovery attempts | Detect recovery phrase attacks | 1 year |
| Handler egress anomalies | Detect data exfiltration | 90 days |
| Admin privilege escalation | Detect insider threats | 1 year |

**Log Integrity:**
- All security logs include cryptographic hash chain
- Logs stored in append-only storage
- Regular integrity verification
- Segregated access (security team only)

### Vault Emergency

Members can suspend their vault immediately if they suspect compromise.

**Triggering Emergency Suspension:**

| Method | Access |
|--------|--------|
| Mobile App | Vault Settings → Emergency → Suspend Vault |
| Web Portal | Account → Vault Services → Vault Emergency |

**Emergency Suspension Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Vault Emergency Suspension                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Suspension (Immediate):                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Member triggers emergency via app or web portal           │  │
│  │  2. Vault Services sends suspend command to EC2               │  │
│  │  3. VM suspended (not terminated) - state preserved           │  │
│  │  4. Member notified of successful suspension                  │  │
│  │  5. Investigation can be performed on suspended state         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Note: Suspension does NOT revoke tokens. Events continue to       │
│  queue in OwnerSpace/MessageSpace and will be processed when       │
│  the vault resumes.                                                │
│                                                                     │
│  Resume (Requires Admin Approval):                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Member requests resume via account page                   │  │
│  │  2. Admin reviews request and any investigation findings      │  │
│  │  3. Admin approves or denies resume request                   │  │
│  │  4. If approved, vault returns to running state               │  │
│  │  5. Queued events processed normally                          │  │
│  │                                                                │  │
│  │  If actual incident confirmed:                                │  │
│  │  └─► Member advised to restore from recent backup             │  │
│  │  └─► Compromised vault terminated after backup confirmed      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Incident Response

**Member-Initiated Response:**

| Scenario | Member Action | VettID Response |
|----------|---------------|-----------------|
| Suspected compromise | Trigger Vault Emergency | Suspend VM, await admin review |
| Lost device | Credential recovery or remote wipe | Issue new credentials |
| Unauthorized transaction | Report via app | Investigate, advise on recovery |

**VettID-Initiated Response:**

| Trigger | Action | Member Notification |
|---------|--------|---------------------|
| Detected anomaly | Flag for review | None until confirmed |
| Confirmed threat | May suspend affected vaults | System notification + email |
| Handler vulnerability | Emergency handler update or removal | System notification |
| Platform breach | Incident response plan activation | Direct notification |

**Breach Notification:**

In the event of a platform-level security incident:
1. Affected members notified within 72 hours
2. Notification includes: scope, data affected, recommended actions
3. Published via System Notifications and direct email
4. Post-incident report published after resolution

### Legal / Law Enforcement Requests

VettID's architecture limits what can be provided in response to legal requests:

**What VettID CAN Provide:**

| Data Type | Description |
|-----------|-------------|
| Account metadata | Email, account creation date, last login |
| IP logs | Connection history to Vault Services API |
| Subscription history | Payment records, subscription status |
| Operational logs | Vault start/stop times, backup timestamps |

**What VettID CANNOT Provide:**

| Data Type | Reason |
|-----------|--------|
| Vault contents | Encrypted with member-held keys |
| Secrets | Never stored on VettID infrastructure |
| Message contents | End-to-end encrypted between vaults |
| Backup contents | Encrypted with member's backup key |
| Recovery phrase | Never transmitted to VettID |

**Process:**
1. Law enforcement provides valid legal process
2. VettID responds with available metadata (see above)
3. For vault data access, law enforcement must obtain cooperation from the member directly
4. VettID cannot decrypt member data even under compulsion

This architecture ensures member privacy while allowing VettID to comply with lawful requests for available metadata.

---

## 15. Service Registry Architecture

### Overview

The Service Registry is implemented as a **special connection** to each vault. This reuses the existing connection infrastructure while providing a secure, centralized source for two catalogs:

1. **Handler Catalog** - Event handler definitions and signed WASM packages
2. **Service Catalog** - Directory of VettID-enabled services (businesses, organizations, apps)

**Key constraint:** Each vault connects to exactly one Service Registry. This ensures a single trusted source for handler packages and simplifies security verification.

### Registry as a Connection

```
┌─────────────────────────────────────────────────────────────────────┐
│               Service Registry Connection Model                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Standard Connection                    Registry Connection         │
│  ┌──────────────────────┐              ┌──────────────────────┐    │
│  │ Invitation generated │              │ Invitation auto-     │    │
│  │ by member            │              │ generated for new    │    │
│  │                      │              │ vaults               │    │
│  │ Both parties must    │              │ Registry auto-accepts│    │
│  │ agree                │              │ (only user agrees)   │    │
│  │                      │              │                      │    │
│  │ Key exchange for     │              │ Access to registry's │    │
│  │ private messaging    │              │ public key for       │    │
│  │                      │              │ package verification │    │
│  └──────────────────────┘              └──────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Registry Connection Flow

```
1. New vault deployed/initialized

2. System auto-generates registry connection invitation
   └─► Registry MessageSpace URI + access token

3. Registry auto-accepts connection
   └─► No manual approval needed on registry side

4. User prompted to accept registry connection
   └─► User agrees to connect to registry

5. Vault retrieves registry profile
   └─► Includes registry's general public key

6. Vault stores registry public key
   └─► Used to verify all handler packages

7. Connection established
   └─► Vault can now browse/download handlers
```

### Handler Package Verification

All packages in the registry are signed with the registry's private key. Vaults verify packages using the public key from the registry's profile.

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Package Verification Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Registry Side:                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Handler package created                                   │  │
│  │  2. Package hash computed                                     │  │
│  │  3. Hash signed with registry private key                     │  │
│  │  4. Signature attached to package                             │  │
│  │  5. Package published to registry                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Vault Side (Download):                                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  1. Download package + signature                              │  │
│  │  2. Compute hash of downloaded package                        │  │
│  │  3. Verify signature using registry public key                │  │
│  │  4. If valid → Install package                                │  │
│  │  5. If invalid → Reject, alert user                           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Registry Profile Structure

```json
{
  "profile_version": "1.0",
  "type": "service_registry",
  "updated_at": "2024-12-04T12:00:00Z",
  "public_key": "ed25519:registry_public_key_base64...",
  "name": "VettID Service Registry",
  "description": "Official handler and service registry for VettID vaults",
  "endpoints": {
    "handler_catalog": "https://registry.vettid.dev/v1/handlers",
    "service_catalog": "https://registry.vettid.dev/v1/services",
    "packages": "https://registry.vettid.dev/v1/packages"
  }
}
```

### Handler Access Control

Handlers can have different access control models:

```
┌─────────────────────────────────────────────────────────────────────┐
│                Handler Access Control Models                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Option 1: Free (First-Party)                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Included with VettID subscription                         │  │
│  │  • No additional authorization required                      │  │
│  │  • manifest.access.type = "free"                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Option 2: Third-Party Authorization                               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Publisher distributes via registry                        │  │
│  │  • Member connects to publisher via MessageSpace             │  │
│  │  • Authorization negotiated directly (VettID not involved)   │  │
│  │  • See Section 10.8 for full authorization model             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Option 3: External API Key (Third-Party Services)                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  • Handler integrates with external service (e.g., payment)  │  │
│  │  • User obtains API key from third-party directly            │  │
│  │  • Key stored in vault secrets or handler_data               │  │
│  │  • Handler uses key when calling external APIs               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Registry Hosting Recommendation

Given security requirements and the connection-based model:

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                   Registry Infrastructure                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Registry Service                           │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  MessageSpace Namespace (ms.vettid.dev/registry)        │ │  │
│  │  │  • Profile topic (public key, endpoints)                │ │  │
│  │  │  • Catalog updates (new/updated handlers)               │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  Catalog API (registry.vettid.dev)                      │ │  │
│  │  │  • GET /v1/catalog - List all handlers                  │ │  │
│  │  │  • GET /v1/catalog/{handler_id} - Handler details       │ │  │
│  │  │  • GET /v1/packages/{handler_id}/{version} - Download   │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  Package Storage (S3 + CloudFront)                      │ │  │
│  │  │  • Signed packages for appliance download               │ │  │
│  │  │  • Versioned storage                                    │ │  │
│  │  │  • Geographic distribution for low latency              │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  Signing Service (Lambda + KMS)                         │ │  │
│  │  │  • Registry private key in KMS                          │ │  │
│  │  │  • Signs packages on publish                            │ │  │
│  │  │  • Audit trail of all signatures                        │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  Subscription Verification (Lambda + DynamoDB)          │ │  │
│  │  │  • Verify vault subscription status                     │ │  │
│  │  │  • Gate premium package downloads                       │ │  │
│  │  │  • Token validation for premium handlers                │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Security Properties:**
- Registry private key stored in KMS (never exposed)
- All packages signed before distribution
- Subscription verification before premium access
- Connection-based trust (vault trusts registry via connection flow)
- Audit logging for all package downloads

### Registry Administration

The Service Registry (both handler catalog and service catalog) is managed through a dedicated section of the VettID Admin Portal.

**Admin Portal Access:**

| Role | Handler Catalog | Service Catalog | Access Level |
|------|-----------------|-----------------|--------------|
| Full Admin | Full access | Full access | Create, update, deprecate, remove |
| Limited Admin | No access | No access | — |
| Support | Read-only | Read-only | View only |

**Handler Catalog Management:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Handler Catalog Admin Functions                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  • Upload new handler packages (triggers signing)                  │
│  • Update handler metadata (description, capabilities, egress)     │
│  • Deprecate handler versions (warn users, block new installs)     │
│  • Remove handlers (emergency use only, affects installed users)   │
│  • Review and approve third-party handler submissions              │
│  • Manage handler categories and tags                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Third-Party Handler Certification Process:**

All third-party handlers must complete certification before being added to the registry:

```
┌─────────────────────────────────────────────────────────────────────┐
│              Handler Certification Pipeline                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Stage 1: Submission                                               │
│  └─► Publisher submits handler package + documentation             │
│  └─► Publisher provides source code for review                     │
│  └─► Publisher signs developer agreement                           │
│                                                                     │
│  Stage 2: Code Review                                              │
│  └─► Security review of WASM source code                           │
│  └─► Verify no malicious data exfiltration patterns                │
│  └─► Verify egress destinations are legitimate and necessary       │
│  └─► Review memory and resource usage                              │
│                                                                     │
│  Stage 3: Testing                                                  │
│  └─► Automated security scanning                                   │
│  └─► Functional testing in sandbox environment                     │
│  └─► Performance and resource consumption testing                  │
│  └─► Verify manifest accuracy (permissions match behavior)         │
│                                                                     │
│  Stage 4: Approval                                                 │
│  └─► Two-person approval required for new handlers                 │
│  └─► Handler signed with registry key (stored in KMS)              │
│  └─► Published to registry with "Certified" status                 │
│                                                                     │
│  Ongoing: Updates                                                  │
│  └─► Handler updates require re-review if:                         │
│      • New egress destinations added                               │
│      • Permission scope increased                                  │
│      • Major version change                                        │
│  └─► Minor updates (bug fixes) require expedited review            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Registry Signing Key Security:**
- Registry private key stored exclusively in AWS KMS
- Key never exported or accessible outside KMS
- All signing operations performed via KMS API
- Key rotation plan documented for compromise scenarios

**Service Catalog Management:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Service Catalog Admin Functions                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  • Add new VettID-enabled services                                 │
│  • Update service profiles and metadata                            │
│  • Manage verification status (Unverified → Verified → Certified)  │
│  • Review and approve service applications                         │
│  • Suspend or remove services (policy violations)                  │
│  • Manage service categories and search tags                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Audit Trail:**

All registry administration actions are logged with:
- Admin user identity
- Action performed
- Timestamp
- Before/after state (for modifications)
- Approval chain (for sensitive actions)

### System Notifications

The Service Registry provides a channel for broadcasting system-wide notifications to all vaults.

**Notification Types:**

| Type | Purpose | Example |
|------|---------|---------|
| Security Alert | Critical security information | "Update app to v2.5.0 to patch vulnerability" |
| Maintenance | Planned service events | "Scheduled maintenance Dec 15, 2-4 AM UTC" |
| Feature Announcement | New capabilities | "New handler category: Healthcare" |
| Policy Update | Terms or policy changes | "Updated privacy policy effective Jan 1" |

**Delivery Mechanism:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                  System Notification Flow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Admin posts system notification via Admin Portal               │
│     └─► Notification stored in Registry                            │
│                                                                     │
│  2. Registry publishes to its MessageSpace                         │
│     └─► system_notifications topic                                 │
│                                                                     │
│  3. All connected vaults receive notification                      │
│     └─► Stored in local feed                                       │
│                                                                     │
│  4. Mobile app displays notification to member                     │
│     └─► Priority based on notification type                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Members automatically see system notifications in their app without any action required.

### VettID-Enabled Services

In addition to event handlers, the Service Registry maintains a catalog of **VettID-enabled services**—businesses and organizations that leverage VettID's secure communication infrastructure to interact with members.

**Benefits of VettID-Enabled Services:**

| Benefit | Description |
|---------|-------------|
| **No phishing** | All communication via authenticated MessageSpace channels |
| **No spoofing** | Service identity cryptographically verified |
| **No smishing** | SMS-based attacks eliminated via secure in-app messaging |
| **On-demand data** | Services access data from vault without storing it locally |
| **Secure authentication** | "Login with VettID" replaces passwords |
| **Transaction authorization** | Real-time approval requests via secure channel |

**Service Catalog Structure:**

```json
{
  "service_id": "acme-bank",
  "name": "ACME National Bank",
  "category": "financial_services",
  "subcategory": "retail_banking",
  "description": "Full-service retail and commercial banking",
  "messagespace_guid": "abc123-def456-...",
  "verified": true,
  "verified_at": "2024-11-01T00:00:00Z",
  "website": "https://acmebank.com",
  "logo_url": "https://registry.vettid.dev/logos/acme-bank.png",
  "supported_features": [
    "login_with_vettid",
    "transaction_authorization",
    "secure_messaging",
    "document_delivery"
  ]
}
```

### Connection Contracts

When a member wants to connect with a VettID-enabled service, the service's profile includes a **connection contract** specifying what data is required to establish the relationship.

**Connection Contract Structure:**

```json
{
  "contract_version": "1.0",
  "service_id": "acme-bank",
  "contract_type": "account_opening",
  "description": "Requirements for opening a personal checking account",
  "required_data": [
    {
      "field": "legal_name",
      "source": "private_data",
      "purpose": "Account holder identification",
      "access": "on_demand"
    },
    {
      "field": "date_of_birth",
      "source": "private_data",
      "purpose": "Identity verification",
      "access": "on_demand"
    },
    {
      "field": "ssn",
      "source": "secrets",
      "purpose": "Tax reporting and identity verification",
      "access": "one_time"
    },
    {
      "field": "address",
      "source": "private_data",
      "purpose": "Account statements and correspondence",
      "access": "on_demand"
    },
    {
      "field": "email",
      "source": "private_data",
      "purpose": "Account notifications",
      "access": "on_demand"
    }
  ],
  "terms_url": "https://acmebank.com/terms",
  "privacy_url": "https://acmebank.com/privacy"
}
```

**Data Access Types:**

| Access Type | Description |
|-------------|-------------|
| `on_demand` | Service can request current value anytime (data stays in vault) |
| `one_time` | Service receives value once during connection setup |
| `snapshot` | Service receives value at connection time, updated on change |

**Connection Contract Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Service Connection Contract Flow                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Discovery                                                      │
│     └─► Member browses Service Catalog                             │
│     └─► Finds desired service (e.g., ACME Bank)                    │
│     └─► Reviews service profile and connection contract            │
│                                                                     │
│  2. Contract Review                                                │
│     └─► App displays required data fields                          │
│     └─► Shows purpose for each field                               │
│     └─► Indicates access type (on_demand, one_time, etc.)          │
│     └─► Links to service's terms and privacy policy                │
│                                                                     │
│  3. Data Verification                                              │
│     └─► App checks member's datastore for required fields          │
│     └─► Highlights any missing data                                │
│     └─► Member adds missing data if needed                         │
│                                                                     │
│  4. Member Agreement                                               │
│     └─► Member agrees to provide specified data                    │
│     └─► Member accepts service's terms                             │
│     └─► Connection request sent to service                         │
│                                                                     │
│  5. Service Agreement                                              │
│     └─► Service receives connection request                        │
│     └─► Service performs any required verification                 │
│     └─► Service accepts or rejects connection                      │
│                                                                     │
│  6. Connection Established                                         │
│     └─► Key exchange completed                                     │
│     └─► Connection contract stored in member's datastore           │
│     └─► Service can now communicate via secure channel             │
│     └─► Service can request on_demand data per contract            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Login with VettID

VettID-enabled services can offer **"Login with VettID"** as a secure, passwordless authentication method.

**Authentication Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Login with VettID Flow                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. User visits service website/app                                │
│     └─► Enters VettID identity (email, username, or account #)     │
│     └─► Clicks "Login with VettID"                                 │
│                                                                     │
│  2. Service initiates login request                                │
│     └─► Sends authentication request via MessageSpace              │
│     └─► Request includes: service identity, timestamp, nonce       │
│     └─► Optionally includes OTP for display on website             │
│                                                                     │
│  3. User receives request in VettID app                            │
│     └─► App shows: "ACME Bank wants to log you in"                 │
│     └─► Displays OTP to verify (e.g., "Enter code: 847293")        │
│     └─► User verifies OTP matches website and approves             │
│                                                                     │
│  4. Authentication response                                        │
│     └─► User's vault signs authentication confirmation             │
│     └─► Response sent to service via MessageSpace                  │
│                                                                     │
│  5. Session established                                            │
│     └─► Service verifies signature                                 │
│     └─► User logged in without password                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Security Properties:**
- No passwords to phish or steal
- OTP verification prevents man-in-the-middle attacks
- Cryptographic proof of user intent
- All requests via authenticated MessageSpace channel

### Transaction Authorization

Services can request real-time authorization for sensitive actions.

**Authorization Request Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Transaction Authorization Flow                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. User initiates transaction on service website/app              │
│     └─► e.g., "Transfer $500 to Bob Smith"                         │
│                                                                     │
│  2. Service sends authorization request                            │
│     └─► Request via MessageSpace                                   │
│     └─► Includes: action type, amount, recipient, timestamp        │
│                                                                     │
│  3. User receives request in VettID app                            │
│     └─► App shows transaction details                              │
│     └─► "ACME Bank: Authorize transfer of $500 to Bob Smith?"      │
│     └─► User reviews and approves/denies                           │
│                                                                     │
│  4. Authorization response                                         │
│     └─► User's vault signs authorization (approve or deny)         │
│     └─► Response sent to service                                   │
│                                                                     │
│  5. Transaction completes                                          │
│     └─► Service executes or cancels based on response              │
│     └─► Confirmation sent to user via MessageSpace                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Use Cases:**
- Bank transfers and payments
- Large purchases
- Subscription changes
- Document signing requests
- Two-factor authentication replacement

### On-Demand Data Access

For fields with `on_demand` access in the connection contract, services request current data as needed rather than storing it locally. This eliminates the need for "update your information" requests—services always get current data directly from the member's vault.

**On-Demand Data Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              On-Demand Data Request Flow                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Service needs data (e.g., current address for statement)       │
│                                                                     │
│  2. Service sends data request via MessageSpace                    │
│     └─► Request specifies: field name, purpose, contract reference │
│                                                                     │
│  3. Vault receives request                                         │
│     └─► Verifies request matches connection contract               │
│     └─► Verifies field has on_demand access granted                │
│                                                                     │
│  4. Data returned automatically                                    │
│     └─► No user interaction required (pre-authorized by contract)  │
│     └─► Current value sent to service                              │
│     └─► Request logged in vault for member visibility              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Member Visibility:**
- All on-demand data requests logged in vault
- Member can view access history in app
- Member can revoke contract at any time (terminates connection)

### Profile Sync and Auto-Updating Contacts

When a connection updates their public profile (e.g., changes their phone number), the updated data automatically propagates to all connected vaults.

**Profile Sync Flow:**

```
┌─────────────────────────────────────────────────────────────────────┐
│              Connection Profile Sync                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Connection updates their public profile                        │
│     └─► e.g., New phone number, address change                     │
│                                                                     │
│  2. Updated profile published to MessageSpace ownerProfile topic   │
│                                                                     │
│  3. Connected vaults receive profile update notification           │
│     └─► Via periodic sync or push notification                     │
│                                                                     │
│  4. Vault updates cached contact in local datastore                │
│     └─► contacts topic updated with new profile data               │
│                                                                     │
│  5. Member sees updated contact info in app                        │
│     └─► Auto-updating contact list, no manual updates needed       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Contact list always current without manual updates
- Services with on_demand contracts automatically get current data
- No need for "update your information" requests
- Changes propagate to all connections simultaneously

### Service Verification

Services in the catalog can be **verified** by VettID to confirm their legitimacy.

| Verification Level | Description |
|--------------------|-------------|
| **Unverified** | Service listed but not reviewed by VettID |
| **Verified** | VettID has confirmed business identity and legitimacy |
| **Certified** | Verified + meets additional security/privacy standards |

Verified and certified services display badges in the Service Catalog to help members make informed decisions.

---

## 16. NATS Authentication Model

### Overview

The central NATS infrastructure (os.vettid.dev, ms.vettid.dev) uses NATS' native NKey/JWT authentication system.

### Hierarchy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NATS Trust Hierarchy                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Operator (VettID)                                                 │
│  └─► Operator NKey controls entire NATS infrastructure             │
│  └─► Issues Account JWTs                                           │
│                                                                     │
│      ├── Account: OwnerSpace.{member_guid}                         │
│      │   └─► Account NKey held by member's vault                   │
│      │   └─► Vault can issue User JWTs for:                        │
│      │       ├── Mobile app (read/write specific topics)           │
│      │       └── Refresh tokens as needed                          │
│      │                                                              │
│      ├── Account: MessageSpace.{member_guid}                       │
│      │   └─► Account NKey held by member's vault                   │
│      │   └─► Vault can issue User JWTs for:                        │
│      │       ├── Connections (write forOwner, read ownerProfile)   │
│      │       └── Token refresh on maintenance cycle                │
│      │                                                              │
│      └── Account: MessageSpace.registry                            │
│          └─► Account NKey held by registry service                 │
│          └─► Vaults connect as users to retrieve profile           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Vault NKey Operations

When a vault is provisioned, it receives:

1. **OwnerSpace Account NKey** - Controls `OwnerSpace.{member_guid}`
2. **MessageSpace Account NKey** - Controls `MessageSpace.{member_guid}`

With these NKeys, the vault can:

```python
# Pseudocode for vault JWT generation

from nats_jwt import AccountClaims, UserClaims
from nkeys import create_user

def generate_mobile_app_token(ownerspace_account_nkey, duration_hours=24):
    """Generate a JWT for the mobile app to access OwnerSpace"""
    
    # Create user keypair for this session
    user_kp = create_user()
    user_pub = user_kp.public_key()
    
    # Create user claims with specific permissions
    user_claims = UserClaims(user_pub)
    user_claims.name = "mobile_app"
    user_claims.expires = now() + timedelta(hours=duration_hours)
    
    # Grant permissions
    user_claims.permissions.pub.allow = [
        f"OwnerSpace.{member_guid}.forVault"
    ]
    user_claims.permissions.sub.allow = [
        f"OwnerSpace.{member_guid}.forApp",
        f"OwnerSpace.{member_guid}.eventTypes"
    ]
    
    # Sign with account NKey
    user_jwt = user_claims.encode(ownerspace_account_nkey)
    
    return {
        "jwt": user_jwt,
        "seed": user_kp.seed(),
        "expires_at": user_claims.expires
    }

def generate_connection_token(messagespace_account_nkey, connection_id, duration_hours=168):
    """Generate a JWT for a connection to access MessageSpace"""
    
    user_kp = create_user()
    user_pub = user_kp.public_key()
    
    user_claims = UserClaims(user_pub)
    user_claims.name = f"connection_{connection_id}"
    user_claims.expires = now() + timedelta(hours=duration_hours)
    
    # Grant permissions (read profile, write messages)
    user_claims.permissions.pub.allow = [
        f"MessageSpace.{member_guid}.forOwner"
    ]
    user_claims.permissions.sub.allow = [
        f"MessageSpace.{member_guid}.ownerProfile"
    ]
    
    user_jwt = user_claims.encode(messagespace_account_nkey)
    
    return {
        "jwt": user_jwt,
        "seed": user_kp.seed(),
        "expires_at": user_claims.expires
    }
```

### Namespace Assignment Timing

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Namespace Lifecycle                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Vault Services Enrollment                                      │
│     └─► Member enrolls with Vault Services                       │
│     └─► System reserves member GUID                                │
│                                                                     │
│  2. Pre-Deployment (before vault exists)                           │
│     └─► OwnerSpace.{member_guid} account created                   │
│     └─► MessageSpace.{member_guid} account created                 │
│     └─► Account NKeys generated                                    │
│     └─► NKeys stored encrypted (awaiting vault)                    │
│                                                                     │
│  3. Vault Deployment                                               │
│     └─► EC2/Appliance initialized                                  │
│     └─► Account NKeys delivered to vault                           │
│     └─► NKeys stored in vault's local NATS                         │
│     └─► Namespaces now "locked" to this vault                      │
│                                                                     │
│  4. Operational                                                    │
│     └─► Vault uses NKeys to issue JWTs                             │
│     └─► Mobile app connects with issued JWTs                       │
│     └─► Connections access MessageSpace with issued JWTs           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 17. Backup Key Rotation

### Policy-Driven Rotation

Backup key rotation is controlled by policy settings in the Vault Services credential.

```json
{
  "backup_policy": {
    "rotation_interval_days": 90,
    "last_rotated": "2024-09-01T00:00:00Z",
    "rotation_due": "2024-12-01T00:00:00Z"
  }
}
```

### Rotation Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Backup Key Rotation Flow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Trigger: User logs in AND rotation_due < now()                    │
│                                                                     │
│  1. Generate new backup key pair                                   │
│     └─► New private key                                            │
│     └─► New public key                                             │
│                                                                     │
│  2. Update Vault Services Credential                               │
│     └─► Set new private key as active                              │
│     └─► Move current active key to previous                        │
│     └─► Discard any older keys (only keep 2)                       │
│     └─► Update last_rotated timestamp                              │
│     └─► Calculate new rotation_due date                            │
│                                                                     │
│  3. Update Vault                                                   │
│     └─► Send new public key to vault                               │
│     └─► Vault starts using new key for future backups              │
│                                                                     │
│  4. Key Retention (2 keys only)                                    │
│     └─► Active key: Used for new backups                           │
│     └─► Previous key: Retained for decrypting older backups        │
│     └─► With daily backups and 90-day rotation, backups never      │
│         span more than 1 rotation                                  │
│     └─► 2 keys sufficient to decrypt any retained backup           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Credential Structure (Two Backup Keys)

Only two backup keys are maintained: the active key and the previous key. With daily backups (last 3 retained) and 90-day key rotation, backups never span more than one rotation cycle.

```json
{
  "backup_keys": {
    "active": {
      "key_id": "bk_002",
      "private_key": "ed25519:...",
      "created_at": "2024-12-01T00:00:00Z"
    },
    "previous": {
      "key_id": "bk_001",
      "private_key": "ed25519:...",
      "created_at": "2024-09-01T00:00:00Z"
    }
  },
  "backup_policy": {
    "rotation_interval_days": 90,
    "last_rotated": "2024-12-01T00:00:00Z",
    "rotation_due": "2025-03-01T00:00:00Z"
  }
}
```

**Why 2 Keys Suffice:**

| Factor | Value | Implication |
|--------|-------|-------------|
| Backup frequency | Daily | New backups created every day |
| Backups retained | Last 3 | Max 3 days of backup history |
| Key rotation | Every 90 days | Keys change quarterly |
| Max backup age | 3 days | Never spans a rotation boundary |

---

## 18. Connection Revocation

### Single-Party Revocation

Either party can revoke a connection unilaterally.

### Revocation Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Connection Revocation Flow                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Member A revokes connection to Member B:                          │
│                                                                     │
│  1. A initiates revocation in mobile app                           │
│                                                                     │
│  2. A's vault processes revocation:                                │
│     └─► Stores connection identifier in revoked_connections        │
│     └─► Invalidates B's MessageSpace token                         │
│     └─► Deletes connection keys (by keyID)                         │
│     └─► Removes B's full profile from contacts                     │
│     └─► Clears any cached data related to B                        │
│                                                                     │
│  3. A's vault sends revocation notice to B:                        │
│     └─► Uses existing MessageSpace token (one last time)           │
│     └─► Notification includes: connection_id, revocation reason    │
│                                                                     │
│  4. B's vault receives notification:                               │
│     └─► Stores connection identifier in revoked_connections        │
│     └─► Invalidates A's MessageSpace token                         │
│     └─► Deletes connection keys (by keyID)                         │
│     └─► Removes A's full profile from contacts                     │
│     └─► Clears any cached data related to A                        │
│     └─► Notifies B's mobile app of revocation                      │
│                                                                     │
│  5. Connection fully severed                                       │
│     └─► Neither party can message the other                        │
│     └─► Keys destroyed on both sides                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Data Retention After Revocation:**

Both parties retain their history of interactions with the revoked connection:

| Data | Retained | Location |
|------|----------|----------|
| Past messages/events | Yes | Feed or archived_events in local datastore |
| Connection identifier | Yes | revoked_connections topic in local datastore |
| Connection contract (if service) | Yes | handler_data in local datastore |
| Full contact profile | No | Removed from contacts |
| Connection keys | No | Destroyed on both sides |

**Connection Identifier (Retained):**

A minimal identifier is preserved in the `revoked_connections` topic to maintain context for historical interactions:

```json
{
  "connection_id": "conn_abc123",
  "guid": "member-guid-xyz",
  "display_name": "Bob Smith",
  "email": "bob@example.com",
  "revoked_at": "2024-12-04T12:00:00Z",
  "revoked_by": "self"
}
```

This ensures members can identify who they interacted with (e.g., "You transferred $500 to Bob Smith on Nov 15") without retaining full profile details. Events in feed and archived_events reference the connection_id, which can be looked up in revoked_connections for display purposes.

### Revocation Notification Structure

```json
{
  "type": "connection_revocation",
  "connection_id": "conn_abc123",
  "key_id": "key_xyz789",
  "revoked_by": "initiator",
  "revoked_at": "2024-12-04T12:00:00Z",
  "reason": "user_requested"
}
```

### Handling Offline Vaults

If the other party's vault is offline when revocation occurs:

1. Revocation notice queued in their MessageSpace
2. Notice delivered when vault comes online
3. Initiating vault immediately clears its local data
4. Tokens invalidated immediately (other party can't connect even if they try)

---

## 19. Open Questions

All major architectural and operational questions have been resolved.

### Resolved in This Version

| Question | Resolution |
|----------|------------|
| Vault Stop | Backup performed, then EC2 deleted. "Stopped" vault is a backup ready to restore. |
| Vault Terminate | Destructive. Removes all data including backups. Requires app request + web confirmation. |
| Manual Backup | Available via mobile app. Vault Manager coalesces, encrypts, uploads, reports status. |
| Billing Model | Included in VettID subscription. One vault or appliance + backups per subscription. |
| Auto-Stop | 48 hours after subscription expires. Backup performed before stop. |
| Event Handler Model | Local WASM execution on vault (no Lambda). Unified model for cloud and appliance. |

### Deferred Questions

1. **Home Appliance Details** - Manufacturing, distribution, and support model to be determined later.

---

## Document Metadata

| Field | Value |
|-------|-------|
| **Version** | 3.3 |
| **Created** | December 4, 2024 |
| **Last Updated** | December 6, 2024 |
| **Status** | Architecture Design |
| **Classification** | CONFIDENTIAL |
| **Dependencies** | Protean Credential System Design v4.6 |

### Change Log

- **v3.3** - VettID-enabled services, reliability, security, and operational refinements:
  - Added VettID Admin Portal component (Section 2.2)
  - Added Credential Backup Service (Section 2.7) with BIP-39 recovery phrase and Argon2id
  - Added single device policy documentation
  - Added Vault health monitoring (memory, disk, CPU, zombie processes, time sync)
  - Added Authentication TTL Model (configurable TTL for API and secret access)
  - Added TLS Configuration requirements (TLS 1.3, cipher suites, certificate pinning)
  - Added Password Policy (12 char minimum, strength test)
  - Added Audit Logging (3 layers: member feed, operational, security events)
  - Added Vault Emergency feature (suspend/resume with admin approval)
  - Added Incident Response procedures
  - Added Third-Party Handler Certification Process (code review, testing, two-person approval)
  - Added Registry Signing Key Security documentation
  - Added Registry Administration section with role-based access
  - Added System Notifications via Service Registry
  - Added Profile Sync and Auto-Updating Contacts section
  - Added revoked_connections topic for historical context after connection revocation
  - Added Vault Credential versioning (4 versions: 1 active + 3 for backup compatibility)
  - Expanded appliance backup/restore (Section 11.4): local backup, cloud backup, cloud restore, local restore
  - Added Vault Services appliance backup endpoints for S3 upload/download
  - Added error handling and retry logic (backup failures, handler timeouts, network interruption)
  - Added Data Portability section for VettID-compliant provider migration
  - Added Schema Versioning approach (additive changes only)
  - Added handler version compatibility (min_app_version, min_vault_version in manifest)
  - Updated backup key rotation to maintain only 2 keys (active + previous)
  - Clarified on-demand data eliminates "update your information" requests
  - Removed account changes from transaction authorization (handled by on-demand data)
  - Added backup retention policy (last 3 backups, 30-day expiry retention)
  - Added Automatic Backup Verification (every other backup, temp instance integrity check)
  - Added Handler Version Selection and Rollback capability
  - Added API Versioning Strategy for Vault Services
  - Added Data Residency section (current: US AWS, future considerations)
  - Added Time Synchronization requirements (AWS NTP, drift detection)
  - Added Resource Limits guidance (datastore 10-20GB typical, soft limits)
  - Added Offline Operation documentation for mobile app
  - Added App Distribution channels (Play Store, F-Droid, GitHub, source builds)
  - Added Estate/Inheritance Access guidance
  - Added Legal/Subpoena Response documentation
  - Updated Terminate Operation with connection cleanup flow
  - Various corrections throughout document
- **v3.2** - Third-party handler authorization and refinements:
  - Added third-party handler authorization model (Section 10.8)
  - Publishers negotiate directly with members via MessageSpace
  - Authorization tokens with multiple models (perpetual, subscription, per_use, permission)
  - Token revocation via publisher profile
  - Added handler update check model (Section 10.9) - push notifications, startup check, manual re-sync
  - Updated manifest structure with publisher and access fields
  - Various diagram and terminology corrections throughout
- **v3.1** - Control topic and security updates:
  - Added OwnerSpace control topic for Vault Services → Vault commands
  - No direct access model (no SSH, no keys, no passwords)
  - Operator-signed JWT for control topic authorization
  - Updated Security Model with no direct access details
- **v3.0** - Major updates:
  - Unified handler model: WASM-based local execution for both cloud and appliance
  - Added Section 13: Vault Lifecycle (stop/start/terminate operations)
  - Updated backup system with manual backup capability
  - Resolved all operational questions (billing, auto-stop, etc.)
  - Removed Lambda/VPC complexity in favor of local WASM execution
- **v2.0** - Added sections 15-18 covering:
  - Service Registry Architecture (registry as special connection)
  - NATS Authentication Model (NKey/JWT hierarchy)
  - Backup Key Rotation (policy-driven)
  - Connection Revocation (single-party revocation flow)
  - Resolved all major open questions
- **v1.0** - Initial draft with core architecture

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **CEK** | Credential Encryption Key - rotates after each authentication |
| **TK** | Transaction Key - rotates after each use for forward secrecy |
| **LAT** | Ledger Authentication Token - prevents phishing attacks |
| **NATS** | Messaging system used as datastore and communication layer |
| **JetStream** | NATS persistence layer for durable message storage |
| **NKey** | Ed25519-based identity key used in NATS authentication |
| **Account NKey** | NKey that controls a NATS namespace and can issue User JWTs |
| **User JWT** | JSON Web Token granting specific pub/sub permissions in NATS |
| **OwnerSpace** | Namespace for app↔vault communication (os.vettid.dev) |
| **Control Topic** | OwnerSpace topic for Vault Services → vault system commands |
| **MessageSpace** | Namespace for receiving connection messages (ms.vettid.dev) |
| **Vault Manager** | Service on vault that processes events |
| **WASM** | WebAssembly - portable binary format for sandboxed execution |
| **WASI** | WebAssembly System Interface - capability-based system access |
| **Event Handler** | WASM module that performs actions on member's behalf |
| **Service Registry** | Special connection providing handler catalog and service catalog |
| **Admin Portal** | Internal administration interface for VettID staff to manage registries and support members |
| **Publisher** | Third party that creates and distributes handlers via the Service Registry |
| **Authorization Token** | Signed token from publisher granting member access to third-party handler |
| **VettID-Enabled Service** | Business or organization that uses VettID for secure communication with members |
| **Connection Contract** | Agreement specifying data requirements and access permissions for a service connection |
| **Revoked Connection** | Minimal identifier retained after connection revocation for historical context |
| **keyID** | Unique identifier for per-connection encryption keys |
| **Connection** | Established trust relationship between two vault members |
| **TPM** | Trusted Platform Module - hardware security for home appliances |
| **Argon2id** | Memory-hard key derivation function used for recovery phrase encryption |
| **BIP-39** | Bitcoin Improvement Proposal 39 - standard for mnemonic recovery phrases |
| **TTL** | Time-To-Live - duration for which authentication remains valid |
| **Vault Emergency** | Member-initiated suspension of vault for suspected compromise |
| **KMS** | AWS Key Management Service - stores registry signing key |

---

## Appendix B: Related Documents

1. **Protean Credential System Design** - Core authentication system
2. **Threat Analysis** - Attack vectors and mitigations
3. **VettID Integration Points** - Web app and API integration details
