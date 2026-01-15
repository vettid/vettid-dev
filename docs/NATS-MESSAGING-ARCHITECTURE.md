# VettID NATS Messaging Architecture

This document defines the NATS messaging patterns, topic structure, permissions, and flows used in the VettID system.

## Table of Contents

1. [Overview](#overview)
2. [Trust Hierarchy](#trust-hierarchy)
3. [Topic Namespaces](#topic-namespaces)
4. [Topic Permissions by Client](#topic-permissions-by-client)
5. [Control Architecture (Multi-Tenant)](#control-architecture-multi-tenant)
6. [Enrollment Flow](#enrollment-flow)
7. [PIN Setup Flow](#pin-setup-flow)
8. [Handler Execution Flow](#handler-execution-flow)
9. [Broadcast System](#broadcast-system)
10. [Message Encryption](#message-encryption)
11. [Security Considerations](#security-considerations)
12. [Resource Limits](#resource-limits)
13. [Topic Reference Table](#topic-reference-table)

---

## Overview

VettID uses NATS for real-time, secure communication between:
- **Mobile App** ↔ **Vault Instance** (user commands and responses)
- **Backend Services** → **Vault Instances** (control commands, broadcasts)
- **Vault** ↔ **Vault** (call signaling between members)
- **Connections** → **Vault** (messages from other members)

### Two NATS Deployments

| Deployment | Domain | Purpose |
|------------|--------|---------|
| Central NATS (OwnerSpace) | os.vettid.dev | App ↔ Vault communication |
| Central NATS (MessageSpace) | ms.vettid.dev | Cross-vault messaging |

---

## Trust Hierarchy

```
Operator: VettID (holds operator signing key)
├── Account: OwnerSpace.{member_guid}
│   └── Users: Mobile App, Vault Instance
├── Account: MessageSpace.{member_guid}
│   └── Users: Vault Instance, Connection Tokens
└── System Accounts
    ├── ServiceRegistry (admin broadcasts)
    └── VaultServices (control commands)
```

---

## Topic Namespaces

### OwnerSpace Namespace

**Purpose:** Secure bidirectional communication between mobile app and their vault instance.

```
OwnerSpace.{member_guid}/
├── forVault.>        # App → Vault: Commands from mobile app
├── forApp.>          # Vault → App: Responses to app
├── eventTypes        # Vault → App: Handler definitions (read-only)
├── forServices.>     # Vault → Backend: Health/status messages
└── call.>            # Vault ↔ Vault: Call signaling
```

> **NOTE:** Control commands use the `Control.*` namespace.
> See [Control Architecture (Multi-Tenant)](#control-architecture-multi-tenant) for details.

### MessageSpace Namespace

**Purpose:** Receive messages from connections and publish member's public profile.

```
MessageSpace.{member_guid}/
├── forOwner.>        # Connections → Vault: Inbound messages
├── ownerProfile      # Vault → Public: Member's public profile
└── call.>            # Vault ↔ Vault: Call signaling
```

### Topic Naming Conventions

| Prefix | Direction | Publisher | Subscriber |
|--------|-----------|-----------|------------|
| `forVault` | → | App | Vault |
| `forApp` | ← | Vault | App |
| `forOwner` | → | Connections | Vault |
| `forServices` | → | Vault | Backend |

**CRITICAL:** The naming convention is consistent:
- `forVault.*` = messages TO the vault
- `forApp.*` = messages TO the app
- `forOwner.*` = messages TO the vault from connections

> **Note:** Control commands use the separate `Control.*` namespace, not `OwnerSpace.*.control`.

---

## Topic Permissions by Client

### Mobile App Permissions

**Credential Type:** User JWT
**Lifetime:** 24 hours (must refresh before expiry)

```json
{
  "permissions": {
    "pub": ["OwnerSpace.{member_guid}.forVault.>"],
    "sub": [
      "OwnerSpace.{member_guid}.forApp.>",
      "OwnerSpace.{member_guid}.eventTypes"
    ]
  }
}
```

| Topic | Permission | Purpose |
|-------|------------|---------|
| `OwnerSpace.{guid}.forVault.>` | **Publish** | Send commands to vault |
| `OwnerSpace.{guid}.forApp.>` | Subscribe | Receive responses |
| `OwnerSpace.{guid}.eventTypes` | Subscribe | Get handler definitions |

**Explicitly Denied:**
- `$SYS.>`, `$JS.>`, `_INBOX.>` (system topics)
- `Broadcast.>` (only vaults can subscribe)
- Cross-namespace access

### Vault Instance Permissions

**Credential Type:** User JWT
**Lifetime:** 24 hours

```json
{
  "permissions": {
    "pub": [
      "OwnerSpace.{member_guid}.forApp.>",
      "OwnerSpace.{member_guid}.forServices.>",
      "MessageSpace.{member_guid}.ownerProfile",
      "MessageSpace.{member_guid}.call.>"
    ],
    "sub": [
      "OwnerSpace.{member_guid}.forVault.>",
      "OwnerSpace.{member_guid}.eventTypes",
      "MessageSpace.{member_guid}.forOwner.>",
      "MessageSpace.{member_guid}.call.>",
      "Broadcast.>"
    ]
  }
}
```

### Vault Services (Control) Permissions

**Credential Type:** System JWT
**Lifetime:** 1 hour

```json
{
  "permissions": {
    "pub": [
      "Control.global.>",
      "Control.user.{member_guid}.>"
    ]
  }
}
```

**Purpose:** Send control commands to enclaves (backup, shutdown, health check, etc.)

### Connection Token Permissions

**Credential Type:** Scoped JWT (issued by vault)
**Lifetime:** Variable (set by vault)

```json
{
  "permissions": {
    "pub": ["MessageSpace.{member_guid}.forOwner"],
    "sub": ["MessageSpace.{member_guid}.ownerProfile"]
  }
}
```

**Purpose:** Allow connections to send messages and view the member's profile.

---

## Control Architecture (Multi-Tenant)

### Background

VettID uses a **multi-tenant Nitro Enclave architecture** where shared enclave instances serve requests for ANY user. This requires a different control topology than the original single-tenant model.

**Single-Tenant (Legacy):** One vault instance per user → `OwnerSpace.{guid}.control` reaches that user's vault.

**Multi-Tenant (Current):** Shared enclave pool → ALL parent processes subscribe to `OwnerSpace.*.control`, causing:
- User-specific commands broadcast to all enclaves (wasteful)
- No way to target a specific enclave instance
- All enclaves see all control commands (security concern)

### Recommended Control Namespace

```
Control/
├── global/                        # Operations for ALL enclaves
│   ├── handlers.reload            # Force all enclaves to reload handlers
│   ├── health.request             # Request health reports from all
│   └── shutdown                   # Graceful shutdown all enclaves
│
├── enclave.{enclave_id}/          # Operations for SPECIFIC enclave
│   ├── health.request             # Health check this enclave
│   ├── metrics.request            # Request metrics from this enclave
│   ├── drain                      # Drain connections, prepare for shutdown
│   └── restart                    # Restart this specific enclave
│
└── user.{member_guid}/            # User-specific operations (routed dynamically)
    ├── backup.request             # Backup user data
    ├── key.rotate                 # Rotate user's encryption keys
    └── session.invalidate         # Force logout all user sessions
```

### Control Topic Types

| Topic Pattern | Receivers | Use Case |
|---------------|-----------|----------|
| `Control.global.{command}` | All parent processes | Handler updates, global health checks |
| `Control.enclave.{id}.{command}` | Single parent process | Instance-specific operations |
| `Control.user.{guid}.{command}` | Dynamically routed | User-specific operations |

### User-Specific Command Routing

For user-specific operations, use **request-reply pattern**:

1. Admin publishes to `Control.user.{guid}.backup.request`
2. All enclaves receive the message
3. Only the enclave holding user's active state responds affirmatively
4. Other enclaves respond with `"not_holding_user"` or don't respond
5. If no enclave holds state, admin receives `"no_active_session"`

### Enclave Identity

Each parent process should have a unique identifier:

```
enclave_id = "{region}-{instance_id}-{launch_timestamp}"
Example: "us-east-1-i-0abc123def-1705312800"
```

Parent process subscribes to:
- `Control.global.>` (all enclaves)
- `Control.enclave.{my_enclave_id}.>` (this enclave only)
- `Control.user.>` (for dynamic routing)

### Control Command Security

All control commands SHOULD include:

```json
{
  "command_id": "uuid",           // Idempotency key
  "command": "backup.request",    // Command type
  "target": {
    "type": "global|enclave|user",
    "id": "optional-target-id"
  },
  "params": {},                   // Command parameters
  "issued_at": "ISO8601",         // Timestamp
  "issued_by": "admin@vettid.dev",// Issuer identity
  "expires_at": "ISO8601",        // Command TTL (prevents replay)
  "signature": "base64..."        // Ed25519 signature (optional but recommended)
}
```

**Security Recommendations:**
- Reject commands older than 5 minutes (`issued_at` check)
- Track `command_id` to prevent replay (idempotency cache with TTL)
- Verify `signature` for sensitive operations
- Audit all control commands

### Migration from Legacy Control Topic

| Legacy | New | Notes |
|--------|-----|-------|
| `OwnerSpace.{guid}.control` | `Control.user.{guid}.*` | User-specific ops |
| `Control.handlers.reload` | `Control.global.handlers.reload` | Add `global.` prefix |
| N/A | `Control.enclave.{id}.*` | New: instance targeting |

### Implementation Status

| Component | Status |
|-----------|--------|
| Global control topics | 🟢 Implemented |
| Enclave-specific topics | 🟢 Implemented |
| User-specific routing | 🟢 Implemented |
| Signed commands | 🔴 Not implemented |
| Idempotency cache | 🟢 Implemented (via replay prevention) |

---

## Enrollment Flow

### State Machine

```
WEB_INITIATED → PENDING → AUTHENTICATED → NATS_CONNECTED → COMPLETED
```

### Phase 1: Session Initialization

```
1. User initiates on web portal
   API: POST /vault/enroll/start
   Creates: EnrollmentSession (status='WEB_INITIATED')
   Returns: session_id, qr_code_data

2. Mobile app scans QR code
   Status → PENDING
```

### Phase 2: Authentication

```
1. App calls POST /vault/enroll/authenticate
   - Validates password hash
   - Creates enrollment JWT (10 min expiry, device-bound)
   Status → AUTHENTICATED

2. Returns enrollment_token for Authorization header
```

### Phase 3: NATS Bootstrap

```
1. App calls POST /vault/enroll/nats-bootstrap
   Headers: Authorization: Bearer {enrollment_token}

2. Creates NATS account (status='enrolling', not 'active')
   - OwnerSpace: OwnerSpace.{member_guid}
   - MessageSpace: MessageSpace.{member_guid}
   - TTL: 1 hour (auto-cleanup if enrollment fails)

3. Returns bootstrap credentials:
   {
     "nats_endpoint": "tls://nats.vettid.dev:443",
     "nats_jwt": "eyJ...",
     "nats_seed": "SUAB...",
     "nats_creds": "-----BEGIN NATS USER JWT-----\n...",
     "owner_space": "OwnerSpace.{member_guid}",
     "message_space": "MessageSpace.{member_guid}",
     "token_id": "nats_enroll_...",
     "expires_at": "2026-01-16T..."
   }
```

### Phase 4: App Bootstrap via NATS

```
1. App publishes to:
   Topic: OwnerSpace.{member_guid}.forVault.app.bootstrap

   {
     "event_id": "uuid",
     "event_type": "app.bootstrap",
     "timestamp": "ISO8601",
     "encrypted_payload": "base64..."
   }

2. Vault subscribes to forVault.>, processes request

3. Vault publishes response to:
   Topic: OwnerSpace.{member_guid}.forApp.app.bootstrap.{event_id}

   {
     "response_id": "uuid",
     "event_id": "uuid",
     "status": "success",
     "encrypted_payload": "base64..."  // Contains full credentials
   }
```

### Phase 5: Finalization

```
1. App calls POST /vault/enroll/finalize
   - Account status: 'enrolling' → 'active'
   - Session status → COMPLETED

2. Returns:
   {
     "status": "enrolled",
     "vault_status": "ENCLAVE_READY"
   }
```

---

## PIN Setup Flow

### Current Implementation (REST + NATS Notification)

PIN setup is handled via REST API for security. NATS is used for real-time sync notifications.

#### PIN Setup

```
POST /account/pin/setup
Body: { "pin": "123456", "device_id": "..." }

1. Validate PIN (6+ digits, no repeating chars)
2. Hash PIN with device-specific salt
3. Store in Registrations table
4. (Optional) Broadcast notification via NATS
```

#### NATS Notification (if vault connected)

```
Topic: OwnerSpace.{member_guid}.forApp.pin.setup
{
  "event_type": "pin.setup_complete",
  "timestamp": "ISO8601",
  "status": "success"
}
```

### Expected Topic Pattern for Direct NATS PIN Setup

If implementing PIN setup via NATS:

| Direction | Topic | Purpose |
|-----------|-------|---------|
| App → Vault | `OwnerSpace.{guid}.forVault.pin` | PIN setup request |
| Vault → App | `OwnerSpace.{guid}.forApp.pin.response` | PIN setup response |

**NOTE:** The response topic MUST use `forApp` prefix, not just `app`. This is a common mistake.

---

## Handler Execution Flow

### Request/Response Pattern

```
1. App sends handler request:
   Topic: OwnerSpace.{member_guid}.forVault.{handler_id}

   {
     "event_id": "uuid",
     "event_type": "messaging.send_text",
     "timestamp": "ISO8601",
     "encrypted_payload": "base64..."
   }

2. Vault processes and responds:
   Topic: OwnerSpace.{member_guid}.forApp.{handler_id}.{event_id}

   {
     "response_id": "uuid",
     "event_id": "uuid",
     "status": "success" | "failure" | "pending",
     "encrypted_payload": "base64..."
   }
```

### Handler Types

| Handler | Request Topic | Response Topic |
|---------|--------------|----------------|
| Bootstrap | `forVault.app.bootstrap` | `forApp.app.bootstrap.{event_id}` |
| PIN Setup | `forVault.pin` | `forApp.pin.response` |
| Profile Update | `forVault.profile.update` | `forApp.profile.update.{event_id}` |
| Messaging | `forVault.messaging.send` | `forApp.messaging.send.{event_id}` |

---

## Broadcast System

### Broadcast Topics

```
Broadcast.system.announcement   # System-wide notifications
Broadcast.security.alert        # Security notifications
Broadcast.admin.message         # Admin messages
```

### Broadcast Message Format

```json
{
  "broadcast_id": "bcast-uuid",
  "type": "system_announcement",
  "priority": "normal" | "high" | "critical",
  "title": "System maintenance scheduled",
  "message": "Full message content",
  "sent_at": "ISO8601",
  "sent_by": "admin@vettid.dev"
}
```

### Priority Levels

| Priority | Behavior |
|----------|----------|
| `normal` | Standard notification |
| `high` | Requires acknowledgment |
| `critical` | Interrupts user flow |

---

## Message Encryption

### Payload Encryption Scheme

All sensitive payloads use **X25519 + XChaCha20-Poly1305**:

```json
{
  "event_id": "uuid",
  "event_type": "handler.action",
  "timestamp": "ISO8601",
  "encrypted_payload": "base64...",
  "encryption": {
    "algorithm": "X25519+XChaCha20-Poly1305",
    "ephemeral_public_key": "base64..."
  }
}
```

**Process:**
1. Generate ephemeral X25519 keypair
2. Compute shared secret with recipient's public key
3. Encrypt payload with XChaCha20-Poly1305 (256-bit key, 192-bit nonce)
4. Include ephemeral public key for recipient to derive shared secret

---

## Security Considerations

### Known Risks and Mitigations

#### 1. NATS-Layer Replay Attack Prevention

**Risk:** Encrypted messages captured from NATS could be replayed, causing duplicate operations.

**Required Mitigations:**
- [ ] Enforce `event_id` uniqueness in vault-manager (track processed IDs with TTL)
- [ ] Include monotonic sequence numbers in encrypted payloads
- [ ] Reject messages with timestamps older than 5 minutes
- [ ] Store processed event IDs in JetStream with auto-expiration

**Message Validation Requirements:**
```json
{
  "event_id": "uuid",           // MUST be unique, track for replay prevention
  "sequence": 12345,            // Monotonic per-session
  "timestamp": "ISO8601",       // Reject if > 5 minutes old
  "encrypted_payload": "..."
}
```

#### 2. Token Revocation

**Risk:** Compromised credentials remain valid for up to 24 hours.

**Required Mitigations:**
- [ ] Implement `natsRevokeToken` Lambda handler
- [ ] Update account JWT revocations map on revocation
- [ ] Publish updated account JWT to NATS resolver
- [ ] Add admin endpoint for emergency credential revocation

**Revocation Flow:**
1. Admin calls `/admin/nats/revoke-token` with user_guid and token_id
2. Lambda marks token as revoked in NatsTokens table
3. Lambda regenerates account JWT with revocation entry
4. Updated account JWT is pushed to NATS resolver
5. NATS server rejects future messages from revoked token

#### 3. Parent Process Credential Security

**Risk:** Parent process credentials have broad permissions (all user namespaces).

**Current State:**
- Lifetime: 1 year (TOO LONG)
- Permissions: `OwnerSpace.*` (all users)
- No per-enclave identity

**Required Mitigations:**
- [ ] Reduce credential lifetime to 30 days
- [ ] Implement automated credential rotation
- [ ] Add per-enclave unique identifiers
- [ ] Split credentials: routing (subscribe-only) vs responding (publish-only)
- [ ] Add anomaly monitoring for parent process behavior

#### 4. Bootstrap Key Exchange

**Risk:** Initial key exchange occurs without channel binding to attestation.

**Current Flow:**
1. App sends X25519 public key in plaintext over NATS
2. Vault responds with its public key
3. Both derive shared secret

**Attack Vector:** MITM at NATS infrastructure layer could substitute keys.

**Required Mitigations:**
- [ ] Include app's public key hash in attestation challenge
- [ ] Add cryptographic proof of enclave identity in responses
- [ ] Consider double-ratchet key exchange for forward secrecy

#### 5. Topic Namespace Information Leakage

**Risk:** Topic names contain user GUIDs, enabling traffic analysis.

**Exposed Information:**
- Which users are active (subscription presence)
- Message timing patterns
- App ↔ Vault correlation

**Accepted Risk:** This is documented as an accepted risk. Full mitigation would require:
- Hashed/tokenized namespace identifiers
- Cover traffic patterns
- Timing obfuscation

#### 6. Enrollment Session Binding

**Risk:** Enrollment tokens could be exfiltrated and used from different devices.

**Required Mitigations:**
- [ ] Require device attestation before NATS bootstrap
- [ ] Bind session token to device attestation hash
- [ ] Include client fingerprint in session validation
- [ ] Add session pinning (reject requests from different device/network)

### Security Implementation Status

| Control | Status | Priority |
|---------|--------|----------|
| NATS message replay prevention | 🟢 Implemented | Critical |
| Token revocation workflow | 🟢 Implemented | Critical |
| Parent credential rotation | 🟢 Implemented (30-day lifetime) | High |
| Multi-tenant control topics | 🟢 Implemented | High |
| Bootstrap attestation binding | 🟢 Implemented | High |
| Signed control commands | 🔴 Not Implemented | Medium |
| Device attestation binding | 🔴 Not Implemented | Medium |
| Legacy seed migration | 🟢 Complete (removed) | Medium |
| Rate limiting on NATS bootstrap | 🟢 Implemented | Low |

### Credential Lifecycle Best Practices

#### Token Lifetimes

| Credential Type | Current | Recommended | Rationale |
|-----------------|---------|-------------|-----------|
| App credentials | 24 hours | 24 hours | ✅ Appropriate |
| Vault credentials | 24 hours | 24 hours | ✅ Appropriate |
| Parent credentials | 30 days | 30 days | ✅ Appropriate |
| Bootstrap credentials | 1 hour | 1 hour | ✅ Appropriate |
| Control credentials | 1 hour | 1 hour | ✅ Appropriate |

#### Credential Refresh Pattern

```
Timeline:  |-------- 24 hours --------|
           0        12h       20h    24h
           |         |         |      |
        issued    [refresh   [must   expires
                  window]   refresh]

Recommendation: Refresh at 50% lifetime (12 hours)
Must refresh by: 83% lifetime (20 hours)
```

### Audit Requirements

All security-sensitive NATS operations MUST be logged:

| Event | Log Fields | Retention |
|-------|------------|-----------|
| Credential issued | user_guid, token_id, device_id, expires_at | 90 days |
| Credential revoked | user_guid, token_id, revoked_by, reason | 1 year |
| Control command | command_id, command, target, issued_by | 1 year |
| Bootstrap attempt | session_id, user_guid, device_id, success | 90 days |
| Replay detected | event_id, user_guid, original_timestamp | 1 year |

### Incident Response

#### Credential Compromise

1. **Immediate:** Revoke compromised token via admin endpoint
2. **Short-term:** Rotate all credentials for affected user
3. **Investigation:** Review audit logs for unauthorized access
4. **Communication:** Notify user of security event

#### NATS Infrastructure Compromise

1. **Immediate:** Rotate operator signing key
2. **Short-term:** Regenerate all account and user JWTs
3. **Investigation:** Analyze message patterns for data exfiltration
4. **Recovery:** Re-establish trust with new operator key

---

## Resource Limits

### Per-Account Limits

| Resource | Limit |
|----------|-------|
| Max subscriptions | 100 |
| Max connections | 10 |
| Max data rate | 10 MB/sec |
| Max payload size | 1 MB |
| Max imports/exports | 10 each |

### Per-User Limits

| Resource | Limit |
|----------|-------|
| Max subscriptions | 50 |
| Max data rate | 5 MB/sec |
| Max payload size | 1 MB |

### Credential Lifetimes

| Credential Type | Lifetime |
|-----------------|----------|
| App credentials | 24 hours |
| Vault credentials | 24 hours |
| Control credentials | 1 hour |
| Bootstrap credentials | 1 hour |
| Enrollment token | 10 minutes |

---

## Topic Reference Table

### Complete Topic Map

| Namespace | Topic | Publisher | Subscriber | Purpose |
|-----------|-------|-----------|------------|---------|
| OwnerSpace | `forVault.>` | App | Vault | User commands |
| OwnerSpace | `forApp.>` | Vault | App | Responses |
| OwnerSpace | `eventTypes` | Vault | App | Handler definitions |
| OwnerSpace | `forServices.>` | Vault | Backend | Health/status |
| OwnerSpace | `call.>` | Vault | Vault | Call signaling |
| MessageSpace | `forOwner.>` | Connections | Vault | Inbound messages |
| MessageSpace | `ownerProfile` | Vault | Connections | Public profile |
| MessageSpace | `call.>` | Vault | Vault | Call signaling |
| Broadcast | `system.*` | Services | Vault | Announcements |
| Broadcast | `security.*` | Services | Vault | Security alerts |
| Broadcast | `admin.*` | Services | Vault | Admin messages |
| Control | `global.*` | Services | All Enclaves | Global operations |
| Control | `enclave.{id}.*` | Services | Specific Enclave | Instance operations |
| Control | `user.{guid}.*` | Services | Routed Dynamically | User operations |

### Control Commands (Multi-Tenant)

| Command | Target | Topic | Description |
|---------|--------|-------|-------------|
| `handlers.reload` | Global | `Control.global.handlers.reload` | Force all enclaves to reload handlers |
| `health.request` | Global | `Control.global.health.request` | Request health from all enclaves |
| `shutdown` | Global | `Control.global.shutdown` | Graceful shutdown all enclaves |
| `health.request` | Enclave | `Control.enclave.{id}.health.request` | Health check specific enclave |
| `drain` | Enclave | `Control.enclave.{id}.drain` | Drain connections from enclave |
| `backup.request` | User | `Control.user.{guid}.backup.request` | Backup user data |
| `key.rotate` | User | `Control.user.{guid}.key.rotate` | Rotate user encryption keys |

---

## Implementation Files

| File | Purpose |
|------|---------|
| `lambda/common/nats-jwt.ts` | JWT generation for accounts/users |
| `lambda/common/enrollment-jwt.ts` | Enrollment token generation |
| `lambda/common/nats-publisher.ts` | Broadcast publishing |
| `lambda/handlers/vault/enrollNatsBootstrap.ts` | Bootstrap credentials |
| `lambda/handlers/vault/enrollFinalize.ts` | Enrollment completion |
| `lambda/handlers/admin/sendVaultBroadcast.ts` | Send broadcasts |
| `lib/nats-stack.ts` | NATS infrastructure |

---

## Common Mistakes to Avoid

1. **Wrong response topic prefix:**
   - ❌ `OwnerSpace.{guid}.app.pin.response`
   - ✅ `OwnerSpace.{guid}.forApp.pin.response`

2. **Missing event_id in response topic:**
   - ❌ `OwnerSpace.{guid}.forApp.handler`
   - ✅ `OwnerSpace.{guid}.forApp.handler.{event_id}`

3. **Subscribing before publishing:**
   - Always subscribe to response topic BEFORE publishing request

4. **Not handling credential refresh:**
   - Credentials expire after 24 hours
   - Refresh 5 minutes before expiry

5. **Using wrong encryption key:**
   - App uses vault's public key for encryption
   - Vault uses ephemeral public key from request to decrypt

---

*Last updated: 2026-01-15*
