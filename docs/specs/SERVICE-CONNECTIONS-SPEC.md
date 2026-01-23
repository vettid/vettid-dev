# Service Connections Specification

**Version:** 1.0
**Status:** Implementation Phase 1
**Last Updated:** 2026-01-22

This document specifies the technical implementation of service connections in VettID, enabling third-party services (banks, apps, government services) to communicate with user vaults.

## Table of Contents

1. [Overview](#overview)
2. [Security Model](#security-model)
3. [Connection Flow](#connection-flow)
4. [Contract System](#contract-system)
5. [Message Handling](#message-handling)
6. [Cryptographic Operations](#cryptographic-operations)
7. [Database Schema](#database-schema)
8. [API Reference](#api-reference)
9. [Implementation Status](#implementation-status)

---

## Overview

Service connections enable B2C (Business-to-Consumer) communication between third-party services and VettID user vaults. Unlike peer-to-peer connections between users, service connections are:

- **Asymmetric**: Services publish to users, users control what data they share
- **Contract-governed**: All data access is defined by user-accepted contracts
- **Capability-based**: Services can only perform operations explicitly granted
- **Auditable**: All service interactions are logged in the vault's event feed

### Key Security Principle

**Services can ONLY publish to users, never subscribe.** Users maintain complete control over their data through cryptographic contracts. A service cannot:
- Subscribe to any MessageSpace topics
- Observe user activity or communications
- Access data without an active contract
- Bypass capability enforcement

---

## Security Model

### Trust Hierarchy

```
VettID Operator (NATS Operator Key)
├── Service Registry (DynamoDB)
│   ├── Registered Services (with NATS accounts)
│   └── Attestation Records (domain verification)
├── User Vaults (Nitro Enclaves)
│   ├── Service Connections
│   ├── Signed Contracts
│   └── Capability Enforcement
```

### Service Authentication

Services authenticate via NATS using account-level credentials:

1. **Account JWT**: Long-lived, identifies the service
2. **User JWT**: 30-day lifetime, used for actual connections
3. **Domain Attestation**: Required before service can become active

### Credential Security

```
NATS Account Seed
    ├── Stored encrypted with KMS (service_registry.nats_account_seed_encrypted)
    ├── Encryption context: {service_id, purpose: "nats_account_seed"}
    └── Only returned once during registration (never retrievable again)
```

### Service NATS Permissions

```json
{
  "pub": {
    "allow": ["MessageSpace.*.fromService.<service_id>.>"]
  },
  "sub": {
    "deny": ["MessageSpace.>", "OwnerSpace.>", "Control.>", "Broadcast.>"]
  },
  "data": 52428800,      // 50 MB/sec
  "payload": 1048576     // 1 MB max
}
```

---

## Connection Flow

### Phase 1: Discovery

```
Mobile App                          Service
    │                                  │
    ├──── [1] Scan QR Code ───────────►│
    │     (contains service_guid,       │
    │      domain, public_key)          │
    │                                  │
```

### Phase 2: Contract Presentation

```
Mobile App                    Vault                    Service
    │                           │                         │
    ├── service.connection ────►│                         │
    │   .initiate               │                         │
    │   {service_guid,          │                         │
    │    domain}                │                         │
    │                           │                         │
    │◄── {contract,            ─┤                         │
    │     connection_id,        │                         │
    │     vault_public_key}     │                         │
    │                           │                         │
```

### Phase 3: User Acceptance

```
Mobile App                    Vault
    │                           │
    │   [User reviews contract] │
    │                           │
    ├── service.contract ──────►│
    │   .accept                 │
    │   {connection_id,         │
    │    version}               │
    │                           │
    │◄── {success,             ─┤ ── [Signs contract with Ed25519]
    │     user_signature,       │
    │     activated}            │
    │                           │
```

### Phase 4: Active Connection

```
Service                       NATS                       Vault
    │                           │                          │
    ├── MessageSpace.{user}.   ─┼─────────────────────────►│
    │   fromService.{svc}.     │                          │
    │   auth                    │                          │
    │   {challenge, purpose}    │                          │
    │                           │                          │
    │◄── {request_id,          ─┼──────────────────────────┤
    │     status: pending}      │   [User sees in feed]    │
    │                           │                          │
```

---

## Contract System

### Contract Structure

```typescript
interface ServiceDataContract {
  contract_id: string;           // Unique identifier
  service_guid: string;          // Service that issued contract
  version: number;               // Monotonically increasing
  title: string;                 // Human-readable title
  description: string;           // Purpose explanation

  // Capability flags
  can_request_auth: boolean;     // Can send auth challenges
  can_request_payment: boolean;  // Can request payments
  can_store_data: boolean;       // Can store data in vault
  can_send_messages: boolean;    // Can send notifications

  // Field access levels (progressive disclosure)
  required_fields: FieldSpec[];  // Must share to connect
  optional_fields: FieldSpec[];  // Can choose to share
  on_demand_fields: string[];    // Auto-shared when requested
  consent_fields: string[];      // Per-request approval required

  // Terms
  terms_url?: string;
  privacy_url?: string;
  expires_at?: Date;
}

interface FieldSpec {
  field: string;                 // Field identifier
  purpose: string;               // Why it's needed
  retention?: string;            // How long kept
}
```

### Contract Signing

Contracts are cryptographically signed using Ed25519:

```go
// Canonical JSON for deterministic signing
canonicalData := CanonicalJSON(contract)

// Hash the canonical form
hash := SHA256(canonicalData)

// Create signing payload with context
payload := fmt.Sprintf("contract-sign-v1|%s|%d|%s",
    contract.ContractID,
    contract.Version,
    base64(hash))

// Sign with vault identity key
signature := Ed25519Sign(identityPrivateKey, payload)
```

### Contract Enforcement

Before processing any service request:

```go
allowed, denied, err := EnforceContract(connectionID, requestedFields, accessType)
if !allowed {
    return AccessDenied(denied)
}
```

---

## Message Handling

### Topic Structure

```
MessageSpace.{user_guid}.fromService.{service_id}/
├── auth              # Authentication challenge
├── consent           # Data consent request
├── payment           # Payment request
├── data/
│   ├── get          # Request profile data
│   └── store        # Store service data
├── contract-update   # Contract version update
└── notify           # Push notification
```

### Message Routing (vault-manager/messages.go)

```go
func handleFromServiceOperation(ctx, msg, serviceID, opParts) {
    // 1. Find connection by service ID
    conn := findConnectionByServiceID(serviceID)

    // 2. Verify connection is active
    if conn.Status != "active" {
        return error("connection not active")
    }

    // 3. Route based on operation
    switch opParts[0] {
    case "auth":
        return handleAuthRequest(msg)
    case "consent":
        return handleConsentRequest(msg)
    case "data":
        return handleDataOperation(msg, conn, opParts[1:])
    // ...
    }
}
```

### Request/Response Flow

All service requests create feed events for user visibility:

1. Service publishes request via NATS
2. Vault validates connection and capabilities
3. Request stored in `service_requests` table
4. Feed event created for user notification
5. User approves/denies via mobile app
6. Response sent back via callback subject

---

## Cryptographic Operations

### Key Types

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| Identity | Ed25519 | Contract signing, auth challenges |
| Encryption | X25519 | E2E encryption with services |
| Session | HKDF-derived | Per-connection encryption |

### E2E Encryption

Service connections use X25519 for key exchange:

```go
// During connection initiation
vaultKeyPair := GenerateX25519KeyPair()
sharedSecret := X25519(vaultPrivate, servicePublicKey)

// Domain-separated key derivation
encryptionKey := HKDF-SHA256(
    sharedSecret,
    "vettid-service-e2e-v1",
    connectionID)
```

### Auth Challenge Signing

```go
// Format: auth-challenge-v1|{service_guid}|{challenge}|{timestamp}
payload := fmt.Sprintf("auth-challenge-v1|%s|%s|%s",
    serviceGUID, challenge, timestamp)

signature := Ed25519Sign(identityPrivateKey, payload)
```

---

## Database Schema

### DynamoDB: ServiceRegistry

| Field | Type | Description |
|-------|------|-------------|
| service_id | String (PK) | Matches supportedServices |
| status | String | pending, active, suspended, revoked |
| domain | String | Verified domain (GSI) |
| public_key | String | Ed25519 for signature verification |
| encryption_key | String | X25519 for E2E encryption |
| nats_account_public_key | String | NATS account public key |
| nats_account_seed_encrypted | String | KMS-encrypted NATS seed |
| attestations | List | Verification records |
| created_at, updated_at | String | ISO timestamps |

**GSIs:**
- `domain-index`: Lookup by domain
- `status-index`: Query by status + created_at

### SQLite (Vault-Local): service_contracts

```sql
CREATE TABLE service_contracts (
    contract_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    service_guid TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','pending','superseded','rejected','expired')),
    contract_data BLOB NOT NULL,      -- Encrypted JSON
    user_signature BLOB,               -- Ed25519 signature
    service_signature BLOB,            -- Service signature
    signed_at INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    UNIQUE(connection_id, version)
);
```

### SQLite (Vault-Local): service_auth_requests

```sql
CREATE TABLE service_auth_requests (
    request_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    challenge TEXT NOT NULL,           -- Encrypted
    purpose TEXT,
    status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')),
    callback_subject TEXT,
    response_data BLOB,                -- Encrypted response
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    responded_at INTEGER
);
```

---

## API Reference

### Admin APIs

#### Register Service Credentials
```
POST /admin/service-registry
Authorization: Bearer {admin_jwt}

{
  "service_id": "signal-messenger",
  "domain": "signal.org",
  "public_key": "base64-ed25519-public-key",
  "encryption_key": "base64-x25519-public-key"
}

Response:
{
  "service_id": "signal-messenger",
  "status": "pending",
  "nats_account_public_key": "...",
  "nats_account_seed": "...",        // Only returned once!
  "nats_account_jwt": "..."
}
```

#### Verify Service Attestation
```
POST /admin/service-registry/{service_id}/attest
Authorization: Bearer {admin_jwt}

{
  "method": "dns_txt"
}

Response:
{
  "service_id": "signal-messenger",
  "status": "active",
  "attestation": {
    "method": "dns_txt",
    "verified_at": "2026-01-22T...",
    "details": "DNS TXT record verified at _vettid-verify.signal.org"
  }
}
```

### Public APIs

#### Service Directory
```
GET /services/directory

Response:
{
  "services": [
    {
      "service_id": "signal-messenger",
      "name": "Signal Messenger",
      "can_connect": true,
      "connection_domain": "signal.org",
      "capabilities": ["auth", "authz", "notify"]
    }
  ],
  "count": 1,
  "connectable_count": 1
}
```

### NATS Topics (Service → Vault)

#### Auth Request
```
Topic: MessageSpace.{user_guid}.fromService.{service_id}.auth

Payload:
{
  "connection_id": "...",
  "challenge": "random-challenge-string",
  "purpose": "Login verification",
  "expires_in": 300,
  "callback_subject": "ServiceSpace.{service_id}.auth-callback"
}
```

#### Consent Request
```
Topic: MessageSpace.{user_guid}.fromService.{service_id}.consent

Payload:
{
  "connection_id": "...",
  "fields": ["full_name", "email"],
  "purpose": "Account creation",
  "one_time": true,
  "expires_in": 600
}
```

---

## Implementation Status

### Completed (Phase 1)

- [x] ServiceRegistry DynamoDB table
- [x] NATS service topic structure
- [x] Service NATS authentication
- [x] Vault subscription updates (`fromService.>`)
- [x] Service registration API
- [x] Service attestation API (DNS TXT, signature)
- [x] Service directory API
- [x] SQLite schema (contracts, keys, requests)
- [x] Contract signing (Ed25519)
- [x] Message routing (`fromService` handler)
- [x] Capability enforcement
- [x] Auth/consent/payment request handlers

### Pending (Phase 2+)

- [ ] ServiceSpace NATS namespace
- [ ] Data storage operations
- [ ] Payment processing integration
- [ ] Contract expiration handling
- [ ] Service suspension automation
- [ ] Mobile app UI for service connections
- [ ] Rate limiting per service

---

## Related Documents

- [NATS-MESSAGING-ARCHITECTURE.md](../NATS-MESSAGING-ARCHITECTURE.md) - NATS topic structure
- [SERVICE-CONNECTIONS-PLAN.md](../SERVICE-CONNECTIONS-PLAN.md) - Implementation planning
- [vault-services-api.yaml](vault-services-api.yaml) - OpenAPI specification
