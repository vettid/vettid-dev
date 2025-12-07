# NATS Topic Structure

This document defines the NATS namespace and topic structure for VettID Vault Services.

## Overview

VettID uses two NATS deployments:

1. **Central NATS** (os.vettid.dev / ms.vettid.dev) - Cross-vault communication
2. **Local NATS** (on vault) - Private datastore for member data

## NATS Trust Hierarchy

```
Operator: VettID (holds operator signing key)
├── Account: OwnerSpace.{member_guid}
│   └── Vault holds Account NKey, issues JWTs for mobile app
├── Account: MessageSpace.{member_guid}
│   └── Vault holds Account NKey, issues JWTs for connections
└── System Accounts (operator-controlled)
    ├── ServiceRegistry
    └── VaultServices (for control topic access)
```

## Central NATS Namespaces

### OwnerSpace (os.vettid.dev)

**Purpose:** Secure communication between member's mobile app and their vault.

```
OwnerSpace.{member_guid}/
├── forVault       # App → Vault: Commands and events from mobile app
├── forApp         # Vault → App: Responses and notifications to app
├── eventTypes     # Read-only: Available event handler definitions
└── control        # Vault Services → Vault: System commands
```

#### Topic Details

| Topic | Publisher | Subscriber | Purpose |
|-------|-----------|------------|---------|
| `forVault` | Mobile App | Vault Manager | User commands, events to process |
| `forApp` | Vault Manager | Mobile App | Responses, notifications, status updates |
| `eventTypes` | Vault Manager | Mobile App | Handler definitions (JSON schema) |
| `control` | Vault Services Lambda | Vault Manager | System commands |

#### Access Control Matrix

| Actor | forVault | forApp | eventTypes | control |
|-------|----------|--------|------------|---------|
| Mobile App | Write | Read | Read | - |
| Vault Manager | Read | Write | Write | Read |
| Vault Services | - | - | - | Write |

#### Control Topic Commands

```json
// Command envelope
{
  "command_id": "uuid",
  "command": "command_name",
  "timestamp": "ISO8601",
  "params": {}
}
```

| Command | Description | Parameters |
|---------|-------------|------------|
| `prepare_backup` | Coalesce datastore for backup | `{}` |
| `execute_backup` | Perform backup and upload to S3 | `{ "trigger": "manual\|scheduled\|pre_stop" }` |
| `update_handler` | Download and install handler update | `{ "handler_id": "...", "version": "..." }` |
| `rotate_namespace_keys` | Rotate NATS access tokens | `{}` |
| `health_check` | Report vault status | `{}` |
| `shutdown` | Graceful shutdown | `{ "reason": "..." }` |

### MessageSpace (ms.vettid.dev)

**Purpose:** Receive messages from connections and publish member profile.

```
MessageSpace.{member_guid}/
├── forOwner       # Connections → Vault: Inbound messages
└── ownerProfile   # Vault → Public: Member's public profile
```

#### Topic Details

| Topic | Publisher | Subscriber | Purpose |
|-------|-----------|------------|---------|
| `forOwner` | Connections (with token) | Vault Manager | Inbound connection messages |
| `ownerProfile` | Vault Manager | Connections (with token) | Member's public profile |

#### Access Control Matrix

| Actor | forOwner | ownerProfile |
|-------|----------|--------------|
| Vault Manager | Read | Write |
| Connections | Write | Read |

## Local NATS (Vault Datastore)

**Location:** Runs on vault instance, localhost only
**Purpose:** Persistent storage for member's private data

### Datastore Topics

```
local.datastore/
├── private_data          # Personal information (address, phone, etc.)
├── secrets_metadata      # Metadata for secrets (actual secrets in credential)
├── contacts              # Cached connection profiles
├── revoked_connections   # Minimal identifiers for revoked connections
├── handlers              # Registered event handler definitions
├── handler_data          # Handler-specific persistent data
├── feed                  # Handled events shown to user
└── archived_events       # Historical event archive
```

### Credentials Topics

```
local.credentials/
├── vault_identity        # Vault's credential for central NATS
├── connection_keys       # Per-connection encryption keys (by keyID)
└── member_keypair        # Member's general-purpose key pair
```

## Message Formats

### Event Message (App → Vault via forVault)

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

### Response Message (Vault → App via forApp)

```json
{
  "response_id": "uuid",
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "status": "success|failure|pending",
  "encrypted_payload": "base64...",
  "encryption": {
    "algorithm": "X25519+XChaCha20-Poly1305",
    "ephemeral_public_key": "base64..."
  }
}
```

### Event Type Definition (eventTypes topic)

```json
{
  "handler_id": "messaging.send_text",
  "name": "Send Text Message",
  "description": "Send encrypted text message to a connection",
  "version": "1.2.0",
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

### Profile (ownerProfile topic)

```json
{
  "profile_version": "1.0",
  "updated_at": "ISO8601",
  "public_key": "ed25519:base64...",
  "public": {
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com"
  },
  "optional": {
    "phone": "+1-555-0100",
    "city": "Denver",
    "company": "Acme Corp"
  }
}
```

### Connection Message (forOwner topic)

```json
{
  "message_id": "uuid",
  "message_type": "text|event|invitation|ack",
  "timestamp": "ISO8601",
  "sender": {
    "messagespace_uri": "ms.vettid.dev/{sender_guid}",
    "key_id": "connection_key_id"
  },
  "encrypted_payload": "base64...",
  "encryption": {
    "algorithm": "X25519+XChaCha20-Poly1305",
    "recipient_key_id": "connection_key_id"
  }
}
```

## JWT Token Structure

### Mobile App Token (OwnerSpace)

```json
{
  "sub": "{member_guid}",
  "iss": "vault.{member_guid}",
  "aud": "os.vettid.dev",
  "exp": 1735689600,
  "permissions": {
    "pub": ["OwnerSpace.{member_guid}.forVault"],
    "sub": ["OwnerSpace.{member_guid}.forApp", "OwnerSpace.{member_guid}.eventTypes"]
  }
}
```

### Connection Token (MessageSpace)

```json
{
  "sub": "connection.{connection_id}",
  "iss": "vault.{member_guid}",
  "aud": "ms.vettid.dev",
  "exp": 1735689600,
  "permissions": {
    "pub": ["MessageSpace.{member_guid}.forOwner"],
    "sub": ["MessageSpace.{member_guid}.ownerProfile"]
  }
}
```

### Vault Services Control Token

```json
{
  "sub": "vault-services",
  "iss": "operator.vettid.dev",
  "aud": "os.vettid.dev",
  "exp": 1735689600,
  "permissions": {
    "pub": ["OwnerSpace.*.control"]
  }
}
```

## Security Considerations

1. **Namespace Isolation**: Members cannot access other members' namespaces
2. **Write-Only Control**: Vault Services can only write to control topic
3. **Short Token Lifetimes**: Recommended 60 minutes for app tokens
4. **Token Binding**: Consider binding tokens to device identifiers
5. **Audit Logging**: All control commands should be logged
6. **TLS Required**: All NATS connections must use TLS

## Implementation Notes

### Mobile App Integration

```typescript
// Connect to OwnerSpace
const nc = await connect({
  servers: 'os.vettid.dev',
  authenticator: jwtAuthenticator(token),
  tls: true
});

// Subscribe to responses
const sub = nc.subscribe(`OwnerSpace.${memberGuid}.forApp`);
for await (const msg of sub) {
  handleResponse(msg.data);
}

// Publish event
await nc.publish(`OwnerSpace.${memberGuid}.forVault`, eventData);
```

### Vault Manager Integration

```go
// Connect to central NATS
nc, _ := nats.Connect("os.vettid.dev",
    nats.UserJWT(jwtCB, signCB),
    nats.Secure())

// Subscribe to forVault and control
nc.Subscribe(fmt.Sprintf("OwnerSpace.%s.forVault", memberGuid), handleEvent)
nc.Subscribe(fmt.Sprintf("OwnerSpace.%s.control", memberGuid), handleControl)

// Publish to forApp
nc.Publish(fmt.Sprintf("OwnerSpace.%s.forApp", memberGuid), response)
```
