# Profiles & Connections Implementation Plan

## Overview

This document outlines the implementation plan for the Profiles and Connections features in VettID. These features enable users to:
1. **Profiles**: Manage personal profile data stored in the vault
2. **Connections**: Establish peer-to-peer encrypted communication channels between vaults

---

## Current State

### Android Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| `ProfileViewModel` | ✅ Implemented | Load, edit, save, publish profile |
| `ProfileScreen` | ✅ Implemented | UI for viewing/editing profile |
| `ProfileApiClient` | ⚠️ Uses HTTP | Should migrate to NATS vault handlers |
| `ConnectionsViewModel` | ✅ Implemented | List, search, navigate to connections |
| `ConnectionsScreen` | ✅ Implemented | Connection list UI |
| `ConnectionsClient` | ✅ Implemented | NATS handlers for connection operations |
| `ConnectionDetailScreen` | ✅ Implemented | View connection details |
| `CreateInvitationScreen` | ✅ Implemented | Create QR code invitation |
| `ScanInvitationScreen` | ✅ Implemented | Scan peer's QR invitation |

### iOS Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Profile Feature | ✅ Implemented | Full profile management |
| Connections Feature | ✅ Implemented | Connection list and management |

### Backend Handler Status

| Handler | Topic | Status |
|---------|-------|--------|
| `profile.get` | `forVault.profile.get` | ⚠️ Verify |
| `profile.update` | `forVault.profile.update` | ⚠️ Verify |
| `profile.publish` | `forVault.profile.publish` | ⚠️ Verify |
| `connection.create-invite` | `forVault.connection.create-invite` | ✅ Implemented |
| `connection.store-credentials` | `forVault.connection.store-credentials` | ✅ Implemented |
| `connection.list` | `forVault.connection.list` | ✅ Implemented |
| `connection.get-credentials` | `forVault.connection.get-credentials` | ✅ Implemented |
| `connection.rotate` | `forVault.connection.rotate` | ✅ Implemented |
| `connection.revoke` | `forVault.connection.revoke` | ✅ Implemented |

---

## Architecture

### Profile Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Mobile    │────▶│    NATS     │────▶│   Vault     │
│     App     │◀────│   Server    │◀────│  (Enclave)  │
└─────────────┘     └─────────────┘     └─────────────┘
      │                                        │
      │  1. profile.get/update                 │
      │  2. Encrypted at rest                  │
      │  3. Owner-only access                  │
      └────────────────────────────────────────┘
```

### Connection Flow

```
┌─────────────┐                              ┌─────────────┐
│   User A    │                              │   User B    │
│   (Vault)   │                              │   (Vault)   │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │ 1. Create Invitation                       │
       │    (generates NATS creds for B)            │
       ▼                                            │
┌─────────────┐                                     │
│  QR Code    │─────── Share QR ───────────────────▶│
│  (Invite)   │                                     │
└─────────────┘                                     │
       │                                            ▼
       │                              2. Scan & Store Credentials
       │                                 (B stores A's creds)
       │                                            │
       │                              3. B creates reciprocal invite
       │◀─────────────────────────────────────────────
       │
       ▼
4. A stores B's credentials
   (bidirectional connection established)
```

---

## Profile Feature

### Data Model

```typescript
interface Profile {
  user_guid: string;           // Owner's GUID
  display_name: string;        // Required
  bio?: string;                // Optional
  location?: string;           // Optional
  avatar_url?: string;         // Optional (future)
  profile_version: number;     // For conflict resolution
  updated_at: string;          // ISO8601 timestamp
}
```

### NATS Handlers Required

#### 1. `profile.get`
- **Topic**: `{owner_space}.forVault.profile.get`
- **Request**: `{}`
- **Response**: `{ profile: Profile }`

#### 2. `profile.update`
- **Topic**: `{owner_space}.forVault.profile.update`
- **Request**: 
  ```json
  {
    "display_name": "string",
    "bio": "string | null",
    "location": "string | null"
  }
  ```
- **Response**: `{ profile: Profile }`

#### 3. `profile.publish`
- **Topic**: `{owner_space}.forVault.profile.publish`
- **Description**: Broadcasts profile to all active connections
- **Request**: `{}`
- **Response**: `{ published_to: number }`

### Storage

- Profile data stored in vault's encrypted DynamoDB
- Key: `profile:{user_guid}`
- Encrypted with vault's DEK

---

## Connections Feature

### Data Model

```typescript
interface Connection {
  connection_id: string;       // UUID
  peer_guid: string;           // Peer's user GUID
  label: string;               // User-defined name
  status: 'active' | 'pending' | 'revoked' | 'expired';
  direction: 'outbound' | 'inbound';
  nats_credentials: string;    // Encrypted NATS .creds
  peer_owner_space: string;    // For receiving their messages
  peer_message_space: string;  // For sending to them
  created_at: string;
  expires_at?: string;
  last_rotated_at?: string;
}
```

### Connection Establishment Flow

1. **User A creates invitation**
   - Calls `connection.create-invite`
   - Vault generates NATS credentials scoped to A's message space
   - Returns QR code data with credentials

2. **User B scans invitation**
   - Decodes QR code to get A's credentials
   - Calls `connection.store-credentials` to save A's creds
   - Creates reciprocal invitation for A

3. **User A completes connection**
   - Scans B's reciprocal QR code
   - Stores B's credentials
   - Both users now have bidirectional communication

### NATS Handlers

| Handler | Description |
|---------|-------------|
| `connection.create-invite` | Generate NATS credentials for peer |
| `connection.store-credentials` | Store peer's credentials in vault |
| `connection.list` | List all connections with status filter |
| `connection.get-credentials` | Get credentials for a connection |
| `connection.rotate` | Rotate credentials (security refresh) |
| `connection.revoke` | Permanently revoke a connection |

### Security Considerations

1. **Credential Scoping**: Each connection gets minimal NATS permissions
2. **Rotation**: Credentials should be rotated periodically
3. **Revocation**: Immediate credential revocation on user action
4. **Expiry**: Invitations expire after configurable time (default: 24h)

---

## Implementation Tasks

### Phase 1: Profile NATS Migration (Android)

- [ ] Create `ProfileClient.kt` using NATS handlers
- [ ] Migrate `ProfileViewModel` from HTTP to NATS
- [ ] Add profile caching in `EncryptedSharedPreferences`
- [ ] Test profile get/update/publish flow

### Phase 2: Connections Polish (Android)

- [ ] Add connection request notifications
- [ ] Implement credential rotation UI
- [ ] Add connection expiry warnings
- [ ] Test full connection flow E2E

### Phase 3: Backend Verification

- [ ] Verify all profile handlers in vault-manager
- [ ] Verify all connection handlers in vault-manager
- [ ] Add integration tests for handlers
- [ ] Document handler response formats

### Phase 4: Cross-Platform Testing

- [ ] Test Android ↔ iOS connections
- [ ] Test profile publishing between platforms
- [ ] Verify message delivery after connection

---

## Related Issues

- Issue #16: Test and verify post-enrollment NATS topics
- Enclave Migration: May affect connection credential storage

---

## References

- [NATS Messaging Architecture](./NATS-MESSAGING-ARCHITECTURE.md)
- [Vault Services Architecture](./vault_services_architecture.md)
- Android: `app/src/main/java/com/vettid/app/features/connections/`
- Android: `app/src/main/java/com/vettid/app/features/profile/`
