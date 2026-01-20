# Profiles & Connections Implementation Plan

## Overview

This document outlines the implementation plan for the Profiles and Connections features in VettID. These features enable users to:
1. **Profiles**: Manage personal profile data with selective sharing controls
2. **Connections**: Establish peer-to-peer encrypted communication channels between vaults with bidirectional consent

---

## Current State

### Android Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| `ProfileViewModel` | ⚠️ Needs Update | Expand for new profile structure |
| `ProfileScreen` | ⚠️ Needs Update | Add sharing controls, metadata editor |
| `ProfileApiClient` | ⚠️ Uses HTTP | Migrate to NATS vault handlers |
| `ConnectionsViewModel` | ⚠️ Needs Update | Add consent flow, profile caching |
| `ConnectionsScreen` | ⚠️ Needs Update | Show peer profiles, pending requests |
| `ConnectionsClient` | ⚠️ Needs Update | Implement new handshake flow |
| `ConnectionDetailScreen` | ⚠️ Needs Update | Display peer profile, capabilities |
| `CreateInvitationScreen` | ✅ Implemented | QR code + share options |
| `ScanInvitationScreen` | ⚠️ Needs Update | Add profile review step |

### iOS Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Profile Feature | ⚠️ Needs Update | Align with new profile structure |
| Connections Feature | ⚠️ Needs Update | Implement consent flow |

---

## Architecture

### Profile Data Model

```typescript
interface UserProfile {
  // === Required Fields (always shared) ===
  user_guid: string;              // Unique identifier
  public_key: string;             // Ed25519 public key (private in Protean Credential)
  first_name: string;             // Required
  last_name: string;              // Required
  email: string;                  // Required, verified

  // === Verification Status ===
  email_verified: boolean;
  identity_verified: boolean;     // Future: ID verification

  // === Optional Shareable Fields ===
  display_name?: string;          // Preferred display name
  phone?: string;
  address?: Address;
  bio?: string;
  avatar_url?: string;
  organization?: string;
  job_title?: string;

  // === Sharing Preferences ===
  sharing_settings: SharingSettings;

  // === Metadata ===
  profile_version: number;
  updated_at: string;             // ISO8601
  created_at: string;
}

interface Address {
  street?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
}

interface SharingSettings {
  // Which optional fields to include in shared profile
  share_phone: boolean;
  share_address: boolean;
  share_organization: boolean;
  share_bio: boolean;
  share_avatar: boolean;

  // Per-connection overrides (connection_id -> field list)
  connection_overrides?: Record<string, string[]>;
}
```

### Capability Metadata

Stored separately for efficient updates and queries:

```typescript
interface VaultCapabilities {
  user_guid: string;

  // === Available Data Types ===
  available_credentials: CredentialMetadata[];

  // === Supported Event Handlers ===
  supported_handlers: HandlerManifest[];

  // === Version Info ===
  capabilities_version: number;
  updated_at: string;
}

interface CredentialMetadata {
  credential_type: string;        // e.g., "credit_card", "drivers_license", "passport"
  credential_subtype?: string;    // e.g., "visa", "mastercard"
  display_name: string;           // e.g., "Visa ending in 4242"
  credential_id: string;          // For requesting specific credential
  issuer?: string;
  expires_at?: string;
  // NOTE: Never includes actual credential data
}

interface HandlerManifest {
  handler_type: string;           // e.g., "payment.request", "document.sign"
  version: string;                // Handler version
  description: string;
  required_permissions: string[]; // What the handler needs
  supported_since: string;        // When this vault added support
}

// Example capabilities for a user:
// {
//   available_credentials: [
//     { credential_type: "credit_card", credential_subtype: "visa", display_name: "Visa •••• 4242", ... },
//     { credential_type: "drivers_license", display_name: "CA Driver's License", ... }
//   ],
//   supported_handlers: [
//     { handler_type: "payment.request", version: "1.0", ... },
//     { handler_type: "identity.verify", version: "1.0", ... }
//   ]
// }
//
// This allows a merchant connection to see "User has a Visa card" and request payment
// WITHOUT ever seeing the actual card number until the user explicitly approves.
```

### Connection Data Model

```typescript
interface Connection {
  connection_id: string;

  // === Peer Identity ===
  peer_guid: string;
  peer_public_key: string;        // For E2E encryption

  // === Cached Peer Profile ===
  peer_profile: CachedPeerProfile;
  peer_capabilities?: VaultCapabilities;

  // === Connection State ===
  status: ConnectionStatus;
  direction: 'outbound' | 'inbound';

  // === NATS Credentials ===
  nats_credentials: string;       // Encrypted
  peer_owner_space: string;
  peer_message_space: string;

  // === Timestamps ===
  created_at: string;
  accepted_at?: string;
  expires_at?: string;
  last_rotated_at?: string;
  profile_last_synced_at?: string;
}

type ConnectionStatus =
  | 'pending_their_review'    // Waiting for peer to review our profile
  | 'pending_our_review'      // We need to review their profile
  | 'pending_their_accept'    // They reviewed, waiting for their accept
  | 'pending_our_accept'      // We reviewed, need to accept
  | 'active'                  // Both accepted, connection established
  | 'revoked'                 // Connection terminated
  | 'expired'                 // Invitation expired
  | 'blocked';                // Peer blocked

interface CachedPeerProfile {
  // Subset of UserProfile that peer chose to share
  user_guid: string;
  public_key: string;
  first_name: string;
  last_name: string;
  email: string;
  email_verified: boolean;

  // Optional fields (based on peer's sharing settings)
  display_name?: string;
  phone?: string;
  address?: Address;
  bio?: string;
  avatar_url?: string;
  organization?: string;

  // Sync metadata
  profile_version: number;
  cached_at: string;
}
```

---

## Connection Flow (Bidirectional Consent)

```
┌─────────────────┐                                    ┌─────────────────┐
│     User A      │                                    │     User B      │
│    (Inviter)    │                                    │   (Invitee)     │
└────────┬────────┘                                    └────────┬────────┘
         │                                                      │
         │ 1. CREATE INVITATION                                 │
         │    - Generate temp NATS creds for B                  │
         │    - Creds scoped to A's message space               │
         │    - Set invitation expiry (default: 24h)            │
         ▼                                                      │
    ┌─────────┐                                                 │
    │ Invite  │──── Share via QR/Message/Email/Link ───────────▶│
    │  Data   │                                                 │
    └─────────┘                                                 │
         │                                                      ▼
         │                                    2. INITIATE CONNECTION
         │                                       - Connect to A's message space
         │                                       - Retrieve A's shared profile
         │                                       - Send B's shared profile to A
         │                                       - Generate reciprocal NATS creds
         │◀──────────────── Profile Exchange ────────────────────│
         │                                                      │
         │                                                      ▼
         │                                    3. REVIEW & DECIDE (User B)
         │                                       - Display A's profile
         │                                       - Show verification status
         │                                       - [ACCEPT] or [REJECT]
         │                                                      │
         │                        ┌─────────────────────────────┤
         │                        │                             │
         │                   [REJECT]                      [ACCEPT]
         │                        │                             │
         │                        ▼                             ▼
         │              Revoke A's temp creds         Notify A of acceptance
         │              Connection terminated         A must now review B
         │                                                      │
         ▼                                                      │
    4. REVIEW & DECIDE (User A)◀────────────────────────────────┘
       - Display B's profile
       - Show verification status
       - [ACCEPT] or [REJECT]
         │
         ├──────────[REJECT]────────▶ Revoke B's creds, notify B
         │
         └──────────[ACCEPT]────────▶ 5. ESTABLISH SECURE CONNECTION
                                         │
                                         ▼
                                    ┌─────────────────────────────┐
                                    │  BIDIRECTIONAL CONNECTION   │
                                    │  - Exchange permanent keys  │
                                    │  - Rotate NATS credentials  │
                                    │  - Cache peer profiles      │
                                    │  - Subscribe to updates     │
                                    └─────────────────────────────┘
                                                │
                                    ┌───────────┴───────────┐
                                    │                       │
                                    ▼                       ▼
                              User A's Vault          User B's Vault
                              stores B's profile      stores A's profile
                              + capabilities          + capabilities
```

### Step-by-Step Protocol

#### Step 1: Create Invitation (User A)
```typescript
// Request
{
  action: "connection.create-invite",
  label: "Connection with Bob",           // A's label for this connection
  expiry_hours: 24,                        // Optional, default 24h
  share_fields: ["phone", "organization"] // Optional per-invite overrides
}

// Response
{
  invitation_id: string,
  invitation_code: string,                // Short code for manual entry
  invitation_url: string,                 // Deep link
  qr_data: string,                        // For QR code generation
  temp_nats_credentials: string,          // Encrypted, for B to use
  expires_at: string
}
```

#### Step 2: Initiate Connection (User B)
```typescript
// B decodes invitation and connects to A's message space

// Request to A's vault
{
  action: "connection.initiate",
  invitation_id: string,
  requester_profile: SharedProfile,       // B's profile to share with A
  requester_capabilities: VaultCapabilities,
  requester_nats_credentials: string      // Reciprocal creds for A
}

// Response from A's vault
{
  connection_id: string,
  inviter_profile: SharedProfile,         // A's profile
  inviter_capabilities: VaultCapabilities,
  status: "pending_their_review"          // B needs to review A
}
```

#### Step 3: Review & Accept/Reject (User B)
```typescript
// Request
{
  action: "connection.respond",
  connection_id: string,
  response: "accept" | "reject",
  rejection_reason?: string               // Optional, for A's information
}

// If accepted, A's vault transitions to "pending_our_accept"
// If rejected, temp credentials are revoked
```

#### Step 4: Review & Accept/Reject (User A)
```typescript
// A receives notification that B accepted
// A reviews B's profile

// Request
{
  action: "connection.respond",
  connection_id: string,
  response: "accept" | "reject"
}
```

#### Step 5: Finalize Connection
```typescript
// Automatically triggered when both accept

// Both vaults:
// 1. Generate permanent NATS credentials for peer
// 2. Rotate encryption keys
// 3. Cache peer profile and capabilities
// 4. Subscribe to peer's profile.updated topic

// Connection status changes to "active"
```

---

## Profile Updates & Notifications

When a user updates their profile:

```typescript
// 1. Update local profile
{
  action: "profile.update",
  updates: Partial<UserProfile>
}

// 2. Vault automatically notifies all active connections
// Published to: {peer_message_space}.profile.updated
{
  event_type: "profile.updated",
  user_guid: string,
  updated_fields: string[],
  profile_version: number,
  timestamp: string
}

// 3. Connected vaults fetch updated profile
{
  action: "connection.get-profile",
  connection_id: string
}

// Response includes only fields the updater chose to share
```

---

## NATS Topics

| Topic | Direction | Description |
|-------|-----------|-------------|
| `{space}.forVault.profile.get` | → Vault | Get own profile |
| `{space}.forVault.profile.update` | → Vault | Update own profile |
| `{space}.forVault.profile.get-shared` | → Vault | Get profile to share (applies sharing settings) |
| `{space}.forVault.capabilities.get` | → Vault | Get own capabilities |
| `{space}.forVault.capabilities.update` | → Vault | Update capabilities |
| `{space}.forVault.connection.create-invite` | → Vault | Create invitation |
| `{space}.forVault.connection.initiate` | → Vault | Initiate connection (invitee) |
| `{space}.forVault.connection.respond` | → Vault | Accept/reject connection |
| `{space}.forVault.connection.list` | → Vault | List connections |
| `{space}.forVault.connection.get` | → Vault | Get connection details |
| `{space}.forVault.connection.get-profile` | → Vault | Get peer's cached profile |
| `{space}.forVault.connection.rotate` | → Vault | Rotate credentials |
| `{space}.forVault.connection.revoke` | → Vault | Revoke connection |
| `{space}.forVault.connection.block` | → Vault | Block peer |
| `{peer_message_space}.profile.updated` | Vault → Vault | Profile update notification |
| `{peer_message_space}.capabilities.updated` | Vault → Vault | Capabilities update notification |
| `{peer_message_space}.connection.request` | Vault → Vault | New connection request |
| `{peer_message_space}.connection.accepted` | Vault → Vault | Connection accepted |
| `{peer_message_space}.connection.rejected` | Vault → Vault | Connection rejected |

---

## Security Considerations

### 1. Bidirectional Consent
- **Both parties must explicitly accept** before connection is established
- Either party can reject at any point during the handshake
- Rejection immediately revokes any temporary credentials

### 2. Credential Scoping & Rotation
- Invitation credentials are temporary with short TTL (default 24h)
- Permanent credentials have minimal NATS permissions (only peer's message space)
- Credentials rotate automatically (recommendation: every 7 days)
- Manual rotation available for security-conscious users

### 3. Profile Privacy
- Users control exactly which fields to share via `SharingSettings`
- Per-connection overrides allow different sharing levels for different connections
- Credential metadata never includes actual credential data (just type/display name)

### 4. End-to-End Encryption
- Each user has an Ed25519 keypair (public in profile, private in Protean Credential)
- Sensitive vault-to-vault messages encrypted with peer's public key
- Profile data changes (name, email, etc.) do NOT affect the keypair
- Key rotation available without credential re-enrollment
- Only catastrophic key compromise (private key extracted) requires re-enrollment

### 5. Verification Indicators
- `email_verified` flag shows if email was verified during enrollment
- Future: `identity_verified` for ID document verification
- UI should clearly indicate verification status to help prevent impersonation

### 6. Rate Limiting & Spam Prevention
- Limit invitation creation (e.g., max 10 pending invitations)
- Limit connection requests per day
- Block feature prevents repeated requests from blocked users

### 7. Invitation Security
- Invitation codes are single-use
- Expired invitations cannot be used
- QR codes should include checksum for tampering detection

### 8. Forward Secrecy
- Use X25519 for ephemeral session keys (rotated frequently)
- Ed25519 identity key for authentication only
- Compromise of current session key doesn't expose past messages

### 9. Trust on First Use (TOFU)
- Pin peer's public key after first successful connection
- Alert user if peer's key changes (possible compromise or re-enrollment)
- Require explicit acceptance to continue with new key

### 10. Audit Trail
- Log all connection events: created, accepted, rejected, revoked, blocked
- Include timestamps and device info
- Available in user's security audit log (Feed feature)

### 11. Emergency Controls
- "Revoke All Connections" panic button for suspected compromise
- "Lock Profile" to temporarily prevent new connection requests
- These actions should require password confirmation

### 12. Invitation Binding
- Invitation can optionally be bound to specific identifier (email, phone)
- Only that identifier can accept the invitation
- Prevents invitation forwarding/sharing attacks

---

## Usability Recommendations

### 1. Clear Status Indicators
```
Pending Requests (3)
├── John Smith - Awaiting your review
├── Jane Doe - Awaiting their acceptance
└── Bob Wilson - Awaiting their review
```

### 2. Profile Preview Before Accept
- Show peer's profile with verification badges
- Highlight what data will be shared with them
- "By accepting, you will share: Name, Email, Phone"

### 3. Easy Sharing Options
- Share via: QR Code, Copy Link, Share Sheet (SMS, Email, etc.)
- "Nearby" option using Bluetooth/WiFi Direct for in-person

### 4. Connection Health Indicators
- Show last activity time
- Warn if credentials expiring soon
- Alert if profile sync failed

### 5. Capability Discovery UI
- "What can I request from this connection?"
- Show available credential types without revealing values
- Enable contextual requests (e.g., "Request payment method")

### 6. Notification Preferences
- Per-connection notification settings
- Mute without blocking
- Digest mode for low-priority connections

### 7. Offline Handling
- Queue acceptance/rejection when offline
- Show "pending sync" indicator
- Gracefully handle mid-handshake disconnections

---

## Implementation Tasks

### Phase 1: Profile Expansion
- [ ] Define new profile schema in backend
- [ ] Create `ProfileClient.kt` with NATS handlers
- [ ] Add sharing settings UI
- [ ] Implement capability metadata storage
- [ ] Add profile caching in `EncryptedSharedPreferences`

### Phase 2: Connection Handshake
- [ ] Implement bidirectional consent flow in backend
- [ ] Create connection state machine
- [ ] Build profile review screen
- [ ] Add accept/reject UI with confirmation
- [ ] Implement invitation expiry handling

### Phase 3: Profile Sync & Notifications
- [ ] Implement `profile.updated` notification handler
- [ ] Build profile cache invalidation logic
- [ ] Add connection health monitoring
- [ ] Create update notification UI

### Phase 4: Credential Rotation
- [ ] Implement automatic rotation schedule
- [ ] Add manual rotation option
- [ ] Build rotation failure recovery
- [ ] Test rotation during active sessions

### Phase 5: Capability Discovery
- [ ] Design capability request protocol
- [ ] Build capability browser UI
- [ ] Implement selective disclosure flow
- [ ] Test cross-platform capability exchange

---

## Storage Architecture

### Local Storage (EncryptedSharedPreferences)

```
vettid_profiles/
├── my_profile.json           # User's own profile
├── my_capabilities.json      # User's capability metadata
└── sharing_settings.json     # Sharing preferences

vettid_connections/
├── index.json                # Connection list with status
├── {connection_id}/
│   ├── connection.json       # Connection metadata
│   ├── peer_profile.json     # Cached peer profile
│   ├── peer_capabilities.json
│   └── credentials.enc       # Encrypted NATS credentials
└── pending_requests.json     # Incoming requests awaiting review
```

### Vault Storage (Encrypted DynamoDB)

```
profile:{user_guid}           # Full profile
capabilities:{user_guid}      # Capability metadata
connection:{connection_id}    # Connection record
invitation:{invitation_id}    # Pending invitation
```

---

## Error Handling

| Scenario | Handling |
|----------|----------|
| Invitation expired | Show "This invitation has expired" with option to request new one |
| Peer rejected | Show "Connection declined" - no retry without new invitation |
| Network failure during handshake | Save state, retry on reconnect |
| Profile sync failed | Use cached version, show "Last updated X ago" |
| Credential rotation failed | Retry with backoff, alert user if persistent |
| Blocked user attempts contact | Silently ignore, no notification to blocker |

---

## References

- [NATS Messaging Architecture](./NATS-MESSAGING-ARCHITECTURE.md)
- [Vault Services Architecture](./vault_services_architecture.md)
- Android: `app/src/main/java/com/vettid/app/features/connections/`
- Android: `app/src/main/java/com/vettid/app/features/profile/`
