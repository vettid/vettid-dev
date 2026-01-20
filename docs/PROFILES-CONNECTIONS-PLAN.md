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

## Usability Features

### 1. Clear Status Indicators

**Description:**
```
Pending Requests (3)
├── John Smith - Awaiting your review
├── Jane Doe - Awaiting their acceptance
└── Bob Wilson - Awaiting their review

Active Connections (12)
├── Alice Cooper ✓ - Last active: 2 hours ago
├── Bob's Hardware Store ✓ - Last active: 1 day ago
└── Mom ✓ - Last active: 5 minutes ago
```

- Use color coding: green (active), yellow (pending), red (issue)
- Badge counts on navigation tabs for pending actions
- Sort by: recent activity, alphabetical, connection date

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionsScreen.kt` | Add `ConnectionStatusChip` composable with color states |
| Android | `ConnectionsViewModel.kt` | Add `pendingCount`, `sortOrder` StateFlow |
| Android | `BottomNavigation` | Add badge count from ViewModel |
| iOS | `ConnectionsView.swift` | Add status pills with SF Symbols |
| iOS | `ConnectionsViewModel.swift` | Add computed `pendingCount` property |
| iOS | `TabView` | Add `.badge()` modifier |
| Backend | `connection.list` handler | Add `last_active_at` field to response |
| Backend | DynamoDB | Track `last_activity_timestamp` per connection |

**Data Model Additions:**
```kotlin
data class ConnectionListItem(
    val connectionId: String,
    val peerName: String,
    val status: ConnectionStatus,
    val lastActiveAt: Instant?,
    val hasUnreadActivity: Boolean
)

enum class SortOrder { RECENT_ACTIVITY, ALPHABETICAL, CONNECTION_DATE }
```

---

### 2. Profile Preview Before Accept

**Description:**
- Show peer's profile with verification badges (✓ Email Verified, ✓ ID Verified)
- Highlight what data will be shared with them
- "By accepting, you will share: Name, Email, Phone"
- Show peer's capabilities: "This connection can request: Payment, Identity Verification"
- Warning if peer has no verifications: "This person has not verified their identity"
- Option to adjust sharing settings before accepting

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionReviewScreen.kt` | New screen with peer profile display |
| Android | `ConnectionReviewViewModel.kt` | Load peer profile, sharing preview |
| Android | `VerificationBadge.kt` | Reusable composable for ✓ badges |
| Android | `SharingPreviewCard.kt` | Show "You will share: X, Y, Z" |
| iOS | `ConnectionReviewView.swift` | SwiftUI view for peer review |
| iOS | `VerificationBadgeView.swift` | Reusable badge component |
| Backend | `connection.initiate` | Return `peer_verifications` array |
| Backend | `profile.get-shared` | Return `fields_to_share` preview |

**UI Flow:**
```
Scan QR → Loading → Review Screen → [Adjust Sharing] → Accept/Reject
                         │
                         ├── Peer Profile Card
                         ├── Verification Badges
                         ├── "You will share" section
                         ├── "They can request" section
                         └── Warning banner (if unverified)
```

---

### 3. Easy Sharing Options

**Description:**
- **QR Code**: Full-screen display with brightness boost, works offline
- **Copy Link**: Deep link that opens app directly
- **Share Sheet**: Native OS share to SMS, Email, WhatsApp, etc.
- **Nearby**: Bluetooth/WiFi Direct for in-person (no internet needed)
- **NFC Tap**: For devices with NFC support
- Show invitation expiry countdown: "Expires in 23h 45m"
- Allow re-generating expired invitations with one tap

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `CreateInvitationScreen.kt` | Update with all sharing methods |
| Android | `QrCodeFullScreen.kt` | Full-screen QR with auto-brightness |
| Android | `NearbyShareManager.kt` | Implement Google Nearby Connections API |
| Android | `NfcInvitationWriter.kt` | Write invitation to NFC tag |
| Android | `WindowManager` | Set `BRIGHTNESS_OVERRIDE_FULL` for QR |
| iOS | `CreateInvitationView.swift` | Update with sharing methods |
| iOS | `QRCodeFullScreenView.swift` | Full-screen with brightness boost |
| iOS | `MultipeerManager.swift` | Implement MultipeerConnectivity |
| iOS | `NFCWriter.swift` | Core NFC for writing invitations |
| Backend | `connection.create-invite` | Add `regenerate` flag for expired |
| Deep Links | Android `AndroidManifest.xml` | Add intent filter for `vettid://connect` |
| Deep Links | iOS `Info.plist` | Add URL scheme `vettid://` |

**QR Brightness Code (Android):**
```kotlin
DisposableEffect(Unit) {
    val window = (context as Activity).window
    val originalBrightness = window.attributes.screenBrightness
    window.attributes = window.attributes.apply {
        screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL
    }
    onDispose {
        window.attributes = window.attributes.apply {
            screenBrightness = originalBrightness
        }
    }
}
```

---

### 4. Connection Health Indicators

**Description:**
- **Last active**: "2 hours ago", "3 days ago", "Offline"
- **Credential status**: "Credentials rotate in 5 days"
- **Sync status**: "Profile up to date" or "Update available"
- **Trust level**: Based on verification status and connection age
- Visual indicator for connections that haven't been active in 30+ days

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionHealthCard.kt` | Composable showing all health metrics |
| Android | `ConnectionDetailScreen.kt` | Add health section |
| Android | `CredentialRotationTracker.kt` | Track rotation schedule locally |
| iOS | `ConnectionHealthView.swift` | SwiftUI health metrics card |
| iOS | `ConnectionDetailView.swift` | Add health section |
| Backend | `connection.get` | Return `credentials_expire_at`, `profile_version` |
| Backend | `connection.list` | Return `last_active_at`, `needs_attention` flag |

**Health Status Model:**
```kotlin
data class ConnectionHealth(
    val lastActiveAt: Instant?,
    val credentialsExpireAt: Instant,
    val profileVersion: Int,
    val cachedProfileVersion: Int,
    val trustScore: TrustLevel
) {
    val needsProfileSync: Boolean get() = profileVersion > cachedProfileVersion
    val credentialsExpiringSoon: Boolean get() = credentialsExpireAt < Instant.now().plus(7.days)
    val isStale: Boolean get() = lastActiveAt?.let { it < Instant.now().minus(30.days) } ?: true
}

enum class TrustLevel { NEW, ESTABLISHED, TRUSTED, VERIFIED }
```

---

### 5. Capability Discovery UI

**Description:**
- "What can I request from this connection?"
- Grouped by category: Payments, Identity, Documents
- Show available credential types without revealing values:
  ```
  Payment Methods (2)
  ├── Visa •••• 4242
  └── Mastercard •••• 8888

  Identity Documents (1)
  └── Driver's License - California
  ```
- "Request" button next to each capability
- History of past requests and responses

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `CapabilityBrowserScreen.kt` | New screen for browsing peer capabilities |
| Android | `CapabilityCard.kt` | Grouped display by category |
| Android | `RequestHistoryScreen.kt` | List of past requests/responses |
| Android | `CapabilityRequestDialog.kt` | Confirm before sending request |
| iOS | `CapabilityBrowserView.swift` | SwiftUI capability browser |
| iOS | `RequestHistoryView.swift` | Request history list |
| Backend | `connection.get-capabilities` | New handler to fetch peer capabilities |
| Backend | `capability.request` | New handler to request specific capability |
| Backend | `capability.request.list` | List request history |
| Backend | DynamoDB | `capability_requests` table |

**Request Flow:**
```
Browse Capabilities → Select Item → Confirm Dialog → Send Request
                                                         │
                                          Peer receives notification
                                                         │
                                          Peer approves/denies
                                                         │
                                          Requester gets result
```

---

### 6. Notification Preferences

**Description:**
- **Per-connection settings**:
  - All notifications
  - Important only (requests, security alerts)
  - Muted (no notifications, still receive messages)
- **Global quiet hours**: No notifications 10pm - 8am
- **Digest mode**: Daily summary instead of real-time
- **Priority connections**: Always notify regardless of quiet hours

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `NotificationPreferencesScreen.kt` | Global notification settings |
| Android | `ConnectionNotificationSettings.kt` | Per-connection preferences |
| Android | `NotificationPreferencesStore.kt` | EncryptedSharedPreferences storage |
| Android | `QuietHoursManager.kt` | Check time before showing notification |
| Android | `DigestWorker.kt` | WorkManager job for daily digest |
| iOS | `NotificationPreferencesView.swift` | Settings UI |
| iOS | `NotificationManager.swift` | Quiet hours, digest logic |
| iOS | `BackgroundTasks` | Daily digest task |
| Backend | `settings.notifications.update` | Store user preferences |
| Backend | `notifications.digest` | Aggregate notifications for digest |

**Preferences Model:**
```kotlin
data class NotificationPreferences(
    val globalEnabled: Boolean = true,
    val quietHoursEnabled: Boolean = false,
    val quietHoursStart: LocalTime = LocalTime.of(22, 0),
    val quietHoursEnd: LocalTime = LocalTime.of(8, 0),
    val digestMode: DigestMode = DigestMode.REALTIME,
    val connectionOverrides: Map<String, ConnectionNotificationLevel> = emptyMap(),
    val priorityConnections: Set<String> = emptySet()
)

enum class ConnectionNotificationLevel { ALL, IMPORTANT_ONLY, MUTED }
enum class DigestMode { REALTIME, DAILY_DIGEST }
```

---

### 7. Offline Handling

**Description:**
- Queue acceptance/rejection when offline
- Show "pending sync" indicator with retry button
- Gracefully handle mid-handshake disconnections
- Cache peer profiles for offline viewing
- Show clear "You're offline" banner with last sync time
- Auto-sync when connection restored

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `OfflineQueueManager.kt` | Queue operations when offline |
| Android | `ConnectionRepository.kt` | Add offline queue, sync status |
| Android | `OfflineBanner.kt` | Composable banner with retry |
| Android | `NetworkMonitor.kt` | ConnectivityManager observer |
| Android | `SyncWorker.kt` | WorkManager to process queue |
| iOS | `OfflineQueueManager.swift` | Queue operations |
| iOS | `ConnectionRepository.swift` | Offline support |
| iOS | `NetworkMonitor.swift` | NWPathMonitor observer |
| iOS | `BackgroundSync.swift` | Process queue when online |

**Offline Queue Model:**
```kotlin
data class PendingOperation(
    val id: String,
    val type: OperationType,
    val connectionId: String,
    val payload: String,  // JSON
    val createdAt: Instant,
    val retryCount: Int = 0
)

enum class OperationType {
    ACCEPT_CONNECTION,
    REJECT_CONNECTION,
    UPDATE_PROFILE,
    SEND_MESSAGE,
    ROTATE_CREDENTIALS
}

// Queue stored in EncryptedSharedPreferences
// Processed FIFO when connectivity restored
```

---

### 8. Onboarding & First-Time Experience

**Description:**
- **First connection wizard**: Guide user through creating first invitation
- **Sample connection**: Option to connect with VettID support for testing
- **Tooltips**: Explain verification badges, capability icons on first view
- **Empty states**: Friendly messages when no connections exist yet

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionsOnboardingScreen.kt` | Step-by-step wizard |
| Android | `TooltipOverlay.kt` | Spotlight tooltips for first use |
| Android | `EmptyConnectionsState.kt` | Friendly empty state |
| Android | `OnboardingPreferences.kt` | Track which tooltips shown |
| iOS | `ConnectionsOnboardingView.swift` | Wizard with page indicators |
| iOS | `TooltipModifier.swift` | SwiftUI tooltip overlay |
| iOS | `EmptyConnectionsView.swift` | Empty state with illustration |
| Backend | VettID Support Vault | Pre-configured test connection endpoint |

**Onboarding Flow:**
```
First Launch → "Let's create your first connection!"
                         │
            ┌────────────┼────────────┐
            │            │            │
       "Invite Someone"  │   "Connect with VettID Support"
            │            │            │
    Create QR Screen     │     Auto-accept test connection
            │            │            │
    Share with friend    │     Explore features safely
            │            │            │
            └────────────┴────────────┘
                         │
              "Great! You're all set."
```

---

### 9. Profile Management

**Description:**
- **Preview mode**: "See how others see your profile"
- **Quick sharing toggles**: One-tap to show/hide phone, address, etc.
- **Field-level privacy**: Lock icon on fields not shared
- **Edit history**: "Last updated 3 days ago"
- **Sync indicator**: Show when profile is syncing to vault

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ProfilePreviewScreen.kt` | Show profile as others see it |
| Android | `ProfileEditScreen.kt` | Add sharing toggles per field |
| Android | `SharingToggle.kt` | Eye/lock icon toggle component |
| Android | `ProfileSyncIndicator.kt` | Syncing/synced status |
| Android | `ProfileViewModel.kt` | Add `previewMode`, `syncStatus` |
| iOS | `ProfilePreviewView.swift` | Preview mode |
| iOS | `ProfileEditView.swift` | Sharing toggles |
| iOS | `SharingToggleStyle.swift` | Custom toggle style |
| Backend | `profile.update` | Return `updated_at` timestamp |
| Backend | `profile.get-shared` | Apply sharing settings |

**UI Layout:**
```
┌─────────────────────────────────────┐
│ My Profile          [Preview] [Edit]│
├─────────────────────────────────────┤
│ Name: John Smith            🔓      │
│ Email: john@example.com     🔓      │
│ Phone: +1 555-1234          👁️ ────── Toggle to share/hide
│ Address: 123 Main St        🔒      │
│ Organization: Acme Inc      👁️      │
├─────────────────────────────────────┤
│ Last updated: 3 days ago    ✓ Synced│
└─────────────────────────────────────┘
```

---

### 10. Trust Building Features

**Description:**
- **Connection age badge**: "Connected for 2 years"
- **Mutual connections**: "You both know: Alice, Bob" (future)
- **Verification chain**: Show what's been verified and by whom
- **Activity summary**: "15 successful transactions"

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `TrustBadge.kt` | Connection age badge composable |
| Android | `VerificationChain.kt` | Show verification history |
| Android | `ActivitySummary.kt` | Transaction/interaction count |
| Android | `ConnectionDetailScreen.kt` | Add trust section |
| iOS | `TrustBadgeView.swift` | Age badge |
| iOS | `VerificationChainView.swift` | Verification history |
| iOS | `ActivitySummaryView.swift` | Activity count |
| Backend | `connection.get` | Return `created_at`, `activity_count` |
| Backend | `connection.activity-summary` | Aggregate activity stats |
| Backend | DynamoDB | Track `activity_count` per connection |

**Trust Calculation:**
```kotlin
fun calculateTrustLevel(connection: Connection): TrustLevel {
    val ageMonths = ChronoUnit.MONTHS.between(connection.createdAt, Instant.now())
    val hasVerifiedEmail = connection.peerProfile.emailVerified
    val hasVerifiedIdentity = connection.peerProfile.identityVerified
    val activityCount = connection.activityCount

    return when {
        hasVerifiedIdentity && ageMonths >= 12 -> TrustLevel.VERIFIED
        hasVerifiedEmail && ageMonths >= 6 && activityCount >= 10 -> TrustLevel.TRUSTED
        ageMonths >= 1 || activityCount >= 3 -> TrustLevel.ESTABLISHED
        else -> TrustLevel.NEW
    }
}
```

---

### 11. Error Recovery

**Description:**
- **Clear error messages**: "Connection failed: John rejected your request"
- **Suggested actions**: "Try sending a new invitation"
- **Retry with context**: Don't lose user's input on failure
- **Support shortcut**: Easy access to help when errors occur

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionErrorScreen.kt` | Dedicated error screen |
| Android | `ErrorMessageMapper.kt` | Map error codes to user messages |
| Android | `RetryManager.kt` | Preserve state for retry |
| Android | `SupportShortcut.kt` | Quick link to help/support |
| iOS | `ConnectionErrorView.swift` | Error display |
| iOS | `ErrorMessageMapper.swift` | Error code mapping |
| iOS | `RetryManager.swift` | State preservation |

**Error Message Mapping:**
```kotlin
object ConnectionErrorMessages {
    fun getErrorMessage(error: ConnectionError): ErrorDisplay {
        return when (error) {
            is ConnectionError.Rejected -> ErrorDisplay(
                title = "Connection Declined",
                message = "${error.peerName} declined your connection request.",
                suggestedAction = "You can send a new invitation if you'd like to try again.",
                actionButton = "Create New Invitation"
            )
            is ConnectionError.Expired -> ErrorDisplay(
                title = "Invitation Expired",
                message = "This invitation is no longer valid.",
                suggestedAction = "Create a new invitation to connect.",
                actionButton = "Create New Invitation"
            )
            is ConnectionError.NetworkError -> ErrorDisplay(
                title = "Connection Failed",
                message = "Unable to reach the server. Check your internet connection.",
                suggestedAction = "Your progress has been saved. Try again when you're online.",
                actionButton = "Retry"
            )
            // ... more mappings
        }
    }
}
```

---

### 12. Connection Organization

**Description:**
- **Labels/Tags**: User-defined categories (Family, Work, Merchants)
- **Favorites**: Pin important connections to top
- **Search**: Find by name, email, organization
- **Filters**: By status, verification level, last active
- **Archive**: Hide inactive connections without revoking

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `ConnectionTagsManager.kt` | Create/assign tags |
| Android | `TagChip.kt` | Tag display composable |
| Android | `ConnectionsFilterSheet.kt` | Bottom sheet with filters |
| Android | `ConnectionSearchBar.kt` | Search with debounce |
| Android | `ArchiveManager.kt` | Archive/unarchive logic |
| iOS | `ConnectionTagsManager.swift` | Tag management |
| iOS | `ConnectionsFilterView.swift` | Filter sheet |
| iOS | `ConnectionSearchBar.swift` | Search bar |
| Backend | `connection.update` | Add `tags`, `is_favorite`, `is_archived` fields |
| Backend | `connection.list` | Support filter/search query params |
| Backend | DynamoDB | GSI for tag-based queries |

**Filter/Search Model:**
```kotlin
data class ConnectionFilter(
    val searchQuery: String? = null,
    val tags: Set<String>? = null,
    val status: Set<ConnectionStatus>? = null,
    val verificationLevel: VerificationLevel? = null,
    val showArchived: Boolean = false,
    val favoritesOnly: Boolean = false,
    val sortOrder: SortOrder = SortOrder.RECENT_ACTIVITY
)

data class ConnectionTag(
    val id: String,
    val name: String,
    val color: String  // Hex color
)
```

---

### 13. Invitation Tracking

**Description:**
- **Sent invitations list**: Track all pending outbound invitations
- **Status updates**: "John viewed your invitation" (if they open the link)
- **Reminder option**: "Resend invitation" for pending invites
- **Cancel invitation**: Revoke before acceptance

**Implementation Requirements:**

| Platform | Component | Work Required |
|----------|-----------|---------------|
| Android | `SentInvitationsScreen.kt` | List of outbound invitations |
| Android | `InvitationStatusCard.kt` | Show status, expiry, actions |
| Android | `InvitationViewModel.kt` | Track invitation states |
| iOS | `SentInvitationsView.swift` | Invitation list |
| iOS | `InvitationStatusCard.swift` | Status display |
| Backend | `invitation.list` | List user's sent invitations |
| Backend | `invitation.cancel` | Revoke pending invitation |
| Backend | `invitation.resend` | Regenerate with new expiry |
| Backend | `invitation.viewed` | Track when invitation link opened |
| Backend | DynamoDB | `invitations` table with status tracking |

**Invitation Status Flow:**
```
Created → Sent → Viewed → Accepted/Rejected/Expired/Cancelled
   │        │       │
   │        │       └── "John viewed 2 hours ago"
   │        │
   │        └── "Sent via SMS"
   │
   └── "Created 5 minutes ago, expires in 23h 55m"
```

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
