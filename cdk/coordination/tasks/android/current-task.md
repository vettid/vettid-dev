# Task: Phase 7 - Connections & Messaging UI

## Phase
Phase 7: Connections & Messaging

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

## Status
Phase 6 complete. Ready for Phase 7 connections & messaging UI.

## Overview

Phase 7 implements the connection and messaging system UI. You need to create:
1. Connection invitation generation and QR code display
2. Connection invitation scanning and acceptance
3. Connection list and detail views
4. Profile viewing and editing
5. Encrypted messaging UI with conversation views

## API Endpoints (Backend)

### Connections
```
POST /connections/invite          # Generate connection invitation
POST /connections/accept          # Accept connection invitation
POST /connections/revoke          # Revoke connection
GET  /connections                 # List connections
GET  /connections/{id}            # Get connection details
GET  /connections/{id}/profile    # Get connection's profile
```

### Profiles
```
GET  /profile                     # Get own profile
PUT  /profile                     # Update own profile
POST /profile/publish             # Publish profile to connections
```

### Messaging
```
POST /messages/send               # Send encrypted message
GET  /messages/{connectionId}     # Get message history
GET  /messages/unread             # Get unread message count
POST /messages/{id}/read          # Mark message as read
```

## Phase 7 Android Tasks

### 1. Connection Data Models

Create connection and messaging data models:

```kotlin
// data/model/Connection.kt

data class Connection(
    val connectionId: String,
    val peerGuid: String,
    val peerDisplayName: String,
    val peerAvatarUrl: String?,
    val status: ConnectionStatus,
    val createdAt: Long,
    val lastMessageAt: Long?,
    val unreadCount: Int
)

enum class ConnectionStatus {
    PENDING,
    ACTIVE,
    REVOKED
}

data class ConnectionInvitation(
    val invitationId: String,
    val invitationCode: String,
    val qrCodeData: String,
    val deepLinkUrl: String,
    val expiresAt: Long,
    val creatorDisplayName: String
)

// data/model/Message.kt

data class Message(
    val messageId: String,
    val connectionId: String,
    val senderId: String,
    val content: String,
    val contentType: MessageContentType,
    val sentAt: Long,
    val receivedAt: Long?,
    val readAt: Long?,
    val status: MessageStatus
)

enum class MessageContentType {
    TEXT,
    IMAGE,
    FILE
}

enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED
}

// data/model/Profile.kt

data class Profile(
    val guid: String,
    val displayName: String,
    val avatarUrl: String?,
    val bio: String?,
    val location: String?,
    val lastUpdated: Long
)
```

### 2. Connection API Client

Create API client for connections:

```kotlin
// network/ConnectionApiClient.kt

interface ConnectionApiClient {
    suspend fun createInvitation(expiresInMinutes: Int = 60): Result<ConnectionInvitation>
    suspend fun acceptInvitation(invitationCode: String, publicKey: ByteArray): Result<Connection>
    suspend fun revokeConnection(connectionId: String): Result<Unit>
    suspend fun listConnections(): Result<List<Connection>>
    suspend fun getConnection(connectionId: String): Result<Connection>
    suspend fun getConnectionProfile(connectionId: String): Result<Profile>
}

// network/ProfileApiClient.kt

interface ProfileApiClient {
    suspend fun getProfile(): Result<Profile>
    suspend fun updateProfile(profile: Profile): Result<Profile>
    suspend fun publishProfile(): Result<Unit>
}

// network/MessagingApiClient.kt

interface MessagingApiClient {
    suspend fun sendMessage(connectionId: String, encryptedContent: ByteArray, nonce: ByteArray): Result<Message>
    suspend fun getMessageHistory(connectionId: String, limit: Int = 50, before: Long? = null): Result<List<Message>>
    suspend fun getUnreadCount(): Result<Map<String, Int>>
    suspend fun markAsRead(messageId: String): Result<Unit>
}
```

### 3. Connection Crypto Manager

Create crypto manager for per-connection encryption:

```kotlin
// crypto/ConnectionCryptoManager.kt

class ConnectionCryptoManager @Inject constructor(
    private val credentialStore: CredentialStore
) {
    // Generate X25519 key pair for new connection
    fun generateConnectionKeyPair(): KeyPair

    // Derive shared secret from X25519 key exchange
    fun deriveSharedSecret(
        privateKey: ByteArray,
        peerPublicKey: ByteArray
    ): ByteArray

    // Derive per-connection encryption key using HKDF
    fun deriveConnectionKey(
        sharedSecret: ByteArray,
        connectionId: String
    ): ByteArray

    // Encrypt message with XChaCha20-Poly1305
    fun encryptMessage(
        plaintext: String,
        connectionKey: ByteArray
    ): EncryptedMessage

    // Decrypt message with XChaCha20-Poly1305
    fun decryptMessage(
        ciphertext: ByteArray,
        nonce: ByteArray,
        connectionKey: ByteArray
    ): String

    // Store connection key securely
    suspend fun storeConnectionKey(connectionId: String, key: ByteArray)

    // Retrieve connection key
    suspend fun getConnectionKey(connectionId: String): ByteArray?
}

data class EncryptedMessage(
    val ciphertext: ByteArray,
    val nonce: ByteArray
)
```

### 4. Connection Invitation UI

Create invitation flow screens:

```kotlin
// ui/connections/invite/CreateInvitationScreen.kt

@Composable
fun CreateInvitationScreen(
    viewModel: CreateInvitationViewModel = hiltViewModel(),
    onInvitationCreated: (ConnectionInvitation) -> Unit,
    onBack: () -> Unit
)

// States: Idle, Creating, Created(invitation), Error

// UI Components:
// - Expiration time selector (15min, 1hr, 24hr)
// - Create button
// - Loading indicator
// - QR code display (large, centered)
// - Share button (deep link)
// - Copy link button
// - Expiration countdown timer

// ui/connections/invite/ScanInvitationScreen.kt

@Composable
fun ScanInvitationScreen(
    viewModel: ScanInvitationViewModel = hiltViewModel(),
    onConnectionEstablished: (Connection) -> Unit,
    onBack: () -> Unit
)

// States: Scanning, Processing, Success(connection), Error

// UI Components:
// - Camera preview with QR scanner overlay
// - Manual code entry option
// - Processing indicator
// - Connection preview (peer name, avatar)
// - Accept/Decline buttons
// - Error display with retry
```

### 5. Connection List UI

Create connection list screen:

```kotlin
// ui/connections/list/ConnectionsScreen.kt

@Composable
fun ConnectionsScreen(
    viewModel: ConnectionsViewModel = hiltViewModel(),
    onConnectionClick: (String) -> Unit,
    onCreateInvitation: () -> Unit,
    onScanInvitation: () -> Unit
)

// States: Loading, Empty, Loaded(connections), Error

// UI Components:
// - FAB with options: Create Invitation, Scan Invitation
// - Connection list with:
//   - Avatar
//   - Display name
//   - Last message preview
//   - Unread badge
//   - Last activity time
// - Pull-to-refresh
// - Search/filter
// - Empty state with onboarding

// ui/connections/list/ConnectionListItem.kt

@Composable
fun ConnectionListItem(
    connection: Connection,
    lastMessage: Message?,
    onClick: () -> Unit
)
```

### 6. Connection Detail UI

Create connection detail screen:

```kotlin
// ui/connections/detail/ConnectionDetailScreen.kt

@Composable
fun ConnectionDetailScreen(
    connectionId: String,
    viewModel: ConnectionDetailViewModel = hiltViewModel(),
    onMessageClick: () -> Unit,
    onBack: () -> Unit
)

// UI Components:
// - Large avatar
// - Display name
// - Connection status badge
// - Connected since date
// - Profile info (bio, location)
// - Actions:
//   - Send Message
//   - View Profile
//   - Revoke Connection (with confirmation)
// - Connection stats (messages exchanged, etc.)
```

### 7. Profile UI

Create profile screens:

```kotlin
// ui/profile/ProfileScreen.kt

@Composable
fun ProfileScreen(
    viewModel: ProfileViewModel = hiltViewModel(),
    onEditProfile: () -> Unit
)

// UI Components:
// - Avatar (with edit option)
// - Display name
// - Bio
// - Location
// - Edit button
// - Publish to connections button

// ui/profile/EditProfileScreen.kt

@Composable
fun EditProfileScreen(
    viewModel: EditProfileViewModel = hiltViewModel(),
    onSave: () -> Unit,
    onBack: () -> Unit
)

// UI Components:
// - Avatar picker (camera/gallery)
// - Display name field (required)
// - Bio field (optional, multiline)
// - Location field (optional)
// - Save button
// - Validation feedback
```

### 8. Messaging UI

Create messaging screens:

```kotlin
// ui/messaging/ConversationScreen.kt

@Composable
fun ConversationScreen(
    connectionId: String,
    viewModel: ConversationViewModel = hiltViewModel(),
    onBack: () -> Unit,
    onConnectionDetail: () -> Unit
)

// States: Loading, Empty, Loaded(messages), Error

// UI Components:
// - Top bar with connection name/avatar
// - Message list (LazyColumn, reversed)
//   - Sent messages (right-aligned, colored)
//   - Received messages (left-aligned)
//   - Timestamps (grouped by day)
//   - Read receipts
// - Message input field
// - Send button
// - Attachment button (future)
// - Scroll to bottom FAB

// ui/messaging/MessageBubble.kt

@Composable
fun MessageBubble(
    message: Message,
    isSent: Boolean,
    showTimestamp: Boolean
)

// ui/messaging/MessageInput.kt

@Composable
fun MessageInput(
    value: String,
    onValueChange: (String) -> Unit,
    onSend: () -> Unit,
    enabled: Boolean
)
```

### 9. Connection ViewModels

Create ViewModels for connection flows:

```kotlin
// ui/connections/invite/CreateInvitationViewModel.kt

@HiltViewModel
class CreateInvitationViewModel @Inject constructor(
    private val connectionApiClient: ConnectionApiClient,
    private val connectionCryptoManager: ConnectionCryptoManager
) : ViewModel() {

    val state: StateFlow<CreateInvitationState>

    fun createInvitation(expiresInMinutes: Int)
    fun shareInvitation()
    fun copyLink()
}

// ui/connections/invite/ScanInvitationViewModel.kt

@HiltViewModel
class ScanInvitationViewModel @Inject constructor(
    private val connectionApiClient: ConnectionApiClient,
    private val connectionCryptoManager: ConnectionCryptoManager
) : ViewModel() {

    val state: StateFlow<ScanInvitationState>

    fun onQrCodeScanned(data: String)
    fun onManualCodeEntered(code: String)
    fun acceptInvitation()
    fun declineInvitation()
}

// ui/connections/list/ConnectionsViewModel.kt

@HiltViewModel
class ConnectionsViewModel @Inject constructor(
    private val connectionApiClient: ConnectionApiClient,
    private val messagingApiClient: MessagingApiClient
) : ViewModel() {

    val connections: StateFlow<List<ConnectionWithLastMessage>>
    val isLoading: StateFlow<Boolean>

    fun refresh()
    fun search(query: String)
}

// ui/messaging/ConversationViewModel.kt

@HiltViewModel
class ConversationViewModel @Inject constructor(
    private val messagingApiClient: MessagingApiClient,
    private val connectionCryptoManager: ConnectionCryptoManager,
    savedStateHandle: SavedStateHandle
) : ViewModel() {

    private val connectionId: String = savedStateHandle["connectionId"]!!

    val messages: StateFlow<List<Message>>
    val connectionKey: StateFlow<ByteArray?>
    val sendingState: StateFlow<SendingState>

    fun loadMessages()
    fun loadMoreMessages()
    fun sendMessage(content: String)
    fun markAsRead(messageId: String)
}
```

### 10. QR Code Components

Create QR code scanner and generator:

```kotlin
// ui/components/QrCodeGenerator.kt

@Composable
fun QrCodeDisplay(
    data: String,
    size: Dp = 250.dp,
    modifier: Modifier = Modifier
)

// ui/components/QrCodeScanner.kt

@Composable
fun QrCodeScanner(
    onQrCodeScanned: (String) -> Unit,
    onError: (Exception) -> Unit,
    modifier: Modifier = Modifier
)

// Uses CameraX + ML Kit Barcode Scanning
// Request camera permission
// Overlay with scan frame
```

### 11. Real-time Updates

Integrate NATS for real-time messaging:

```kotlin
// messaging/MessageSubscriber.kt

class MessageSubscriber @Inject constructor(
    private val natsClient: NatsClient,
    private val connectionCryptoManager: ConnectionCryptoManager
) {
    // Subscribe to incoming messages
    fun subscribeToMessages(
        onMessage: (Message) -> Unit
    ): Job

    // Subscribe to connection events
    fun subscribeToConnectionEvents(
        onEvent: (ConnectionEvent) -> Unit
    ): Job
}

sealed class ConnectionEvent {
    data class InvitationAccepted(val connection: Connection) : ConnectionEvent()
    data class ConnectionRevoked(val connectionId: String) : ConnectionEvent()
    data class ProfileUpdated(val connectionId: String, val profile: Profile) : ConnectionEvent()
}
```

### 12. Navigation Integration

Add connection routes to navigation:

```kotlin
// Update VettIDApp.kt navigation graph

// New routes:
// - connections (list)
// - connections/create-invitation
// - connections/scan-invitation
// - connections/{connectionId}
// - connections/{connectionId}/messages
// - profile
// - profile/edit
```

## Dependencies

Add to `build.gradle.kts`:
```kotlin
// QR Code generation
implementation("com.google.zxing:core:3.5.2")

// QR Code scanning (CameraX + ML Kit)
implementation("androidx.camera:camera-camera2:1.3.1")
implementation("androidx.camera:camera-lifecycle:1.3.1")
implementation("androidx.camera:camera-view:1.3.1")
implementation("com.google.mlkit:barcode-scanning:17.2.0")

// Image loading for avatars (already have Coil)
// implementation("io.coil-kt:coil-compose:2.5.0")
```

## Deliverables

- [ ] Connection data models (Connection, Invitation, Message, Profile)
- [ ] ConnectionApiClient implementation
- [ ] MessagingApiClient implementation
- [ ] ProfileApiClient implementation
- [ ] ConnectionCryptoManager (X25519, XChaCha20-Poly1305)
- [ ] CreateInvitationScreen with QR code display
- [ ] ScanInvitationScreen with camera/ML Kit
- [ ] ConnectionsScreen (list with last message)
- [ ] ConnectionDetailScreen
- [ ] ProfileScreen and EditProfileScreen
- [ ] ConversationScreen with message bubbles
- [ ] MessageSubscriber for real-time updates
- [ ] Navigation integration
- [ ] Unit tests for ViewModels

## Acceptance Criteria

- [ ] Can create and display connection invitation QR code
- [ ] Can scan QR code and accept invitation
- [ ] X25519 key exchange establishes shared secret
- [ ] Per-connection encryption keys stored securely
- [ ] Connection list shows all connections with unread counts
- [ ] Can view and edit own profile
- [ ] Messages encrypted with XChaCha20-Poly1305
- [ ] Real-time message delivery via NATS
- [ ] Proper error handling and loading states

## Notes

- Use ZXing for QR generation, ML Kit for scanning
- Store connection keys in EncryptedSharedPreferences
- Test encryption with known test vectors
- Handle offline scenarios (queue messages)
- Consider message pagination for long conversations

## Status Update

```bash
cd /path/to/vettid-android
git pull
# Implement connections & messaging UI
./gradlew test  # Verify tests pass
git add .
git commit -m "Phase 7: Add connections and messaging UI"
git push

# Update status
# Edit cdk/coordination/status/android.json (in vettid-dev repo)
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 7 connections & messaging complete"
git push
```
