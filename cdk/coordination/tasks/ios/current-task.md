# Task: Phase 7 - Connections & Messaging UI

## Phase
Phase 7: Connections & Messaging

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

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

## Phase 7 iOS Tasks

### 1. Connection Data Models

Create connection and messaging data models:

```swift
// Models/Connection.swift

struct Connection: Codable, Identifiable {
    let id: String           // connectionId
    let peerGuid: String
    let peerDisplayName: String
    let peerAvatarUrl: String?
    let status: ConnectionStatus
    let createdAt: Date
    let lastMessageAt: Date?
    let unreadCount: Int
}

enum ConnectionStatus: String, Codable {
    case pending
    case active
    case revoked
}

struct ConnectionInvitation: Codable {
    let invitationId: String
    let invitationCode: String
    let qrCodeData: String
    let deepLinkUrl: String
    let expiresAt: Date
    let creatorDisplayName: String
}

// Models/Message.swift

struct Message: Codable, Identifiable {
    let id: String           // messageId
    let connectionId: String
    let senderId: String
    let content: String
    let contentType: MessageContentType
    let sentAt: Date
    let receivedAt: Date?
    let readAt: Date?
    let status: MessageStatus
}

enum MessageContentType: String, Codable {
    case text
    case image
    case file
}

enum MessageStatus: String, Codable {
    case sending
    case sent
    case delivered
    case read
    case failed
}

// Models/Profile.swift

struct Profile: Codable {
    let guid: String
    var displayName: String
    var avatarUrl: String?
    var bio: String?
    var location: String?
    let lastUpdated: Date
}
```

### 2. Connection API Client

Create API client extensions for connections:

```swift
// Services/ConnectionAPIClient.swift

extension APIClient {
    func createInvitation(expiresInMinutes: Int = 60) async throws -> ConnectionInvitation
    func acceptInvitation(code: String, publicKey: Data) async throws -> Connection
    func revokeConnection(connectionId: String) async throws
    func listConnections() async throws -> [Connection]
    func getConnection(id: String) async throws -> Connection
    func getConnectionProfile(connectionId: String) async throws -> Profile
}

// Services/ProfileAPIClient.swift

extension APIClient {
    func getProfile() async throws -> Profile
    func updateProfile(_ profile: Profile) async throws -> Profile
    func publishProfile() async throws
}

// Services/MessagingAPIClient.swift

extension APIClient {
    func sendMessage(
        connectionId: String,
        encryptedContent: Data,
        nonce: Data
    ) async throws -> Message

    func getMessageHistory(
        connectionId: String,
        limit: Int = 50,
        before: Date? = nil
    ) async throws -> [Message]

    func getUnreadCount() async throws -> [String: Int]

    func markAsRead(messageId: String) async throws
}
```

### 3. Connection Crypto Manager

Create crypto manager for per-connection encryption:

```swift
// Crypto/ConnectionCryptoManager.swift

class ConnectionCryptoManager {
    private let credentialStore: CredentialStore

    init(credentialStore: CredentialStore) {
        self.credentialStore = credentialStore
    }

    // Generate X25519 key pair for new connection
    func generateConnectionKeyPair() throws -> (publicKey: Data, privateKey: Data)

    // Derive shared secret from X25519 key exchange
    func deriveSharedSecret(
        privateKey: Data,
        peerPublicKey: Data
    ) throws -> Data

    // Derive per-connection encryption key using HKDF
    func deriveConnectionKey(
        sharedSecret: Data,
        connectionId: String
    ) throws -> Data

    // Encrypt message with XChaCha20-Poly1305
    func encryptMessage(
        plaintext: String,
        connectionKey: Data
    ) throws -> EncryptedMessage

    // Decrypt message with XChaCha20-Poly1305
    func decryptMessage(
        ciphertext: Data,
        nonce: Data,
        connectionKey: Data
    ) throws -> String

    // Store connection key securely in Keychain
    func storeConnectionKey(connectionId: String, key: Data) throws

    // Retrieve connection key from Keychain
    func getConnectionKey(connectionId: String) throws -> Data?
}

struct EncryptedMessage {
    let ciphertext: Data
    let nonce: Data
}
```

### 4. Connection Invitation Views

Create invitation flow views:

```swift
// Views/Connections/CreateInvitationView.swift

struct CreateInvitationView: View {
    @StateObject private var viewModel = CreateInvitationViewModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                switch viewModel.state {
                case .idle:
                    expirationPicker
                    createButton

                case .creating:
                    ProgressView("Creating invitation...")

                case .created(let invitation):
                    qrCodeDisplay(invitation)
                    shareButtons(invitation)
                    expirationTimer(invitation)

                case .error(let message):
                    ErrorView(message: message) {
                        viewModel.reset()
                    }
                }
            }
            .padding()
            .navigationTitle("Create Invitation")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}

// Views/Connections/ScanInvitationView.swift

struct ScanInvitationView: View {
    @StateObject private var viewModel = ScanInvitationViewModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            ZStack {
                switch viewModel.state {
                case .scanning:
                    QRCodeScannerView(
                        onScan: { viewModel.onQrCodeScanned($0) }
                    )
                    scanOverlay

                case .processing:
                    ProgressView("Connecting...")

                case .preview(let peerInfo):
                    ConnectionPreviewView(
                        peerInfo: peerInfo,
                        onAccept: { viewModel.acceptInvitation() },
                        onDecline: { dismiss() }
                    )

                case .success(let connection):
                    ConnectionSuccessView(connection: connection) {
                        dismiss()
                    }

                case .error(let message):
                    ErrorView(message: message) {
                        viewModel.reset()
                    }
                }
            }
            .navigationTitle("Scan Invitation")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
```

### 5. Connection List View

Create connection list screen:

```swift
// Views/Connections/ConnectionsListView.swift

struct ConnectionsListView: View {
    @StateObject private var viewModel = ConnectionsViewModel()
    @State private var showCreateInvitation = false
    @State private var showScanInvitation = false

    var body: some View {
        NavigationView {
            Group {
                switch viewModel.state {
                case .loading:
                    ProgressView()

                case .empty:
                    EmptyConnectionsView(
                        onCreateInvitation: { showCreateInvitation = true },
                        onScanInvitation: { showScanInvitation = true }
                    )

                case .loaded(let connections):
                    List(connections) { connection in
                        NavigationLink(destination: ConnectionDetailView(connectionId: connection.id)) {
                            ConnectionListRow(
                                connection: connection,
                                lastMessage: viewModel.lastMessage(for: connection.id)
                            )
                        }
                    }
                    .listStyle(.plain)
                    .refreshable {
                        await viewModel.refresh()
                    }

                case .error(let message):
                    ErrorView(message: message) {
                        Task { await viewModel.refresh() }
                    }
                }
            }
            .navigationTitle("Connections")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button(action: { showCreateInvitation = true }) {
                            Label("Create Invitation", systemImage: "qrcode")
                        }
                        Button(action: { showScanInvitation = true }) {
                            Label("Scan Invitation", systemImage: "qrcode.viewfinder")
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .searchable(text: $viewModel.searchQuery)
        }
        .sheet(isPresented: $showCreateInvitation) {
            CreateInvitationView()
        }
        .sheet(isPresented: $showScanInvitation) {
            ScanInvitationView()
        }
        .task {
            await viewModel.loadConnections()
        }
    }
}

// Views/Connections/ConnectionListRow.swift

struct ConnectionListRow: View {
    let connection: Connection
    let lastMessage: Message?

    var body: some View {
        HStack(spacing: 12) {
            // Avatar
            AsyncImage(url: URL(string: connection.peerAvatarUrl ?? "")) { image in
                image.resizable().aspectRatio(contentMode: .fill)
            } placeholder: {
                Image(systemName: "person.circle.fill")
                    .foregroundColor(.secondary)
            }
            .frame(width: 50, height: 50)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(connection.peerDisplayName)
                        .font(.headline)
                    Spacer()
                    if let lastMessageAt = connection.lastMessageAt {
                        Text(lastMessageAt, style: .relative)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if let lastMessage = lastMessage {
                    Text(lastMessage.content)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            // Unread badge
            if connection.unreadCount > 0 {
                Text("\(connection.unreadCount)")
                    .font(.caption2)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.blue)
                    .clipShape(Capsule())
            }
        }
        .padding(.vertical, 4)
    }
}
```

### 6. Connection Detail View

Create connection detail screen:

```swift
// Views/Connections/ConnectionDetailView.swift

struct ConnectionDetailView: View {
    let connectionId: String
    @StateObject private var viewModel = ConnectionDetailViewModel()
    @State private var showRevokeConfirmation = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Avatar and name
                VStack(spacing: 12) {
                    AsyncImage(url: URL(string: viewModel.connection?.peerAvatarUrl ?? "")) { image in
                        image.resizable().aspectRatio(contentMode: .fill)
                    } placeholder: {
                        Image(systemName: "person.circle.fill")
                            .resizable()
                            .foregroundColor(.secondary)
                    }
                    .frame(width: 100, height: 100)
                    .clipShape(Circle())

                    Text(viewModel.connection?.peerDisplayName ?? "")
                        .font(.title)
                        .fontWeight(.bold)

                    ConnectionStatusBadge(status: viewModel.connection?.status ?? .active)
                }

                // Profile info
                if let profile = viewModel.peerProfile {
                    ProfileInfoSection(profile: profile)
                }

                // Actions
                VStack(spacing: 12) {
                    NavigationLink(destination: ConversationView(connectionId: connectionId)) {
                        Label("Send Message", systemImage: "message.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    Button(role: .destructive) {
                        showRevokeConfirmation = true
                    } label: {
                        Label("Revoke Connection", systemImage: "xmark.circle")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)

                // Connection stats
                if let stats = viewModel.connectionStats {
                    ConnectionStatsSection(stats: stats)
                }
            }
            .padding()
        }
        .navigationTitle("Connection")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(
            "Revoke Connection",
            isPresented: $showRevokeConfirmation,
            titleVisibility: .visible
        ) {
            Button("Revoke", role: .destructive) {
                Task { await viewModel.revokeConnection() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will permanently end the connection. You won't be able to message each other.")
        }
        .task {
            await viewModel.loadConnection(connectionId)
        }
    }
}
```

### 7. Profile Views

Create profile screens:

```swift
// Views/Profile/ProfileView.swift

struct ProfileView: View {
    @StateObject private var viewModel = ProfileViewModel()
    @State private var showEditProfile = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Avatar
                    AsyncImage(url: URL(string: viewModel.profile?.avatarUrl ?? "")) { image in
                        image.resizable().aspectRatio(contentMode: .fill)
                    } placeholder: {
                        Image(systemName: "person.circle.fill")
                            .resizable()
                            .foregroundColor(.secondary)
                    }
                    .frame(width: 120, height: 120)
                    .clipShape(Circle())

                    // Display name
                    Text(viewModel.profile?.displayName ?? "")
                        .font(.title)
                        .fontWeight(.bold)

                    // Bio
                    if let bio = viewModel.profile?.bio, !bio.isEmpty {
                        Text(bio)
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }

                    // Location
                    if let location = viewModel.profile?.location, !location.isEmpty {
                        Label(location, systemImage: "location")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }

                    // Actions
                    VStack(spacing: 12) {
                        Button(action: { showEditProfile = true }) {
                            Label("Edit Profile", systemImage: "pencil")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)

                        Button(action: { Task { await viewModel.publishProfile() } }) {
                            Label("Publish to Connections", systemImage: "arrow.up.circle")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(viewModel.isPublishing)
                    }
                    .padding(.horizontal)
                }
                .padding()
            }
            .navigationTitle("Profile")
        }
        .sheet(isPresented: $showEditProfile) {
            EditProfileView(profile: viewModel.profile) { updatedProfile in
                Task { await viewModel.updateProfile(updatedProfile) }
            }
        }
        .task {
            await viewModel.loadProfile()
        }
    }
}

// Views/Profile/EditProfileView.swift

struct EditProfileView: View {
    let profile: Profile?
    let onSave: (Profile) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var displayName: String = ""
    @State private var bio: String = ""
    @State private var location: String = ""
    @State private var showImagePicker = false

    var body: some View {
        NavigationView {
            Form {
                Section {
                    // Avatar picker
                    HStack {
                        Spacer()
                        Button(action: { showImagePicker = true }) {
                            Image(systemName: "camera.circle.fill")
                                .resizable()
                                .frame(width: 100, height: 100)
                                .foregroundColor(.blue)
                        }
                        Spacer()
                    }
                }
                .listRowBackground(Color.clear)

                Section("Display Name") {
                    TextField("Display Name", text: $displayName)
                }

                Section("Bio") {
                    TextEditor(text: $bio)
                        .frame(minHeight: 100)
                }

                Section("Location") {
                    TextField("Location (optional)", text: $location)
                }
            }
            .navigationTitle("Edit Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        let updated = Profile(
                            guid: profile?.guid ?? "",
                            displayName: displayName,
                            avatarUrl: profile?.avatarUrl,
                            bio: bio.isEmpty ? nil : bio,
                            location: location.isEmpty ? nil : location,
                            lastUpdated: Date()
                        )
                        onSave(updated)
                        dismiss()
                    }
                    .disabled(displayName.isEmpty)
                }
            }
        }
        .onAppear {
            displayName = profile?.displayName ?? ""
            bio = profile?.bio ?? ""
            location = profile?.location ?? ""
        }
    }
}
```

### 8. Messaging Views

Create messaging screens:

```swift
// Views/Messaging/ConversationView.swift

struct ConversationView: View {
    let connectionId: String
    @StateObject private var viewModel = ConversationViewModel()
    @State private var messageText = ""
    @FocusState private var isInputFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            // Messages list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(viewModel.groupedMessages, id: \.date) { group in
                            DateDivider(date: group.date)

                            ForEach(group.messages) { message in
                                MessageBubble(
                                    message: message,
                                    isSent: message.senderId == viewModel.currentUserId
                                )
                                .id(message.id)
                            }
                        }
                    }
                    .padding()
                }
                .onAppear {
                    if let lastMessage = viewModel.messages.last {
                        proxy.scrollTo(lastMessage.id, anchor: .bottom)
                    }
                }
            }

            Divider()

            // Message input
            MessageInputView(
                text: $messageText,
                isFocused: $isInputFocused,
                onSend: {
                    Task {
                        await viewModel.sendMessage(messageText)
                        messageText = ""
                    }
                }
            )
        }
        .navigationTitle(viewModel.connectionName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                NavigationLink(destination: ConnectionDetailView(connectionId: connectionId)) {
                    Image(systemName: "info.circle")
                }
            }
        }
        .task {
            viewModel.connectionId = connectionId
            await viewModel.loadMessages()
        }
    }
}

// Views/Messaging/MessageBubble.swift

struct MessageBubble: View {
    let message: Message
    let isSent: Bool

    var body: some View {
        HStack {
            if isSent { Spacer(minLength: 60) }

            VStack(alignment: isSent ? .trailing : .leading, spacing: 4) {
                Text(message.content)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(isSent ? Color.blue : Color(.systemGray5))
                    .foregroundColor(isSent ? .white : .primary)
                    .cornerRadius(16)

                HStack(spacing: 4) {
                    Text(message.sentAt, style: .time)
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    if isSent {
                        MessageStatusIcon(status: message.status)
                    }
                }
            }

            if !isSent { Spacer(minLength: 60) }
        }
    }
}

// Views/Messaging/MessageInputView.swift

struct MessageInputView: View {
    @Binding var text: String
    var isFocused: FocusState<Bool>.Binding
    let onSend: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            TextField("Message", text: $text, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...5)
                .focused(isFocused)

            Button(action: onSend) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
            }
            .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding()
        .background(Color(.systemBackground))
    }
}
```

### 9. Connection ViewModels

Create ViewModels for connection flows:

```swift
// ViewModels/CreateInvitationViewModel.swift

@MainActor
class CreateInvitationViewModel: ObservableObject {
    @Published var state: CreateInvitationState = .idle
    @Published var expirationMinutes = 60

    private let apiClient: APIClient
    private let cryptoManager: ConnectionCryptoManager

    func createInvitation() async
    func shareInvitation()
    func copyLink()
    func reset()
}

// ViewModels/ScanInvitationViewModel.swift

@MainActor
class ScanInvitationViewModel: ObservableObject {
    @Published var state: ScanInvitationState = .scanning

    private let apiClient: APIClient
    private let cryptoManager: ConnectionCryptoManager

    func onQrCodeScanned(_ data: String)
    func onManualCodeEntered(_ code: String)
    func acceptInvitation() async
    func reset()
}

// ViewModels/ConnectionsViewModel.swift

@MainActor
class ConnectionsViewModel: ObservableObject {
    @Published var state: ConnectionsListState = .loading
    @Published var searchQuery = ""

    private let apiClient: APIClient
    private let messagingClient: MessagingAPIClient
    private var lastMessages: [String: Message] = [:]

    func loadConnections() async
    func refresh() async
    func lastMessage(for connectionId: String) -> Message?
}

// ViewModels/ConversationViewModel.swift

@MainActor
class ConversationViewModel: ObservableObject {
    @Published var messages: [Message] = []
    @Published var connectionName = ""
    @Published var isSending = false

    var connectionId: String = ""
    var currentUserId: String { credentialStore.currentUserId }

    var groupedMessages: [MessageGroup] { /* group by date */ }

    private let apiClient: APIClient
    private let cryptoManager: ConnectionCryptoManager
    private let messageSubscriber: MessageSubscriber

    func loadMessages() async
    func loadMoreMessages() async
    func sendMessage(_ content: String) async
    func markAsRead(_ messageId: String) async
}
```

### 10. QR Code Components

Create QR code scanner and generator:

```swift
// Views/Components/QRCodeGenerator.swift

struct QRCodeView: View {
    let data: String
    let size: CGFloat

    var body: some View {
        if let image = generateQRCode(from: data) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(width: size, height: size)
        }
    }

    private func generateQRCode(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)

        if let outputImage = filter.outputImage,
           let cgImage = context.createCGImage(outputImage, from: outputImage.extent) {
            return UIImage(cgImage: cgImage)
        }
        return nil
    }
}

// Views/Components/QRCodeScannerView.swift

struct QRCodeScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    class Coordinator: NSObject, ScannerDelegate {
        let onScan: (String) -> Void

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func didScanCode(_ code: String) {
            onScan(code)
        }
    }
}

// Uses AVFoundation for camera + code scanning
```

### 11. Real-time Updates

Integrate NATS for real-time messaging:

```swift
// Services/MessageSubscriber.swift

class MessageSubscriber {
    private let natsClient: NatsClient
    private let cryptoManager: ConnectionCryptoManager

    init(natsClient: NatsClient, cryptoManager: ConnectionCryptoManager) {
        self.natsClient = natsClient
        self.cryptoManager = cryptoManager
    }

    // Subscribe to incoming messages
    func subscribeToMessages(
        onMessage: @escaping (Message) -> Void
    ) -> AnyCancellable

    // Subscribe to connection events
    func subscribeToConnectionEvents(
        onEvent: @escaping (ConnectionEvent) -> Void
    ) -> AnyCancellable
}

enum ConnectionEvent {
    case invitationAccepted(Connection)
    case connectionRevoked(String)
    case profileUpdated(connectionId: String, profile: Profile)
}
```

### 12. Navigation Integration

Add connection routes to navigation:

```swift
// Update main app navigation

// Tab: Connections
// - ConnectionsListView
//   - CreateInvitationView (sheet)
//   - ScanInvitationView (sheet)
//   - ConnectionDetailView (push)
//     - ConversationView (push)

// Tab: Profile
// - ProfileView
//   - EditProfileView (sheet)
```

## Dependencies

Add to Package.swift or via SPM:
```swift
// QR Code generation uses CoreImage (built-in)
// QR Code scanning uses AVFoundation (built-in)

// For advanced crypto (if CryptoKit insufficient):
// .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1")
```

## Deliverables

- [ ] Connection data models (Connection, Invitation, Message, Profile)
- [ ] APIClient extensions for connections, profiles, messaging
- [ ] ConnectionCryptoManager (X25519, XChaCha20-Poly1305)
- [ ] CreateInvitationView with QR code display
- [ ] ScanInvitationView with AVFoundation scanner
- [ ] ConnectionsListView with search and unread badges
- [ ] ConnectionDetailView with revocation
- [ ] ProfileView and EditProfileView
- [ ] ConversationView with message bubbles
- [ ] MessageSubscriber for real-time updates
- [ ] Navigation integration
- [ ] Unit tests for ViewModels

## Acceptance Criteria

- [ ] Can create and display connection invitation QR code
- [ ] Can scan QR code and accept invitation
- [ ] X25519 key exchange establishes shared secret
- [ ] Per-connection encryption keys stored in Keychain
- [ ] Connection list shows all connections with unread counts
- [ ] Can view and edit own profile
- [ ] Messages encrypted with XChaCha20-Poly1305
- [ ] Real-time message delivery via NATS
- [ ] Proper error handling and loading states

## Notes

- Use CoreImage CIFilter.qrCodeGenerator() for QR generation
- Use AVFoundation for QR scanning
- Store connection keys in Keychain with kSecAttrAccessible
- Test encryption with known test vectors
- Handle offline scenarios (queue messages)
- Consider message pagination for long conversations
- Use async/await throughout for clean async code

## Status Update

```bash
cd /path/to/vettid-ios
git pull
# Implement connections & messaging UI
swift test  # Verify tests pass
git add .
git commit -m "Phase 7: Add connections and messaging UI"
git push

# Update status
# Edit cdk/coordination/status/ios.json (in vettid-dev repo)
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 7 connections & messaging complete"
git push
```
