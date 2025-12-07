# Task: Phase 4 - NATS Client Integration

## Phase
Phase 4: NATS Infrastructure

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 3 complete. Ready for Phase 4 NATS client integration.

## Overview

Implement NATS client integration for the iOS app. The backend now provides:
- NATS account creation (namespace allocation)
- JWT token generation for NATS authentication
- Token revocation

The mobile app needs to:
1. Create a NATS account via API
2. Request tokens for NATS connection
3. Connect to NATS cluster using tokens
4. Implement pub/sub for vault communication

## API Endpoints

### Create NATS Account
```
POST /vault/nats/account
Authorization: Bearer <member_jwt>

Response 200:
{
  "owner_space_id": "OwnerSpace.{user_guid}",
  "message_space_id": "MessageSpace.{user_guid}",
  "nats_endpoint": "nats://nats.vettid.dev:4222",
  "status": "active"
}
```

### Generate NATS Token
```
POST /vault/nats/token
Authorization: Bearer <member_jwt>
Content-Type: application/json

{
  "client_type": "app",
  "device_id": "optional-device-identifier"
}

Response 200:
{
  "token_id": "nats_uuid",
  "nats_jwt": "base64url.payload.signature",
  "nats_seed": "SUAM...",
  "nats_endpoint": "nats://nats.vettid.dev:4222",
  "expires_at": "2025-12-08T...",
  "permissions": {
    "publish": ["OwnerSpace.guid.forVault.>"],
    "subscribe": ["OwnerSpace.guid.forApp.>", "OwnerSpace.guid.eventTypes"]
  }
}
```

### Get NATS Status
```
GET /vault/nats/status
Authorization: Bearer <member_jwt>

Response 200:
{
  "has_account": true,
  "account": {
    "owner_space_id": "OwnerSpace.{user_guid}",
    "message_space_id": "MessageSpace.{user_guid}",
    "status": "active",
    "created_at": "2025-12-07T..."
  },
  "active_tokens": [...],
  "nats_endpoint": "nats://nats.vettid.dev:4222"
}
```

## Phase 4 iOS Tasks

### 1. Add NATS Client Dependency

Add Swift NATS client via SPM:

```swift
// Package.swift or Xcode SPM
dependencies: [
    .package(url: "https://github.com/nats-io/nats.swift.git", from: "0.1.0")
]
```

Note: Swift NATS client is relatively new. Alternative: Use a bridged Objective-C/C client or implement minimal client.

### 2. NATS Client Module

Create NATS client components:

```
VettID/Sources/NATS/
├── NatsClient.swift             # Main client wrapper
├── NatsCredentials.swift        # Token/credential management
├── NatsConnectionManager.swift  # Connection lifecycle
├── OwnerSpaceClient.swift       # OwnerSpace operations
└── MessageSpaceClient.swift     # MessageSpace operations
```

#### NatsCredentials.swift
```swift
struct NatsCredentials: Codable {
    let tokenId: String
    let jwt: String
    let seed: String
    let endpoint: String
    let expiresAt: Date
    let permissions: NatsPermissions

    var isExpired: Bool {
        Date() >= expiresAt
    }

    var shouldRefresh: Bool {
        // Refresh if less than 1 hour remaining
        Date().addingTimeInterval(3600) >= expiresAt
    }
}

struct NatsPermissions: Codable {
    let publish: [String]
    let subscribe: [String]
}
```

#### NatsConnectionManager.swift
```swift
@MainActor
class NatsConnectionManager: ObservableObject {
    @Published var connectionState: NatsConnectionState = .disconnected

    private let apiClient: VettIdApiClient
    private let credentialStore: NatsCredentialStore
    private var connection: NatsConnection?

    init(apiClient: VettIdApiClient, credentialStore: NatsCredentialStore) {
        self.apiClient = apiClient
        self.credentialStore = credentialStore
    }

    func connect() async throws {
        connectionState = .connecting

        // Get or refresh credentials
        var credentials = try await credentialStore.getCredentials()
        if credentials?.shouldRefresh ?? true {
            credentials = try await refreshCredentials()
        }

        guard let creds = credentials else {
            throw NatsError.noCredentials
        }

        // Connect using credentials
        connection = try await NatsConnection.connect(
            endpoint: creds.endpoint,
            jwt: creds.jwt,
            seed: creds.seed
        )

        connectionState = .connected
    }

    func disconnect() async {
        await connection?.close()
        connection = nil
        connectionState = .disconnected
    }

    private func refreshCredentials() async throws -> NatsCredentials {
        let response = try await apiClient.generateNatsToken(clientType: .app)
        let credentials = NatsCredentials(
            tokenId: response.token_id,
            jwt: response.nats_jwt,
            seed: response.nats_seed,
            endpoint: response.nats_endpoint,
            expiresAt: ISO8601DateFormatter().date(from: response.expires_at) ?? Date(),
            permissions: NatsPermissions(
                publish: response.permissions.publish,
                subscribe: response.permissions.subscribe
            )
        )
        try await credentialStore.saveCredentials(credentials)
        return credentials
    }
}

enum NatsConnectionState {
    case disconnected
    case connecting
    case connected
    case error(Error)
}
```

### 3. NATS Account Setup Flow

Implement account setup after vault enrollment:

```swift
@MainActor
class NatsSetupViewModel: ObservableObject {
    @Published var setupState: SetupState = .initial

    enum SetupState {
        case initial
        case creatingAccount
        case generatingToken
        case connecting
        case connected(NatsAccountStatus)
        case error(String)
    }

    private let apiClient: VettIdApiClient
    private let connectionManager: NatsConnectionManager

    init(apiClient: VettIdApiClient, connectionManager: NatsConnectionManager) {
        self.apiClient = apiClient
        self.connectionManager = connectionManager
    }

    func setupNats() async {
        do {
            // 1. Create NATS account
            setupState = .creatingAccount
            let account = try await apiClient.createNatsAccount()

            // 2. Generate app token
            setupState = .generatingToken
            let token = try await apiClient.generateNatsToken(clientType: .app)

            // 3. Connect to NATS
            setupState = .connecting
            try await connectionManager.connect()

            // 4. Report success
            setupState = .connected(NatsAccountStatus(
                ownerSpaceId: account.owner_space_id,
                messageSpaceId: account.message_space_id
            ))
        } catch {
            setupState = .error(error.localizedDescription)
        }
    }
}
```

### 4. OwnerSpace Client

Implement OwnerSpace communication:

```swift
class OwnerSpaceClient {
    private let connectionManager: NatsConnectionManager
    private let ownerSpaceId: String

    init(connectionManager: NatsConnectionManager, ownerSpaceId: String) {
        self.connectionManager = connectionManager
        self.ownerSpaceId = ownerSpaceId
    }

    // Topics
    // Publish: OwnerSpace.{guid}.forVault.>
    // Subscribe: OwnerSpace.{guid}.forApp.>

    func sendToVault<T: Encodable>(_ message: T, topic: String) async throws {
        let fullTopic = "\(ownerSpaceId).forVault.\(topic)"
        let data = try JSONEncoder().encode(message)
        try await connectionManager.publish(data, to: fullTopic)
    }

    func subscribeToVaultResponses<T: Decodable>(
        topic: String,
        type: T.Type
    ) -> AsyncStream<T> {
        let fullTopic = "\(ownerSpaceId).forApp.\(topic)"
        return connectionManager.subscribe(to: fullTopic, type: type)
    }

    func getEventTypes() async throws -> [EventType] {
        let topic = "\(ownerSpaceId).eventTypes"
        // Request/reply pattern or fetch from stream
        return []
    }
}
```

### 5. Message Types

Define message structures:

```swift
// Messages TO vault
enum VaultMessage: Encodable {
    case executeHandler(ExecuteHandlerMessage)
    case statusRequest(StatusRequestMessage)
}

struct ExecuteHandlerMessage: Encodable {
    let handlerId: String
    let payload: [String: AnyCodable]
}

struct StatusRequestMessage: Encodable {
    let requestId: String
}

// Messages FROM vault
enum VaultResponse: Decodable {
    case handlerResult(HandlerResultMessage)
    case statusResponse(StatusResponseMessage)
}

struct HandlerResultMessage: Decodable {
    let requestId: String
    let success: Bool
    let result: [String: AnyCodable]?
}

struct StatusResponseMessage: Decodable {
    let requestId: String
    let vaultStatus: VaultStatus
}
```

### 6. Connection UI

Create connection status UI:

```swift
struct NatsConnectionStatusView: View {
    @ObservedObject var viewModel: NatsSetupViewModel

    var body: some View {
        switch viewModel.setupState {
        case .connected:
            HStack {
                Circle()
                    .fill(.green)
                    .frame(width: 8, height: 8)
                Text("Connected")
                    .font(.caption)
            }
        case .connecting, .creatingAccount, .generatingToken:
            HStack {
                ProgressView()
                    .scaleEffect(0.7)
                Text("Connecting...")
                    .font(.caption)
            }
        case .error(let message):
            HStack {
                Circle()
                    .fill(.red)
                    .frame(width: 8, height: 8)
                Text(message)
                    .font(.caption)
                    .lineLimit(1)
            }
        case .initial:
            EmptyView()
        }
    }
}
```

### 7. Token Refresh

Implement automatic token refresh:

```swift
import BackgroundTasks

class NatsTokenRefreshTask {
    static let identifier = "dev.vettid.natsrefresh"

    static func register() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: identifier,
            using: nil
        ) { task in
            handleRefresh(task: task as! BGAppRefreshTask)
        }
    }

    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 3600) // 6 hours

        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Failed to schedule NATS token refresh: \(error)")
        }
    }

    private static func handleRefresh(task: BGAppRefreshTask) {
        schedule() // Schedule next refresh

        let refreshTask = Task {
            do {
                let credentialStore = NatsCredentialStore()
                guard let credentials = try await credentialStore.getCredentials(),
                      credentials.shouldRefresh else {
                    task.setTaskCompleted(success: true)
                    return
                }

                let apiClient = VettIdApiClient()
                let response = try await apiClient.generateNatsToken(clientType: .app)

                // Save new credentials
                let newCredentials = NatsCredentials(
                    tokenId: response.token_id,
                    jwt: response.nats_jwt,
                    seed: response.nats_seed,
                    endpoint: response.nats_endpoint,
                    expiresAt: ISO8601DateFormatter().date(from: response.expires_at) ?? Date(),
                    permissions: NatsPermissions(
                        publish: response.permissions.publish,
                        subscribe: response.permissions.subscribe
                    )
                )
                try await credentialStore.saveCredentials(newCredentials)

                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }
        }

        task.expirationHandler = {
            refreshTask.cancel()
        }
    }
}
```

## Testing Requirements

### Unit Tests
```swift
class NatsCredentialsTests: XCTestCase {
    func testIsExpired_returnsTrueForPastDate() { }
    func testShouldRefresh_returnsTrueWhenLessThanOneHour() { }
}

class OwnerSpaceClientTests: XCTestCase {
    func testSendToVault_formatsTopicCorrectly() async { }
    func testSubscribeToVaultResponses_createsCorrectSubscription() { }
}
```

### Integration Tests
```swift
class NatsIntegrationTests: XCTestCase {
    func testCreateAccountAndConnect() async { }
    func testSendMessageToVaultTopic() async { }
    func testReceiveMessageFromAppTopic() async { }
}
```

## Deliverables

- [ ] NatsClient wrapper class
- [ ] NatsCredentials model with Keychain storage
- [ ] NatsConnectionManager with lifecycle management
- [ ] OwnerSpaceClient for vault communication
- [ ] NatsSetupViewModel and UI
- [ ] Token refresh background task
- [ ] Unit tests for NATS components
- [ ] Integration tests for NATS connection

## Acceptance Criteria

- [ ] App can create NATS account via API
- [ ] App can generate and store NATS tokens in Keychain
- [ ] App connects to NATS using TLS (port 4222)
- [ ] App can publish to OwnerSpace.forVault
- [ ] App can subscribe to OwnerSpace.forApp
- [ ] Token refresh works before expiration
- [ ] Connection errors are handled gracefully
- [ ] All unit tests pass

## Status Update

```bash
cd /path/to/vettid-ios
git pull  # Get latest from backend if needed
# Edit VettID/Sources/... (create NATS components)
git add .
git commit -m "Phase 4: Add NATS client integration"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 4 NATS client complete"
git push
```
