# Phase 11: NATS Integration

## Overview
Integrate NATS messaging for real-time communication with the member's vault instance.

## Priority Task: NATS Connection & Messaging

### 1. Add NATS Dependency
Add the NATS.swift package via Swift Package Manager:
```swift
// Package.swift or Xcode Package Dependencies
// URL: https://github.com/nats-io/nats.swift
// Version: 0.2.0+
```

Or via Xcode:
1. File > Add Packages...
2. Enter: `https://github.com/nats-io/nats.swift`
3. Select version 0.2.0 or later

### 2. Create NATS Credential Models
```swift
// Models/NatsCredentials.swift
import Foundation

struct NatsCredentials: Codable {
    let jwt: String
    let seed: String
    let publicKey: String
    let natsCreds: String
    let expiresAt: String
    let natsUrl: String
    let ownerSpace: String
    let messageSpace: String

    enum CodingKeys: String, CodingKey {
        case jwt, seed
        case publicKey = "public_key"
        case natsCreds = "nats_creds"
        case expiresAt = "expires_at"
        case natsUrl = "nats_url"
        case ownerSpace = "owner_space"
        case messageSpace = "message_space"
    }
}

struct NatsAccountInfo: Codable {
    let accountPublicKey: String
    let ownerSpace: String
    let messageSpace: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case accountPublicKey = "account_public_key"
        case ownerSpace = "owner_space"
        case messageSpace = "message_space"
        case createdAt = "created_at"
    }
}
```

### 3. Create NATS API Service
```swift
// Services/NatsApiService.swift
import Foundation

class NatsApiService {
    private let apiClient: APIClient

    init(apiClient: APIClient) {
        self.apiClient = apiClient
    }

    func createAccount() async throws -> NatsAccountInfo {
        return try await apiClient.post("/nats/account")
    }

    func getCredentials() async throws -> NatsCredentials {
        return try await apiClient.post(
            "/nats/credentials",
            body: ["client_type": "app"]
        )
    }
}
```

### 4. Create NATS Connection Manager
```swift
// Services/NatsConnectionManager.swift
import Foundation
import NATS

actor NatsConnectionManager {
    private let natsApi: NatsApiService
    private var client: NatsClient?
    private var credentials: NatsCredentials?
    private var subscription: Subscription?

    init(natsApi: NatsApiService) {
        self.natsApi = natsApi
    }

    func ensureConnected() async throws -> NatsClient {
        // Check if we have valid credentials
        if let creds = credentials, !isExpiringSoon(creds) {
            if let client = client, client.isConnected {
                return client
            }
        }

        // Refresh credentials
        credentials = try await natsApi.getCredentials()
        return try await connect(credentials!)
    }

    private func connect(_ creds: NatsCredentials) async throws -> NatsClient {
        let options = NatsClientOptions(
            url: creds.natsUrl,
            jwt: creds.jwt,
            nkeySeed: creds.seed,
            reconnectWait: .seconds(2),
            maxReconnects: -1
        )

        client = NatsClient(options: options)
        try await client?.connect()
        return client!
    }

    private func isExpiringSoon(_ creds: NatsCredentials) -> Bool {
        guard let expiresAt = ISO8601DateFormatter().date(from: creds.expiresAt) else {
            return true
        }
        let fiveMinutesFromNow = Date().addingTimeInterval(300)
        return expiresAt < fiveMinutesFromNow
    }

    func getCredentials() -> NatsCredentials? {
        return credentials
    }

    func disconnect() async {
        await subscription?.unsubscribe()
        await client?.close()
        client = nil
        credentials = nil
    }
}
```

### 5. Create Vault Event Repository
```swift
// Repositories/VaultEventRepository.swift
import Foundation
import Combine
import NATS

class VaultEventRepository: ObservableObject {
    @Published var responses: [VaultResponse] = []

    private let natsManager: NatsConnectionManager
    private var subscription: Subscription?

    init(natsManager: NatsConnectionManager) {
        self.natsManager = natsManager
    }

    func subscribeToResponses() async throws {
        let client = try await natsManager.ensureConnected()
        guard let creds = await natsManager.getCredentials() else {
            throw NatsError.noCredentials
        }

        let subject = "\(creds.ownerSpace).forApp.>"
        subscription = try await client.subscribe(to: subject)

        Task {
            if let sub = subscription {
                for try await message in sub {
                    if let response = try? JSONDecoder().decode(
                        VaultResponse.self,
                        from: message.payload
                    ) {
                        await MainActor.run {
                            self.responses.append(response)
                        }
                    }
                }
            }
        }
    }

    func sendEvent(type: String, payload: Data) async throws {
        let client = try await natsManager.ensureConnected()
        guard let creds = await natsManager.getCredentials() else {
            throw NatsError.noCredentials
        }

        let event = VaultEvent(
            eventId: UUID().uuidString,
            type: type,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            payload: payload.base64EncodedString()
        )

        let eventData = try JSONEncoder().encode(event)
        let subject = "\(creds.ownerSpace).forVault.\(type)"

        try await client.publish(to: subject, payload: eventData)
    }
}

// Models/VaultEvent.swift
struct VaultEvent: Codable {
    let eventId: String
    let type: String
    let timestamp: String
    let payload: String

    enum CodingKeys: String, CodingKey {
        case eventId = "event_id"
        case type, timestamp, payload
    }
}

struct VaultResponse: Codable, Identifiable {
    let responseId: String
    let eventId: String
    let timestamp: String
    let status: String
    let payload: String?
    let error: String?

    var id: String { responseId }

    enum CodingKeys: String, CodingKey {
        case responseId = "response_id"
        case eventId = "event_id"
        case timestamp, status, payload, error
    }
}

enum NatsError: Error {
    case noCredentials
    case connectionFailed
    case publishFailed
}
```

### 6. Create Account Setup Flow
After enrollment completes, call the account setup:
```swift
// ViewModels/EnrollmentViewModel.swift
extension EnrollmentViewModel {
    func setupNatsAccount() async throws {
        do {
            let accountInfo = try await natsApi.createAccount()
            // Store account info locally
            UserDefaults.standard.set(accountInfo.ownerSpace, forKey: "ownerSpace")
            UserDefaults.standard.set(accountInfo.messageSpace, forKey: "messageSpace")
        } catch {
            print("Failed to create NATS account: \(error)")
            throw error
        }
    }
}
```

### 7. Usage in SwiftUI View
```swift
// Views/VaultConnectionView.swift
import SwiftUI

struct VaultConnectionView: View {
    @StateObject private var vaultRepo: VaultEventRepository

    init(natsManager: NatsConnectionManager) {
        _vaultRepo = StateObject(wrappedValue: VaultEventRepository(natsManager: natsManager))
    }

    var body: some View {
        VStack {
            Text("Vault Connection")
                .font(.title)

            List(vaultRepo.responses) { response in
                VStack(alignment: .leading) {
                    Text("Event: \(response.eventId)")
                        .font(.caption)
                    Text("Status: \(response.status)")
                        .foregroundColor(response.status == "success" ? .green : .red)
                    if let error = response.error {
                        Text("Error: \(error)")
                            .foregroundColor(.red)
                    }
                }
            }

            Button("Send Test Event") {
                Task {
                    try? await vaultRepo.sendEvent(
                        type: "test.ping",
                        payload: "{}".data(using: .utf8)!
                    )
                }
            }
        }
        .task {
            try? await vaultRepo.subscribeToResponses()
        }
    }
}
```

### 8. ViewModel Pattern (Alternative)
```swift
// ViewModels/VaultViewModel.swift
import Foundation
import Combine

@MainActor
class VaultViewModel: ObservableObject {
    @Published var responses: [VaultResponse] = []
    @Published var isConnected = false
    @Published var error: String?

    private let vaultRepo: VaultEventRepository
    private var cancellables = Set<AnyCancellable>()

    init(vaultRepo: VaultEventRepository) {
        self.vaultRepo = vaultRepo

        vaultRepo.$responses
            .receive(on: DispatchQueue.main)
            .sink { [weak self] responses in
                self?.responses = responses
            }
            .store(in: &cancellables)
    }

    func connect() {
        Task {
            do {
                try await vaultRepo.subscribeToResponses()
                isConnected = true
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    func sendTestEvent() {
        Task {
            do {
                try await vaultRepo.sendEvent(
                    type: "test.ping",
                    payload: "{}".data(using: .utf8)!
                )
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
```

## API Reference

See `coordination/specs/nats-api.md` for the complete API specification including:
- Account creation endpoint
- Credential generation endpoint
- NATS topic permissions
- Code examples

## NATS Topic Reference

See `coordination/specs/nats-topics.md` for:
- Complete topic structure
- Message formats
- Security considerations

## Testing

### Unit Tests
```swift
// Tests/NatsConnectionManagerTests.swift
import XCTest
@testable import VettID

final class NatsConnectionManagerTests: XCTestCase {
    func testCredentialExpiration() async {
        let mockApi = MockNatsApiService()
        let manager = NatsConnectionManager(natsApi: mockApi)

        // Test that expired credentials trigger refresh
        // ...
    }

    func testEventSerialization() {
        let event = VaultEvent(
            eventId: "test-id",
            type: "test.ping",
            timestamp: "2024-01-15T10:00:00Z",
            payload: "e30="
        )

        let encoded = try! JSONEncoder().encode(event)
        let decoded = try! JSONDecoder().decode(VaultEvent.self, from: encoded)

        XCTAssertEqual(event.eventId, decoded.eventId)
    }
}
```

### Integration Tests
- Test actual NATS connection (requires deployed infrastructure)
- Test publish/subscribe flow
- Test reconnection behavior

## Deliverables
- [ ] NATS.swift package integrated
- [ ] Credential models created
- [ ] NatsConnectionManager implemented
- [ ] VaultEventRepository implemented
- [ ] Account setup flow integrated with enrollment
- [ ] Basic vault communication working
- [ ] Unit tests for NATS logic

## Notes
- NATS credentials expire after 24 hours - implement automatic refresh
- Always check connection status before publishing
- Handle authorization errors by refreshing credentials
- TLS is required for all NATS connections
- Use `actor` isolation for thread-safe NATS connection management
- Consider using Combine for reactive event streaming
