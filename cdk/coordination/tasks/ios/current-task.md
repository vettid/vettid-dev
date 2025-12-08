# Task: Phase 5 - Vault Communication

## Phase
Phase 5: Vault Instance (EC2)

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 4 complete. Ready for Phase 5 vault communication.

## Overview

Phase 5 connects the mobile app to the user's vault instance. With NATS infrastructure in place from Phase 4, you now need to:
1. Implement event submission to the vault
2. Handle responses from the vault
3. Display vault health status
4. Handle vault lifecycle events (provisioning, stop, terminate)

## New Backend Endpoints

### Vault Lifecycle
```
POST /vault/provision    # Start provisioning vault EC2 instance
POST /vault/initialize   # Initialize vault after EC2 is running
POST /vault/stop         # Stop vault (preserve state)
POST /vault/terminate    # Terminate vault (cleanup)
GET  /vault/health       # Get vault health status
```

## Phase 5 iOS Tasks

### 1. Vault Lifecycle API

Add vault lifecycle endpoints to APIClient:

```swift
// Services/APIClient.swift

extension APIClient {
    func provisionVault() async throws -> ProvisionResponse
    func initializeVault() async throws -> InitializeResponse
    func stopVault() async throws -> StopResponse
    func terminateVault() async throws -> TerminateResponse
    func getVaultHealth() async throws -> VaultHealthResponse
}

struct ProvisionResponse: Codable {
    let instance_id: String
    let status: String  // "provisioning", "running", "failed"
    let region: String
    let availability_zone: String
    let private_ip: String?
    let estimated_ready_at: String
}

struct InitializeResponse: Codable {
    let status: String  // "initialized", "failed"
    let local_nats_status: String
    let central_nats_status: String
    let owner_space_id: String
    let message_space_id: String
}

struct VaultHealthResponse: Codable {
    let status: String  // "healthy", "unhealthy", "degraded"
    let uptime_seconds: Int
    let local_nats: NatsHealth
    let central_nats: CentralNatsHealth
    let vault_manager: VaultManagerHealth
    let last_event_at: String?
}

struct NatsHealth: Codable {
    let status: String
    let connections: Int
}

struct CentralNatsHealth: Codable {
    let status: String
    let latency_ms: Int
}

struct VaultManagerHealth: Codable {
    let status: String
    let memory_mb: Int
    let cpu_percent: Float
    let handlers_loaded: Int
}
```

### 2. Event Submission via NATS

Implement event submission through OwnerSpaceClient:

```swift
// NATS/VaultEventClient.swift

class VaultEventClient {
    private let ownerSpaceClient: OwnerSpaceClient

    init(ownerSpaceClient: OwnerSpaceClient) {
        self.ownerSpaceClient = ownerSpaceClient
    }

    /// Submit an event to the vault for processing
    func submitEvent(_ event: VaultEvent) async throws -> String {
        let requestId = UUID().uuidString
        let message = VaultEventMessage(
            request_id: requestId,
            event_type: event.type,
            payload: event.payload,
            timestamp: ISO8601DateFormatter().string(from: Date())
        )

        try await ownerSpaceClient.sendToVault(
            message: message,
            topic: "events.\(event.type)"
        )

        return requestId
    }

    /// Subscribe to event responses from vault
    func subscribeToResponses() -> AsyncStream<VaultEventResponse> {
        ownerSpaceClient.subscribeToVaultResponses(
            topic: "responses.>",
            type: VaultEventResponse.self
        )
    }
}

struct VaultEventMessage: Encodable {
    let request_id: String
    let event_type: String
    let payload: [String: AnyCodable]
    let timestamp: String
}

struct VaultEventResponse: Decodable {
    let request_id: String
    let status: String  // "success", "error"
    let result: [String: AnyCodable]?
    let error: String?
    let processed_at: String
}

enum VaultEvent {
    case sendMessage(recipient: String, content: String)
    case updateProfile(updates: [String: Any])
    case createConnection(inviteCode: String)

    var type: String {
        switch self {
        case .sendMessage: return "messaging.send"
        case .updateProfile: return "profile.update"
        case .createConnection: return "connection.create"
        }
    }

    var payload: [String: AnyCodable] {
        switch self {
        case .sendMessage(let recipient, let content):
            return ["recipient": AnyCodable(recipient), "content": AnyCodable(content)]
        case .updateProfile(let updates):
            return updates.mapValues { AnyCodable($0) }
        case .createConnection(let inviteCode):
            return ["invite_code": AnyCodable(inviteCode)]
        }
    }
}
```

### 3. Vault Health ViewModel

Create ViewModel for vault health monitoring:

```swift
// Vault/VaultHealthViewModel.swift

@MainActor
class VaultHealthViewModel: ObservableObject {
    @Published var healthState: VaultHealthState = .loading

    private let apiClient: APIClient
    private let natsConnectionManager: NatsConnectionManager
    private var healthCheckTask: Task<Void, Never>?

    init(apiClient: APIClient, natsConnectionManager: NatsConnectionManager) {
        self.apiClient = apiClient
        self.natsConnectionManager = natsConnectionManager
    }

    func startHealthMonitoring() {
        healthCheckTask?.cancel()
        healthCheckTask = Task {
            while !Task.isCancelled {
                await checkHealth()
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30 seconds
            }
        }
    }

    func stopHealthMonitoring() {
        healthCheckTask?.cancel()
        healthCheckTask = nil
    }

    private func checkHealth() async {
        do {
            let health = try await apiClient.getVaultHealth()
            healthState = .loaded(VaultHealthInfo(
                status: HealthStatus(rawValue: health.status) ?? .unhealthy,
                uptime: TimeInterval(health.uptime_seconds),
                localNats: health.local_nats.status == "running",
                centralNats: health.central_nats.status == "connected",
                centralLatency: health.central_nats.latency_ms,
                vaultManager: health.vault_manager.status == "running",
                handlersLoaded: health.vault_manager.handlers_loaded,
                lastEventAt: health.last_event_at.flatMap { ISO8601DateFormatter().date(from: $0) }
            ))
        } catch {
            healthState = .error(error.localizedDescription)
        }
    }

    func provisionVault() async {
        healthState = .provisioning

        do {
            let provision = try await apiClient.provisionVault()
            // Poll for completion
            await pollForProvisioning(instanceId: provision.instance_id)
        } catch {
            healthState = .error(error.localizedDescription)
        }
    }

    private func pollForProvisioning(instanceId: String) async {
        for _ in 0..<60 { // Max 2 minutes
            try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            do {
                let health = try await apiClient.getVaultHealth()
                if health.status == "healthy" {
                    await checkHealth()
                    return
                }
            } catch {
                // Still provisioning
            }
        }
        healthState = .error("Provisioning timeout")
    }

    deinit {
        healthCheckTask?.cancel()
    }
}

enum VaultHealthState {
    case loading
    case provisioning
    case notProvisioned
    case loaded(VaultHealthInfo)
    case error(String)
}

struct VaultHealthInfo {
    let status: HealthStatus
    let uptime: TimeInterval
    let localNats: Bool
    let centralNats: Bool
    let centralLatency: Int
    let vaultManager: Bool
    let handlersLoaded: Int
    let lastEventAt: Date?
}

enum HealthStatus: String {
    case healthy
    case degraded
    case unhealthy
}
```

### 4. Vault Health View

Create health display components:

```swift
// Vault/VaultHealthView.swift

struct VaultHealthView: View {
    @StateObject var viewModel: VaultHealthViewModel

    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                switch viewModel.healthState {
                case .loading:
                    ProgressView()
                case .provisioning:
                    ProvisioningView()
                case .notProvisioned:
                    NotProvisionedView(onProvision: {
                        Task { await viewModel.provisionVault() }
                    })
                case .loaded(let info):
                    VaultHealthDetailsView(info: info)
                case .error(let message):
                    ErrorView(message: message, onRetry: {
                        viewModel.startHealthMonitoring()
                    })
                }
            }
            .padding()
            .navigationTitle("Vault Health")
        }
        .onAppear {
            viewModel.startHealthMonitoring()
        }
        .onDisappear {
            viewModel.stopHealthMonitoring()
        }
    }
}

struct VaultHealthDetailsView: View {
    let info: VaultHealthInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Status header
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 16, height: 16)
                Text(info.status.rawValue.capitalized)
                    .font(.title2)
                    .fontWeight(.semibold)
            }

            Divider()

            // Component status
            ComponentStatusRow(
                title: "Local NATS",
                isActive: info.localNats
            )
            ComponentStatusRow(
                title: "Central NATS",
                isActive: info.centralNats,
                detail: "\(info.centralLatency)ms"
            )
            ComponentStatusRow(
                title: "Vault Manager",
                isActive: info.vaultManager
            )

            Divider()

            // Stats
            VStack(alignment: .leading, spacing: 8) {
                Text("Handlers Loaded: \(info.handlersLoaded)")
                Text("Uptime: \(formatUptime(info.uptime))")
                if let lastEvent = info.lastEventAt {
                    Text("Last Event: \(lastEvent, style: .relative)")
                }
            }
            .font(.subheadline)
            .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }

    private var statusColor: Color {
        switch info.status {
        case .healthy: return .green
        case .degraded: return .yellow
        case .unhealthy: return .red
        }
    }

    private func formatUptime(_ interval: TimeInterval) -> String {
        let hours = Int(interval) / 3600
        let minutes = (Int(interval) % 3600) / 60
        return "\(hours)h \(minutes)m"
    }
}

struct ComponentStatusRow: View {
    let title: String
    let isActive: Bool
    var detail: String? = nil

    var body: some View {
        HStack {
            Image(systemName: isActive ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(isActive ? .green : .red)
            Text(title)
            Spacer()
            if let detail = detail {
                Text(detail)
                    .foregroundColor(.secondary)
            }
        }
    }
}
```

### 5. Event Response Handler

Handle responses from vault events:

```swift
// NATS/VaultResponseHandler.swift

actor VaultResponseHandler {
    private let vaultEventClient: VaultEventClient
    private var pendingRequests: [String: CheckedContinuation<VaultEventResponse, Error>] = [:]
    private var responseTask: Task<Void, Never>?

    init(vaultEventClient: VaultEventClient) {
        self.vaultEventClient = vaultEventClient
        startListening()
    }

    private func startListening() {
        responseTask = Task {
            for await response in vaultEventClient.subscribeToResponses() {
                if let continuation = pendingRequests.removeValue(forKey: response.request_id) {
                    continuation.resume(returning: response)
                }
            }
        }
    }

    func submitAndAwait(
        _ event: VaultEvent,
        timeout: TimeInterval = 30
    ) async throws -> VaultEventResponse {
        let requestId = try await vaultEventClient.submitEvent(event)

        return try await withCheckedThrowingContinuation { continuation in
            Task {
                await self.registerPending(requestId: requestId, continuation: continuation)

                // Set up timeout
                Task {
                    try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    await self.handleTimeout(requestId: requestId)
                }
            }
        }
    }

    private func registerPending(
        requestId: String,
        continuation: CheckedContinuation<VaultEventResponse, Error>
    ) {
        pendingRequests[requestId] = continuation
    }

    private func handleTimeout(requestId: String) {
        if let continuation = pendingRequests.removeValue(forKey: requestId) {
            continuation.resume(throwing: VaultError.responseTimeout)
        }
    }

    deinit {
        responseTask?.cancel()
    }
}

enum VaultError: Error {
    case responseTimeout
    case eventSubmissionFailed
}
```

### 6. Unit Tests

```swift
// VettIDTests/VaultEventClientTests.swift

class VaultEventClientTests: XCTestCase {
    func testSubmitEvent_sendsToCorrectTopic() async { }
    func testSubscribeToResponses_receivesVaultMessages() { }
}

// VettIDTests/VaultHealthViewModelTests.swift

class VaultHealthViewModelTests: XCTestCase {
    func testCheckHealth_updatesStateCorrectly() async { }
    func testProvisionVault_pollsUntilReady() async { }
    func testTimeout_duringProvisioning_showsError() async { }
}

// VettIDTests/VaultResponseHandlerTests.swift

class VaultResponseHandlerTests: XCTestCase {
    func testSubmitAndAwait_matchesRequestToResponse() async { }
    func testSubmitAndAwait_timesOutAfterDuration() async { }
}
```

## Deliverables

- [ ] APIClient with vault lifecycle endpoints
- [ ] VaultEventClient for NATS event submission
- [ ] VaultHealthViewModel for health monitoring
- [ ] VaultHealthView with SwiftUI status UI
- [ ] VaultResponseHandler for request/response correlation
- [ ] Unit tests for new components

## Acceptance Criteria

- [ ] App can provision vault via API
- [ ] App polls for provisioning completion
- [ ] App displays vault health status
- [ ] App submits events via NATS to vault
- [ ] App receives and correlates responses
- [ ] Health monitoring updates every 30 seconds
- [ ] Error states displayed with retry option

## Notes

- iOS notes: nats.swift SPM integration still pending - may need to use mock for now
- Vault provisioning may take 1-2 minutes - show appropriate progress UI
- Consider battery impact of 30-second health polling - adjust interval as needed
- Use async/await and actors for thread-safe response handling

## Status Update

```bash
cd /path/to/vettid-ios
git pull
# Create vault communication components
git add .
git commit -m "Phase 5: Add vault communication"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 5 vault communication complete"
git push
```
