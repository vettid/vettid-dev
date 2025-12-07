# Task: Phase 3 - Vault Lifecycle Management

## Phase
Phase 3: Vault Services Enrollment

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 2 complete. Ready for Phase 3 vault lifecycle management.

## New Backend Endpoints

Three new endpoints have been added:

1. `GET /vault/status` - Get vault status (not_enrolled, pending, enrolled, active)
2. `POST /vault/sync` - Sync vault and replenish transaction keys
3. `POST /member/vault/deploy` - Web portal endpoint (not used by mobile)

## Phase 3 iOS Tasks

### 1. Add Vault Status API

Update VaultService:

```swift
// VaultService.swift

extension VaultService {
    func getVaultStatus() async throws -> VaultStatusResponse
    func syncVault() async throws -> SyncResponse
}

struct VaultStatusResponse: Codable {
    let status: String                    // "not_enrolled", "pending", "enrolled", "active", "error"
    let user_guid: String?
    let enrolled_at: String?
    let last_auth_at: String?
    let last_sync_at: String?
    let device_type: String?              // "android" or "ios"
    let security_level: String?           // "hardware"
    let transaction_keys_remaining: Int?
    let credential_version: Int?
    let error_message: String?
}

struct SyncResponse: Codable {
    let status: String                    // "synced" or "keys_replenished"
    let last_sync_at: String
    let transaction_keys_remaining: Int
    let new_transaction_keys: [TransactionKey]?
    let credential_version: Int
}
```

### 2. Create VaultStatusViewModel

```swift
// VettID/Sources/Vault/VaultStatusViewModel.swift

@MainActor
class VaultStatusViewModel: ObservableObject {
    @Published var state: VaultState = .loading

    private let vaultService: VaultService
    private let credentialStore: CredentialStore

    init(vaultService: VaultService, credentialStore: CredentialStore) {
        self.vaultService = vaultService
        self.credentialStore = credentialStore
    }

    func loadVaultStatus() async {
        state = .loading
        do {
            let response = try await vaultService.getVaultStatus()
            state = mapResponseToState(response)
        } catch {
            state = .error(message: error.localizedDescription)
        }
    }

    func syncVault() async {
        do {
            let response = try await vaultService.syncVault()

            // Store any new transaction keys
            if let newKeys = response.new_transaction_keys {
                try await credentialStore.addTransactionKeys(newKeys)
            }

            // Refresh status
            await loadVaultStatus()
        } catch {
            // Handle sync error
        }
    }

    private func mapResponseToState(_ response: VaultStatusResponse) -> VaultState {
        switch response.status {
        case "not_enrolled":
            return .notEnrolled
        case "pending":
            return .pending
        case "enrolled":
            return .enrolled(
                userGuid: response.user_guid ?? "",
                enrolledAt: response.enrolled_at,
                keysRemaining: response.transaction_keys_remaining ?? 0
            )
        case "active":
            return .active(
                userGuid: response.user_guid ?? "",
                lastAuthAt: response.last_auth_at,
                lastSyncAt: response.last_sync_at,
                keysRemaining: response.transaction_keys_remaining ?? 0,
                credentialVersion: response.credential_version ?? 1
            )
        default:
            return .error(message: response.error_message ?? "Unknown error")
        }
    }
}

enum VaultState {
    case loading
    case notEnrolled
    case pending
    case enrolled(userGuid: String, enrolledAt: String?, keysRemaining: Int)
    case active(userGuid: String, lastAuthAt: String?, lastSyncAt: String?, keysRemaining: Int, credentialVersion: Int)
    case error(message: String)
}
```

### 3. Create VaultStatusView

```swift
// VettID/Sources/Vault/VaultStatusView.swift

struct VaultStatusView: View {
    @StateObject var viewModel: VaultStatusViewModel
    var onEnrollTap: () -> Void

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                switch viewModel.state {
                case .loading:
                    ProgressView()

                case .notEnrolled:
                    VaultNotEnrolledCard(onEnrollTap: onEnrollTap)

                case .pending:
                    VaultPendingCard()

                case .enrolled(let userGuid, let enrolledAt, let keysRemaining):
                    VaultEnrolledCard(
                        userGuid: userGuid,
                        enrolledAt: enrolledAt,
                        keysRemaining: keysRemaining
                    )

                case .active(_, let lastAuthAt, let lastSyncAt, let keysRemaining, let credentialVersion):
                    VaultActiveCard(
                        lastAuthAt: lastAuthAt,
                        lastSyncAt: lastSyncAt,
                        keysRemaining: keysRemaining,
                        credentialVersion: credentialVersion,
                        onSyncTap: {
                            Task { await viewModel.syncVault() }
                        }
                    )

                case .error(let message):
                    VaultErrorCard(
                        message: message,
                        onRetryTap: {
                            Task { await viewModel.loadVaultStatus() }
                        }
                    )
                }
            }
            .padding()
            .navigationTitle("Vault Status")
        }
        .task {
            await viewModel.loadVaultStatus()
        }
    }
}

struct VaultActiveCard: View {
    let lastAuthAt: String?
    let lastSyncAt: String?
    let keysRemaining: Int
    let credentialVersion: Int
    let onSyncTap: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(.green)
                    .font(.title)
                Text("Vault Active")
                    .font(.headline)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                InfoRow(label: "Last Sync", value: lastSyncAt ?? "Never")
                InfoRow(label: "Transaction Keys", value: "\(keysRemaining)")
                InfoRow(label: "Credential Version", value: "\(credentialVersion)")
            }

            Button("Sync Now", action: onSyncTap)
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
        }
    }
}
```

### 4. Background Refresh

```swift
// VettID/Sources/Vault/VaultBackgroundRefresh.swift

import BackgroundTasks

class VaultBackgroundRefresh {
    static let taskIdentifier = "dev.vettid.vaultsync"

    static func register() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: taskIdentifier,
            using: nil
        ) { task in
            handleRefresh(task: task as! BGAppRefreshTask)
        }
    }

    static func scheduleRefresh() {
        let request = BGAppRefreshTaskRequest(identifier: taskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 6 * 60 * 60) // 6 hours

        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Could not schedule app refresh: \(error)")
        }
    }

    private static func handleRefresh(task: BGAppRefreshTask) {
        scheduleRefresh() // Schedule next refresh

        let syncTask = Task {
            do {
                let vaultService = VaultService()
                let credentialStore = CredentialStore()

                let response = try await vaultService.syncVault()

                if let newKeys = response.new_transaction_keys {
                    try await credentialStore.addTransactionKeys(newKeys)
                }

                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }
        }

        task.expirationHandler = {
            syncTask.cancel()
        }
    }
}
```

### 5. Update Home/Main View

Add vault status card to main view:

```swift
// VettID/Sources/ContentView.swift

struct ContentView: View {
    @StateObject var vaultViewModel = VaultStatusViewModel(
        vaultService: VaultService(),
        credentialStore: CredentialStore()
    )
    @State private var showingVaultStatus = false

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                // Other content...

                VaultStatusCard(state: vaultViewModel.state) {
                    showingVaultStatus = true
                }
            }
            .padding()
            .sheet(isPresented: $showingVaultStatus) {
                VaultStatusView(
                    viewModel: vaultViewModel,
                    onEnrollTap: { /* Navigate to enrollment */ }
                )
            }
        }
        .task {
            await vaultViewModel.loadVaultStatus()
        }
    }
}

struct VaultStatusCard: View {
    let state: VaultState
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack {
                Image(systemName: iconName)
                    .font(.title2)
                    .foregroundColor(iconColor)

                VStack(alignment: .leading) {
                    Text("Vault")
                        .font(.headline)
                    Text(statusText)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Image(systemName: "chevron.right")
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)
        }
        .buttonStyle(.plain)
    }

    private var iconName: String {
        switch state {
        case .active: return "lock.shield.fill"
        case .notEnrolled: return "lock.open"
        case .pending, .enrolled: return "arrow.triangle.2.circlepath"
        case .loading: return "ellipsis"
        case .error: return "exclamationmark.triangle"
        }
    }

    private var iconColor: Color {
        switch state {
        case .active: return .green
        case .error: return .red
        default: return .blue
        }
    }

    private var statusText: String {
        switch state {
        case .active: return "Active"
        case .notEnrolled: return "Not Set Up"
        case .pending: return "Setup in Progress"
        case .enrolled: return "Enrolled"
        case .loading: return "Loading..."
        case .error: return "Error"
        }
    }
}
```

### 6. Unit Tests

```swift
// VettIDTests/VaultStatusViewModelTests.swift

class VaultStatusViewModelTests: XCTestCase {
    func testLoadVaultStatus_returnsActive() async { }
    func testLoadVaultStatus_returnsNotEnrolled() async { }
    func testSyncVault_storesNewTransactionKeys() async { }
    func testSyncVault_refreshesStatusAfterSync() async { }
}

// VettIDTests/VaultBackgroundRefreshTests.swift

class VaultBackgroundRefreshTests: XCTestCase {
    func testRegister_registersTask() { }
    func testScheduleRefresh_submitsRequest() { }
}
```

## Key References (in vettid-dev)

Pull latest from vettid-dev:
- `cdk/lambda/handlers/vault/getVaultStatus.ts`
- `cdk/lambda/handlers/vault/syncVault.ts`

## Acceptance Criteria

- [ ] VaultStatusViewModel loads and displays vault status
- [ ] VaultStatusView shows appropriate UI for each state
- [ ] Sync button triggers vault sync
- [ ] New transaction keys stored after sync
- [ ] Background refresh scheduled for every 6 hours
- [ ] Home screen shows vault status card
- [ ] Unit tests pass

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 3 vault lifecycle complete"
git push
```
