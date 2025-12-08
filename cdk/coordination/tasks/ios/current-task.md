# Task: Phase 6 - Handler Discovery & Execution

## Phase
Phase 6: Handler System (WASM)

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 5 complete. Ready for Phase 6 handler discovery and execution.

## Overview

Phase 6 implements the handler system UI for discovering, installing, and triggering WASM handlers. The mobile app interacts with:
1. Handler Registry API to list and download handlers
2. Vault to install and execute handlers
3. Handler responses via NATS

## New Backend Endpoints

### Handler Registry
```
GET  /registry/handlers              # List available handlers
GET  /registry/handlers/{id}         # Get handler details and download URL
POST /vault/handlers/install         # Install handler on vault
POST /vault/handlers/uninstall       # Uninstall handler from vault
GET  /vault/handlers                 # List installed handlers
POST /vault/handlers/{id}/execute    # Execute handler with input
```

## Phase 6 iOS Tasks

### 1. Handler Registry Client

Add registry API to APIClient:

```swift
// Services/HandlerRegistryClient.swift

extension APIClient {
    func listHandlers(
        category: String? = nil,
        page: Int = 1,
        limit: Int = 20
    ) async throws -> HandlerListResponse

    func getHandler(id: String) async throws -> HandlerDetailResponse
}

struct HandlerListResponse: Codable {
    let handlers: [HandlerSummary]
    let total: Int
    let page: Int
    let has_more: Bool
}

struct HandlerSummary: Codable, Identifiable {
    let id: String
    let name: String
    let description: String
    let version: String
    let category: String
    let icon_url: String?
    let publisher: String
    let installed: Bool
    let installed_version: String?
}

struct HandlerDetailResponse: Codable {
    let id: String
    let name: String
    let description: String
    let version: String
    let category: String
    let icon_url: String?
    let publisher: String
    let published_at: String
    let size_bytes: Int
    let permissions: [HandlerPermission]
    let input_schema: [String: AnyCodableValue]
    let output_schema: [String: AnyCodableValue]
    let changelog: String?
    let installed: Bool
    let installed_version: String?
}

struct HandlerPermission: Codable {
    let type: String      // "network", "storage", "crypto"
    let scope: String     // e.g., "api.example.com" for network
    let description: String
}
```

### 2. Handler Installation Client

Add vault handler management endpoints:

```swift
// Services/VaultHandlerClient.swift

extension APIClient {
    func installHandler(
        handlerId: String,
        version: String
    ) async throws -> InstallHandlerResponse

    func uninstallHandler(handlerId: String) async throws -> UninstallHandlerResponse

    func listInstalledHandlers() async throws -> InstalledHandlersResponse

    func executeHandler(
        handlerId: String,
        input: [String: AnyCodableValue],
        timeoutMs: Int = 30000
    ) async throws -> ExecuteHandlerResponse
}

struct InstallHandlerRequest: Encodable {
    let handler_id: String
    let version: String
}

struct InstallHandlerResponse: Codable {
    let status: String      // "installed", "failed"
    let handler_id: String
    let version: String
    let installed_at: String?
}

struct ExecuteHandlerRequest: Encodable {
    let input: [String: AnyCodableValue]
    let timeout_ms: Int
}

struct ExecuteHandlerResponse: Codable {
    let request_id: String
    let status: String      // "success", "error", "timeout"
    let output: [String: AnyCodableValue]?
    let error: String?
    let execution_time_ms: Int
}
```

### 3. Handler Discovery ViewModel

Create ViewModel for browsing handlers:

```swift
// Handlers/HandlerDiscoveryViewModel.swift

@MainActor
class HandlerDiscoveryViewModel: ObservableObject {
    @Published var state: HandlerDiscoveryState = .loading
    @Published var selectedCategory: String? = nil
    @Published var installingHandlerId: String? = nil

    private let apiClient: APIClient

    init(apiClient: APIClient) {
        self.apiClient = apiClient
    }

    func loadHandlers() async {
        state = .loading
        do {
            let response = try await apiClient.listHandlers(category: selectedCategory)
            state = .loaded(handlers: response.handlers, hasMore: response.has_more)
        } catch {
            state = .error(error.localizedDescription)
        }
    }

    func selectCategory(_ category: String?) {
        selectedCategory = category
        Task { await loadHandlers() }
    }

    func installHandler(_ handler: HandlerSummary) async {
        installingHandlerId = handler.id
        do {
            let result = try await apiClient.installHandler(
                handlerId: handler.id,
                version: handler.version
            )
            if result.status == "installed" {
                await loadHandlers()
            }
        } catch {
            // Handle error
        }
        installingHandlerId = nil
    }

    func uninstallHandler(_ handler: HandlerSummary) async {
        do {
            _ = try await apiClient.uninstallHandler(handlerId: handler.id)
            await loadHandlers()
        } catch {
            // Handle error
        }
    }
}

enum HandlerDiscoveryState {
    case loading
    case loaded(handlers: [HandlerSummary], hasMore: Bool)
    case error(String)
}
```

### 4. Handler Discovery View

Create handler browsing screens:

```swift
// Handlers/HandlerDiscoveryView.swift

struct HandlerDiscoveryView: View {
    @StateObject var viewModel: HandlerDiscoveryViewModel
    @State private var selectedHandler: HandlerSummary?

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Category picker
                CategoryPicker(
                    selectedCategory: $viewModel.selectedCategory,
                    onSelect: { viewModel.selectCategory($0) }
                )

                // Handler list
                switch viewModel.state {
                case .loading:
                    ProgressView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                case .loaded(let handlers, _):
                    List(handlers) { handler in
                        HandlerListRow(
                            handler: handler,
                            isInstalling: viewModel.installingHandlerId == handler.id,
                            onTap: { selectedHandler = handler },
                            onInstall: { Task { await viewModel.installHandler(handler) } },
                            onUninstall: { Task { await viewModel.uninstallHandler(handler) } }
                        )
                    }
                    .listStyle(.plain)

                case .error(let message):
                    ErrorView(message: message) {
                        Task { await viewModel.loadHandlers() }
                    }
                }
            }
            .navigationTitle("Handlers")
            .sheet(item: $selectedHandler) { handler in
                HandlerDetailView(handlerId: handler.id)
            }
        }
        .task {
            await viewModel.loadHandlers()
        }
    }
}

struct CategoryPicker: View {
    @Binding var selectedCategory: String?
    let onSelect: (String?) -> Void

    let categories: [(String?, String)] = [
        (nil, "All"),
        ("messaging", "Messaging"),
        ("social", "Social"),
        ("productivity", "Productivity"),
        ("utilities", "Utilities")
    ]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                ForEach(categories, id: \.0) { category, label in
                    CategoryChip(
                        label: label,
                        isSelected: selectedCategory == category,
                        action: { onSelect(category) }
                    )
                }
            }
            .padding(.horizontal)
        }
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }
}

struct HandlerListRow: View {
    let handler: HandlerSummary
    let isInstalling: Bool
    let onTap: () -> Void
    let onInstall: () -> Void
    let onUninstall: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            // Handler icon
            AsyncImage(url: URL(string: handler.icon_url ?? "")) { image in
                image.resizable().aspectRatio(contentMode: .fit)
            } placeholder: {
                Image(systemName: "cube.box")
                    .foregroundColor(.secondary)
            }
            .frame(width: 48, height: 48)
            .background(Color(.systemGray6))
            .cornerRadius(8)

            VStack(alignment: .leading, spacing: 4) {
                Text(handler.name)
                    .font(.headline)
                Text(handler.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
                Text("v\(handler.version) by \(handler.publisher)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Install/Uninstall button
            if isInstalling {
                ProgressView()
            } else if handler.installed {
                Button("Uninstall", action: onUninstall)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            } else {
                Button("Install", action: onInstall)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .onTapGesture(perform: onTap)
    }
}
```

### 5. Handler Detail View

Create handler detail screen:

```swift
// Handlers/HandlerDetailView.swift

struct HandlerDetailView: View {
    let handlerId: String
    @StateObject private var viewModel: HandlerDetailViewModel
    @Environment(\.dismiss) private var dismiss

    init(handlerId: String) {
        self.handlerId = handlerId
        self._viewModel = StateObject(wrappedValue: HandlerDetailViewModel())
    }

    var body: some View {
        NavigationView {
            Group {
                switch viewModel.state {
                case .loading:
                    ProgressView()

                case .loaded(let handler):
                    HandlerDetailContent(
                        handler: handler,
                        isInstalling: viewModel.isInstalling,
                        onInstall: { Task { await viewModel.installHandler() } },
                        onUninstall: { Task { await viewModel.uninstallHandler() } },
                        onExecute: { viewModel.showExecutionSheet = true }
                    )

                case .error(let message):
                    ErrorView(message: message) {
                        Task { await viewModel.loadHandler(handlerId) }
                    }
                }
            }
            .navigationTitle("Handler Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .sheet(isPresented: $viewModel.showExecutionSheet) {
            if case .loaded(let handler) = viewModel.state {
                HandlerExecutionView(
                    handler: handler,
                    viewModel: HandlerExecutionViewModel()
                )
            }
        }
        .task {
            await viewModel.loadHandler(handlerId)
        }
    }
}

struct HandlerDetailContent: View {
    let handler: HandlerDetailResponse
    let isInstalling: Bool
    let onInstall: () -> Void
    let onUninstall: () -> Void
    let onExecute: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack(spacing: 16) {
                    AsyncImage(url: URL(string: handler.icon_url ?? "")) { image in
                        image.resizable().aspectRatio(contentMode: .fit)
                    } placeholder: {
                        Image(systemName: "cube.box")
                    }
                    .frame(width: 64, height: 64)
                    .background(Color(.systemGray6))
                    .cornerRadius(12)

                    VStack(alignment: .leading) {
                        Text(handler.name)
                            .font(.title2)
                            .fontWeight(.bold)
                        Text("v\(handler.version) by \(handler.publisher)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }

                Text(handler.description)
                    .font(.body)

                // Permissions section
                VStack(alignment: .leading, spacing: 12) {
                    Text("Permissions")
                        .font(.headline)

                    ForEach(handler.permissions, id: \.type) { permission in
                        PermissionRow(permission: permission)
                    }
                }

                // Action buttons
                if handler.installed {
                    HStack(spacing: 12) {
                        Button(action: onExecute) {
                            Label("Execute", systemImage: "play.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)

                        Button(action: onUninstall) {
                            Label("Uninstall", systemImage: "trash")
                        }
                        .buttonStyle(.bordered)
                    }
                } else {
                    Button(action: onInstall) {
                        if isInstalling {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Label("Install", systemImage: "arrow.down.circle")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isInstalling)
                }

                // Changelog
                if let changelog = handler.changelog {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Changelog")
                            .font(.headline)
                        Text(changelog)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding()
        }
    }
}

struct PermissionRow: View {
    let permission: HandlerPermission

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: iconForPermission(permission.type))
                .foregroundColor(.blue)
                .frame(width: 24)

            VStack(alignment: .leading) {
                Text(permission.type.capitalized)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(permission.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private func iconForPermission(_ type: String) -> String {
        switch type {
        case "network": return "network"
        case "storage": return "externaldrive"
        case "crypto": return "lock.shield"
        default: return "questionmark.circle"
        }
    }
}
```

### 6. Handler Execution View

Create input form and result display:

```swift
// Handlers/HandlerExecutionView.swift

struct HandlerExecutionView: View {
    let handler: HandlerDetailResponse
    @StateObject var viewModel: HandlerExecutionViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                // Dynamic input form
                DynamicInputForm(
                    schema: handler.input_schema,
                    values: $viewModel.inputValues
                )

                // Execute button
                Button(action: {
                    Task {
                        await viewModel.execute(
                            handlerId: handler.id,
                            input: viewModel.inputValues
                        )
                    }
                }) {
                    if viewModel.isExecuting {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text("Execute")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isExecuting)

                // Result display
                if let result = viewModel.result {
                    ExecutionResultView(result: result)
                }

                if let error = viewModel.errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Execute \(handler.name)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct ExecutionResultView: View {
    let result: ExecuteHandlerResponse

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: result.status == "success" ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(result.status == "success" ? .green : .red)
                Text(result.status.capitalized)
                    .fontWeight(.semibold)
                Spacer()
                Text("\(result.execution_time_ms)ms")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if let output = result.output {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Output:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(formatOutput(output))
                        .font(.system(.caption, design: .monospaced))
                        .padding(8)
                        .background(Color(.systemGray6))
                        .cornerRadius(4)
                }
            }

            if let error = result.error {
                Text(error)
                    .foregroundColor(.red)
                    .font(.caption)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }

    private func formatOutput(_ output: [String: AnyCodableValue]) -> String {
        // Convert to JSON string for display
        if let data = try? JSONEncoder().encode(output),
           let string = String(data: data, encoding: .utf8) {
            return string
        }
        return "Unable to display output"
    }
}
```

### 7. Unit Tests

```swift
// VettIDTests/HandlerDiscoveryViewModelTests.swift

class HandlerDiscoveryViewModelTests: XCTestCase {
    func testLoadHandlers_updatesStateWithHandlerList() async { }
    func testSelectCategory_filtersHandlers() async { }
    func testInstallHandler_callsAPIAndRefreshesList() async { }
    func testUninstallHandler_callsAPIAndRefreshesList() async { }
}

// VettIDTests/HandlerDetailViewModelTests.swift

class HandlerDetailViewModelTests: XCTestCase {
    func testLoadHandler_fetchesHandlerDetails() async { }
    func testExecuteHandler_sendsInputAndReceivesOutput() async { }
    func testExecuteHandler_handlesTimeout() async { }
}

// VettIDTests/HandlerExecutionViewModelTests.swift

class HandlerExecutionViewModelTests: XCTestCase {
    func testExecute_sendsRequestAndUpdatesState() async { }
    func testExecute_handlesErrorResponse() async { }
    func testExecute_showsLoadingStateDuringExecution() async { }
}
```

## Deliverables

- [ ] APIClient extensions for registry and handler management
- [ ] HandlerDiscoveryViewModel and HandlerDiscoveryView
- [ ] HandlerDetailView with permissions display
- [ ] HandlerExecutionView with dynamic input form
- [ ] DynamicInputForm component for schema-driven forms
- [ ] Navigation integration for handler flows
- [ ] Unit tests for ViewModels

## Acceptance Criteria

- [ ] User can browse available handlers by category
- [ ] User can view handler details and permissions
- [ ] User can install/uninstall handlers
- [ ] User can execute installed handlers
- [ ] Handler execution shows input form based on schema
- [ ] Handler results displayed correctly
- [ ] Error states handled gracefully

## Notes

- Handler icons may be null - show SF Symbol placeholder
- Input schema drives dynamic form generation using SwiftUI
- Consider caching handler list for offline browsing
- Permissions should be clearly explained to user
- Use async/await throughout for clean async code

## Status Update

```bash
cd /path/to/vettid-ios
git pull
# Create handler UI components
git add .
git commit -m "Phase 6: Add handler discovery and execution UI"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 6 handler UI complete"
git push
```
