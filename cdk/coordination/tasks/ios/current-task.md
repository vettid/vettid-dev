# Task: Phase 8 - Backup System UI

## Phase
Phase 8: Backup System

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 7 complete. Ready for Phase 8 backup system UI.

## Overview

Phase 8 implements the backup and recovery system UI. You need to create:
1. Backup management screen (list, create, restore)
2. Credential backup with recovery phrase
3. Recovery flow for device loss
4. Backup settings configuration
5. Background backup scheduling

## API Endpoints (Backend)

### Backup Management
```
POST /vault/backup                # Trigger manual backup
GET  /vault/backups               # List available backups
POST /vault/restore               # Initiate restore from backup
DELETE /vault/backups/{id}        # Delete specific backup
```

### Credential Backup
```
POST /vault/credentials/backup    # Create credential backup
GET  /vault/credentials/backup    # Get credential backup status
POST /vault/credentials/recover   # Recover credentials from backup
```

### Backup Settings
```
GET  /vault/backup/settings       # Get backup settings
PUT  /vault/backup/settings       # Update backup settings
```

## Phase 8 iOS Tasks

### 1. Backup Data Models

Create backup data models:

```swift
// Models/Backup.swift

struct Backup: Codable, Identifiable {
    let id: String           // backupId
    let createdAt: Date
    let sizeBytes: Int64
    let type: BackupType
    let status: BackupStatus
    let encryptionMethod: String
}

enum BackupType: String, Codable {
    case auto
    case manual
}

enum BackupStatus: String, Codable {
    case complete
    case partial
    case failed
}

struct BackupSettings: Codable {
    var autoBackupEnabled: Bool
    var backupFrequency: BackupFrequency
    var backupTimeUtc: String  // HH:mm format
    var retentionDays: Int
    var includeMessages: Bool
    var wifiOnly: Bool
}

enum BackupFrequency: String, Codable, CaseIterable {
    case daily
    case weekly
    case monthly
}

struct CredentialBackupStatus: Codable {
    let exists: Bool
    let createdAt: Date?
    let lastVerifiedAt: Date?
}
```

### 2. Backup API Client

Create API client extensions for backups:

```swift
// Services/BackupAPIClient.swift

extension APIClient {
    func triggerBackup() async throws -> Backup
    func listBackups() async throws -> [Backup]
    func restoreBackup(backupId: String) async throws -> RestoreResult
    func deleteBackup(backupId: String) async throws

    func getBackupSettings() async throws -> BackupSettings
    func updateBackupSettings(_ settings: BackupSettings) async throws -> BackupSettings
}

// Services/CredentialBackupAPIClient.swift

extension APIClient {
    func createCredentialBackup(encryptedBlob: Data) async throws
    func getCredentialBackupStatus() async throws -> CredentialBackupStatus
    func downloadCredentialBackup() async throws -> Data
}

struct RestoreResult: Codable {
    let success: Bool
    let restoredItems: Int
    let conflicts: [String]
    let requiresReauth: Bool
}
```

### 3. Recovery Phrase Manager

Create recovery phrase utilities:

```swift
// Crypto/RecoveryPhraseManager.swift

class RecoveryPhraseManager {
    // BIP-39 word list
    private let wordList: [String]

    init()

    // Generate 24-word recovery phrase (BIP-39)
    func generateRecoveryPhrase() -> [String]

    // Validate phrase against BIP-39 word list
    func validatePhrase(_ phrase: [String]) -> Bool

    // Validate single word
    func isValidWord(_ word: String) -> Bool

    // Get autocomplete suggestions
    func getSuggestions(for prefix: String) -> [String]

    // Derive encryption key from phrase using Argon2id
    func deriveKeyFromPhrase(
        _ phrase: [String],
        salt: Data
    ) throws -> Data

    // Encrypt credential blob for backup
    func encryptCredentialBackup(
        _ credentialBlob: Data,
        phrase: [String]
    ) throws -> EncryptedCredentialBackup

    // Decrypt credential backup
    func decryptCredentialBackup(
        _ encryptedBackup: Data,
        phrase: [String]
    ) throws -> Data
}

struct EncryptedCredentialBackup {
    let ciphertext: Data
    let salt: Data
    let nonce: Data
}
```

### 4. Backup List View

Create backup list UI:

```swift
// Views/Backup/BackupListView.swift

struct BackupListView: View {
    @StateObject private var viewModel = BackupListViewModel()
    @State private var showSettings = false
    @State private var showCreateBackup = false

    var body: some View {
        NavigationView {
            Group {
                switch viewModel.state {
                case .loading:
                    ProgressView()

                case .empty:
                    EmptyBackupView(onCreate: { showCreateBackup = true })

                case .loaded(let backups):
                    List {
                        ForEach(backups) { backup in
                            NavigationLink(destination: BackupDetailView(backupId: backup.id)) {
                                BackupListRow(backup: backup)
                            }
                        }
                        .onDelete { indexSet in
                            viewModel.deleteBackups(at: indexSet)
                        }
                    }
                    .refreshable {
                        await viewModel.refresh()
                    }

                case .error(let message):
                    ErrorView(message: message) {
                        Task { await viewModel.loadBackups() }
                    }
                }
            }
            .navigationTitle("Backups")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showSettings = true }) {
                        Image(systemName: "gearshape")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button(action: { showCreateBackup = true }) {
                        Image(systemName: "plus")
                    }
                }
            }
        }
        .sheet(isPresented: $showSettings) {
            BackupSettingsView()
        }
        .sheet(isPresented: $showCreateBackup) {
            CreateBackupView(onComplete: { Task { await viewModel.refresh() } })
        }
        .task {
            await viewModel.loadBackups()
        }
    }
}

// Views/Backup/BackupListRow.swift

struct BackupListRow: View {
    let backup: Backup

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(backup.createdAt, style: .date)
                    .font(.headline)
                Text(backup.createdAt, style: .time)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 4) {
                BackupTypeBadge(type: backup.type)
                Text(formatBytes(backup.sizeBytes))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
```

### 5. Backup Detail View

Create backup detail/restore UI:

```swift
// Views/Backup/BackupDetailView.swift

struct BackupDetailView: View {
    let backupId: String
    @StateObject private var viewModel = BackupDetailViewModel()
    @State private var showRestoreConfirmation = false
    @State private var showDeleteConfirmation = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Backup info card
                BackupInfoCard(backup: viewModel.backup)

                // Contents preview
                if let contents = viewModel.backupContents {
                    BackupContentsCard(contents: contents)
                }

                // Actions
                VStack(spacing: 12) {
                    Button(action: { showRestoreConfirmation = true }) {
                        Label("Restore from Backup", systemImage: "arrow.counterclockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    Button(role: .destructive, action: { showDeleteConfirmation = true }) {
                        Label("Delete Backup", systemImage: "trash")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)
            }
            .padding()
        }
        .navigationTitle("Backup Details")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Restore Backup", isPresented: $showRestoreConfirmation, titleVisibility: .visible) {
            Button("Restore") {
                Task { await viewModel.restoreBackup() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will replace your current data with the backup. This action cannot be undone.")
        }
        .confirmationDialog("Delete Backup", isPresented: $showDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                Task {
                    await viewModel.deleteBackup()
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .task {
            await viewModel.loadBackup(backupId)
        }
    }
}
```

### 6. Backup Settings View

Create backup settings UI:

```swift
// Views/Backup/BackupSettingsView.swift

struct BackupSettingsView: View {
    @StateObject private var viewModel = BackupSettingsViewModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            Form {
                Section("Automatic Backup") {
                    Toggle("Enable Auto-Backup", isOn: $viewModel.settings.autoBackupEnabled)

                    if viewModel.settings.autoBackupEnabled {
                        Picker("Frequency", selection: $viewModel.settings.backupFrequency) {
                            ForEach(BackupFrequency.allCases, id: \.self) { frequency in
                                Text(frequency.rawValue.capitalized)
                            }
                        }

                        DatePicker("Time", selection: $viewModel.backupTime, displayedComponents: .hourAndMinute)

                        Toggle("WiFi Only", isOn: $viewModel.settings.wifiOnly)
                    }
                }

                Section("Content") {
                    Toggle("Include Messages", isOn: $viewModel.settings.includeMessages)

                    Stepper("Keep \(viewModel.settings.retentionDays) days", value: $viewModel.settings.retentionDays, in: 7...365, step: 7)
                }

                Section {
                    if let lastBackup = viewModel.lastBackupDate {
                        HStack {
                            Text("Last Backup")
                            Spacer()
                            Text(lastBackup, style: .relative)
                                .foregroundColor(.secondary)
                        }
                    }

                    Button("Backup Now") {
                        Task { await viewModel.backupNow() }
                    }
                    .disabled(viewModel.isBackingUp)
                }

                Section("Credential Backup") {
                    NavigationLink(destination: CredentialBackupView()) {
                        HStack {
                            Text("Recovery Phrase")
                            Spacer()
                            if viewModel.credentialBackupExists {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                            } else {
                                Text("Not Set")
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Backup Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        Task {
                            await viewModel.saveSettings()
                            dismiss()
                        }
                    }
                }
            }
        }
        .task {
            await viewModel.loadSettings()
        }
    }
}
```

### 7. Credential Backup View

Create credential backup UI:

```swift
// Views/Backup/CredentialBackupView.swift

struct CredentialBackupView: View {
    @StateObject private var viewModel = CredentialBackupViewModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 24) {
            switch viewModel.state {
            case .initial:
                InitialBackupView(onGenerate: { viewModel.generateBackup() })

            case .generating:
                ProgressView("Generating recovery phrase...")

            case .showingPhrase(let words):
                RecoveryPhraseDisplayView(
                    words: words,
                    onConfirm: { viewModel.confirmWrittenDown() }
                )

            case .verifying(let words, let verifyIndices):
                RecoveryPhraseVerifyView(
                    originalWords: words,
                    verifyIndices: verifyIndices,
                    onVerify: { viewModel.completeBackup() }
                )

            case .complete:
                BackupCompleteView(onDone: { dismiss() })

            case .error(let message):
                ErrorView(message: message) {
                    viewModel.reset()
                }
            }
        }
        .padding()
        .navigationTitle("Credential Backup")
    }
}

// Views/Backup/RecoveryPhraseDisplayView.swift

struct RecoveryPhraseDisplayView: View {
    let words: [String]
    let onConfirm: () -> Void
    @State private var showCopied = false

    var body: some View {
        VStack(spacing: 24) {
            // Warning
            WarningBanner(
                message: "Write down these 24 words in order. Never share them with anyone."
            )

            // Word grid (4x6)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 4), spacing: 8) {
                ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                    HStack(spacing: 4) {
                        Text("\(index + 1).")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(word)
                            .font(.system(.body, design: .monospaced))
                    }
                    .padding(.vertical, 8)
                    .padding(.horizontal, 4)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                }
            }

            // Copy button
            Button(action: {
                UIPasteboard.general.string = words.joined(separator: " ")
                showCopied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    showCopied = false
                }
            }) {
                Label(showCopied ? "Copied!" : "Copy to Clipboard", systemImage: showCopied ? "checkmark" : "doc.on.doc")
            }

            Spacer()

            // Confirm button
            Button("I've Written It Down") {
                onConfirm()
            }
            .buttonStyle(.borderedProminent)
        }
    }
}
```

### 8. Credential Recovery View

Create credential recovery UI:

```swift
// Views/Recovery/CredentialRecoveryView.swift

struct CredentialRecoveryView: View {
    @StateObject private var viewModel = CredentialRecoveryViewModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 24) {
            switch viewModel.state {
            case .entering:
                RecoveryPhraseInputView(
                    words: $viewModel.enteredWords,
                    wordValidation: viewModel.wordValidation,
                    suggestions: viewModel.currentSuggestions,
                    onWordChange: { index, word in
                        viewModel.setWord(index, word)
                    },
                    onRecover: {
                        Task { await viewModel.recoverCredentials() }
                    }
                )

            case .validating:
                ProgressView("Validating phrase...")

            case .recovering:
                ProgressView("Recovering credentials...")

            case .complete:
                RecoveryCompleteView(onDone: { dismiss() })

            case .error(let message):
                ErrorView(message: message) {
                    viewModel.reset()
                }
            }
        }
        .padding()
        .navigationTitle("Recover Credentials")
    }
}

// Views/Recovery/RecoveryPhraseInputView.swift

struct RecoveryPhraseInputView: View {
    @Binding var words: [String]
    let wordValidation: [Bool]
    let suggestions: [String]
    let onWordChange: (Int, String) -> Void
    let onRecover: () -> Void
    @FocusState private var focusedField: Int?

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Text("Enter your 24-word recovery phrase")
                    .font(.headline)

                // Word input grid (3x8)
                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 8) {
                    ForEach(0..<24, id: \.self) { index in
                        HStack(spacing: 4) {
                            Text("\(index + 1).")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .frame(width: 20)

                            TextField("", text: Binding(
                                get: { words[index] },
                                set: { onWordChange(index, $0) }
                            ))
                            .textFieldStyle(.roundedBorder)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .focused($focusedField, equals: index)
                            .foregroundColor(wordValidation[index] ? .primary : .red)
                        }
                    }
                }

                // Suggestions
                if !suggestions.isEmpty && focusedField != nil {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(suggestions, id: \.self) { suggestion in
                                Button(suggestion) {
                                    if let index = focusedField {
                                        onWordChange(index, suggestion)
                                        focusedField = index < 23 ? index + 1 : nil
                                    }
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    }
                }

                Spacer()

                // Recover button
                Button("Recover") {
                    onRecover()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!wordValidation.allSatisfy { $0 })
            }
        }
    }
}
```

### 9. Backup ViewModels

Create ViewModels:

```swift
// ViewModels/BackupListViewModel.swift

@MainActor
class BackupListViewModel: ObservableObject {
    @Published var state: BackupListState = .loading

    private let apiClient: APIClient

    func loadBackups() async
    func refresh() async
    func deleteBackups(at indexSet: IndexSet)
}

// ViewModels/BackupDetailViewModel.swift

@MainActor
class BackupDetailViewModel: ObservableObject {
    @Published var backup: Backup?
    @Published var backupContents: BackupContents?
    @Published var isRestoring = false

    private let apiClient: APIClient

    func loadBackup(_ id: String) async
    func restoreBackup() async
    func deleteBackup() async
}

// ViewModels/CredentialBackupViewModel.swift

@MainActor
class CredentialBackupViewModel: ObservableObject {
    @Published var state: CredentialBackupState = .initial
    @Published var recoveryPhrase: [String] = []

    private let recoveryPhraseManager: RecoveryPhraseManager
    private let apiClient: APIClient
    private let credentialStore: CredentialStore

    func generateBackup()
    func confirmWrittenDown()
    func completeBackup() async
    func reset()
}

// ViewModels/CredentialRecoveryViewModel.swift

@MainActor
class CredentialRecoveryViewModel: ObservableObject {
    @Published var state: CredentialRecoveryState = .entering
    @Published var enteredWords: [String] = Array(repeating: "", count: 24)
    @Published var wordValidation: [Bool] = Array(repeating: true, count: 24)
    @Published var currentSuggestions: [String] = []

    private let recoveryPhraseManager: RecoveryPhraseManager
    private let apiClient: APIClient
    private let credentialStore: CredentialStore

    func setWord(_ index: Int, _ word: String)
    func getSuggestions(for prefix: String)
    func recoverCredentials() async
    func reset()
}
```

### 10. Background Backup Task

Create BGTaskScheduler backup task:

```swift
// Services/BackupBackgroundTask.swift

class BackupBackgroundTask {
    static let identifier = "dev.vettid.backup"

    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            handleBackupTask(task as! BGProcessingTask)
        }
    }

    static func schedule(settings: BackupSettings) {
        let request = BGProcessingTaskRequest(identifier: identifier)
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false

        // Calculate next backup time based on settings
        request.earliestBeginDate = calculateNextBackupDate(settings)

        try? BGTaskScheduler.shared.submit(request)
    }

    static func cancel() {
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
    }

    private static func handleBackupTask(_ task: BGProcessingTask) {
        // Check WiFi if required
        // Trigger backup
        // Schedule next backup
        // Complete task
    }
}
```

### 11. BIP-39 Word List

Add BIP-39 word list:

```swift
// Crypto/BIP39WordList.swift

struct BIP39WordList {
    static let words: [String] = [
        "abandon", "ability", "able", "about", "above",
        // ... 2048 words total
    ]

    static func isValidWord(_ word: String) -> Bool {
        words.contains(word.lowercased())
    }

    static func getSuggestions(for prefix: String) -> [String] {
        guard prefix.count >= 2 else { return [] }
        let lowercased = prefix.lowercased()
        return words.filter { $0.hasPrefix(lowercased) }.prefix(5).map { $0 }
    }
}
```

### 12. Navigation Integration

Add backup routes to navigation:

```swift
// Update main app navigation

// Tab: Settings
// - BackupSettingsView
//   - BackupListView (push)
//     - BackupDetailView (push)
//   - CredentialBackupView (push)

// Recovery (entry point from login/onboarding)
// - CredentialRecoveryView
```

## Deliverables

- [ ] Backup data models with Codable
- [ ] APIClient extensions for backup endpoints
- [ ] RecoveryPhraseManager (BIP-39)
- [ ] BackupListView with list and swipe-to-delete
- [ ] BackupDetailView with restore
- [ ] BackupSettingsView with all options
- [ ] CredentialBackupView with phrase display
- [ ] CredentialRecoveryView with phrase input
- [ ] BackupBackgroundTask for scheduled backups
- [ ] BIP-39 word list and validation
- [ ] Navigation integration
- [ ] Unit tests for ViewModels

## Acceptance Criteria

- [ ] Can view list of backups with metadata
- [ ] Can trigger manual backup
- [ ] Can restore from backup with confirmation
- [ ] Can delete backups
- [ ] Backup settings persist and work
- [ ] Auto-backup runs on schedule via BGTask
- [ ] Can create credential backup with recovery phrase
- [ ] Recovery phrase displays correctly (24 words)
- [ ] Can recover credentials using phrase
- [ ] Phrase validation with autocomplete works
- [ ] WiFi-only setting respected

## Notes

- Use CryptoKit for key derivation where possible
- Argon2id via existing PasswordHasher for phrase key derivation
- BGProcessingTask for background backups (iOS 13+)
- Consider iCloud Keychain integration for backup
- Test phrase entry UX for accessibility
- Handle app termination during backup gracefully

## Status Update

```bash
cd /path/to/vettid-ios
git pull
# Implement backup system UI
swift test  # Verify tests pass
git add .
git commit -m "Phase 8: Add backup system UI"
git push

# Update status
# Edit cdk/coordination/status/ios.json (in vettid-dev repo)
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 8 backup UI complete"
git push
```
