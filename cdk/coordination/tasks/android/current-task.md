# Task: Phase 8 - Backup System UI

## Phase
Phase 8: Backup System

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

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

## Phase 8 Android Tasks

### 1. Backup Data Models

Create backup data models:

```kotlin
// data/model/Backup.kt

data class Backup(
    val backupId: String,
    val createdAt: Long,
    val sizeBytes: Long,
    val type: BackupType,
    val status: BackupStatus,
    val encryptionMethod: String
)

enum class BackupType {
    AUTO,
    MANUAL
}

enum class BackupStatus {
    COMPLETE,
    PARTIAL,
    FAILED
}

data class BackupSettings(
    val autoBackupEnabled: Boolean,
    val backupFrequency: BackupFrequency,
    val backupTimeUtc: String,  // HH:mm format
    val retentionDays: Int,
    val includeMessages: Boolean,
    val wifiOnly: Boolean
)

enum class BackupFrequency {
    DAILY,
    WEEKLY,
    MONTHLY
}

data class CredentialBackupStatus(
    val exists: Boolean,
    val createdAt: Long?,
    val lastVerifiedAt: Long?
)
```

### 2. Backup API Client

Create API client for backups:

```kotlin
// network/BackupApiClient.kt

interface BackupApiClient {
    suspend fun triggerBackup(): Result<Backup>
    suspend fun listBackups(): Result<List<Backup>>
    suspend fun restoreBackup(backupId: String): Result<RestoreResult>
    suspend fun deleteBackup(backupId: String): Result<Unit>

    suspend fun getBackupSettings(): Result<BackupSettings>
    suspend fun updateBackupSettings(settings: BackupSettings): Result<BackupSettings>
}

// network/CredentialBackupApiClient.kt

interface CredentialBackupApiClient {
    suspend fun createCredentialBackup(encryptedBlob: ByteArray): Result<Unit>
    suspend fun getCredentialBackupStatus(): Result<CredentialBackupStatus>
    suspend fun downloadCredentialBackup(): Result<ByteArray>
}

data class RestoreResult(
    val success: Boolean,
    val restoredItems: Int,
    val conflicts: List<String>,
    val requiresReauth: Boolean
)
```

### 3. Recovery Phrase Manager

Create recovery phrase utilities:

```kotlin
// crypto/RecoveryPhraseManager.kt

class RecoveryPhraseManager @Inject constructor() {
    // Generate 24-word recovery phrase (BIP-39)
    fun generateRecoveryPhrase(): List<String>

    // Validate phrase against BIP-39 word list
    fun validatePhrase(phrase: List<String>): Boolean

    // Derive encryption key from phrase
    fun deriveKeyFromPhrase(
        phrase: List<String>,
        salt: ByteArray
    ): ByteArray

    // Encrypt credential blob for backup
    fun encryptCredentialBackup(
        credentialBlob: ByteArray,
        phrase: List<String>
    ): EncryptedCredentialBackup

    // Decrypt credential backup
    fun decryptCredentialBackup(
        encryptedBackup: ByteArray,
        phrase: List<String>
    ): ByteArray
}

data class EncryptedCredentialBackup(
    val ciphertext: ByteArray,
    val salt: ByteArray,
    val nonce: ByteArray
)
```

### 4. Backup List Screen

Create backup list UI:

```kotlin
// ui/backup/BackupListScreen.kt

@Composable
fun BackupListScreen(
    viewModel: BackupListViewModel = hiltViewModel(),
    onBackupClick: (String) -> Unit,
    onCreateBackup: () -> Unit,
    onSettings: () -> Unit
)

// States: Loading, Empty, Loaded(backups), Error

// UI Components:
// - Toolbar with settings icon
// - Create Backup FAB
// - Backup list:
//   - Backup date/time
//   - Backup type (auto/manual) badge
//   - Backup size
//   - Status indicator
//   - Swipe to delete
// - Pull-to-refresh
// - Empty state with explanation

// ui/backup/BackupListItem.kt

@Composable
fun BackupListItem(
    backup: Backup,
    onClick: () -> Unit,
    onDelete: () -> Unit
)
```

### 5. Backup Detail Screen

Create backup detail/restore UI:

```kotlin
// ui/backup/BackupDetailScreen.kt

@Composable
fun BackupDetailScreen(
    backupId: String,
    viewModel: BackupDetailViewModel = hiltViewModel(),
    onRestoreComplete: () -> Unit,
    onBack: () -> Unit
)

// UI Components:
// - Backup info card:
//   - Created date/time
//   - Backup type
//   - Size
//   - Encryption info
// - Contents preview:
//   - Handlers count
//   - Connections count
//   - Messages count
// - Restore button (with confirmation dialog)
// - Delete button (with confirmation dialog)
// - Restore progress dialog

// States: Loading, Loaded, Restoring(progress), RestoreComplete, Error
```

### 6. Backup Settings Screen

Create backup settings UI:

```kotlin
// ui/backup/BackupSettingsScreen.kt

@Composable
fun BackupSettingsScreen(
    viewModel: BackupSettingsViewModel = hiltViewModel(),
    onBack: () -> Unit
)

// UI Components:
// - Auto-backup toggle
// - Backup frequency selector (daily/weekly/monthly)
// - Backup time picker
// - Retention period selector
// - Include messages toggle
// - WiFi only toggle
// - Last backup info
// - Backup now button

// ui/backup/BackupSettingsItem.kt

@Composable
fun BackupFrequencySelector(
    frequency: BackupFrequency,
    onSelect: (BackupFrequency) -> Unit
)

@Composable
fun BackupTimeSelector(
    time: String,
    onSelect: (String) -> Unit
)
```

### 7. Credential Backup Screen

Create credential backup UI:

```kotlin
// ui/backup/CredentialBackupScreen.kt

@Composable
fun CredentialBackupScreen(
    viewModel: CredentialBackupViewModel = hiltViewModel(),
    onComplete: () -> Unit,
    onBack: () -> Unit
)

// States: Initial, GeneratingPhrase, ShowingPhrase, VerifyingPhrase, Complete, Error

// UI Components:
// - Explanation of credential backup
// - Generate backup button
// - Recovery phrase display (24 words in grid)
// - Copy phrase button
// - "I've written it down" confirmation
// - Phrase verification step (select words)
// - Success confirmation

// ui/backup/RecoveryPhraseDisplay.kt

@Composable
fun RecoveryPhraseDisplay(
    words: List<String>,
    onCopy: () -> Unit
)

// Shows 24 words in 4x6 or 3x8 grid
// Numbered words
// Copy to clipboard option
// Warning about not sharing
```

### 8. Credential Recovery Screen

Create credential recovery UI:

```kotlin
// ui/recovery/CredentialRecoveryScreen.kt

@Composable
fun CredentialRecoveryScreen(
    viewModel: CredentialRecoveryViewModel = hiltViewModel(),
    onRecoveryComplete: () -> Unit,
    onBack: () -> Unit
)

// States: EnteringPhrase, Validating, Recovering, Complete, Error

// UI Components:
// - Instructions
// - Word entry (24 text fields or word-by-word entry)
// - Auto-complete from BIP-39 word list
// - Validation feedback per word
// - Recover button
// - Progress indicator
// - Success/Error result

// ui/recovery/RecoveryPhraseInput.kt

@Composable
fun RecoveryPhraseInput(
    words: List<String>,
    onWordChange: (Int, String) -> Unit,
    wordErrors: List<Boolean>
)

// Features:
// - 24 input fields
// - Auto-complete suggestions
// - Invalid word highlighting
// - Paste from clipboard option
```

### 9. Backup ViewModels

Create ViewModels:

```kotlin
// ui/backup/BackupListViewModel.kt

@HiltViewModel
class BackupListViewModel @Inject constructor(
    private val backupApiClient: BackupApiClient
) : ViewModel() {

    val state: StateFlow<BackupListState>

    fun loadBackups()
    fun createBackup()
    fun deleteBackup(backupId: String)
    fun refresh()
}

// ui/backup/BackupDetailViewModel.kt

@HiltViewModel
class BackupDetailViewModel @Inject constructor(
    private val backupApiClient: BackupApiClient,
    savedStateHandle: SavedStateHandle
) : ViewModel() {

    private val backupId: String = savedStateHandle["backupId"]!!

    val state: StateFlow<BackupDetailState>

    fun loadBackup()
    fun restoreBackup()
    fun deleteBackup()
}

// ui/backup/CredentialBackupViewModel.kt

@HiltViewModel
class CredentialBackupViewModel @Inject constructor(
    private val recoveryPhraseManager: RecoveryPhraseManager,
    private val credentialBackupApiClient: CredentialBackupApiClient,
    private val credentialStore: CredentialStore
) : ViewModel() {

    val state: StateFlow<CredentialBackupState>
    val recoveryPhrase: StateFlow<List<String>?>

    fun generateBackup()
    fun confirmWrittenDown()
    fun verifyWord(index: Int, word: String): Boolean
    fun completeBackup()
}

// ui/recovery/CredentialRecoveryViewModel.kt

@HiltViewModel
class CredentialRecoveryViewModel @Inject constructor(
    private val recoveryPhraseManager: RecoveryPhraseManager,
    private val credentialBackupApiClient: CredentialBackupApiClient,
    private val credentialStore: CredentialStore
) : ViewModel() {

    val state: StateFlow<CredentialRecoveryState>
    val enteredWords: StateFlow<List<String>>
    val wordValidation: StateFlow<List<Boolean>>

    fun setWord(index: Int, word: String)
    fun validatePhrase(): Boolean
    fun recoverCredentials()
    fun getSuggestions(partial: String): List<String>
}
```

### 10. Background Backup Worker

Create WorkManager backup worker:

```kotlin
// worker/BackupWorker.kt

@HiltWorker
class BackupWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val backupApiClient: BackupApiClient,
    private val backupSettingsStore: BackupSettingsStore
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Check if auto-backup enabled
        // Check if WiFi required and connected
        // Trigger backup
        // Handle success/failure
        // Schedule next backup
    }

    companion object {
        fun schedule(context: Context, settings: BackupSettings)
        fun cancel(context: Context)
    }
}

// Schedule with PeriodicWorkRequest
// Constraints: network, battery not low
// BackoffPolicy for retries
```

### 11. BIP-39 Word List

Add BIP-39 word list resource:

```kotlin
// util/Bip39WordList.kt

object Bip39WordList {
    val words: List<String> = listOf(
        "abandon", "ability", "able", "about", "above", ...
        // 2048 words total
    )

    fun isValidWord(word: String): Boolean
    fun getSuggestions(prefix: String): List<String>
}
```

### 12. Navigation Integration

Add backup routes to navigation:

```kotlin
// Update VettIDApp.kt navigation graph

// New routes:
// - backups (list)
// - backups/settings
// - backups/{backupId}
// - backup/credential
// - recovery/credential

// Settings screen should link to:
// - Backup settings
// - Credential backup
```

## Dependencies

Add to `build.gradle.kts`:
```kotlin
// WorkManager for background backups
implementation("androidx.work:work-runtime-ktx:2.9.0")

// For BIP-39 (if using library instead of word list)
// implementation("cash.z.ecc.android:kotlin-bip39:1.0.6")
```

## Deliverables

- [ ] Backup data models
- [ ] BackupApiClient implementation
- [ ] RecoveryPhraseManager (BIP-39)
- [ ] BackupListScreen with list and delete
- [ ] BackupDetailScreen with restore
- [ ] BackupSettingsScreen with all options
- [ ] CredentialBackupScreen with phrase display
- [ ] CredentialRecoveryScreen with phrase input
- [ ] BackupWorker for scheduled backups
- [ ] BIP-39 word list and validation
- [ ] Navigation integration
- [ ] Unit tests for ViewModels

## Acceptance Criteria

- [ ] Can view list of backups with metadata
- [ ] Can trigger manual backup
- [ ] Can restore from backup with confirmation
- [ ] Can delete backups
- [ ] Backup settings persist and work
- [ ] Auto-backup runs on schedule
- [ ] Can create credential backup with recovery phrase
- [ ] Recovery phrase displays correctly (24 words)
- [ ] Can recover credentials using phrase
- [ ] Phrase validation works correctly
- [ ] WiFi-only setting respected

## Notes

- Store BIP-39 word list as string resource
- Use Argon2id for key derivation (already have)
- Test with known recovery phrases
- Consider phrase entry UX (word-by-word vs all at once)
- Handle backup during low battery gracefully
- Show notification for background backup completion

## Status Update

```bash
cd /path/to/vettid-android
git pull
# Implement backup system UI
./gradlew test  # Verify tests pass
git add .
git commit -m "Phase 8: Add backup system UI"
git push

# Update status
# Edit cdk/coordination/status/android.json (in vettid-dev repo)
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 8 backup UI complete"
git push
```
