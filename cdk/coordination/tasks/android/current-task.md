# Task: Phase 3 - Vault Lifecycle Management

## Phase
Phase 3: Vault Services Enrollment

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

## Status
Phase 2 complete. Ready for Phase 3 vault lifecycle management.

## New Backend Endpoints

Three new endpoints have been added:

1. `GET /vault/status` - Get vault status (not_enrolled, pending, enrolled, active)
2. `POST /vault/sync` - Sync vault and replenish transaction keys
3. `POST /member/vault/deploy` - Web portal endpoint (not used by mobile)

## Phase 3 Android Tasks

### 1. Add Vault Status API

Update VaultService interface:

```kotlin
interface VaultService {
    // Existing enrollment/auth endpoints...

    @GET("/vault/status")
    suspend fun getVaultStatus(): VaultStatusResponse

    @POST("/vault/sync")
    suspend fun syncVault(): SyncResponse
}

data class VaultStatusResponse(
    val status: String,                    // "not_enrolled", "pending", "enrolled", "active", "error"
    val user_guid: String? = null,
    val enrolled_at: String? = null,
    val last_auth_at: String? = null,
    val last_sync_at: String? = null,
    val device_type: String? = null,       // "android" or "ios"
    val security_level: String? = null,    // "hardware", "StrongBox", "TEE"
    val transaction_keys_remaining: Int? = null,
    val credential_version: Int? = null,
    val error_message: String? = null
)

data class SyncResponse(
    val status: String,                    // "synced" or "keys_replenished"
    val last_sync_at: String,
    val transaction_keys_remaining: Int,
    val new_transaction_keys: List<TransactionKey>? = null,
    val credential_version: Int
)
```

### 2. Create VaultStatusViewModel

```kotlin
// app/src/main/kotlin/dev/vettid/vault/
VaultStatusViewModel.kt

@HiltViewModel
class VaultStatusViewModel @Inject constructor(
    private val vaultService: VaultService,
    private val credentialStore: CredentialStore
) : ViewModel() {

    private val _state = MutableStateFlow<VaultState>(VaultState.Loading)
    val state: StateFlow<VaultState> = _state.asStateFlow()

    init {
        loadVaultStatus()
    }

    fun loadVaultStatus() {
        viewModelScope.launch {
            _state.value = VaultState.Loading
            try {
                val response = vaultService.getVaultStatus()
                _state.value = when (response.status) {
                    "not_enrolled" -> VaultState.NotEnrolled
                    "pending" -> VaultState.Pending
                    "enrolled" -> VaultState.Enrolled(
                        userGuid = response.user_guid!!,
                        enrolledAt = response.enrolled_at,
                        keysRemaining = response.transaction_keys_remaining ?: 0
                    )
                    "active" -> VaultState.Active(
                        userGuid = response.user_guid!!,
                        lastAuthAt = response.last_auth_at,
                        lastSyncAt = response.last_sync_at,
                        keysRemaining = response.transaction_keys_remaining ?: 0,
                        credentialVersion = response.credential_version ?: 1
                    )
                    else -> VaultState.Error(response.error_message ?: "Unknown error")
                }
            } catch (e: Exception) {
                _state.value = VaultState.Error(e.message ?: "Failed to load status")
            }
        }
    }

    fun syncVault() {
        viewModelScope.launch {
            try {
                val response = vaultService.syncVault()

                // Store any new transaction keys
                response.new_transaction_keys?.let { keys ->
                    credentialStore.addTransactionKeys(keys)
                }

                // Refresh status
                loadVaultStatus()
            } catch (e: Exception) {
                // Handle sync error
            }
        }
    }
}

sealed class VaultState {
    object Loading : VaultState()
    object NotEnrolled : VaultState()
    object Pending : VaultState()
    data class Enrolled(
        val userGuid: String,
        val enrolledAt: String?,
        val keysRemaining: Int
    ) : VaultState()
    data class Active(
        val userGuid: String,
        val lastAuthAt: String?,
        val lastSyncAt: String?,
        val keysRemaining: Int,
        val credentialVersion: Int
    ) : VaultState()
    data class Error(val message: String) : VaultState()
}
```

### 3. Create VaultStatusScreen

```kotlin
// app/src/main/kotlin/dev/vettid/vault/
VaultStatusScreen.kt

@Composable
fun VaultStatusScreen(
    viewModel: VaultStatusViewModel = hiltViewModel(),
    onEnrollClick: () -> Unit
) {
    val state by viewModel.state.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Vault Status",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        when (val currentState = state) {
            is VaultState.Loading -> {
                CircularProgressIndicator()
            }
            is VaultState.NotEnrolled -> {
                VaultNotEnrolledCard(onEnrollClick = onEnrollClick)
            }
            is VaultState.Pending -> {
                VaultPendingCard()
            }
            is VaultState.Enrolled -> {
                VaultEnrolledCard(state = currentState)
            }
            is VaultState.Active -> {
                VaultActiveCard(
                    state = currentState,
                    onSyncClick = { viewModel.syncVault() }
                )
            }
            is VaultState.Error -> {
                VaultErrorCard(
                    message = currentState.message,
                    onRetryClick = { viewModel.loadVaultStatus() }
                )
            }
        }
    }
}

@Composable
fun VaultActiveCard(
    state: VaultState.Active,
    onSyncClick: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = Color.Green
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Vault Active", style = MaterialTheme.typography.titleMedium)
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text("Last Sync: ${state.lastSyncAt ?: "Never"}")
            Text("Transaction Keys: ${state.keysRemaining}")
            Text("Credential Version: ${state.credentialVersion}")

            Spacer(modifier = Modifier.height(16.dp))

            Button(onClick = onSyncClick) {
                Text("Sync Now")
            }
        }
    }
}
```

### 4. Background Sync Worker

```kotlin
// app/src/main/kotlin/dev/vettid/vault/
VaultSyncWorker.kt

@HiltWorker
class VaultSyncWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val vaultService: VaultService,
    private val credentialStore: CredentialStore
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            val response = vaultService.syncVault()

            // Store new transaction keys if any
            response.new_transaction_keys?.let { keys ->
                credentialStore.addTransactionKeys(keys)
            }

            Result.success()
        } catch (e: Exception) {
            if (runAttemptCount < 3) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }

    companion object {
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val syncRequest = PeriodicWorkRequestBuilder<VaultSyncWorker>(
                repeatInterval = 6,
                repeatIntervalTimeUnit = TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(
                    "vault_sync",
                    ExistingPeriodicWorkPolicy.KEEP,
                    syncRequest
                )
        }
    }
}
```

### 5. Update Home Screen

Add vault status card to main screen:

```kotlin
@Composable
fun HomeScreen(
    vaultViewModel: VaultStatusViewModel = hiltViewModel(),
    onVaultClick: () -> Unit
) {
    val vaultState by vaultViewModel.state.collectAsState()

    Column(modifier = Modifier.padding(16.dp)) {
        // Other home content...

        VaultStatusCard(
            state = vaultState,
            onClick = onVaultClick
        )
    }
}

@Composable
fun VaultStatusCard(
    state: VaultState,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = when (state) {
                    is VaultState.Active -> Icons.Default.Lock
                    is VaultState.NotEnrolled -> Icons.Default.LockOpen
                    else -> Icons.Default.Sync
                },
                contentDescription = null
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text("Vault", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = when (state) {
                        is VaultState.Active -> "Active"
                        is VaultState.NotEnrolled -> "Not Set Up"
                        is VaultState.Pending -> "Setup in Progress"
                        is VaultState.Enrolled -> "Enrolled"
                        is VaultState.Loading -> "Loading..."
                        is VaultState.Error -> "Error"
                    },
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
```

### 6. Unit Tests

```kotlin
class VaultStatusViewModelTest {
    @Test
    fun `loadVaultStatus updates state to Active`()

    @Test
    fun `loadVaultStatus updates state to NotEnrolled`()

    @Test
    fun `syncVault stores new transaction keys`()

    @Test
    fun `syncVault refreshes status after sync`()
}

class VaultSyncWorkerTest {
    @Test
    fun `doWork syncs successfully`()

    @Test
    fun `doWork retries on failure`()

    @Test
    fun `doWork stores new keys`()
}
```

## Key References (in vettid-dev)

Pull latest from vettid-dev:
- `cdk/lambda/handlers/vault/getVaultStatus.ts`
- `cdk/lambda/handlers/vault/syncVault.ts`

## Acceptance Criteria

- [ ] VaultStatusViewModel loads and displays vault status
- [ ] VaultStatusScreen shows appropriate UI for each state
- [ ] Sync button triggers vault sync
- [ ] New transaction keys stored after sync
- [ ] Background worker syncs every 6 hours
- [ ] Home screen shows vault status card
- [ ] Unit tests pass

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 3 vault lifecycle complete"
git push
```
