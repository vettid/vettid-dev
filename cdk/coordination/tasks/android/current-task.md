# Task: Phase 5 - Vault Communication

## Phase
Phase 5: Vault Instance (EC2)

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

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

## Phase 5 Android Tasks

### 1. Vault Provisioning Client

Add vault lifecycle API to VaultServiceClient:

```kotlin
// api/VaultServiceClient.kt

interface VaultServiceClient {
    // Existing endpoints...

    @POST("/vault/provision")
    suspend fun provisionVault(): ProvisionResponse

    @POST("/vault/initialize")
    suspend fun initializeVault(): InitializeResponse

    @POST("/vault/stop")
    suspend fun stopVault(): StopResponse

    @POST("/vault/terminate")
    suspend fun terminateVault(): TerminateResponse

    @GET("/vault/health")
    suspend fun getVaultHealth(): VaultHealthResponse
}

data class ProvisionResponse(
    val instance_id: String,
    val status: String,  // "provisioning", "running", "failed"
    val region: String,
    val availability_zone: String,
    val private_ip: String?,
    val estimated_ready_at: String
)

data class InitializeResponse(
    val status: String,  // "initialized", "failed"
    val local_nats_status: String,
    val central_nats_status: String,
    val owner_space_id: String,
    val message_space_id: String
)

data class VaultHealthResponse(
    val status: String,  // "healthy", "unhealthy", "degraded"
    val uptime_seconds: Long,
    val local_nats: NatsHealth,
    val central_nats: CentralNatsHealth,
    val vault_manager: VaultManagerHealth,
    val last_event_at: String?
)

data class NatsHealth(
    val status: String,
    val connections: Int
)

data class CentralNatsHealth(
    val status: String,
    val latency_ms: Long
)

data class VaultManagerHealth(
    val status: String,
    val memory_mb: Int,
    val cpu_percent: Float,
    val handlers_loaded: Int
)
```

### 2. Event Submission via NATS

Implement event submission through OwnerSpaceClient:

```kotlin
// nats/VaultEventClient.kt

class VaultEventClient @Inject constructor(
    private val ownerSpaceClient: OwnerSpaceClient
) {
    /**
     * Submit an event to the vault for processing
     */
    suspend fun submitEvent(event: VaultEvent): Result<String> {
        val requestId = UUID.randomUUID().toString()
        val message = VaultEventMessage(
            request_id = requestId,
            event_type = event.type,
            payload = event.payload,
            timestamp = Instant.now().toString()
        )

        return ownerSpaceClient.sendToVault(
            message = message,
            topic = "events.${event.type}"
        ).map { requestId }
    }

    /**
     * Subscribe to event responses from vault
     */
    fun subscribeToResponses(): Flow<VaultEventResponse> {
        return ownerSpaceClient.subscribeToVaultResponses(
            topic = "responses.>",
            type = VaultEventResponse::class
        )
    }
}

data class VaultEventMessage(
    val request_id: String,
    val event_type: String,
    val payload: JsonObject,
    val timestamp: String
)

data class VaultEventResponse(
    val request_id: String,
    val status: String,  // "success", "error"
    val result: JsonObject?,
    val error: String?,
    val processed_at: String
)

sealed class VaultEvent(val type: String, val payload: JsonObject) {
    class SendMessage(recipient: String, content: String) : VaultEvent(
        "messaging.send",
        JsonObject(mapOf("recipient" to recipient, "content" to content))
    )

    class UpdateProfile(updates: Map<String, Any>) : VaultEvent(
        "profile.update",
        JsonObject(updates)
    )

    class CreateConnection(inviteCode: String) : VaultEvent(
        "connection.create",
        JsonObject(mapOf("invite_code" to inviteCode))
    )
}
```

### 3. Vault Health ViewModel

Create ViewModel for vault health monitoring:

```kotlin
// vault/VaultHealthViewModel.kt

@HiltViewModel
class VaultHealthViewModel @Inject constructor(
    private val vaultService: VaultServiceClient,
    private val natsConnectionManager: NatsConnectionManager
) : ViewModel() {

    private val _healthState = MutableStateFlow<VaultHealthState>(VaultHealthState.Loading)
    val healthState: StateFlow<VaultHealthState> = _healthState.asStateFlow()

    private var healthCheckJob: Job? = null

    init {
        startHealthMonitoring()
    }

    fun startHealthMonitoring() {
        healthCheckJob?.cancel()
        healthCheckJob = viewModelScope.launch {
            while (isActive) {
                checkHealth()
                delay(30_000) // Check every 30 seconds
            }
        }
    }

    private suspend fun checkHealth() {
        try {
            val health = vaultService.getVaultHealth()
            _healthState.value = VaultHealthState.Loaded(
                status = when (health.status) {
                    "healthy" -> HealthStatus.Healthy
                    "degraded" -> HealthStatus.Degraded
                    else -> HealthStatus.Unhealthy
                },
                uptime = Duration.ofSeconds(health.uptime_seconds),
                localNats = health.local_nats.status == "running",
                centralNats = health.central_nats.status == "connected",
                centralLatency = health.central_nats.latency_ms,
                vaultManager = health.vault_manager.status == "running",
                handlersLoaded = health.vault_manager.handlers_loaded,
                lastEventAt = health.last_event_at?.let { Instant.parse(it) }
            )
        } catch (e: Exception) {
            _healthState.value = VaultHealthState.Error(e.message ?: "Health check failed")
        }
    }

    fun provisionVault() {
        viewModelScope.launch {
            _healthState.value = VaultHealthState.Provisioning
            try {
                val provision = vaultService.provisionVault()
                // Poll for completion
                pollForProvisioning(provision.instance_id)
            } catch (e: Exception) {
                _healthState.value = VaultHealthState.Error(e.message ?: "Provisioning failed")
            }
        }
    }

    private suspend fun pollForProvisioning(instanceId: String) {
        repeat(60) { // Max 2 minutes
            delay(2000)
            try {
                val health = vaultService.getVaultHealth()
                if (health.status == "healthy") {
                    checkHealth()
                    return
                }
            } catch (e: Exception) {
                // Still provisioning
            }
        }
        _healthState.value = VaultHealthState.Error("Provisioning timeout")
    }

    override fun onCleared() {
        healthCheckJob?.cancel()
        super.onCleared()
    }
}

sealed class VaultHealthState {
    object Loading : VaultHealthState()
    object Provisioning : VaultHealthState()
    object NotProvisioned : VaultHealthState()
    data class Loaded(
        val status: HealthStatus,
        val uptime: Duration,
        val localNats: Boolean,
        val centralNats: Boolean,
        val centralLatency: Long,
        val vaultManager: Boolean,
        val handlersLoaded: Int,
        val lastEventAt: Instant?
    ) : VaultHealthState()
    data class Error(val message: String) : VaultHealthState()
}

enum class HealthStatus { Healthy, Degraded, Unhealthy }
```

### 4. Vault Health UI

Create health display components:

```kotlin
// vault/VaultHealthScreen.kt

@Composable
fun VaultHealthScreen(
    viewModel: VaultHealthViewModel = hiltViewModel()
) {
    val state by viewModel.healthState.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("Vault Health", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))

        when (val currentState = state) {
            is VaultHealthState.Loading -> LoadingIndicator()
            is VaultHealthState.Provisioning -> ProvisioningIndicator()
            is VaultHealthState.NotProvisioned -> NotProvisionedCard(
                onProvision = { viewModel.provisionVault() }
            )
            is VaultHealthState.Loaded -> VaultHealthDetails(currentState)
            is VaultHealthState.Error -> ErrorCard(
                message = currentState.message,
                onRetry = { viewModel.startHealthMonitoring() }
            )
        }
    }
}

@Composable
fun VaultHealthDetails(state: VaultHealthState.Loaded) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Status header
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusIndicator(state.status)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = state.status.name,
                    style = MaterialTheme.typography.titleLarge
                )
            }

            Divider(modifier = Modifier.padding(vertical = 12.dp))

            // Component status
            ComponentStatusRow("Local NATS", state.localNats)
            ComponentStatusRow("Central NATS", state.centralNats, "${state.centralLatency}ms")
            ComponentStatusRow("Vault Manager", state.vaultManager)

            Divider(modifier = Modifier.padding(vertical = 12.dp))

            // Stats
            Text("Handlers Loaded: ${state.handlersLoaded}")
            Text("Uptime: ${state.uptime.toHours()}h ${state.uptime.toMinutesPart()}m")
            state.lastEventAt?.let {
                Text("Last Event: ${formatRelativeTime(it)}")
            }
        }
    }
}

@Composable
fun StatusIndicator(status: HealthStatus) {
    val color = when (status) {
        HealthStatus.Healthy -> Color.Green
        HealthStatus.Degraded -> Color.Yellow
        HealthStatus.Unhealthy -> Color.Red
    }
    Box(
        modifier = Modifier
            .size(16.dp)
            .background(color, CircleShape)
    )
}
```

### 5. Event Response Handler

Handle responses from vault events:

```kotlin
// nats/VaultResponseHandler.kt

@Singleton
class VaultResponseHandler @Inject constructor(
    private val vaultEventClient: VaultEventClient
) {
    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<VaultEventResponse>>()

    init {
        // Start listening for responses
        CoroutineScope(Dispatchers.IO).launch {
            vaultEventClient.subscribeToResponses().collect { response ->
                pendingRequests.remove(response.request_id)?.complete(response)
            }
        }
    }

    suspend fun submitAndAwait(
        event: VaultEvent,
        timeout: Duration = Duration.ofSeconds(30)
    ): Result<VaultEventResponse> {
        val deferred = CompletableDeferred<VaultEventResponse>()

        return try {
            val requestId = vaultEventClient.submitEvent(event).getOrThrow()
            pendingRequests[requestId] = deferred

            withTimeout(timeout.toMillis()) {
                Result.success(deferred.await())
            }
        } catch (e: TimeoutCancellationException) {
            Result.failure(Exception("Vault response timeout"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

### 6. Unit Tests

```kotlin
class VaultEventClientTest {
    @Test fun `submitEvent sends to correct topic`()
    @Test fun `subscribeToResponses receives vault messages`()
}

class VaultHealthViewModelTest {
    @Test fun `checkHealth updates state correctly`()
    @Test fun `provisionVault polls until ready`()
    @Test fun `timeout during provisioning shows error`()
}

class VaultResponseHandlerTest {
    @Test fun `submitAndAwait matches request to response`()
    @Test fun `submitAndAwait times out after duration`()
}
```

## Deliverables

- [ ] VaultServiceClient with lifecycle endpoints
- [ ] VaultEventClient for NATS event submission
- [ ] VaultHealthViewModel for health monitoring
- [ ] VaultHealthScreen with status UI
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

- Android notes duplicate response types in Phase 2/3 code - resolve before starting
- Vault provisioning may take 1-2 minutes - show appropriate progress UI
- Consider battery impact of 30-second health polling - adjust interval as needed

## Status Update

```bash
cd /path/to/vettid-android
git pull
# Create vault communication components
git add .
git commit -m "Phase 5: Add vault communication"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 5 vault communication complete"
git push
```
