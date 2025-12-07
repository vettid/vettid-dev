# Task: Phase 4 - NATS Client Integration

## Phase
Phase 4: NATS Infrastructure

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

## Status
Phase 3 complete. Ready for Phase 4 NATS client integration.

## Overview

Implement NATS client integration for the Android app. The backend now provides:
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

## Phase 4 Android Tasks

### 1. Add NATS Client Dependency

Add the official NATS.io Java client:

```kotlin
// build.gradle.kts (app)
dependencies {
    implementation("io.nats:jnats:2.17.6")
}
```

### 2. NATS Client Module

Create NATS client components:

```
app/src/main/kotlin/dev/vettid/nats/
├── NatsClient.kt             # Main client wrapper
├── NatsCredentials.kt        # Token/credential management
├── NatsConnectionManager.kt  # Connection lifecycle
├── OwnerSpaceClient.kt       # OwnerSpace operations
└── MessageSpaceClient.kt     # MessageSpace operations
```

#### NatsCredentials.kt
```kotlin
data class NatsCredentials(
    val tokenId: String,
    val jwt: String,
    val seed: String,
    val endpoint: String,
    val expiresAt: Instant,
    val permissions: NatsPermissions
)

data class NatsPermissions(
    val publish: List<String>,
    val subscribe: List<String>
)
```

#### NatsConnectionManager.kt
```kotlin
class NatsConnectionManager @Inject constructor(
    private val apiClient: VettIdApiClient,
    private val credentialStore: NatsCredentialStore
) {
    private var connection: Connection? = null

    suspend fun connect(): Result<Connection>
    suspend fun disconnect()
    suspend fun refreshTokenIfNeeded()
    fun isConnected(): Boolean
}
```

### 3. NATS Account Setup Flow

Implement account setup after vault enrollment:

```kotlin
class NatsSetupViewModel @Inject constructor(
    private val apiClient: VettIdApiClient,
    private val connectionManager: NatsConnectionManager
) : ViewModel() {
    sealed class SetupState {
        object Initial : SetupState()
        object CreatingAccount : SetupState()
        object GeneratingToken : SetupState()
        object Connecting : SetupState()
        data class Connected(val status: NatsAccountStatus) : SetupState()
        data class Error(val message: String) : SetupState()
    }

    suspend fun setupNats() {
        // 1. Create NATS account
        // 2. Generate app token
        // 3. Connect to NATS
        // 4. Subscribe to forApp topic
    }
}
```

### 4. OwnerSpace Client

Implement OwnerSpace communication:

```kotlin
class OwnerSpaceClient @Inject constructor(
    private val connectionManager: NatsConnectionManager
) {
    // Topics
    // Publish: OwnerSpace.{guid}.forVault.>
    // Subscribe: OwnerSpace.{guid}.forApp.>

    suspend fun sendToVault(message: VaultMessage): Result<Unit>
    fun subscribeToVaultResponses(callback: (VaultResponse) -> Unit): Subscription
    suspend fun getEventTypes(): List<EventType>
}
```

### 5. Message Types

Define message structures:

```kotlin
// Messages TO vault
sealed class VaultMessage {
    data class ExecuteHandler(
        val handlerId: String,
        val payload: JsonObject
    ) : VaultMessage()

    data class StatusRequest(
        val requestId: String
    ) : VaultMessage()
}

// Messages FROM vault
sealed class VaultResponse {
    data class HandlerResult(
        val requestId: String,
        val success: Boolean,
        val result: JsonObject?
    ) : VaultResponse()

    data class StatusResponse(
        val requestId: String,
        val vaultStatus: VaultStatus
    ) : VaultResponse()
}
```

### 6. Connection UI

Create connection status UI:

```kotlin
@Composable
fun NatsConnectionStatus(
    viewModel: NatsSetupViewModel = hiltViewModel()
) {
    val state by viewModel.setupState.collectAsState()

    when (state) {
        is SetupState.Connected -> ConnectionActiveIndicator()
        is SetupState.Connecting -> ConnectionProgressIndicator()
        is SetupState.Error -> ConnectionErrorBanner(state.message)
        else -> Unit
    }
}
```

### 7. Token Refresh

Implement automatic token refresh:

```kotlin
class NatsTokenRefreshWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Check token expiration
        // Refresh if < 1 hour remaining
        // Reconnect with new token
    }

    companion object {
        fun schedule(context: Context) {
            // Schedule periodic token refresh check
            val request = PeriodicWorkRequestBuilder<NatsTokenRefreshWorker>(
                6, TimeUnit.HOURS
            ).build()
            WorkManager.getInstance(context).enqueue(request)
        }
    }
}
```

## Testing Requirements

### Unit Tests
```kotlin
class NatsCredentialsTest {
    @Test fun `should parse token response correctly`()
    @Test fun `should detect expired token`()
}

class OwnerSpaceClientTest {
    @Test fun `should format publish topic correctly`()
    @Test fun `should handle connection failure`()
}
```

### Integration Tests
```kotlin
class NatsIntegrationTest {
    @Test fun `should create account and connect`()
    @Test fun `should send message to vault topic`()
    @Test fun `should receive message from app topic`()
}
```

## Deliverables

- [ ] NatsClient wrapper class
- [ ] NatsCredentials data model
- [ ] NatsConnectionManager with lifecycle management
- [ ] OwnerSpaceClient for vault communication
- [ ] NatsSetupViewModel and UI
- [ ] Token refresh worker
- [ ] Unit tests for NATS components
- [ ] Integration tests for NATS connection

## Acceptance Criteria

- [ ] App can create NATS account via API
- [ ] App can generate and store NATS tokens
- [ ] App connects to NATS using TLS (port 4222)
- [ ] App can publish to OwnerSpace.forVault
- [ ] App can subscribe to OwnerSpace.forApp
- [ ] Token refresh works before expiration
- [ ] Connection errors are handled gracefully
- [ ] All unit tests pass

## Status Update

```bash
cd /path/to/vettid-android
git pull  # Get latest from backend if needed
# Edit app/src/main/kotlin/... (create NATS components)
git add .
git commit -m "Phase 4: Add NATS client integration"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 4 NATS client complete"
git push
```
