# Phase 11: NATS Integration

## Overview
Integrate NATS messaging for real-time communication with the member's vault instance.

## Priority Task: NATS Connection & Messaging

### 1. Add NATS Dependency
Add the NATS.java client library:
```kotlin
// app/build.gradle.kts
dependencies {
    implementation("io.nats:jnats:2.17.2")
}
```

### 2. Create NATS Credential Models
```kotlin
// data/model/NatsCredentials.kt
@Serializable
data class NatsCredentials(
    val jwt: String,
    val seed: String,
    @SerialName("public_key") val publicKey: String,
    @SerialName("nats_creds") val natsCreds: String,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("nats_url") val natsUrl: String,
    @SerialName("owner_space") val ownerSpace: String,
    @SerialName("message_space") val messageSpace: String
)

@Serializable
data class NatsAccountInfo(
    @SerialName("account_public_key") val accountPublicKey: String,
    @SerialName("owner_space") val ownerSpace: String,
    @SerialName("message_space") val messageSpace: String,
    @SerialName("created_at") val createdAt: String
)
```

### 3. Create NATS API Service
```kotlin
// data/remote/NatsApiService.kt
interface NatsApiService {
    @POST("nats/account")
    suspend fun createAccount(): NatsAccountInfo

    @POST("nats/credentials")
    suspend fun getCredentials(
        @Body body: Map<String, String> = mapOf("client_type" to "app")
    ): NatsCredentials
}
```

### 4. Create NATS Connection Manager
```kotlin
// data/nats/NatsConnectionManager.kt
class NatsConnectionManager @Inject constructor(
    private val natsApi: NatsApiService
) {
    private var connection: Connection? = null
    private var credentials: NatsCredentials? = null
    private var dispatcher: Dispatcher? = null

    suspend fun ensureConnected(): Connection {
        val creds = credentials
        if (creds != null && !isExpiringSoon(creds)) {
            connection?.let { if (it.status == Connection.Status.CONNECTED) return it }
        }

        // Refresh credentials
        credentials = natsApi.getCredentials()
        return connect(credentials!!)
    }

    private fun connect(creds: NatsCredentials): Connection {
        val options = Options.Builder()
            .server(creds.natsUrl)
            .authHandler(Nats.credentials(creds.jwt, creds.seed))
            .connectionTimeout(Duration.ofSeconds(10))
            .reconnectWait(Duration.ofSeconds(2))
            .maxReconnects(-1)
            .errorListener { conn, error, _ ->
                Log.e("NATS", "Error: ${error.message}")
            }
            .connectionListener { conn, event ->
                Log.d("NATS", "Event: $event")
            }
            .build()

        connection = Nats.connect(options)
        return connection!!
    }

    private fun isExpiringSoon(creds: NatsCredentials): Boolean {
        val expiresAt = Instant.parse(creds.expiresAt)
        val fiveMinutesFromNow = Instant.now().plusSeconds(300)
        return expiresAt.isBefore(fiveMinutesFromNow)
    }

    fun disconnect() {
        dispatcher?.unsubscribe()
        connection?.close()
        connection = null
        credentials = null
    }
}
```

### 5. Create Vault Event Repository
```kotlin
// data/repository/VaultEventRepository.kt
class VaultEventRepository @Inject constructor(
    private val natsManager: NatsConnectionManager
) {
    private val _events = MutableSharedFlow<VaultResponse>(replay = 0)
    val events: SharedFlow<VaultResponse> = _events

    suspend fun subscribeToResponses() {
        val conn = natsManager.ensureConnected()
        val creds = natsManager.credentials!!

        val dispatcher = conn.createDispatcher { msg ->
            try {
                val response = Json.decodeFromString<VaultResponse>(
                    msg.data.decodeToString()
                )
                runBlocking { _events.emit(response) }
            } catch (e: Exception) {
                Log.e("NATS", "Failed to parse response: ${e.message}")
            }
        }
        dispatcher.subscribe("${creds.ownerSpace}.forApp.>")
    }

    suspend fun sendEvent(type: String, payload: ByteArray) {
        val conn = natsManager.ensureConnected()
        val creds = natsManager.credentials!!

        val event = VaultEvent(
            eventId = UUID.randomUUID().toString(),
            type = type,
            timestamp = Instant.now().toString(),
            payload = Base64.encodeToString(payload, Base64.NO_WRAP)
        )

        conn.publish(
            "${creds.ownerSpace}.forVault.$type",
            Json.encodeToString(event).toByteArray()
        )
    }
}

@Serializable
data class VaultEvent(
    @SerialName("event_id") val eventId: String,
    val type: String,
    val timestamp: String,
    val payload: String
)

@Serializable
data class VaultResponse(
    @SerialName("response_id") val responseId: String,
    @SerialName("event_id") val eventId: String,
    val timestamp: String,
    val status: String,
    val payload: String? = null,
    val error: String? = null
)
```

### 6. Create Account Setup Flow
After enrollment completes, call the account setup:
```kotlin
// In EnrollmentViewModel or similar
suspend fun setupNatsAccount() {
    try {
        val accountInfo = natsApi.createAccount()
        // Store account info locally
        prefsManager.setOwnerSpace(accountInfo.ownerSpace)
        prefsManager.setMessageSpace(accountInfo.messageSpace)
    } catch (e: Exception) {
        Log.e("Enrollment", "Failed to create NATS account: ${e.message}")
        throw e
    }
}
```

### 7. Usage in ViewModel
```kotlin
// viewmodel/VaultViewModel.kt
@HiltViewModel
class VaultViewModel @Inject constructor(
    private val vaultRepo: VaultEventRepository
) : ViewModel() {

    private val _responses = MutableStateFlow<List<VaultResponse>>(emptyList())
    val responses: StateFlow<List<VaultResponse>> = _responses

    init {
        viewModelScope.launch {
            vaultRepo.events.collect { response ->
                _responses.update { it + response }
            }
        }
    }

    fun connect() {
        viewModelScope.launch {
            try {
                vaultRepo.subscribeToResponses()
            } catch (e: Exception) {
                Log.e("Vault", "Connection failed: ${e.message}")
            }
        }
    }

    fun sendTestEvent() {
        viewModelScope.launch {
            vaultRepo.sendEvent(
                type = "test.ping",
                payload = "{}".toByteArray()
            )
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
- Mock NatsApiService responses
- Test credential expiration logic
- Test event serialization

### Integration Tests
- Test actual NATS connection (requires deployed infrastructure)
- Test publish/subscribe flow
- Test reconnection behavior

## Deliverables
- [ ] NATS client library integrated
- [ ] Credential models created
- [ ] NatsConnectionManager implemented
- [ ] VaultEventRepository implemented
- [ ] Account setup flow integrated with enrollment
- [ ] Basic vault communication working
- [ ] Unit tests for NATS logic

## Notes
- NATS credentials expire after 24 hours - implement automatic refresh
- Always check connection status before publishing
- Handle `AUTHORIZATION_VIOLATION` errors by refreshing credentials
- TLS is required for all NATS connections
