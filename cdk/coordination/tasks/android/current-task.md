# Task: Phase 6 - Handler Discovery & Execution

## Phase
Phase 6: Handler System (WASM)

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

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

## Phase 6 Android Tasks

### 1. Handler Registry Client

Add registry API to service client:

```kotlin
// api/HandlerRegistryClient.kt

interface HandlerRegistryClient {
    @GET("/registry/handlers")
    suspend fun listHandlers(
        @Query("category") category: String? = null,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20
    ): HandlerListResponse

    @GET("/registry/handlers/{id}")
    suspend fun getHandler(@Path("id") handlerId: String): HandlerDetailResponse
}

data class HandlerListResponse(
    val handlers: List<HandlerSummary>,
    val total: Int,
    val page: Int,
    val has_more: Boolean
)

data class HandlerSummary(
    val id: String,
    val name: String,
    val description: String,
    val version: String,
    val category: String,
    val icon_url: String?,
    val publisher: String,
    val installed: Boolean,
    val installed_version: String?
)

data class HandlerDetailResponse(
    val id: String,
    val name: String,
    val description: String,
    val version: String,
    val category: String,
    val icon_url: String?,
    val publisher: String,
    val published_at: String,
    val size_bytes: Long,
    val permissions: List<HandlerPermission>,
    val input_schema: JsonObject,
    val output_schema: JsonObject,
    val changelog: String?,
    val installed: Boolean,
    val installed_version: String?
)

data class HandlerPermission(
    val type: String,  // "network", "storage", "crypto"
    val scope: String, // e.g., "api.example.com" for network
    val description: String
)
```

### 2. Handler Installation Client

Add vault handler management endpoints:

```kotlin
// api/VaultHandlerClient.kt

interface VaultHandlerClient {
    @POST("/vault/handlers/install")
    suspend fun installHandler(
        @Body request: InstallHandlerRequest
    ): InstallHandlerResponse

    @POST("/vault/handlers/uninstall")
    suspend fun uninstallHandler(
        @Body request: UninstallHandlerRequest
    ): UninstallHandlerResponse

    @GET("/vault/handlers")
    suspend fun listInstalledHandlers(): InstalledHandlersResponse

    @POST("/vault/handlers/{id}/execute")
    suspend fun executeHandler(
        @Path("id") handlerId: String,
        @Body request: ExecuteHandlerRequest
    ): ExecuteHandlerResponse
}

data class InstallHandlerRequest(
    val handler_id: String,
    val version: String
)

data class InstallHandlerResponse(
    val status: String,  // "installed", "failed"
    val handler_id: String,
    val version: String,
    val installed_at: String?
)

data class ExecuteHandlerRequest(
    val input: JsonObject,
    val timeout_ms: Long = 30000
)

data class ExecuteHandlerResponse(
    val request_id: String,
    val status: String,  // "success", "error", "timeout"
    val output: JsonObject?,
    val error: String?,
    val execution_time_ms: Long
)
```

### 3. Handler Discovery ViewModel

Create ViewModel for browsing handlers:

```kotlin
// handlers/HandlerDiscoveryViewModel.kt

@HiltViewModel
class HandlerDiscoveryViewModel @Inject constructor(
    private val registryClient: HandlerRegistryClient,
    private val vaultHandlerClient: VaultHandlerClient
) : ViewModel() {

    private val _state = MutableStateFlow<HandlerDiscoveryState>(HandlerDiscoveryState.Loading)
    val state: StateFlow<HandlerDiscoveryState> = _state.asStateFlow()

    private val _selectedCategory = MutableStateFlow<String?>(null)
    val selectedCategory: StateFlow<String?> = _selectedCategory.asStateFlow()

    init {
        loadHandlers()
    }

    fun loadHandlers(category: String? = null) {
        viewModelScope.launch {
            _state.value = HandlerDiscoveryState.Loading
            try {
                val response = registryClient.listHandlers(category = category)
                _state.value = HandlerDiscoveryState.Loaded(
                    handlers = response.handlers,
                    hasMore = response.has_more
                )
            } catch (e: Exception) {
                _state.value = HandlerDiscoveryState.Error(e.message ?: "Failed to load handlers")
            }
        }
    }

    fun selectCategory(category: String?) {
        _selectedCategory.value = category
        loadHandlers(category)
    }

    fun installHandler(handlerId: String, version: String) {
        viewModelScope.launch {
            try {
                val result = vaultHandlerClient.installHandler(
                    InstallHandlerRequest(handlerId, version)
                )
                if (result.status == "installed") {
                    loadHandlers(_selectedCategory.value)
                }
            } catch (e: Exception) {
                // Handle error
            }
        }
    }

    fun uninstallHandler(handlerId: String) {
        viewModelScope.launch {
            try {
                vaultHandlerClient.uninstallHandler(
                    UninstallHandlerRequest(handlerId)
                )
                loadHandlers(_selectedCategory.value)
            } catch (e: Exception) {
                // Handle error
            }
        }
    }
}

sealed class HandlerDiscoveryState {
    object Loading : HandlerDiscoveryState()
    data class Loaded(
        val handlers: List<HandlerSummary>,
        val hasMore: Boolean
    ) : HandlerDiscoveryState()
    data class Error(val message: String) : HandlerDiscoveryState()
}
```

### 4. Handler Discovery UI

Create handler browsing screens:

```kotlin
// handlers/HandlerDiscoveryScreen.kt

@Composable
fun HandlerDiscoveryScreen(
    viewModel: HandlerDiscoveryViewModel = hiltViewModel(),
    onHandlerSelected: (String) -> Unit
) {
    val state by viewModel.state.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()

    Column(modifier = Modifier.fillMaxSize()) {
        // Category tabs
        CategoryTabs(
            selectedCategory = selectedCategory,
            onCategorySelected = { viewModel.selectCategory(it) }
        )

        when (val currentState = state) {
            is HandlerDiscoveryState.Loading -> LoadingIndicator()
            is HandlerDiscoveryState.Loaded -> HandlerList(
                handlers = currentState.handlers,
                onHandlerClick = onHandlerSelected,
                onInstall = { viewModel.installHandler(it.id, it.version) },
                onUninstall = { viewModel.uninstallHandler(it.id) }
            )
            is HandlerDiscoveryState.Error -> ErrorCard(
                message = currentState.message,
                onRetry = { viewModel.loadHandlers() }
            )
        }
    }
}

@Composable
fun CategoryTabs(
    selectedCategory: String?,
    onCategorySelected: (String?) -> Unit
) {
    val categories = listOf(
        null to "All",
        "messaging" to "Messaging",
        "social" to "Social",
        "productivity" to "Productivity",
        "utilities" to "Utilities"
    )

    ScrollableTabRow(
        selectedTabIndex = categories.indexOfFirst { it.first == selectedCategory }
    ) {
        categories.forEach { (category, label) ->
            Tab(
                selected = selectedCategory == category,
                onClick = { onCategorySelected(category) },
                text = { Text(label) }
            )
        }
    }
}

@Composable
fun HandlerList(
    handlers: List<HandlerSummary>,
    onHandlerClick: (String) -> Unit,
    onInstall: (HandlerSummary) -> Unit,
    onUninstall: (HandlerSummary) -> Unit
) {
    LazyColumn {
        items(handlers) { handler ->
            HandlerListItem(
                handler = handler,
                onClick = { onHandlerClick(handler.id) },
                onInstall = { onInstall(handler) },
                onUninstall = { onUninstall(handler) }
            )
        }
    }
}

@Composable
fun HandlerListItem(
    handler: HandlerSummary,
    onClick: () -> Unit,
    onInstall: () -> Unit,
    onUninstall: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Handler icon
            AsyncImage(
                model = handler.icon_url,
                contentDescription = handler.name,
                modifier = Modifier.size(48.dp)
            )

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(handler.name, style = MaterialTheme.typography.titleMedium)
                Text(handler.description, style = MaterialTheme.typography.bodySmall)
                Text("v${handler.version} by ${handler.publisher}",
                    style = MaterialTheme.typography.labelSmall)
            }

            // Install/Uninstall button
            if (handler.installed) {
                OutlinedButton(onClick = onUninstall) {
                    Text("Uninstall")
                }
            } else {
                Button(onClick = onInstall) {
                    Text("Install")
                }
            }
        }
    }
}
```

### 5. Handler Detail Screen

Create handler detail view:

```kotlin
// handlers/HandlerDetailScreen.kt

@Composable
fun HandlerDetailScreen(
    handlerId: String,
    viewModel: HandlerDetailViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    LaunchedEffect(handlerId) {
        viewModel.loadHandler(handlerId)
    }

    when (val currentState = state) {
        is HandlerDetailState.Loading -> LoadingIndicator()
        is HandlerDetailState.Loaded -> HandlerDetailContent(
            handler = currentState.handler,
            onInstall = { viewModel.installHandler() },
            onUninstall = { viewModel.uninstallHandler() },
            onExecute = { input -> viewModel.executeHandler(input) }
        )
        is HandlerDetailState.Error -> ErrorCard(currentState.message)
    }
}

@Composable
fun HandlerDetailContent(
    handler: HandlerDetailResponse,
    onInstall: () -> Unit,
    onUninstall: () -> Unit,
    onExecute: (JsonObject) -> Unit
) {
    LazyColumn(modifier = Modifier.padding(16.dp)) {
        item {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                AsyncImage(
                    model = handler.icon_url,
                    contentDescription = handler.name,
                    modifier = Modifier.size(64.dp)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column {
                    Text(handler.name, style = MaterialTheme.typography.headlineMedium)
                    Text("v${handler.version} by ${handler.publisher}")
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))
            Text(handler.description, style = MaterialTheme.typography.bodyLarge)
        }

        // Permissions section
        item {
            Spacer(modifier = Modifier.height(24.dp))
            Text("Permissions", style = MaterialTheme.typography.titleMedium)
            handler.permissions.forEach { permission ->
                PermissionItem(permission)
            }
        }

        // Install/Execute buttons
        item {
            Spacer(modifier = Modifier.height(24.dp))
            if (handler.installed) {
                Row {
                    Button(
                        onClick = { onExecute(JsonObject(emptyMap())) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Execute")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    OutlinedButton(onClick = onUninstall) {
                        Text("Uninstall")
                    }
                }
            } else {
                Button(
                    onClick = onInstall,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Install")
                }
            }
        }

        // Changelog
        handler.changelog?.let { changelog ->
            item {
                Spacer(modifier = Modifier.height(24.dp))
                Text("Changelog", style = MaterialTheme.typography.titleMedium)
                Text(changelog, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
```

### 6. Handler Execution UI

Create input form and result display:

```kotlin
// handlers/HandlerExecutionScreen.kt

@Composable
fun HandlerExecutionScreen(
    handlerId: String,
    inputSchema: JsonObject,
    viewModel: HandlerExecutionViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    var inputValues by remember { mutableStateOf(mutableMapOf<String, Any>()) }

    Column(modifier = Modifier.padding(16.dp)) {
        Text("Execute Handler", style = MaterialTheme.typography.headlineMedium)

        Spacer(modifier = Modifier.height(16.dp))

        // Dynamic input form based on schema
        DynamicInputForm(
            schema = inputSchema,
            values = inputValues,
            onValueChange = { key, value ->
                inputValues = inputValues.toMutableMap().apply { put(key, value) }
            }
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { viewModel.execute(handlerId, JsonObject(inputValues)) },
            enabled = state !is HandlerExecutionState.Executing,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (state is HandlerExecutionState.Executing) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            } else {
                Text("Execute")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Result display
        when (val currentState = state) {
            is HandlerExecutionState.Success -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Success", color = Color.Green)
                        Text("Execution time: ${currentState.executionTimeMs}ms")
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Output:", style = MaterialTheme.typography.labelMedium)
                        Text(currentState.output.toString())
                    }
                }
            }
            is HandlerExecutionState.Error -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Error", color = Color.Red)
                        Text(currentState.message)
                    }
                }
            }
            else -> {}
        }
    }
}
```

### 7. Unit Tests

```kotlin
class HandlerDiscoveryViewModelTest {
    @Test fun `loadHandlers updates state with handler list`()
    @Test fun `selectCategory filters handlers`()
    @Test fun `installHandler calls API and refreshes list`()
    @Test fun `uninstallHandler calls API and refreshes list`()
}

class HandlerDetailViewModelTest {
    @Test fun `loadHandler fetches handler details`()
    @Test fun `executeHandler sends input and receives output`()
    @Test fun `executeHandler handles timeout`()
}

class HandlerExecutionViewModelTest {
    @Test fun `execute sends request and updates state`()
    @Test fun `execute handles error response`()
    @Test fun `execute shows loading state during execution`()
}
```

## Deliverables

- [ ] HandlerRegistryClient for registry API
- [ ] VaultHandlerClient for vault handler management
- [ ] HandlerDiscoveryViewModel and UI
- [ ] HandlerDetailScreen with permissions display
- [ ] HandlerExecutionScreen with dynamic input form
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

- Handler icons may be null - show placeholder
- Input schema drives dynamic form generation
- Consider caching handler list for offline browsing
- Permissions should be clearly explained to user

## Status Update

```bash
cd /path/to/vettid-android
git pull
# Create handler UI components
git add .
git commit -m "Phase 6: Add handler discovery and execution UI"
git push

# Update status in backend repo
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 6 handler UI complete"
git push
```
