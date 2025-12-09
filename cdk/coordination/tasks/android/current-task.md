# Phase 12: Connections & Profile UI

## Overview
Implement the connections and profile management features using the new Phase 7 backend APIs.

## Priority Task 1: Connection Invitations

### 1. Create Connection Models
```kotlin
// data/model/Connection.kt
@Serializable
data class Connection(
    @SerialName("connection_id") val connectionId: String,
    @SerialName("peer_guid") val peerGuid: String,
    @SerialName("peer_display_name") val peerDisplayName: String,
    @SerialName("peer_profile") val peerProfile: PeerProfile? = null,
    val status: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_message_at") val lastMessageAt: String? = null,
    @SerialName("unread_count") val unreadCount: Int = 0
)

@Serializable
data class PeerProfile(
    @SerialName("avatar_url") val avatarUrl: String? = null,
    val bio: String? = null
)

@Serializable
data class ConnectionInvitation(
    @SerialName("invitation_id") val invitationId: String,
    @SerialName("invite_code") val inviteCode: String,
    @SerialName("public_key") val publicKey: String,
    @SerialName("display_name") val displayName: String,
    @SerialName("profile_snippet") val profileSnippet: PeerProfile? = null,
    @SerialName("expires_at") val expiresAt: String,
    @SerialName("max_uses") val maxUses: Int,
    @SerialName("share_url") val shareUrl: String,
    @SerialName("qr_payload") val qrPayload: String
)

@Serializable
data class CreateInvitationRequest(
    @SerialName("display_name") val displayName: String? = null,
    val message: String? = null,
    @SerialName("expires_in_hours") val expiresInHours: Int? = null,
    @SerialName("max_uses") val maxUses: Int? = null,
    @SerialName("include_profile") val includeProfile: Boolean? = null
)

@Serializable
data class AcceptInvitationRequest(
    @SerialName("invite_code") val inviteCode: String,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("include_profile") val includeProfile: Boolean? = null
)

@Serializable
data class AcceptInvitationResponse(
    @SerialName("connection_id") val connectionId: String,
    @SerialName("peer_guid") val peerGuid: String,
    @SerialName("peer_display_name") val peerDisplayName: String,
    @SerialName("peer_profile") val peerProfile: PeerProfile? = null,
    val status: String,
    @SerialName("created_at") val createdAt: String
)
```

### 2. Create Connections API Service
```kotlin
// data/remote/ConnectionsApiService.kt
interface ConnectionsApiService {
    @POST("member/connections/invitations")
    suspend fun createInvitation(
        @Body request: CreateInvitationRequest = CreateInvitationRequest()
    ): ConnectionInvitation

    @POST("member/connections/accept")
    suspend fun acceptInvitation(
        @Body request: AcceptInvitationRequest
    ): AcceptInvitationResponse

    @GET("member/connections")
    suspend fun listConnections(
        @Query("status") status: String? = "active",
        @Query("limit") limit: Int? = 50,
        @Query("cursor") cursor: String? = null
    ): ConnectionsListResponse

    @GET("member/connections/{connectionId}")
    suspend fun getConnection(
        @Path("connectionId") connectionId: String
    ): Connection

    @POST("member/connections/{connectionId}/revoke")
    suspend fun revokeConnection(
        @Path("connectionId") connectionId: String
    ): RevokeResponse

    @GET("member/connections/{connectionId}/profile")
    suspend fun getConnectionProfile(
        @Path("connectionId") connectionId: String
    ): PeerProfile
}

@Serializable
data class ConnectionsListResponse(
    val connections: List<Connection>,
    @SerialName("next_cursor") val nextCursor: String? = null,
    @SerialName("has_more") val hasMore: Boolean = false
)

@Serializable
data class RevokeResponse(
    @SerialName("connection_id") val connectionId: String,
    val status: String,
    @SerialName("revoked_at") val revokedAt: String
)
```

### 3. Create Connections Repository
```kotlin
// data/repository/ConnectionsRepository.kt
class ConnectionsRepository @Inject constructor(
    private val api: ConnectionsApiService
) {
    suspend fun createInvitation(
        displayName: String? = null,
        message: String? = null,
        expiresInHours: Int = 168,
        maxUses: Int = 1
    ): Result<ConnectionInvitation> = runCatching {
        api.createInvitation(
            CreateInvitationRequest(
                displayName = displayName,
                message = message,
                expiresInHours = expiresInHours,
                maxUses = maxUses,
                includeProfile = true
            )
        )
    }

    suspend fun acceptInvitation(
        inviteCode: String,
        displayName: String? = null
    ): Result<AcceptInvitationResponse> = runCatching {
        api.acceptInvitation(
            AcceptInvitationRequest(
                inviteCode = inviteCode,
                displayName = displayName,
                includeProfile = true
            )
        )
    }

    suspend fun getConnections(
        status: String = "active",
        cursor: String? = null
    ): Result<ConnectionsListResponse> = runCatching {
        api.listConnections(status = status, cursor = cursor)
    }

    suspend fun revokeConnection(connectionId: String): Result<RevokeResponse> = runCatching {
        api.revokeConnection(connectionId)
    }
}
```

### 4. Create QR Code Generator
```kotlin
// util/QrCodeGenerator.kt
import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

object QrCodeGenerator {
    fun generateQrCode(content: String, size: Int = 512): Bitmap {
        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)

        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
        return bitmap
    }
}
```

Add ZXing dependency:
```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.google.zxing:core:3.5.2")
}
```

### 5. Create QR Code Scanner
```kotlin
// ui/scanner/QrScannerScreen.kt
@Composable
fun QrScannerScreen(
    onCodeScanned: (String) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    if (hasCameraPermission) {
        AndroidView(
            factory = { ctx ->
                PreviewView(ctx).apply {
                    implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                }
            },
            modifier = Modifier.fillMaxSize()
        ) { previewView ->
            val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
            cameraProviderFuture.addListener({
                val cameraProvider = cameraProviderFuture.get()

                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(previewView.surfaceProvider)
                }

                val imageAnalyzer = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also {
                        it.setAnalyzer(Executors.newSingleThreadExecutor()) { imageProxy ->
                            // Use ML Kit or ZXing to scan QR code
                            scanQrCode(imageProxy) { code ->
                                onCodeScanned(code)
                            }
                            imageProxy.close()
                        }
                    }

                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalyzer
                )
            }, ContextCompat.getMainExecutor(context))
        }
    }
}
```

Add CameraX dependencies:
```kotlin
// app/build.gradle.kts
dependencies {
    implementation("androidx.camera:camera-camera2:1.3.1")
    implementation("androidx.camera:camera-lifecycle:1.3.1")
    implementation("androidx.camera:camera-view:1.3.1")
    implementation("com.google.mlkit:barcode-scanning:17.2.0")
}
```

### 6. Create Connections ViewModel
```kotlin
// viewmodel/ConnectionsViewModel.kt
@HiltViewModel
class ConnectionsViewModel @Inject constructor(
    private val repository: ConnectionsRepository
) : ViewModel() {

    private val _connections = MutableStateFlow<List<Connection>>(emptyList())
    val connections: StateFlow<List<Connection>> = _connections

    private val _invitation = MutableStateFlow<ConnectionInvitation?>(null)
    val invitation: StateFlow<ConnectionInvitation?> = _invitation

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error

    init {
        loadConnections()
    }

    fun loadConnections() {
        viewModelScope.launch {
            _isLoading.value = true
            repository.getConnections()
                .onSuccess { response ->
                    _connections.value = response.connections
                }
                .onFailure { e ->
                    _error.value = e.message
                }
            _isLoading.value = false
        }
    }

    fun createInvitation() {
        viewModelScope.launch {
            _isLoading.value = true
            repository.createInvitation()
                .onSuccess { inv ->
                    _invitation.value = inv
                }
                .onFailure { e ->
                    _error.value = e.message
                }
            _isLoading.value = false
        }
    }

    fun acceptInvitation(inviteCode: String) {
        viewModelScope.launch {
            _isLoading.value = true
            repository.acceptInvitation(inviteCode)
                .onSuccess { response ->
                    loadConnections() // Refresh list
                }
                .onFailure { e ->
                    _error.value = e.message
                }
            _isLoading.value = false
        }
    }

    fun revokeConnection(connectionId: String) {
        viewModelScope.launch {
            repository.revokeConnection(connectionId)
                .onSuccess {
                    loadConnections() // Refresh list
                }
                .onFailure { e ->
                    _error.value = e.message
                }
        }
    }

    fun clearInvitation() {
        _invitation.value = null
    }

    fun clearError() {
        _error.value = null
    }
}
```

### 7. Create Connections UI
```kotlin
// ui/connections/ConnectionsScreen.kt
@Composable
fun ConnectionsScreen(
    viewModel: ConnectionsViewModel = hiltViewModel(),
    onNavigateToScanner: () -> Unit,
    onNavigateToConnection: (String) -> Unit
) {
    val connections by viewModel.connections.collectAsState()
    val invitation by viewModel.invitation.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()

    var showInviteDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Connections") },
                actions = {
                    IconButton(onClick = onNavigateToScanner) {
                        Icon(Icons.Default.QrCodeScanner, "Scan QR")
                    }
                    IconButton(onClick = {
                        viewModel.createInvitation()
                        showInviteDialog = true
                    }) {
                        Icon(Icons.Default.PersonAdd, "Create Invite")
                    }
                }
            )
        }
    ) { padding ->
        if (isLoading && connections.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else {
            LazyColumn(
                modifier = Modifier.padding(padding),
                contentPadding = PaddingValues(16.dp)
            ) {
                items(connections) { connection ->
                    ConnectionItem(
                        connection = connection,
                        onClick = { onNavigateToConnection(connection.connectionId) }
                    )
                }
            }
        }
    }

    // Show invitation dialog with QR code
    if (showInviteDialog && invitation != null) {
        InvitationDialog(
            invitation = invitation!!,
            onDismiss = {
                showInviteDialog = false
                viewModel.clearInvitation()
            }
        )
    }
}

@Composable
fun ConnectionItem(
    connection: Connection,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Avatar placeholder
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(MaterialTheme.colorScheme.primary, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = connection.peerDisplayName.take(1).uppercase(),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }

            Spacer(Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = connection.peerDisplayName,
                    style = MaterialTheme.typography.titleMedium
                )
                connection.peerProfile?.bio?.let { bio ->
                    Text(
                        text = bio,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            if (connection.unreadCount > 0) {
                Badge { Text(connection.unreadCount.toString()) }
            }
        }
    }
}

@Composable
fun InvitationDialog(
    invitation: ConnectionInvitation,
    onDismiss: () -> Unit
) {
    val qrBitmap = remember(invitation.qrPayload) {
        QrCodeGenerator.generateQrCode(invitation.qrPayload)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Connection Invite") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = "QR Code",
                    modifier = Modifier.size(200.dp)
                )
                Spacer(Modifier.height(16.dp))
                Text("Code: ${invitation.inviteCode}")
                Text(
                    "Expires: ${invitation.expiresAt}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        },
        confirmButton = {
            Row {
                TextButton(onClick = {
                    // Share invite
                }) {
                    Text("Share")
                }
                TextButton(onClick = onDismiss) {
                    Text("Close")
                }
            }
        }
    )
}
```

---

## Priority Task 2: Profile Management

### 1. Create Profile Models
```kotlin
// data/model/Profile.kt
@Serializable
data class Profile(
    val guid: String,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("avatar_url") val avatarUrl: String? = null,
    val bio: String? = null,
    val location: String? = null,
    @SerialName("last_updated") val lastUpdated: String? = null,
    val version: Int = 0
)

@Serializable
data class UpdateProfileRequest(
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("avatar_url") val avatarUrl: String? = null,
    val bio: String? = null,
    val location: String? = null
)
```

### 2. Create Profile API Service
```kotlin
// data/remote/ProfileApiService.kt
interface ProfileApiService {
    @GET("member/profile")
    suspend fun getProfile(): Profile

    @PUT("member/profile")
    suspend fun updateProfile(
        @Body request: UpdateProfileRequest
    ): Profile

    @POST("member/profile/publish")
    suspend fun publishProfile(): PublishResponse
}

@Serializable
data class PublishResponse(
    val published: Boolean,
    @SerialName("connections_notified") val connectionsNotified: Int
)
```

### 3. Create Profile ViewModel
```kotlin
// viewmodel/ProfileViewModel.kt
@HiltViewModel
class ProfileViewModel @Inject constructor(
    private val api: ProfileApiService
) : ViewModel() {

    private val _profile = MutableStateFlow<Profile?>(null)
    val profile: StateFlow<Profile?> = _profile

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _isSaving = MutableStateFlow(false)
    val isSaving: StateFlow<Boolean> = _isSaving

    init {
        loadProfile()
    }

    fun loadProfile() {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _profile.value = api.getProfile()
            } catch (e: Exception) {
                Log.e("Profile", "Failed to load: ${e.message}")
            }
            _isLoading.value = false
        }
    }

    fun updateProfile(
        displayName: String? = null,
        bio: String? = null,
        location: String? = null
    ) {
        viewModelScope.launch {
            _isSaving.value = true
            try {
                _profile.value = api.updateProfile(
                    UpdateProfileRequest(
                        displayName = displayName,
                        bio = bio,
                        location = location
                    )
                )
                // Publish to connections
                api.publishProfile()
            } catch (e: Exception) {
                Log.e("Profile", "Failed to update: ${e.message}")
            }
            _isSaving.value = false
        }
    }
}
```

---

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/member/connections/invitations` | Create connection invitation |
| POST | `/member/connections/accept` | Accept invitation |
| GET | `/member/connections` | List connections |
| GET | `/member/connections/{id}` | Get connection details |
| POST | `/member/connections/{id}/revoke` | Revoke connection |
| GET | `/member/connections/{id}/profile` | Get peer's profile |
| GET | `/member/profile` | Get own profile |
| PUT | `/member/profile` | Update profile |
| POST | `/member/profile/publish` | Publish to connections |

---

## Deliverables
- [ ] Connection models created
- [ ] ConnectionsApiService implemented
- [ ] ConnectionsRepository implemented
- [ ] QR code generation working
- [ ] QR code scanning working
- [ ] ConnectionsViewModel implemented
- [ ] Connections list UI
- [ ] Create invitation dialog with QR
- [ ] Accept invitation flow
- [ ] Profile models created
- [ ] ProfileApiService implemented
- [ ] Profile edit screen
- [ ] Unit tests for connections logic

## Notes
- X25519 key exchange happens server-side - app just sends/receives codes
- QR payload contains the full invitation data for offline scanning
- Invite codes are 6 characters, case-insensitive (e.g., "ABC123")
- Connection invitations expire (default 7 days, max 30 days)
- Always include profile when accepting for better UX
