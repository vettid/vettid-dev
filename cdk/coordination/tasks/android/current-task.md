# Task: Phase 1 - Enrollment Flow Implementation

## Phase
Phase 1: Protean Credential System - Core

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

## Status
Phase 0 complete. Migration to dedicated repo complete. Ready for Phase 1.

## Phase 1 Android Tasks

### 1. Enrollment Flow UI

Implement the complete enrollment flow screens:

```kotlin
// app/src/main/kotlin/dev/vettid/features/enrollment/
EnrollmentScreen.kt          // Main enrollment container
QRScannerScreen.kt           // Scan invitation QR code
AttestationScreen.kt         // Hardware attestation progress
PasswordSetupScreen.kt       // Password creation with strength meter
EnrollmentCompleteScreen.kt  // Success confirmation
```

**Flow:**
1. User scans QR code containing invitation code
2. App requests attestation challenge from backend
3. App performs hardware attestation
4. User creates password (min 12 chars, strength indicator)
5. App encrypts password with transaction key
6. Backend returns credential blob and LAT
7. App stores credential blob encrypted in EncryptedSharedPreferences

### 2. Implement VaultServiceClient

Create API client matching `vault-services-api.yaml`:

```kotlin
// app/src/main/kotlin/dev/vettid/core/network/
VaultServiceClient.kt

interface VaultService {
    @POST("/vault/enroll/start")
    suspend fun enrollStart(body: EnrollStartRequest): EnrollStartResponse

    @POST("/vault/enroll/attestation")
    suspend fun submitAttestation(body: AttestationRequest): AttestationResponse

    @POST("/vault/enroll/set-password")
    suspend fun setPassword(body: SetPasswordRequest): SetPasswordResponse

    @POST("/vault/enroll/finalize")
    suspend fun finalize(body: FinalizeRequest): FinalizeResponse

    @POST("/vault/auth/action-request")
    suspend fun actionRequest(body: ActionRequest): ActionResponse

    @POST("/vault/auth/execute")
    suspend fun authExecute(body: AuthExecuteRequest): AuthExecuteResponse
}
```

### 3. Enrollment State Management

```kotlin
// app/src/main/kotlin/dev/vettid/features/enrollment/
EnrollmentViewModel.kt
EnrollmentState.kt

sealed class EnrollmentState {
    object Initial : EnrollmentState()
    data class ScanningQR(val error: String? = null) : EnrollmentState()
    data class Attesting(val progress: Float) : EnrollmentState()
    data class SettingPassword(val strength: PasswordStrength) : EnrollmentState()
    data class Finalizing(val progress: Float) : EnrollmentState()
    data class Complete(val userGuid: String) : EnrollmentState()
    data class Error(val message: String, val retryable: Boolean) : EnrollmentState()
}
```

### 4. Transaction Key Encryption

Implement client-side encryption using transaction keys:

```kotlin
// In CryptoManager.kt, add:
fun encryptWithTransactionKey(
    plaintext: ByteArray,
    transactionKeyPublicKey: ByteArray
): EncryptedPayload

data class EncryptedPayload(
    val ciphertext: ByteArray,
    val ephemeralPublicKey: ByteArray,
    val nonce: ByteArray
)
```

### 5. Unit Tests

Add tests for new functionality:

```kotlin
// app/src/test/kotlin/dev/vettid/
EnrollmentViewModelTest.kt    // State transitions
VaultServiceClientTest.kt     // API contract tests
TransactionKeyEncryptionTest.kt  // Crypto operations
```

## Key References (in vettid-dev)

Pull latest from vettid-dev and reference:
- `cdk/coordination/specs/vault-services-api.yaml` - API endpoints
- `cdk/coordination/specs/credential-format.md` - Credential blob format
- `cdk/coordination/specs/nats-topics.md` - Future NATS integration

## API Base URL

For development testing:
- `https://api-dev.vettid.dev` (when backend is deployed)

## Status Update Workflow

After completing work:
```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 1 enrollment flow complete"
git push
```

## Acceptance Criteria

- [ ] QR scanner captures invitation code
- [ ] Hardware attestation completes successfully
- [ ] Password encryption uses transaction keys correctly
- [ ] Credential blob stored securely
- [ ] LAT stored for future authentication
- [ ] All unit tests pass
- [ ] UI follows Material 3 design guidelines
