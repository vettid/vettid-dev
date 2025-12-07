# Task: Phase 2 - Hardware Key Attestation Integration

## Phase
Phase 2: Device Attestation

## Assigned To
Android Instance

## Repository
`github.com/mesmerverse/vettid-android`

## Status
Phase 1 complete. Ready for Phase 2 attestation integration.

## IMPORTANT: API Change

The enrollment flow has changed. The backend now requires attestation verification as a separate step.

**New Flow:**
1. `POST /vault/enroll/start` - Returns `attestation_challenge`
2. `POST /vault/enroll/attestation/android` - Submit attestation certificate chain
3. `POST /vault/enroll/set-password` - Set password (only after attestation verified)
4. `POST /vault/enroll/finalize` - Complete enrollment

## Phase 2 Android Tasks

### 1. Update VaultServiceClient

Add the new attestation endpoint:

```kotlin
interface VaultService {
    @POST("/vault/enroll/start")
    suspend fun enrollStart(body: EnrollStartRequest): EnrollStartResponse
    // Response now includes: attestation_challenge, attestation_endpoint

    @POST("/vault/enroll/attestation/android")
    suspend fun submitAndroidAttestation(body: AndroidAttestationRequest): AttestationResponse
    // New endpoint!

    // ... existing endpoints
}

data class EnrollStartRequest(
    val invitation_code: String,
    val device_id: String,
    val device_type: String = "android"  // NEW: specify device type
)

data class EnrollStartResponse(
    val enrollment_session_id: String,
    val user_guid: String,
    val attestation_challenge: String,  // NEW: challenge for attestation
    val attestation_endpoint: String,   // NEW: endpoint to submit attestation
    val transaction_keys: List<TransactionKey>,
    val next_step: String  // "attestation_required"
)

data class AndroidAttestationRequest(
    val enrollment_session_id: String,
    val certificate_chain: List<String>  // Base64-encoded DER certs
)

data class AttestationResponse(
    val status: String,  // "attestation_verified"
    val device_type: String,
    val security_level: String,  // "hardware" or "software"
    val next_step: String,  // "password_required"
    val password_key_id: String
)
```

### 2. Implement Hardware Key Attestation

Create attestation with the challenge from backend:

```kotlin
// app/src/main/kotlin/dev/vettid/core/attestation/
HardwareKeyAttestation.kt

class HardwareKeyAttestation(private val context: Context) {

    /**
     * Generate attestation certificate chain using KeyStore
     */
    suspend fun generateAttestation(challenge: ByteArray): AttestationResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        // Generate key with attestation
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(
            "vettid_attestation_key",
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)  // Include backend challenge
            .setUserAuthenticationRequired(false)

        // Request StrongBox if available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        keyPairGenerator.initialize(builder.build())
        keyPairGenerator.generateKeyPair()

        // Get certificate chain
        val chain = keyStore.getCertificateChain("vettid_attestation_key")

        return AttestationResult(
            certificateChain = chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) },
            securityLevel = if (isStrongBoxBacked()) "StrongBox" else "TEE"
        )
    }
}
```

### 3. Update EnrollmentViewModel

Add attestation step to state machine:

```kotlin
sealed class EnrollmentState {
    object Initial : EnrollmentState()
    data class ScanningQR(val error: String? = null) : EnrollmentState()
    data class StartingEnrollment(val inviteCode: String) : EnrollmentState()
    data class Attesting(val challenge: String, val progress: Float) : EnrollmentState()  // NEW
    data class AttestationFailed(val error: String) : EnrollmentState()  // NEW
    data class SettingPassword(val strength: PasswordStrength) : EnrollmentState()
    data class Finalizing(val progress: Float) : EnrollmentState()
    data class Complete(val userGuid: String) : EnrollmentState()
    data class Error(val message: String, val retryable: Boolean) : EnrollmentState()
}

// In ViewModel:
fun submitAttestation(challenge: String) {
    viewModelScope.launch {
        _state.value = EnrollmentState.Attesting(challenge, 0.2f)

        val attestation = hardwareKeyAttestation.generateAttestation(
            Base64.decode(challenge, Base64.DEFAULT)
        )

        _state.value = EnrollmentState.Attesting(challenge, 0.6f)

        val response = vaultService.submitAndroidAttestation(
            AndroidAttestationRequest(
                enrollment_session_id = sessionId,
                certificate_chain = attestation.certificateChain
            )
        )

        if (response.status == "attestation_verified") {
            passwordKeyId = response.password_key_id
            _state.value = EnrollmentState.SettingPassword(PasswordStrength.NONE)
        } else {
            _state.value = EnrollmentState.AttestationFailed("Attestation rejected")
        }
    }
}
```

### 4. Update AttestationScreen

Show attestation progress and handle failures:

```kotlin
@Composable
fun AttestationScreen(
    state: EnrollmentState.Attesting,
    onRetry: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = null,
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text("Verifying Device Security")

        Spacer(modifier = Modifier.height(16.dp))

        LinearProgressIndicator(progress = state.progress)

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Generating hardware attestation...",
            style = MaterialTheme.typography.bodySmall
        )
    }
}
```

### 5. Unit Tests

Add attestation tests:

```kotlin
class HardwareKeyAttestationTest {
    @Test
    fun `generateAttestation returns valid certificate chain`()

    @Test
    fun `attestation includes challenge in certificate`()

    @Test
    fun `falls back to TEE when StrongBox unavailable`()
}

class EnrollmentViewModelTest {
    @Test
    fun `transitions to Attesting after enrollment start`()

    @Test
    fun `transitions to SettingPassword after attestation verified`()

    @Test
    fun `transitions to AttestationFailed on rejection`()
}
```

## Key References (in vettid-dev)

Pull latest from vettid-dev:
- `cdk/lambda/common/attestation.ts` - Backend attestation verification
- `cdk/lambda/handlers/attestation/verifyAndroidAttestation.ts` - Android handler
- `cdk/coordination/specs/vault-services-api.yaml` - Updated API spec

## Acceptance Criteria

- [ ] Hardware Key Attestation generates valid certificate chain
- [ ] Challenge from backend is included in attestation
- [ ] StrongBox used when available, falls back to TEE
- [ ] EnrollmentViewModel handles attestation state
- [ ] AttestationScreen shows progress and errors
- [ ] Unit tests pass
- [ ] Integration with backend verified on physical device

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/android.json
git add cdk/coordination/status/android.json
git commit -m "Update Android status: Phase 2 attestation complete"
git push
```
