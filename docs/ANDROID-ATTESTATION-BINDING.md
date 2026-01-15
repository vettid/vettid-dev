# Android: Attestation-Bound Key Exchange Implementation

This document describes the required Android changes to implement attestation-bound key exchange,
which prevents MITM attacks on the bootstrap key exchange.

## Background

Previously, the key exchange flow was:
1. App verifies enclave attestation (REST API)
2. App connects to NATS and sends its X25519 public key
3. Enclave responds with its keys

The security gap: These steps happen over different channels without cryptographic binding.
An attacker with NATS infrastructure access could potentially MITM the key exchange after
attestation completes.

## New Flow (Attestation-Bound)

1. App generates X25519 keypair BEFORE attestation verification
2. App computes `app_public_key_hash = SHA-256(app_public_key)`
3. App requests attestation with `app_public_key_hash` included
4. Server returns `binding_token` proving the hash was verified
5. App sends `binding_token` + `app_public_key` in bootstrap request
6. Enclave verifies the binding token matches

## Required Changes

### 1. Generate Keypair Before Attestation

```kotlin
// In EnrollmentManager.kt or equivalent

class AttestationBoundKeyExchange {
    private var appKeyPair: KeyPair? = null
    private var bindingToken: String? = null
    private var pcrHash: String? = null
    private var sessionId: String? = null

    /**
     * Generate X25519 keypair for key exchange
     * MUST be called before requesting attestation verification
     */
    fun prepareKeyExchange(): ByteArray {
        // Generate X25519 keypair
        val keyPairGenerator = KeyPairGenerator.getInstance("X25519")
        appKeyPair = keyPairGenerator.generateKeyPair()

        return appKeyPair!!.public.encoded
    }

    /**
     * Compute SHA-256 hash of app's public key
     */
    fun getPublicKeyHash(): String {
        val publicKey = appKeyPair?.public?.encoded
            ?: throw IllegalStateException("Call prepareKeyExchange first")

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKey)
        return hash.joinToString("") { "%02x".format(it) }
    }
}
```

### 2. Update Attestation Verification Request

```kotlin
// When calling POST /vault/attestation/nitro

data class VerifyAttestationRequest(
    @SerializedName("attestation_document") val attestationDocument: String,
    @SerializedName("session_id") val sessionId: String?,
    @SerializedName("nonce") val nonce: String?,
    // NEW: Include hash of app's public key
    @SerializedName("app_public_key_hash") val appPublicKeyHash: String?
)

data class VerifyAttestationResponse(
    val valid: Boolean,
    @SerializedName("enclave_public_key") val enclavePublicKey: String?,
    @SerializedName("pcr_version") val pcrVersion: String?,
    @SerializedName("module_id") val moduleId: String?,
    val timestamp: String?,
    val errors: List<String>?,
    // NEW: Binding token for bootstrap
    @SerializedName("binding_token") val bindingToken: String?
)

// Usage:
suspend fun verifyAttestation(
    attestationDoc: String,
    sessionId: String,
    keyExchange: AttestationBoundKeyExchange
): VerifyAttestationResponse {
    val request = VerifyAttestationRequest(
        attestationDocument = attestationDoc,
        sessionId = sessionId,
        nonce = null,
        appPublicKeyHash = keyExchange.getPublicKeyHash()  // NEW
    )

    val response = api.verifyNitroAttestation(request)

    // Store binding token for bootstrap
    if (response.valid && response.bindingToken != null) {
        keyExchange.bindingToken = response.bindingToken
        keyExchange.sessionId = sessionId
        // Extract PCR hash (first 24 chars) from pcr_version or enclave response
        keyExchange.pcrHash = extractPcrHash(response)
    }

    return response
}
```

### 3. Update Bootstrap Request

```kotlin
// When publishing to NATS: OwnerSpace.{guid}.forVault.app.bootstrap

data class BootstrapRequest(
    @SerializedName("bootstrap_token") val bootstrapToken: String? = null,
    // NEW: Attestation binding fields
    @SerializedName("session_id") val sessionId: String? = null,
    @SerializedName("app_public_key") val appPublicKey: String? = null,  // Base64
    @SerializedName("binding_token") val bindingToken: String? = null,
    @SerializedName("pcr_hash") val pcrHash: String? = null
)

data class BootstrapResponse(
    val status: String,
    val utks: List<String>,
    @SerializedName("ecies_public_key") val eciesPublicKey: String,
    @SerializedName("enclave_public_key") val enclavePublicKey: String,
    val capabilities: List<String>,
    @SerializedName("requires_password") val requiresPassword: Boolean,
    @SerializedName("requires_pin") val requiresPIN: Boolean,
    // NEW: Binding verification result
    @SerializedName("binding_verified") val bindingVerified: Boolean? = null
)

// Usage:
suspend fun bootstrap(
    natsClient: NatsClient,
    ownerSpace: String,
    keyExchange: AttestationBoundKeyExchange
): BootstrapResponse {
    val request = BootstrapRequest(
        sessionId = keyExchange.sessionId,
        appPublicKey = Base64.encodeToString(
            keyExchange.appKeyPair!!.public.encoded,
            Base64.NO_WRAP
        ),
        bindingToken = keyExchange.bindingToken,
        pcrHash = keyExchange.pcrHash
    )

    val response = natsClient.request(
        "$ownerSpace.forVault.app.bootstrap",
        Json.encodeToString(request)
    )

    val bootstrapResponse = Json.decodeFromString<BootstrapResponse>(response)

    // SECURITY: Warn if binding was not verified
    if (bootstrapResponse.bindingVerified != true) {
        Log.w("Bootstrap", "WARNING: Attestation binding was not verified")
        // Consider failing enrollment in high-security mode
    }

    return bootstrapResponse
}
```

### 4. Complete Flow Example

```kotlin
class SecureEnrollmentManager(
    private val api: VettIdApi,
    private val natsClient: NatsClient
) {
    private val keyExchange = AttestationBoundKeyExchange()

    suspend fun enroll(sessionId: String, attestationDoc: String): EnrollmentResult {
        // Step 1: Prepare key exchange BEFORE attestation
        keyExchange.prepareKeyExchange()

        // Step 2: Verify attestation with app's public key hash
        val attestationResult = verifyAttestation(attestationDoc, sessionId, keyExchange)
        if (!attestationResult.valid) {
            return EnrollmentResult.AttestationFailed(attestationResult.errors)
        }

        // Step 3: Get NATS credentials
        val natsCredentials = api.enrollNatsBootstrap(sessionId)
        natsClient.connect(natsCredentials)

        // Step 4: Bootstrap with binding verification
        val ownerSpace = natsCredentials.ownerSpace
        val bootstrapResult = bootstrap(natsClient, ownerSpace, keyExchange)

        // Step 5: Verify binding was successful
        if (bootstrapResult.bindingVerified != true) {
            Log.w("Enrollment", "Key exchange was not attestation-bound (legacy mode)")
            // In strict mode, you may want to fail here
        }

        // Continue with PIN setup, password, etc.
        return EnrollmentResult.Success(bootstrapResult)
    }
}
```

## Security Properties

When attestation binding is properly implemented:

1. **MITM Protection**: An attacker cannot substitute their own public key because:
   - The app's public key hash is verified during attestation
   - The binding token proves the hash was verified by the trusted backend
   - The enclave verifies the binding token before accepting the key

2. **Channel Binding**: The REST attestation verification and NATS key exchange
   are cryptographically bound together

3. **Replay Protection**: The binding token includes session_id and is single-use

## Backward Compatibility

The enclave still accepts bootstrap requests without binding fields for backward
compatibility with older app versions. However, the `binding_verified` field in
the response will be `false` for these requests.

New app versions should ALWAYS include binding fields for security.

## PCR Hash Extraction

The `pcr_hash` is the first 24 hex characters of PCR0, which uniquely identifies
the enclave image. You can extract this from:

1. The attestation response's `pcr_version` field (if it includes the hash)
2. By parsing the attestation document yourself
3. By requesting it from a separate endpoint

Example:
```kotlin
fun extractPcrHash(response: VerifyAttestationResponse): String {
    // PCR hash is first 24 chars of PCR0 (12 bytes = 24 hex chars)
    // This should be provided by your attestation verification endpoint
    // or parsed from the attestation document
    return response.pcrHash ?: throw IllegalStateException("PCR hash not available")
}
```

## Testing

1. **Test with binding**: Verify `binding_verified: true` in bootstrap response
2. **Test without binding**: Verify backward compatibility works
3. **Test with wrong binding**: Verify enclave logs warning (does not fail for compat)
4. **Test with tampered key**: Verify binding verification fails

## Questions?

Contact the backend team if you have questions about:
- The binding token format
- PCR hash extraction
- Error handling for binding failures
