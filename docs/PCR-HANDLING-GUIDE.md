# VettID PCR (Platform Configuration Register) Handling Guide

This document explains how PCRs are generated, published, rotated, and verified across the VettID system, including detailed guidance for mobile app developers.

## Table of Contents

1. [Overview](#overview)
2. [What Are PCRs?](#what-are-pcrs)
3. [PCR Generation](#pcr-generation)
4. [PCR Storage](#pcr-storage)
5. [PCR Publication](#pcr-publication)
6. [PCR Rotation & Versioning](#pcr-rotation--versioning)
7. [Mobile App PCR Handling](#mobile-app-pcr-handling)
8. [Attestation Verification Flow](#attestation-verification-flow)
9. [Error Handling & Edge Cases](#error-handling--edge-cases)
10. [Security Considerations](#security-considerations)

---

## Overview

PCRs (Platform Configuration Registers) are cryptographic measurements that uniquely identify the code running inside a Nitro Enclave. They form the foundation of VettID's trust model - mobile apps use PCRs to verify they're communicating with authentic VettID enclave code, not a compromised or malicious server.

**Trust Flow:**
```
AWS Nitro Hardware
    ↓ (generates)
PCR Values (hash of enclave code)
    ↓ (stored in)
SSM Parameters + S3 Manifest
    ↓ (signed by)
VettID Signing Key (ECDSA P-256)
    ↓ (fetched by)
Mobile Apps
    ↓ (compared against)
Attestation Document from Enclave
    ↓ (if match)
Trust Established → Safe to Send Sensitive Data
```

---

## What Are PCRs?

AWS Nitro Enclaves generate three primary PCR values:

| PCR | Description | Changes When |
|-----|-------------|--------------|
| **PCR0** | Hash of enclave image file (EIF) | Any code change, dependency update, or rebuild |
| **PCR1** | Hash of Linux kernel and bootstrap | Kernel or bootstrap changes (rare) |
| **PCR2** | Hash of application code | Application-level changes |

**Format:** Each PCR is a 48-byte SHA-384 hash, represented as a 96-character hex string.

**Example:**
```
PCR0: 5cbc157248fbf4ead4f793248b403aa637a4a423bf665c1e8fa23cae2dca3f893a5f4e3311e8f46fb8ab36590040a89b
PCR1: 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493
PCR2: f7ca84f78deea25b495af4c4c84e8080fe8b1a2385946eaee8f90d0dda172dd60427111037f1ddd1ee0973c6eda38100
```

**Key Property:** PCRs are deterministic - the same code always produces the same PCRs. Any tampering or modification results in different PCR values.

---

## PCR Generation

PCRs are generated during the enclave build process in `deploy-enclave.sh`:

```bash
# 1. Build Docker image
docker build -t vettid-vault-enclave .

# 2. Convert to Enclave Image Format (EIF)
nitro-cli build-enclave \
    --docker-uri vettid-vault-enclave:latest \
    --output-file vettid-vault-enclave.eif

# 3. Extract PCR values
nitro-cli describe-eif --eif-path vettid-vault-enclave.eif > /tmp/eif-info.json
PCR0=$(jq -r '.Measurements.PCR0' /tmp/eif-info.json)
PCR1=$(jq -r '.Measurements.PCR1' /tmp/eif-info.json)
PCR2=$(jq -r '.Measurements.PCR2' /tmp/eif-info.json)
```

**When PCRs Change:**
- Any modification to enclave source code
- Dependency updates (Go modules, etc.)
- Docker base image updates
- Build environment changes

---

## PCR Storage

PCRs are stored in multiple locations for different purposes:

### SSM Parameters

| Parameter Path | Purpose | Format |
|----------------|---------|--------|
| `/vettid/enclave/pcr/pcr0` | Individual PCR0 (parent reads this) | Hex string |
| `/vettid/enclave/pcr/pcr1` | Individual PCR1 | Hex string |
| `/vettid/enclave/pcr/pcr2` | Individual PCR2 | Hex string |
| `/vettid/enclave/pcr/current` | Combined manifest | JSON (see below) |
| `/vettid/enclave/pcr0` | **DEPRECATED** - Legacy path, no longer used | Hex string |

**Combined Manifest Format (`/vettid/enclave/pcr/current`):**
```json
{
  "PCR0": "5cbc157248fbf4ead4f793248b403aa637a4a423bf665c1e8fa23cae2dca3f893a5f4e3311e8f46fb8ab36590040a89b",
  "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
  "PCR2": "f7ca84f78deea25b495af4c4c84e8080fe8b1a2385946eaee8f90d0dda172dd60427111037f1ddd1ee0973c6eda38100",
  "version": "2026-01-15-v1",
  "published_at": "2026-01-15T11:10:00Z"
}
```

### S3 + CloudFront (Public Distribution)

A signed PCR manifest is published to S3 and served via CloudFront for mobile apps:

**URL:** `https://api.vettid.dev/attestation/pcr-manifest`

---

## PCR Publication

### API Endpoint

**Endpoint:** `GET /attestation/pcr-manifest`
**Authentication:** None (public endpoint)
**Cache:** 5 minutes (`Cache-Control: public, max-age=300`)

**Response Format:**
```json
{
  "version": 2,
  "timestamp": "2026-01-15T11:10:00Z",
  "pcr_sets": [
    {
      "id": "2026-01-15-v1",
      "pcr0": "5cbc157248fbf4ead4f793248b403aa637a4a423bf665c1e8fa23cae2dca3f893a5f4e3311e8f46fb8ab36590040a89b",
      "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      "pcr2": "f7ca84f78deea25b495af4c4c84e8080fe8b1a2385946eaee8f90d0dda172dd60427111037f1ddd1ee0973c6eda38100",
      "valid_from": "2026-01-15T11:10:00Z",
      "valid_until": null,
      "is_current": true,
      "description": "ECIES crypto parameter fix"
    },
    {
      "id": "2026-01-14-v1",
      "pcr0": "42b6b3cfc2d8001624dc54513c67f12d3a4752f717ce67cd483d77b71d60f846b4b6481d67fc182dcb7795648e92238e",
      "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      "pcr2": "cecbc6e5037719cf68e55436b52c65122b9345a822aec9ce28ba8f73a0dc2e1251e82c56dc16405b10fc0e6927dc2348",
      "valid_from": "2026-01-14T00:00:00Z",
      "valid_until": "2026-01-16T11:10:00Z",
      "is_current": false,
      "description": "Previous production version"
    }
  ],
  "signature": "MEUCIQC...base64-ecdsa-signature..."
}
```

### Signature Verification

The manifest is signed with VettID's ECDSA P-256 signing key:

**Public Key (Base64):**
```
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzSr2U/RxJRP7dWKMASJSs6fURsEzdn59XSvp3TitMaw3bMBIj8slPXJhJF7d2/DS4UnzMhxEdQHLq2NdoKaVUw==
```

**Verification Algorithm:**
1. Extract `pcr_sets` array from response
2. Compute SHA-256 hash of JSON-serialized `pcr_sets`
3. Verify ECDSA signature using VettID public key

---

## PCR Rotation & Versioning

### Version Format

```
{YYYY-MM-DD}-v{increment}
Example: 2026-01-15-v1
```

### Rotation Process

1. **New Build:** Deploy script builds new enclave, generates new PCRs
2. **SSM Update:** New PCRs stored with new version string
3. **Manifest Update:** PCR manifest updated with new entry marked `is_current: true`
4. **Previous Version:** Old PCRs remain in manifest with `valid_until` set
5. **Transition Period:** Both versions accepted for 24-48 hours
6. **Deprecation:** Old version eventually removed from manifest

### Rolling Update Timeline

```
T+0:  New enclave deployed
      - New PCRs published (is_current: true)
      - Old PCRs marked (is_current: false, valid_until: T+48h)

T+0 to T+48h: Transition Period
      - Mobile apps accept BOTH PCR versions
      - Background refresh updates cached PCRs

T+48h: Transition Complete
      - Old PCRs removed from manifest
      - Only new PCRs accepted
```

---

## Mobile App PCR Handling

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Mobile App                            │
├─────────────────────────────────────────────────────────────┤
│  PcrConfigManager                                            │
│  ├── Fetches PCRs from API                                  │
│  ├── Verifies signature                                     │
│  ├── Caches locally (encrypted)                             │
│  └── Provides PCRs for verification                         │
├─────────────────────────────────────────────────────────────┤
│  NitroAttestationVerifier                                    │
│  ├── Parses attestation document (CBOR/COSE)                │
│  ├── Verifies AWS certificate chain                         │
│  ├── Extracts PCRs from attestation                         │
│  ├── Compares against expected PCRs                         │
│  └── Extracts enclave public key                            │
├─────────────────────────────────────────────────────────────┤
│  NitroEnrollmentClient                                       │
│  ├── Requests attestation from enclave                      │
│  ├── Uses verified public key for encryption                │
│  └── Sends encrypted data to enclave                        │
└─────────────────────────────────────────────────────────────┘
```

### PCR Fetching Strategy

Mobile apps should implement a layered fetching strategy:

```kotlin
class PcrConfigManager {

    companion object {
        const val UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L  // 24 hours
        const val API_ENDPOINT = "/attestation/pcr-manifest"
    }

    /**
     * Initialize PCRs - call on app startup
     */
    suspend fun initialize() {
        if (shouldUpdate()) {
            fetchAndCachePcrs()
        }
    }

    /**
     * Layered fetch strategy with fallbacks
     */
    private suspend fun fetchAndCachePcrs(): Boolean {
        // Layer 1: Try API endpoint
        try {
            val manifest = apiClient.get(API_ENDPOINT)
            if (verifySignature(manifest)) {
                cachePcrs(manifest.pcr_sets)
                return true
            }
        } catch (e: Exception) {
            Log.w(TAG, "API fetch failed: ${e.message}")
        }

        // Layer 2: Try CloudFront fallback
        try {
            val manifest = httpClient.get(CLOUDFRONT_URL)
            if (verifySignature(manifest)) {
                cachePcrs(manifest.pcr_sets)
                return true
            }
        } catch (e: Exception) {
            Log.w(TAG, "CloudFront fetch failed: ${e.message}")
        }

        // Layer 3: Use bundled defaults (app update required for new PCRs)
        Log.w(TAG, "Using bundled PCRs - network unavailable")
        return hasCachedPcrs()
    }
}
```

### Local Caching

PCRs should be cached locally using encrypted storage:

```kotlin
// Android: EncryptedSharedPreferences
private val prefs = EncryptedSharedPreferences.create(
    "pcr_config",
    masterKeyAlias,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Cache structure
data class CachedPcrs(
    val currentPcrs: PcrSet,           // Current active PCRs
    val previousPcrs: PcrSet?,         // Previous version (transition support)
    val version: String,               // e.g., "2026-01-15-v1"
    val lastUpdated: Long,             // Timestamp
    val signature: String              // Original signature for audit
)

data class PcrSet(
    val id: String,
    val pcr0: String,
    val pcr1: String,
    val pcr2: String,
    val validFrom: String,
    val validUntil: String?,
    val isCurrent: Boolean
)
```

### Signature Verification

```kotlin
object PcrSignatureVerifier {

    // VettID's PCR signing public key
    private const val VETTID_PUBLIC_KEY_BASE64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzSr2U/RxJRP7dWKMASJSs6fURsEzdn59XSvp3TitMaw3bMBIj8slPXJhJF7d2/DS4UnzMhxEdQHLq2NdoKaVUw=="

    fun verify(pcrSets: List<PcrSet>, signature: String): Boolean {
        // 1. Serialize PCR sets to canonical JSON
        val jsonBytes = Json.encodeToString(pcrSets).toByteArray()

        // 2. Compute SHA-256 hash
        val hash = MessageDigest.getInstance("SHA-256").digest(jsonBytes)

        // 3. Decode public key
        val keyBytes = Base64.decode(VETTID_PUBLIC_KEY_BASE64, Base64.DEFAULT)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val publicKey = KeyFactory.getInstance("EC").generatePublic(keySpec)

        // 4. Verify signature
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(publicKey)
        sig.update(jsonBytes)

        val sigBytes = Base64.decode(signature, Base64.DEFAULT)
        return sig.verify(sigBytes)
    }
}
```

### PCR Verification During Attestation

```kotlin
class NitroAttestationVerifier {

    /**
     * Verify attestation document and extract enclave public key
     */
    fun verify(
        attestationDocument: ByteArray,
        expectedNonce: ByteArray?,
        pcrConfig: PcrConfigManager
    ): VerificationResult {

        // 1. Parse COSE_Sign1 structure
        val coseSign1 = parseCoseSign1(attestationDocument)

        // 2. Parse attestation payload
        val attestation = parseAttestationPayload(coseSign1.payload)

        // 3. Verify AWS certificate chain
        verifyCertificateChain(attestation.certificate, attestation.cabundle)

        // 4. Verify COSE signature
        verifyCoseSignature(coseSign1, attestation.certificate)

        // 5. Verify timestamp (must be < 5 minutes old)
        verifyTimestamp(attestation.timestamp)

        // 6. Verify nonce (if provided)
        if (expectedNonce != null) {
            verifyNonce(attestation.nonce, expectedNonce)
        }

        // 7. CRITICAL: Verify PCR values
        val pcrResult = verifyPcrs(attestation.pcrs, pcrConfig)
        if (!pcrResult.valid) {
            throw AttestationException("PCR verification failed: ${pcrResult.reason}")
        }

        // 8. Extract and return enclave public key
        return VerificationResult(
            valid = true,
            enclavePublicKey = attestation.publicKey,
            moduleId = attestation.moduleId,
            pcrVersion = pcrResult.matchedVersion
        )
    }

    /**
     * Verify PCRs with fallback support for rolling updates
     */
    private fun verifyPcrs(
        actualPcrs: Map<Int, ByteArray>,
        pcrConfig: PcrConfigManager
    ): PcrVerificationResult {

        val actualPcr0 = actualPcrs[0]?.toHexString() ?: return PcrVerificationResult(
            valid = false,
            reason = "PCR0 missing from attestation"
        )
        val actualPcr1 = actualPcrs[1]?.toHexString()
        val actualPcr2 = actualPcrs[2]?.toHexString()

        // Try current PCRs first
        val currentPcrs = pcrConfig.getCurrentPcrs()
        if (matchesPcrs(actualPcr0, actualPcr1, actualPcr2, currentPcrs)) {
            return PcrVerificationResult(
                valid = true,
                matchedVersion = currentPcrs.id
            )
        }

        // During transition, try previous version
        val previousPcrs = pcrConfig.getPreviousPcrs()
        if (previousPcrs != null && matchesPcrs(actualPcr0, actualPcr1, actualPcr2, previousPcrs)) {
            Log.i(TAG, "Matched previous PCR version (transition period): ${previousPcrs.id}")
            return PcrVerificationResult(
                valid = true,
                matchedVersion = previousPcrs.id
            )
        }

        // No match - potential attack or outdated app
        return PcrVerificationResult(
            valid = false,
            reason = "PCR mismatch - actual PCR0: ${actualPcr0.take(16)}..., " +
                     "expected: ${currentPcrs.pcr0.take(16)}..."
        )
    }

    private fun matchesPcrs(
        actualPcr0: String,
        actualPcr1: String?,
        actualPcr2: String?,
        expected: PcrSet
    ): Boolean {
        // PCR0 is required
        if (!actualPcr0.equals(expected.pcr0, ignoreCase = true)) {
            return false
        }

        // PCR1 and PCR2 verified if present in both
        if (actualPcr1 != null && !actualPcr1.equals(expected.pcr1, ignoreCase = true)) {
            return false
        }
        if (actualPcr2 != null && !actualPcr2.equals(expected.pcr2, ignoreCase = true)) {
            return false
        }

        return true
    }
}
```

### Complete Enrollment Flow

```kotlin
class NitroEnrollmentClient(
    private val pcrConfig: PcrConfigManager,
    private val attestationVerifier: NitroAttestationVerifier,
    private val cryptoManager: CryptoManager
) {

    /**
     * Complete enrollment flow with PCR verification
     */
    suspend fun enrollWithPin(pin: String): EnrollmentResult {

        // Step 1: Ensure PCRs are up to date
        pcrConfig.initialize()

        // Step 2: Request attestation from enclave
        val attestationResponse = api.requestAttestation(
            nonce = generateNonce()
        )

        // Step 3: Verify attestation (includes PCR check)
        val verificationResult = attestationVerifier.verify(
            attestationDocument = attestationResponse.attestationDocument,
            expectedNonce = attestationResponse.nonce,
            pcrConfig = pcrConfig
        )

        if (!verificationResult.valid) {
            throw SecurityException("Attestation verification failed")
        }

        Log.i(TAG, "Attestation verified. PCR version: ${verificationResult.pcrVersion}")

        // Step 4: Encrypt PIN using verified enclave public key
        val encryptedPin = cryptoManager.encryptToPublicKey(
            publicKey = verificationResult.enclavePublicKey,
            plaintext = pin.toByteArray()
        )

        // Step 5: Send encrypted PIN to enclave
        val pinResponse = api.setupPin(
            encryptedPin = encryptedPin.ciphertext,
            ephemeralPublicKey = encryptedPin.ephemeralPublicKey,
            nonce = encryptedPin.nonce
        )

        return EnrollmentResult(success = true)
    }
}
```

### iOS Implementation Notes

For iOS, use similar patterns with:

```swift
// Keychain for secure PCR storage
class PcrConfigManager {
    private let keychain = KeychainSwift()

    func cachePcrs(_ pcrs: PcrManifest) {
        let data = try! JSONEncoder().encode(pcrs)
        keychain.set(data, forKey: "pcr_config", withAccess: .accessibleAfterFirstUnlock)
    }
}

// CryptoKit for signature verification
func verifySignature(pcrSets: [PcrSet], signature: Data) -> Bool {
    let publicKey = try! P256.Signing.PublicKey(derRepresentation: vettidPublicKeyData)
    let jsonData = try! JSONEncoder().encode(pcrSets)
    let ecdsaSignature = try! P256.Signing.ECDSASignature(derRepresentation: signature)
    return publicKey.isValidSignature(ecdsaSignature, for: jsonData)
}
```

---

## Error Handling & Edge Cases

### Network Failures

```kotlin
sealed class PcrFetchResult {
    data class Success(val manifest: PcrManifest) : PcrFetchResult()
    data class CachedFallback(val cachedPcrs: CachedPcrs, val reason: String) : PcrFetchResult()
    data class BundledFallback(val reason: String) : PcrFetchResult()
    data class Error(val exception: Exception) : PcrFetchResult()
}

// Handle gracefully
when (val result = pcrConfig.fetchPcrs()) {
    is PcrFetchResult.Success -> {
        // Use fresh PCRs
    }
    is PcrFetchResult.CachedFallback -> {
        // Use cached PCRs, log warning
        Log.w(TAG, "Using cached PCRs: ${result.reason}")
    }
    is PcrFetchResult.BundledFallback -> {
        // Use bundled PCRs, suggest app update
        Log.w(TAG, "Using bundled PCRs - consider updating app")
    }
    is PcrFetchResult.Error -> {
        // Critical error - may need to block operation
        throw SecurityException("Cannot verify enclave identity")
    }
}
```

### PCR Mismatch Scenarios

| Scenario | Cause | Action |
|----------|-------|--------|
| PCR mismatch, cached PCRs stale | New enclave deployed | Refresh PCRs, retry |
| PCR mismatch after refresh | Possible attack | Abort, alert user |
| PCR mismatch, matches previous | Rolling update in progress | Accept (transition) |
| All PCRs unknown | Severely outdated app | Require app update |

### Handling Rolling Updates

```kotlin
fun handlePcrMismatch(
    actualPcrs: Map<Int, ByteArray>,
    pcrConfig: PcrConfigManager
): RecoveryAction {

    // 1. Try refreshing PCRs
    val refreshResult = pcrConfig.forceRefresh()
    if (refreshResult.success) {
        // Retry verification with fresh PCRs
        if (verifyPcrs(actualPcrs, pcrConfig).valid) {
            return RecoveryAction.RETRY_SUCCEEDED
        }
    }

    // 2. Check if we're in a transition period
    val previousPcrs = pcrConfig.getPreviousPcrs()
    if (previousPcrs != null) {
        val timeSinceUpdate = System.currentTimeMillis() - pcrConfig.getLastUpdateTime()
        if (timeSinceUpdate < 48.hours.inMilliseconds) {
            // We're likely in a transition - this is suspicious
            Log.e(TAG, "PCR mismatch during transition period - potential attack")
        }
    }

    // 3. Fail securely
    return RecoveryAction.ABORT_SECURITY_RISK
}
```

---

## Security Considerations

### Trust Model

```
┌─────────────────────────────────────────────────────────────┐
│                      TRUST ANCHORS                          │
├─────────────────────────────────────────────────────────────┤
│  1. AWS Nitro Root CA                                       │
│     - Embedded in mobile app                                │
│     - Verifies attestation certificate chain                │
│                                                             │
│  2. VettID PCR Signing Key                                  │
│     - Embedded in mobile app                                │
│     - Verifies PCR manifest signature                       │
│                                                             │
│  3. App Store Distribution                                  │
│     - Ensures app hasn't been tampered with                 │
│     - Trust anchors are authentic                           │
└─────────────────────────────────────────────────────────────┘
```

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Man-in-the-middle | ECDSA signature on PCR manifest |
| Replay attack | Timestamp verification (< 5 min) |
| Fake enclave | PCR verification against known values |
| Compromised server | Attestation signed by AWS hardware |
| Downgrade attack | Version tracking, `valid_until` enforcement |

### Best Practices

1. **Always verify signatures** - Never trust PCRs without signature verification
2. **Cache defensively** - Use encrypted storage, validate on read
3. **Fail securely** - If verification fails, abort the operation
4. **Log appropriately** - Log verification results (not PCR values) for debugging
5. **Update promptly** - Keep bundled PCRs current with app releases
6. **Handle transitions** - Support previous version during rolling updates

---

## Appendix: Quick Reference

### API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/attestation/pcr-manifest` | GET | None | Fetch signed PCR manifest |
| `/vault/attest` | POST | Member | Request attestation document |

### SSM Parameters

| Path | Type | Purpose |
|------|------|---------|
| `/vettid/enclave/pcr/current` | String | Combined manifest (JSON) |
| `/vettid/enclave/pcr/pcr0` | String | Individual PCR0 |
| `/vettid/enclave/pcr/pcr1` | String | Individual PCR1 |
| `/vettid/enclave/pcr/pcr2` | String | Individual PCR2 |

### Key Constants

```kotlin
// Android
const val PCR_UPDATE_INTERVAL = 24 * 60 * 60 * 1000L  // 24 hours
const val ATTESTATION_MAX_AGE = 5 * 60 * 1000L        // 5 minutes
const val TRANSITION_PERIOD = 48 * 60 * 60 * 1000L    // 48 hours
```

```swift
// iOS
let pcrUpdateInterval: TimeInterval = 24 * 60 * 60    // 24 hours
let attestationMaxAge: TimeInterval = 5 * 60          // 5 minutes
let transitionPeriod: TimeInterval = 48 * 60 * 60     // 48 hours
```

### VettID PCR Signing Public Key

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzSr2U/RxJRP7dWKMASJSs6fURsEz
dn59XSvp3TitMaw3bMBIj8slPXJhJF7d2/DS4UnzMhxEdQHLq2NdoKaVUw==
-----END PUBLIC KEY-----
```

Base64: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzSr2U/RxJRP7dWKMASJSs6fURsEzdn59XSvp3TitMaw3bMBIj8slPXJhJF7d2/DS4UnzMhxEdQHLq2NdoKaVUw==`

---

*Last updated: 2026-01-15*
