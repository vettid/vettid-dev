# Task: Create Android Project Scaffold

## Phase
Phase 0: Foundation & Coordination Setup

## Assigned To
Android Instance

## Prerequisites
- [x] Coordination directory structure created
- [x] API specifications available in `cdk/coordination/specs/`

## Context

You are the **Android Instance** for the VettID Vault Services project. Your role is to develop the Android mobile app that handles vault enrollment, credential management, and vault communication.

Read these files first:
1. `cdk/docs/DEVELOPMENT_PLAN.md` - Overall development plan
2. `cdk/coordination/README.md` - Coordination protocol
3. `cdk/coordination/specs/vault-services-api.yaml` - API specification
4. `cdk/coordination/specs/credential-format.md` - Credential format spec
5. `cdk/coordination/specs/nats-topics.md` - NATS topic structure

## Deliverables

### 1. Create Android Project Structure

Create a new Android project at the repository root:

```
android/
├── app/
│   ├── build.gradle.kts
│   ├── src/
│   │   ├── main/
│   │   │   ├── AndroidManifest.xml
│   │   │   ├── kotlin/dev/vettid/
│   │   │   │   ├── VettIDApplication.kt
│   │   │   │   ├── auth/
│   │   │   │   │   ├── CredentialStore.kt
│   │   │   │   │   ├── CredentialBlob.kt
│   │   │   │   │   ├── CryptoUtils.kt
│   │   │   │   │   └── DeviceAttestation.kt
│   │   │   │   ├── api/
│   │   │   │   │   ├── VaultServiceClient.kt
│   │   │   │   │   └── ApiModels.kt
│   │   │   │   ├── enrollment/
│   │   │   │   │   ├── EnrollmentActivity.kt
│   │   │   │   │   ├── EnrollmentViewModel.kt
│   │   │   │   │   └── EnrollmentManager.kt
│   │   │   │   ├── nats/
│   │   │   │   │   └── NatsClient.kt
│   │   │   │   └── ui/
│   │   │   │       └── theme/
│   │   │   └── res/
│   │   │       ├── layout/
│   │   │       ├── values/
│   │   │       └── drawable/
│   │   ├── test/
│   │   │   └── kotlin/dev/vettid/
│   │   │       ├── auth/
│   │   │       │   ├── CredentialStoreTest.kt
│   │   │       │   └── CryptoUtilsTest.kt
│   │   │       └── api/
│   │   │           └── VaultServiceClientTest.kt
│   │   └── androidTest/
│   │       └── kotlin/dev/vettid/
│   │           └── enrollment/
│   │               └── EnrollmentFlowTest.kt
├── build.gradle.kts
├── settings.gradle.kts
└── gradle.properties
```

### 2. Configure Dependencies

**build.gradle.kts (app):**

```kotlin
dependencies {
    // Android core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.7.0")
    implementation("androidx.activity:activity-ktx:1.8.2")

    // Jetpack Compose
    implementation(platform("androidx.compose:compose-bom:2024.02.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")

    // Networking
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Crypto
    implementation("org.whispersystems:curve25519-android:0.5.0")
    // Or: implementation("com.goterl:lazysodium-android:5.1.0")

    // Secure storage
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // QR scanning
    implementation("com.google.mlkit:barcode-scanning:17.2.0")

    // NATS (if available, otherwise use raw WebSocket)
    // implementation("io.nats:jnats:2.17.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
```

### 3. Implement Core Crypto Utilities

**CryptoUtils.kt:**
```kotlin
object CryptoUtils {
    // X25519 key pair generation
    fun generateX25519KeyPair(): KeyPair

    // X25519 key exchange
    fun deriveSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray

    // XChaCha20-Poly1305 encryption
    fun encrypt(plaintext: ByteArray, key: ByteArray): EncryptedData
    fun decrypt(encrypted: EncryptedData, key: ByteArray): ByteArray

    // HKDF key derivation
    fun deriveKey(sharedSecret: ByteArray, info: String): ByteArray
}
```

### 4. Implement Credential Storage

**CredentialStore.kt:**
```kotlin
class CredentialStore(private val context: Context) {
    // Store credential blob securely
    fun storeCredentialBlob(blob: CredentialBlob)
    fun getCredentialBlob(): CredentialBlob?

    // Store LAT
    fun storeLAT(lat: LAT)
    fun getLAT(): LAT?

    // Store transaction keys
    fun storeTransactionKeys(keys: List<TransactionKey>)
    fun getUnusedTransactionKey(): TransactionKey?
    fun markTransactionKeyUsed(keyId: String)

    // Clear all credentials
    fun clear()
}
```

### 5. Define API Models

**ApiModels.kt:**
Based on `vault-services-api.yaml`, create Kotlin data classes:
- `EnrollStartRequest` / `EnrollStartResponse`
- `AttestationRequest` / `AttestationResponse`
- `SetPasswordRequest` / `SetPasswordResponse`
- `FinalizeRequest` / `FinalizeResponse`
- `CredentialBlob`
- `LAT`
- `TransactionKey`

### 6. Create Unit Tests

**CryptoUtilsTest.kt:**
- Test key pair generation
- Test encryption/decryption roundtrip
- Test key derivation

**CredentialStoreTest.kt:**
- Test storing and retrieving credential blob
- Test LAT storage
- Test transaction key management

## Acceptance Criteria

- [ ] Android project builds successfully
- [ ] CryptoUtils generates valid X25519 keys
- [ ] Encryption/decryption roundtrip works
- [ ] CredentialStore securely stores data
- [ ] Unit tests pass
- [ ] API models match OpenAPI spec

## Reporting

When complete:
1. Update `cdk/coordination/status/android.json`:
   ```json
   {
     "instance": "android",
     "phase": 0,
     "task": "Android project scaffold complete",
     "status": "completed",
     "completedTasks": ["Project structure", "Crypto utils", "Credential store", "API models", "Unit tests"],
     "lastUpdated": "<current timestamp>"
   }
   ```

2. Document any issues in `cdk/coordination/results/issues/`

## Notes

- Target Android API 26+ (Android 8.0+)
- Use Kotlin with coroutines for async operations
- Follow Material Design 3 guidelines
- Use Jetpack Compose for UI
- Hardware attestation requires Android 8.0+ with hardware-backed keystore
- Test on both emulator and physical device
