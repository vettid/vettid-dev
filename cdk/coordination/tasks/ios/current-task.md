# Task: Create iOS Project Scaffold

## Phase
Phase 0: Foundation & Coordination Setup

## Assigned To
iOS Instance

## Prerequisites
- [x] Coordination directory structure created
- [x] API specifications available in `cdk/coordination/specs/`

## Context

You are the **iOS Instance** for the VettID Vault Services project. Your role is to develop the iOS mobile app that handles vault enrollment, credential management, and vault communication.

Read these files first:
1. `cdk/docs/DEVELOPMENT_PLAN.md` - Overall development plan
2. `cdk/coordination/README.md` - Coordination protocol
3. `cdk/coordination/specs/vault-services-api.yaml` - API specification
4. `cdk/coordination/specs/credential-format.md` - Credential format spec
5. `cdk/coordination/specs/nats-topics.md` - NATS topic structure

## Deliverables

### 1. Create iOS Project Structure

Create a new iOS project at the repository root:

```
ios/
├── VettID.xcodeproj/
├── VettID/
│   ├── VettIDApp.swift
│   ├── Info.plist
│   ├── Sources/
│   │   ├── Auth/
│   │   │   ├── CredentialStore.swift
│   │   │   ├── CredentialBlob.swift
│   │   │   ├── CryptoUtils.swift
│   │   │   └── DeviceAttestation.swift
│   │   ├── API/
│   │   │   ├── VaultServiceClient.swift
│   │   │   └── APIModels.swift
│   │   ├── Enrollment/
│   │   │   ├── EnrollmentView.swift
│   │   │   ├── EnrollmentViewModel.swift
│   │   │   ├── EnrollmentManager.swift
│   │   │   ├── QRScannerView.swift
│   │   │   └── PasswordSetupView.swift
│   │   ├── NATS/
│   │   │   └── NatsClient.swift
│   │   └── UI/
│   │       ├── Theme/
│   │       │   └── VettIDTheme.swift
│   │       └── Components/
│   ├── Resources/
│   │   ├── Assets.xcassets/
│   │   └── Localizable.strings
│   └── Preview Content/
├── VettIDTests/
│   ├── Auth/
│   │   ├── CredentialStoreTests.swift
│   │   └── CryptoUtilsTests.swift
│   └── API/
│       └── VaultServiceClientTests.swift
└── VettIDUITests/
    └── EnrollmentFlowTests.swift
```

### 2. Configure Project Settings

**Xcode Configuration:**
- Deployment target: iOS 15.0+
- Swift version: 5.9+
- Enable App Attest capability
- Enable Keychain sharing if needed

**Package.swift or SPM Dependencies:**

```swift
dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
    // Or use CryptoKit (built-in) for most operations
]
```

### 3. Implement Core Crypto Utilities

**CryptoUtils.swift:**
```swift
import CryptoKit

enum CryptoUtils {
    // X25519 key pair generation
    static func generateX25519KeyPair() -> (publicKey: Data, privateKey: Data)

    // X25519 key exchange
    static func deriveSharedSecret(
        privateKey: Data,
        publicKey: Data
    ) -> Data

    // XChaCha20-Poly1305 encryption (use libsodium/swift-sodium)
    static func encrypt(
        plaintext: Data,
        key: Data
    ) throws -> EncryptedData

    static func decrypt(
        encrypted: EncryptedData,
        key: Data
    ) throws -> Data

    // HKDF key derivation
    static func deriveKey(
        sharedSecret: Data,
        info: String
    ) -> Data
}

struct EncryptedData {
    let nonce: Data      // 24 bytes for XChaCha20
    let ciphertext: Data // Includes auth tag
}
```

### 4. Implement Credential Storage

**CredentialStore.swift:**
```swift
import Security

class CredentialStore {
    private let service = "dev.vettid.credentials"

    // Store credential blob in Keychain
    func storeCredentialBlob(_ blob: CredentialBlob) throws
    func getCredentialBlob() throws -> CredentialBlob?

    // Store LAT
    func storeLAT(_ lat: LAT) throws
    func getLAT() throws -> LAT?

    // Store transaction keys
    func storeTransactionKeys(_ keys: [TransactionKey]) throws
    func getUnusedTransactionKey() throws -> TransactionKey?
    func markTransactionKeyUsed(_ keyId: String) throws

    // Clear all credentials
    func clear() throws

    // Private helpers
    private func saveToKeychain(
        _ data: Data,
        account: String,
        accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws

    private func loadFromKeychain(account: String) throws -> Data?
}
```

### 5. Implement App Attest

**DeviceAttestation.swift:**
```swift
import DeviceCheck

class DeviceAttestation {
    private let service = DCAppAttestService.shared

    // Check if App Attest is supported
    var isSupported: Bool {
        service.isSupported
    }

    // Generate attestation key
    func generateKey() async throws -> String

    // Create attestation
    func attestKey(
        keyId: String,
        challenge: Data
    ) async throws -> Data

    // Generate assertion for authenticated requests
    func generateAssertion(
        keyId: String,
        clientData: Data
    ) async throws -> Data
}
```

### 6. Define API Models

**APIModels.swift:**
Based on `vault-services-api.yaml`, create Swift structs:

```swift
// Enrollment
struct EnrollStartRequest: Codable { ... }
struct EnrollStartResponse: Codable { ... }
struct AttestationRequest: Codable { ... }
struct AttestationResponse: Codable { ... }
struct SetPasswordRequest: Codable { ... }
struct SetPasswordResponse: Codable { ... }
struct FinalizeRequest: Codable { ... }
struct FinalizeResponse: Codable { ... }

// Credentials
struct CredentialBlob: Codable {
    let userGuid: String
    let encryptedBlob: Data
    let ephemeralPublicKey: Data
    let cekVersion: Int
}

struct LAT: Codable {
    let token: String
    let version: Int
}

struct TransactionKey: Codable {
    let keyId: String
    let publicKey: Data
    let algorithm: String
    let createdAt: Date
}
```

### 7. Create API Client

**VaultServiceClient.swift:**
```swift
import Foundation

class VaultServiceClient {
    private let baseURL: URL
    private let session: URLSession

    init(baseURL: URL) { ... }

    // Enrollment
    func enrollStart(request: EnrollStartRequest) async throws -> EnrollStartResponse
    func submitAttestation(request: AttestationRequest) async throws -> AttestationResponse
    func setPassword(request: SetPasswordRequest) async throws -> SetPasswordResponse
    func finalizeEnrollment(request: FinalizeRequest) async throws -> FinalizeResponse

    // Private helpers
    private func request<T: Decodable, R: Encodable>(
        method: String,
        path: String,
        body: R?
    ) async throws -> T
}
```

### 8. Create Unit Tests

**CryptoUtilsTests.swift:**
```swift
import XCTest
@testable import VettID

class CryptoUtilsTests: XCTestCase {
    func testKeyPairGeneration()
    func testEncryptDecryptRoundtrip()
    func testKeyDerivation()
    func testSharedSecretDerivation()
}
```

**CredentialStoreTests.swift:**
```swift
import XCTest
@testable import VettID

class CredentialStoreTests: XCTestCase {
    func testStoreAndRetrieveCredentialBlob()
    func testStoreLAT()
    func testTransactionKeyManagement()
    func testClearCredentials()
}
```

## Acceptance Criteria

- [ ] iOS project builds successfully in Xcode
- [ ] CryptoUtils generates valid X25519 keys
- [ ] Encryption/decryption roundtrip works
- [ ] CredentialStore securely stores data in Keychain
- [ ] DeviceAttestation compiles (runtime testing on device)
- [ ] Unit tests pass
- [ ] API models match OpenAPI spec

## Reporting

When complete:
1. Update `cdk/coordination/status/ios.json`:
   ```json
   {
     "instance": "ios",
     "phase": 0,
     "task": "iOS project scaffold complete",
     "status": "completed",
     "completedTasks": ["Project structure", "Crypto utils", "Credential store", "API models", "Unit tests"],
     "lastUpdated": "<current timestamp>"
   }
   ```

2. Document any issues in `cdk/coordination/results/issues/`

## Notes

- Target iOS 15.0+ for App Attest support
- Use SwiftUI for all views
- Use async/await for API calls
- CryptoKit provides X25519 and Curve25519
- For XChaCha20-Poly1305, use swift-sodium or libsodium wrapper
- App Attest requires a physical device to test (not simulator)
- Use @MainActor for UI updates
- Follow Apple Human Interface Guidelines
