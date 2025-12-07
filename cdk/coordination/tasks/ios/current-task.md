# Task: Create iOS Project in Dedicated Repository

## Phase
Phase 0: Foundation & Coordination Setup

## Assigned To
iOS Instance

## IMPORTANT: Repository Location

**The iOS app must be created in a separate, dedicated repository.**

| Item | Value |
|------|-------|
| **Repository** | `github.com/mesmerverse/vettid-ios` |
| **Coordination Repo** | `github.com/mesmerverse/vettid-dev` |

## Setup Steps

### 1. Clone the iOS Repository

```bash
git clone https://github.com/mesmerverse/vettid-ios.git
cd vettid-ios
```

### 2. Clone vettid-dev for Specifications

```bash
# In a separate directory
git clone https://github.com/mesmerverse/vettid-dev.git
```

Reference these specs while building:
- `vettid-dev/cdk/coordination/specs/vault-services-api.yaml` - API endpoints
- `vettid-dev/cdk/coordination/specs/credential-format.md` - Crypto operations
- `vettid-dev/cdk/coordination/specs/nats-topics.md` - NATS structure
- `vettid-dev/cdk/docs/DEVELOPMENT_PLAN.md` - Overall plan

## Deliverables

### 1. Create iOS Project Structure

Create a new Xcode project in `vettid-ios/`:

```
vettid-ios/
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
- Enable Keychain sharing

**Dependencies (Swift Package Manager):**

```swift
dependencies: [
    .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
]
```

Or use CryptoKit (built-in) for X25519 operations.

### 3. Implement Core Crypto Utilities

**CryptoUtils.swift:**
```swift
import CryptoKit

enum CryptoUtils {
    static func generateX25519KeyPair() -> (publicKey: Data, privateKey: Data)
    static func deriveSharedSecret(privateKey: Data, publicKey: Data) -> Data
    static func encrypt(plaintext: Data, key: Data) throws -> EncryptedData
    static func decrypt(encrypted: EncryptedData, key: Data) throws -> Data
    static func deriveKey(sharedSecret: Data, info: String) -> Data
}
```

### 4. Implement Credential Storage

**CredentialStore.swift:**
```swift
class CredentialStore {
    func storeCredentialBlob(_ blob: CredentialBlob) throws
    func getCredentialBlob() throws -> CredentialBlob?
    func storeLAT(_ lat: LAT) throws
    func getLAT() throws -> LAT?
    func storeTransactionKeys(_ keys: [TransactionKey]) throws
    func getUnusedTransactionKey() throws -> TransactionKey?
    func markTransactionKeyUsed(_ keyId: String) throws
    func clear() throws
}
```

### 5. Implement App Attest

**DeviceAttestation.swift:**
```swift
import DeviceCheck

class DeviceAttestation {
    var isSupported: Bool { DCAppAttestService.shared.isSupported }
    func generateKey() async throws -> String
    func attestKey(keyId: String, challenge: Data) async throws -> Data
    func generateAssertion(keyId: String, clientData: Data) async throws -> Data
}
```

### 6. Define API Models

Based on `vault-services-api.yaml`, create Swift Codable structs.

### 7. Create Unit Tests

- `CryptoUtilsTests.swift`
- `CredentialStoreTests.swift`

## Workflow for Status Updates

After completing work, update status in `vettid-dev`:

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 0 complete"
git push
```

## Acceptance Criteria

- [ ] iOS project created in `vettid-ios` repository
- [ ] CryptoUtils generates valid X25519 keys
- [ ] Encryption/decryption roundtrip works
- [ ] CredentialStore securely stores data in Keychain
- [ ] DeviceAttestation compiles (runtime testing on device)
- [ ] Unit tests pass
- [ ] API models match OpenAPI spec
- [ ] Status updated in `vettid-dev`

## Notes

- Target iOS 15.0+ for App Attest support
- Use SwiftUI for all views
- Use async/await for API calls
- CryptoKit provides X25519 and Curve25519
- For XChaCha20-Poly1305, use swift-sodium
- App Attest requires a physical device (not simulator)
- Use @MainActor for UI updates
