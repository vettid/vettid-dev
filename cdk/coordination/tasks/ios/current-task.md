# Task: Phase 1 - Enrollment Flow Implementation

## Phase
Phase 1: Protean Credential System - Core

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 0 complete. Project scaffold created with crypto, storage, and attestation. Ready for Phase 1.

## Phase 1 iOS Tasks

### 1. Enrollment Flow UI

Implement the complete enrollment flow screens using SwiftUI:

```swift
// VettID/Sources/Enrollment/
EnrollmentView.swift          // Main enrollment container
QRScannerView.swift           // Scan invitation QR code
AttestationView.swift         // App Attest progress
PasswordSetupView.swift       // Password creation with strength meter
EnrollmentCompleteView.swift  // Success confirmation
```

**Flow:**
1. User scans QR code containing invitation code
2. App requests attestation challenge from backend
3. App performs App Attest attestation
4. User creates password (min 12 chars, strength indicator)
5. App encrypts password with transaction key
6. Backend returns credential blob and LAT
7. App stores credential blob in Keychain

### 2. Update VaultServiceClient

Ensure API client matches `vault-services-api.yaml`:

```swift
// VettID/Sources/API/
VaultServiceClient.swift

protocol VaultServiceProtocol {
    func enrollStart(inviteCode: String, deviceInfo: DeviceInfo) async throws -> EnrollStartResponse
    func submitAttestation(sessionId: String, attestation: AttestationData) async throws -> AttestationResponse
    func setPassword(sessionId: String, encryptedPassword: Data, keyId: String) async throws -> SetPasswordResponse
    func finalize(sessionId: String) async throws -> FinalizeResponse
    func actionRequest(userGuid: String, actionType: ActionType) async throws -> ActionResponse
    func authExecute(actionId: String, signature: Data) async throws -> AuthExecuteResponse
}
```

### 3. Enrollment State Management

```swift
// VettID/Sources/Enrollment/
EnrollmentViewModel.swift

@MainActor
class EnrollmentViewModel: ObservableObject {
    @Published var state: EnrollmentState = .initial

    enum EnrollmentState {
        case initial
        case scanningQR(error: String?)
        case attesting(progress: Double)
        case settingPassword(strength: PasswordStrength)
        case finalizing(progress: Double)
        case complete(userGuid: String)
        case error(message: String, retryable: Bool)
    }

    func startEnrollment(inviteCode: String) async
    func submitAttestation() async
    func setPassword(_ password: String) async
    func finalize() async
}
```

### 4. Transaction Key Encryption

Implement client-side encryption using transaction keys:

```swift
// In CryptoManager.swift, add:
func encryptWithTransactionKey(
    plaintext: Data,
    transactionKeyPublicKey: Data
) throws -> EncryptedPayload

struct EncryptedPayload {
    let ciphertext: Data
    let ephemeralPublicKey: Data
    let nonce: Data
}
```

### 5. QR Code Scanner

Implement camera-based QR scanning:

```swift
// VettID/Sources/Enrollment/
QRScannerView.swift

struct QRScannerView: View {
    @Binding var scannedCode: String?
    var onCodeScanned: (String) -> Void

    // Use AVFoundation for camera access
    // Parse QR code for invitation code format
}
```

### 6. Unit Tests

Add tests for new functionality:

```swift
// VettIDTests/
EnrollmentViewModelTests.swift    // State transitions
VaultServiceClientTests.swift     // API contract tests
TransactionKeyEncryptionTests.swift  // Crypto operations
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
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 1 enrollment flow complete"
git push
```

## Notes

- App Attest requires physical device (not simulator)
- Use async/await for all API calls
- Use @MainActor for all UI updates
- Follow Apple Human Interface Guidelines for UI
- Camera permission required for QR scanning

## Acceptance Criteria

- [ ] QR scanner captures invitation code
- [ ] App Attest completes successfully (on device)
- [ ] Password encryption uses transaction keys correctly
- [ ] Credential blob stored in Keychain
- [ ] LAT stored for future authentication
- [ ] All unit tests pass
- [ ] UI follows iOS design guidelines
