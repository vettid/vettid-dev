# Task: Phase 2 - App Attest Integration

## Phase
Phase 2: Device Attestation

## Assigned To
iOS Instance

## Repository
`github.com/mesmerverse/vettid-ios`

## Status
Phase 1 complete. Ready for Phase 2 attestation integration.

## IMPORTANT: API Change

The enrollment flow has changed. The backend now requires attestation verification as a separate step.

**New Flow:**
1. `POST /vault/enroll/start` - Returns `attestation_challenge`
2. `POST /vault/enroll/attestation/ios` - Submit attestation object
3. `POST /vault/enroll/set-password` - Set password (only after attestation verified)
4. `POST /vault/enroll/finalize` - Complete enrollment

## Phase 2 iOS Tasks

### 1. Update VaultServiceClient

Add the new attestation endpoint:

```swift
// VaultService.swift

struct EnrollStartRequest: Codable {
    let invitation_code: String
    let device_id: String
    let device_type: String  // NEW: must be "ios"
}

struct EnrollStartResponse: Codable {
    let enrollment_session_id: String
    let user_guid: String
    let attestation_challenge: String  // NEW: challenge for attestation
    let attestation_endpoint: String   // NEW: "/vault/enroll/attestation/ios"
    let transaction_keys: [TransactionKey]
    let next_step: String  // "attestation_required"
}

struct IosAttestationRequest: Codable {
    let enrollment_session_id: String
    let attestation_object: String  // Base64-encoded CBOR
    let key_id: String              // From generateKey()
}

struct AttestationResponse: Codable {
    let status: String         // "attestation_verified"
    let device_type: String
    let security_level: String
    let next_step: String      // "password_required"
    let password_key_id: String
}

// Add to VaultService:
func submitIosAttestation(_ request: IosAttestationRequest) async throws -> AttestationResponse
```

### 2. Implement App Attest

Create attestation using DCAppAttestService:

```swift
// Core/Attestation/AppAttestManager.swift

import DeviceCheck

@available(iOS 14.0, *)
class AppAttestManager {
    private let attestService = DCAppAttestService.shared

    /// Check if App Attest is supported on this device
    var isSupported: Bool {
        attestService.isSupported
    }

    /// Generate a new attestation key
    func generateKey() async throws -> String {
        try await attestService.generateKey()
    }

    /// Create attestation with the backend's challenge
    func attestKey(keyId: String, challenge: Data) async throws -> Data {
        // Hash the challenge with SHA256 as required by Apple
        let clientDataHash = SHA256.hash(data: challenge)
        let hashData = Data(clientDataHash)

        return try await attestService.attestKey(keyId, clientDataHash: hashData)
    }
}

struct AppAttestResult {
    let keyId: String
    let attestationObject: Data  // CBOR-encoded
}
```

### 3. Update EnrollmentViewModel

Add attestation step to state machine:

```swift
enum EnrollmentState {
    case initial
    case scanningQR(error: String?)
    case startingEnrollment(inviteCode: String)
    case attesting(challenge: String, progress: Float)  // NEW
    case attestationFailed(error: String)               // NEW
    case settingPassword(strength: PasswordStrength)
    case finalizing(progress: Float)
    case complete(userGuid: String)
    case error(message: String, retryable: Bool)
}

// In ViewModel:
@MainActor
func submitAttestation(challenge: String) async {
    state = .attesting(challenge: challenge, progress: 0.2)

    do {
        // Generate attestation key
        let keyId = try await appAttestManager.generateKey()

        state = .attesting(challenge: challenge, progress: 0.4)

        // Create attestation with challenge
        guard let challengeData = Data(base64Encoded: challenge) else {
            throw AttestationError.invalidChallenge
        }

        let attestationObject = try await appAttestManager.attestKey(
            keyId: keyId,
            challenge: challengeData
        )

        state = .attesting(challenge: challenge, progress: 0.7)

        // Submit to backend
        let response = try await vaultService.submitIosAttestation(
            IosAttestationRequest(
                enrollment_session_id: sessionId,
                attestation_object: attestationObject.base64EncodedString(),
                key_id: keyId
            )
        )

        if response.status == "attestation_verified" {
            passwordKeyId = response.password_key_id
            state = .settingPassword(strength: .none)
        } else {
            state = .attestationFailed(error: "Attestation rejected by server")
        }

    } catch {
        state = .attestationFailed(error: error.localizedDescription)
    }
}
```

### 4. Create AttestationView

Show attestation progress and handle failures:

```swift
struct AttestationView: View {
    let state: EnrollmentState
    let onRetry: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 64))
                .foregroundColor(.blue)

            Text("Verifying Device Security")
                .font(.title2)
                .fontWeight(.semibold)

            if case .attesting(_, let progress) = state {
                ProgressView(value: progress)
                    .progressViewStyle(.linear)
                    .padding(.horizontal, 40)

                Text("Generating device attestation...")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if case .attestationFailed(let error) = state {
                Text(error)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding()

                Button("Try Again", action: onRetry)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}
```

### 5. Handle Unsupported Devices

App Attest requires iOS 14+ and specific hardware:

```swift
func startEnrollment(inviteCode: String) async {
    // Check App Attest support early
    if #available(iOS 14.0, *) {
        guard AppAttestManager().isSupported else {
            state = .error(
                message: "This device does not support secure attestation. A newer device is required.",
                retryable: false
            )
            return
        }
    } else {
        state = .error(
            message: "iOS 14.0 or later is required for secure enrollment.",
            retryable: false
        )
        return
    }

    // Continue with enrollment...
}
```

### 6. Unit Tests

Add attestation tests:

```swift
class AppAttestManagerTests: XCTestCase {
    func testIsSupported_returnsBoolean()
    func testGenerateKey_createsValidKeyId()
    func testAttestKey_withValidChallenge_returnsData()
    func testAttestKey_withInvalidKeyId_throws()
}

class EnrollmentViewModelTests: XCTestCase {
    func testState_transitionsToAttesting_afterEnrollmentStart()
    func testState_transitionsToSettingPassword_afterAttestationVerified()
    func testState_transitionsToAttestationFailed_onRejection()
    func testState_showsError_whenDeviceUnsupported()
}
```

## Key References (in vettid-dev)

Pull latest from vettid-dev:
- `cdk/lambda/common/attestation.ts` - Backend attestation verification
- `cdk/lambda/handlers/attestation/verifyIosAttestation.ts` - iOS handler
- `cdk/coordination/specs/vault-services-api.yaml` - Updated API spec

## Apple Documentation

- [App Attest](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity)
- [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice)

## Acceptance Criteria

- [ ] App Attest generates attestation with backend challenge
- [ ] Key ID properly stored for future assertions
- [ ] EnrollmentViewModel handles attestation state transitions
- [ ] AttestationView shows progress and errors
- [ ] Graceful handling for unsupported devices (iOS < 14, simulators)
- [ ] Unit tests pass
- [ ] Integration with backend verified on physical device

## Status Update

```bash
cd /path/to/vettid-dev
git pull
# Edit cdk/coordination/status/ios.json
git add cdk/coordination/status/ios.json
git commit -m "Update iOS status: Phase 2 attestation complete"
git push
```
