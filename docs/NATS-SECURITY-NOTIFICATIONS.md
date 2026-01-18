# NATS-Based Real-Time Security Notifications

## Overview

This document describes the implementation of NATS-based real-time security notifications for both Android and iOS platforms, replacing the need for Firebase Cloud Messaging (FCM) or Apple Push Notification Service (APNs).

**Covers:**
- Issue #33: NATS notifications with foreground service (replacing Firebase/APNs)
- Issue #31: Device-to-device credential transfer
- Issue #32: Recovery fraud detection (auto-cancel on credential use)

## Why NATS Instead of FCM/APNs?

| Aspect | NATS | FCM/APNs |
|--------|------|----------|
| Privacy | VettID controls entire stack | Google/Apple sees metadata |
| GrapheneOS | Works without Play Services | Requires Play Services (FCM) |
| Dependency | Existing infrastructure | Additional service integration |
| Real-time | Direct connection | May have delays |
| Offline | Foreground service (Android) | Works when app killed |

**Trade-off:** NATS requires an active connection, which we maintain via:
- Android: Foreground service with persistent notification
- iOS: Hybrid approach (NATS in foreground + BGTask fallback)

## Current State

### Android (Existing Infrastructure)
- **VaultProtectionService** - Foreground service already handles NATS notifications
- **VaultEvent** - Has RecoveryRequested, RecoveryCancelled, RecoveryCompleted
- **OwnerSpaceClient** - Full NATS pub/sub implementation
- **Notification channels** - Security alerts channel exists

### iOS (Existing Infrastructure)
- **NatsConnectionManager** - Full NATS orchestration
- **OwnerSpaceClient** - Vault communication
- **BGTaskScheduler** - Token refresh every 6 hours
- **PushKit** - VoIP only, no standard push notifications

## Architecture

### Notification Flow
```
Vault Enclave
     │
     ▼ (publishes to NATS)
{OwnerSpace}.forApp.security.*
     │
     ├──► Android: VaultProtectionService (foreground)
     │         └── Local notification
     │
     └──► iOS: VaultSecurityService + BGTask
               └── Local notification
```

### NATS Topics

| Topic | Direction | Purpose |
|-------|-----------|---------|
| `{OwnerSpace}.forApp.recovery.requested` | Vault → App | Recovery initiated |
| `{OwnerSpace}.forApp.recovery.cancelled` | Vault → App | Recovery cancelled |
| `{OwnerSpace}.forApp.recovery.completed` | Vault → App | Recovery completed elsewhere |
| `{OwnerSpace}.forApp.transfer.requested` | Vault → App | Transfer request from new device |
| `{OwnerSpace}.forApp.transfer.approved` | Vault → App | Transfer approved |
| `{OwnerSpace}.forApp.transfer.denied` | Vault → App | Transfer denied |
| `{OwnerSpace}.forApp.transfer.completed` | Vault → App | Transfer finished |
| `{OwnerSpace}.forApp.transfer.expired` | Vault → App | Transfer timed out |
| `{OwnerSpace}.forApp.security.fraud_detected` | Vault → App | Fraud auto-cancelled recovery |

### Event Types

```
VaultEvent:
  // Recovery events
  - RecoveryRequested(requestId, email)
  - RecoveryCancelled(requestId, reason?)
  - RecoveryCompleted(requestId)

  // Transfer events
  - TransferRequested(transferId, sourceDevice, targetDevice)
  - TransferApproved(transferId)
  - TransferDenied(transferId)
  - TransferCompleted(transferId)
  - TransferExpired(transferId)

  // Fraud detection
  - RecoveryFraudDetected(requestId, reason, detectedAt)
```

---

## Feature: Device-to-Device Transfer (Issue #31)

Allows instant credential transfer between a user's own devices, bypassing the 24-hour recovery delay.

### Flow

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│  New Device │                    │    Vault    │                    │  Old Device │
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │ 1. Request Transfer              │                                  │
       │─────────────────────────────────►│                                  │
       │                                  │                                  │
       │                                  │ 2. Publish TransferRequested     │
       │                                  │─────────────────────────────────►│
       │                                  │                                  │
       │                                  │                                  │ 3. Show notification
       │                                  │                                  │    + approval screen
       │                                  │                                  │
       │                                  │ 4. Approve (with biometric)      │
       │                                  │◄─────────────────────────────────│
       │                                  │                                  │
       │ 5. TransferCompleted             │                                  │
       │◄─────────────────────────────────│                                  │
       │                                  │                                  │
       │ 6. Receive encrypted credential  │                                  │
       │◄─────────────────────────────────│                                  │
```

### Security Requirements

- **15-minute timeout** - Transfer expires if not approved
- **Biometric required** - Old device must authenticate to approve
- **Device attestation** - Both devices verified via attestation
- **Single use** - Transfer token can only be used once
- **Audit logging** - All transfer attempts logged

### API Endpoints

```
POST /vault/credentials/transfer/request
{
  "target_device_id": "<new device id>",
  "target_attestation": "<device attestation>"
}
Response: { "transfer_id": "uuid", "expires_at": "timestamp" }

POST /vault/credentials/transfer/approve
{
  "transfer_id": "uuid",
  "approved": true,
  "source_attestation": "<old device attestation>"
}

POST /vault/credentials/transfer/deny
{
  "transfer_id": "uuid"
}
```

---

## Feature: Recovery Fraud Detection (Issue #32)

Automatically cancels pending recovery if the original credential is used during the 24-hour waiting period.

### Flow

```
1. Attacker requests recovery for victim's credentials
2. 24-hour waiting period begins
3. Victim uses their credential (authentication, vault operation)
4. System detects credential usage during pending recovery
5. Recovery automatically cancelled
6. Victim notified: "Recovery cancelled - your credential was used"
7. Audit log: "recovery_fraud_detected"
```

### Detection Logic (Backend)

```python
def on_credential_used(user_id, device_id):
    pending_recovery = get_pending_recovery(user_id)
    if pending_recovery and pending_recovery.device_id != device_id:
        cancel_recovery(pending_recovery.id, reason="credential_used")
        notify_user(user_id, "recovery_cancelled_fraud_detected")
        audit_log("recovery_fraud_detected", user_id, pending_recovery.id)
```

### Grace Period

5-minute grace period after recovery request to allow:
- User testing if their credential still works
- Accidental taps during recovery request

---

## Android Implementation

### Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `core/nats/OwnerSpaceClient.kt` | Modify | Add transfer/fraud VaultEvent types |
| `core/notifications/VaultProtectionService.kt` | Modify | Handle transfer & fraud notifications |
| `features/transfer/TransferModels.kt` | Create | Transfer data models |
| `features/transfer/TransferViewModel.kt` | Create | Transfer business logic |
| `features/transfer/TransferRequestScreen.kt` | Create | New device UI |
| `features/transfer/TransferApprovalScreen.kt` | Create | Old device approval UI |
| `VettIDApp.kt` | Modify | Add transfer routes & deep links |

### VaultProtectionService Extensions

```kotlin
// New notification IDs
const val TRANSFER_ALERT_NOTIFICATION_ID = 1002
const val FRAUD_ALERT_NOTIFICATION_ID = 1003

private fun handleVaultEvent(event: VaultEvent) {
    when (event) {
        is VaultEvent.TransferRequested -> {
            showTransferRequestAlert(event.transferId, event.targetDeviceInfo)
        }
        is VaultEvent.RecoveryFraudDetected -> {
            showFraudDetectedNotification(event.requestId, event.reason)
        }
        // ...
    }
}
```

### Deep Links

| Deep Link | Action |
|-----------|--------|
| `vettid://transfer/approve?id=X` | Open transfer approval screen |
| `vettid://transfer/request` | Open transfer request screen |
| `vettid://recovery/status` | Open recovery status screen |

---

## iOS Implementation

### Hybrid Notification Approach

Since iOS doesn't have foreground services:

1. **App in foreground** - Direct NATS subscription via VaultSecurityService
2. **App in background** - BGAppRefreshTask checks for missed events
3. **App terminated** - Events queued on server, delivered on next app launch

### Files to Create

| File | Description |
|------|-------------|
| `Core/NATS/VaultEvent.swift` | Event type definitions |
| `Core/NATS/VaultSecurityService.swift` | Security event handling |
| `Core/Notifications/LocalNotificationManager.swift` | Local notification handling |
| `Features/Transfer/TransferModels.swift` | Transfer data models |
| `Features/Transfer/TransferViewModel.swift` | Transfer business logic |
| `Features/Transfer/TransferRequestView.swift` | New device UI |
| `Features/Transfer/TransferApprovalView.swift` | Old device approval UI |

### VaultSecurityService

```swift
class VaultSecurityService {
    private let ownerSpaceClient: OwnerSpaceClient
    private let notificationManager: LocalNotificationManager

    func startMonitoring() async {
        for await event in ownerSpaceClient.securityEvents {
            await handleSecurityEvent(event)
        }
    }

    private func handleSecurityEvent(_ event: VaultEvent) async {
        switch event {
        case .recoveryRequested(let requestId, let email):
            await notificationManager.showRecoveryAlert(requestId: requestId, email: email)
        case .transferRequested(let transferId, let deviceInfo):
            await notificationManager.showTransferAlert(transferId: transferId, device: deviceInfo)
        case .recoveryFraudDetected(let requestId, let reason):
            await notificationManager.showFraudAlert(requestId: requestId, reason: reason)
        }
    }
}
```

### LocalNotificationManager

```swift
class LocalNotificationManager {
    func requestPermission() async -> Bool
    func showRecoveryAlert(requestId: String, email: String?) async
    func showTransferAlert(transferId: String, device: DeviceInfo) async
    func showFraudAlert(requestId: String, reason: String) async
    func dismissAlert(identifier: String)
}
```

---

## Notification Content

### Recovery Requested
```
Title: "Recovery Requested"
Body: "Someone requested to recover your credentials for {email}.
       If this wasn't you, tap Cancel immediately."
Actions: [Cancel Recovery] [View Details]
```

### Transfer Requested
```
Title: "Credential Transfer Request"
Body: "{Device Model} is requesting your credentials.
       This request expires in 15 minutes."
Actions: [Approve] [Deny]
```

### Recovery Fraud Detected
```
Title: "Recovery Auto-Cancelled"
Body: "A recovery request was cancelled because your credential was used.
       This may indicate an unauthorized recovery attempt."
Actions: [View Details]
```

---

## Security Considerations

1. **E2E Encryption** - All NATS messages encrypted with session keys
2. **Device Attestation** - Transfers bound to attested devices
3. **Biometric Required** - Transfer approval requires biometric/PIN
4. **Timeouts** - 15-minute transfer timeout, 5-minute fraud grace period
5. **Audit Logging** - All security events logged for review
6. **Single Use Tokens** - Transfer tokens invalidated after use

---

## Testing

### Android
```bash
# Build
./gradlew assembleDebug

# Test deep link
adb shell am start -d "vettid://transfer/approve?id=test-123"

# Simulate NATS event (via test harness)
# Verify notification appears with correct actions
```

### iOS
```bash
# Build
xcodebuild -scheme VettID -destination 'platform=iOS Simulator,name=iPhone 15'

# Test deep link
xcrun simctl openurl booted "vettid://transfer/approve?id=test-123"

# Verify local notification permissions
# Verify notification actions work
```

### Cross-Platform
1. Initiate transfer from iOS, approve on Android
2. Initiate transfer from Android, approve on iOS
3. Test timeout behavior (15 minutes)
4. Test fraud detection by using credential during pending recovery

---

## Related Documents

- [NATS Messaging Architecture](./NATS-MESSAGING-ARCHITECTURE.md)
- [Vault Voting Design](./vault-voting-design.md) - Similar NATS patterns
- [Protean Credential System](./protean_credential_system_design.md)
