# VettID Mobile Development Coordination Plan

**Version:** 1.0
**Created:** 2025-12-14
**Status:** Ready for Implementation

---

## 1. Overview

This document outlines the coordination strategy for developing the VettID mobile applications (Android and iOS) using Claude Code instances as developers. Development will be coordinated via GitHub issues and a shared task tracking system.

### 1.1 Repositories

| Platform | Repository | Primary Language |
|----------|------------|------------------|
| Android | `github.com/anthropics/vettid-android` | Kotlin |
| iOS | `github.com/anthropics/vettid-ios` | Swift |
| Shared Docs | `github.com/anthropics/vettid-scaffold-with-gsi` | - |

### 1.2 Reference Documents

- **UI/UX Specification:** `cdk/coordination/mobile-ui-plan.md`
- **E2EE Architecture:** `cdk/coordination/e2ee-key-exchange-architecture.md`
- **Backend API:** VettID API (URL available from CDK stack outputs)

---

## 2. Development Phases

### Phase 1: Project Setup & Core Navigation (Week 1)

**Goal:** Establish project structure and implement drawer + contextual bottom nav pattern.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 1.1 | Initialize project with recommended architecture (MVVM) | Yes | Yes |
| 1.2 | Set up dependency injection (Hilt/Koin for Android, native for iOS) | Yes | Yes |
| 1.3 | Implement secure credential storage (Keystore/Keychain) | Yes | Yes |
| 1.4 | Create navigation framework with drawer + bottom nav | Yes | Yes |
| 1.5 | Implement app state management (Unenrolled/Enrolled/Active) | Yes | Yes |
| 1.6 | Create theme system (light/dark/auto) | Yes | Yes |
| 1.7 | Implement base screen templates with header pattern | Yes | Yes |

**Deliverables:**
- App launches with Welcome screen
- Drawer opens from avatar tap or swipe
- Bottom nav changes based on section
- Theme switching works

---

### Phase 2: Enrollment Flow (Week 2)

**Goal:** Complete QR code enrollment and vault services credential creation.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 2.1 | Implement Welcome screen UI | Yes | Yes |
| 2.2 | Add QR code scanner (CameraX/AVFoundation) | Yes | Yes |
| 2.3 | Parse and validate enrollment QR payload | Yes | Yes |
| 2.4 | Implement password setup screen with validation | Yes | Yes |
| 2.5 | Integrate Argon2id password hashing | Yes | Yes |
| 2.6 | Implement X25519 key exchange for password encryption | Yes | Yes |
| 2.7 | Call enrollment API endpoints | Yes | Yes |
| 2.8 | Store vault services credential securely | Yes | Yes |
| 2.9 | Implement first authentication flow | Yes | Yes |
| 2.10 | Handle deep links (vettid://, https://vettid.dev/enroll/*) | Yes | Yes |

**API Endpoints:**
- `POST /vault/enroll/authenticate`
- `POST /vault/enroll/start`
- `POST /vault/enroll/set-password`
- `POST /vault/enroll/finalize`

**Deliverables:**
- User can scan QR and complete enrollment
- Password validated (12+ chars, visual match)
- Credential stored securely
- Deep links open enrollment flow

---

### Phase 3: Vault Services Section (Week 3)

**Goal:** Implement vault status, deployment, and backup management.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 3.1 | Implement Vault Services Status screen | Yes | Yes |
| 3.2 | Show vault status (none/provisioning/running/stopped) | Yes | Yes |
| 3.3 | Implement Deploy Vault confirmation dialog | Yes | Yes |
| 3.4 | Create deployment progress UI with steps | Yes | Yes |
| 3.5 | Call vault provisioning APIs | Yes | Yes |
| 3.6 | Implement Manage Vault screen (stop/restart/terminate) | Yes | Yes |
| 3.7 | Implement Backups screen | Yes | Yes |
| 3.8 | Add credential backup/restore functionality | Yes | Yes |
| 3.9 | Handle vault status polling/updates | Yes | Yes |

**API Endpoints:**
- `GET /vault/status`
- `POST /vault/nats/account`
- `POST /vault/provision`
- `POST /vault/initialize`
- `POST /vault/stop`
- `POST /vault/terminate`

**Deliverables:**
- User can view vault status
- User can deploy new vault
- Progress shown during deployment
- Stop/restart/terminate work
- Backups can be created/restored

---

### Phase 4: Vault Credential & Core Vault (Week 4)

**Goal:** Implement vault credential enrollment and preferences.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 4.1 | Detect first vault access and trigger credential enrollment | Yes | Yes |
| 4.2 | Implement vault credential password setup | Yes | Yes |
| 4.3 | Implement vault authentication screen | Yes | Yes |
| 4.4 | Create Preferences screen | Yes | Yes |
| 4.5 | Implement TTL settings | Yes | Yes |
| 4.6 | Implement Event Handler management UI | Yes | Yes |
| 4.7 | Implement archive settings (archive after X days, delete after Y days) | Yes | Yes |
| 4.8 | Create Personal Data screen with sections | Yes | Yes |
| 4.9 | Implement add/edit personal data items | Yes | Yes |
| 4.10 | Auto-populate name/email from membership | Yes | Yes |

**Deliverables:**
- Vault credential created on first access
- Vault authentication works
- Preferences configurable
- Personal data can be added/edited

---

### Phase 5: Connections & Messaging (Week 5)

**Goal:** Implement connection management and basic messaging.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 5.1 | Implement Connections list screen | Yes | Yes |
| 5.2 | Implement Connection Detail view | Yes | Yes |
| 5.3 | Add tap (detail) and long-press (actions) interactions | Yes | Yes |
| 5.4 | Implement New Connection screen | Yes | Yes |
| 5.5 | Generate and display connection QR code | Yes | Yes |
| 5.6 | Implement connection invitation via email/SMS | Yes | Yes |
| 5.7 | Handle incoming connection requests | Yes | Yes |
| 5.8 | Implement accept/decline connection flow | Yes | Yes |
| 5.9 | Create basic messaging UI | Yes | Yes |
| 5.10 | Integrate with MessageSpace for message delivery | Yes | Yes |

**Deliverables:**
- Connections list with search
- Connection details viewable
- QR code connection works
- Invitations can be sent/received
- Basic messaging functional

---

### Phase 6: Feed & Secrets (Week 6)

**Goal:** Implement activity feed and top secrets management.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 6.1 | Implement Feed screen with event list | Yes | Yes |
| 6.2 | Create event type renderers (message, connection, auth request) | Yes | Yes |
| 6.3 | Implement event actions (reply, accept, approve, etc.) | Yes | Yes |
| 6.4 | Add feed filtering | Yes | Yes |
| 6.5 | Implement Secrets screen | Yes | Yes |
| 6.6 | Create add secret flow | Yes | Yes |
| 6.7 | Implement view secret with password auth | Yes | Yes |
| 6.8 | Add 30-second auto-hide for revealed secrets | Yes | Yes |
| 6.9 | Implement Archive screen | Yes | Yes |
| 6.10 | Add archive selection and bulk delete | Yes | Yes |

**Deliverables:**
- Feed shows all events
- Events actionable
- Secrets can be added
- Secrets require password to view
- Archive works with selection mode

---

### Phase 7: Voice/Video Calling (Week 7)

**Goal:** Implement E2EE voice and video calling.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 7.1 | Integrate WebRTC library | Yes | Yes |
| 7.2 | Implement call initiation UI | Yes | Yes |
| 7.3 | Implement incoming call UI | Yes | Yes |
| 7.4 | Integrate with vault key exchange handler | Yes | Yes |
| 7.5 | Implement ECDH key exchange via MessageSpace | Yes | Yes |
| 7.6 | Set up FrameCryptor for E2EE | Yes | Yes |
| 7.7 | Implement voice call screen | Yes | Yes |
| 7.8 | Implement video call screen | Yes | Yes |
| 7.9 | Add call controls (mute, speaker, camera flip) | Yes | Yes |
| 7.10 | Show encryption status indicator | Yes | Yes |

**Deliverables:**
- Voice calls work with E2EE
- Video calls work with E2EE
- Key exchange transparent to user
- Lock icon shows encryption status

---

### Phase 8: Polish & App Settings (Week 8)

**Goal:** Complete remaining features and polish.

**Tasks:**

| ID | Task | Android | iOS |
|----|------|---------|-----|
| 8.1 | Implement App Settings section | Yes | Yes |
| 8.2 | Add Theme screen (auto/light/dark) | Yes | Yes |
| 8.3 | Implement Security screen (app lock) | Yes | Yes |
| 8.4 | Add PIN setup/change | Yes | Yes |
| 8.5 | Implement biometric authentication | Yes | Yes |
| 8.6 | Create About screen | Yes | Yes |
| 8.7 | Implement sign-out flow with context options | Yes | Yes |
| 8.8 | Add error handling and retry logic | Yes | Yes |
| 8.9 | Implement loading states and skeletons | Yes | Yes |
| 8.10 | Final UI polish and accessibility | Yes | Yes |

**Deliverables:**
- All settings functional
- App lock works (PIN and/or biometrics)
- Sign-out has context options
- Error handling complete
- Polished UI throughout

---

## 3. GitHub Coordination

### 3.1 Labels

Create these labels in both repositories:

| Label | Color | Description |
|-------|-------|-------------|
| `phase-1` | #0E8A16 | Phase 1: Project Setup & Navigation |
| `phase-2` | #1D76DB | Phase 2: Enrollment Flow |
| `phase-3` | #5319E7 | Phase 3: Vault Services |
| `phase-4` | #D93F0B | Phase 4: Vault Credential & Core |
| `phase-5` | #FBCA04 | Phase 5: Connections & Messaging |
| `phase-6` | #B60205 | Phase 6: Feed & Secrets |
| `phase-7` | #006B75 | Phase 7: Voice/Video Calling |
| `phase-8` | #C2E0C6 | Phase 8: Polish & Settings |
| `blocked` | #D73A4A | Blocked by dependency |
| `api-needed` | #F9D0C4 | Needs backend API work |
| `in-progress` | #0075CA | Currently being worked on |
| `ready-for-review` | #7057FF | Ready for code review |

### 3.2 Issue Template

```markdown
## Task: [Task Name]

**Phase:** [Phase Number]
**Task ID:** [e.g., 2.3]
**Platform:** [Android/iOS/Both]

### Description
[Clear description of what needs to be built]

### Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

### UI Reference
See `mobile-ui-plan.md` section [X.X]

### API Endpoints
- `METHOD /endpoint` - Description

### Dependencies
- [List any blocking dependencies]

### Notes
[Any additional context or considerations]
```

### 3.3 Branch Naming

```
feature/phase-X-task-description
bugfix/issue-number-description
```

### 3.4 PR Template

```markdown
## Summary
[Brief description of changes]

## Related Issue
Closes #[issue number]

## Changes Made
- Change 1
- Change 2

## Screenshots
[If UI changes, include before/after screenshots]

## Testing
- [ ] Tested on device/emulator
- [ ] Edge cases handled
- [ ] No regressions introduced

## Checklist
- [ ] Code follows project style guide
- [ ] Self-reviewed code
- [ ] Added necessary comments
- [ ] Updated documentation if needed
```

---

## 4. Communication Protocol

### 4.1 Task Files

Each developer maintains a current task file in their repo:

**Location:** `docs/current-task.md`

**Format:**
```markdown
# Current Task

**Task ID:** 2.3
**Status:** In Progress
**Started:** 2025-12-14

## What I'm Working On
[Description]

## Progress
- [x] Step 1
- [ ] Step 2
- [ ] Step 3

## Blockers
[Any blockers or questions]

## Questions for Lead
[Questions that need answers]
```

### 4.2 Sync Points

At the end of each task:
1. Update `current-task.md`
2. Commit and push changes
3. Create PR if feature complete
4. Update GitHub issue status

### 4.3 Cross-Platform Coordination

For features that need parity:
1. Android implements first (reference implementation)
2. iOS follows same patterns
3. Both update shared documentation if API changes needed

---

## 5. Technical Standards

### 5.1 Architecture

**Android:**
- MVVM with Repository pattern
- Kotlin Coroutines for async
- Hilt for DI
- Jetpack Compose for UI
- Retrofit for networking

**iOS:**
- MVVM with Combine
- Swift Concurrency (async/await)
- SwiftUI for UI
- URLSession with async for networking

### 5.2 Security Requirements

- All credentials stored in secure storage (Keystore/Keychain)
- No sensitive data in logs
- Certificate pinning for API calls
- Biometric authentication uses system APIs only
- Password never stored, only derived keys

### 5.3 Code Quality

- Meaningful variable/function names
- Comments for complex logic
- Error handling for all API calls
- Loading states for async operations
- Accessibility labels for UI elements

---

## 6. API Integration Notes

### 6.1 Authentication

All authenticated endpoints require JWT in Authorization header:
```
Authorization: Bearer <jwt_token>
```

### 6.2 Common Response Handling

```kotlin
// Android example
sealed class ApiResult<T> {
    data class Success<T>(val data: T) : ApiResult<T>()
    data class Error<T>(val message: String, val code: Int) : ApiResult<T>()
}
```

```swift
// iOS example
enum ApiResult<T> {
    case success(T)
    case failure(Error)
}
```

### 6.3 WebSocket/NATS Integration

MessageSpace communication uses NATS over WebSocket:
- Connection URL provided after vault deployment
- Credentials stored in vault services credential
- Auto-reconnect on disconnect

---

## 7. Testing Strategy

### 7.1 Test Accounts

| Email | Purpose |
|-------|---------|
| `android-test@vettid.dev` | Android development testing |
| `ios-test@vettid.dev` | iOS development testing |

### 7.2 Test Scenarios

Each phase includes test scenarios in the GitHub issues.

### 7.3 Manual Testing Checklist

Before marking a phase complete:
- [ ] All features work on physical device
- [ ] Works in airplane mode gracefully
- [ ] Handles API errors gracefully
- [ ] No memory leaks
- [ ] No ANRs/hangs
- [ ] Theme switching works
- [ ] Rotation handled (if supported)

---

## Appendix A: Key Data Structures

### AppState
```kotlin
data class AppState(
    val isEnrolled: Boolean,
    val hasActiveVault: Boolean,
    val vaultStatus: VaultStatus,
    val lastAuthAt: Instant?,
    val ttlMinutes: Int = 15
)

enum class VaultStatus {
    NONE, PROVISIONING, RUNNING, STOPPED, TERMINATED
}
```

### PersonalDataItem
```kotlin
data class PersonalDataItem(
    val id: String,
    val name: String,
    val type: DataType,
    val value: Any,
    val isSystemField: Boolean,
    val createdAt: Instant,
    val updatedAt: Instant
)

enum class DataType {
    PUBLIC, PRIVATE, KEY, MINOR_SECRET
}
```

### FeedEvent
```kotlin
data class FeedEvent(
    val id: String,
    val type: EventType,
    val title: String,
    val body: String,
    val sender: ConnectionInfo?,
    val actions: List<EventAction>,
    val createdAt: Instant,
    val readAt: Instant?,
    val archivedAt: Instant?
)
```

---

*Document End*
