# VettID Mobile Development Progress Review

**Date:** 2025-12-14
**Reviewer:** Lead Developer

---

## Executive Summary

Both Android and iOS apps have made excellent progress on core functionality but have diverged from the planned navigation architecture. The apps are functional for enrollment and basic vault operations but need alignment with the UI/UX plan for the drawer + contextual bottom nav pattern and several missing screens.

---

## Implementation Status Comparison

### Phase Completion Overview

| Phase | Description | Android | iOS | Plan |
|-------|-------------|---------|-----|------|
| **Phase 1** | Project Setup & Core Navigation | ✅ | ✅ | Drawer + Bottom Nav |
| **Phase 2** | Enrollment Flow | ✅ | ✅ | Complete |
| **Phase 3** | Vault Services | ✅ | ✅ | Complete |
| **Phase 4** | Vault Credential & Core | ⚠️ Partial | ⚠️ Partial | Missing screens |
| **Phase 5** | Connections & Messaging | ✅ | ✅ | Complete |
| **Phase 6** | Feed & Secrets | ❌ | ❌ | Not implemented |
| **Phase 7** | Voice/Video Calling | ❌ | ❌ | Not implemented |
| **Phase 8** | Polish & App Settings | ⚠️ Partial | ⚠️ Partial | Backup done, settings minimal |

### Source File Counts

| Platform | Files | Lines (approx) |
|----------|-------|----------------|
| Android | 103 Kotlin files | ~15,000 |
| iOS | 108 Swift files | ~14,000 |

---

## Critical Deviations from Plan

### 1. Navigation Architecture (HIGH PRIORITY)

**Planned (mobile-ui-plan.md Section 2):**
```
┌─────────────────────────────────────────┐
│ (👤) Section Title           [+ Action] │  ← Profile avatar opens drawer
├─────────────────────────────────────────┤
│              [Content]                  │
├─────────────────────────────────────────┤
│  Item 1 │ Item 2 │ Item 3 │ ••• More    │  ← Context-specific bottom nav
└─────────────────────────────────────────┘
```

**Android Current:**
```
┌─────────────────────────────────────────┐
│                                         │
│              [Content]                  │
│                                         │
├─────────────────────────────────────────┤
│ Vault │ Connections │ Handlers │ Profile │  ← Static 4-tab nav
└─────────────────────────────────────────┘
```

**iOS Current:**
```
┌─────────────────────────────────────────┐
│                                         │
│              [Content]                  │
│                                         │
├─────────────────────────────────────────┤
│    Vault    │  Credentials  │ Settings  │  ← Static 3-tab nav
└─────────────────────────────────────────┘
```

**Issue:** Neither app implements:
- Profile avatar that opens drawer
- Three-section organization (App Settings | Vault Services | Vault)
- Contextual bottom navigation that changes per section
- Swipe-to-open drawer gesture

### 2. Missing Screens (MEDIUM PRIORITY)

**Planned but not implemented in either app:**

| Screen | Section | Description |
|--------|---------|-------------|
| **Feed** | Vault | Activity feed with events, messages, auth requests |
| **Secrets** | Vault | Top secrets with 30-second reveal, password auth |
| **Personal Data** | Vault | Public/private data management |
| **Archive** | Vault | Archived items with bulk delete |
| **Preferences** | Vault | TTL settings, Event Handlers, archive rules |

### 3. Bottom Nav Mismatch

**Plan specifies for Vault section:**
```
│ Connections │ Feed │ ••• │
```

**Android has:**
```
│ Vault │ Connections │ Handlers │ Profile │
```

**iOS has:**
```
│ Vault │ Credentials │ Settings │
```

### 4. App State Distinction

**Plan:** Active = Vault Deployed + Vault Credential Created

**Current:** Both apps conflate "enrolled" with "active" and don't distinguish:
- Vault services credential (for API auth)
- Vault credential (for vault data access)

---

## What's Working Well

### Both Platforms

1. **Enrollment Flow** ✅
   - QR code scanning
   - Manual code entry
   - Password setup with validation
   - Argon2id hashing
   - X25519 key exchange
   - Credential storage

2. **Authentication** ✅
   - Biometric unlock (Face ID / Fingerprint)
   - Password fallback
   - Session management

3. **NATS Integration** ✅
   - WebSocket connection
   - Token refresh (background tasks)
   - Message subscription

4. **Connections & Messaging** ✅
   - Connection list
   - Create/scan invitations
   - Connection detail view
   - Conversation UI
   - E2E encrypted messaging

5. **Backup System** ✅
   - Backup list
   - Backup settings
   - Credential backup with BIP-39
   - Recovery phrase management

6. **Security** ✅
   - RASP (jailbreak/root detection)
   - Secure memory handling
   - Certificate pinning (iOS)
   - Request signing

7. **Handler System** ✅
   - Handler discovery
   - Handler detail view
   - Handler execution

---

## Platform-Specific Notes

### Android Strengths
- Hardware attestation with StrongBox support
- Comprehensive test coverage (CryptoManager, CredentialStore)
- Well-organized feature modules
- VettID tower icon implemented

### Android Gaps
- AuthenticationScreen is placeholder (just a button)
- Main screen tabs show placeholder content
- No drawer implementation

### iOS Strengths
- Clean SwiftUI architecture
- Proper state machine for enrollment flow
- Well-structured Features directory
- Good error handling in enrollment

### iOS Gaps
- CredentialsView is placeholder
- SettingsView is placeholder list
- No drawer implementation
- Tab icons don't match plan (uses building.columns instead of tower)

---

## Updated Guidance

### Priority 1: Navigation Architecture Refactor

Both developers should implement the drawer + contextual bottom nav pattern:

**Required Components:**
1. **DrawerView** - Slides in from left, shows profile + section nav
2. **HeaderView** - Profile avatar (left), title (center), action button (right)
3. **ContextualBottomNav** - Changes based on current section
4. **Section State Management** - Track which section (App | Services | Vault)

**Section Navigation:**
```kotlin
// Android
enum class AppSection {
    APP_SETTINGS,      // Bottom nav: Theme | Security | About
    VAULT_SERVICES,    // Bottom nav: Status | Backups | Manage
    VAULT              // Bottom nav: Connections | Feed | •••
}
```

```swift
// iOS
enum AppSection {
    case appSettings   // Bottom nav: Theme | Security | About
    case vaultServices // Bottom nav: Status | Backups | Manage
    case vault         // Bottom nav: Connections | Feed | •••
}
```

### Priority 2: Implement Missing Vault Screens

**Feed Screen:**
- Event list (messages, connection requests, auth requests)
- Event type renderers
- Action buttons per event
- Search/filter capability

**Secrets Screen:**
- Secret list with lock icons
- Add secret flow
- View secret requires PASSWORD (not biometrics)
- 30-second auto-hide timer

**Personal Data Screen:**
- Sections: Public, Private, Keys, Minor Secrets
- Add/edit data items
- Type-specific input forms

**Archive Screen:**
- List archived items
- Selection mode for bulk operations
- Restore/delete actions

### Priority 3: Fix App State Model

```kotlin
// Android - Update AppState
data class AppState(
    val enrollmentStatus: EnrollmentStatus,  // UNENROLLED, ENROLLED, ACTIVE
    val hasVaultServicesCredential: Boolean,
    val hasVaultCredential: Boolean,
    val vaultStatus: VaultStatus,
    val lastVaultAuthAt: Instant?,
    val vaultTtlMinutes: Int = 15
)

enum class EnrollmentStatus {
    UNENROLLED,  // No vault services credential
    ENROLLED,    // Has vault services credential
    ACTIVE       // Has vault services credential + vault deployed + vault credential
}
```

### Priority 4: Voice/Video Calling (Phase 7)

Per `e2ee-key-exchange-architecture.md`:
1. Integrate WebRTC library
2. Implement ECDH key exchange via MessageSpace
3. Set up FrameCryptor for E2EE
4. Build call UI (voice and video screens)
5. Add encryption status indicator

---

## Recommended Next Steps

### Android Developer

1. **Immediate:**
   - Implement DrawerView component
   - Add HeaderView with profile avatar
   - Create section-aware bottom nav

2. **Short-term:**
   - Implement Feed screen with event list
   - Implement Secrets screen with password auth
   - Connect AuthenticationScreen to actual biometric flow

3. **Medium-term:**
   - Implement Personal Data screen
   - Implement Archive screen
   - Add Voice/Video calling (Phase 7)

### iOS Developer

1. **Immediate:**
   - Implement DrawerView (slide-over)
   - Add HeaderView with profile avatar
   - Create section-aware TabView alternative

2. **Short-term:**
   - Implement Feed screen
   - Implement Secrets screen (password only, no biometrics)
   - Replace CredentialsView placeholder

3. **Medium-term:**
   - Implement Personal Data screen
   - Implement Archive screen
   - Add Voice/Video calling (Phase 7)
   - Update vault icon to tower (🏰) instead of building.columns

---

## File References

### Plan Documents
- `/home/al/Sites/vettid-scaffold-with-gsi/cdk/coordination/mobile-ui-plan.md`
- `/home/al/Sites/vettid-scaffold-with-gsi/cdk/coordination/mobile-dev-coordination.md`
- `/home/al/Sites/vettid-scaffold-with-gsi/cdk/coordination/e2ee-key-exchange-architecture.md`

### Android Source
- `/home/al/Sites/vettid-android/app/src/main/java/com/vettid/app/VettIDApp.kt`
- `/home/al/Sites/vettid-android/app/src/main/java/com/vettid/app/features/`

### iOS Source
- `/home/al/Sites/vettid-ios/VettID/App/ContentView.swift`
- `/home/al/Sites/vettid-ios/VettID/Features/`

---

*Document End*
