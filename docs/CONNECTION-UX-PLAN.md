# Connection UX Improvement Plan

## Status: Connections & Messaging Working (2026-03-15)

Core flow is functional: QR scan → invite resolve → profile preview → accept →
key exchange → active → encrypted messaging with vault-side encryption/decryption.

This plan covers all remaining UX issues, grouped by priority.

---

## Priority 1: Connection Detail & Profile Display

### 1.1 Full Public Profile in Connection Detail
**Current**: Connection detail shows only photo + name + action icons.
**Target**: Show the peer's full cached public profile (like a contact card):
- Photo (large, top)
- Name, email
- All public fields from their published profile (emergency contact, custom fields, etc.)
- Grouped by category (Identity, Contact, Medical, etc.)

**Changes**:
- `ConnectionDetailScreen.kt`: Render `peerProfile.fields` grouped by category below the name/photo header
- `ConnectionDetailViewModel.kt`: Already has `peerProfile` from `connection.list` response
- Reuse the `ProfileCategorySection` composable from `PersonalDataScreen.kt`

### 1.2 Manage Connection Section
**Current**: Connection info, location sharing, rotate keys, revoke are shown inline.
**Target**: Move management options to a collapsible section or separate "Manage" card at the bottom of the profile view.
- Connection info (created date, status, key exchange date)
- Share my location toggle
- Rotate keys button
- Revoke connection button (destructive, at bottom)

**Changes**:
- `ConnectionDetailScreen.kt`: Restructure layout — profile at top, management card at bottom

### 1.3 Profile Photo in Review Dialog
**Current**: Inviter's review dialog sometimes missing photo.
**Target**: Always show photo when available.

**Changes**:
- Verify `loadPublishedProfileForPeer` includes photo from vault storage
- The photo is stored at `profile/_photo` — confirm it's loaded in the acceptance notification

---

## Priority 2: Messaging UX

### 2.1 Fixed Header in Conversation
**Current**: Peer name and back button scroll off the top.
**Target**: Fixed header bar with peer name and back button.

**Changes**:
- `ConversationScreen.kt`: Use `Scaffold` with `topBar` containing the peer name + back button, message list in scrollable content area below

### 2.2 First Message Delivery Timing
**Current**: First message may not deliver if sent before peer's key exchange completes.
**Target**: Disable send button until connection status is `active` with `e2e_ready: true`.

**Changes**:
- `ConversationViewModel.kt`: Check connection status before allowing send
- Show "Waiting for encryption setup..." if keys not ready

---

## Priority 3: Invitation Flow Polish

### 3.1 Invitation Timer
**Current**: User can select expiration time (15min, 1hr, 24hr) but the INVITATIONS stream has a 5-minute TTL, so only 5 minutes actually works.
**Target**: Remove the time selector, show "Valid for 5 minutes" on the QR screen.

**Changes**:
- `CreateInvitationScreen.kt`: Remove expiration selector
- Show countdown timer or "Scan within 5 minutes" text
- `CreateInvitationViewModel.kt`: Hardcode 5-minute expiration

### 3.2 Inviter Notification While on QR Screen
**Current**: Inviter has to leave the QR screen to see the accept dialog.
**Target**: When the peer accepts, the QR screen should show a notification or auto-transition.

**Changes**:
- `CreateInvitationViewModel.kt`: Listen for `connection.peer-accepted` events
- Transition to a "Connection request received" state with accept/decline options

### 3.3 Scanner Auto-Navigate After Accept
**Current**: Scanner sees "Continue" button after accepting.
**Target**: Auto-navigate to connections list.

**Changes**: Already partially fixed — verify `NavigateToConnection` effect fires reliably

---

## Priority 4: Security Hardening

### 4.1 App-to-Vault Message Encryption
**Current**: Plaintext `content` sent over NATS to vault (protected by NATS JWT auth but not E2E encrypted between app and vault).
**Target**: Export a derived messaging key from vault to app, app encrypts before sending.

**Changes**:
- Add `connection.get-messaging-key` vault handler — returns HKDF-derived key (different from shared secret)
- App stores key locally, encrypts messages before sending to vault
- Vault decrypts with same derived key, re-encrypts with connection shared secret for peer

### 4.2 Connection Status Enforcement
**Current**: Messages can be sent to "pending" connections.
**Target**: Only allow messaging on "active" connections.

**Changes**: Already enforced in vault's `HandleSend` (checks `conn.Status != "active"`)

---

## Priority 5: Previously Tabled Issues

### 5.1 Photo Upload Vsock EOF
- Large photo uploads cause vsock disconnect between parent and enclave
- 16KB chunking partially mitigates but not fully resolved
- Need to investigate vsock buffer limits on Nitro

### 5.2 Secrets Metadata Display
- Secrets (passwords, keys) metadata not showing correctly in the app

### 5.3 Session TTL
- Session timeout handling needs fixing

### 5.4 Backup Status Display
- Credential backup status not showing correctly

### 5.5 Missing RequestID in Vault-Manager
- `messages.go` forOwner ack (lines 468-471) missing RequestID

### 5.6 Diagnostic Logging Cleanup
- Remove debug logging from `parent/vsock_client.go` and `supervisor/vsock.go`

---

## Implementation Order

**Phase 1** (App-only, no deploy):
- 2.1 Fixed conversation header
- 3.1 Invitation timer (5 min display)
- 1.2 Manage connection section layout

**Phase 2** (App-only):
- 1.1 Full public profile display
- 3.3 Scanner auto-navigate verification

**Phase 3** (Backend + App):
- 1.3 Profile photo in review dialog
- 3.2 Inviter notification on QR screen
- 2.2 First message timing guard

**Phase 4** (Security):
- 4.1 App-to-vault message encryption

**Phase 5** (Maintenance):
- 5.1-5.6 Previously tabled issues
