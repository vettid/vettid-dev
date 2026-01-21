# VettID Mobile App UI/UX Plan

**Version:** 1.2
**Last Updated:** 2025-12-14
**Status:** Draft - Pending Review

---

## Table of Contents

1. [Overview](#1-overview)
2. [App States & Navigation](#2-app-states--navigation)
3. [Screen Specifications](#3-screen-specifications)
4. [User Flows](#4-user-flows)
5. [Data Models](#5-data-models)
6. [API Integration](#6-api-integration)
7. [Security Requirements](#7-security-requirements)
8. [Coordination & Development](#8-coordination--development)

---

## 1. Overview

### 1.1 Purpose

This document defines the UI/UX specifications for the VettID mobile applications (Android and iOS). It serves as the authoritative guide for development teams implementing the mobile clients.

### 1.2 App Hierarchy

The app has three main states based on user progression:

```
UNENROLLED → ENROLLED (Vault Services) → ACTIVE (Vault Deployed + Credential Created)
```

| State | Description | Default Landing | Authentication Required |
|-------|-------------|-----------------|------------------------|
| Unenrolled | No vault services credential | Welcome Screen | None |
| Enrolled | Has vault services credential | Vault Services | Yes (unless within 15-min TTL) |
| Active | Vault deployed AND vault credential created | Vault Feed | Only for sensitive actions |

**Note:** A user is only considered "Active" when they have both:
1. Successfully deployed their vault instance
2. Created their vault credential (separate from vault services credential)

### 1.3 Navigation Architecture (Summary)

The app uses a **Drawer + Contextual Bottom Nav** pattern:

```
┌─────────────────────────────────────────┐
│ (👤) Section Title           [+ Action] │  ← Profile avatar opens drawer
├─────────────────────────────────────────┤
│                                         │
│              [Content]                  │
│                                         │
├─────────────────────────────────────────┤
│  Item 1 │ Item 2 │ Item 3 │ ••• More    │  ← Context-specific bottom nav
└─────────────────────────────────────────┘
```

**Key Features:**
- **Profile Avatar (top-left):** Opens drawer for section switching and user profile
- **Header Action (top-right):** Context-aware primary action button
- **Bottom Nav:** Changes based on current section (not static)
- **Swipe Gestures:** Swipe from left edge for drawer, swipe content for tab switching

See [Section 2](#2-app-states--navigation) for detailed navigation specifications.

### 1.4 Main Sections (Post-Enrollment)

Once enrolled, users have access to three main sections via the drawer:

| Section | Icon | Description |
|---------|------|-------------|
| **App Settings** | Gear | App preferences, lock settings, about |
| **Vault Services** | Cloud | Deploy vault, manage instance, backups |
| **Vault** | Tower | Personal data, secrets, connections, feed |

---

## 2. App States & Navigation

### 2.1 Navigation Architecture

The app uses a **Drawer + Contextual Bottom Nav** pattern:
- **Profile Avatar (top-left)** opens drawer for section switching
- **Bottom Nav** shows contextual items for the current section
- **Header Action (top-right)** provides context-aware primary action

```
┌─────────────────────────────────────────┐
│ (👤) Section Title           [+ Action] │  ← Avatar opens drawer
├─────────────────────────────────────────┤
│                                         │
│              [Content]                  │
│                                         │
├─────────────────────────────────────────┤
│  Item 1 │ Item 2 │ Item 3 │ ••• More    │  ← Contextual nav
└─────────────────────────────────────────┘
```

### 2.2 Drawer Content

The drawer shows user profile, section navigation, and quick settings:

```
┌─────────────────────────────────────────┐
│  ┌───────┐                              │
│  │       │  Jane Smith                   │
│  │  👤   │  jane@example.com            │
│  │       │  ✓ Vault Active              │  ← Status indicator
│  └───────┘                              │
├─────────────────────────────────────────┤
│                                         │
│  🏰 Vault                               │  ← Current section (highlighted)
│  ☁️  Vault Services                     │
│  ⚙️  App Settings                       │
│                                         │
├─────────────────────────────────────────┤
│  Theme: Dark                        ▶   │  ← Quick toggles
│  Notifications                     🔔   │
├─────────────────────────────────────────┤
│  Help & Support                         │
│  Sign Out                           ▶   │  ← Opens sign-out options
└─────────────────────────────────────────┘
```

**Sign-Out Options:**

When tapping "Sign Out", show a bottom sheet with context-aware options:

```
┌─────────────────────────────────────────┐
│           Sign Out                      │
├─────────────────────────────────────────┤
│                                         │
│  Where would you like to sign out?      │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │ 🏰 Sign out of Vault            │    │
│  │ Ends vault session, keeps       │    │
│  │ vault services active           │    │
│  └─────────────────────────────────┘    │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │ ☁️  Sign out of Vault Services  │    │
│  │ Signs out of both vault and     │    │
│  │ vault services                  │    │
│  └─────────────────────────────────┘    │
│                                         │
│  [Cancel]                               │
│                                         │
└─────────────────────────────────────────┘
```

**State-Aware Drawer Options:**

| State | Drawer Sections | Sign Out Shows |
|-------|-----------------|----------------|
| Unenrolled | • Enroll in Vault Services, App Settings | N/A |
| Enrolled (no vault) | • Vault Services, Deploy Your Vault →, App Settings | Vault Services only |
| Active | • Vault, Vault Services, App Settings | Both options |

### 2.3 Contextual Bottom Navigation

The bottom nav changes based on the current section:

**App Settings Section:**
```
│ Theme │ Security │ About │
```

**Vault Services Section:**
```
│ Status │ Backups │ Manage │
```

**Vault Section (2 primary items + overflow):**
```
│ Connections │ Feed │ ••• │
```

**"More" Overflow Menu (Vault):**
- Personal Data
- Secrets
- Archive
- Preferences

### 2.4 Header Actions

The top-right area shows context-aware action buttons. Screens with searchable content show a search icon alongside the primary action.

| Section / Screen | Primary Action | Search |
|------------------|----------------|--------|
| Personal Data | `+ Add` | Yes |
| Secrets | `+ Add` | Yes |
| Connections | `+ Connect` | Yes |
| Feed | `Filter` | Yes |
| Archive | `Select` | Yes |
| Vault Services Status | `Refresh` | No |
| Backups | - | No |

**Search Behavior:**
- Tapping search icon expands to search input field
- Search filters content in real-time
- X button clears search and collapses back to icon

### 2.5 Gesture Support

| Gesture | Action |
|---------|--------|
| Swipe from left edge | Open drawer |
| Swipe left/right on content | Navigate between bottom nav items |
| Long-press on avatar | Quick section picker (optional) |

### 2.6 Navigation Rules

- Drawer accessible from all screens (post-enrollment)
- Bottom nav visible at all times (post-enrollment)
- Badge indicators for pending items (connection requests, unread messages)
- Current bottom nav item highlighted in accent color
- Drawer shows current section with filled indicator
- "Vault" section disabled in drawer until vault is deployed and active

### 2.7 State Transitions

```
┌──────────────┐     Scan QR      ┌──────────────┐
│  UNENROLLED  │ ───────────────► │  ENROLLING   │
│              │                   │              │
│ Welcome      │                   │ Password     │
│ Screen       │                   │ Setup        │
└──────────────┘                   └──────┬───────┘
                                          │
                                          │ Finalize
                                          ▼
┌──────────────┐     Deploy       ┌──────────────┐
│    ACTIVE    │ ◄─────────────── │   ENROLLED   │
│              │                   │              │
│ Vault Feed   │                   │ Vault        │
│ (default)    │                   │ Services     │
└──────────────┘                   └──────────────┘
```

---

## 3. Screen Specifications

### 3.1 Welcome Screen (Unenrolled State)

**Purpose:** First-time user onboarding and enrollment initiation.

**Layout:**
```
┌─────────────────────────────────┐
│                                 │
│         [VettID Logo]           │
│                                 │
│    "Welcome to VettID"          │
│                                 │
│    Your secure personal vault   │
│    for digital identity and     │
│    private communications.      │
│                                 │
│                                 │
│   ┌─────────────────────────┐   │
│   │   [📷] Scan QR Code     │   │
│   └─────────────────────────┘   │
│                                 │
│    Need help? [Learn More]      │
│                                 │
└─────────────────────────────────┘
```

**Components:**
- VettID logo (centered, top third)
- Welcome message and brief description
- Primary CTA: "Scan QR Code" button
- Secondary link: "Learn More" (opens help/FAQ)

**Removed:** Link/URL input option (per requirements)

**Deep Link Support:**
- App should register for `vettid://` and `https://vettid.dev/enroll/*` URLs
- When opened via deep link, skip to enrollment flow with pre-populated session

---

### 3.2 Enrollment Flow Screens

#### 3.2.1 QR Scanner

**Layout:**
```
┌─────────────────────────────────┐
│  ← Back            [?] Help     │
├─────────────────────────────────┤
│                                 │
│   ┌─────────────────────────┐   │
│   │                         │   │
│   │                         │   │
│   │    [Camera Viewfinder]  │   │
│   │                         │   │
│   │    ┌───────────────┐    │   │
│   │    │   Scan Area   │    │   │
│   │    └───────────────┘    │   │
│   │                         │   │
│   └─────────────────────────┘   │
│                                 │
│   Position the QR code from     │
│   your account portal within    │
│   the frame                     │
│                                 │
│   [💡] Toggle Flash             │
│                                 │
└─────────────────────────────────┘
```

**Behavior:**
- Auto-detect and process QR code
- Validate QR payload structure
- Show error toast for invalid QR codes
- On success, transition to password setup

#### 3.2.2 Password Setup

**Layout:**
```
┌─────────────────────────────────┐
│  ← Back                         │
├─────────────────────────────────┤
│                                 │
│   Create Your Vault Password    │
│                                 │
│   This password protects your   │
│   vault services credential.    │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Password                │   │
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│   ✓ At least 12 characters      │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Confirm Password    ✓   │   │  ← ✓ shows when passwords match
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│   ✓ Passwords match             │  ← Visual confirmation
│                                 │
│   ┌─────────────────────────┐   │
│   │      Continue           │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

**Validation:**
- Minimum 12 characters (only requirement)
- Real-time password match indicator:
  - While typing confirm: Show ✓ when passwords match
  - Show ✗ with red border when passwords don't match
  - Continue button disabled until passwords match

**Visual Match States:**
| State | Confirm Field | Message |
|-------|---------------|---------|
| Empty | Normal border | - |
| Typing, no match | Red border | "Passwords don't match" |
| Match | Green border + ✓ | "Passwords match" |

**Processing:**
1. Hash password with Argon2id (client-side)
2. Encrypt hash with transaction key (X25519 + XChaCha20-Poly1305)
3. Submit to `/vault/enroll/set-password`

#### 3.2.3 Enrollment Complete - First Authentication

**Layout:**
```
┌─────────────────────────────────┐
│                                 │
│         [✓ Checkmark]           │
│                                 │
│   Enrollment Successful!        │
│                                 │
│   Your vault services           │
│   credential has been created.  │
│                                 │
│   Please authenticate now to    │
│   verify your enrollment.       │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Password                │   │
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │     Authenticate        │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

**Behavior:**
- Required first authentication to verify enrollment
- On success: Set TTL (15 minutes), navigate to Vault Services
- On failure: Show error, allow retry

---

### 3.3 App Settings Section

**Purpose:** Application-level preferences and settings.

**Bottom Nav Items:** Theme | Security | About

#### 3.3.1 Theme Screen

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Theme                      │
├─────────────────────────────────┤
│                                 │
│   APPEARANCE                    │
│                                 │
│   ┌─────────────────────────┐   │
│   │ ○ Auto (follow system)  │   │
│   ├─────────────────────────┤   │
│   │ ○ Light                 │   │
│   ├─────────────────────────┤   │
│   │ ● Dark                  │   │  ← Selected
│   └─────────────────────────┘   │
│                                 │
│   Preview:                      │
│   ┌─────────────────────────┐   │
│   │  [Theme Preview Card]   │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Theme]  [Security]  [About]   │
└─────────────────────────────────┘
```

#### 3.3.2 Security Screen

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Security                   │
├─────────────────────────────────┤
│                                 │
│   APP LOCK                      │
│   ┌─────────────────────────┐   │
│   │ Enable App Lock  [Toggle]│   │
│   └─────────────────────────┘   │
│                                 │
│   LOCK METHOD                   │
│   ┌─────────────────────────┐   │
│   │ ○ PIN (4-6 digits)      │   │
│   ├─────────────────────────┤   │
│   │ ● Biometrics            │   │
│   ├─────────────────────────┤   │
│   │ ○ Both (bio + PIN)      │   │
│   └─────────────────────────┘   │
│                                 │
│   AUTO-LOCK                     │
│   ┌─────────────────────────┐   │
│   │ Lock after        5 min ▼│   │
│   └─────────────────────────┘   │
│                                 │
│   💡 Recommended: Enable app    │
│   lock for additional security  │
│                                 │
├─────────────────────────────────┤
│  [Theme]  [Security]  [About]   │
└─────────────────────────────────┘
```

#### 3.3.3 About Screen

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) About                      │
├─────────────────────────────────┤
│                                 │
│   ┌─────────────────────────┐   │
│   │      [VettID Logo]      │   │
│   │       Version 1.0.0     │   │
│   └─────────────────────────┘   │
│                                 │
│   LEGAL                         │
│   ┌─────────────────────────┐   │
│   │ Terms of Service   [→]  │   │
│   ├─────────────────────────┤   │
│   │ Privacy Policy     [→]  │   │
│   ├─────────────────────────┤   │
│   │ Open Source Licenses [→]│   │
│   └─────────────────────────┘   │
│                                 │
│   SUPPORT                       │
│   ┌─────────────────────────┐   │
│   │ Help Center        [→]  │   │
│   ├─────────────────────────┤   │
│   │ Contact Support    [→]  │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Theme]  [Security]  [About]   │
└─────────────────────────────────┘
```

---

### 3.4 Vault Services Section

**Purpose:** Manage vault infrastructure (EC2 instance, NATS, backups).

**Bottom Nav Items:** Status | Backups | Manage

#### 3.4.1 Status Screen (No Vault Deployed)

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Vault Services             │
├─────────────────────────────────┤
│                                 │
│   ┌─────────────────────────┐   │
│   │    [Cloud Icon]         │   │
│   │                         │   │
│   │  No Vault Deployed      │   │
│   │                         │   │
│   │  Deploy your personal   │   │
│   │  vault to enable secure │   │
│   │  communications and     │   │
│   │  data management.       │   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │   🚀 Deploy Vault       │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Status]  [Backups]  [Manage]  │
└─────────────────────────────────┘
```

#### 3.4.2 Status Screen (Vault Deployed)

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Vault Services   [Refresh] │
├─────────────────────────────────┤
│                                 │
│   VAULT STATUS                  │
│   ┌─────────────────────────┐   │
│   │ Status      🟢 Running  │   │
│   │ Uptime         2d 14h   │   │
│   │ Instance    i-abc123... │   │
│   │ Region       us-east-1  │   │
│   └─────────────────────────┘   │
│                                 │
│   QUICK ACTIONS                 │
│   ┌─────────────────────────┐   │
│   │ 🔓 Open Vault       [→] │   │
│   │ Access your vault data  │   │
│   └─────────────────────────┘   │
│                                 │
│   RECENT ACTIVITY               │
│   ┌─────────────────────────┐   │
│   │ Last backup: 2h ago     │   │
│   │ Last login: 15m ago     │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Status]  [Backups]  [Manage]  │
└─────────────────────────────────┘
```

#### 3.4.3 Manage Screen

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Manage Vault               │
├─────────────────────────────────┤
│                                 │
│   VAULT CONTROL                 │
│   ┌─────────────────────────┐   │
│   │ ⏸️  Stop Vault          │   │
│   │ Pause without deleting  │   │
│   │                    [→]  │   │
│   └─────────────────────────┘   │
│   ┌─────────────────────────┐   │
│   │ 🔄  Restart Vault       │   │
│   │ Restart the instance    │   │
│   │                    [→]  │   │
│   └─────────────────────────┘   │
│                                 │
│   DANGER ZONE                   │
│   ┌─────────────────────────┐   │
│   │ 🗑️  Terminate Vault     │   │
│   │ Permanently delete      │   │
│   │                    [→]  │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Status]  [Backups]  [Manage]  │
└─────────────────────────────────┘
```

#### 3.4.4 Backups Screen

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Backups                    │
├─────────────────────────────────┤
│                                 │
│   CREDENTIAL BACKUP             │
│   ┌─────────────────────────┐   │
│   │ Backup Credential  [→]  │   │
│   │ Export encrypted copy   │   │
│   └─────────────────────────┘   │
│   ┌─────────────────────────┐   │
│   │ Restore Credential [→]  │   │
│   │ Import from backup      │   │
│   └─────────────────────────┘   │
│                                 │
│   VAULT BACKUPS                 │
│   ┌─────────────────────────┐   │
│   │ Auto-Backup     [Toggle]│   │
│   │ Daily at 2:00 AM        │   │
│   └─────────────────────────┘   │
│                                 │
│   RECENT BACKUPS                │
│   ┌─────────────────────────┐   │
│   │ Dec 14, 2025  2:00 AM   │   │
│   │ Size: 12.4 MB    [···]  │   │
│   ├─────────────────────────┤   │
│   │ Dec 13, 2025  2:00 AM   │   │
│   │ Size: 12.1 MB    [···]  │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│  [Status]  [Backups]  [Manage]  │
└─────────────────────────────────┘
```

#### 3.4.5 Deploy Vault Flow

**Step 1: Confirmation**
```
┌─────────────────────────────────┐
│  ← Back        Deploy Vault     │
├─────────────────────────────────┤
│                                 │
│   Deploy Your Personal Vault    │
│                                 │
│   This will:                    │
│   • Create your MessageSpace    │
│     and OwnerSpace accounts     │
│   • Launch your dedicated       │
│     secure vault                │
│   • Initialize secure storage   │
│     for your data               │
│                                 │
│   Estimated time: 2-3 minutes   │
│                                 │
│   ┌─────────────────────────┐   │
│   │    Begin Deployment     │   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │        Cancel           │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

**Step 2: Deployment Progress**
```
┌─────────────────────────────────┐
│         Deploying Vault         │
├─────────────────────────────────┤
│                                 │
│   ┌─────────────────────────┐   │
│   │    [Spinning Loader]    │   │
│   └─────────────────────────┘   │
│                                 │
│   ✓ Creating secure accounts    │
│   ✓ Launching vault             │
│   ◐ Initializing storage...     │
│   ○ Configuring handlers        │
│   ○ Finalizing setup            │
│                                 │
│   Please wait, this may take    │
│   a few minutes...              │
│                                 │
└─────────────────────────────────┘
```

**Deployment Actions (Backend):**
1. `POST /vault/nats/account` - Create MessageSpace/OwnerSpace accounts
2. `POST /vault/provision` - Launch dedicated vault instance
3. `POST /vault/initialize` - Initialize vault manager
4. Store vault keys/secrets in vault services credential
5. On completion: Auto-redirect to Vault section for credential creation

---

### 3.5 Vault Section

**Purpose:** Personal data management, secrets, connections, and activity feed.

**Bottom Nav Items:** Connections | Feed | ••• (More)

**"More" Menu Contains:** Personal Data, Secrets, Archive, Preferences

**Access Control:**
- Disabled in drawer until vault is deployed AND vault credential created
- First access requires vault credential enrollment
- Subsequent access shows Feed (auth only for sensitive actions)

#### 3.5.1 Vault Credential Enrollment (First Time)

**Triggered:** When user first accesses Vault after deployment.

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Vault Setup                │
├─────────────────────────────────┤
│                                 │
│   Create Your Vault Credential  │
│                                 │
│   This credential authenticates │
│   you directly to your vault    │
│   instance.                     │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Password                │   │
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Confirm Password        │   │
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│                                 │
│   Note: This can be different   │
│   from your vault services      │
│   password.                     │
│                                 │
│   ┌─────────────────────────┐   │
│   │    Create Credential    │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

**Backend:**
- Credential stored in vault's local NATS datastore
- Keys and tokens stored locally on vault instance

#### 3.5.2 Vault Authentication

**Triggered:** First time after vault credential creation.

```
┌─────────────────────────────────┐
│ (👤) Authenticate to Vault      │
├─────────────────────────────────┤
│                                 │
│   Enter your vault password     │
│   to verify your credential.    │
│                                 │
│   ┌─────────────────────────┐   │
│   │ Password                │   │
│   │ ••••••••••••       [👁]│   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │     Authenticate        │   │
│   └─────────────────────────┘   │
│                                 │
│   [Use Biometrics]              │
│                                 │
└─────────────────────────────────┘
```

**On Success:**
- Mark vault as "successfully deployed and active"
- Navigate to Vault Feed (default) or Preferences (first time setup)

#### 3.5.3 Vault Navigation Structure

The Vault section uses the contextual bottom nav pattern:

```
┌─────────────────────────────────┐
│ (👤) Vault - Feed   [🔍][Filter]│  ← Search + contextual action
├─────────────────────────────────┤
│                                 │
│        [Content Area]           │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │  ← Contextual bottom nav
└─────────────────────────────────┘
```

**Bottom Nav Items:**
| Item | Icon | Badge |
|------|------|-------|
| Connections | 👥 | Pending requests count |
| Feed | 🔔 | Unread count |
| ••• (More) | ⋯ | - |

**More Menu:**
```
┌─────────────────────┐
│ 📋 Personal Data    │
│ 🔐 Secrets          │
│ 📦 Archive          │
│ ⚙️  Preferences     │
└─────────────────────┘
```

**Default Tab:** Feed (after initial setup complete)

#### 3.5.4 Vault Preferences

**Accessed via:** More menu → Preferences

**First-time Setup Flow:**
1. TTL Settings
2. Event Handler Management
3. Archive Settings

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Preferences                │
├─────────────────────────────────┤
│                                 │
│   CREDENTIAL SETTINGS           │
│   ┌─────────────────────────┐   │
│   │ Session TTL      15 min ▼│   │
│   │ Time before re-auth     │   │
│   └─────────────────────────┘   │
│   ┌─────────────────────────┐   │
│   │ Change Password    [→]  │   │
│   └─────────────────────────┘   │
│                                 │
│   EVENT HANDLERS                │
│   ┌─────────────────────────┐   │
│   │ Manage Handlers    [→]  │   │
│   │ 3 installed, 2 available│   │
│   └─────────────────────────┘   │
│                                 │
│   ARCHIVE SETTINGS              │
│   ┌─────────────────────────┐   │
│   │ Archive after     7 days▼│   │
│   │ Delete after     30 days▼│   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

#### 3.5.5 Event Handler Management

**Layout:**
```
┌─────────────────────────────────┐
│  ← Back       Event Handlers    │
├─────────────────────────────────┤
│                                 │
│   INSTALLED                     │
│   ┌─────────────────────────┐   │
│   │ 📨 Messaging            │   │
│   │ vettid.messaging.send   │   │
│   │ v1.0.0    [Update][Remove]│  │
│   ├─────────────────────────┤   │
│   │ 👤 Profile Update       │   │
│   │ vettid.profile.update   │   │
│   │ v1.0.0          [Remove]│   │
│   ├─────────────────────────┤   │
│   │ 🔗 Connection Invite    │   │
│   │ vettid.connection.invite│   │
│   │ v1.0.0          [Remove]│   │
│   ├─────────────────────────┤   │
│   │ 🔐 Key Exchange         │   │
│   │ vettid.crypto.keyexchange│  │
│   │ v1.0.0          [Remove]│   │
│   └─────────────────────────┘   │
│                                 │
│   AVAILABLE                     │
│   ┌─────────────────────────┐   │
│   │ 📁 File Sharing         │   │
│   │ vettid.files.share      │   │
│   │ v1.0.0         [Install]│   │
│   ├─────────────────────────┤   │
│   │ 📞 Voice Calls          │   │
│   │ vettid.voice.call       │   │
│   │ v1.0.0         [Install]│   │
│   ├─────────────────────────┤   │
│   │ 📹 Video Calls          │   │
│   │ vettid.video.call       │   │
│   │ v1.0.0         [Install]│   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

**First-time Behavior:**
- System default handlers auto-installed (messaging, profile, connection, key exchange)
- User prompted to review and optionally add more

**Core Event Handlers (Auto-installed):**

| Handler | Purpose | Transparent |
|---------|---------|-------------|
| `vettid.messaging.send` | Process incoming/outgoing messages | Yes |
| `vettid.profile.update` | Sync profile changes to connections | Yes |
| `vettid.connection.invite` | Handle connection requests | Yes |
| `vettid.crypto.keyexchange` | ECDH key exchange for E2EE calls | Yes |

**Transparent Operations:**
These handlers run on the vault and operate transparently to the user. For example, when initiating a voice call:
1. Mobile app sends call initiation request
2. `vettid.crypto.keyexchange` handler automatically:
   - Generates ephemeral ECDH keypair
   - Exchanges public keys with peer's vault
   - Derives shared secret using ECDH + HKDF
3. Call proceeds with E2EE using derived key
4. User never sees the key exchange - it just works

#### 3.5.5.1 E2EE Voice/Video Calling

**How it works:**
Voice and video calls use end-to-end encryption (E2EE) with user-controlled keys. The key exchange is handled automatically by vault event handlers.

**Encryption Layers:**
| Layer | Protection | Key Control |
|-------|------------|-------------|
| User E2EE (AES-GCM) | Your servers, TURN servers, MITM | Users (via vault) |
| SRTP | Network eavesdropping | Auto-negotiated |
| DTLS | Key exchange tampering | Auto-negotiated |

**Call Initiation Flow:**
```
┌──────────────┐                    ┌──────────────┐
│   Alice's    │                    │    Bob's     │
│    Vault     │                    │    Vault     │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │  1. Generate ECDH keypair         │
       │                                   │
       │  2. Send public key ─────────────►│
       │     via MessageSpace              │
       │                                   │  3. Generate ECDH keypair
       │◄───────────────── Send public key │
       │                                   │
       │  4. Derive shared secret          │  4. Derive shared secret
       │     (ECDH + HKDF)                 │     (ECDH + HKDF)
       │                                   │
       └──────────────┬────────────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │  WebRTC call with      │
         │  E2EE frame encryption │
         │  (AES-256-GCM)         │
         └────────────────────────┘
```

**Mobile Implementation:**
- iOS: Uses `RTCFrameCryptor` from WebRTC.framework
- Android: Uses `FrameCryptor` from libwebrtc

**User Experience:**
- User taps call button
- Call connects (key exchange happens in background)
- Lock icon shows call is encrypted
- User can optionally verify Safety Number with peer

#### 3.5.6 Personal Data

**Header Action:** `+ Add Data`

**Data Model:**
```json
{
  "name": "string",
  "type": "public|private|key|minor_secret",
  "properties": {},
  "value": "any"
}
```

**Types:**
| Type | Description | Sharing |
|------|-------------|---------|
| `public` | Shared with all connections | Automatic |
| `private` | Shared with consent/contract | Per-request |
| `key` | Cryptographic keys | Configurable |
| `minor_secret` | Comfortable in NATS | Never shared |

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Personal Data [🔍][+ Add]  │
├─────────────────────────────────┤
│                                 │
│   PUBLIC DATA                   │
│   ┌─────────────────────────┐   │
│   │ First Name        [🔒]  │   │
│   │ Jane                    │   │
│   ├─────────────────────────┤   │
│   │ Last Name         [🔒]  │   │
│   │ Smith                   │   │
│   ├─────────────────────────┤   │
│   │ Email             [🔒]  │   │
│   │ jane@example.com        │   │
│   └─────────────────────────┘   │
│   [🔒] = From membership, locked│
│                                 │
│   PRIVATE DATA                  │
│   ┌─────────────────────────┐   │
│   │ Phone Number      [···] │   │
│   │ +1 555-***-****         │   │
│   ├─────────────────────────┤   │
│   │ Address           [···] │   │
│   │ 123 Main St...          │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

**First-time Setup:**
1. Auto-populate name/email from membership (read-only)
2. Prompt to add common data (phone, address, etc.)
3. Explain data types

#### 3.5.7 Secrets (Top Secrets)

**Accessed via:** More menu → Secrets
**Header Action:** `[🔍] [+ Add]`

**Purpose:** Highly sensitive data requiring password authentication for every access.

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Secrets       [🔍][+ Add]  │
├─────────────────────────────────┤
│                                 │
│   ⚠️ Top Secret Data            │
│   Requires password to view.    │
│   Never shared.                 │
│                                 │
│   ┌─────────────────────────┐   │
│   │ 🔐 BTC Private Key      │   │
│   │ Added: Dec 10, 2025     │   │
│   │ Type: Cryptocurrency    │   │
│   │           [View][Delete]│   │
│   ├─────────────────────────┤   │
│   │ 🔐 Recovery Phrase      │   │
│   │ Added: Dec 8, 2025      │   │
│   │ Type: Seed Phrase       │   │
│   │           [View][Delete]│   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

**View Secret Flow:**
1. User taps "View"
2. Password authentication dialog appears (password only, no biometrics)
3. User enters vault credential password
4. Vault authenticates and retrieves secret from credential
5. Secret revealed for limited time (30 seconds)
6. Auto-hide after timeout

**Important:** Secrets are stored in the vault credential itself, not in the NATS datastore. The vault must authenticate with the user's password to decrypt and retrieve the secret. Biometric authentication is NOT allowed for secrets - password is always required.

#### 3.5.8 Connections

**Header Action:** `[🔍] [+ Connect]`

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Connections [🔍][+ Connect]│
├─────────────────────────────────┤
│                                 │
│   ACTIVE CONNECTIONS (12)       │
│   ┌─────────────────────────┐   │
│   │ 👤 Alice Smith          │   │
│   │ Last message: 2h ago    │   │
│   ├─────────────────────────┤   │
│   │ 👤 Bob Johnson          │   │
│   │ Last message: 1d ago    │   │
│   ├─────────────────────────┤   │
│   │ 👤 Carol Williams       │   │
│   │ Connected: Dec 1, 2025  │   │
│   └─────────────────────────┘   │
│                                 │
│   PENDING (2)                   │
│   ┌─────────────────────────┐   │
│   │ 👤 Dave Brown           │   │
│   │ Awaiting response       │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

**Interaction Patterns:**

| Action | Result |
|--------|--------|
| Tap on connection | Opens Connection Detail view |
| Long-press on connection | Shows action menu (bottom sheet) |

**Long-Press Action Menu:**
```
┌─────────────────────────────────┐
│        Alice Smith              │
├─────────────────────────────────┤
│  💬  Send Message               │
│  📞  Voice Call                 │
│  📹  Video Call                 │
│  👤  View Profile               │
│  🔕  Mute Notifications         │
│  🚫  Remove Connection          │
└─────────────────────────────────┘
```

#### 3.5.8.1 Connection Detail View

**Opened by:** Tapping a connection in the list

**Layout:**
```
┌─────────────────────────────────┐
│  ← Back       Alice Smith       │
├─────────────────────────────────┤
│                                 │
│   ┌─────────────────────────┐   │
│   │         [Avatar]        │   │
│   │       Alice Smith       │   │
│   │    alice@example.com    │   │
│   │    Connected Dec 1, 2025│   │
│   └─────────────────────────┘   │
│                                 │
│   ┌─────────────────────────┐   │
│   │ [💬 Message][📞 Call][📹]│   │
│   └─────────────────────────┘   │
│                                 │
│   PUBLIC PROFILE                │
│   ┌─────────────────────────┐   │
│   │ Location    San Francisco│   │
│   │ Company     Acme Inc     │   │
│   │ Bio         Developer... │   │
│   └─────────────────────────┘   │
│                                 │
│   CONNECTION SETTINGS           │
│   ┌─────────────────────────┐   │
│   │ Notifications      [On] │   │
│   │ Shared Data        [→]  │   │
│   │ Remove Connection  [→]  │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

#### 3.5.9 New Connection

**Layout:**
```
┌─────────────────────────────────┐
│  ← Back      New Connection     │
├─────────────────────────────────┤
│                                 │
│   INVITE SOMEONE                │
│   ┌─────────────────────────┐   │
│   │ 📱 Show QR Code    [→]  │   │
│   │ Let them scan to connect│   │
│   └─────────────────────────┘   │
│   ┌─────────────────────────┐   │
│   │ 📧 Send via Email  [→]  │   │
│   │ Email invitation link   │   │
│   └─────────────────────────┘   │
│   ┌─────────────────────────┐   │
│   │ 💬 Send via SMS    [→]  │   │
│   │ Text invitation link    │   │
│   └─────────────────────────┘   │
│                                 │
│   ACCEPT INVITATION             │
│   ┌─────────────────────────┐   │
│   │ 📷 Scan QR Code    [→]  │   │
│   │ Scan their invitation   │   │
│   └─────────────────────────┘   │
│                                 │
└─────────────────────────────────┘
```

#### 3.5.10 Feed

**Header Action:** `Filter`
**Default Tab:** This is the default screen when entering Vault section

**Purpose:** Central activity stream for events requiring attention.

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Feed        [🔍] [Filter]  │
├─────────────────────────────────┤
│                                 │
│   TODAY                         │
│   ┌─────────────────────────┐   │
│   │ 🔗 Connection Request   │   │
│   │ Eve Wilson wants to     │   │
│   │ connect with you        │   │
│   │ 10:30 AM    [View]      │   │
│   ├─────────────────────────┤   │
│   │ 💬 New Message          │   │
│   │ Alice Smith: "Hey, are  │   │
│   │ you free tomorrow?"     │   │
│   │ 9:15 AM     [Reply]     │   │
│   └─────────────────────────┘   │
│                                 │
│   YESTERDAY                     │
│   ┌─────────────────────────┐   │
│   │ 🔐 Auth Request         │   │
│   │ Service X requested     │   │
│   │ access to your email    │   │
│   │ 3:45 PM [Approve][Deny] │   │
│   ├─────────────────────────┤   │
│   │ 📨 Message from Bob     │   │
│   │ "Thanks for the help!"  │   │
│   │ 11:20 AM    [View]      │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

**Event Types:**
| Type | Icon | Actions |
|------|------|---------|
| Connection Request | 🔗 | Accept, Decline, View Profile |
| Message | 💬 | Reply, View Thread |
| Auth Request | 🔐 | Approve, Deny (requires auth) |
| File Shared | 📁 | Download, Preview |
| Voice/Video Call | 📞/📹 | Answer, Decline |

**Deep Link Handling:**
- Connection invites via email/SMS open directly to feed
- Show connection request event at top

#### 3.5.11 Archive

**Accessed via:** More menu → Archive
**Header Action:** `Select`

**Layout:**
```
┌─────────────────────────────────┐
│ (👤) Archive     [🔍] [Select]  │
├─────────────────────────────────┤
│                                 │
│   DECEMBER 2025                 │
│   ┌─────────────────────────┐   │
│   │ ☐ 💬 Message from Carol │   │
│   │ Dec 5, 2025             │   │
│   ├─────────────────────────┤   │
│   │ ☐ 🔗 Connection: Frank  │   │
│   │ Dec 3, 2025             │   │
│   └─────────────────────────┘   │
│                                 │
│   NOVEMBER 2025                 │
│   ┌─────────────────────────┐   │
│   │ ☐ 💬 Thread with Alice  │   │
│   │ Nov 28, 2025            │   │
│   ├─────────────────────────┤   │
│   │ ☐ 📁 File: report.pdf   │   │
│   │ Nov 15, 2025            │   │
│   └─────────────────────────┘   │
│                                 │
├─────────────────────────────────┤
│   [Connections]  [Feed]  [•••]  │
└─────────────────────────────────┘
```

**Selection Mode Header:**
When items are selected, the header changes:
```
│ (✓) 2 selected   [Delete] [Cancel] │
```

---

## 4. User Flows

### 4.1 Complete Enrollment Flow

```
┌─────────────┐
│   Launch    │
│    App      │
└──────┬──────┘
       │
       ▼
┌─────────────┐     No      ┌─────────────┐
│  Has Vault  │ ──────────► │   Welcome   │
│  Services?  │             │   Screen    │
└──────┬──────┘             └──────┬──────┘
       │ Yes                       │
       │                           │ Scan QR / Deep Link
       ▼                           ▼
┌─────────────┐             ┌─────────────┐
│  Within     │     No      │   Enroll    │
│   TTL?      │ ──────────► │  Password   │
└──────┬──────┘             │   Setup     │
       │ Yes                └──────┬──────┘
       │                           │
       ▼                           ▼
┌─────────────┐             ┌─────────────┐
│  Has Active │     No      │  First      │
│   Vault?    │ ──────────► │   Auth      │
└──────┬──────┘             └──────┬──────┘
       │ Yes                       │
       ▼                           ▼
┌─────────────┐             ┌─────────────┐
│   Vault     │             │   Vault     │
│   Feed      │             │  Services   │
└─────────────┘             └─────────────┘
```

### 4.2 Vault Deployment Flow

```
┌─────────────┐
│   Deploy    │
│   Button    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Confirm   │ ──► Cancel ──► Back to Services
│   Dialog    │
└──────┬──────┘
       │ Confirm
       ▼
┌─────────────────────────────────┐
│   Deployment Progress           │
│   1. Create NATS Account    ✓   │
│   2. Provision Instance     ✓   │
│   3. Initialize Vault       ◐   │
│   4. Store Keys/Secrets     ○   │
│   5. Finalize               ○   │
└──────┬──────────────────────────┘
       │ Complete
       ▼
┌─────────────┐
│   Vault     │
│  Credential │
│   Enroll    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Vault     │
│    Auth     │
└──────┬──────┘
       │ Success
       ▼
┌─────────────┐
│   Vault     │
│ Preferences │
│ (First Time)│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Personal   │
│    Data     │
│   Setup     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Secrets   │
│   (Optional)│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Publish    │
│   Profile   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Connections │
│   Setup     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Vault     │
│    Feed     │
└─────────────┘
```

### 4.3 Connection Request Flow (Incoming)

**Important:** Connections can only be established between active VettID members. Non-members who receive a connection invitation will be prompted to join VettID.

```
┌─────────────────────────────────┐
│  User receives email/SMS with   │
│  connection invitation link     │
└──────┬──────────────────────────┘
       │ Clicks link
       ▼
┌─────────────────────────────────┐
│  Is VettID app installed?       │
└──────┬──────────────────────────┘
       │
       ├─── No ───────────────────────────────────┐
       │                                          ▼
       │                          ┌─────────────────────────────────┐
       │                          │   Web page opens:               │
       │                          │   "Join VettID to Connect"      │
       │                          │                                 │
       │                          │   [Download for iOS]            │
       │                          │   [Download for Android]        │
       │                          │                                 │
       │                          │   Not a member?                 │
       │                          │   [Register at vettid.dev]  →   │
       │                          └─────────────────────────────────┘
       │ Yes
       ▼
┌─────────────┐     No      ┌─────────────────────────────────┐
│  Has Active │ ──────────► │   "Complete Your Setup"         │
│   Vault?    │             │                                 │
└──────┬──────┘             │   You need an active vault to   │
       │                    │   connect with other members.   │
       │                    │                                 │
       │                    │   [Go to Vault Services]        │
       │                    └─────────────────────────────────┘
       │ Yes
       ▼
┌─────────────────────────────────┐
│   Feed with Connection Request  │
│   at top showing:               │
│   - Sender's public profile     │
│   - Accept / Decline buttons    │
└──────┬──────────────────────────┘
       │ Accept
       ▼
┌─────────────────────────────────┐
│   Connection established        │
│   Added to Connections list     │
│   (Key exchange happens         │
│    automatically via handlers)  │
└─────────────────────────────────┘
```

**Non-Member Handling:**
When a non-VettID user receives a connection invitation:
1. Link opens in browser (app not installed)
2. Landing page explains VettID and the invitation
3. Options to download app or register via web
4. After registration and vault setup, they can accept the invitation

---

## 5. Data Models

### 5.1 App State

```typescript
interface AppState {
  // Enrollment state
  isEnrolled: boolean;
  vaultServicesCredential: CredentialPackage | null;
  lastAuthAt: Date | null;
  ttlMinutes: number; // Default: 15

  // Vault state
  hasActiveVault: boolean;
  vaultCredential: VaultCredential | null;
  vaultStatus: 'none' | 'provisioning' | 'running' | 'stopped' | 'terminated';

  // App settings
  theme: 'auto' | 'light' | 'dark';
  appLock: {
    enabled: boolean;
    type: 'pin' | 'biometric' | 'both';
    pin?: string; // Encrypted
  };
  autoLockMinutes: number;
}
```

### 5.2 Personal Data Item

```typescript
interface PersonalDataItem {
  id: string;
  name: string;
  type: 'public' | 'private' | 'key' | 'minor_secret';
  properties: {
    keyType?: 'x25519' | 'ed25519' | 'rsa' | 'other';
    shareable?: boolean;
    category?: string;
    [key: string]: any;
  };
  value: any;
  createdAt: string;
  updatedAt: string;
  isSystemField: boolean; // true for name, email from membership
}
```

### 5.3 Feed Event

```typescript
interface FeedEvent {
  id: string;
  type: 'connection_request' | 'message' | 'auth_request' | 'file_share' | 'call';
  title: string;
  body: string;
  sender?: {
    guid: string;
    displayName: string;
    avatarUrl?: string;
  };
  actions: Array<{
    id: string;
    label: string;
    type: 'primary' | 'secondary' | 'danger';
    requiresAuth: boolean;
  }>;
  createdAt: string;
  readAt?: string;
  archivedAt?: string;
  expiresAt?: string;
}
```

---

## 6. API Integration

### 6.1 Key Endpoints by Flow

**Enrollment:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/vault/enroll/authenticate` | POST | Exchange QR token for JWT |
| `/vault/enroll/start` | POST | Begin enrollment |
| `/vault/enroll/set-password` | POST | Set credential password |
| `/vault/enroll/finalize` | POST | Complete enrollment |

**Vault Services:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/vault/status` | GET | Get vault status |
| `/vault/health` | GET | Get vault health |
| `/vault/nats/account` | POST | Create NATS account |
| `/vault/provision` | POST | Deploy EC2 instance |
| `/vault/initialize` | POST | Initialize vault |
| `/vault/stop` | POST | Stop vault |
| `/vault/terminate` | POST | Terminate vault |

**Authentication:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/vault/action/request` | POST | Request auth action |
| `/vault/auth/execute` | POST | Execute auth |

**Connections:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/connections/invite` | POST | Create invitation |
| `/connections/accept` | POST | Accept invitation |
| `/connections` | GET | List connections |
| `/connections/{id}` | DELETE | Remove connection |

**Messaging:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/messages` | POST | Send message |
| `/connections/{id}/messages` | GET | Get message history |

### 6.2 Deep Link Schema

```
vettid://enroll?token={session_token}
vettid://connect?code={invite_code}
vettid://message?connection={connection_id}
```

HTTPS equivalents:
```
https://vettid.dev/enroll/{session_token}
https://vettid.dev/connect/{invite_code}
```

---

## 7. Security Requirements

### 7.1 Credential Storage

| Platform | Storage Mechanism |
|----------|-------------------|
| Android | Android Keystore (hardware-backed) |
| iOS | iOS Keychain (Secure Enclave) |

**Stored Securely:**
- Vault services credential blob
- Vault credential blob
- Transaction keys
- NATS credentials
- App lock PIN (if set)

### 7.2 Authentication Requirements

| Action | Auth Required |
|--------|---------------|
| View Feed | No (if within TTL) |
| Send Message | No (if within TTL) |
| View Top Secret | Always |
| Approve Auth Request | Always |
| Change Password | Always |
| Deploy/Terminate Vault | Always |
| Access Vault Services (outside TTL) | Always |

### 7.3 TTL Management

- Default TTL: 15 minutes
- TTL refreshed on successful authentication
- App should track `lastAuthAt` and calculate remaining TTL
- Prompt for auth when TTL expired and user attempts protected action

---

## 8. Coordination & Development

### 8.1 Repository Structure

**Android:** `github.com/mesmerverse/vettid-android`
**iOS:** `github.com/mesmerverse/vettid-ios`
**Shared Docs:** `github.com/mesmerverse/vettid-dev` (this plan)

### 8.2 Development Phases

**Phase 1: Core Enrollment**
- Welcome screen
- QR code scanning
- Enrollment flow
- First authentication
- Basic navigation structure

**Phase 2: Vault Services**
- Vault Services section
- Deploy vault flow
- Stop/terminate vault
- Basic backup management

**Phase 3: Vault Core**
- Vault credential enrollment
- Preferences
- Personal data management
- Secrets management

**Phase 4: Connections & Messaging**
- Connection management
- Create/accept invitations
- Basic messaging

**Phase 5: Feed & Archive**
- Feed implementation
- Event handling
- Archive management
- Deep link handling

**Phase 6: Polish**
- App lock (PIN/biometrics)
- Theme support
- Error handling refinement
- Performance optimization

### 8.3 GitHub Coordination

**Branch Strategy:**
- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - Feature branches
- `bugfix/*` - Bug fixes

**PR Requirements:**
- Link to relevant issue/task
- Screenshots for UI changes
- Test coverage for new features
- Code review required

**Issue Labels:**
- `android` - Android-specific
- `ios` - iOS-specific
- `api` - Backend API related
- `ui` - UI/UX related
- `phase-1` through `phase-6` - Development phase

### 8.4 Testing Coordination

A dedicated testing instance will:
- Execute test plans against both platforms
- Report issues via GitHub
- Verify fixes before merge
- Perform regression testing

---

## Appendix A: Account Portal Changes

The web account portal needs updates to align with mobile:

1. **Vault Status Section:**
   - Show "Not Enrolled" if no credential exists
   - Show "Enrolled - Deploy Vault" if enrolled but no vault
   - Show vault status only when vault exists

2. **QR Code Generation:**
   - Add "Send Link via Email" button
   - Email contains deep link for mobile app

3. **Remove:** Enrollment progress UI (handled by mobile)

---

## Appendix B: Backend API Changes Needed

1. **Email Link Endpoint:**
   - `POST /vault/enroll/send-link` - Send enrollment link via email

2. **Profile Auto-Population:**
   - Include `first_name`, `last_name`, `email` in enrollment response
   - Mark as `isSystemField: true`

3. **Vault Credential Enrollment:**
   - New endpoints for vault-level credential (vs vault services credential)
   - Stored in vault's local NATS, not central ledger

---

*Document End*
