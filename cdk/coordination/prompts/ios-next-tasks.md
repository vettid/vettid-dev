# VettID iOS - Next Tasks

**Date:** 2025-12-14
**Priority:** Navigation Architecture Alignment

---

## Context

The iOS app has made excellent progress on core functionality (enrollment, authentication, NATS, connections, messaging, handlers, backups). However, the navigation architecture diverges from the planned drawer + contextual bottom nav pattern.

**Current:** Static 3-tab TabView (Vault | Credentials | Settings)
**Planned:** Profile avatar opens drawer, contextual bottom nav changes per section

---

## Task 1: Implement Drawer Navigation (HIGH PRIORITY)

Replace the current TabView with the drawer + contextual bottom nav pattern.

### 1.1 Create DrawerView Component

```swift
// Features/Navigation/DrawerView.swift

import SwiftUI

struct DrawerView: View {
    @Binding var isOpen: Bool
    @Binding var currentSection: AppSection
    let onSignOut: () -> Void

    var body: some View {
        ZStack {
            // Scrim
            if isOpen {
                Color.black.opacity(0.5)
                    .ignoresSafeArea()
                    .onTapGesture { isOpen = false }
            }

            // Drawer
            HStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    // Profile header
                    DrawerHeader()

                    Divider()

                    // Section navigation
                    DrawerItem(
                        icon: "building.columns.fill", // TODO: Use tower icon
                        title: "Vault",
                        isSelected: currentSection == .vault
                    ) {
                        currentSection = .vault
                        isOpen = false
                    }

                    DrawerItem(
                        icon: "cloud.fill",
                        title: "Vault Services",
                        isSelected: currentSection == .vaultServices
                    ) {
                        currentSection = .vaultServices
                        isOpen = false
                    }

                    DrawerItem(
                        icon: "gearshape.fill",
                        title: "App Settings",
                        isSelected: currentSection == .appSettings
                    ) {
                        currentSection = .appSettings
                        isOpen = false
                    }

                    Spacer()

                    Divider()

                    // Sign out
                    DrawerItem(icon: "rectangle.portrait.and.arrow.right", title: "Sign Out") {
                        onSignOut()
                    }
                }
                .frame(width: UIScreen.main.bounds.width * 0.75)
                .background(Color(.systemBackground))

                Spacer()
            }
            .offset(x: isOpen ? 0 : -UIScreen.main.bounds.width)
            .animation(.spring(response: 0.3), value: isOpen)
        }
    }
}

struct DrawerHeader: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: "person.circle.fill")
                .font(.system(size: 60))
                .foregroundStyle(.blue)

            Text("User Name")
                .font(.headline)

            Text("email@example.com")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Text("Vault Active")
                    .font(.caption)
            }
        }
        .padding()
    }
}

struct DrawerItem: View {
    let icon: String
    let title: String
    var isSelected: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                    .frame(width: 24)
                Text(title)
                Spacer()
            }
            .padding()
            .background(isSelected ? Color.blue.opacity(0.1) : Color.clear)
        }
        .foregroundStyle(isSelected ? .blue : .primary)
    }
}
```

### 1.2 Create HeaderView Component

```swift
// Features/Navigation/HeaderView.swift

import SwiftUI

struct HeaderView: View {
    let title: String
    let onProfileTap: () -> Void
    var actionIcon: String? = nil
    var onActionTap: (() -> Void)? = nil
    var showSearch: Bool = false
    var onSearchTap: (() -> Void)? = nil

    var body: some View {
        HStack {
            // Profile avatar (opens drawer)
            Button(action: onProfileTap) {
                Image(systemName: "person.circle.fill")
                    .font(.title2)
            }

            Spacer()

            Text(title)
                .font(.headline)

            Spacer()

            HStack(spacing: 16) {
                if showSearch {
                    Button(action: { onSearchTap?() }) {
                        Image(systemName: "magnifyingglass")
                    }
                }

                if let icon = actionIcon, let action = onActionTap {
                    Button(action: action) {
                        Image(systemName: icon)
                    }
                }
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 12)
    }
}
```

### 1.3 Create Contextual Bottom Navigation

```swift
// Features/Navigation/ContextualBottomNav.swift

import SwiftUI

enum AppSection: String, CaseIterable {
    case appSettings = "App Settings"
    case vaultServices = "Vault Services"
    case vault = "Vault"
}

struct ContextualBottomNav: View {
    let section: AppSection
    @Binding var selectedItem: Int
    var onMoreTap: (() -> Void)? = nil

    var body: some View {
        switch section {
        case .appSettings:
            AppSettingsNav(selectedItem: $selectedItem)
        case .vaultServices:
            VaultServicesNav(selectedItem: $selectedItem)
        case .vault:
            VaultNav(selectedItem: $selectedItem, onMoreTap: onMoreTap)
        }
    }
}

struct VaultNav: View {
    @Binding var selectedItem: Int
    var onMoreTap: (() -> Void)?

    var body: some View {
        HStack {
            NavItem(
                icon: "person.2.fill",
                title: "Connections",
                isSelected: selectedItem == 0
            ) { selectedItem = 0 }

            NavItem(
                icon: "list.bullet.rectangle",
                title: "Feed",
                isSelected: selectedItem == 1
            ) { selectedItem = 1 }

            NavItem(
                icon: "ellipsis",
                title: "More",
                isSelected: selectedItem == 2
            ) { onMoreTap?() }
        }
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }
}

struct NavItem: View {
    let icon: String
    let title: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.title3)
                Text(title)
                    .font(.caption2)
            }
            .frame(maxWidth: .infinity)
            .foregroundStyle(isSelected ? .blue : .secondary)
        }
    }
}
```

### 1.4 Update MainTabView

Replace `MainTabView` in `ContentView.swift` with the new navigation:

```swift
struct MainNavigationView: View {
    @State private var isDrawerOpen = false
    @State private var currentSection: AppSection = .vault
    @State private var selectedNavItem = 0
    @State private var showMoreMenu = false

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // Header
                HeaderView(
                    title: currentScreenTitle,
                    onProfileTap: { isDrawerOpen = true },
                    actionIcon: currentActionIcon,
                    onActionTap: currentActionHandler,
                    showSearch: currentScreenHasSearch,
                    onSearchTap: handleSearch
                )

                // Content
                currentSectionContent

                // Bottom Nav
                ContextualBottomNav(
                    section: currentSection,
                    selectedItem: $selectedNavItem,
                    onMoreTap: { showMoreMenu = true }
                )
            }

            // Drawer overlay
            DrawerView(
                isOpen: $isDrawerOpen,
                currentSection: $currentSection,
                onSignOut: handleSignOut
            )
        }
        .gesture(
            DragGesture()
                .onEnded { value in
                    if value.translation.width > 100 {
                        isDrawerOpen = true
                    }
                }
        )
        .sheet(isPresented: $showMoreMenu) {
            MoreMenuSheet(onSelect: handleMoreSelection)
        }
    }

    @ViewBuilder
    private var currentSectionContent: some View {
        switch currentSection {
        case .vault:
            vaultContent
        case .vaultServices:
            vaultServicesContent
        case .appSettings:
            appSettingsContent
        }
    }

    @ViewBuilder
    private var vaultContent: some View {
        switch selectedNavItem {
        case 0: ConnectionsListView()
        case 1: FeedView()
        default: EmptyView()
        }
    }
}
```

---

## Task 2: Implement Feed Screen (MEDIUM PRIORITY)

Create the Feed screen showing activity events.

### Location: `Features/Feed/`

### Files to Create:
- `FeedView.swift`
- `FeedViewModel.swift`
- `FeedEvent.swift`
- `EventCardView.swift`

### Event Types:
```swift
enum FeedEvent: Identifiable {
    case message(MessageEvent)
    case connectionRequest(ConnectionRequestEvent)
    case authRequest(AuthRequestEvent)

    var id: String {
        switch self {
        case .message(let e): return e.id
        case .connectionRequest(let e): return e.id
        case .authRequest(let e): return e.id
        }
    }
}

struct MessageEvent {
    let id: String
    let senderId: String
    let senderName: String
    let preview: String
    let timestamp: Date
    let isRead: Bool
}
```

---

## Task 3: Implement Secrets Screen (MEDIUM PRIORITY)

Create the Secrets screen with password-only authentication.

### Requirements:
- List of secrets with lock icons
- "Add Secret" action in header
- View secret requires PASSWORD entry (NOT biometrics)
- 30-second auto-hide timer for revealed secrets
- Search capability

### Location: `Features/Secrets/`

### Key Implementation Note:
```swift
// When revealing a secret, ALWAYS prompt for password
// Never use biometrics for secrets

func revealSecret(secretId: String) async {
    // Show password entry sheet
    let password = await showPasswordPrompt()

    // Verify password against stored hash
    guard await verifyPassword(password) else {
        showError("Invalid password")
        return
    }

    // Decrypt and show secret
    let secret = await decryptSecret(secretId, password: password)
    revealedSecret = secret

    // Start 30-second auto-hide timer
    startAutoHideTimer()
}

private func startAutoHideTimer() {
    autoHideTask?.cancel()
    autoHideTask = Task {
        try await Task.sleep(nanoseconds: 30_000_000_000) // 30 seconds
        await MainActor.run {
            revealedSecret = nil
        }
    }
}
```

---

## Task 4: Implement Personal Data Screen (LOWER PRIORITY)

Create the Personal Data management screen.

### Sections:
- Public (name, email - auto-populated from membership)
- Private
- Keys
- Minor Secrets

### Location: `Features/PersonalData/`

---

## Task 5: Update Icon to Tower

Change the Vault icon from `building.columns.fill` to a tower icon throughout the app.

**Files to update:**
- `ContentView.swift` (MainTabView)
- `DrawerView.swift`
- Any other vault icon references

**Note:** SwiftUI doesn't have a built-in tower icon. Options:
1. Use SF Symbol `building.2` or custom asset
2. Add custom tower icon to Assets.xcassets

---

## Navigation Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                         DRAWER                                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  👤 User Name                                           │ │
│  │     email@example.com                                   │ │
│  │     ✓ Vault Active                                      │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  🏰 Vault                    ← Selected                      │
│  ☁️  Vault Services                                          │
│  ⚙️  App Settings                                            │
│                                                              │
│  ─────────────────────                                       │
│  Sign Out                    → Shows action sheet options    │
└──────────────────────────────────────────────────────────────┘

Selected: Vault Section
┌──────────────────────────────────────────────────────────────┐
│ (👤) Connections                              [🔍] [+ Add]   │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│                    [Connections List]                        │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│     Connections     │        Feed       │       •••          │
└──────────────────────────────────────────────────────────────┘
```

---

## Testing Checklist

- [ ] Drawer opens from profile avatar tap
- [ ] Drawer opens from left edge swipe gesture
- [ ] Section switching updates bottom nav
- [ ] Bottom nav items change per section
- [ ] Header action changes per screen
- [ ] Search icon appears on searchable screens
- [ ] Feed shows mock events
- [ ] Secrets requires password (not biometrics)
- [ ] Sign out shows action sheet with options
- [ ] Vault icon is tower (not building.columns)

---

## Reference Documents

- `cdk/coordination/mobile-ui-plan.md` - Full UI/UX specification
- `cdk/coordination/mobile-progress-review.md` - Gap analysis

---

*Start with Task 1 (navigation refactor) as it affects all other screens.*
