# VettID Android - Next Tasks

**Date:** 2025-12-14
**Priority:** Navigation Architecture Alignment

---

## Context

The Android app has made excellent progress on core functionality (enrollment, authentication, NATS, connections, messaging, handlers, backups). However, the navigation architecture diverges from the planned drawer + contextual bottom nav pattern.

**Current:** Static 4-tab bottom nav (Vault | Connections | Handlers | Profile)
**Planned:** Profile avatar opens drawer, contextual bottom nav changes per section

---

## Task 1: Implement Drawer Navigation (HIGH PRIORITY)

Replace the current static bottom navigation with the drawer + contextual bottom nav pattern.

### 1.1 Create DrawerView Component

```kotlin
// ui/navigation/DrawerView.kt

@Composable
fun DrawerView(
    isOpen: Boolean,
    onClose: () -> Unit,
    currentSection: AppSection,
    onSectionChange: (AppSection) -> Unit,
    onSignOut: () -> Unit
) {
    AnimatedVisibility(
        visible = isOpen,
        enter = slideInHorizontally(initialOffsetX = { -it }),
        exit = slideOutHorizontally(targetOffsetX = { -it })
    ) {
        Row(modifier = Modifier.fillMaxSize()) {
            // Drawer content (70% width)
            Surface(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(0.7f),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 8.dp
            ) {
                Column {
                    // Profile header
                    DrawerHeader()

                    Divider()

                    // Section navigation
                    DrawerSection(
                        icon = Icons.Default.Castle, // Tower icon
                        title = "Vault",
                        selected = currentSection == AppSection.VAULT,
                        onClick = { onSectionChange(AppSection.VAULT); onClose() }
                    )
                    DrawerSection(
                        icon = Icons.Default.Cloud,
                        title = "Vault Services",
                        selected = currentSection == AppSection.VAULT_SERVICES,
                        onClick = { onSectionChange(AppSection.VAULT_SERVICES); onClose() }
                    )
                    DrawerSection(
                        icon = Icons.Default.Settings,
                        title = "App Settings",
                        selected = currentSection == AppSection.APP_SETTINGS,
                        onClick = { onSectionChange(AppSection.APP_SETTINGS); onClose() }
                    )

                    Spacer(modifier = Modifier.weight(1f))

                    Divider()

                    // Sign out
                    DrawerSection(
                        icon = Icons.Default.Logout,
                        title = "Sign Out",
                        onClick = onSignOut
                    )
                }
            }

            // Scrim (click to close)
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.5f))
                    .clickable(onClick = onClose)
            )
        }
    }
}
```

### 1.2 Create HeaderView Component

```kotlin
// ui/navigation/HeaderView.kt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HeaderView(
    title: String,
    onProfileClick: () -> Unit,
    actionIcon: ImageVector? = null,
    onActionClick: (() -> Unit)? = null,
    showSearch: Boolean = false,
    onSearchClick: (() -> Unit)? = null
) {
    TopAppBar(
        navigationIcon = {
            // Profile avatar (opens drawer)
            IconButton(onClick = onProfileClick) {
                Icon(
                    imageVector = Icons.Default.AccountCircle,
                    contentDescription = "Profile",
                    modifier = Modifier.size(32.dp)
                )
            }
        },
        title = { Text(title) },
        actions = {
            if (showSearch) {
                IconButton(onClick = { onSearchClick?.invoke() }) {
                    Icon(Icons.Default.Search, contentDescription = "Search")
                }
            }
            if (actionIcon != null && onActionClick != null) {
                IconButton(onClick = onActionClick) {
                    Icon(actionIcon, contentDescription = "Action")
                }
            }
        }
    )
}
```

### 1.3 Create Contextual Bottom Navigation

```kotlin
// ui/navigation/ContextualBottomNav.kt

enum class AppSection {
    APP_SETTINGS,
    VAULT_SERVICES,
    VAULT
}

@Composable
fun ContextualBottomNav(
    section: AppSection,
    selectedItem: Int,
    onItemSelected: (Int) -> Unit,
    onMoreClick: () -> Unit
) {
    when (section) {
        AppSection.APP_SETTINGS -> AppSettingsBottomNav(selectedItem, onItemSelected)
        AppSection.VAULT_SERVICES -> VaultServicesBottomNav(selectedItem, onItemSelected)
        AppSection.VAULT -> VaultBottomNav(selectedItem, onItemSelected, onMoreClick)
    }
}

@Composable
private fun VaultBottomNav(
    selectedItem: Int,
    onItemSelected: (Int) -> Unit,
    onMoreClick: () -> Unit
) {
    NavigationBar {
        NavigationBarItem(
            icon = { Icon(Icons.Default.People, null) },
            label = { Text("Connections") },
            selected = selectedItem == 0,
            onClick = { onItemSelected(0) }
        )
        NavigationBarItem(
            icon = { Icon(Icons.Default.DynamicFeed, null) },
            label = { Text("Feed") },
            selected = selectedItem == 1,
            onClick = { onItemSelected(1) }
        )
        NavigationBarItem(
            icon = { Icon(Icons.Default.MoreHoriz, null) },
            label = { Text("More") },
            selected = selectedItem == 2,
            onClick = onMoreClick
        )
    }
}
```

### 1.4 Update MainScreen

Replace the current `MainScreen` in `VettIDApp.kt` with the new navigation pattern.

---

## Task 2: Implement Feed Screen (MEDIUM PRIORITY)

Create the Feed screen showing activity events.

### Location: `features/feed/`

### Files to Create:
- `FeedScreen.kt`
- `FeedViewModel.kt`
- `FeedEvent.kt` (data model)
- `EventCard.kt` (composable for rendering events)

### Event Types:
```kotlin
sealed class FeedEvent {
    data class Message(
        val id: String,
        val senderId: String,
        val senderName: String,
        val preview: String,
        val timestamp: Instant,
        val isRead: Boolean
    ) : FeedEvent()

    data class ConnectionRequest(
        val id: String,
        val fromName: String,
        val fromEmail: String,
        val timestamp: Instant
    ) : FeedEvent()

    data class AuthRequest(
        val id: String,
        val serviceName: String,
        val scope: String,
        val timestamp: Instant
    ) : FeedEvent()
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

### Location: `features/secrets/`

### Key Implementation Note:
```kotlin
// When revealing a secret, ALWAYS prompt for password
// Never use biometrics for secrets
suspend fun revealSecret(secretId: String, password: String): Result<String> {
    // Verify password against stored hash
    // Return decrypted secret value
    // Start 30-second timer to auto-hide
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

### Location: `features/personaldata/`

---

## Task 5: Fix AuthenticationScreen

The current `AuthenticationScreen` is a placeholder. Integrate with `BiometricAuthManager`:

```kotlin
@Composable
fun AuthenticationScreen(
    onAuthenticated: () -> Unit,
    viewModel: AuthenticationViewModel = hiltViewModel()
) {
    val context = LocalContext.current
    val activity = context as FragmentActivity

    LaunchedEffect(Unit) {
        // Attempt biometric auth on screen load
        viewModel.authenticateWithBiometrics(activity)
    }

    // ... UI for biometric prompt or password fallback
}
```

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
│  Sign Out                    → Shows bottom sheet options    │
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
- [ ] Drawer opens from left edge swipe
- [ ] Section switching updates bottom nav
- [ ] Bottom nav items change per section
- [ ] Header action changes per screen
- [ ] Search icon appears on searchable screens
- [ ] Feed shows mock events
- [ ] Secrets requires password (not biometrics)
- [ ] Sign out shows options bottom sheet

---

## Reference Documents

- `cdk/coordination/mobile-ui-plan.md` - Full UI/UX specification
- `cdk/coordination/mobile-progress-review.md` - Gap analysis

---

*Start with Task 1 (navigation refactor) as it affects all other screens.*
