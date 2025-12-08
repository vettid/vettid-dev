# Vault Services Frontend Integration Plan

## Overview
Connect the account portal vault tab to the backend vault services API. The backend is fully implemented with 12 Lambda handlers and complete API routes. The frontend has placeholder UI that needs to be replaced with functional components.

## Current State

### Backend (Ready)
- **12 Lambda handlers** in `/lambda/handlers/vault/`
- **24 DynamoDB tables** for vault services
- **API Routes** all wired up in vettid-stack.ts
- **Security**: All endpoints protected by member JWT

### Frontend (Placeholder)
- **3 sub-tabs** under Vault: Deploy, BYOV, Backup
- All show "Coming soon" placeholders
- Tab visibility controlled by subscription status
- Getting Started step 4 points to vault deployment

## Implementation Phases

### Phase 1: Vault Status Dashboard (Deploy Tab)
**Goal**: Show current vault enrollment and instance status

**API Endpoints Used**:
- `GET /vault/status` - Enrollment state (not_enrolled, pending, enrolled, active)
- `GET /vault/health` - Instance health (when deployed)

**UI Components**:
1. **Status Card** - Shows current state with icon
   - Not Enrolled → "Set up your vault" with button
   - Pending → "Enrollment in progress" spinner
   - Enrolled (no instance) → "Ready to deploy" with Provision button
   - Active → Health dashboard

2. **Health Dashboard** (when active)
   - EC2 Instance: Running/Stopped/etc
   - NATS Central: Connected/Disconnected
   - NATS Local: Connected/Disconnected
   - Vault Manager: CPU/Memory usage
   - Uptime display
   - Last sync time

3. **Action Buttons**
   - Provision Vault (when enrolled, no instance)
   - Initialize (after provisioning)
   - Stop/Start (when running/stopped)
   - Terminate (with confirmation modal)

**JavaScript Functions**:
```javascript
async function loadVaultStatus() { ... }
async function loadVaultHealth() { ... }
async function provisionVault() { ... }
async function initializeVault() { ... }
async function stopVault() { ... }
async function terminateVault() { ... }
function renderVaultStatusCard(status) { ... }
function renderHealthDashboard(health) { ... }
```

### Phase 2: Mobile App Enrollment Flow
**Goal**: Guide users through enrolling their mobile device

**API Endpoints Used**:
- `POST /vault/enroll/start` - Start enrollment, get challenge
- `POST /vault/enroll/set-password` - Set password
- `POST /vault/enroll/finalize` - Complete enrollment

**UI Components**:
1. **Enrollment Modal/Wizard**
   - Step 1: Enter invitation code (or generate one)
   - Step 2: Display QR code for mobile app to scan
   - Step 3: Wait for mobile attestation
   - Step 4: Confirm enrollment complete

2. **QR Code Display**
   - Generate QR with enrollment session data
   - Include: session_id, attestation_challenge, API URL

3. **Status Indicators**
   - Waiting for mobile app
   - Attestation received
   - Enrollment complete

**Note**: Most of the enrollment happens on the mobile app. The web portal shows status and provides the QR code.

### Phase 3: Vault Provisioning & Lifecycle
**Goal**: Allow users to provision and manage their vault instance

**API Endpoints Used**:
- `POST /vault/provision` - Start EC2 provisioning
- `POST /vault/initialize` - Initialize after EC2 ready
- `POST /vault/stop` - Stop instance
- `POST /vault/terminate` - Terminate instance
- `POST /vault/sync` - Sync keys

**UI Components**:
1. **Provisioning Progress**
   - "Launching instance..." with progress
   - Estimated time remaining
   - Poll for completion

2. **Instance Management Card**
   - Instance ID display
   - Region/AZ info
   - Start time
   - Cost estimate (optional)

3. **Confirmation Modals**
   - Stop vault confirmation
   - Terminate vault confirmation (destructive action warning)

### Phase 4: Backup Services Tab
**Goal**: Manage vault backups and settings

**API Endpoints Used**:
- `GET /vault/backups` - List backups
- `POST /vault/backup` - Trigger backup
- `POST /vault/restore` - Restore from backup
- `DELETE /vault/backups/{id}` - Delete backup
- `GET /vault/backup/settings` - Get settings
- `PUT /vault/backup/settings` - Update settings

**UI Components**:
1. **Backup List**
   - Table/grid of backups
   - Date, size, type (manual/auto)
   - Status badge
   - Actions: Restore, Delete

2. **Backup Settings Card**
   - Auto-backup toggle
   - Frequency selector (daily/weekly/monthly)
   - Time picker
   - Retention period slider
   - WiFi-only toggle

3. **Backup Actions**
   - "Backup Now" button
   - Restore confirmation modal
   - Delete confirmation modal

### Phase 5: Credential Backup & Recovery
**Goal**: BIP-39 recovery phrase backup for credentials

**API Endpoints Used**:
- `POST /vault/credentials/backup` - Create credential backup
- `GET /vault/credentials/backup` - Get backup status
- `POST /vault/credentials/recover` - Download for recovery

**UI Components**:
1. **Credential Backup Card**
   - Status: Not backed up / Backed up on [date]
   - "Create Backup" button

2. **Recovery Phrase Display Modal**
   - 24-word grid (4x6)
   - Copy to clipboard
   - Download as text file
   - Verification step

3. **Recovery Flow** (if needed)
   - Enter 24 words
   - Autocomplete suggestions
   - Validate phrase
   - Recover credentials

### Phase 6: BYOV (Bring Your Own Vault) - Future
**Goal**: Connect external vault instances

**Status**: Lower priority, can remain "Coming soon" initially

**Potential Features**:
- URL input for external vault
- Connection test
- API key/token configuration
- Status monitoring

## Technical Implementation Details

### API Client Pattern
```javascript
// Use existing pattern from account portal
async function vaultApiCall(endpoint, method = 'GET', body = null) {
  const token = VettIDAuth.getIdToken();
  const options = {
    method,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    }
  };
  if (body) options.body = JSON.stringify(body);

  const res = await fetch(window.VettIDConfig.API_URL + endpoint, options);
  if (!res.ok) {
    if (res.status === 401) {
      await VettIDAuth.refreshTokens(window.VettIDConfig);
      return vaultApiCall(endpoint, method, body); // Retry
    }
    throw new Error(await res.text());
  }
  return res.json();
}
```

### Polling Pattern (for status updates)
```javascript
let vaultStatusInterval = null;

function startVaultStatusPolling() {
  stopVaultStatusPolling();
  loadVaultStatus(); // Initial load
  vaultStatusInterval = setInterval(loadVaultStatus, 30000); // 30s
}

function stopVaultStatusPolling() {
  if (vaultStatusInterval) {
    clearInterval(vaultStatusInterval);
    vaultStatusInterval = null;
  }
}
```

### Tab Activation Hook
```javascript
// When vault tab is activated
document.querySelector('.tab[data-tab="deploy-vault"]')
  .addEventListener('click', () => {
    startVaultStatusPolling();
  });

// When leaving vault tab
function onTabChange(newTab) {
  if (newTab !== 'deploy-vault') {
    stopVaultStatusPolling();
  }
}
```

## UI Design Guidelines

### Status Colors
- **Not Enrolled**: Gray (#6b7280)
- **Pending**: Yellow (#f59e0b)
- **Enrolled**: Blue (#3b82f6)
- **Active/Healthy**: Green (#10b981)
- **Degraded**: Orange (#f97316)
- **Unhealthy/Error**: Red (#ef4444)

### Card Layout
```html
<div class="card">
  <div class="card-header">
    <h4>Vault Status</h4>
    <span class="status-badge status-active">Active</span>
  </div>
  <div class="card-body">
    <!-- Content -->
  </div>
  <div class="card-footer">
    <button class="btn btn-primary">Action</button>
  </div>
</div>
```

### Loading States
- Use existing `showGridLoadingSkeleton()` for lists
- Use spinner icon for buttons during API calls
- Disable buttons during operations

## Getting Started Integration

Update step 4 completion check:
```javascript
async function checkVaultDeployed() {
  try {
    const status = await vaultApiCall('/vault/status');
    return status.status === 'active';
  } catch {
    return false;
  }
}
```

## File Changes Required

1. **`/frontend/account/index.html`**
   - Replace vault placeholder sections with functional UI
   - Add JavaScript functions for vault API calls
   - Add CSS for vault-specific components

2. **`/frontend/shared/config.js`** (if needed)
   - Add vault-specific configuration
   - Polling intervals, timeouts

## Estimated Effort

| Phase | Components | Complexity | Est. Lines |
|-------|------------|------------|------------|
| Phase 1 | Status Dashboard | Medium | ~300 |
| Phase 2 | Enrollment Flow | Medium | ~250 |
| Phase 3 | Provisioning | Medium | ~200 |
| Phase 4 | Backup Services | Medium | ~350 |
| Phase 5 | Credential Backup | High | ~400 |
| Phase 6 | BYOV | Low | ~100 |
| **Total** | | | **~1600** |

## Dependencies

- Backend API deployed and accessible
- Member authentication working
- Subscription status check working
- QR code library (for enrollment) - can use inline SVG generation

## Implementation Status

### Phase 1: Vault Status Dashboard - COMPLETE
- [x] Status card with refresh button
- [x] Health dashboard card (hidden until vault active)
- [x] Provisioning progress card
- [x] All state rendering (not_enrolled, pending, enrolled, provisioning, active, stopped)
- [x] Health metrics grid (EC2, NATS Central, NATS Local, CPU, Memory, Disk)
- [x] Action handlers (provision, stop, start, terminate)
- [x] Terminate confirmation modal
- [x] Status polling every 30 seconds
- [x] Getting Started step 4 integration

### Phase 2-6: Remaining
- [ ] Phase 2: Mobile App Enrollment Flow (QR code display)
- [ ] Phase 3: Vault Provisioning details & Lifecycle
- [ ] Phase 4: Backup Services Tab
- [ ] Phase 5: Credential Backup & Recovery
- [ ] Phase 6: BYOV (Bring Your Own Vault)

## Testing Checklist

- [x] Vault status loads correctly for all states
- [x] Health dashboard updates in real-time
- [x] Provision flow works end-to-end
- [x] Stop/Start/Terminate work correctly
- [ ] Backup list displays correctly
- [ ] Backup settings save and load
- [ ] Trigger backup works
- [ ] Restore backup works
- [ ] Credential backup phrase displays
- [x] Getting Started step 4 marks complete
- [x] Error states handled gracefully
- [x] Loading states shown during API calls
- [ ] Token refresh works when expired
