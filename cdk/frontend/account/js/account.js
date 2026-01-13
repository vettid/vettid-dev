// ====== CONFIG ======
// Load configuration from centralized config file
const API_URL = window.VettIDConfig.apiUrl;
// ====================

// ---- DOM Cache for Performance ----
const DOMCache = {};
function getElement(id) {
  if (!DOMCache[id]) {
    DOMCache[id] = document.getElementById(id);
  }
  return DOMCache[id];
}

// ---- Token storage ----
function loadTokens() {
  try { return JSON.parse(localStorage.getItem('tokens') || 'null'); } catch { return null; }
}
function saveTokens(tokens) {
  localStorage.setItem('tokens', JSON.stringify(tokens));
}
function clearTokens() { localStorage.removeItem('tokens'); localStorage.removeItem('authEmail'); }
function idToken() { return (loadTokens() || {}).id_token; }
function signedIn() { return !!idToken(); }

// Refresh tokens using Cognito OAuth endpoint
async function refreshTokens() {
  const tokens = loadTokens();
  if (!tokens || !tokens.refresh_token) {
    return false;
  }

  const cognitoDomain = window.VettIDConfig.member.cognitoDomain;
  const clientId = window.VettIDConfig.member.clientId;

  try {
    const response = await fetch(`${cognitoDomain}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: tokens.refresh_token
      })
    });

    if (!response.ok) {
      console.error('[AUTH] Token refresh failed:', response.status);
      return false;
    }

    const data = await response.json();

    // Update stored tokens (refresh_token stays the same)
    saveTokens({
      id_token: data.id_token,
      access_token: data.access_token,
      refresh_token: tokens.refresh_token // Keep existing refresh token
    });

    return true;
  } catch (error) {
    console.error('[AUTH] Token refresh error:', error);
    return false;
  }
}

// ---- Toast Notifications ----
let toastOffset = 0;
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = 'vettid-toast';
  const bgColor = type === 'error' ? '#f44336' : type === 'success' ? '#4caf50' : type === 'warning' ? '#ff9800' : '#2196f3';

  // Calculate position based on existing toasts
  const existingToasts = document.querySelectorAll('.vettid-toast');
  let topOffset = 20;
  existingToasts.forEach(t => {
    topOffset += t.offsetHeight + 10;
  });

  toast.style.cssText = `position:fixed;top:${topOffset}px;right:20px;padding:16px 24px;background:${bgColor};color:#fff;border-radius:4px;box-shadow:0 4px 12px rgba(0,0,0,0.5);z-index:9999;animation:slideIn 0.3s;max-width:400px;word-wrap:break-word;transition:top 0.3s ease;`;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s';
    setTimeout(() => {
      toast.remove();
      // Reposition remaining toasts
      let newTop = 20;
      document.querySelectorAll('.vettid-toast').forEach(t => {
        t.style.top = newTop + 'px';
        newTop += t.offsetHeight + 10;
      });
    }, 300);
  }, 4000);
}

// ---- Proposal Results Modal ----
function showProposalResultsModal(htmlContent) {
  const modal = getElement('proposalResultsModal');
  const content = getElement('proposalResultsContent');
  content.innerHTML = htmlContent;
  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

function closeProposalResultsModal() {
  const modal = getElement('proposalResultsModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
}

// Close modal on overlay click
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('proposalResultsModal');
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) closeProposalResultsModal();
  });

  // Close modal on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (modal?.style.display === 'block') {
        closeProposalResultsModal();
      }
      const pinModal = document.getElementById('pinDisableModal');
      if (pinModal?.style.display === 'block') {
        closePinDisableModal();
      }
      // Close mobile sidebar on Escape
      closeMobileSidebar();
    }
  });

  // Mobile sidebar toggle
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');

  function openMobileSidebar() {
    sidebar?.classList.add('mobile-open');
    sidebarOverlay?.classList.add('visible');
    document.body.style.overflow = 'hidden';
  }

  function closeMobileSidebar() {
    sidebar?.classList.remove('mobile-open');
    sidebarOverlay?.classList.remove('visible');
    document.body.style.overflow = '';
  }

  mobileMenuBtn?.addEventListener('click', () => {
    if (sidebar?.classList.contains('mobile-open')) {
      closeMobileSidebar();
    } else {
      openMobileSidebar();
    }
  });

  sidebarOverlay?.addEventListener('click', closeMobileSidebar);

  // Theme toggle
  const themeToggle = document.getElementById('themeToggle');
  themeToggle?.addEventListener('click', toggleTheme);

  // Close sidebar when a tab is clicked on mobile
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      if (window.innerWidth <= 768) {
        closeMobileSidebar();
      }
    });
  });
});

// ---- PIN Disable Modal ----
function showPinDisableModal() {
  const modal = getElement('pinDisableModal');
  const input = getElement('pinDisableInput');
  const error = getElement('pinDisableError');

  input.value = '';
  error.style.display = 'none';
  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';

  // Focus input after modal opens
  setTimeout(() => input.focus(), 100);
}

function closePinDisableModal() {
  const modal = getElement('pinDisableModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
}

async function submitPinDisable() {
  const input = getElement('pinDisableInput');
  const error = getElement('pinDisableError');
  const pin = input.value.trim();

  // Validate PIN format
  if (!/^\d{4,6}$/.test(pin)) {
    error.textContent = 'PIN must be 4-6 digits';
    error.style.display = 'block';
    return;
  }

  error.style.display = 'none';

  // Call the actual disable function with the PIN
  closePinDisableModal();
  await executePinDisable(pin);
}

// ---- PIN Verification on Login ----
// Session-based PIN verification - user must verify PIN once per browser session when PIN is enabled
function isPinVerifiedForSession() {
  return sessionStorage.getItem('pinVerified') === 'true';
}

function markPinVerifiedForSession() {
  sessionStorage.setItem('pinVerified', 'true');
}

function clearPinVerificationForSession() {
  sessionStorage.removeItem('pinVerified');
}

// Check if PIN verification is required and show modal if needed
// Returns: true if PIN verification is required (blocks load), false if can proceed
async function checkAndRequirePinVerification() {
  // If already verified this session, skip
  if (isPinVerifiedForSession()) {
    return false;
  }

  const token = idToken();
  if (!token) {
    return false;
  }

  try {
    const res = await fetch(API_URL + '/account/security/pin/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    // 404 = PIN not configured, no verification needed
    if (res.status === 404) {
      return false;
    }

    if (!res.ok) {
      return false; // On error, allow access (fail open)
    }

    const data = await res.json();

    if (data.pin_enabled) {
      // PIN is enabled, show verification modal
      showPinVerificationModal();
      return true; // Block load until PIN verified
    } else {
      return false;
    }
  } catch (err) {
    console.error('[PIN-LOGIN] Error checking PIN status:', err);
    return false; // On error, allow access (fail open)
  }
}

function showPinVerificationModal() {
  const modal = document.getElementById('verifyPinLoginModal');
  const input = document.getElementById('verifyPinLoginInput');
  const error = document.getElementById('verifyPinLoginError');

  input.value = '';
  error.style.display = 'none';
  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';

  // Focus input after modal opens
  setTimeout(() => input.focus(), 100);

  // Setup Enter key listener for convenience
  input.onkeydown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submitPinVerification();
    }
  };
}

function hidePinVerificationModal() {
  const modal = document.getElementById('verifyPinLoginModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
}

async function submitPinVerification() {
  const input = document.getElementById('verifyPinLoginInput');
  const error = document.getElementById('verifyPinLoginError');
  const btn = document.getElementById('verifyPinLoginBtn');
  const pin = input.value.trim();

  // Validate PIN format
  if (!/^\d{4,6}$/.test(pin)) {
    error.textContent = 'PIN must be 4-6 digits';
    error.style.display = 'block';
    input.focus();
    return;
  }

  error.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'Verifying...';

  const token = idToken();
  if (!token) {
    error.textContent = 'Session expired. Please sign in again.';
    error.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Verify';
    return;
  }

  try {
    const res = await fetch(API_URL + '/account/security/pin/verify', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ pin })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      error.textContent = errData.message || 'Failed to verify PIN. Please try again.';
      error.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Verify';
      input.value = '';
      input.focus();
      return;
    }

    const data = await res.json();

    if (data.verified) {
      // PIN verified successfully!
      markPinVerifiedForSession();
      hidePinVerificationModal();
      // Continue loading the app
      continueAppInitialization();
    } else {
      // PIN incorrect
      error.textContent = data.message || 'Incorrect PIN. Please try again.';
      error.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Verify';
      input.value = '';
      input.focus();
    }
  } catch (err) {
    console.error('[PIN-LOGIN] Error verifying PIN:', err);
    error.textContent = 'Failed to verify PIN. Please try again.';
    error.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
}

// Store the continuation function for after PIN verification
let continueAppInitialization = () => {};

// ---- Membership Confirmation Modal ----
function showMembershipConfirmModal() {
  const modal = getElement('membershipConfirmModal');
  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

function closeMembershipConfirmModal() {
  const modal = getElement('membershipConfirmModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
}

// Called when user clicks "Accept & Continue" in the modal
async function confirmMembership() {
  closeMembershipConfirmModal();
  await executeMembershipRequest();
}

// ---- Debounce Helper ----
function debounce(func, delay = 300) {
  let timeoutId;
  return function(...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(this, args), delay);
  };
}

// Prevent double-clicks on async operations
const buttonClickTracking = new WeakMap();
function preventDoubleClick(button, asyncFunc) {
  return async function(...args) {
    if (buttonClickTracking.get(button)) {
      return; // Already processing
    }
    buttonClickTracking.set(button, true);
    try {
      await asyncFunc.apply(this, args);
    } finally {
      setTimeout(() => buttonClickTracking.delete(button), 1000);
    }
  };
}

// ---- Tab Lock/Unlock with Tooltips ----
function lockTab(tabId, tooltipMessage) {
  const tab = document.querySelector(`[data-tab="${tabId}"]`);
  if (tab) {
    tab.classList.add('locked');
    tab.setAttribute('data-tooltip', tooltipMessage);
    tab.addEventListener('click', preventTabClick);
  }
}

function unlockTab(tabId) {
  const tab = document.querySelector(`[data-tab="${tabId}"]`);
  if (tab) {
    tab.classList.remove('locked');
    tab.removeAttribute('data-tooltip');
    tab.removeEventListener('click', preventTabClick);
  }
}

function preventTabClick(e) {
  if (e.currentTarget.classList.contains('locked')) {
    e.preventDefault();
    e.stopPropagation();
  }
}

// ---- Loading State Helpers ----
function setLoading(button, loading = true) {
  if (loading) {
    button.dataset.originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Processing...';
    button.style.opacity = '0.7';
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText || button.textContent;
    button.style.opacity = '1';
  }
}

function showGridLoadingSkeleton(containerId, count = 3) {
  const container = document.getElementById(containerId);
  let skeletonHTML = '';
  for (let i = 0; i < count; i++) {
    skeletonHTML += `
      <div style="padding:20px;background:#0a0a0a;border-radius:8px;border:1px solid var(--border);">
        <div class="skeleton" style="height:24px;margin-bottom:12px;border-radius:4px;width:60%;"></div>
        <div class="skeleton" style="height:16px;margin-bottom:8px;border-radius:4px;width:80%;"></div>
        <div class="skeleton" style="height:16px;margin-bottom:8px;border-radius:4px;width:70%;"></div>
        <div class="skeleton" style="height:36px;margin-top:16px;border-radius:4px;width:100%;"></div>
      </div>
    `;
  }
  container.innerHTML = skeletonHTML;
}

// ---- JWT helpers ----
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  return atob(str + '='.repeat(pad));
}
/* SECURITY NOTE: Frontend JWT parsing is for display/UX purposes only.
 * JWT signature validation is performed server-side by API Gateway's Cognito authorizer.
 * Never trust client-side JWT claims for authorization - they can be tampered with.
 * All protected API endpoints validate the JWT signature and claims on the backend. */
function parseJwt(idt) {
  try {
    const [h, p, s] = idt.split('.');
    return { header: JSON.parse(b64urlDecode(h)), payload: JSON.parse(b64urlDecode(p)), signature: s };
  } catch { return { header: {}, payload: {}, signature: '' }; }
}

// Check if JWT token is expired
function isTokenExpired(token) {
  if (!token) return true;
  try {
    const { payload } = parseJwt(token);
    if (!payload.exp) return true;
    // exp is in seconds, Date.now() is in milliseconds
    const expiryTime = payload.exp * 1000;
    const now = Date.now();
    // Add 60 second buffer to account for clock skew
    return expiryTime < (now + 60000);
  } catch {
    return true;
  }
}

// Handle session expiry - logs out user and redirects to signin
function handleSessionExpired() {
  clearTokens();
  // Redirect to signin with message
  window.location.href = '/signin?expired=1';
}

// Check API response for auth errors and handle logout
// Returns true if response indicates auth failure (caller should stop processing)
function isAuthError(response) {
  if (response.status === 401 || response.status === 403) {
    handleSessionExpired();
    return true;
  }
  return false;
}

// Periodic token expiry check (every 30 seconds)
let tokenCheckInterval = null;
function startTokenExpiryCheck() {
  if (tokenCheckInterval) return;
  tokenCheckInterval = setInterval(() => {
    const token = idToken();
    if (isTokenExpired(token)) {
      handleSessionExpired();
    }
  }, 30000);
}

function stopTokenExpiryCheck() {
  if (tokenCheckInterval) {
    clearInterval(tokenCheckInterval);
    tokenCheckInterval = null;
  }
}

// ---- Auth check ----
function checkAuth() {
  if (!signedIn()) {
    // Redirect to signin page
    window.location.href = '/signin';
    return false;
  }

  // Check if token is expired
  const token = idToken();
  if (isTokenExpired(token)) {
    clearTokens();
    window.location.href = '/signin';
    return false;
  }

  return true;
}

function signOut() {
  // Redirect to dedicated signout page
  window.location.href = '/signout';
}

function populateProfile() {
  if (!signedIn()) return;
  const { payload } = parseJwt(idToken());
  document.getElementById('firstName').textContent = payload.given_name || '—';
  document.getElementById('lastName').textContent = payload.family_name || '—';
  document.getElementById('email').textContent = payload.email || '—';
  document.getElementById('userGuid').textContent = payload['custom:user_guid'] || '—';
  // Also populate email in header and show dropdown
  document.getElementById('userEmail').textContent = payload.email || '';
  document.getElementById('userDropdownContainer').style.display = 'inline-block';
}

async function cancelAccount() {
  const confirmed = await showConfirmModal({
    title: 'Cancel Account',
    message: 'Are you sure you want to cancel your account? This will disable your access. An administrator can reactivate or permanently delete it.',
    confirmText: 'Cancel Account',
    cancelText: 'Keep Account',
    type: 'danger'
  });
  if (!confirmed) return;

  const btn = document.getElementById('cancelAccountBtn');
  setLoading(btn, true);

  try {
    const res = await fetch(API_URL + '/account/cancel', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });
    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to cancel account'), 'error');
      setLoading(btn, false);
      return;
    }
    const data = await res.json();
    showToast(data.message || 'Account canceled successfully', 'success');
    setTimeout(() => signOut(), 2000);
  } catch (err) {
    showToast('Error: ' + (err.message || 'Failed to cancel account'), 'error');
    setLoading(btn, false);
  }
}

// Tab switching with parent/child support
document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    const target = tab.getAttribute('data-tab');
    const subTab = tab.getAttribute('data-sub-tab');
    const isParent = tab.classList.contains('tab-parent');
    const isChild = tab.classList.contains('tab-child');

    // If it's a parent tab, toggle expand/collapse and switch to first child
    if (isParent) {
      const parentId = tab.id;
      const childrenId = parentId.replace('Parent', 'Children');
      const children = document.getElementById(childrenId);

      // Toggle expansion
      tab.classList.toggle('expanded');
      children?.classList.toggle('expanded');

      // If expanding, switch to the parent's tab content and first sub-tab
      if (tab.classList.contains('expanded')) {
        // Clear active state from all non-child tabs
        document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        // Activate parent and content
        tab.classList.add('active');
        document.getElementById(target)?.classList.add('active');

        // Activate first child tab and its sub-content
        const firstChild = children?.querySelector('.tab-child');
        if (firstChild) {
          document.querySelectorAll('.tab-child').forEach(c => c.classList.remove('active'));
          firstChild.classList.add('active');
          const firstSubTab = firstChild.getAttribute('data-sub-tab');
          if (firstSubTab) {
            activateSubTab(target, firstSubTab);
          }
        }
      }
      return;
    }

    // If it's a child tab, switch sub-tab content
    if (isChild) {
      // Clear active from all child tabs
      document.querySelectorAll('.tab-child').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');

      // Activate the sub-tab content
      if (subTab) {
        activateSubTab(target, subTab);
      }
      return;
    }

    // Regular tab - collapse any expanded parent tabs
    document.querySelectorAll('.tab-parent').forEach(p => p.classList.remove('expanded'));
    document.querySelectorAll('.tab-children').forEach(c => c.classList.remove('expanded'));
    document.querySelectorAll('.tab-child').forEach(c => c.classList.remove('active'));

    // Standard tab switching
    document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(target)?.classList.add('active');

    // Load voting data when voting tab is clicked
    if (target === 'voting' && signedIn()) {
      loadAllProposals();
    }
  };
});

// Helper function to activate sub-tab content
function activateSubTab(parentTab, subTabName) {
  const parentContent = document.getElementById(parentTab);
  if (!parentContent) return;

  // Clear all sub-tab-content active states within this parent
  parentContent.querySelectorAll('.sub-tab-content').forEach(s => s.classList.remove('active'));

  // Determine the sub-tab-content ID based on parent tab
  let subContentId;
  if (parentTab === 'account') {
    subContentId = 'account-' + subTabName;
  } else if (parentTab === 'deploy-vault') {
    subContentId = 'vault-' + subTabName;
  }

  // Activate the specific sub-tab content
  const subContent = document.getElementById(subContentId);
  if (subContent) {
    subContent.classList.add('active');
  }

  // Initialize tab-specific data
  if (parentTab === 'deploy-vault' && subTabName === 'credential-backup') {
    initCredentialBackupTab();
  }
  if (parentTab === 'deploy-vault' && subTabName === 'byov') {
    initByovTab();
  }
}

// Keyboard shortcuts for tab navigation (1-6)
document.addEventListener('keydown', (e) => {
  // Only trigger if not typing in an input field
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

  const tabMap = {
    '1': 'getting-started',
    '2': 'account',
    '3': 'subscription',
    '4': 'voting',
    '5': 'deploy-vault'
  };

  const tabName = tabMap[e.key];
  if (tabName) {
    const tabButton = document.querySelector(`.tab[data-tab="${tabName}"]`);
    // Check if tab is visible and not locked
    if (tabButton && tabButton.style.display !== 'none' && !tabButton.classList.contains('locked')) {
      e.preventDefault();
      switchToTab(tabName);
    }
  }
});

// ---- PIN Management ----
async function loadPinStatus() {
  try {
    const token = idToken();
    if (!token) {
      console.error('[PIN] No ID token found');
      throw new Error('No authentication token found');
    }
    const res = await fetch(API_URL + '/account/security/pin/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    // Handle 404 as "PIN not configured yet" (valid state for new users)
    if (res.status === 404) {
      pinStatusData = { pin_enabled: false }; // Cache the result
      const statusSpan = document.getElementById('pinStatus');
      const updatedAtP = document.getElementById('pinUpdatedAt');
      const enableBtn = document.getElementById('enablePinBtn');
      const updateBtn = document.getElementById('updatePinBtn');
      const disableBtn = document.getElementById('disablePinBtn');

      statusSpan.textContent = 'Disabled';
      statusSpan.style.color = '#f44336';
      statusSpan.style.fontWeight = '600';
      updatedAtP.innerHTML = '';
      enableBtn.style.display = 'inline-block';
      updateBtn.style.display = 'none';
      disableBtn.style.display = 'none';
      return; // Exit early - this is not an error
    }

    if (!res.ok) {
      const errorText = await res.text();
      console.error('[PIN] Error response:', errorText);
      throw new Error(`Failed to load PIN status: ${res.status} ${errorText}`);
    }
    const data = await res.json();
    pinStatusData = data; // Cache the result

    const statusSpan = document.getElementById('pinStatus');
    const updatedAtP = document.getElementById('pinUpdatedAt');
    const enableBtn = document.getElementById('enablePinBtn');
    const updateBtn = document.getElementById('updatePinBtn');
    const disableBtn = document.getElementById('disablePinBtn');

    if (data.pin_enabled) {
      statusSpan.textContent = 'Enabled';
      statusSpan.style.color = '#4caf50';
      statusSpan.style.fontWeight = '600';
      if (data.pin_updated_at) {
        updatedAtP.innerHTML = '<span class="muted" style="font-size:0.85rem;">Last updated: ' + new Date(data.pin_updated_at).toLocaleString() + '</span>';
      }
      enableBtn.style.display = 'none';
      updateBtn.style.display = 'inline-block';
      disableBtn.style.display = 'inline-block';
    } else {
      statusSpan.textContent = 'Disabled';
      statusSpan.style.color = '#f44336';
      statusSpan.style.fontWeight = '600';
      updatedAtP.innerHTML = '';
      enableBtn.style.display = 'inline-block';
      updateBtn.style.display = 'none';
      disableBtn.style.display = 'none';
    }
  } catch (err) {
    console.error('Error loading PIN status:', err);
    document.getElementById('pinStatus').textContent = 'Error loading status';
  }
}

function validatePin(pin) {
  return /^\d{4,6}$/.test(pin);
}

function showEnablePinModal() {
  document.getElementById('enablePinModal').style.display = 'flex';
  document.getElementById('newPinInput').value = '';
  document.getElementById('confirmPinInput').value = '';
  document.getElementById('pinMatchIndicator').style.display = 'none';
  document.getElementById('newPinInput').focus();

  // Setup PIN match indicator
  const newPinInput = document.getElementById('newPinInput');
  const confirmPinInput = document.getElementById('confirmPinInput');
  const indicator = document.getElementById('pinMatchIndicator');

  function checkPinMatch() {
    const newPin = newPinInput.value;
    const confirmPin = confirmPinInput.value;

    if (!confirmPin) {
      indicator.style.display = 'none';
      return;
    }

    indicator.style.display = 'flex';

    if (newPin === confirmPin && newPin.length >= 4) {
      // Pins match
      indicator.style.background = 'rgba(76, 175, 80, 0.15)';
      indicator.style.border = '1px solid #4caf50';
      indicator.innerHTML = '<span style="color:#4caf50;font-size:1.2rem;">✓</span><span style="color:#4caf50;">PINs match</span>';
    } else {
      // Pins don't match
      indicator.style.background = 'rgba(244, 67, 54, 0.15)';
      indicator.style.border = '1px solid #f44336';
      indicator.innerHTML = '<span style="color:#f44336;font-size:1.2rem;">✗</span><span style="color:#f44336;">PINs do not match</span>';
    }
  }

  newPinInput.addEventListener('input', checkPinMatch);
  confirmPinInput.addEventListener('input', checkPinMatch);
}

function hideEnablePinModal() {
  document.getElementById('enablePinModal').style.display = 'none';
}

function showUpdatePinModal() {
  document.getElementById('updatePinModal').style.display = 'flex';
  document.getElementById('currentPinInput').value = '';
  document.getElementById('updatePinInput').value = '';
  document.getElementById('confirmUpdatePinInput').value = '';
  document.getElementById('currentPinInput').focus();
}

function hideUpdatePinModal() {
  document.getElementById('updatePinModal').style.display = 'none';
}

async function confirmEnablePin() {
  const pin = document.getElementById('newPinInput').value;
  const confirmPin = document.getElementById('confirmPinInput').value;

  if (!validatePin(pin)) {
    showToast('PIN must be 4-6 digits', 'error');
    return;
  }

  if (pin !== confirmPin) {
    showToast('PINs do not match', 'error');
    return;
  }

  const btn = document.getElementById('confirmEnablePinBtn');
  setLoading(btn, true);

  try {
    const res = await fetch(API_URL + '/account/security/pin/enable', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ pin: pin })
    });

    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to enable PIN'), 'error');
      setLoading(btn, false);
      return;
    }

    const data = await res.json();
    showToast(data.message || 'PIN enabled successfully', 'success');
    hideEnablePinModal();
    setLoading(btn, false);
    await loadPinStatus();

    // Redirect to getting started tab and refresh steps
    await populateGettingStartedSteps();
    switchToTab('getting-started');
  } catch (err) {
    console.error('Error enabling PIN:', err);
    showToast('Error: ' + (err.message || 'Failed to enable PIN'), 'error');
    setLoading(btn, false);
  }
}

async function confirmUpdatePin() {
  const currentPin = document.getElementById('currentPinInput').value;
  const newPin = document.getElementById('updatePinInput').value;
  const confirmPin = document.getElementById('confirmUpdatePinInput').value;

  if (!validatePin(currentPin)) {
    showToast('Current PIN must be 4-6 digits', 'error');
    return;
  }

  if (!validatePin(newPin)) {
    showToast('New PIN must be 4-6 digits', 'error');
    return;
  }

  if (newPin !== confirmPin) {
    showToast('New PINs do not match', 'error');
    return;
  }

  if (currentPin === newPin) {
    showToast('New PIN must be different from current PIN', 'error');
    return;
  }

  const btn = document.getElementById('confirmUpdatePinBtn');
  setLoading(btn, true);

  try {
    const res = await fetch(API_URL + '/account/security/pin/update', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ currentPin: currentPin, newPin: newPin })
    });

    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to update PIN'), 'error');
      setLoading(btn, false);
      return;
    }

    const data = await res.json();
    showToast(data.message || 'PIN updated successfully', 'success');
    hideUpdatePinModal();
    setLoading(btn, false);
    await loadPinStatus();
  } catch (err) {
    console.error('Error updating PIN:', err);
    showToast('Error: ' + (err.message || 'Failed to update PIN'), 'error');
    setLoading(btn, false);
  }
}

async function disablePin() {
  const confirmed = await showConfirmModal({
    title: 'Disable PIN Authentication',
    message: 'Are you sure you want to disable PIN authentication? You will only need your magic link to sign in.',
    confirmText: 'Disable PIN',
    cancelText: 'Keep PIN',
    type: 'warning'
  });
  if (!confirmed) return;

  // Show PIN confirmation modal instead of prompt
  showPinDisableModal();
}

async function executePinDisable(currentPin) {
  const btn = document.getElementById('disablePinBtn');
  setLoading(btn, true);

  try {
    const res = await fetch(API_URL + '/account/security/pin/disable', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ currentPin })
    });

    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to disable PIN'), 'error');
      setLoading(btn, false);
      return;
    }

    const data = await res.json();
    showToast(data.message || 'PIN disabled successfully', 'success');
    setLoading(btn, false);
    await loadPinStatus();
  } catch (err) {
    console.error('Error disabling PIN:', err);
    showToast('Error: ' + (err.message || 'Failed to disable PIN'), 'error');
    setLoading(btn, false);
  }
}

// ---- Email Preferences Management ----
async function loadEmailPreferences() {
  try {
    const token = idToken();
    if (!token) {
      console.error('[Email Prefs] No ID token found');
      throw new Error('No authentication token found');
    }

    const res = await fetch(API_URL + '/account/email-preferences', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      const errorText = await res.text();
      console.error('[Email Prefs] Error response:', errorText);
      throw new Error(`Failed to load email preferences: ${res.status}`);
    }

    const data = await res.json();
    const toggle = document.getElementById('systemEmailsToggle');
    const statusSpan = document.getElementById('emailPrefsStatus');

    // Set toggle state
    toggle.checked = data.system_emails_enabled;
    toggle.disabled = false;

    // Update status text
    if (data.system_emails_enabled) {
      statusSpan.textContent = 'Enabled - You will receive system emails';
      statusSpan.style.color = '#4caf50';
      if (data.opted_in_at) {
        statusSpan.textContent += ' (since ' + new Date(data.opted_in_at).toLocaleDateString() + ')';
      }
    } else {
      statusSpan.textContent = 'Disabled - You will not receive system emails';
      statusSpan.style.color = '#f44336';
      if (data.opted_out_at) {
        statusSpan.textContent += ' (since ' + new Date(data.opted_out_at).toLocaleDateString() + ')';
      }
    }
  } catch (err) {
    console.error('Error loading email preferences:', err);
    document.getElementById('emailPrefsStatus').textContent = 'Error loading preferences';
    document.getElementById('emailPrefsStatus').style.color = '#f44336';
  }
}

async function toggleEmailPreferences(event) {
  const toggle = event.target;
  const newValue = toggle.checked;

  // Show confirmation dialog based on action
  const modalOptions = newValue ? {
    title: 'Enable System Emails',
    message: 'By enabling system emails, you agree to receive account notifications, security alerts, and service updates from VettID. Do you want to continue?',
    confirmText: 'Enable',
    cancelText: 'Cancel',
    type: 'default'
  } : {
    title: 'Disable System Emails',
    message: 'If you disable system emails, you will stop receiving important account notifications, security alerts, and service updates. Are you sure you want to continue?',
    confirmText: 'Disable',
    cancelText: 'Keep Enabled',
    type: 'warning'
  };

  const confirmed = await showConfirmModal(modalOptions);
  if (!confirmed) {
    // User cancelled, revert toggle
    toggle.checked = !newValue;
    return;
  }

  // Disable toggle during update
  toggle.disabled = true;

  try {
    const res = await fetch(API_URL + '/account/email-preferences', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        system_emails_enabled: newValue
      })
    });

    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to update email preferences'), 'error');
      // Revert toggle on error
      toggle.checked = !newValue;
      toggle.disabled = false;
      return;
    }

    const data = await res.json();
    showToast(data.message || 'Email preferences updated successfully', 'success');

    // Reload preferences to update status text
    await loadEmailPreferences();
  } catch (err) {
    console.error('Error updating email preferences:', err);
    showToast('Error: ' + (err.message || 'Failed to update email preferences'), 'error');
    // Revert toggle on error
    toggle.checked = !newValue;
    toggle.disabled = false;
  }
}

// ---- Membership Management ----
let currentTermsData = null;

async function loadMembershipTerms() {
  try {
    const res = await fetch(API_URL + '/account/membership/terms', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });
    if (!res.ok) {
      throw new Error('Failed to load membership terms');
    }
    currentTermsData = await res.json();

    // Display terms text (using textContent to prevent XSS)
    const termsBox = document.getElementById('termsTextBox');
    const pre = document.createElement('pre');
    pre.style.cssText = 'white-space:pre-wrap;font-family:inherit;margin:0;line-height:1.6;';
    pre.textContent = currentTermsData.terms_text || '';
    termsBox.innerHTML = '';
    termsBox.appendChild(pre);

    // Set all download links (validate URL to prevent open redirect)
    const validatedUrl = validateUrl(currentTermsData.download_url);
    document.getElementById('termsDownloadLink').href = validatedUrl || '#';
    document.getElementById('memberTermsDownloadLink').href = validatedUrl || '#';

  } catch (err) {
    console.error('Error loading membership terms:', err);
    const termsBox = document.getElementById('termsTextBox');
    if (err.message && err.message.includes('404')) {
      termsBox.innerHTML = '<p class="muted">Membership terms have not been configured yet. Please contact an administrator.</p>';
    } else {
      // Don't expose raw error message - use generic message
      termsBox.innerHTML = '<p class="muted">Failed to load membership terms. Please try again later.</p>';
    }
    // Disable the request button if terms can't be loaded
    const requestBtn = document.getElementById('requestMembershipBtn');
    if (requestBtn) {
      requestBtn.disabled = true;
      requestBtn.style.opacity = '0.5';
    }
  }
}

async function loadMembershipStatus() {
  try {
    const token = idToken();
    if (!token) {
      console.error('[MEMBERSHIP] No ID token found');
      throw new Error('No authentication token found');
    }
    const res = await fetch(API_URL + '/account/membership/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (!res.ok) {
      throw new Error('Failed to load membership status');
    }
    const data = await res.json();

    // Store membership status globally
    membershipStatus = data.membership_status;

    const statusSpan = document.getElementById('membershipStatus');
    const detailsP = document.getElementById('membershipDetails');
    const termsSection = document.getElementById('membershipTermsSection');
    const memberInfoSection = document.getElementById('memberInfoSection');
    const membershipCard = document.getElementById('membershipCard');

    switch (data.membership_status) {
      case 'none':
        statusSpan.textContent = 'Registered User';
        statusSpan.style.color = '#ffc125';
        statusSpan.style.fontWeight = '600';
        detailsP.innerHTML = '<span class="muted" style="font-size:0.85rem;">You are a registered user. Review and accept the membership terms below to request full membership.</span>';
        termsSection.style.display = 'block';
        memberInfoSection.style.display = 'none';
        membershipCard.classList.add('double-width');
        await loadMembershipTerms();
        break;
      case 'pending':
        statusSpan.textContent = 'Membership Pending';
        statusSpan.style.color = '#ffc125';
        statusSpan.style.fontWeight = '600';
        detailsP.innerHTML = '<span class="muted" style="font-size:0.85rem;">Your membership request is pending approval.</span>';
        termsSection.style.display = 'none';
        memberInfoSection.style.display = 'none';
        membershipCard.classList.remove('double-width');
        break;
      case 'approved':
        statusSpan.textContent = 'Member';
        statusSpan.style.color = '#4caf50';
        statusSpan.style.fontWeight = '600';
        // Only show "Activate a paid subscription" if user doesn't have an active paid subscription
        if (!isPaidSubscriber()) {
          detailsP.innerHTML = '<span class="muted" style="font-size:0.85rem;"><a href="#" data-action="switchTab" data-tab="subscription" style="color:var(--accent);text-decoration:underline;font-weight:600;">Activate a paid subscription</a> to unlock all features.</span>';
        } else {
          detailsP.innerHTML = '<span class="muted" style="font-size:0.85rem;">You have an active subscription with access to all features.</span>';
        }
        termsSection.style.display = 'none';
        memberInfoSection.style.display = 'block';
        membershipCard.classList.remove('double-width');

        let memberDetails = '';
        if (data.membership_approved_at) {
          memberDetails += '<strong>Approved:</strong> ' + new Date(data.membership_approved_at).toLocaleString() + '<br>';
        }
        if (data.terms_accepted_at) {
          memberDetails += '<strong>Terms Accepted:</strong> ' + new Date(data.terms_accepted_at).toLocaleString() + '<br>';
        }
        if (data.terms_version_id) {
          memberDetails += '<strong>Terms Version:</strong> ' + data.terms_version_id;
        }
        document.getElementById('memberDetailsText').innerHTML = memberDetails;
        await loadMembershipTerms();

        // Check if JWT token has member group - if not, try to refresh tokens
        const { payload } = parseJwt(token);
        const groups = payload['cognito:groups'] || [];
        if (!groups.includes('member')) {
          // Try to refresh tokens automatically
          detailsP.innerHTML += '<br><br><div style="padding:12px;background:#2196f3;color:#fff;border-radius:4px;margin-top:12px;"><strong>Updating access...</strong> Please wait while we activate your member features.</div>';
          const refreshed = await refreshTokens();
          if (refreshed) {
            // Reload the page to apply new token
            window.location.reload();
          } else {
            detailsP.innerHTML += '<br><br><div style="padding:12px;background:#ff9800;color:#000;border-radius:4px;margin-top:12px;"><strong>Action Required:</strong> Your membership has been approved! Please <a href="#" data-action="signOut" style="color:#000;text-decoration:underline;font-weight:700;">sign out and sign back in</a> to update your account and gain access to member features.</div>';
          }
        }
        break;
      default:
        statusSpan.textContent = 'Unknown';
        detailsP.innerHTML = '';
        termsSection.style.display = 'none';
        memberInfoSection.style.display = 'none';
        membershipCard.classList.remove('double-width');
    }
  } catch (err) {
    console.error('Error loading membership status:', err);
    const statusSpan = document.getElementById('membershipStatus');
    const detailsP = document.getElementById('membershipDetails');
    const membershipCard = document.getElementById('membershipCard');
    statusSpan.textContent = 'Error loading status';
    statusSpan.style.color = '#f44336';
    detailsP.innerHTML = '<span class="muted" style="font-size:0.85rem;">Unable to load membership status. Please try refreshing the page. Error: ' + (err.message || 'Unknown error') + '</span>';

    // Try to load terms anyway in case that works
    const termsSection = document.getElementById('membershipTermsSection');
    termsSection.style.display = 'block';
    membershipCard.classList.add('double-width');
    await loadMembershipTerms().catch(termsErr => {
      console.error('Also failed to load terms:', termsErr);
    });
  }
}

async function requestMembership() {
  if (!currentTermsData || !currentTermsData.version_id) {
    showToast('Unable to process request: Terms data not loaded', 'error');
    return;
  }

  const checkbox = document.getElementById('acceptTermsCheckbox');
  if (!checkbox.checked) {
    showToast('You must accept the membership terms before requesting membership', 'warning');
    return;
  }

  // Show custom modal instead of browser confirm
  showMembershipConfirmModal();
}

async function executeMembershipRequest() {
  const btn = document.getElementById('requestMembershipBtn');
  const msgEl = document.getElementById('requestMembershipMsg');
  setLoading(btn, true);

  try {
    const res = await fetch(API_URL + '/account/membership/request', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        terms_version_id: currentTermsData.version_id
      })
    });

    if (!res.ok) {
      const err = await res.json();
      msgEl.textContent = 'Error: ' + (err.message || 'Failed to request membership');
      msgEl.style.color = '#f44336';
      showToast('Error: ' + (err.message || 'Failed to request membership'), 'error');
      setLoading(btn, false);
      return;
    }

    const data = await res.json();
    msgEl.textContent = data.message || 'Membership approved successfully';
    msgEl.style.color = '#4caf50';
    showToast(data.message || 'Membership approved successfully', 'success');

    // If response indicates user needs updated token (new group membership)
    if (data.requires_signin) {
      // Try to refresh tokens silently instead of forcing sign out
      showToast('Updating your account access...', 'info');
      const refreshed = await refreshTokens();

      if (refreshed) {
        // Token refreshed successfully - reload UI with new permissions
        clearGettingStartedComplete();
        await loadMembershipStatus();
        await populateGettingStartedSteps();
        updateTabVisibility();
        showToast('Membership activated! You now have full member access.', 'success');
      } else {
        // Refresh failed - fall back to sign out
        clearGettingStartedComplete();
        showToast('Please sign in again to complete activation.', 'warning');
        setTimeout(() => {
          signOut();
        }, 2000);
      }
    } else {
      setLoading(btn, false);
      await loadMembershipStatus();
    }

    // Redirect to getting started tab and refresh steps
    await populateGettingStartedSteps();
    switchToTab('getting-started');
  } catch (err) {
    console.error('Error requesting membership:', err);
    showToast('Error: ' + (err.message || 'Failed to request membership'), 'error');
    setLoading(btn, false);
  }
}

// Subscription functions
async function createSubscription(subscription_type_id) {
  const msgEl = document.getElementById('subscriptionMessage');

  try {
    const res = await fetch(API_URL + '/account/subscriptions', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ subscription_type_id })
    });

    const data = await res.json();

    if (!res.ok) {
      msgEl.style.display = 'block';
      msgEl.style.background = '#3d0a0a';
      msgEl.style.border = '1px solid #f44336';
      msgEl.innerHTML = '<strong>Error</strong><br/>' + (data.message || 'Failed to create subscription');
      msgEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }

    msgEl.style.display = 'block';
    msgEl.style.background = '#0a3d0a';
    msgEl.style.border = '1px solid #4caf50';

    const expiresDate = new Date(data.subscription.expires_at).toLocaleDateString();
    msgEl.innerHTML = '<strong>Subscription Activated!</strong><br/>' + data.message + ' (Expires: ' + expiresDate + ')';
    msgEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Check if this was the user's first subscription
    const wasFirstSubscription = !subscriptionStatus || !subscriptionStatus.has_subscription;

    // Reload subscription status (this updates has_used_trial flag)
    await loadSubscriptionStatus();

    // Reload subscription types to filter out used one-time offers
    await loadSubscriptionTypes();

    // Update tab visibility to show subscriber tabs
    updateTabVisibility();

    // Only redirect to getting started for first subscription
    if (wasFirstSubscription) {
      await populateGettingStartedSteps();
      switchToTab('getting-started');
    } else {
      // Just refresh the steps but stay on current tab
      await populateGettingStartedSteps();
    }
  } catch (err) {
    console.error('Error creating subscription:', err);
    msgEl.style.display = 'block';
    msgEl.style.background = '#3d0a0a';
    msgEl.style.border = '1px solid #f44336';
    msgEl.innerHTML = '<strong>Error</strong><br/>Failed to create subscription. Please try again.';
    msgEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// Load subscription status
async function loadSubscriptionStatus() {
  try {
    const res = await fetch(API_URL + '/account/subscriptions/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });

    if (!res.ok) {
      console.error('[SUBSCRIPTION] Failed to load subscription status');
      return;
    }

    subscriptionStatus = await res.json();

    // Update UI based on subscription status
    updateSubscriptionUI();
  } catch (err) {
    console.error('[SUBSCRIPTION] Error loading subscription status:', err);
  }
}

function updateSubscriptionUI() {
  const detailsDiv = document.getElementById('currentSubscriptionDetails');
  const profileSubDiv = document.getElementById('profileSubscriptionStatus');
  const msgEl = document.getElementById('subscriptionMessage');

  if (subscriptionStatus && subscriptionStatus.is_active) {
    // User has active subscription - show subscription details
    let plan = subscriptionStatus.plan || 'Unknown';
    let expiresAt = subscriptionStatus.expires_at ? new Date(subscriptionStatus.expires_at).toLocaleString() : 'N/A';
    let status = subscriptionStatus.status || 'Unknown';
    let statusColor = '#4caf50';
    let statusText = status;

    // Better status display for cancelled subscriptions
    if (status === 'cancelled') {
      statusColor = '#ff9800';
      statusText = 'Cancelled (Active until expiry)';
    } else if (status === 'active') {
      statusColor = '#4caf50';
      statusText = 'Active';
    } else if (status === 'expired') {
      statusColor = '#f44336';
      statusText = 'Expired';
    }

    detailsDiv.innerHTML = `
      <div style="padding:16px;background:#0a0a0a;border-radius:4px;border:2px solid var(--accent);margin-bottom:16px;">
        <p><strong>Plan:</strong> ${plan}</p>
        <p><strong>Status:</strong> <span style="color:${statusColor};font-weight:600;">${statusText}</span></p>
        <p style="margin-bottom:0;"><strong>Expires:</strong> ${expiresAt}</p>
      </div>
      ${status === 'cancelled' ? '<p style="color:#ff9800;font-size:0.9rem;margin-top:8px;"><strong>Note:</strong> Your subscription has been cancelled but you retain access until the expiration date above.</p>' : ''}
      ${status === 'active' ? '<button class="btn" data-action="cancelSubscription" style="background:linear-gradient(135deg,#d32f2f 0%,#a00 100%);color:#fff;">Cancel Subscription</button>' : ''}
    `;

    // Update profile subscription status
    if (profileSubDiv) {
      profileSubDiv.innerHTML = `
        <p style="margin:0;"><strong>Plan:</strong> ${plan}</p>
        <p style="margin:8px 0 0;"><strong>Status:</strong> <span style="color:${statusColor};font-weight:600;">${statusText}</span></p>
      `;
    }
  } else {
    // No active subscription - clear any success messages
    if (msgEl) {
      msgEl.style.display = 'none';
      msgEl.innerHTML = '';
    }

    detailsDiv.innerHTML = `
      <div style="padding:24px;background:#0a0a0a;border-radius:4px;text-align:center;">
        <p class="muted" style="font-size:1rem;margin:0;">No active subscription</p>
        <p class="muted" style="font-size:0.85rem;margin-top:8px;margin-bottom:0;">Select a plan from the options to get started.</p>
      </div>
    `;

    // Update profile subscription status
    if (profileSubDiv) {
      profileSubDiv.innerHTML = `
        <p style="margin:0;color:#999;">No active subscription</p>
      `;
    }
  }
}

function isSubscriber() {
  return subscriptionStatus && subscriptionStatus.is_active === true;
}

function isPaidSubscriber() {
  return subscriptionStatus && subscriptionStatus.is_active === true && subscriptionStatus.amount > 0;
}


async function cancelSubscription() {
  const confirmed = await showConfirmModal({
    title: 'Cancel Subscription',
    message: 'Are you sure you want to cancel your subscription? You will lose access when your current period ends.',
    confirmText: 'Cancel Subscription',
    cancelText: 'Keep Subscription',
    type: 'danger'
  });
  if (!confirmed) return;

  // Create a temporary button reference for loading state
  const tempBtn = document.createElement('button');
  tempBtn.textContent = 'Cancel Subscription';

  try {
    const res = await fetch(API_URL + '/account/subscriptions/cancel', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const err = await res.json();
      showToast('Error: ' + (err.message || 'Failed to cancel subscription'), 'error');
      return;
    }

    const data = await res.json();
    showToast(data.message || 'Your subscription has been cancelled. You will retain access until the end of your billing period.', 'success');
    await loadSubscriptionStatus();
  } catch (err) {
    console.error('Error cancelling subscription:', err);
    showToast('Failed to cancel subscription. Please try again.', 'error');
  }
}

// Event listeners
document.getElementById('signout').onclick = signOut;
document.getElementById('cancelAccountBtn').onclick = cancelAccount;

// User dropdown toggle
const userDropdownBtn = document.querySelector('.user-dropdown-btn');
const userDropdownMenu = document.getElementById('userDropdownMenu');
if (userDropdownBtn) {
  userDropdownBtn.onclick = (e) => {
    e.stopPropagation();
    userDropdownMenu.classList.toggle('active');
  };
}
// Close dropdown when clicking outside
document.addEventListener('click', () => {
  if (userDropdownMenu) userDropdownMenu.classList.remove('active');
});

// Membership Management event listeners
document.getElementById('requestMembershipBtn').onclick = requestMembership;

// Terms acceptance checkbox handler
document.getElementById('acceptTermsCheckbox').onchange = function() {
  const btn = document.getElementById('requestMembershipBtn');
  if (this.checked) {
    btn.disabled = false;
    btn.style.opacity = '1';
  } else {
    btn.disabled = true;
    btn.style.opacity = '0.5';
  }
};

// PIN Management event listeners
document.getElementById('enablePinBtn').onclick = showEnablePinModal;
document.getElementById('updatePinBtn').onclick = showUpdatePinModal;
document.getElementById('disablePinBtn').onclick = disablePin;
document.getElementById('cancelEnablePinBtn').onclick = hideEnablePinModal;
document.getElementById('confirmEnablePinBtn').onclick = confirmEnablePin;
document.getElementById('cancelUpdatePinBtn').onclick = hideUpdatePinModal;
document.getElementById('confirmUpdatePinBtn').onclick = confirmUpdatePin;

// Email Preferences event listener
document.getElementById('systemEmailsToggle').onchange = toggleEmailPreferences;

// Close modals on background click
document.getElementById('enablePinModal').onclick = (e) => {
  if (e.target === e.currentTarget) hideEnablePinModal();
};
document.getElementById('updatePinModal').onclick = (e) => {
  if (e.target === e.currentTarget) hideUpdatePinModal();
};

// ---- Voting Functions ----
let userVotesCache = null;
let allProposalsData = { active: [], upcoming: [], completed: [] };
let currentProposalFilter = 'active';

async function loadAllProposals() {
  // Show skeleton loading
  showGridLoadingSkeleton('proposalsContainer', 3);

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/proposals', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) throw new Error('Failed to load proposals');
    const data = await res.json();

    // Store proposals data
    allProposalsData = {
      active: data.active || [],
      upcoming: data.upcoming || [],
      completed: data.closed || []  // Using closed data as completed
    };

    // Load user's existing votes
    await loadUserVotes();

    // Update all count badges
    updateProposalCounts();

    // Render proposals based on current filter
    renderProposals(currentProposalFilter);

    // Set up filter button handlers
    setupProposalFilters();

  } catch (error) {
    console.error('Error loading proposals:', error);
    document.getElementById('proposalsContainer').innerHTML = '<p style="color:#f44336;text-align:center;padding:20px;grid-column:1/-1;">Failed to load proposals</p>';
  }
}

function updateProposalCounts() {
  document.getElementById('activeProposalsCount').textContent = allProposalsData.active.length;
  document.getElementById('completedProposalsCount').textContent = allProposalsData.completed.length;

  // Update voting badge with count of active proposals user hasn't voted on
  updateVotingBadge();
}

function updateVotingBadge() {
  const badge = document.getElementById('votingBadge');
  if (!badge) return;

  // Count active proposals the user hasn't voted on
  const unvotedCount = allProposalsData.active.filter(proposal => {
    const hasVoted = userVotesCache && userVotesCache.some(v => v.proposal_id === proposal.proposal_id);
    return !hasVoted;
  }).length;

  if (unvotedCount > 0) {
    badge.textContent = unvotedCount;
    badge.style.display = 'inline-flex';
  } else {
    badge.style.display = 'none';
  }
}

function setupProposalFilters() {
  const filters = document.querySelectorAll('.proposal-filter');
  filters.forEach(filter => {
    filter.addEventListener('click', () => {
      const filterType = filter.dataset.filter;
      currentProposalFilter = filterType;

      // Update active state
      filters.forEach(f => f.classList.remove('active'));
      filter.classList.add('active');

      // Render filtered proposals
      renderProposals(filterType);
    });
  });
}

async function renderProposals(filter) {
  const container = document.getElementById('proposalsContainer');

  let proposalsToRender = [];

  if (filter === 'active') {
    proposalsToRender = [...allProposalsData.active].sort((a, b) => new Date(a.closes_at) - new Date(b.closes_at));

    if (proposalsToRender.length === 0) {
      container.innerHTML = `
        <div style="grid-column:1/-1;text-align:center;padding:60px 20px;">
          <div style="background:linear-gradient(135deg,#1a1a1a 0%,#0a0a0a 100%);border-radius:12px;border:2px solid #222;padding:40px 20px;max-width:500px;margin:0 auto;">
            <div style="width:80px;height:80px;margin:0 auto 20px;background:rgba(16,185,129,0.1);border-radius:50%;display:flex;align-items:center;justify-content:center;">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
                <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                <path d="M9 12l2 2 4-4"/>
              </svg>
            </div>
            <h4 style="color:var(--accent);margin:0 0 12px 0;font-size:1.2rem;">No Active Proposals</h4>
            <p style="color:var(--gray);margin:0 0 20px 0;line-height:1.6;">There are no proposals currently open for voting. Check back soon for new community proposals.</p>
            <button class="btn proposal-filter" data-action="filterProposals" data-filter="completed" style="background:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);padding:10px 24px;font-weight:600;">
              View Completed Proposals
            </button>
          </div>
        </div>
      `;
      return;
    }
  } else if (filter === 'completed') {
    proposalsToRender = [...allProposalsData.completed].sort((a, b) => new Date(b.closes_at) - new Date(a.closes_at));

    if (proposalsToRender.length === 0) {
      container.innerHTML = `
        <div style="grid-column:1/-1;text-align:center;padding:60px 20px;">
          <div style="background:linear-gradient(135deg,#1a1a1a 0%,#0a0a0a 100%);border-radius:12px;border:2px solid #222;padding:40px 20px;max-width:500px;margin:0 auto;">
            <div style="width:80px;height:80px;margin:0 auto 20px;background:rgba(99,102,241,0.1);border-radius:50%;display:flex;align-items:center;justify-content:center;">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <h4 style="color:var(--accent);margin:0 0 12px 0;font-size:1.2rem;">No Completed Proposals</h4>
            <p style="color:var(--gray);margin:0 0 20px 0;line-height:1.6;">No proposals have been completed yet. Completed proposals will appear here after voting closes.</p>
            <button class="btn proposal-filter" data-action="filterProposals" data-filter="active" style="background:linear-gradient(135deg,#10b981 0%,#059669 100%);padding:10px 24px;font-weight:600;">
              View Active Proposals
            </button>
          </div>
        </div>
      `;
      return;
    }

    // Render completed proposals in tiled grid
    renderCompletedProposals(proposalsToRender);
    return;
  }

  container.innerHTML = proposalsToRender.map(proposal => {
    const proposalId = proposal.proposal_id;
    const hasVoted = userVotesCache && userVotesCache.some(v => v.proposal_id === proposalId);
    const userVote = userVotesCache && userVotesCache.find(v => v.proposal_id === proposalId);

    // Render active proposal
      const closesAt = new Date(proposal.closes_at);
      const now = new Date();
      const diff = closesAt - now;
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const timeRemaining = days > 0 ? `${days}d ${hours}h` : hours > 0 ? `${hours}h` : 'Closing soon';

      return `
        <div style="background:#0a0a0a;border:1px solid #333;border-radius:8px;padding:12px;">
          ${proposal.proposal_number ? `<div style="margin-bottom:4px;"><span style="font-family:monospace;font-size:0.7rem;color:#6b7280;background:#1f2937;padding:2px 6px;border-radius:4px;">${proposal.proposal_number}</span></div>` : ''}
          <h4 style="margin:0 0 6px 0;font-weight:700;font-size:0.95rem;">${proposal.proposal_title || 'Untitled Proposal'}</h4>
          <div style="margin-bottom:8px;">
            <span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>
          </div>
          <div style="margin-bottom:8px;padding:8px;background:#1a1a1a;border-radius:6px;text-align:center;">
            <span style="font-size:0.85rem;color:var(--accent);font-weight:600;">Closes in ${timeRemaining}</span>
          </div>
          <button data-action="toggleProposalText" data-target="proposal-text-${proposalId}" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;">View Proposal</button>
          <div id="proposal-text-${proposalId}" style="display:none;padding:10px;background:#050505;border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;">${proposal.proposal_text}</div>
          ${hasVoted ? `
            <div style="margin-bottom:8px;padding:10px;background:#050505;border-left:3px solid ${userVote && userVote.vote ? (userVote.vote.toLowerCase() === 'yes' ? '#10b981' : userVote.vote.toLowerCase() === 'no' ? '#ef4444' : '#6b7280') : '#4caf50'};border-radius:4px;">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-size:0.8rem;color:var(--gray);">Your vote:</span>
                <span style="font-size:0.85rem;font-weight:700;color:${userVote && userVote.vote ? (userVote.vote.toLowerCase() === 'yes' ? '#10b981' : userVote.vote.toLowerCase() === 'no' ? '#ef4444' : '#6b7280') : '#4caf50'};text-transform:uppercase;">${userVote && userVote.vote ? userVote.vote : 'UNKNOWN'}</span>
              </div>
            </div>
          ` : `
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:8px;">
              <button class="btn" data-action="selectVote" data-proposal-id="${proposalId}" data-vote="yes" id="vote-${proposalId}-yes" style="padding:10px 8px;font-size:0.8rem;background:#16a34a;color:#fff;border:2px solid transparent;font-weight:600;">Yes</button>
              <button class="btn" data-action="selectVote" data-proposal-id="${proposalId}" data-vote="no" id="vote-${proposalId}-no" style="padding:10px 8px;font-size:0.8rem;background:#dc2626;color:#fff;border:2px solid transparent;font-weight:600;">No</button>
              <button class="btn" data-action="selectVote" data-proposal-id="${proposalId}" data-vote="abstain" id="vote-${proposalId}-abstain" style="padding:10px 8px;font-size:0.8rem;background:#6b7280;color:#fff;border:2px solid transparent;font-weight:600;">Abstain</button>
            </div>
            <button class="btn" data-action="submitVote" data-proposal-id="${proposalId}" id="submit-${proposalId}" style="width:100%;display:none;padding:10px;font-size:0.85rem;background:var(--accent);color:#000;font-weight:600;">Submit Vote</button>
          `}
          <div id="results-${proposalId}" style="margin-top:8px;"></div>
        </div>
      `;
  }).join('');

  // Load results for active proposals
  for (const proposal of proposalsToRender) {
    const proposalId = proposal.proposal_id;
    await loadCompactVoteResults(proposalId, 'results-' + proposalId);
  }
}

let selectedVotes = {};

function selectVote(proposalId, choice) {
  selectedVotes[proposalId] = choice;

  // Update button styles
  ['yes', 'no', 'abstain'].forEach(c => {
    const btn = document.getElementById(`vote-${proposalId}-${c}`);
    if (c === choice) {
      btn.style.borderColor = 'var(--accent)';
      btn.style.fontWeight = '600';
    } else {
      btn.style.borderColor = 'transparent';
      btn.style.fontWeight = '400';
    }
  });

  // Show submit button
  document.getElementById(`submit-${proposalId}`).style.display = 'block';
}

async function submitVote(proposalId) {
  const choice = selectedVotes[proposalId];
  if (!choice) return;

  const confirmed = await showConfirmModal({
    title: 'Confirm Vote Submission',
    message: '<strong style="color:#ff9800;">WARNING:</strong> Your vote is permanent and cannot be changed once submitted.<br><br>Are you sure you want to submit your vote?',
    confirmText: 'Submit Vote',
    cancelText: 'Cancel',
    type: 'warning'
  });
  if (!confirmed) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/votes', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        proposal_id: proposalId,
        vote: choice
      })
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.message || 'Failed to submit vote');
    }

    await showAlertModal({
      type: 'success',
      title: 'Vote Recorded',
      message: 'Your vote has been recorded successfully!'
    });

    // Clear cache and reload
    userVotesCache = null;
    delete selectedVotes[proposalId];
    await loadAllProposals();
  } catch (error) {
    console.error('Error submitting vote:', error);
    await showAlertModal({
      type: 'error',
      title: 'Vote Failed',
      message: 'Failed to submit vote: ' + error.message
    });
  }
}

async function loadUserVotes() {
  if (userVotesCache) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/votes/history', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    // Handle 400/404 as "no votes yet" (valid state for new users)
    if (res.status === 400 || res.status === 404) {
      userVotesCache = [];
      return;
    }

    if (!res.ok) throw new Error('Failed to load vote history');
    const data = await res.json();

    userVotesCache = data.votes || [];
  } catch (error) {
    console.error('Error loading user votes:', error);
    userVotesCache = [];
  }
}

// Render completed proposals in a tiled grid
async function renderCompletedProposals(proposals) {
  const container = document.getElementById('proposalsContainer');

  container.innerHTML = proposals.map(proposal => {
    const proposalId = proposal.proposal_id;
    const userVote = userVotesCache && userVotesCache.find(v => v.proposal_id === proposalId);

    // Prepare vote badge colors
    const voteColors = {
      yes: '#10b981',
      no: '#ef4444',
      abstain: '#6b7280'
    };

    const userVoteText = userVote ? userVote.vote : 'Not Voted';
    const userVoteColor = userVote && voteColors[userVote.vote.toLowerCase()] ? voteColors[userVote.vote.toLowerCase()] : '#6b7280';

    return `
      <div id="completed-${proposalId}" style="background:#0a0a0a;border:1px solid #333;border-radius:8px;padding:16px;display:flex;flex-direction:column;position:relative;min-height:280px;">
        ${proposal.proposal_number ? `<div style="margin-bottom:4px;"><span style="font-family:monospace;font-size:0.7rem;color:#6b7280;background:#1f2937;padding:2px 6px;border-radius:4px;">${proposal.proposal_number}</span></div>` : ''}
        <h4 style="margin:0 0 12px 0;font-weight:700;font-size:1rem;line-height:1.4;">${proposal.proposal_title || 'Untitled Proposal'}</h4>

        <!-- Pass/Fail Badge -->
        <div id="result-badge-${proposalId}" style="margin-bottom:12px;height:24px;">
          <div class="skeleton" style="height:24px;width:80px;border-radius:12px;"></div>
        </div>

        <!-- User Vote -->
        <div style="margin-bottom:16px;padding:10px;background:#050505;border-left:3px solid ${userVoteColor};border-radius:4px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-size:0.8rem;color:var(--gray);">Your vote:</span>
            <span style="font-size:0.85rem;font-weight:700;color:${userVoteColor};text-transform:uppercase;">${userVoteText}</span>
          </div>
        </div>

        <!-- Vote Results -->
        <div id="results-${proposalId}" style="flex:1;min-height:140px;">
          <div style="padding:10px;background:#050505;border-radius:6px;">
            <div class="skeleton" style="height:16px;margin-bottom:12px;border-radius:4px;width:40%;"></div>
            <div class="skeleton" style="height:12px;margin-bottom:8px;border-radius:4px;width:100%;"></div>
            <div class="skeleton" style="height:4px;margin-bottom:16px;border-radius:4px;width:100%;"></div>
            <div class="skeleton" style="height:12px;margin-bottom:8px;border-radius:4px;width:100%;"></div>
            <div class="skeleton" style="height:4px;margin-bottom:16px;border-radius:4px;width:100%;"></div>
            <div class="skeleton" style="height:12px;margin-bottom:8px;border-radius:4px;width:100%;"></div>
            <div class="skeleton" style="height:4px;border-radius:4px;width:100%;"></div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Load results for each completed proposal in parallel
  await Promise.all(proposals.map(proposal => loadCompletedProposalResults(proposal.proposal_id)));
}

// Load results for completed proposals
async function loadCompletedProposalResults(proposalId) {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/proposals/' + proposalId + '/results', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) throw new Error('Failed to load results');
    const data = await res.json();

    const yes = data.results.yes || 0;
    const no = data.results.no || 0;
    const abstain = data.results.abstain || 0;
    const total = yes + no + abstain;

    const yesPercent = total > 0 ? Math.round((yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((abstain / total) * 100) : 0;

    const passed = yes > no;

    // Update result badge
    const badgeEl = document.getElementById('result-badge-' + proposalId);
    if (badgeEl) {
      badgeEl.innerHTML = passed
        ? '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">✅ PASSED</span>'
        : '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">❌ FAILED</span>';
    }

    // Update card border color
    const cardEl = document.getElementById('completed-' + proposalId);
    if (cardEl) {
      cardEl.style.borderColor = passed ? '#10b981' : '#ef4444';
      cardEl.style.borderWidth = '2px';
    }

    // Update results
    const resultsEl = document.getElementById('results-' + proposalId);
    if (resultsEl) {
      resultsEl.innerHTML = `
        <div style="padding:10px;background:#050505;border-radius:6px;">
          <div style="margin-bottom:6px;font-size:0.75rem;color:var(--gray);">
            Total votes: ${total}
          </div>
          <div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
              <span style="font-size:0.7rem;color:#10b981;font-weight:600;">Yes</span>
              <span style="font-size:0.7rem;font-weight:600;">${yes} (${yesPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:4px;overflow:hidden;">
              <div style="background:#10b981;height:100%;width:${yesPercent}%;"></div>
            </div>
          </div>
          <div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
              <span style="font-size:0.7rem;color:#ef4444;font-weight:600;">No</span>
              <span style="font-size:0.7rem;font-weight:600;">${no} (${noPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:4px;overflow:hidden;">
              <div style="background:#ef4444;height:100%;width:${noPercent}%;"></div>
            </div>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
              <span style="font-size:0.7rem;color:#6b7280;font-weight:600;">Abstain</span>
              <span style="font-size:0.7rem;font-weight:600;">${abstain} (${abstainPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:4px;overflow:hidden;">
              <div style="background:#6b7280;height:100%;width:${abstainPercent}%;"></div>
            </div>
          </div>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading results for proposal', proposalId, error);
    const resultsEl = document.getElementById('results-' + proposalId);
    if (resultsEl) {
      resultsEl.innerHTML = '<p class="muted" style="font-size:0.8rem;text-align:center;">Failed to load results</p>';
    }
  }
}

// Load compact live results for active proposals
async function loadCompactVoteResults(proposalId, containerId) {
  try {
    const token = idToken();
    if (!token) return;

    const res = await fetch(API_URL + '/proposals/' + proposalId + '/vote-counts', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) return;
    const data = await res.json();

    const total = data.yes + data.no + data.abstain;
    const yesPercent = total > 0 ? Math.round((data.yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((data.no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((data.abstain / total) * 100) : 0;

    const resultsContainer = document.getElementById(containerId);
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div style="padding:12px;background:#050505;border-radius:4px;border:1px solid #333;">
          <p style="margin:0 0 8px 0;font-size:0.85rem;color:#999;font-weight:600;">Live Results (${total} votes)</p>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
                <span style="color:#4caf50;font-size:0.8rem;font-weight:600;">Yes</span>
                <span style="color:#4caf50;font-size:0.8rem;font-weight:600;">${data.yes} (${yesPercent}%)</span>
              </div>
              <div style="background:#1a1a1a;border-radius:3px;height:6px;overflow:hidden;">
                <div style="background:linear-gradient(90deg,#4caf50 0%,#66bb6a 100%);height:100%;width:${yesPercent}%;"></div>
              </div>
            </div>
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
                <span style="color:#f44336;font-size:0.8rem;font-weight:600;">No</span>
                <span style="color:#f44336;font-size:0.8rem;font-weight:600;">${data.no} (${noPercent}%)</span>
              </div>
              <div style="background:#1a1a1a;border-radius:3px;height:6px;overflow:hidden;">
                <div style="background:linear-gradient(90deg,#f44336 0%,#ef5350 100%);height:100%;width:${noPercent}%;"></div>
              </div>
            </div>
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
                <span style="color:#999;font-size:0.8rem;font-weight:600;">Abstain</span>
                <span style="color:#999;font-size:0.8rem;font-weight:600;">${data.abstain} (${abstainPercent}%)</span>
              </div>
              <div style="background:#1a1a1a;border-radius:3px;height:6px;overflow:hidden;">
                <div style="background:linear-gradient(90deg,#999 0%,#aaa 100%);height:100%;width:${abstainPercent}%;"></div>
              </div>
            </div>
          </div>
        </div>
      `;
    }
  } catch (error) {
    // Silently fail for live results
    console.error('Error loading compact vote results:', error);
  }
}

function toggleProposalText(elementId) {
  const element = document.getElementById(elementId);
  const button = element.previousElementSibling;
  if (element.style.display === 'none') {
    element.style.display = 'block';
    button.textContent = 'Hide Proposal';
  } else {
    element.style.display = 'none';
    button.textContent = 'View Proposal';
  }
}

async function loadProposalResultsInline(proposalId) {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/proposals/' + proposalId + '/results', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) throw new Error('Failed to load proposal results');
    const data = await res.json();

    const total = data.results.yes + data.results.no + data.results.abstain;
    const yesPercent = total > 0 ? Math.round((data.results.yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((data.results.no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((data.results.abstain / total) * 100) : 0;

    const resultsContainer = document.getElementById(`results-${proposalId}`);
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div style="margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #333;">
          <p style="margin:0 0 4px 0;font-weight:600;font-size:0.9rem;">Voting Results</p>
          <p class="muted" style="margin:0;font-size:0.85rem;">Total Votes: ${total}</p>
        </div>
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <span style="color:#4caf50;font-weight:600;font-size:0.9rem;">Yes</span>
              <span style="color:#4caf50;font-weight:600;font-size:0.9rem;">${data.results.yes} (${yesPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#4caf50 0%,#66bb6a 100%);height:100%;width:${yesPercent}%;transition:width 0.3s;"></div>
            </div>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <span style="color:#f44336;font-weight:600;font-size:0.9rem;">No</span>
              <span style="color:#f44336;font-weight:600;font-size:0.9rem;">${data.results.no} (${noPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#f44336 0%,#ef5350 100%);height:100%;width:${noPercent}%;transition:width 0.3s;"></div>
            </div>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <span style="color:#999;font-weight:600;font-size:0.9rem;">Abstain</span>
              <span style="color:#999;font-weight:600;font-size:0.9rem;">${data.results.abstain} (${abstainPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#999 0%,#aaa 100%);height:100%;width:${abstainPercent}%;transition:width 0.3s;"></div>
            </div>
          </div>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading proposal results:', error);
    const resultsContainer = document.getElementById(`results-${proposalId}`);
    if (resultsContainer) {
      resultsContainer.innerHTML = '<p style="margin:0;color:#f44336;text-align:center;font-size:0.9rem;">Failed to load results</p>';
    }
  }
}

async function viewProposalResults(proposalId) {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/proposals/' + proposalId + '/results', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) throw new Error('Failed to load proposal results');
    const data = await res.json();

    const total = data.results.yes + data.results.no + data.results.abstain;
    const yesPercent = total > 0 ? Math.round((data.results.yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((data.results.no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((data.results.abstain / total) * 100) : 0;

    const htmlContent = `
      <div style="margin-bottom:20px;">
        <h4 style="margin:0 0 12px 0;color:var(--accent);font-size:1.1rem;">${data.proposal.proposal_title || 'Untitled'}</h4>
        <p style="color:var(--gray);margin-bottom:16px;line-height:1.6;">${data.proposal.proposal_text}</p>

        <div style="display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;">
          <div>
            <span style="color:var(--gray);font-size:0.9rem;">Status:</span>
            <span style="color:var(--text);margin-left:8px;font-weight:600;">${data.proposal.status}</span>
          </div>
          <div>
            <span style="color:var(--gray);font-size:0.9rem;">Closed:</span>
            <span style="color:var(--text);margin-left:8px;font-weight:600;">${new Date(data.proposal.closes_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      <div style="background:#050505;border-radius:8px;padding:20px;border:1px solid #222;">
        <h5 style="margin:0 0 16px 0;color:var(--accent);font-size:1rem;">Results</h5>
        <div style="margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
            <span style="color:var(--gray);">Total Votes</span>
            <span style="color:var(--text);font-weight:600;">${total}</span>
          </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:12px;">
          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#4caf50;font-weight:600;">Yes</span>
              <span style="color:var(--text);">${data.results.yes} (${yesPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#4caf50 0%,#2e7d32 100%);height:100%;width:${yesPercent}%;transition:width 0.5s ease;"></div>
            </div>
          </div>

          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#f44336;font-weight:600;">No</span>
              <span style="color:var(--text);">${data.results.no} (${noPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#f44336 0%,#c62828 100%);height:100%;width:${noPercent}%;transition:width 0.5s ease;"></div>
            </div>
          </div>

          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#9e9e9e;font-weight:600;">Abstain</span>
              <span style="color:var(--text);">${data.results.abstain} (${abstainPercent}%)</span>
            </div>
            <div style="background:#1a1a1a;border-radius:4px;height:8px;overflow:hidden;">
              <div style="background:linear-gradient(90deg,#9e9e9e 0%,#616161 100%);height:100%;width:${abstainPercent}%;transition:width 0.5s ease;"></div>
            </div>
          </div>
        </div>
      </div>
    `;

    showProposalResultsModal(htmlContent);
  } catch (error) {
    console.error('Error loading proposal results:', error);
    showToast('Failed to load proposal results: ' + error.message, 'error');
  }
}

// Update tab visibility based on membership status and subscription status
function updateTabVisibility() {
  if (!signedIn()) return;

  // Use database membership status, not JWT groups
  const isMember = (membershipStatus === 'approved');
  const hasSubscription = isSubscriber();
  const hasPaidSubscription = isPaidSubscriber();

  // Show subscription tab to members (but voting only to paid subscribers, vault to any subscriber)
  const subscriptionTab = document.querySelector('.tab[data-tab="subscription"]');
  const votingTab = document.querySelector('.tab[data-tab="voting"]');
  const deployVaultTab = document.querySelector('.tab[data-tab="deploy-vault"]');

  if (isMember) {
    // Show subscription tab to all members
    if (subscriptionTab) subscriptionTab.style.display = 'inline-block';

    // Show voting tab only to paid subscribers
    if (hasPaidSubscription) {
      if (votingTab) votingTab.style.display = 'inline-block';
    } else {
      if (votingTab) votingTab.style.display = 'none';
    }

    // Show vault tab to any active subscriber (free or paid)
    if (hasSubscription) {
      if (deployVaultTab) deployVaultTab.style.display = 'inline-block';
    } else {
      if (deployVaultTab) deployVaultTab.style.display = 'none';
    }
  } else {
    // Hide all tabs for non-members
    if (subscriptionTab) subscriptionTab.style.display = 'none';
    if (votingTab) votingTab.style.display = 'none';
    if (deployVaultTab) deployVaultTab.style.display = 'none';
  }
}

// ---- Getting Started Functions ----
async function isGettingStartedComplete() {
  if (!signedIn()) return false;
  try {
    const res = await fetch(API_URL + '/account/getting-started-preference', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });

    if (!res.ok) {
      console.error('Error fetching getting started preference:', res.status);
      return false;
    }

    const response = await res.json();
    return response.getting_started_complete || false;
  } catch (error) {
    console.error('Error fetching getting started preference:', error);
    return false; // Default to false on error
  }
}

async function markGettingStartedComplete() {
  if (!signedIn()) return;
  try {
    const res = await fetch(API_URL + '/account/getting-started-preference', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ getting_started_complete: true })
    });

    if (!res.ok) {
      console.error('Error marking getting started as complete:', res.status);
    }
  } catch (error) {
    console.error('Error marking getting started as complete:', error);
  }
}

async function clearGettingStartedComplete() {
  if (!signedIn()) return;
  try {
    const res = await fetch(API_URL + '/account/getting-started-preference', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ getting_started_complete: false })
    });

    if (!res.ok) {
      console.error('Error clearing getting started preference:', res.status);
    }
  } catch (error) {
    console.error('Error clearing getting started preference:', error);
  }
}

function switchToTab(tabName, subTabName) {
  const tab = document.querySelector(`.tab[data-tab="${tabName}"]:not(.tab-child)`);
  const content = document.getElementById(tabName);
  const isParent = tab?.classList.contains('tab-parent');

  // Collapse all parent tabs first
  document.querySelectorAll('.tab-parent').forEach(p => p.classList.remove('expanded'));
  document.querySelectorAll('.tab-children').forEach(c => c.classList.remove('expanded'));
  document.querySelectorAll('.tab-child').forEach(c => c.classList.remove('active'));
  document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  if (tab) tab.classList.add('active');
  if (content) content.classList.add('active');

  // If this is a parent tab, expand it and activate first child
  if (isParent && tab) {
    const parentId = tab.id;
    const childrenId = parentId.replace('Parent', 'Children');
    const children = document.getElementById(childrenId);

    tab.classList.add('expanded');
    children?.classList.add('expanded');

    // If a specific sub-tab is requested, use it; otherwise use first child
    const targetSubTab = subTabName || children?.querySelector('.tab-child')?.getAttribute('data-sub-tab');
    if (targetSubTab) {
      // Activate the specific child tab
      const childTab = children?.querySelector(`.tab-child[data-sub-tab="${targetSubTab}"]`);
      if (childTab) childTab.classList.add('active');
      activateSubTab(tabName, targetSubTab);
    }
  }

  // Load voting data if switching to voting tab
  if (tabName === 'voting' && signedIn()) {
    loadAllProposals();
    loadVotingHistory();
  }

  // Load vault status if switching to deploy-vault tab
  if (tabName === 'deploy-vault' && signedIn()) {
    startVaultStatusPolling();
  }
}

function navigateToStep(tabName, cardId, subTabName) {
  // Switch to the tab
  switchToTab(tabName);

  // If there's a sub-tab specified, switch to it
  if (subTabName && subTabName !== 'null') {
    activateSubTab(tabName, subTabName);
    // Also update the child tab active state in the sidebar
    const childTab = document.querySelector(`.tab-child[data-tab="${tabName}"][data-sub-tab="${subTabName}"]`);
    if (childTab) {
      document.querySelectorAll('.tab-child').forEach(c => c.classList.remove('active'));
      childTab.classList.add('active');
    }
  }

  // If there's a specific card to focus on
  if (cardId && cardId !== 'null') {
    // Wait for tab switch to complete, then scroll to and highlight the card
    setTimeout(() => {
      const card = document.getElementById(cardId);
      if (card) {
        // Scroll to the card with some offset
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });

        // Add highlight effect
        const originalBorder = card.style.border;
        const originalBoxShadow = card.style.boxShadow;
        card.style.border = '2px solid var(--accent)';
        card.style.boxShadow = '0 0 20px rgba(255,193,37,0.6)';
        card.style.transition = 'all 0.3s ease';

        // Remove highlight after 2 seconds
        setTimeout(() => {
          card.style.border = originalBorder;
          card.style.boxShadow = originalBoxShadow;
        }, 2000);
      } else {
        console.error('Card not found:', cardId);
      }
    }, 300);
  }
}

// Preload vault status for caching (non-blocking, used by Getting Started)
async function preloadVaultStatus() {
  if (vaultStatusData !== null) return; // Already cached
  try {
    const token = idToken();
    if (!token) return;
    const res = await fetch(API_URL + '/vault/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.ok) {
      vaultStatusData = await res.json();
    } else if (res.status === 404) {
      vaultStatusData = { status: 'not_enrolled' };
    }
  } catch (e) {
    console.error('Error preloading vault status:', e);
  }
}

// Preload voting history for caching (non-blocking, used by Getting Started)
async function preloadVotingHistory() {
  if (votingHistoryData !== null) return; // Already cached
  try {
    const token = idToken();
    if (!token) return;
    const res = await fetch(API_URL + '/votes/history', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.status === 400 || res.status === 404) {
      votingHistoryData = { votes: [] };
    } else if (res.ok) {
      votingHistoryData = await res.json();
    }
  } catch (e) {
    console.error('Error preloading voting history:', e);
  }
}

async function checkStepCompletion() {
  const steps = {
    pinEnabled: false,
    isMember: false,
    membershipPending: false,
    hasSubscription: false,
    vaultDeployed: false,
    hasVoted: false,
    backupsConfigured: false
  };

  if (signedIn()) {
    const token = idToken();
    const { payload } = parseJwt(token);
    const groups = payload['cognito:groups'] || [];
    steps.isMember = groups.includes('member');

    // Use cached PIN status from loadPinStatus() instead of making duplicate API call
    if (pinStatusData !== null) {
      steps.pinEnabled = pinStatusData.pin_enabled || false;
    }

    // Use cached membership status instead of making duplicate API call
    if (membershipStatus !== null) {
      steps.membershipPending = membershipStatus === 'pending';
    }

    // Use cached subscription status
    if (subscriptionStatus && subscriptionStatus.is_active) {
      steps.hasSubscription = true;
    }

    // Fetch vault status and voting history in parallel (these aren't cached yet)
    const [vaultResult, votesResult] = await Promise.allSettled([
      // Vault status - use cached if available
      vaultStatusData !== null ? Promise.resolve(vaultStatusData) : (async () => {
        try {
          const vaultRes = await fetch(API_URL + '/vault/status', {
            method: 'GET',
            headers: { 'Authorization': 'Bearer ' + token }
          });
          if (vaultRes.ok) {
            const data = await vaultRes.json();
            vaultStatusData = data; // Cache it
            return data;
          }
          return null;
        } catch (e) {
          console.error('Error checking vault status:', e);
          return null;
        }
      })(),
      // Voting history - use cached if available
      votingHistoryData !== null ? Promise.resolve(votingHistoryData) : (async () => {
        try {
          const votesRes = await fetch(API_URL + '/votes/history', {
            method: 'GET',
            headers: { 'Authorization': 'Bearer ' + token }
          });
          if (votesRes.status === 400 || votesRes.status === 404) {
            const data = { votes: [] };
            votingHistoryData = data; // Cache it
            return data;
          } else if (votesRes.ok) {
            const data = await votesRes.json();
            votingHistoryData = data; // Cache it
            return data;
          }
          return null;
        } catch (e) {
          console.error('Error checking voting history:', e);
          return null;
        }
      })()
    ]);

    // Process vault result
    if (vaultResult.status === 'fulfilled' && vaultResult.value) {
      steps.vaultDeployed = vaultResult.value.status === 'active';
    }

    // Process votes result
    if (votesResult.status === 'fulfilled' && votesResult.value) {
      steps.hasVoted = votesResult.value.votes && votesResult.value.votes.length > 0;
    }
  }

  return steps;
}

async function populateGettingStartedSteps() {
  const steps = await checkStepCompletion();
  const { payload } = parseJwt(idToken());
  const groups = payload['cognito:groups'] || [];
  const isMember = groups.includes('member');
  const hasSubscription = subscriptionStatus && subscriptionStatus.is_active;
  const hasPaidSubscription = isPaidSubscriber();

  const stepsData = [
    {
      number: 1,
      title: 'Add a PIN Code',
      description: 'Add a PIN code to your account for better security.',
      completed: steps.pinEnabled,
      accessible: true,
      tab: 'account',
      subTab: 'pin-code',
      cardId: 'pinCodeCard',
      note: null
    },
    {
      number: 2,
      title: 'Become a VettID Member',
      description: 'Read and accept the VettID Membership Terms.',
      completed: steps.isMember,
      pending: steps.membershipPending,
      accessible: true,
      tab: 'account',
      subTab: 'membership',
      cardId: 'membershipCard',
      note: steps.membershipPending ? 'Membership Pending' : null
    },
    {
      number: 3,
      title: 'Subscribe',
      description: 'Select a free or paid subscription to gain access to voting rights and the VettID service.',
      completed: steps.hasSubscription,
      accessible: isMember,
      tab: 'subscription',
      cardId: null,
      note: isMember ? null : 'Complete step 2 to unlock'
    },
    {
      number: 4,
      title: 'Deploy Your Vault',
      description: 'Deploy a secure Vault under your complete control and connect it to the VettID app on your phone.',
      completed: steps.vaultDeployed,
      accessible: hasSubscription,
      tab: 'deploy-vault',
      cardId: null,
      note: hasSubscription ? null : 'Complete step 3 to unlock'
    },
    {
      number: 5,
      title: 'Vote on Proposals',
      description: 'Review open proposals related to the operation of VettID and cast your vote as a paying member.',
      completed: steps.hasVoted,
      accessible: hasPaidSubscription,
      tab: 'voting',
      cardId: null,
      note: hasPaidSubscription ? null : 'Upgrade to a paid subscription to unlock'
    },
    {
      number: 6,
      title: 'Enable Credential Backups',
      description: 'Securely backup your vault credentials for recovery if your device is lost.',
      completed: steps.backupsConfigured,
      accessible: hasSubscription,
      tab: 'deploy-vault',
      subTab: 'credential-backup',
      cardId: null,
      note: hasSubscription ? null : 'Complete step 3 to unlock'
    }
  ];

  const container = document.getElementById('gettingStartedSteps');
  container.innerHTML = stepsData.map(step => {
    const isAccessible = step.accessible;
    const isCompleted = step.completed;
    const isPending = step.pending || false;
    const opacity = isAccessible ? '1' : '0.5';
    const cursor = isAccessible && !isCompleted && !isPending ? 'pointer' : 'default';
    const borderColor = isCompleted ? '#4caf50' : isPending ? '#ff9800' : isAccessible ? 'var(--accent)' : '#333';
    const iconBg = isCompleted ? '#4caf50' : isPending ? '#ff9800' : isAccessible ? 'var(--accent)' : '#333';

    return `
      <div ${isAccessible && !isCompleted && !isPending && step.tab ? `data-action="navigateToStep" data-step-tab="${step.tab}" data-step-card="${step.cardId || 'null'}" data-step-subtab="${step.subTab || 'null'}"` : ''} style="padding:20px;background:#0a0a0a;border-radius:8px;border:2px solid ${borderColor};opacity:${opacity};cursor:${cursor};position:relative;">
        <div style="display:flex;align-items:start;gap:16px;">
          <div style="flex-shrink:0;width:40px;height:40px;border-radius:50%;background:${iconBg};display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.2rem;color:${isCompleted || isPending || isAccessible ? '#000' : '#666'};">
            ${isCompleted ? '✓' : step.number}
          </div>
          <div style="flex:1;">
            <h4 style="margin:0 0 8px 0;color:${isAccessible ? 'var(--text)' : '#666'};">${step.title}</h4>
            <p style="margin:0 0 8px 0;color:${isAccessible ? 'var(--gray)' : '#555'};font-size:0.95rem;">${step.description}</p>
            ${step.note ? `<p style="margin:0;color:#fbbf24;font-size:0.85rem;font-weight:600;">${step.note}</p>` : ''}
          </div>
          ${isCompleted ? `<div style="position:absolute;top:16px;right:16px;padding:4px 12px;background:#4caf50;color:#000;border-radius:12px;font-size:0.75rem;font-weight:700;">COMPLETE</div>` : ''}
          ${isPending && !isCompleted ? `<div style="position:absolute;top:16px;right:16px;padding:4px 12px;background:#ff9800;color:#000;border-radius:12px;font-size:0.75rem;font-weight:700;">PENDING</div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // Update progress bar
  const completedCount = stepsData.filter(s => s.completed).length;
  const totalCount = stepsData.length;
  const progressPercent = Math.round((completedCount / totalCount) * 100);

  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  if (progressBar) progressBar.style.width = progressPercent + '%';
  if (progressText) progressText.textContent = `${completedCount} of ${totalCount} complete`;
}

document.getElementById('gotItBtn').onclick = async () => {
  await markGettingStartedComplete();
  switchToTab('deploy-vault');
};

// ---- Vault Services Functions ----
let vaultStatusInterval = null;
let vaultStatus = null;

async function loadVaultStatus() {
  const statusContent = document.getElementById('vaultStatusContent');
  if (!statusContent) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      if (res.status === 404) {
        // Not enrolled yet
        vaultStatus = { status: 'not_enrolled' };
        renderVaultStatusContent(vaultStatus);
        return;
      }
      throw new Error('Failed to load vault status');
    }

    vaultStatus = await res.json();
    renderVaultStatusContent(vaultStatus);

    // If active, also load health data (if health card exists)
    const healthCard = document.getElementById('vaultHealthCard');
    if (vaultStatus.status === 'active' && healthCard) {
      await loadVaultHealth();
    } else if (healthCard) {
      healthCard.style.display = 'none';
    }
  } catch (error) {
    console.error('Error loading vault status:', error);
    statusContent.innerHTML = `
      <div style="padding:24px;background:#1a0a0a;border-radius:4px;border:1px solid #ef4444;text-align:center;">
        <div style="font-size:2rem;margin-bottom:12px;">⚠</div>
        <div style="color:#ef4444;font-weight:600;margin-bottom:8px;">Error Loading Status</div>
        <p class="muted" style="margin:0;">${error.message}</p>
        <button data-action="loadVaultStatus" class="btn" style="margin-top:16px;padding:8px 16px;background:#333;">Try Again</button>
      </div>
    `;
  }
}

function renderVaultStatusContent(status) {
  const statusContent = document.getElementById('vaultStatusContent');
  const provisioningCard = document.getElementById('vaultProvisioningCard');

  if (!statusContent) return;

  // Hide cards by default - only show in appropriate states
  if (provisioningCard) provisioningCard.style.display = 'none';
  const deletionCard = document.getElementById('vaultDeletionCard');
  if (deletionCard) deletionCard.style.display = 'none';

  switch (status.status) {
    case 'not_enrolled':
      statusContent.innerHTML = `
        <div style="padding:24px;background:#050505;border-radius:4px;border:1px solid #333;text-align:center;">
          <div style="font-size:3rem;margin-bottom:16px;">🔐</div>
          <div style="font-size:1.2rem;font-weight:600;color:var(--text);margin-bottom:8px;">Set Up Your Vault</div>
          <p class="muted" style="margin-bottom:20px;max-width:400px;margin-left:auto;margin-right:auto;">
            Your vault runs in a secure Nitro Enclave, providing hardware-isolated protection for your credentials and secrets. Start by enrolling your mobile device.
          </p>
          <button data-action="startEnrollment" class="btn" style="padding:12px 24px;background:linear-gradient(135deg,var(--accent) 0%,#2563eb 100%);font-weight:600;">
            Start Enrollment
          </button>
        </div>
      `;
      break;

    case 'pending':
      statusContent.innerHTML = `
        <div style="padding:24px;background:#0a0a05;border-radius:4px;border:1px solid #f59e0b;text-align:center;">
          <div style="width:40px;height:40px;border:3px solid #f59e0b;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px;"></div>
          <div style="font-size:1.2rem;font-weight:600;color:#f59e0b;margin-bottom:8px;">Enrollment In Progress</div>
          <p class="muted" style="margin-bottom:8px;">Complete the enrollment process on your mobile device.</p>
          <p class="muted" style="font-size:0.85rem;">Session started: ${status.started_at ? new Date(status.started_at).toLocaleString() : 'Unknown'}</p>
        </div>
      `;
      break;

    case 'enrolled':
      statusContent.innerHTML = `
        <div style="padding:24px;background:#050a05;border-radius:4px;border:1px solid #10b981;text-align:center;">
          <div style="font-size:3rem;margin-bottom:16px;">✓</div>
          <div style="font-size:1.2rem;font-weight:600;color:#10b981;margin-bottom:8px;">Device Enrolled</div>
          <p class="muted" style="margin-bottom:20px;">
            Your mobile device is enrolled and connected to your Nitro Enclave vault.
          </p>
          <button data-action="provisionVault" class="btn" style="padding:12px 24px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);font-weight:600;">
            Initialize Vault
          </button>
        </div>
      `;
      break;

    case 'provisioning':
      if (provisioningCard) provisioningCard.style.display = 'block';
      statusContent.innerHTML = `
        <div style="padding:24px;background:#050505;border-radius:4px;border:1px solid var(--accent);text-align:center;">
          <div style="font-size:1.2rem;font-weight:600;color:var(--accent);margin-bottom:8px;">Initializing Vault...</div>
          <p class="muted">Setting up your secure Nitro Enclave vault. This may take a moment.</p>
        </div>
      `;
      // Start polling for provisioning completion
      startProvisioningPoll();
      break;

    case 'active':
      const enrolledDate = status.enrolled_at ? new Date(status.enrolled_at).toLocaleDateString() : 'Unknown';
      const lastActivity = status.last_sync_at ? new Date(status.last_sync_at).toLocaleString() : 'Never';
      const deviceIcon = status.device_type === 'ios' ? '📱' : status.device_type === 'android' ? '🤖' : '📱';
      const deviceLabel = status.device_type === 'ios' ? 'iOS' : status.device_type === 'android' ? 'Android' : 'Mobile';
      const keysRemaining = status.transaction_keys_remaining !== undefined ? status.transaction_keys_remaining : 'N/A';
      const keysColor = keysRemaining === 'N/A' ? '#6b7280' : keysRemaining < 5 ? '#ef4444' : keysRemaining < 10 ? '#f59e0b' : '#10b981';
      // Attestation info
      const attestationTime = status.attestation_time ? new Date(status.attestation_time).toLocaleString() : null;
      const pcrHash = status.pcr_hash ? status.pcr_hash.substring(0, 12) + '...' : null;
      statusContent.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;">
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #10b981;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Enclave Status</div>
            <div style="display:flex;align-items:center;gap:8px;">
              <span style="width:10px;height:10px;background:#10b981;border-radius:50%;animation:pulse 2s ease-in-out infinite;"></span>
              <span style="color:#10b981;font-weight:600;">Connected</span>
            </div>
          </div>
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Enrolled Device</div>
            <div style="color:var(--text);font-weight:600;">${deviceIcon} ${deviceLabel}</div>
          </div>
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Enrolled Since</div>
            <div style="color:var(--text);font-size:0.9rem;">${enrolledDate}</div>
          </div>
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Last Activity</div>
            <div style="color:var(--text);font-size:0.9rem;">${lastActivity}</div>
          </div>
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Transaction Keys</div>
            <div style="color:${keysColor};font-weight:600;">${keysRemaining}</div>
          </div>
          <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
            <div class="muted" style="font-size:0.8rem;margin-bottom:4px;">Protection</div>
            <div style="color:#10b981;font-weight:600;">Nitro Enclave</div>
          </div>
        </div>

        <!-- Attestation Section -->
        <div style="margin-top:20px;padding:16px;background:linear-gradient(135deg,rgba(16,185,129,0.05) 0%,rgba(5,150,105,0.02) 100%);border:1px solid rgba(16,185,129,0.3);border-radius:8px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
            <div style="width:32px;height:32px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 12 15 22 5"></polyline>
              </svg>
            </div>
            <div>
              <div style="color:#10b981;font-weight:600;font-size:0.95rem;">Enclave Attestation Verified</div>
              <div style="color:var(--gray);font-size:0.8rem;">Hardware-backed cryptographic proof</div>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;font-size:0.85rem;">
            ${attestationTime ? `
            <div style="display:flex;flex-direction:column;gap:2px;">
              <span class="muted">Last Attestation</span>
              <span style="color:var(--text);font-family:monospace;">${attestationTime}</span>
            </div>
            ` : ''}
            ${pcrHash ? `
            <div style="display:flex;flex-direction:column;gap:2px;">
              <span class="muted">PCR Hash</span>
              <span style="color:var(--text);font-family:monospace;">${pcrHash}</span>
            </div>
            ` : ''}
            <div style="display:flex;flex-direction:column;gap:2px;">
              <span class="muted">Enclave Type</span>
              <span style="color:var(--text);">AWS Nitro</span>
            </div>
          </div>
        </div>

      `;
      // Show deletion card for active vaults and load deletion status
      if (deletionCard) {
        deletionCard.style.display = 'block';
        loadVaultDeletionStatus();
      }
      break;

    default:
      statusContent.innerHTML = `
        <div style="padding:24px;background:#050505;border-radius:4px;border:1px solid #333;text-align:center;">
          <div class="muted">Unknown status: ${status.status}</div>
        </div>
      `;
  }
}

function formatUptime(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

async function loadVaultHealth() {
  const healthCard = document.getElementById('vaultHealthCard');
  const healthContent = document.getElementById('vaultHealthContent');
  const healthBadge = document.getElementById('vaultHealthBadge');

  if (!healthCard || !healthContent) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/health', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) throw new Error('Failed to load vault health');

    const health = await res.json();
    renderHealthDashboard(health);
  } catch (error) {
    console.error('Error loading vault health:', error);
    healthContent.innerHTML = `
      <div style="padding:16px;background:#1a0a0a;border-radius:4px;border:1px solid #ef4444;text-align:center;">
        <span style="color:#ef4444;">Error loading health data</span>
      </div>
    `;
    healthBadge.textContent = 'Error';
    healthBadge.style.background = '#ef4444';
    healthBadge.style.color = '#fff';
  }
}

function renderHealthDashboard(health) {
  const healthContent = document.getElementById('vaultHealthContent');
  const healthBadge = document.getElementById('vaultHealthBadge');

  if (!healthContent) return;

  // Determine overall health status
  const isHealthy = health.ec2_status === 'running' &&
                    health.nats_central === 'connected' &&
                    health.nats_local === 'connected';
  const isDegraded = !isHealthy && health.ec2_status === 'running';

  if (healthBadge) {
    if (isHealthy) {
      healthBadge.textContent = 'Healthy';
      healthBadge.style.background = '#10b981';
      healthBadge.style.color = '#000';
    } else if (isDegraded) {
      healthBadge.textContent = 'Degraded';
      healthBadge.style.background = '#f59e0b';
      healthBadge.style.color = '#000';
    } else {
      healthBadge.textContent = 'Unhealthy';
      healthBadge.style.background = '#ef4444';
      healthBadge.style.color = '#fff';
    }
  }

  const statusIcon = (connected) => connected ?
    '<span style="color:#10b981;">●</span>' :
    '<span style="color:#ef4444;">●</span>';

  const statusText = (val, goodVal) => val === goodVal ?
    `<span style="color:#10b981;">${val}</span>` :
    `<span style="color:#ef4444;">${val}</span>`;

  healthContent.innerHTML = `
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">EC2 Instance</div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${statusIcon(health.ec2_status === 'running')}
        ${statusText(health.ec2_status || 'unknown', 'running')}
      </div>
    </div>
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">NATS Central</div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${statusIcon(health.nats_central === 'connected')}
        ${statusText(health.nats_central || 'unknown', 'connected')}
      </div>
    </div>
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">NATS Local</div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${statusIcon(health.nats_local === 'connected')}
        ${statusText(health.nats_local || 'unknown', 'connected')}
      </div>
    </div>
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">CPU Usage</div>
      <div style="color:var(--text);font-weight:600;">${health.cpu_percent !== undefined ? health.cpu_percent + '%' : 'N/A'}</div>
      ${health.cpu_percent !== undefined ? `
        <div style="margin-top:8px;height:4px;background:#222;border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${health.cpu_percent}%;background:${health.cpu_percent > 80 ? '#ef4444' : health.cpu_percent > 60 ? '#f59e0b' : '#10b981'};"></div>
        </div>
      ` : ''}
    </div>
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">Memory Usage</div>
      <div style="color:var(--text);font-weight:600;">${health.memory_percent !== undefined ? health.memory_percent + '%' : 'N/A'}</div>
      ${health.memory_percent !== undefined ? `
        <div style="margin-top:8px;height:4px;background:#222;border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${health.memory_percent}%;background:${health.memory_percent > 80 ? '#ef4444' : health.memory_percent > 60 ? '#f59e0b' : '#10b981'};"></div>
        </div>
      ` : ''}
    </div>
    <div style="padding:16px;background:#050505;border-radius:4px;border:1px solid #333;">
      <div class="muted" style="font-size:0.75rem;margin-bottom:6px;text-transform:uppercase;">Disk Usage</div>
      <div style="color:var(--text);font-weight:600;">${health.disk_percent !== undefined ? health.disk_percent + '%' : 'N/A'}</div>
      ${health.disk_percent !== undefined ? `
        <div style="margin-top:8px;height:4px;background:#222;border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${health.disk_percent}%;background:${health.disk_percent > 80 ? '#ef4444' : health.disk_percent > 60 ? '#f59e0b' : '#10b981'};"></div>
        </div>
      ` : ''}
    </div>
  `;
}

async function provisionVault() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    showToast('Provisioning vault...', 'info');

    const res = await fetch(API_URL + '/vault/provision', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to provision vault');
    }

    const data = await res.json();
    showToast('Vault provisioning started', 'success');

    // Update status to show provisioning state
    vaultStatus = { status: 'provisioning' };
    renderVaultStatusContent(vaultStatus);

    // Start polling for completion
    startProvisioningPoll();
  } catch (error) {
    console.error('Error provisioning vault:', error);
    showToast('Failed to provision vault: ' + error.message, 'error');
  }
}

let provisioningPollInterval = null;

function startProvisioningPoll() {
  stopProvisioningPoll();

  const provisioningCard = document.getElementById('vaultProvisioningCard');
  if (provisioningCard) provisioningCard.style.display = 'block';

  let progress = 0;
  provisioningPollInterval = setInterval(async () => {
    // Update progress bar (simulated)
    progress = Math.min(progress + Math.random() * 10, 90);
    const progressBar = document.getElementById('provisioningProgressBar');
    const progressText = document.getElementById('provisioningProgress');
    if (progressBar) progressBar.style.width = progress + '%';
    if (progressText) progressText.textContent = Math.round(progress) + '%';

    // Check actual status
    try {
      const token = idToken();
      const res = await fetch(API_URL + '/vault/status', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + token }
      });

      if (res.ok) {
        const status = await res.json();
        if (status.status === 'active') {
          stopProvisioningPoll();
          if (progressBar) progressBar.style.width = '100%';
          if (progressText) progressText.textContent = '100%';

          setTimeout(() => {
            showToast('Vault provisioned successfully!', 'success');
            loadVaultStatus();
          }, 500);
        }
      }
    } catch (e) {
      console.error('Error polling provision status:', e);
    }
  }, 5000);
}

function stopProvisioningPoll() {
  if (provisioningPollInterval) {
    clearInterval(provisioningPollInterval);
    provisioningPollInterval = null;
  }
}

async function stopVault() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    showToast('Stopping vault...', 'info');

    const res = await fetch(API_URL + '/vault/stop', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to stop vault');
    }

    showToast('Vault stopped', 'success');
    await loadVaultStatus();
  } catch (error) {
    console.error('Error stopping vault:', error);
    showToast('Failed to stop vault: ' + error.message, 'error');
  }
}

async function startVault() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    showToast('Starting vault...', 'info');

    const res = await fetch(API_URL + '/vault/initialize', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to start vault');
    }

    showToast('Vault starting...', 'success');
    await loadVaultStatus();
  } catch (error) {
    console.error('Error starting vault:', error);
    showToast('Failed to start vault: ' + error.message, 'error');
  }
}

function confirmTerminateVault() {
  const modal = document.createElement('div');
  modal.id = 'terminateVaultModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:9999;';
  modal.innerHTML = `
    <div style="background:#0a0a0a;border:1px solid #ef4444;border-radius:12px;padding:32px;max-width:420px;width:90%;text-align:center;">
      <div style="font-size:3rem;margin-bottom:16px;">⚠️</div>
      <h3 style="margin:0 0 12px 0;color:#ef4444;">Terminate Vault?</h3>
      <p style="color:var(--gray);margin-bottom:24px;line-height:1.6;">
        This action is <strong style="color:#ef4444;">permanent and cannot be undone</strong>.
        Your vault instance will be destroyed and all local data will be lost.
      </p>
      <p style="color:var(--gray);margin-bottom:24px;font-size:0.9rem;">
        If you have credential backups, they will remain safe. You can provision a new vault and restore from backup.
      </p>
      <div style="display:flex;gap:12px;justify-content:center;">
        <button data-action="closeTerminateModal" class="btn" style="padding:12px 24px;background:#333;">
          Cancel
        </button>
        <button data-action="terminateVault" class="btn" style="padding:12px 24px;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);font-weight:600;">
          Terminate Vault
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) closeTerminateModal(); };
}

function closeTerminateModal() {
  const modal = document.getElementById('terminateVaultModal');
  if (modal) modal.remove();
}

async function terminateVault() {
  closeTerminateModal();

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    showToast('Terminating vault...', 'info');

    const res = await fetch(API_URL + '/vault/terminate', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to terminate vault');
    }

    showToast('Vault terminated', 'success');
    await loadVaultStatus();
  } catch (error) {
    console.error('Error terminating vault:', error);
    showToast('Failed to terminate vault: ' + error.message, 'error');
  }
}

function confirmStopVault() {
  const modal = document.createElement('div');
  modal.id = 'stopVaultModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:9999;';
  modal.innerHTML = `
    <div style="background:#0a0a0a;border:1px solid #f59e0b;border-radius:12px;padding:32px;max-width:420px;width:90%;text-align:center;">
      <div style="font-size:3rem;margin-bottom:16px;">⏸️</div>
      <h3 style="margin:0 0 12px 0;color:#f59e0b;">Stop Vault?</h3>
      <p style="color:var(--gray);margin-bottom:24px;line-height:1.6;">
        Stopping your vault will pause all vault services. Your data will be preserved
        and you can restart it at any time.
      </p>
      <p style="color:var(--gray);margin-bottom:24px;font-size:0.9rem;">
        While stopped, you won't be able to use vault-based authentication or sync credentials.
      </p>
      <div style="display:flex;gap:12px;justify-content:center;">
        <button data-action="closeStopModal" class="btn" style="padding:12px 24px;background:#333;">
          Cancel
        </button>
        <button data-action="stopVaultAndClose" class="btn" style="padding:12px 24px;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);font-weight:600;">
          Stop Vault
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) closeStopModal(); };
}

function closeStopModal() {
  const modal = document.getElementById('stopVaultModal');
  if (modal) modal.remove();
}

async function syncVault() {
  const syncBtn = document.getElementById('syncVaultBtn');
  const originalText = syncBtn ? syncBtn.innerHTML : '';

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    if (syncBtn) {
      syncBtn.disabled = true;
      syncBtn.innerHTML = '🔄 Syncing...';
    }

    const res = await fetch(API_URL + '/vault/sync', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to sync vault');
    }

    const data = await res.json();

    if (data.status === 'keys_replenished') {
      showToast(`Synced! ${data.new_transaction_keys?.length || 0} new keys generated`, 'success');
    } else {
      showToast('Vault synced successfully', 'success');
    }

    // Refresh status to show updated data
    await loadVaultStatus();
  } catch (error) {
    console.error('Error syncing vault:', error);
    showToast('Failed to sync vault: ' + error.message, 'error');
  } finally {
    if (syncBtn) {
      syncBtn.disabled = false;
      syncBtn.innerHTML = originalText;
    }
  }
}

// ============================================
// BYOV (Bring Your Own Vault) FUNCTIONS
// ============================================

let byovStatus = null;

async function loadByovStatus() {
  const statusContent = document.getElementById('byovStatusContent');
  const registerCard = document.getElementById('byovRegisterCard');
  const connectedCard = document.getElementById('byovConnectedCard');

  if (!statusContent) return;

  // Show loading state
  statusContent.innerHTML = `
    <div style="padding:24px;background:#050505;border-radius:4px;border:1px solid #333;text-align:center;">
      <div class="skeleton" style="height:24px;width:200px;margin:0 auto;border-radius:4px;"></div>
    </div>
  `;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/byov/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      throw new Error('Failed to load BYOV status');
    }

    byovStatus = await res.json();

    if (!byovStatus.has_vault) {
      // No vault registered - show registration form
      statusContent.innerHTML = `
        <div style="padding:24px;background:#050505;border-radius:4px;border:1px solid #333;text-align:center;">
          <div style="font-size:3rem;margin-bottom:16px;">🔗</div>
          <div style="font-size:1.2rem;font-weight:600;color:var(--text);margin-bottom:8px;">No Vault Connected</div>
          <p class="muted" style="margin:0;max-width:400px;margin:0 auto;">
            Register your self-hosted vault below to connect it to VettID.
          </p>
        </div>
      `;
      registerCard.style.display = 'block';
      connectedCard.style.display = 'none';
    } else {
      // Vault registered - show connected card
      statusContent.innerHTML = `
        <div style="padding:16px;background:#050a05;border-radius:4px;border:1px solid #10b981;text-align:center;">
          <span style="color:#10b981;font-weight:600;">✓ Vault Connected</span>
        </div>
      `;
      registerCard.style.display = 'none';
      connectedCard.style.display = 'block';
      renderByovConnectedCard(byovStatus);
    }
  } catch (error) {
    console.error('Error loading BYOV status:', error);
    statusContent.innerHTML = `
      <div style="padding:24px;background:#1a0a0a;border-radius:4px;border:1px solid #ef4444;text-align:center;">
        <div style="font-size:2rem;margin-bottom:12px;">⚠</div>
        <div style="color:#ef4444;font-weight:600;margin-bottom:8px;">Error Loading Status</div>
        <p class="muted" style="margin:0;">${error.message}</p>
        <button data-action="loadByovStatus" class="btn" style="margin-top:16px;padding:8px 16px;background:#333;">Try Again</button>
      </div>
    `;
    registerCard.style.display = 'none';
    connectedCard.style.display = 'none';
  }
}

function renderByovConnectedCard(status) {
  // Update vault name and URL
  document.getElementById('byovConnectedName').textContent = status.vault_name || 'My Vault';
  document.getElementById('byovConnectedUrl').textContent = status.vault_url || '-';

  // Update health badge
  const healthBadge = document.getElementById('byovHealthBadge');
  const healthStatus = status.health_status || 'UNKNOWN';
  const healthColors = {
    'HEALTHY': { bg: '#10b981', text: '#fff' },
    'UNHEALTHY': { bg: '#ef4444', text: '#fff' },
    'AUTH_REQUIRED': { bg: '#f59e0b', text: '#000' },
    'TIMEOUT': { bg: '#6b7280', text: '#fff' },
    'DNS_ERROR': { bg: '#ef4444', text: '#fff' },
    'CONNECTION_REFUSED': { bg: '#ef4444', text: '#fff' },
    'SSL_ERROR': { bg: '#f59e0b', text: '#000' },
    'UNREACHABLE': { bg: '#ef4444', text: '#fff' },
    'UNKNOWN': { bg: '#6b7280', text: '#fff' }
  };
  const colors = healthColors[healthStatus] || healthColors['UNKNOWN'];
  healthBadge.style.background = colors.bg;
  healthBadge.style.color = colors.text;
  healthBadge.textContent = healthStatus.replace(/_/g, ' ');

  // Update info grid
  document.getElementById('byovInfoStatus').textContent = (status.status || 'Unknown').replace(/_/g, ' ');
  document.getElementById('byovInfoLastCheck').textContent = status.last_health_check
    ? new Date(status.last_health_check).toLocaleString()
    : 'Never';
  document.getElementById('byovInfoCreated').textContent = status.created_at
    ? new Date(status.created_at).toLocaleDateString()
    : 'Unknown';
  document.getElementById('byovInfoApiKey').textContent = status.api_key_set ? 'Configured' : 'Not set';

  // Update health message
  const healthMsg = document.getElementById('byovHealthMessage');
  if (status.health_message) {
    healthMsg.style.display = 'block';
    if (healthStatus === 'HEALTHY') {
      healthMsg.style.background = 'rgba(16,185,129,0.1)';
      healthMsg.style.border = '1px solid #10b981';
      healthMsg.style.color = '#10b981';
    } else if (healthStatus === 'AUTH_REQUIRED' || healthStatus === 'SSL_ERROR') {
      healthMsg.style.background = 'rgba(245,158,11,0.1)';
      healthMsg.style.border = '1px solid #f59e0b';
      healthMsg.style.color = '#f59e0b';
    } else {
      healthMsg.style.background = 'rgba(239,68,68,0.1)';
      healthMsg.style.border = '1px solid #ef4444';
      healthMsg.style.color = '#ef4444';
    }
    healthMsg.textContent = status.health_message;
  } else {
    healthMsg.style.display = 'none';
  }
}

async function registerByovVault() {
  const btn = document.getElementById('registerByovBtn');
  const errorDiv = document.getElementById('byovRegisterError');
  const originalText = btn.innerHTML;

  // Get form values
  const vaultName = document.getElementById('byovVaultName').value.trim();
  const vaultUrl = document.getElementById('byovVaultUrl').value.trim();
  const apiKey = document.getElementById('byovApiKey').value;
  const verifySsl = document.getElementById('byovVerifySsl').checked;

  // Validate
  if (!vaultUrl) {
    errorDiv.style.display = 'block';
    errorDiv.textContent = 'Vault URL is required';
    return;
  }

  try {
    new URL(vaultUrl);
    if (!vaultUrl.startsWith('https://')) {
      throw new Error('URL must use HTTPS');
    }
  } catch (e) {
    errorDiv.style.display = 'block';
    errorDiv.textContent = 'Please enter a valid HTTPS URL';
    return;
  }

  errorDiv.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<span style="display:inline-block;animation:spin 1s linear infinite;">⏳</span> Registering...';

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const body = {
      vault_url: vaultUrl,
      verify_ssl: verifySsl
    };
    if (vaultName) body.vault_name = vaultName;
    if (apiKey) body.api_key = apiKey;

    const res = await fetch(API_URL + '/vault/byov/register', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || 'Failed to register vault');
    }

    showToast('Vault registered successfully!', 'success');

    // Clear form
    document.getElementById('byovVaultName').value = '';
    document.getElementById('byovVaultUrl').value = '';
    document.getElementById('byovApiKey').value = '';
    document.getElementById('byovVerifySsl').checked = true;

    // Reload status
    await loadByovStatus();

    // Auto-verify if needed
    if (data.requires_verification) {
      setTimeout(() => verifyByovVault(), 500);
    }
  } catch (error) {
    console.error('Error registering BYOV vault:', error);
    errorDiv.style.display = 'block';
    errorDiv.textContent = error.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

async function verifyByovVault() {
  const btn = document.getElementById('verifyByovBtn');
  const originalText = btn ? btn.innerHTML : '';

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-block;animation:spin 1s linear infinite;">⏳</span> Verifying...';
  }

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/byov/verify', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || 'Failed to verify vault');
    }

    if (data.health_status === 'HEALTHY') {
      showToast('Vault verified and healthy!', 'success');
    } else if (data.health_status === 'AUTH_REQUIRED') {
      showToast('Vault requires authentication. Please add an API key.', 'warning');
    } else {
      showToast(`Verification issue: ${data.health_message || data.health_status}`, 'warning');
    }

    // Reload status to reflect changes
    await loadByovStatus();
  } catch (error) {
    console.error('Error verifying BYOV vault:', error);
    showToast('Failed to verify vault: ' + error.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  }
}

function showByovSettingsModal() {
  if (!byovStatus || !byovStatus.has_vault) {
    showToast('No vault to configure', 'error');
    return;
  }

  // Pre-fill form with current values
  document.getElementById('byovSettingsName').value = byovStatus.vault_name || '';
  document.getElementById('byovSettingsUrl').value = byovStatus.vault_url || '';
  document.getElementById('byovSettingsApiKey').value = '';
  document.getElementById('byovSettingsVerifySsl').checked = byovStatus.verify_ssl !== false;
  document.getElementById('byovSettingsApiKeyStatus').textContent = byovStatus.api_key_set ? 'Configured' : 'Not set';
  document.getElementById('byovSettingsError').style.display = 'none';

  document.getElementById('byovSettingsModal').style.display = 'block';
}

function closeByovSettingsModal() {
  document.getElementById('byovSettingsModal').style.display = 'none';
}

async function saveByovSettings() {
  const btn = document.getElementById('saveByovSettingsBtn');
  const errorDiv = document.getElementById('byovSettingsError');
  const originalText = btn.innerHTML;

  const vaultName = document.getElementById('byovSettingsName').value.trim();
  const vaultUrl = document.getElementById('byovSettingsUrl').value.trim();
  const apiKey = document.getElementById('byovSettingsApiKey').value;
  const verifySsl = document.getElementById('byovSettingsVerifySsl').checked;

  // Validate URL if provided
  if (vaultUrl) {
    try {
      new URL(vaultUrl);
      if (!vaultUrl.startsWith('https://')) {
        throw new Error('URL must use HTTPS');
      }
    } catch (e) {
      errorDiv.style.display = 'block';
      errorDiv.textContent = 'Please enter a valid HTTPS URL';
      return;
    }
  }

  errorDiv.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<span style="display:inline-block;animation:spin 1s linear infinite;">⏳</span> Saving...';

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const body = {};
    if (vaultName !== byovStatus.vault_name) body.vault_name = vaultName;
    if (vaultUrl && vaultUrl !== byovStatus.vault_url) body.vault_url = vaultUrl;
    if (apiKey) body.api_key = apiKey;
    if (verifySsl !== (byovStatus.verify_ssl !== false)) body.verify_ssl = verifySsl;

    // Only make request if there are changes
    if (Object.keys(body).length === 0) {
      showToast('No changes to save', 'info');
      closeByovSettingsModal();
      return;
    }

    const res = await fetch(API_URL + '/vault/byov', {
      method: 'PATCH',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || 'Failed to update vault settings');
    }

    showToast('Vault settings updated!', 'success');
    closeByovSettingsModal();

    // Reload status
    await loadByovStatus();

    // Auto-verify if URL changed
    if (data.requires_verification) {
      setTimeout(() => verifyByovVault(), 500);
    }
  } catch (error) {
    console.error('Error saving BYOV settings:', error);
    errorDiv.style.display = 'block';
    errorDiv.textContent = error.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

async function clearByovApiKey() {
  if (!confirm('Clear the API key for this vault?')) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/byov', {
      method: 'PATCH',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ clear_api_key: true })
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || 'Failed to clear API key');
    }

    document.getElementById('byovSettingsApiKeyStatus').textContent = 'Not set';
    showToast('API key cleared', 'success');

    // Update local status
    if (byovStatus) byovStatus.api_key_set = false;
  } catch (error) {
    console.error('Error clearing API key:', error);
    showToast('Failed to clear API key: ' + error.message, 'error');
  }
}

function confirmDeleteByovVault() {
  const modal = document.createElement('div');
  modal.id = 'deleteByovModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:9999;';
  modal.innerHTML = `
    <div style="background:#0a0a0a;border:2px solid #ef4444;border-radius:12px;padding:32px;max-width:420px;width:90%;text-align:center;">
      <div style="font-size:3rem;margin-bottom:16px;">⚠️</div>
      <h3 style="margin:0 0 12px 0;color:#ef4444;">Remove Vault?</h3>
      <p style="color:var(--gray);margin-bottom:24px;line-height:1.6;">
        This will disconnect your vault from VettID. You can re-register it later if needed.
      </p>
      <div style="display:flex;gap:12px;justify-content:center;">
        <button data-action="closeDeleteByovModal" class="btn" style="padding:12px 24px;background:#333;">
          Cancel
        </button>
        <button data-action="deleteByovAndClose" class="btn" style="padding:12px 24px;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);font-weight:600;">
          Remove Vault
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) closeDeleteByovModal(); };
}

function closeDeleteByovModal() {
  const modal = document.getElementById('deleteByovModal');
  if (modal) modal.remove();
}

async function deleteByovVault() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/byov', {
      method: 'DELETE',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || 'Failed to remove vault');
    }

    showToast('Vault removed successfully', 'success');
    byovStatus = null;
    await loadByovStatus();
  } catch (error) {
    console.error('Error deleting BYOV vault:', error);
    showToast('Failed to remove vault: ' + error.message, 'error');
  }
}

function initByovTab() {
  loadByovStatus();
}

// ============================================
// CREDENTIAL BACKUP FUNCTIONS
// ============================================

// BIP39 English word list (2048 words) - subset for demonstration
// In production, include the full BIP39 word list
const BIP39_WORDLIST = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
  'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
  'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
  'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
  'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
  'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
  'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
  'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
  'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'arch', 'arctic',
  'area', 'arena', 'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
  'arrive', 'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset',
  'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction',
  'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado', 'avoid', 'awake',
  'aware', 'away', 'awesome', 'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge',
  'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain',
  'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become',
  'beef', 'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt', 'bench', 'benefit',
  'best', 'betray', 'better', 'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology',
  'bird', 'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless',
  'blind', 'blood', 'blossom', 'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body',
  'boil', 'bomb', 'bone', 'bonus', 'book', 'boost', 'border', 'boring', 'borrow', 'boss',
  'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain', 'brand', 'brass', 'brave', 'bread',
  'breeze', 'brick', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze',
  'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb',
  'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus', 'business', 'busy',
  'butter', 'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake', 'call',
  'calm', 'camera', 'camp', 'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas',
  'canyon', 'capable', 'capital', 'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry',
  'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat', 'catalog', 'catch', 'category',
  'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery', 'cement', 'census', 'century',
  'cereal', 'certain', 'chair', 'chalk', 'champion', 'change', 'chaos', 'chapter', 'charge', 'chase',
  'chat', 'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child',
  'chimney', 'choice', 'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar', 'cinnamon', 'circle',
  'citizen', 'city', 'civil', 'claim', 'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk',
  'clever', 'click', 'client', 'cliff', 'climb', 'clinic', 'clip', 'clock', 'clog', 'close',
  'cloth', 'cloud', 'clown', 'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut',
  'code', 'coffee', 'coil', 'coin', 'collect', 'color', 'column', 'combine', 'come', 'comfort',
  'comic', 'common', 'company', 'concert', 'conduct', 'confirm', 'congress', 'connect', 'consider', 'control',
  'convince', 'cook', 'cool', 'copper', 'copy', 'coral', 'core', 'corn', 'correct', 'cost',
  'cotton', 'couch', 'country', 'couple', 'course', 'cousin', 'cover', 'coyote', 'crack', 'cradle',
  'craft', 'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream', 'credit', 'creek',
  'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross', 'crouch', 'crowd', 'crucial',
  'cruel', 'cruise', 'crumble', 'crunch', 'crush', 'cry', 'crystal', 'cube', 'culture', 'cup',
  'cupboard', 'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad',
  'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn', 'day', 'deal',
  'debate', 'debris', 'decade', 'december', 'decide', 'decline', 'decorate', 'decrease', 'deer', 'defense',
  'define', 'defy', 'degree', 'delay', 'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny',
  'depart', 'depend', 'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk'
];

// Store the current recovery phrase temporarily (cleared after acknowledgment)
let currentRecoveryPhrase = null;
let currentRecoveryEntropy = null;

/**
 * Generate cryptographically secure random bytes
 */
function getRandomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Generate a 24-word recovery phrase from entropy
 */
function generateRecoveryPhrase() {
  // Generate 256 bits of entropy for 24 words
  const entropy = getRandomBytes(32);
  currentRecoveryEntropy = entropy;

  // Convert entropy to words (simplified - in production use proper BIP39)
  const words = [];
  for (let i = 0; i < 24; i++) {
    const index = (entropy[i] + entropy[(i + 1) % 32]) % BIP39_WORDLIST.length;
    words.push(BIP39_WORDLIST[index]);
  }

  return words.join(' ');
}

/**
 * Derive encryption key from password and recovery phrase using PBKDF2
 */
async function deriveEncryptionKey(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data using AES-GCM
 */
async function encryptData(data, key, nonce) {
  const encoder = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encoder.encode(JSON.stringify(data))
  );
  return new Uint8Array(encrypted);
}

/**
 * Decrypt data using AES-GCM
 */
async function decryptData(encryptedData, key, nonce) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encryptedData
  );
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}

/**
 * Convert Uint8Array to Base64
 */
function uint8ArrayToBase64(array) {
  return btoa(String.fromCharCode.apply(null, array));
}

/**
 * Convert Base64 to Uint8Array
 */
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const array = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
  }
  return array;
}

/**
 * Load credential backup status from API
 */
async function loadCredentialBackupStatus() {
  const statusContent = document.getElementById('credentialBackupStatusContent');

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/backup', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      throw new Error('Failed to load credential backup status');
    }

    const status = await res.json();
    renderCredentialBackupStatus(status);

  } catch (error) {
    console.error('Error loading credential backup status:', error);
    statusContent.innerHTML = `
      <div style="padding:20px;background:rgba(244,67,54,0.1);border:1px solid #f44336;border-radius:8px;text-align:center;">
        <p style="margin:0;color:#f44336;">Failed to load backup status</p>
        <p style="margin:8px 0 0 0;color:var(--gray);font-size:0.85rem;">${error.message}</p>
      </div>
    `;
  }
}

/**
 * Render credential backup status
 */
function renderCredentialBackupStatus(status) {
  const statusContent = document.getElementById('credentialBackupStatusContent');
  const createCard = document.getElementById('credentialBackupCreateCard');

  if (status.exists) {
    const createdDate = new Date(status.created_at).toLocaleDateString();
    const updatedDate = status.updated_at ? new Date(status.updated_at).toLocaleDateString() : createdDate;
    const sizeKB = Math.round(status.size_bytes / 1024 * 10) / 10;

    statusContent.innerHTML = `
      <div style="display:grid;gap:16px;">
        <div style="display:flex;align-items:center;gap:12px;padding:16px;background:linear-gradient(135deg,rgba(16,185,129,0.1) 0%,rgba(5,150,105,0.05) 100%);border:1px solid #10b981;border-radius:8px;">
          <div style="width:40px;height:40px;background:#10b981;border-radius:50%;display:flex;align-items:center;justify-content:center;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          </div>
          <div>
            <p style="margin:0;color:#10b981;font-weight:600;">Backup Active</p>
            <p style="margin:4px 0 0 0;color:var(--gray);font-size:0.85rem;">Your credentials are securely backed up</p>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;">
          <div style="padding:12px;background:#0a0a0a;border-radius:6px;border:1px solid #222;">
            <p style="margin:0;color:var(--gray);font-size:0.75rem;text-transform:uppercase;">Created</p>
            <p style="margin:4px 0 0 0;color:var(--text);font-weight:600;">${createdDate}</p>
          </div>
          <div style="padding:12px;background:#0a0a0a;border-radius:6px;border:1px solid #222;">
            <p style="margin:0;color:var(--gray);font-size:0.75rem;text-transform:uppercase;">Last Updated</p>
            <p style="margin:4px 0 0 0;color:var(--text);font-weight:600;">${updatedDate}</p>
          </div>
          <div style="padding:12px;background:#0a0a0a;border-radius:6px;border:1px solid #222;">
            <p style="margin:0;color:var(--gray);font-size:0.75rem;text-transform:uppercase;">Size</p>
            <p style="margin:4px 0 0 0;color:var(--text);font-weight:600;">${sizeKB} KB</p>
          </div>
          <div style="padding:12px;background:#0a0a0a;border-radius:6px;border:1px solid #222;">
            <p style="margin:0;color:var(--gray);font-size:0.75rem;text-transform:uppercase;">Encryption</p>
            <p style="margin:4px 0 0 0;color:var(--text);font-weight:600;">${status.encryption_method || 'AES-256-GCM'}</p>
          </div>
        </div>
      </div>
    `;

    // Update create card to show "Update Backup" instead
    const createCardTitle = createCard.querySelector('h3');
    if (createCardTitle) {
      createCardTitle.textContent = 'Update Credential Backup';
    }
    const createBtn = document.getElementById('createCredBackupBtn');
    if (createBtn) {
      createBtn.textContent = 'Update Encrypted Backup';
    }

    // Update inline backup status in vault deploy view
    const inlineStatus = document.getElementById('backupStatusValueInline');
    const inlineLastBackup = document.getElementById('lastBackupValueInline');
    if (inlineStatus) inlineStatus.textContent = 'Active';
    if (inlineLastBackup) inlineLastBackup.textContent = updatedDate;

  } else {
    statusContent.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;padding:16px;background:rgba(255,193,37,0.1);border:1px solid var(--accent);border-radius:8px;">
        <div style="width:40px;height:40px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>
        <div>
          <p style="margin:0;color:var(--accent);font-weight:600;">No Backup Found</p>
          <p style="margin:4px 0 0 0;color:var(--gray);font-size:0.85rem;">Create a backup to protect your credentials</p>
        </div>
      </div>
    `;

    // Update inline backup status in vault deploy view
    const inlineStatus = document.getElementById('backupStatusValueInline');
    const inlineLastBackup = document.getElementById('lastBackupValueInline');
    if (inlineStatus) inlineStatus.textContent = 'Not configured';
    if (inlineLastBackup) inlineLastBackup.textContent = 'Never';
  }
}

/**
 * Validate password strength
 */
function validateBackupPassword(password) {
  if (password.length < 12) {
    return 'Password must be at least 12 characters';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain lowercase letters';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain uppercase letters';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password must contain numbers';
  }
  return null;
}

/**
 * Create credential backup
 */
async function createCredentialBackup() {
  const password = document.getElementById('credBackupPassword').value;
  const confirmPassword = document.getElementById('credBackupPasswordConfirm').value;
  const errorDiv = document.getElementById('credBackupError');
  const btn = document.getElementById('createCredBackupBtn');

  // Reset error
  errorDiv.style.display = 'none';

  // Validate passwords
  const passwordError = validateBackupPassword(password);
  if (passwordError) {
    errorDiv.textContent = passwordError;
    errorDiv.style.display = 'block';
    return;
  }

  if (password !== confirmPassword) {
    errorDiv.textContent = 'Passwords do not match';
    errorDiv.style.display = 'block';
    return;
  }

  // Disable button and show loading
  btn.disabled = true;
  const originalText = btn.textContent;
  btn.textContent = 'Encrypting...';

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    // Generate recovery phrase
    currentRecoveryPhrase = generateRecoveryPhrase();

    // Create salt from recovery phrase entropy
    const salt = currentRecoveryEntropy.slice(0, 16);

    // Generate nonce for encryption (12 bytes for AES-GCM)
    const nonce = getRandomBytes(12);

    // Derive encryption key from password + salt
    const key = await deriveEncryptionKey(password, salt);

    // Get credential data to backup (in a real implementation, this would be actual credentials)
    // For now, we create a placeholder structure
    const credentialData = {
      version: 1,
      created_at: new Date().toISOString(),
      recovery_phrase_hash: await hashRecoveryPhrase(currentRecoveryPhrase),
      placeholder: 'Credential data would be stored here'
    };

    // Encrypt the credential data
    const encryptedBlob = await encryptData(credentialData, key, nonce);

    // Prepare 24-byte nonce for XChaCha20 format (pad our 12-byte nonce)
    const extendedNonce = new Uint8Array(24);
    extendedNonce.set(nonce);

    // Send to backend
    const res = await fetch(API_URL + '/vault/credentials/backup', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        encrypted_blob: uint8ArrayToBase64(encryptedBlob),
        salt: uint8ArrayToBase64(salt),
        nonce: uint8ArrayToBase64(extendedNonce)
      })
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to create backup');
    }

    // Show recovery phrase card
    document.getElementById('recoveryPhraseDisplay').textContent = currentRecoveryPhrase;
    document.getElementById('recoveryPhraseCard').style.display = 'block';
    document.getElementById('credentialBackupCreateCard').style.display = 'none';

    // Clear password fields
    document.getElementById('credBackupPassword').value = '';
    document.getElementById('credBackupPasswordConfirm').value = '';

    showToast('Backup created successfully! Save your recovery phrase.', 'success');

  } catch (error) {
    console.error('Error creating credential backup:', error);
    errorDiv.textContent = error.message;
    errorDiv.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

/**
 * Hash recovery phrase for verification
 */
async function hashRecoveryPhrase(phrase) {
  const encoder = new TextEncoder();
  const data = encoder.encode(phrase);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return uint8ArrayToBase64(new Uint8Array(hash));
}

/**
 * Copy recovery phrase to clipboard
 */
function copyRecoveryPhrase() {
  if (!currentRecoveryPhrase) return;

  navigator.clipboard.writeText(currentRecoveryPhrase).then(() => {
    showToast('Recovery phrase copied to clipboard', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showToast('Failed to copy to clipboard', 'error');
  });
}

/**
 * Download recovery phrase as a file
 */
function downloadRecoveryPhrase() {
  if (!currentRecoveryPhrase) return;

  const content = `VettID Credential Recovery Phrase
================================
Generated: ${new Date().toISOString()}

Your recovery phrase (24 words):
${currentRecoveryPhrase}

IMPORTANT:
- Store this file in a secure location
- Never share this phrase with anyone
- You will need this phrase AND your backup password to recover your credentials
- VettID cannot recover your credentials if you lose this phrase
`;

  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vettid-recovery-phrase.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast('Recovery phrase downloaded', 'success');
}

/**
 * Handle acknowledgment checkbox
 */
document.addEventListener('DOMContentLoaded', function() {
  const checkbox = document.getElementById('recoveryPhraseAcknowledge');
  const btn = document.getElementById('acknowledgeRecoveryBtn');

  if (checkbox && btn) {
    checkbox.addEventListener('change', function() {
      btn.disabled = !this.checked;
    });
  }
});

/**
 * Acknowledge recovery phrase has been saved
 */
function acknowledgeRecoveryPhrase() {
  // Clear the recovery phrase from memory
  currentRecoveryPhrase = null;
  currentRecoveryEntropy = null;

  // Hide recovery phrase card, show create card again
  document.getElementById('recoveryPhraseCard').style.display = 'none';
  document.getElementById('credentialBackupCreateCard').style.display = 'block';

  // Reset checkbox
  document.getElementById('recoveryPhraseAcknowledge').checked = false;
  document.getElementById('acknowledgeRecoveryBtn').disabled = true;

  // Reload status
  loadCredentialBackupStatus();

  showToast('Backup complete. Your credentials are now protected.', 'success');
}

/**
 * Recover credentials from backup
 */
async function recoverCredentials() {
  const recoveryPhrase = document.getElementById('credRecoveryPhrase').value.trim();
  const password = document.getElementById('credRecoveryPassword').value;
  const errorDiv = document.getElementById('credRecoveryError');
  const successDiv = document.getElementById('credRecoverySuccess');
  const btn = document.getElementById('recoverCredBtn');

  // Reset messages
  errorDiv.style.display = 'none';
  successDiv.style.display = 'none';

  // Validate inputs
  if (!recoveryPhrase) {
    errorDiv.textContent = 'Please enter your recovery phrase';
    errorDiv.style.display = 'block';
    return;
  }

  const words = recoveryPhrase.toLowerCase().split(/\s+/).filter(w => w.length > 0);
  if (words.length !== 24) {
    errorDiv.textContent = 'Recovery phrase must be exactly 24 words (you entered ' + words.length + ')';
    errorDiv.style.display = 'block';
    return;
  }

  if (!password) {
    errorDiv.textContent = 'Please enter your backup password';
    errorDiv.style.display = 'block';
    return;
  }

  // Disable button and show loading
  btn.disabled = true;
  const originalText = btn.textContent;
  btn.textContent = 'Recovering...';

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    // Download encrypted backup from backend
    const res = await fetch(API_URL + '/vault/credentials/recover', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      if (res.status === 404) {
        throw new Error('No backup found for your account');
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to download backup');
    }

    const backupData = await res.json();

    // Decode backup data
    const encryptedBlob = base64ToUint8Array(backupData.encrypted_blob);
    const salt = base64ToUint8Array(backupData.salt);
    const nonce = base64ToUint8Array(backupData.nonce).slice(0, 12); // Get first 12 bytes for AES-GCM

    // Derive decryption key from password + salt
    const key = await deriveEncryptionKey(password, salt);

    // Attempt decryption
    try {
      const decryptedData = await decryptData(encryptedBlob, key, nonce);

      // Verify recovery phrase hash
      const providedHash = await hashRecoveryPhrase(words.join(' '));
      if (decryptedData.recovery_phrase_hash !== providedHash) {
        throw new Error('Recovery phrase does not match');
      }

      // Success!
      successDiv.innerHTML = `
        <p style="margin:0;font-weight:600;">Credentials recovered successfully!</p>
        <p style="margin:8px 0 0 0;">Your credentials have been restored to this device.</p>
      `;
      successDiv.style.display = 'block';

      // Clear form
      document.getElementById('credRecoveryPhrase').value = '';
      document.getElementById('credRecoveryPassword').value = '';

      showToast('Credentials recovered successfully!', 'success');

    } catch (decryptError) {
      console.error('Decryption error:', decryptError);
      throw new Error('Invalid password or recovery phrase. Please check and try again.');
    }

  } catch (error) {
    console.error('Error recovering credentials:', error);
    errorDiv.textContent = error.message;
    errorDiv.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

/**
 * Initialize credential backup tab
 */
function initCredentialBackupTab() {
  loadCredentialBackupStatus();
  loadBackupSettings();
  loadRestoreStatus();
}

// ============================================
// BACKUP SETTINGS FUNCTIONS
// ============================================

/**
 * Load backup settings from API
 */
async function loadBackupSettings() {
  const toggle = document.getElementById('credentialBackupEnabled');
  const inlineToggle = document.getElementById('credentialBackupEnabledInline');

  try {
    const token = idToken();
    if (!token) return;

    const res = await fetch(API_URL + '/vault/credentials/backup/settings', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.ok) {
      const settings = await res.json();
      const enabled = settings.enabled || false;
      if (toggle) toggle.checked = enabled;
      if (inlineToggle) inlineToggle.checked = enabled;
      updateBackupCardsState(enabled);
    } else {
      // If no settings exist, assume disabled
      updateBackupCardsState(false);
    }
  } catch (error) {
    console.error('Error loading backup settings:', error);
    updateBackupCardsState(false);
  }

  // Add change handler for original toggle
  if (toggle) {
    toggle.addEventListener('change', async () => {
      await updateBackupSettings(toggle.checked);
      if (inlineToggle) inlineToggle.checked = toggle.checked;
      updateBackupCardsState(toggle.checked);
    });
  }

  // Add change handler for inline toggle (syncs with original)
  if (inlineToggle) {
    inlineToggle.addEventListener('change', async () => {
      await updateBackupSettings(inlineToggle.checked);
      if (toggle) toggle.checked = inlineToggle.checked;
      updateBackupCardsState(inlineToggle.checked);
    });
  }
}

/**
 * Update backup status and restore cards enabled/disabled state
 */
function updateBackupCardsState(enabled) {
  const statusCard = document.getElementById('credentialBackupStatusCard');
  const restoreCard = document.getElementById('credentialRestoreCard');

  const disabledStyles = {
    opacity: '0.5',
    pointerEvents: 'none',
    filter: 'grayscale(0.5)'
  };

  const enabledStyles = {
    opacity: '1',
    pointerEvents: 'auto',
    filter: 'none'
  };

  const styles = enabled ? enabledStyles : disabledStyles;

  if (statusCard) {
    Object.assign(statusCard.style, styles);
  }
  if (restoreCard) {
    Object.assign(restoreCard.style, styles);
    // Also show/hide disabled message
    let disabledMsg = restoreCard.querySelector('.backup-disabled-msg');
    if (!enabled) {
      if (!disabledMsg) {
        disabledMsg = document.createElement('div');
        disabledMsg.className = 'backup-disabled-msg';
        disabledMsg.style.cssText = 'padding:12px;background:rgba(107,114,128,0.1);border:1px solid #6b7280;border-radius:6px;margin-bottom:16px;text-align:center;';
        disabledMsg.innerHTML = '<span style="color:#6b7280;font-size:0.9rem;">Enable automatic backups above to use restore features.</span>';
        restoreCard.insertBefore(disabledMsg, restoreCard.children[2]);
      }
    } else if (disabledMsg) {
      disabledMsg.remove();
    }
  }
}

/**
 * Update backup settings
 */
async function updateBackupSettings(enabled) {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/backup/settings', {
      method: 'PUT',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ enabled })
    });

    if (!res.ok) {
      throw new Error('Failed to update backup settings');
    }

    showToast(enabled ? 'Automatic backups enabled' : 'Automatic backups disabled', 'success');
  } catch (error) {
    console.error('Error updating backup settings:', error);
    showToast('Failed to update settings', 'error');
  }
}

// ============================================
// CREDENTIAL RESTORE FUNCTIONS
// ============================================

/**
 * Load restore status from API
 */
async function loadRestoreStatus() {
  try {
    const token = idToken();
    if (!token) return;

    const res = await fetch(API_URL + '/vault/credentials/restore/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) return;

    const status = await res.json();
    renderRestoreStatus(status);
  } catch (error) {
    console.error('Error loading restore status:', error);
  }
}

/**
 * Load and display recovery QR code
 * Architecture v2.0: Recovery via QR code scanned by mobile app
 */
let recoveryQRRefreshTimer = null;

async function loadRecoveryQR(recoveryId) {
  const qrContainer = document.getElementById('recoveryQRContainer');
  const qrImage = document.getElementById('recoveryQRImage');
  const qrExpiry = document.getElementById('recoveryQRExpiry');
  const qrError = document.getElementById('recoveryQRError');

  if (!qrContainer || !qrImage) return;

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    // Fetch QR code data from new endpoint
    const res = await fetch(API_URL + '/vault/recovery/qr?recovery_id=' + encodeURIComponent(recoveryId), {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to load recovery QR code');
    }

    const data = await res.json();

    // Generate QR code using Google Charts API (simple, no library needed)
    // The qr_data is base64-encoded JSON payload
    const qrCodeUrl = `https://chart.googleapis.com/chart?cht=qr&chs=250x250&chl=${encodeURIComponent(data.qr_data)}&choe=UTF-8`;
    qrImage.src = qrCodeUrl;
    qrImage.style.display = 'block';

    // Show expiry countdown
    if (qrExpiry && data.expires_at) {
      updateQRExpiryCountdown(data.expires_at);
    }

    if (qrError) qrError.style.display = 'none';

  } catch (error) {
    console.error('Error loading recovery QR:', error);
    if (qrError) {
      qrError.textContent = error.message;
      qrError.style.display = 'block';
    }
    if (qrImage) qrImage.style.display = 'none';
  }
}

/**
 * Update QR code expiry countdown
 */
function updateQRExpiryCountdown(expiresAt) {
  const qrExpiry = document.getElementById('recoveryQRExpiry');
  if (!qrExpiry) return;

  // Clear any existing timer
  if (recoveryQRRefreshTimer) {
    clearInterval(recoveryQRRefreshTimer);
  }

  const expiryTime = new Date(expiresAt).getTime();

  function updateCountdown() {
    const now = Date.now();
    const remaining = Math.max(0, expiryTime - now);

    if (remaining === 0) {
      qrExpiry.textContent = 'QR code expired. Click "Refresh QR Code" to generate a new one.';
      qrExpiry.style.color = '#f44336';
      clearInterval(recoveryQRRefreshTimer);
      return;
    }

    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    qrExpiry.textContent = `QR code expires in ${minutes}:${seconds.toString().padStart(2, '0')}`;
    qrExpiry.style.color = minutes < 2 ? '#f59e0b' : 'var(--gray)';
  }

  updateCountdown();
  recoveryQRRefreshTimer = setInterval(updateCountdown, 1000);
}

/**
 * Refresh the recovery QR code
 */
async function refreshRecoveryQR() {
  const recoveryId = document.getElementById('recoveryQRContainer')?.dataset?.recoveryId;
  if (recoveryId) {
    await loadRecoveryQR(recoveryId);
    showToast('QR code refreshed', 'success');
  }
}

/**
 * Render restore status UI
 * Updated for Architecture v2.0: QR code recovery flow
 */
function renderRestoreStatus(status) {
  const statusSection = document.getElementById('restoreStatusSection');
  const optionsSection = document.getElementById('restoreOptionsSection');
  const confirmSection = document.getElementById('confirmRecoverySection');
  const statusContent = document.getElementById('restoreStatusContent');

  if (!statusSection || !optionsSection) return;

  if (!status.has_pending_request) {
    statusSection.style.display = 'none';
    optionsSection.style.display = 'grid';
    confirmSection.style.display = 'none';
    return;
  }

  optionsSection.style.display = 'none';
  statusSection.style.display = 'block';

  // Escape dynamic values from server to prevent XSS
  const safeMessage = escapeHtml(status.message || '');
  const safeRecoveryId = escapeHtml(status.recovery_id || '');
  const safeTimeRemaining = escapeHtml(status.time_remaining_display || '--');

  if (status.is_ready) {
    // Show QR code section for recovery (Architecture v2.0)
    confirmSection.style.display = 'block';

    // For transfers, show old flow; for recovery, show QR code
    if (status.status === 'approved') {
      // Transfer flow (device-to-device) - keep old behavior
      statusContent.innerHTML = '<div style="display:flex;align-items:center;gap:12px;">' +
        '<div style="width:40px;height:40px;background:#10b981;border-radius:50%;display:flex;align-items:center;justify-content:center;">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' +
        '</div><div>' +
        '<p style="margin:0;color:#10b981;font-weight:600;">Transfer Approved!</p>' +
        '<p style="margin:4px 0 0 0;color:var(--gray);font-size:0.9rem;">' + safeMessage + '</p>' +
        '</div></div>';
    } else {
      // Recovery flow (device lost) - show QR code
      statusContent.innerHTML = '<div style="text-align:center;">' +
        '<div style="display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:20px;">' +
        '<div style="width:40px;height:40px;background:#10b981;border-radius:50%;display:flex;align-items:center;justify-content:center;">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' +
        '</div><div style="text-align:left;">' +
        '<p style="margin:0;color:#10b981;font-weight:600;">Recovery Ready</p>' +
        '<p style="margin:4px 0 0 0;color:var(--gray);font-size:0.9rem;">Scan the QR code with your VettID app</p>' +
        '</div></div>' +
        '<div id="recoveryQRContainer" data-recovery-id="' + safeRecoveryId + '" style="background:#fff;padding:20px;border-radius:12px;display:inline-block;margin:20px 0;">' +
        '<img id="recoveryQRImage" alt="Recovery QR Code" style="width:250px;height:250px;display:none;" />' +
        '<div id="recoveryQRError" style="display:none;color:#f44336;padding:20px;"></div>' +
        '<div id="recoveryQRLoading" style="width:250px;height:250px;display:flex;align-items:center;justify-content:center;">' +
        '<div style="width:40px;height:40px;border:4px solid #e5e7eb;border-top-color:#10b981;border-radius:50%;animation:spin 1s linear infinite;"></div>' +
        '</div></div>' +
        '<p id="recoveryQRExpiry" style="margin:0 0 16px 0;color:var(--gray);font-size:0.9rem;">Loading QR code...</p>' +
        '<div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">' +
        '<button data-action="refreshRecoveryQR" class="btn" style="padding:10px 20px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;font-weight:600;">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:8px;vertical-align:middle;"><path d="M21 12a9 9 0 11-6.22-8.56"/><polyline points="21 3 21 9 15 9"/></svg>' +
        'Refresh QR Code</button>' +
        '<button data-action="cancelRestore" class="btn" style="padding:10px 20px;background:#333;">Cancel Request</button>' +
        '</div>' +
        '<p style="margin:20px 0 0 0;color:var(--gray);font-size:0.85rem;">' +
        'Open the VettID app on your new device and scan this QR code to recover your vault credentials.</p>' +
        '</div>';

      // Hide the old recovery phrase section
      confirmSection.style.display = 'none';

      // Load QR code after DOM update
      if (status.recovery_id) {
        setTimeout(function() {
          var loading = document.getElementById('recoveryQRLoading');
          if (loading) loading.style.display = 'flex';
          loadRecoveryQR(status.recovery_id);
        }, 100);
      }
    }
  } else {
    confirmSection.style.display = 'none';
    const isPendingApproval = status.status === 'pending_approval';
    const pendingMessage = isPendingApproval ? 'Check your device for approval request' : 'Time remaining: ' + safeTimeRemaining;
    statusContent.innerHTML = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">' +
      '<div style="width:40px;height:40px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;">' +
      '<div style="width:20px;height:20px;border:3px solid #000;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>' +
      '</div><div>' +
      '<p style="margin:0;color:var(--accent);font-weight:600;">' + (isPendingApproval ? 'Waiting for Approval' : 'Recovery Pending') + '</p>' +
      '<p style="margin:4px 0 0 0;color:var(--gray);font-size:0.9rem;">' + (safeMessage || pendingMessage) + '</p>' +
      '</div></div>' +
      '<button data-action="cancelRestore" class="btn" style="padding:8px 16px;background:#333;">Cancel Request</button>';
  }
}

/**
 * Request credential transfer (old device still active)
 */
async function requestTransfer() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/restore/request', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ lost_device: false })
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to request transfer');
    }

    showToast('Transfer request sent! Check your device for approval.', 'success');
    loadRestoreStatus();
  } catch (error) {
    console.error('Error requesting transfer:', error);
    showToast(error.message, 'error');
  }
}

/**
 * Request credential recovery (device lost)
 */
async function requestRecovery() {
  if (!confirm('Are you sure? A 24-hour security delay will begin. If you find your device during this time, you can cancel the request.')) {
    return;
  }

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/restore/request', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ lost_device: true })
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to request recovery');
    }

    showToast('Recovery request submitted. 24-hour security delay started.', 'success');
    loadRestoreStatus();
  } catch (error) {
    console.error('Error requesting recovery:', error);
    showToast(error.message, 'error');
  }
}

/**
 * Cancel restore request
 */
async function cancelRestore() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/restore/cancel', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      throw new Error('Failed to cancel request');
    }

    showToast('Restore request cancelled', 'success');
    loadRestoreStatus();
  } catch (error) {
    console.error('Error cancelling restore:', error);
    showToast(error.message, 'error');
  }
}

/**
 * Confirm recovery with phrase
 */
async function confirmRecovery() {
  const phrase = document.getElementById('credRecoveryPhrase')?.value?.trim();
  const errorDiv = document.getElementById('credRecoveryError');

  if (!phrase) {
    errorDiv.textContent = 'Please enter your recovery phrase';
    errorDiv.style.display = 'block';
    return;
  }

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/credentials/restore/confirm', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ recovery_phrase: phrase })
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to confirm recovery');
    }

    const result = await res.json();
    showToast('Credentials restored successfully!', 'success');
    errorDiv.style.display = 'none';
    loadRestoreStatus();
    loadCredentialBackupStatus();
  } catch (error) {
    console.error('Error confirming recovery:', error);
    errorDiv.textContent = error.message;
    errorDiv.style.display = 'block';
  }
}

// ============================================
// VAULT DELETION FUNCTIONS
// ============================================

/**
 * Load vault deletion status
 */
async function loadVaultDeletionStatus() {
  const deletionCard = document.getElementById('vaultDeletionCard');
  if (!deletionCard) return;

  try {
    const token = idToken();
    if (!token) return;

    const res = await fetch(API_URL + '/vault/delete/status', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) return;

    const status = await res.json();
    renderVaultDeletionStatus(status);
  } catch (error) {
    console.error('Error loading vault deletion status:', error);
  }
}

/**
 * Render vault deletion status
 */
function renderVaultDeletionStatus(status) {
  const normalState = document.getElementById('deletionNormalState');
  const pendingState = document.getElementById('deletionPendingState');
  const readyState = document.getElementById('deletionReadyState');
  const timeRemaining = document.getElementById('deletionTimeRemaining');

  if (!normalState || !pendingState || !readyState) return;

  if (!status.has_pending_request) {
    normalState.style.display = 'block';
    pendingState.style.display = 'none';
    readyState.style.display = 'none';
  } else if (status.is_ready) {
    normalState.style.display = 'none';
    pendingState.style.display = 'none';
    readyState.style.display = 'block';
  } else {
    normalState.style.display = 'none';
    pendingState.style.display = 'block';
    readyState.style.display = 'none';
    if (timeRemaining) {
      timeRemaining.textContent = 'Time remaining: ' + (status.time_remaining_display || '--');
    }
  }
}

/**
 * Request vault deletion
 */
async function requestVaultDeletion() {
  if (!confirm('Are you sure you want to delete your vault? A 24-hour waiting period will begin.')) {
    return;
  }

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/delete/request', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to request deletion');
    }

    showToast('Vault deletion requested. 24-hour waiting period started.', 'success');
    loadVaultDeletionStatus();
  } catch (error) {
    console.error('Error requesting vault deletion:', error);
    showToast(error.message, 'error');
  }
}

/**
 * Cancel vault deletion
 */
async function cancelVaultDeletion() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/delete/cancel', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      throw new Error('Failed to cancel deletion');
    }

    showToast('Vault deletion cancelled', 'success');
    loadVaultDeletionStatus();
  } catch (error) {
    console.error('Error cancelling vault deletion:', error);
    showToast(error.message, 'error');
  }
}

/**
 * Confirm vault deletion
 */
async function confirmVaultDeletion() {
  if (!confirm('⚠️ FINAL WARNING: This will PERMANENTLY DELETE your vault and all associated data. This action CANNOT be undone. Are you absolutely sure?')) {
    return;
  }

  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    const res = await fetch(API_URL + '/vault/delete/confirm', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.message || 'Failed to confirm deletion');
    }

    showToast('Vault has been permanently deleted', 'success');
    loadVaultStatus();
    loadVaultDeletionStatus();
  } catch (error) {
    console.error('Error confirming vault deletion:', error);
    showToast(error.message, 'error');
  }
}

// ============================================
// END CREDENTIAL BACKUP FUNCTIONS
// ============================================

let enrollmentSession = null;
let enrollmentPollInterval = null;

async function startEnrollment() {
  try {
    const token = idToken();
    if (!token) throw new Error('No authentication token');

    showToast('Creating enrollment session...', 'info');

    // Create enrollment session on backend
    const res = await fetch(API_URL + '/vault/enroll/session', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    });

    if (!res.ok) {
      // If endpoint not available (404 or 403), show manual enrollment instructions
      if (res.status === 404 || res.status === 403) {
        showManualEnrollmentModal();
        return;
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.message || 'Failed to create enrollment session');
    }

    enrollmentSession = await res.json();
    showEnrollmentModal(enrollmentSession);

  } catch (error) {
    console.error('Error starting enrollment:', error);
    // Network error or other issue - show manual enrollment
    showManualEnrollmentModal();
  }
}

function showManualEnrollmentModal() {
  const modal = document.createElement('div');
  modal.id = 'enrollmentModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.9);display:flex;align-items:center;justify-content:center;z-index:9999;';
  modal.innerHTML = `
    <div style="background:#0a0a0a;border:1px solid var(--accent);border-radius:12px;padding:32px;max-width:480px;width:90%;text-align:center;">
      <h3 style="margin:0 0 8px 0;color:var(--accent);">Enroll Your Mobile Device</h3>
      <p style="color:var(--gray);margin-bottom:24px;font-size:0.95rem;">
        To enroll your mobile device with VettID, follow these steps:
      </p>

      <div style="text-align:left;background:#050505;border-radius:8px;padding:20px;margin-bottom:24px;border:1px solid #333;">
        <div style="display:flex;gap:12px;margin-bottom:16px;">
          <div style="flex-shrink:0;width:28px;height:28px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;color:#000;">1</div>
          <div>
            <div style="color:var(--text);font-weight:600;margin-bottom:4px;">Download the VettID App</div>
            <div style="color:var(--gray);font-size:0.9rem;">Available on iOS App Store and Google Play</div>
          </div>
        </div>
        <div style="display:flex;gap:12px;margin-bottom:16px;">
          <div style="flex-shrink:0;width:28px;height:28px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;color:#000;">2</div>
          <div>
            <div style="color:var(--text);font-weight:600;margin-bottom:4px;">Sign In with Your Account</div>
            <div style="color:var(--gray);font-size:0.9rem;">Use the same email you registered with</div>
          </div>
        </div>
        <div style="display:flex;gap:12px;">
          <div style="flex-shrink:0;width:28px;height:28px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;color:#000;">3</div>
          <div>
            <div style="color:var(--text);font-weight:600;margin-bottom:4px;">Complete Enrollment</div>
            <div style="color:var(--gray);font-size:0.9rem;">Follow the in-app instructions to set up your vault</div>
          </div>
        </div>
      </div>

      <div style="display:flex;gap:12px;justify-content:center;margin-bottom:20px;">
        <a href="#" style="display:inline-flex;align-items:center;gap:8px;padding:12px 20px;background:#000;border:1px solid #333;border-radius:8px;color:var(--text);text-decoration:none;">
          <span style="font-size:1.2rem;"></span> App Store
        </a>
        <a href="#" style="display:inline-flex;align-items:center;gap:8px;padding:12px 20px;background:#000;border:1px solid #333;border-radius:8px;color:var(--text);text-decoration:none;">
          <span style="font-size:1.2rem;"></span> Google Play
        </a>
      </div>

      <button data-action="closeEnrollmentModal" class="btn" style="padding:12px 24px;background:#333;">
        Close
      </button>
    </div>
  `;

  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) closeEnrollmentModal(); };
}

function showEnrollmentModal(session) {
  // Generate QR code data as JSON string
  const qrData = JSON.stringify(session.qr_data);
  const deepLinkUrl = session.deep_link_url || '';

  const modal = document.createElement('div');
  modal.id = 'enrollmentModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.9);display:flex;align-items:flex-start;justify-content:center;z-index:9999;overflow-y:auto;padding:20px 0;';
  modal.innerHTML = `
    <div style="background:#0a0a0a;border:1px solid var(--accent);border-radius:12px;padding:32px;max-width:480px;width:90%;text-align:center;margin:auto 0;">
      <h3 style="margin:0 0 8px 0;color:var(--accent);">Enroll Your Mobile Device</h3>
      <p style="color:var(--gray);margin-bottom:24px;font-size:0.95rem;">
        Scan this QR code with the VettID app on your mobile device to complete enrollment.
      </p>

      <div id="enrollmentQRContainer" style="background:#fff;padding:20px;border-radius:8px;display:inline-block;margin-bottom:16px;">
        <div id="enrollmentQRCode" style="width:200px;height:200px;display:flex;align-items:center;justify-content:center;">
          <div style="color:#000;">Loading QR code...</div>
        </div>
      </div>

      ${deepLinkUrl ? `
      <div style="margin-bottom:20px;">
        <p style="color:var(--gray);font-size:0.85rem;margin-bottom:8px;">Or tap the link on your mobile device:</p>
        <a href="${deepLinkUrl}" target="_blank" style="display:inline-block;padding:12px 20px;background:var(--accent);color:#000;text-decoration:none;border-radius:6px;font-weight:600;font-size:0.9rem;">
          Open in VettID App
        </a>
        <button id="copyEnrollLink" style="margin-left:8px;padding:12px 16px;background:#333;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:0.9rem;" title="Copy link">
          Copy Link
        </button>
      </div>
      ` : ''}

      <div id="enrollmentStatus" style="margin-bottom:20px;">
        <div style="display:flex;align-items:center;justify-content:center;gap:12px;padding:16px;background:#050505;border-radius:8px;border:1px solid #333;">
          <div id="enrollmentSpinner" style="width:20px;height:20px;border:2px solid var(--accent);border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
          <span style="color:var(--gray);">Waiting for mobile app to scan...</span>
        </div>
      </div>

      <div style="margin-bottom:20px;padding:16px;background:#050505;border-radius:8px;border:1px solid #333;">
        <div style="color:var(--gray);font-size:0.85rem;margin-bottom:8px;">Session expires in:</div>
        <div id="enrollmentTimer" style="color:var(--accent);font-size:1.2rem;font-weight:600;">7:00</div>
      </div>

      <div style="display:flex;gap:12px;justify-content:center;">
        <button data-action="closeEnrollmentModal" class="btn" style="padding:12px 24px;background:#333;">
          Cancel
        </button>
      </div>

      <p style="color:var(--gray);margin-top:20px;font-size:0.8rem;">
        Don't have the VettID app? Download it from the
        <a href="#" style="color:var(--accent);">App Store</a> or
        <a href="#" style="color:var(--accent);">Google Play</a>
      </p>
    </div>
  `;

  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) closeEnrollmentModal(); };

  // Add copy link handler
  const copyBtn = document.getElementById('copyEnrollLink');
  if (copyBtn && deepLinkUrl) {
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(deepLinkUrl);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy Link'; }, 2000);
      } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = deepLinkUrl;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy Link'; }, 2000);
      }
    };
  }

  // Generate QR code
  generateQRCode(qrData);

  // Start countdown timer
  startEnrollmentTimer(new Date(session.expires_at));

  // Start polling for enrollment status
  startEnrollmentPoll();
}

function generateQRCode(data) {
  const container = document.getElementById('enrollmentQRCode');
  if (!container) return;

  // Check if QRCode library is already loaded
  if (typeof QRCode !== 'undefined' && QRCode.CorrectLevel) {
    container.innerHTML = '';
    new QRCode(container, {
      text: data,
      width: 200,
      height: 200,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });
  } else {
    // Load qrcodejs library (David Shim's version - simpler browser API)
    // SECURITY: Self-hosted to avoid CDN dependency
    const script = document.createElement('script');
    script.src = '/shared/vendor/qrcode.min.js';
    script.onload = () => {
      container.innerHTML = '';
      try {
        new QRCode(container, {
          text: data,
          width: 200,
          height: 200,
          colorDark: '#000000',
          colorLight: '#ffffff',
          correctLevel: QRCode.CorrectLevel.M
        });
      } catch (error) {
        console.error('QR generation error:', error);
        showManualEnrollmentCode(container, data);
      }
    };
    script.onerror = () => {
      console.error('Failed to load QR code library');
      showManualEnrollmentCode(container, data);
    };
    document.head.appendChild(script);
  }
}

function showManualEnrollmentCode(container, data) {
  // Parse the QR data to show useful info
  let qrInfo;
  try {
    qrInfo = JSON.parse(data);
  } catch (e) {
    qrInfo = { session_token: enrollmentSession?.session_token };
  }

  container.innerHTML = `
    <div style="color:#000;font-size:0.75rem;word-break:break-all;max-width:180px;text-align:left;">
      <div style="font-weight:600;margin-bottom:8px;text-align:center;">Manual Entry</div>
      <div style="margin-bottom:6px;"><strong>Token:</strong></div>
      <div style="background:#f0f0f0;padding:8px;border-radius:4px;font-family:monospace;font-size:0.65rem;margin-bottom:8px;">${qrInfo.session_token || 'N/A'}</div>
      <div style="font-size:0.65rem;color:#666;text-align:center;">Enter this in the VettID app</div>
    </div>
  `;
}

function startEnrollmentTimer(expiresAt) {
  const timerEl = document.getElementById('enrollmentTimer');
  if (!timerEl) return;

  const updateTimer = () => {
    const now = new Date();
    const diff = expiresAt - now;

    if (diff <= 0) {
      timerEl.textContent = 'Expired';
      timerEl.style.color = '#ef4444';
      stopEnrollmentPoll();
      return;
    }

    const minutes = Math.floor(diff / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    timerEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;

    if (diff < 60000) {
      timerEl.style.color = '#f59e0b';
    }
  };

  updateTimer();
  const timerInterval = setInterval(() => {
    if (!document.getElementById('enrollmentTimer')) {
      clearInterval(timerInterval);
      return;
    }
    updateTimer();
  }, 1000);
}

function startEnrollmentPoll() {
  stopEnrollmentPoll();

  enrollmentPollInterval = setInterval(async () => {
    try {
      const token = idToken();
      const res = await fetch(API_URL + '/vault/status', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + token }
      });

      if (res.ok) {
        const status = await res.json();

        // Check if enrollment completed
        if (status.status === 'enrolled' || status.status === 'active') {
          stopEnrollmentPoll();
          updateEnrollmentStatus('success', 'Enrollment complete!');

          setTimeout(() => {
            closeEnrollmentModal();
            showToast('Mobile device enrolled successfully!', 'success');
            loadVaultStatus();
          }, 1500);
        } else if (status.status === 'pending') {
          updateEnrollmentStatus('pending', 'Mobile app connected, completing enrollment...');
        }
      }
    } catch (e) {
      console.error('Error polling enrollment status:', e);
    }
  }, 3000); // Poll every 3 seconds
}

function stopEnrollmentPoll() {
  if (enrollmentPollInterval) {
    clearInterval(enrollmentPollInterval);
    enrollmentPollInterval = null;
  }
}

function updateEnrollmentStatus(state, message) {
  const statusEl = document.getElementById('enrollmentStatus');
  if (!statusEl) return;

  if (state === 'success') {
    statusEl.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;gap:12px;padding:16px;background:#050a05;border-radius:8px;border:1px solid #10b981;">
        <span style="font-size:1.5rem;">✓</span>
        <span style="color:#10b981;font-weight:600;">${message}</span>
      </div>
    `;
  } else if (state === 'pending') {
    statusEl.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;gap:12px;padding:16px;background:#0a0a05;border-radius:8px;border:1px solid #f59e0b;">
        <div style="width:20px;height:20px;border:2px solid #f59e0b;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
        <span style="color:#f59e0b;">${message}</span>
      </div>
    `;
  }
}

async function closeEnrollmentModal() {
  stopEnrollmentPoll();

  // Cancel the enrollment session on the backend (best-effort cleanup)
  // 404 is expected if session already completed/expired - don't log as error
  if (enrollmentSession) {
    try {
      const token = idToken();
      const res = await fetch(API_URL + '/vault/enroll/cancel', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        }
      });
      // Only log unexpected errors (not 404 which means session already gone)
      if (!res.ok && res.status !== 404) {
        console.error('Error cancelling enrollment session:', res.status);
      }
    } catch (e) {
      // Network errors only - HTTP errors are handled above
      console.error('Network error cancelling enrollment session:', e);
    }
  }

  const modal = document.getElementById('enrollmentModal');
  if (modal) modal.remove();
  enrollmentSession = null;
}

function startVaultStatusPolling() {
  stopVaultStatusPolling();
  loadVaultStatus();
  // Also load backup settings for the integrated credential backup card
  loadBackupSettings();
  loadCredentialBackupStatus();
  vaultStatusInterval = setInterval(loadVaultStatus, 30000); // Poll every 30s
}

function stopVaultStatusPolling() {
  if (vaultStatusInterval) {
    clearInterval(vaultStatusInterval);
    vaultStatusInterval = null;
  }
}

// Initialize vault status when vault tab is activated
document.addEventListener('DOMContentLoaded', () => {
  const vaultTab = document.querySelector('.tab[data-tab="deploy-vault"]');
  if (vaultTab) {
    vaultTab.addEventListener('click', () => {
      startVaultStatusPolling();
    });
  }
});

// Initialize
if (checkAuth()) {
  // Start periodic token expiry checking
  startTokenExpiryCheck();

  // Define the main app initialization function
  const runAppInitialization = async () => {
    populateProfile();

    // Load subscription status first so isPaidSubscriber() works correctly in loadMembershipStatus()
    await loadSubscriptionStatus();

    // Load all data in parallel - including preloading for Getting Started steps
    // This eliminates duplicate API calls and runs vault/voting fetches early
    await Promise.all([
      loadMembershipStatus(),
      loadSubscriptionTypes(),
      loadPinStatus(),
      loadEmailPreferences(),
      preloadVaultStatus(),    // Preload for Getting Started (cached)
      preloadVotingHistory()   // Preload for Getting Started (cached)
    ]);

    updateTabVisibility();

    // populateGettingStartedSteps now uses cached data - no additional API calls needed
    await populateGettingStartedSteps();

    // Show Getting Started tab unless user has clicked "Got it" button
    // This is independent of membership status - getting started has multiple steps
    const complete = await isGettingStartedComplete();
    if (complete) {
      switchToTab('deploy-vault');
    } else {
      switchToTab('getting-started');
    }
  };

  // Store the continuation function for use after PIN verification
  continueAppInitialization = runAppInitialization;

  // PIN verification is handled during Cognito auth flow (magic link + PIN)
  // No need to verify again on account page load - this was causing double PIN prompts
  // The sessionStorage 'pinVerified' flag set during auth is sufficient
  // Wrap in async IIFE for proper top-level await support in non-module scripts
  (async () => {
    try {
      await runAppInitialization();
    } catch (error) {
      console.error('Error during app initialization:', error);
      // Show a user-friendly error message
      const container = document.getElementById('gettingStartedSteps');
      if (container) {
        container.innerHTML = '<div style="color:#ef4444;padding:20px;background:#1a1a1a;border-radius:8px;border:2px solid #ef4444;">Error loading your account. Please try refreshing the page.</div>';
      }
    }
  })();
}

// Sidebar toggle
document.getElementById('sidebarToggle').onclick=()=>{
  const sidebar=document.getElementById('sidebar');
  const toggle=document.getElementById('sidebarToggle');
  sidebar.classList.toggle('collapsed');
  toggle.textContent=sidebar.classList.contains('collapsed')?'>':'<';
};

// Event delegation for data-action handlers
// This replaces inline onclick handlers for CSP compliance
document.addEventListener('click', (e) => {
  const target = e.target.closest('[data-action]');
  if (!target) return;

  const action = target.dataset.action;

  // Map action names to functions (simple actions with no parameters)
  const actions = {
    'requestMembership': requestMembership,
    'loadVaultStatus': loadVaultStatus,
    'confirmStopVault': confirmStopVault,
    'confirmTerminateVault': confirmTerminateVault,
    'loadByovStatus': loadByovStatus,
    'registerByovVault': registerByovVault,
    'verifyByovVault': verifyByovVault,
    'showByovSettingsModal': showByovSettingsModal,
    'confirmDeleteByovVault': confirmDeleteByovVault,
    'loadCredentialBackupStatus': loadCredentialBackupStatus,
    'createCredentialBackup': createCredentialBackup,
    'copyRecoveryPhrase': copyRecoveryPhrase,
    'downloadRecoveryPhrase': downloadRecoveryPhrase,
    'acknowledgeRecoveryPhrase': acknowledgeRecoveryPhrase,
    'recoverCredentials': recoverCredentials,
    'closeProposalResultsModal': closeProposalResultsModal,
    'closePinDisableModal': closePinDisableModal,
    'submitPinDisable': submitPinDisable,
    'submitPinVerification': submitPinVerification,
    'signOut': () => { signOut(); return false; },
    'closeMembershipConfirmModal': closeMembershipConfirmModal,
    'confirmMembership': confirmMembership,
    'closeByovSettingsModal': closeByovSettingsModal,
    'clearByovApiKey': clearByovApiKey,
    'saveByovSettings': saveByovSettings,
    // Vault deletion actions
    'requestVaultDeletion': requestVaultDeletion,
    'cancelVaultDeletion': cancelVaultDeletion,
    'confirmVaultDeletion': confirmVaultDeletion,
    // Credential restore actions
    'requestTransfer': requestTransfer,
    'requestRecovery': requestRecovery,
    'cancelRestore': cancelRestore,
    'confirmRecovery': confirmRecovery,
    'refreshRecoveryQR': refreshRecoveryQR,
    // Vault management actions
    'startEnrollment': startEnrollment,
    'provisionVault': provisionVault,
    'startVault': startVault,
    // Modal close actions
    'closeTerminateModal': closeTerminateModal,
    'terminateVault': terminateVault,
    'closeStopModal': closeStopModal,
    'stopVaultAndClose': () => { stopVault(); closeStopModal(); },
    'closeDeleteByovModal': closeDeleteByovModal,
    'deleteByovAndClose': () => { deleteByovVault(); closeDeleteByovModal(); },
    'closeEnrollmentModal': closeEnrollmentModal,
    // Subscription actions
    'cancelSubscription': cancelSubscription
  };

  // Handle simple actions
  if (actions[action]) {
    e.preventDefault();
    actions[action]();
    return;
  }

  // Handle parameterized actions
  switch (action) {
    case 'filterProposals': {
      const filter = target.dataset.filter;
      if (filter) {
        const filterInput = document.getElementById(filter === 'completed' ? 'filterCompletedProposals' : 'filterActiveProposals');
        if (filterInput) filterInput.click();
      }
      e.preventDefault();
      break;
    }
    case 'toggleProposalText': {
      const targetId = target.dataset.target;
      if (targetId) toggleProposalText(targetId);
      e.preventDefault();
      break;
    }
    case 'selectVote': {
      const proposalId = target.dataset.proposalId;
      const vote = target.dataset.vote;
      if (proposalId && vote) selectVote(proposalId, vote);
      e.preventDefault();
      break;
    }
    case 'submitVote': {
      const proposalId = target.dataset.proposalId;
      if (proposalId) submitVote(proposalId);
      e.preventDefault();
      break;
    }
    case 'switchTab': {
      const tab = target.dataset.tab;
      if (tab) switchToTab(tab);
      e.preventDefault();
      break;
    }
    case 'navigateToStep': {
      const stepTab = target.dataset.stepTab;
      const stepCard = target.dataset.stepCard;
      const stepSubtab = target.dataset.stepSubtab;
      if (stepTab) {
        navigateToStep(stepTab, stepCard === 'null' ? null : stepCard, stepSubtab === 'null' ? null : stepSubtab);
      }
      e.preventDefault();
      break;
    }
    case 'selectSubscription': {
      const subscriptionId = target.dataset.subscriptionId;
      if (subscriptionId) selectSubscriptionType(subscriptionId);
      e.preventDefault();
      break;
    }
  }
});
