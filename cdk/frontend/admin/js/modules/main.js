/**
 * Admin Portal Main Entry Point
 *
 * Orchestrates all modules, handles authentication, tab switching,
 * and event delegation. This file should be loaded with type="module".
 */

// ─────────────────────────────────────────────────────────────────────────────
// Module Imports
// ─────────────────────────────────────────────────────────────────────────────

import {
  config,
  store,
  api,
  showToast,
  signedIn,
  signOut,
  saveTokens,
  idToken,
  accessToken,
  isAdmin,
  isSuperAdmin,
  escapeHtml,
  parseTimestamp,
  debounce,
  showLoadingSkeleton,
  initTheme,
  toggleTheme,
  initViewPreferences,
  toggleView,
  applyView,
  resetIdleTimer,
  clearPasswordFields,
  submitPasswordChange,
  toggleActionDropdown,
  openGenericConfirmModal,
  closeGenericConfirmModal
} from './core.js';

import {
  loadUsers,
  renderUsers,
  renderUsersCards,
  userFilters,
  setupUserBulkActions,
  setupUserEventHandlers,
  bulkApproveRegistrations,
  bulkRejectRegistrations,
  bulkDisableUsers,
  bulkEnableUsers,
  bulkDeleteUsers,
  openComposeEmailModal,
  closeComposeEmailModal,
  sendEmail
} from './users.js';

import {
  loadInvites,
  renderInvites,
  createInvite,
  openCreateInviteModal,
  closeCreateInviteModal,
  bulkExpireInvites,
  bulkDeleteInvites,
  setInviteQuickFilter,
  setupInviteEventHandlers
} from './invites.js';

import {
  loadAdmins,
  loadPendingAdmins,
  renderAdmins,
  addAdmin,
  openAddAdminModal,
  closeAddAdminModal,
  openManageAccessModal,
  closeManageAccessModal,
  openActivityLogModal,
  closeActivityLogModal,
  openChangeAdminTypeModal,
  closeChangeAdminTypeModal,
  handleChangeAdminType,
  handleToggleAdminStatus,
  handleResetAdminPassword,
  handleDeleteAdmin,
  activatePendingAdmin,
  bulkDisableAdmins,
  bulkEnableAdmins,
  setupAdminsEventHandlers
} from './admins.js';

import {
  loadCurrentTerms,
  viewTerms,
  createMembershipTerms,
  openCreateTermsModal,
  closeCreateTermsModal,
  openConfirmTermsModal,
  closeConfirmTermsModal,
  loadSubscriptionTypes,
  toggleSubscriptionType,
  createSubscriptionType,
  openCreateSubscriptionTypeModal,
  closeCreateSubscriptionTypeModal,
  loadAllSubscriptions,
  renderSubscriptions,
  setupMembershipEventHandlers
} from './membership.js';

import {
  loadAllProposalsAdmin,
  renderProposals,
  createProposal,
  openCreateProposalModal,
  closeCreateProposalModal,
  toggleProposalText,
  openProposalAnalytics,
  closeProposalAnalyticsModal,
  setProposalFilter,
  setupProposalEventHandlers
} from './proposals.js';

import {
  loadSystemHealth,
  loadSystemLogs,
  loadSecurityEvents,
  loadRecoveryRequests,
  loadDeletionRequests,
  loadVaultMetrics,
  loadDeployedHandlers,
  loadHandlers,
  setupHandlersEventHandlers
} from './system.js';

import {
  loadServices,
  renderServices,
  openServiceModal,
  closeServiceModal,
  openEditServiceModal,
  openServiceDetails,
  closeServiceDetailsModal,
  editServiceFromDetails,
  saveService,
  toggleServiceStatus,
  openDeleteServiceModal,
  closeDeleteServiceModal,
  deleteService,
  toggleServiceDropdown,
  setServiceStatusFilter,
  setServiceTypeFilter,
  setServiceSearchTerm,
  setupServicesEventHandlers
} from './services.js';

// ─────────────────────────────────────────────────────────────────────────────
// Expose Functions Globally for Inline Handlers (temporary compatibility)
// ─────────────────────────────────────────────────────────────────────────────

// Core
window.toggleTheme = toggleTheme;
window.toggleView = toggleView;
window.signOut = signOut;
window.showToast = showToast;
window.toggleActionDropdown = toggleActionDropdown;

// Users
window.loadUsers = loadUsers;
window.openComposeEmailModal = openComposeEmailModal;
window.closeComposeEmailModal = closeComposeEmailModal;
window.sendEmail = sendEmail;

// Invites
window.loadInvites = loadInvites;
window.createInvite = createInvite;
window.openCreateInviteModal = openCreateInviteModal;
window.closeCreateInviteModal = closeCreateInviteModal;

// Admins
window.loadAdmins = loadAdmins;
window.addAdmin = addAdmin;
window.openAddAdminModal = openAddAdminModal;
window.closeAddAdminModal = closeAddAdminModal;
window.openManageAccessModal = openManageAccessModal;
window.closeManageAccessModal = closeManageAccessModal;
window.openActivityLogModal = openActivityLogModal;
window.closeActivityLogModal = closeActivityLogModal;
window.openChangeAdminTypeModal = openChangeAdminTypeModal;
window.closeChangeAdminTypeModal = closeChangeAdminTypeModal;
window.handleChangeAdminType = handleChangeAdminType;
window.handleToggleAdminStatus = handleToggleAdminStatus;
window.handleResetAdminPassword = handleResetAdminPassword;
window.handleDeleteAdmin = handleDeleteAdmin;

// Membership
window.loadCurrentTerms = loadCurrentTerms;
window.viewTerms = viewTerms;
window.createMembershipTerms = createMembershipTerms;
window.openCreateTermsModal = openCreateTermsModal;
window.closeCreateTermsModal = closeCreateTermsModal;
window.openConfirmTermsModal = openConfirmTermsModal;
window.closeConfirmTermsModal = closeConfirmTermsModal;
window.loadSubscriptionTypes = loadSubscriptionTypes;
window.toggleSubscriptionType = toggleSubscriptionType;
window.createSubscriptionType = createSubscriptionType;
window.openCreateSubscriptionTypeModal = openCreateSubscriptionTypeModal;
window.closeCreateSubscriptionTypeModal = closeCreateSubscriptionTypeModal;
window.loadAllSubscriptions = loadAllSubscriptions;

// Proposals
window.loadAllProposalsAdmin = loadAllProposalsAdmin;
window.createProposal = createProposal;
window.openCreateProposalModal = openCreateProposalModal;
window.closeCreateProposalModal = closeCreateProposalModal;
window.toggleProposalText = toggleProposalText;
window.openProposalAnalytics = openProposalAnalytics;
window.closeProposalAnalyticsModal = closeProposalAnalyticsModal;

// System
window.loadSystemHealth = loadSystemHealth;
window.loadSystemLogs = loadSystemLogs;
window.loadSecurityEvents = loadSecurityEvents;
window.loadRecoveryRequests = loadRecoveryRequests;
window.loadDeletionRequests = loadDeletionRequests;
window.loadVaultMetrics = loadVaultMetrics;
window.loadDeployedHandlers = loadDeployedHandlers;
window.loadHandlers = loadHandlers;

// Services
window.loadServices = loadServices;
window.openServiceModal = openServiceModal;
window.closeServiceModal = closeServiceModal;
window.openEditServiceModal = openEditServiceModal;
window.openServiceDetails = openServiceDetails;
window.closeServiceDetailsModal = closeServiceDetailsModal;
window.editServiceFromDetails = editServiceFromDetails;
window.saveService = saveService;
window.toggleServiceStatus = toggleServiceStatus;
window.openDeleteServiceModal = openDeleteServiceModal;
window.closeDeleteServiceModal = closeDeleteServiceModal;
window.deleteService = deleteService;

// ─────────────────────────────────────────────────────────────────────────────
// Authentication & Initialization
// ─────────────────────────────────────────────────────────────────────────────

function initAuth() {
  // Check for OAuth callback
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');

  if (code) {
    exchangeCodeForTokens(code);
    return;
  }

  // Check existing session
  if (signedIn()) {
    showLoggedInUI();
    loadInitialData();
  } else {
    showLoginUI();
  }
}

async function exchangeCodeForTokens(code) {
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    showToast('Missing PKCE verifier. Please try logging in again.', 'error');
    redirectToLogin();
    return;
  }

  try {
    const tokenUrl = `${config.cognitoDomain}/oauth2/token`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      code: code,
      code_verifier: codeVerifier
    });

    const res = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    if (!res.ok) {
      throw new Error(`Token exchange failed: ${res.status}`);
    }

    const tokens = await res.json();

    // Store tokens using core.js saveTokens for consistency
    saveTokens(tokens);

    // Clean up
    sessionStorage.removeItem('pkce_code_verifier');
    window.history.replaceState({}, document.title, window.location.pathname);

    showLoggedInUI();
    loadInitialData();
  } catch (err) {
    console.error('Token exchange error:', err);
    showToast('Authentication failed. Please try again.', 'error');
    redirectToLogin();
  }
}

function redirectToLogin() {
  // Generate PKCE challenge
  const codeVerifier = generateCodeVerifier();
  sessionStorage.setItem('pkce_code_verifier', codeVerifier);

  generateCodeChallenge(codeVerifier).then(codeChallenge => {
    const authUrl = `${config.cognitoDomain}/oauth2/authorize?` +
      `response_type=code&` +
      `client_id=${config.clientId}&` +
      `redirect_uri=${encodeURIComponent(config.redirectUri)}&` +
      `scope=email+openid+profile&` +
      `code_challenge=${codeChallenge}&` +
      `code_challenge_method=S256`;

    window.location.href = authUrl;
  });
}

function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function showLoginUI() {
  // Show sign-in button, hide logged-in UI
  const signinBtn = document.getElementById('signin');
  const userDropdown = document.getElementById('userDropdownContainer');
  if (signinBtn) signinBtn.style.display = 'inline-block';
  if (userDropdown) userDropdown.style.display = 'none';

  // Hide admin content when not logged in
  document.querySelectorAll('.admin-only').forEach(el => {
    el.style.display = 'none';
  });
}

function showLoggedInUI() {
  // Hide sign-in button, show logged-in UI
  const signinBtn = document.getElementById('signin');
  const userDropdown = document.getElementById('userDropdownContainer');
  if (signinBtn) signinBtn.style.display = 'none';
  if (userDropdown) userDropdown.style.display = 'flex';

  // Show admin content when logged in
  document.querySelectorAll('.admin-only').forEach(el => {
    el.style.display = 'flex';
  });

  // Display user info
  const token = idToken();
  if (token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const userEmail = document.getElementById('userEmail');
      if (userEmail) userEmail.textContent = payload.email || 'Admin';

      // Store admin status
      const groups = payload['cognito:groups'] || [];
      store.isAdmin = groups.includes('admin') || groups.includes('super-admin');
      store.isSuperAdmin = groups.includes('super-admin');
    } catch (e) {
      console.error('Error parsing token:', e);
    }
  }

  // Start idle timer
  resetIdleTimer();
}

function loadInitialData() {
  // Load default tab data (users)
  loadUsers();
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab Switching
// ─────────────────────────────────────────────────────────────────────────────

function setupTabSwitching() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.onclick = () => {
      const target = tab.getAttribute('data-tab');
      const subTab = tab.getAttribute('data-sub-tab');

      // Handle parent tab clicks (expand/collapse)
      if (tab.classList.contains('tab-parent')) {
        handleParentTabClick(tab, target);
        return;
      }

      // Handle child tab clicks (sub-tab switching)
      if (tab.classList.contains('tab-child')) {
        handleChildTabClick(tab, subTab);
        return;
      }

      // Handle regular tab clicks
      handleRegularTabClick(tab, target);
    };
  });
}

function handleParentTabClick(tab, target) {
  const isSubscribers = tab.id === 'subscribersParent';
  const isVoteManagement = tab.id === 'voteManagementParent';
  const isSiteManagement = tab.id === 'siteManagementParent';
  const isAdmin = tab.id === 'adminParent';

  const childrenId = isSubscribers ? 'subscribersChildren' :
                     isVoteManagement ? 'voteManagementChildren' :
                     isSiteManagement ? 'siteManagementChildren' :
                     'adminChildren';

  const children = document.getElementById(childrenId);

  // Toggle expand/collapse
  children.classList.toggle('expanded');
  tab.classList.toggle('expanded');

  // If expanding, collapse others and show default sub-tab
  if (tab.classList.contains('expanded')) {
    collapseOtherParents(tab.id);
    activateParentContent(tab, target, isSubscribers, isVoteManagement, isSiteManagement, isAdmin);
  }
}

function collapseOtherParents(currentId) {
  const parentIds = ['subscribersParent', 'voteManagementParent', 'siteManagementParent', 'adminParent'];
  const childrenIds = ['subscribersChildren', 'voteManagementChildren', 'siteManagementChildren', 'adminChildren'];

  parentIds.forEach((id, i) => {
    if (id !== currentId) {
      const parent = document.getElementById(id);
      const children = document.getElementById(childrenIds[i]);
      if (parent) parent.classList.remove('expanded');
      if (children) children.classList.remove('expanded');
    }
  });
}

function activateParentContent(tab, target, isSubscribers, isVoteManagement, isSiteManagement, isAdminTab) {
  // Remove active from all tabs and tab contents
  document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  // Activate parent tab and content
  tab.classList.add('active');
  document.getElementById(target).classList.add('active');

  // Show default sub-tab
  document.querySelectorAll('.sub-tab-content').forEach(s => s.classList.remove('active'));

  if (isSubscribers) {
    document.getElementById('subscriber-management').classList.add('active');
    document.querySelector('[data-sub-tab="subscriber-management"]')?.classList.add('active');
    loadAllSubscriptions();
  } else if (isVoteManagement) {
    document.getElementById('in-progress').classList.add('active');
    document.querySelector('[data-sub-tab="in-progress"]')?.classList.add('active');
    loadAllProposalsAdmin();
  } else if (isSiteManagement) {
    document.getElementById('system-health').classList.add('active');
    document.querySelector('[data-sub-tab="system-health"]')?.classList.add('active');
    loadSystemHealth();
    loadSystemLogs();
  } else if (isAdminTab) {
    document.getElementById('admin-users').classList.add('active');
    document.querySelector('[data-sub-tab="admin-users"]')?.classList.add('active');
    loadAdmins();
    loadPendingAdmins();
  }
}

function handleChildTabClick(tab, subTab) {
  // Remove active from all child tabs
  document.querySelectorAll('.tab-child').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');

  // Switch sub-tab content
  document.querySelectorAll('.sub-tab-content').forEach(s => s.classList.remove('active'));
  document.getElementById(subTab).classList.add('active');

  // Load data for the sub-tab
  loadSubTabData(subTab);

  // Close sidebar on mobile
  closeSidebarOnMobile();
}

function loadSubTabData(subTab) {
  switch (subTab) {
    case 'admin-users':
      loadAdmins();
      loadPendingAdmins();
      break;
    case 'subscription-types':
      loadSubscriptionTypes();
      break;
    case 'membership-terms':
      loadCurrentTerms();
      break;
    case 'event-handlers':
      loadHandlers();
      break;
    case 'supported-services':
      loadServices();
      break;
    case 'vault-metrics':
      loadVaultMetrics();
      break;
    case 'security-events':
      loadSecurityEvents();
      loadRecoveryRequests();
      loadDeletionRequests();
      break;
  }
}

function handleRegularTabClick(tab, target) {
  // Collapse any expanded parent tabs
  collapseOtherParents(null);

  // Remove active from all tabs and tab contents
  document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  // Activate clicked tab and its content
  tab.classList.add('active');
  document.getElementById(target).classList.add('active');

  // Load data for the tab
  loadTabData(target);

  // Close sidebar on mobile
  closeSidebarOnMobile();
}

function loadTabData(target) {
  switch (target) {
    case 'users':
      loadUsers();
      break;
    case 'invites':
      loadInvites();
      break;
    case 'admins':
      loadAdmins();
      break;
    case 'subscriptions':
      loadAllSubscriptions();
      break;
  }
}

function closeSidebarOnMobile() {
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar')?.classList.add('collapsed');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Delegation for data-action Handlers
// ─────────────────────────────────────────────────────────────────────────────

function setupEventDelegation() {
  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const action = target.dataset.action;

    // Map action names to functions
    const actions = {
      // Core
      'closeGenericConfirmModal': () => closeGenericConfirmModal(false),

      // Admins
      'closeActivityLogModal': closeActivityLogModal,
      'closeAddAdminModal': closeAddAdminModal,
      'closeChangeAdminTypeModal': closeChangeAdminTypeModal,
      'closeManageAccessModal': closeManageAccessModal,
      'handleChangeAdminType': handleChangeAdminType,
      'handleDeleteAdmin': handleDeleteAdmin,
      'handleResetAdminPassword': handleResetAdminPassword,
      'handleToggleAdminStatus': handleToggleAdminStatus,
      'openChangeAdminTypeModal': openChangeAdminTypeModal,

      // Users
      'closeComposeEmailModal': closeComposeEmailModal,

      // Invites
      'closeCreateInviteModal': closeCreateInviteModal,

      // Membership
      'closeConfirmTermsModal': closeConfirmTermsModal,
      'closeCreateSubscriptionTypeModal': closeCreateSubscriptionTypeModal,
      'closeCreateTermsModal': closeCreateTermsModal,

      // Proposals
      'closeCreateProposalModal': closeCreateProposalModal,
      'closeProposalAnalyticsModal': closeProposalAnalyticsModal,

      // Services
      'closeDeleteServiceModal': closeDeleteServiceModal,
      'closeServiceDetailsModal': closeServiceDetailsModal,
      'closeServiceModal': closeServiceModal,
      'service-details': () => {
        const serviceId = target.dataset.serviceId;
        if (serviceId) openServiceDetails(serviceId);
      },
      'service-edit': () => {
        const serviceId = target.dataset.serviceId;
        if (serviceId) openEditServiceModal(serviceId);
      },
      'service-toggle-status': () => {
        const serviceId = target.dataset.serviceId;
        const newStatus = target.dataset.newStatus;
        if (serviceId && newStatus) toggleServiceStatus(serviceId, newStatus);
      },
      'service-delete': () => {
        const serviceId = target.dataset.serviceId;
        if (serviceId) openDeleteServiceModal(serviceId);
      },
      'toggle-service-dropdown': () => {
        toggleServiceDropdown(target, e);
      },

      // CSV Import
      'openCsvImportModal': openCsvImportModal,
      'closeCsvImportModal': closeCsvImportModal,

      'stop-propagation': () => {
        e.stopPropagation();
      }
    };

    if (actions[action]) {
      e.preventDefault();
      actions[action]();
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar and UI Setup
// ─────────────────────────────────────────────────────────────────────────────

function setupSidebar() {
  const sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebarToggle) {
    sidebarToggle.onclick = () => {
      const sidebar = document.getElementById('sidebar');
      sidebar.classList.toggle('collapsed');
      // Use textContent for safe text assignment
      sidebarToggle.textContent = sidebar.classList.contains('collapsed') ? '>' : '<';
    };
  }
}

function setupUserDropdown() {
  const userDropdownBtn = document.querySelector('.user-dropdown-btn');
  const userDropdownMenu = document.getElementById('userDropdownMenu');

  if (userDropdownBtn) {
    userDropdownBtn.onclick = (e) => {
      e.stopPropagation();
      userDropdownMenu.classList.toggle('active');
    };
  }

  // Theme toggle
  const themeToggleBtn = document.getElementById('themeToggle');
  if (themeToggleBtn) {
    themeToggleBtn.onclick = (e) => {
      e.stopPropagation();
      toggleTheme();
    };
  }

  // Close on outside click
  document.addEventListener('click', () => {
    if (userDropdownMenu) userDropdownMenu.classList.remove('active');
    document.querySelectorAll('.action-dropdown-menu.active').forEach(m => m.classList.remove('active'));
  });
}

function setupPasswordModal() {
  const passwordModal = document.getElementById('passwordModal');
  const changePasswordBtn = document.getElementById('changePasswordBtn');
  const closePasswordModal = document.getElementById('closePasswordModal');
  const cancelPasswordChange = document.getElementById('cancelPasswordChange');
  const userDropdownMenu = document.getElementById('userDropdownMenu');

  if (changePasswordBtn) {
    changePasswordBtn.onclick = () => {
      passwordModal.classList.add('active');
      userDropdownMenu.classList.remove('active');
    };
  }

  if (closePasswordModal) {
    closePasswordModal.onclick = () => {
      passwordModal.classList.remove('active');
      clearPasswordFields();
    };
  }

  if (cancelPasswordChange) {
    cancelPasswordChange.onclick = () => {
      passwordModal.classList.remove('active');
      clearPasswordFields();
    };
  }

  if (passwordModal) {
    passwordModal.onclick = (e) => {
      if (e.target === passwordModal) {
        passwordModal.classList.remove('active');
        clearPasswordFields();
      }
    };
  }
}

function setupSignOut() {
  const signoutBtn = document.getElementById('signout');
  if (signoutBtn) {
    signoutBtn.onclick = (e) => {
      e.stopPropagation();
      signOut();
    };
  }
}

function setupLoginButton() {
  // Support both 'signin' (HTML) and 'loginBtn' (legacy) IDs
  const loginBtn = document.getElementById('signin') || document.getElementById('loginBtn');
  if (loginBtn) {
    loginBtn.onclick = redirectToLogin;
  }
}

function setupIdleTracking() {
  // Reset idle timer on user activity
  ['click', 'keypress', 'mousemove', 'scroll'].forEach(event => {
    document.addEventListener(event, () => {
      if (signedIn()) resetIdleTimer();
    }, { passive: true });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DOMContentLoaded - Initialize Everything
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Initialize theme and preferences
  initTheme();
  initViewPreferences();

  // Setup UI components
  setupSidebar();
  setupUserDropdown();
  setupPasswordModal();
  setupSignOut();
  setupLoginButton();
  setupIdleTracking();

  // Setup tab navigation
  setupTabSwitching();

  // Setup event delegation
  setupEventDelegation();

  // Setup module-specific event handlers
  setupUserEventHandlers();
  setupInviteEventHandlers();
  setupAdminsEventHandlers();
  setupMembershipEventHandlers();
  setupProposalEventHandlers();
  setupServicesEventHandlers();
  setupHandlersEventHandlers();
  setupWaitlistEventHandlers();

  // Initialize authentication
  initAuth();
});

// ─────────────────────────────────────────────────────────────────────────────
// Waitlist Event Handlers
// ─────────────────────────────────────────────────────────────────────────────

// Waitlist state
let waitlistQuickFilter = 'pending';
let waitlistData = [];
let waitlistPaginationState = { currentPage: 1, perPage: 10, search: '' };

function setupWaitlistEventHandlers() {
  // Waitlist filter buttons
  const pendingBtn = document.getElementById('quickFilterPending');
  const invitedBtn = document.getElementById('waitlistFilterInvited');
  const rejectedBtn = document.getElementById('quickFilterRejected');

  if (pendingBtn) {
    pendingBtn.onclick = () => {
      waitlistQuickFilter = 'pending';
      document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
      pendingBtn.classList.add('active');
      waitlistPaginationState.currentPage = 1;
      renderWaitlist();
    };
  }

  if (invitedBtn) {
    invitedBtn.onclick = () => {
      waitlistQuickFilter = 'invited';
      document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
      invitedBtn.classList.add('active');
      waitlistPaginationState.currentPage = 1;
      renderWaitlist();
    };
  }

  if (rejectedBtn) {
    rejectedBtn.onclick = () => {
      waitlistQuickFilter = 'rejected';
      document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
      rejectedBtn.classList.add('active');
      waitlistPaginationState.currentPage = 1;
      renderWaitlist();
    };
  }

  // Waitlist search
  const searchInput = document.getElementById('waitlistSearch');
  if (searchInput) {
    searchInput.oninput = (e) => {
      waitlistPaginationState.search = e.target.value;
      waitlistPaginationState.currentPage = 1;
      renderWaitlist();
    };
  }

  // Select all waitlist checkbox
  const selectAll = document.getElementById('selectAllWaitlist');
  if (selectAll) {
    selectAll.onchange = () => {
      document.querySelectorAll('.waitlist-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
      });
    };
  }
}

async function loadWaitlist(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) waitlistPaginationState.currentPage = 1;

  const tbody = document.querySelector('#waitlistTable tbody');
  if (!tbody) return;

  showLoadingSkeleton('waitlistTable');

  try {
    const data = await api('/admin/waitlist');
    waitlistData = data.waitlist || [];
    renderWaitlist();
  } catch (e) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'muted';
    td.textContent = 'Error: ' + (e.message || String(e));
    tr.appendChild(td);
    tbody.replaceChildren(tr);
  }
}

function renderWaitlist() {
  const tbody = document.querySelector('#waitlistTable tbody');
  if (!tbody) return;

  tbody.replaceChildren();

  // Apply filters
  let filtered = waitlistData.filter(w => {
    // Quick filter
    if (waitlistQuickFilter === 'pending' && w.status !== 'pending' && w.status) return false;
    if (waitlistQuickFilter === 'invited' && w.status !== 'invited') return false;
    if (waitlistQuickFilter === 'rejected' && w.status !== 'rejected') return false;

    // Search filter
    const search = waitlistPaginationState.search.toLowerCase();
    if (search) {
      const searchable = [w.first_name, w.last_name, w.email].filter(Boolean).join(' ').toLowerCase();
      if (!searchable.includes(search)) return false;
    }
    return true;
  });

  // Update counts
  const pendingCount = waitlistData.filter(w => !w.status || w.status === 'pending').length;
  const invitedCount = waitlistData.filter(w => w.status === 'invited').length;
  const rejectedCount = waitlistData.filter(w => w.status === 'rejected').length;

  const countEls = {
    pending: document.getElementById('pendingWaitlistCount'),
    invited: document.getElementById('invitedWaitlistCount'),
    rejected: document.getElementById('rejectedWaitlistCount')
  };
  if (countEls.pending) countEls.pending.textContent = pendingCount;
  if (countEls.invited) countEls.invited.textContent = invitedCount;
  if (countEls.rejected) countEls.rejected.textContent = rejectedCount;

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.style.cssText = 'text-align:center;padding:40px;';
    td.textContent = 'No waitlist entries found';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  // Paginate
  const start = (waitlistPaginationState.currentPage - 1) * waitlistPaginationState.perPage;
  const page = filtered.slice(start, start + waitlistPaginationState.perPage);

  page.forEach(w => {
    const tr = document.createElement('tr');
    const name = `${w.first_name || ''} ${w.last_name || ''}`.trim();

    // Checkbox
    const td1 = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'waitlist-checkbox';
    cb.dataset.email = w.email;
    td1.appendChild(cb);

    // Name
    const td2 = document.createElement('td');
    td2.textContent = name || '—';

    // Email
    const td3 = document.createElement('td');
    td3.textContent = w.email;

    // Status badge
    const td4 = document.createElement('td');
    const badge = document.createElement('span');
    badge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;color:#fff;';
    const status = w.status || 'pending';
    const colors = { pending: '#3b82f6', invited: '#10b981', rejected: '#ef4444' };
    badge.style.background = colors[status] || '#6b7280';
    badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    td4.appendChild(badge);

    // Date
    const td5 = document.createElement('td');
    td5.textContent = w.created_at ? new Date(w.created_at).toLocaleDateString() : '—';

    tr.append(td1, td2, td3, td4, td5);
    tbody.appendChild(tr);
  });
}

// Expose waitlist functions globally
window.loadWaitlist = loadWaitlist;

// ─────────────────────────────────────────────────────────────────────────────
// CSV Batch Import
// ─────────────────────────────────────────────────────────────────────────────

let csvData = [];

function openCsvImportModal() {
  const modal = document.getElementById('csvImportModal');
  if (modal) {
    modal.classList.add('active');
    resetCsvImport();
  }
}

function closeCsvImportModal() {
  const modal = document.getElementById('csvImportModal');
  if (modal) modal.classList.remove('active');
  resetCsvImport();
}

function resetCsvImport() {
  csvData = [];
  const fileInput = document.getElementById('csvFileInput');
  const previewSection = document.getElementById('csvPreviewSection');
  const progressSection = document.getElementById('importProgressSection');
  const startBtn = document.getElementById('startImportBtn');
  const recordCount = document.getElementById('csvRecordCount');

  if (fileInput) fileInput.value = '';
  if (previewSection) previewSection.style.display = 'none';
  if (progressSection) progressSection.style.display = 'none';
  if (startBtn) startBtn.disabled = true;
  if (recordCount) recordCount.textContent = '0';
}

function handleCsvFile(input) {
  const file = input.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const text = e.target.result;
    parseCsvData(text);
  };
  reader.readAsText(file);
}

function parseCsvData(text) {
  const lines = text.split('\n').filter(line => line.trim());
  if (lines.length < 2) {
    showToast('CSV file must have a header row and at least one data row', 'error');
    return;
  }

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const emailIndex = headers.findIndex(h => h === 'email');
  const firstNameIndex = headers.findIndex(h => h === 'first_name' || h === 'firstname');
  const lastNameIndex = headers.findIndex(h => h === 'last_name' || h === 'lastname');

  if (emailIndex === -1) {
    showToast('CSV must have an "email" column', 'error');
    return;
  }

  csvData = [];
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim());
    const email = values[emailIndex];
    if (email && email.includes('@')) {
      csvData.push({
        email,
        first_name: firstNameIndex >= 0 ? values[firstNameIndex] : '',
        last_name: lastNameIndex >= 0 ? values[lastNameIndex] : ''
      });
    }
  }

  const recordCount = document.getElementById('csvRecordCount');
  const previewSection = document.getElementById('csvPreviewSection');
  const startBtn = document.getElementById('startImportBtn');
  const previewBody = document.getElementById('csvPreviewBody');

  if (recordCount) recordCount.textContent = csvData.length;
  if (previewSection) previewSection.style.display = 'block';
  if (startBtn) startBtn.disabled = csvData.length === 0;

  // Show preview (first 5 rows) using safe DOM methods
  if (previewBody) {
    previewBody.replaceChildren();
    csvData.slice(0, 5).forEach(row => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      td1.textContent = row.email;
      const td2 = document.createElement('td');
      td2.textContent = row.first_name;
      const td3 = document.createElement('td');
      td3.textContent = row.last_name;
      tr.append(td1, td2, td3);
      previewBody.appendChild(tr);
    });
  }
}

async function startCsvImport() {
  if (csvData.length === 0) return;

  const progressSection = document.getElementById('importProgressSection');
  const progressBar = document.getElementById('importProgressBar');
  const progressText = document.getElementById('importProgressText');
  const startBtn = document.getElementById('startImportBtn');

  if (progressSection) progressSection.style.display = 'block';
  if (startBtn) startBtn.disabled = true;

  let success = 0;
  let failed = 0;

  for (let i = 0; i < csvData.length; i++) {
    try {
      await api('/admin/waitlist', {
        method: 'POST',
        body: JSON.stringify(csvData[i])
      });
      success++;
    } catch (e) {
      failed++;
    }

    const progress = Math.round(((i + 1) / csvData.length) * 100);
    if (progressBar) progressBar.style.width = progress + '%';
    if (progressText) progressText.textContent = `${i + 1} of ${csvData.length} (${success} success, ${failed} failed)`;
  }

  showToast(`Import complete: ${success} added, ${failed} failed`, success > 0 ? 'success' : 'error');
  if (startBtn) startBtn.disabled = false;

  // Refresh waitlist after import
  loadWaitlist();
}

// Expose CSV import functions globally
window.openCsvImportModal = openCsvImportModal;
window.closeCsvImportModal = closeCsvImportModal;
window.handleCsvFile = handleCsvFile;
window.startCsvImport = startCsvImport;

// ─────────────────────────────────────────────────────────────────────────────
// Export for Testing (optional)
// ─────────────────────────────────────────────────────────────────────────────

export {
  initAuth,
  redirectToLogin,
  loadInitialData
};
