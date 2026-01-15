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

    // Store tokens
    localStorage.setItem('id_token', tokens.id_token);
    localStorage.setItem('access_token', tokens.access_token);
    if (tokens.refresh_token) {
      localStorage.setItem('refresh_token', tokens.refresh_token);
    }

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
  document.getElementById('loginSection').style.display = 'flex';
  document.getElementById('appContainer').style.display = 'none';
}

function showLoggedInUI() {
  document.getElementById('loginSection').style.display = 'none';
  document.getElementById('appContainer').style.display = 'flex';

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
  const loginBtn = document.getElementById('loginBtn');
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
  setupInviteEventHandlers();
  setupAdminsEventHandlers();
  setupMembershipEventHandlers();
  setupProposalEventHandlers();
  setupServicesEventHandlers();
  setupHandlersEventHandlers();

  // Initialize authentication
  initAuth();
});

// ─────────────────────────────────────────────────────────────────────────────
// Export for Testing (optional)
// ─────────────────────────────────────────────────────────────────────────────

export {
  initAuth,
  redirectToLogin,
  loadInitialData
};
