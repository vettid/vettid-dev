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
  setupAdminsEventHandlers,
  setShowConfirm
} from './admins.js';

import {
  loadCurrentTerms,
  viewTerms,
  regenerateTermsPdf,
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
  setupMembershipEventHandlers,
  updateSubscriptionAnalytics
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
  setupHandlersEventHandlers,
  loadAllNotifications,
  loadNotifications,
  openAddNotificationModal,
  closeSelectNotificationAdminModal,
  removeNotification,
  setupNotificationEventHandlers
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

import {
  loadHelpRequests,
  renderHelpRequests,
  openHelpDetailModal,
  closeHelpDetailModal,
  saveHelpRequest,
  setHelpQuickFilter,
  setupHelpRequestsEventHandlers
} from './help-requests.js';

// ─────────────────────────────────────────────────────────────────────────────
// Modal Helpers
// ─────────────────────────────────────────────────────────────────────────────

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('active');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('active');
}

// ─────────────────────────────────────────────────────────────────────────────
// Date/Time Picker Initialization (Flatpickr)
// ─────────────────────────────────────────────────────────────────────────────

function setupDateTimePickers() {
  // Check if flatpickr is loaded
  if (typeof flatpickr === 'undefined') {
    console.warn('Flatpickr not loaded, date pickers will not be available');
    return;
  }

  const isDarkTheme = () => document.documentElement.getAttribute('data-theme') !== 'light';

  // Apply theme styles to flatpickr calendar
  const applyFlatpickrTheme = (instance) => {
    const cal = instance.calendarContainer;
    if (!cal) return;

    if (!isDarkTheme()) {
      // Light theme styles
      cal.style.setProperty('background', '#ffffff', 'important');
      cal.style.setProperty('border', '1px solid #d1d5db', 'important');
      cal.style.setProperty('box-shadow', '0 4px 16px rgba(0,0,0,0.15)', 'important');

      const months = cal.querySelector('.flatpickr-months');
      if (months) {
        months.style.setProperty('background', 'linear-gradient(135deg, #d4a012 0%, #b8860b 100%)', 'important');
        months.style.setProperty('border-bottom', '1px solid #b8860b', 'important');
        months.style.setProperty('border-radius', '4px 4px 0 0', 'important');
      }

      cal.querySelectorAll('.flatpickr-month, .flatpickr-current-month, .cur-year').forEach(el => {
        el.style.setProperty('color', '#000', 'important');
        el.style.setProperty('background', 'transparent', 'important');
      });

      cal.querySelectorAll('.flatpickr-day').forEach(el => {
        el.style.setProperty('color', '#1f2937', 'important');
      });
    } else {
      // Dark theme styles
      cal.style.setProperty('background', '#1a1a2e', 'important');
      cal.style.setProperty('border', '1px solid #3b3b5c', 'important');
      cal.style.setProperty('box-shadow', '0 4px 16px rgba(0,0,0,0.4)', 'important');

      const months = cal.querySelector('.flatpickr-months');
      if (months) {
        months.style.setProperty('background', 'linear-gradient(135deg, #d4a012 0%, #b8860b 100%)', 'important');
        months.style.setProperty('border-bottom', '1px solid #b8860b', 'important');
        months.style.setProperty('border-radius', '4px 4px 0 0', 'important');
      }

      cal.querySelectorAll('.flatpickr-month, .flatpickr-current-month, .cur-year').forEach(el => {
        el.style.setProperty('color', '#000', 'important');
        el.style.setProperty('background', 'transparent', 'important');
      });

      const weekdays = cal.querySelector('.flatpickr-weekdays');
      if (weekdays) {
        weekdays.style.setProperty('background', '#2a2a3e', 'important');
      }
      cal.querySelectorAll('.flatpickr-weekday').forEach(el => {
        el.style.setProperty('color', '#9ca3af', 'important');
        el.style.setProperty('background', 'transparent', 'important');
      });

      cal.querySelectorAll('.flatpickr-day').forEach(el => {
        el.style.setProperty('color', '#e5e7eb', 'important');
      });
    }
  };

  // Common Flatpickr config
  const baseConfig = {
    allowInput: true,
    animate: true,
    onReady: function(selectedDates, dateStr, instance) {
      applyFlatpickrTheme(instance);
    },
    onOpen: function(selectedDates, dateStr, instance) {
      applyFlatpickrTheme(instance);
    },
  };

  // DateTime picker for invite expiry
  if (document.getElementById('expiresAt')) {
    flatpickr('#expiresAt', {
      ...baseConfig,
      enableTime: true,
      dateFormat: 'Y-m-d H:i',
      time_24hr: true,
      minDate: 'today'
    });
  }

  // DateTime pickers for proposal dates
  if (document.getElementById('proposalOpenDate')) {
    flatpickr('#proposalOpenDate', {
      ...baseConfig,
      enableTime: true,
      dateFormat: 'Y-m-d H:i',
      time_24hr: true,
      minDate: 'today'
    });
  }

  if (document.getElementById('proposalCloseDate')) {
    flatpickr('#proposalCloseDate', {
      ...baseConfig,
      enableTime: true,
      dateFormat: 'Y-m-d H:i',
      time_24hr: true,
      minDate: 'today'
    });
  }
}

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

// Help Requests
window.loadHelpRequests = loadHelpRequests;
window.openHelpDetailModal = openHelpDetailModal;
window.closeHelpDetailModal = closeHelpDetailModal;
window.saveHelpRequest = saveHelpRequest;

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
  // Load data for the currently active tab
  const activeTab = document.querySelector('.tab.active:not(.tab-child)');
  const activeTarget = activeTab?.getAttribute('data-tab');
  if (activeTarget) {
    loadTabData(activeTarget);
  } else {
    // Fallback to waitlist (default tab)
    loadWaitlist();
  }
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
    case 'subscription-analytics':
      // Analytics uses data from subscriptions, use cached data if available
      loadAllSubscriptions(false).then(() => updateSubscriptionAnalytics());
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
    case 'notifications':
      loadAllNotifications();
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
    case 'waitlist':
      loadWaitlist();
      break;
    case 'help-requests':
      loadHelpRequests();
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
      'admin-manage': () => {
        const email = target.dataset.email;
        const name = target.dataset.name;
        const enabled = target.dataset.enabled === 'true';
        const adminType = target.dataset.adminType;
        if (email) openManageAccessModal(email, name, enabled, adminType);
      },
      'admin-activity': () => {
        const email = target.dataset.email;
        const name = target.dataset.name;
        if (email) openActivityLogModal(email, name);
      },

      // Users
      'closeComposeEmailModal': closeComposeEmailModal,

      // Invites
      'closeCreateInviteModal': closeCreateInviteModal,

      // Membership
      'closeConfirmTermsModal': closeConfirmTermsModal,
      'closeCreateSubscriptionTypeModal': closeCreateSubscriptionTypeModal,
      'closeCreateTermsModal': closeCreateTermsModal,
      'view-terms': () => {
        const versionId = target.dataset.versionId;
        if (versionId) viewTerms(versionId, target);
      },
      'regenerate-terms-pdf': () => {
        const versionId = target.dataset.versionId;
        if (versionId) regenerateTermsPdf(versionId, target);
      },

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
      'toggle-subscription-type': () => {
        const typeId = target.dataset.typeId;
        // Handle boolean, string 'true'/'TRUE', or any truthy value
        const isEnabledStr = String(target.dataset.isEnabled).toLowerCase();
        const isEnabled = isEnabledStr === 'true';
        if (typeId) toggleSubscriptionType(typeId, isEnabled);
      },

      // CSV Import
      'openCsvImportModal': openCsvImportModal,
      'closeCsvImportModal': closeCsvImportModal,

      // Notifications
      'remove-notification': () => {
        const type = target.dataset.type;
        const email = target.dataset.email;
        if (type && email) removeNotification(type, email);
      },
      'closeSelectNotificationAdminModal': closeSelectNotificationAdminModal,

      'stop-propagation': () => {
        e.stopPropagation();
      }
    };

    if (actions[action]) {
      e.preventDefault();
      actions[action]();
    }
  });

  // Event delegation for proposal tile buttons
  document.addEventListener('click', (e) => {
    // Handle "View Proposal" toggle buttons
    const toggleBtn = e.target.closest('[data-toggle-proposal]');
    if (toggleBtn) {
      const proposalId = toggleBtn.getAttribute('data-toggle-proposal');
      toggleProposalText(proposalId);
      return;
    }

    // Handle "View Analytics" buttons
    const analyticsBtn = e.target.closest('[data-analytics-proposal]');
    if (analyticsBtn) {
      const proposalId = analyticsBtn.getAttribute('data-analytics-proposal');
      const title = analyticsBtn.getAttribute('data-analytics-title') || 'Untitled Proposal';
      const status = analyticsBtn.getAttribute('data-analytics-status') || 'active';
      openProposalAnalytics(proposalId, title, status);
      return;
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
// Communications / Email Functions
// ─────────────────────────────────────────────────────────────────────────────

async function loadSentEmails() {
  if (!signedIn()) return;

  const list = document.getElementById('sentEmailsList');
  if (!list) return;

  // Show loading
  list.replaceChildren();
  const loadingP = document.createElement('p');
  loadingP.className = 'muted';
  loadingP.style.cssText = 'text-align:center;padding:20px;';
  loadingP.textContent = 'Loading sent emails...';
  list.appendChild(loadingP);

  try {
    const emails = await api('/admin/sent-emails');

    list.replaceChildren();

    if (!emails || emails.length === 0) {
      const emptyP = document.createElement('p');
      emptyP.className = 'muted';
      emptyP.style.cssText = 'text-align:center;padding:20px;';
      emptyP.textContent = 'No emails sent yet';
      list.appendChild(emptyP);
      return;
    }

    // Display emails (newest first) using safe DOM methods
    emails.forEach(email => {
      const sentDate = new Date(email.sent_at).toLocaleString();
      const recipientLabel = {
        'waitlist': 'Waitlisted Users',
        'registered': 'Registered Users',
        'members': 'Members',
        'subscribers': 'Subscribers'
      }[email.recipient_type] || email.recipient_type;

      const card = document.createElement('div');
      card.style.cssText = 'background:var(--bg-input);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;';

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:8px;';

      const info = document.createElement('div');
      info.style.cssText = 'flex:1;min-width:200px;';

      const title = document.createElement('h4');
      title.style.cssText = 'margin:0 0 4px 0;font-size:1rem;';
      title.textContent = email.subject;

      const recipient = document.createElement('p');
      recipient.className = 'muted';
      recipient.style.cssText = 'font-size:0.85rem;margin:0;';
      recipient.textContent = 'To: ';
      const recipientStrong = document.createElement('strong');
      recipientStrong.textContent = recipientLabel;
      recipient.appendChild(recipientStrong);

      info.append(title, recipient);

      const badge = document.createElement('span');
      badge.style.cssText = 'background:#10b981;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.75rem;font-weight:600;';
      badge.textContent = `${email.recipient_count || 0} recipients`;

      header.append(info, badge);

      const meta = document.createElement('div');
      meta.style.cssText = 'font-size:0.85rem;color:var(--gray);margin-bottom:8px;';
      meta.textContent = `Sent: ${sentDate} | By: ${email.sent_by || 'Unknown'}`;

      const details = document.createElement('details');
      details.style.marginTop = '12px';

      const summary = document.createElement('summary');
      summary.style.cssText = 'cursor:pointer;color:var(--accent);font-size:0.9rem;font-weight:600;';
      summary.textContent = 'View Message';

      const content = document.createElement('div');
      content.style.cssText = 'margin-top:12px;padding:12px;background:var(--bg-card);border-radius:4px;border:1px solid var(--border);font-size:0.9rem;max-height:300px;overflow-y:auto;white-space:pre-wrap;';
      content.textContent = email.body_text || email.body_html?.replace(/<[^>]*>/g, '') || '';

      details.append(summary, content);
      card.append(header, meta, details);
      list.appendChild(card);
    });

  } catch (err) {
    console.error('Error loading sent emails:', err);
    list.replaceChildren();
    const errorP = document.createElement('p');
    errorP.className = 'muted';
    errorP.style.cssText = 'text-align:center;padding:20px;color:var(--error);';
    errorP.textContent = 'Error loading sent emails. Please try again.';
    list.appendChild(errorP);
  }
}

// Load combined broadcast history (emails + vault broadcasts)
async function loadBroadcastHistory() {
  if (!signedIn()) return;

  const container = document.getElementById('broadcastHistoryList');
  if (!container) return;

  const filter = document.getElementById('historyTypeFilter')?.value || 'all';

  // Show loading
  container.replaceChildren();
  const loadingDiv = document.createElement('div');
  loadingDiv.style.cssText = 'padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);';
  loadingDiv.textContent = 'Loading...';
  container.appendChild(loadingDiv);

  try {
    // Fetch vault broadcasts
    let vaultBroadcasts = [];
    if (filter === 'all' || filter === 'vault') {
      try {
        const vaultData = await api('/admin/broadcasts');
        vaultBroadcasts = (vaultData.broadcasts || []).map(b => ({
          ...b,
          source: 'vault',
          sent_at: b.sent_at
        }));
      } catch (e) {
        console.log('No vault broadcasts or error:', e.message);
      }
    }

    // Fetch email broadcasts
    let emailBroadcasts = [];
    if (filter === 'all' || filter === 'email') {
      try {
        const emailData = await api('/admin/sent-emails');
        const emailArray = Array.isArray(emailData) ? emailData : (emailData.emails || []);
        emailBroadcasts = emailArray.slice(0, 50).map(e => ({
          broadcast_id: e.email_id,
          type: 'email',
          priority: 'normal',
          title: e.subject,
          message: e.body_preview || (e.body_text || '').substring(0, 100),
          sent_at: e.sent_at,
          sent_by: e.sent_by,
          source: 'email',
          recipient_count: e.recipient_count
        }));
      } catch (e) {
        console.log('No emails or error:', e.message);
      }
    }

    // Combine and sort by sent_at
    const allBroadcasts = [...vaultBroadcasts, ...emailBroadcasts].sort((a, b) => {
      return new Date(b.sent_at).getTime() - new Date(a.sent_at).getTime();
    });

    container.replaceChildren();

    if (allBroadcasts.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.style.cssText = 'padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);';
      emptyDiv.textContent = 'No broadcasts found.';
      container.appendChild(emptyDiv);
      return;
    }

    // Render broadcasts
    allBroadcasts.slice(0, 50).forEach(b => {
      const isVault = b.source === 'vault';
      const typeColor = b.type === 'security_alert' ? '#ef4444' :
                        b.type === 'system_announcement' ? '#3b82f6' :
                        b.type === 'admin_message' ? '#10b981' : '#6b7280';

      const card = document.createElement('div');
      card.style.cssText = `padding:16px;background:#050505;border-radius:8px;border-left:4px solid ${typeColor};`;

      // Header row
      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;align-items:start;gap:12px;margin-bottom:8px;';

      const titleWrap = document.createElement('div');
      titleWrap.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap;';

      // Source icon
      const sourceIcon = document.createElement('span');
      sourceIcon.style.color = typeColor;
      sourceIcon.innerHTML = isVault ?
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>' :
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>';
      titleWrap.appendChild(sourceIcon);

      // Title
      const titleSpan = document.createElement('span');
      titleSpan.style.cssText = 'font-weight:600;color:var(--text);';
      titleSpan.textContent = b.title || 'Untitled';
      titleWrap.appendChild(titleSpan);

      // Priority badge
      if (b.priority === 'critical' || b.priority === 'high') {
        const priorityBadge = document.createElement('span');
        priorityBadge.style.cssText = b.priority === 'critical' ?
          'background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem;' :
          'background:#f59e0b;color:#000;padding:2px 8px;border-radius:4px;font-size:0.7rem;';
        priorityBadge.textContent = b.priority.toUpperCase();
        titleWrap.appendChild(priorityBadge);
      }

      // Status badge
      const statusBadge = document.createElement('span');
      statusBadge.style.cssText = 'background:#10b98122;color:#10b981;padding:2px 8px;border-radius:4px;font-size:0.7rem;';
      statusBadge.textContent = isVault ? (b.delivery_status || 'sent') : 'Sent';
      titleWrap.appendChild(statusBadge);

      header.appendChild(titleWrap);

      // Timestamp
      const timestamp = document.createElement('span');
      timestamp.style.cssText = 'color:var(--gray);font-size:0.8rem;white-space:nowrap;';
      timestamp.textContent = b.sent_at ? new Date(b.sent_at).toLocaleString() : '—';
      header.appendChild(timestamp);

      card.appendChild(header);

      // Message preview
      const messageP = document.createElement('p');
      messageP.style.cssText = 'margin:0 0 8px 0;color:var(--gray);font-size:0.9rem;line-height:1.5;';
      const msgText = b.message || '';
      messageP.textContent = msgText.length > 200 ? msgText.substring(0, 200) + '...' : msgText;
      card.appendChild(messageP);

      // Meta info
      const meta = document.createElement('div');
      meta.style.cssText = 'display:flex;gap:16px;color:var(--gray);font-size:0.8rem;flex-wrap:wrap;';

      const typeSpan = document.createElement('span');
      typeSpan.textContent = 'Type: ';
      const typeValue = document.createElement('span');
      typeValue.style.color = typeColor;
      typeValue.textContent = (b.type || 'email').replace('_', ' ');
      typeSpan.appendChild(typeValue);
      meta.appendChild(typeSpan);

      const bySpan = document.createElement('span');
      bySpan.textContent = `By: ${b.sent_by || '—'}`;
      meta.appendChild(bySpan);

      if (b.recipient_count) {
        const recipSpan = document.createElement('span');
        recipSpan.textContent = `Recipients: ${b.recipient_count}`;
        meta.appendChild(recipSpan);
      }

      card.appendChild(meta);
      container.appendChild(card);
    });

  } catch (e) {
    console.error('Error loading broadcast history:', e);
    container.replaceChildren();
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'padding:20px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;';
    errorDiv.textContent = 'Error loading history: ' + (e.message || e);
    container.appendChild(errorDiv);
  }
}

async function sendBulkEmail() {
  const recipientType = document.getElementById('emailRecipientType')?.value;
  const subject = document.getElementById('emailSubject')?.value.trim();
  const body = document.getElementById('emailBody')?.value.trim();

  // Validation
  if (!recipientType) {
    showToast('Please select a recipient group', 'error');
    return;
  }
  if (!subject) {
    showToast('Please enter an email subject', 'error');
    return;
  }
  if (!body) {
    showToast('Please enter an email message', 'error');
    return;
  }

  // Confirm before sending
  const recipientLabel = {
    'waitlist': 'all waitlisted users',
    'registered': 'all registered users',
    'members': 'all members',
    'subscribers': 'all subscribers'
  }[recipientType];

  const confirmed = await openGenericConfirmModal(
    'Send Bulk Email',
    `Send this email to ${recipientLabel}? This action cannot be undone.`,
    'Send Email',
    'Cancel',
    false
  );
  if (!confirmed) return;

  const btn = document.getElementById('sendBulkEmail');
  const originalText = btn?.textContent || 'Send';
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Sending...';
  }

  try {
    const data = await api('/admin/send-bulk-email', {
      method: 'POST',
      body: JSON.stringify({
        recipient_type: recipientType,
        subject,
        body_html: body,
        body_text: body.replace(/<[^>]*>/g, '') // Strip HTML for text version
      })
    });

    showToast(`Email sent successfully to ${data.recipient_count || 0} recipients!`, 'success');
    closeComposeEmailModal();
    // Refresh history if that panel is visible
    if (document.getElementById('broadcast-history-panel')?.style.display !== 'none') {
      await loadBroadcastHistory();
    }

  } catch (err) {
    console.error('Error sending email:', err);
    showToast(err.message || 'Failed to send email', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  }
}

function setupCommunicationsTabSwitching() {
  // Communications sub-tab switching (Email Broadcast / Vault Broadcast / History)
  document.querySelectorAll('.comm-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      // Update active tab styling
      document.querySelectorAll('.comm-tab').forEach(t => {
        t.classList.remove('active');
        t.style.background = '#333';
      });
      tab.classList.add('active');
      tab.style.background = 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)';

      // Show correct panel
      const targetPanel = tab.getAttribute('data-comm-tab');
      document.querySelectorAll('.comm-panel').forEach(p => p.style.display = 'none');
      const panel = document.getElementById(`${targetPanel}-panel`);
      if (panel) panel.style.display = 'block';

      // Load data for history panel
      if (targetPanel === 'broadcast-history') {
        loadBroadcastHistory();
      }
    });
  });

  // Compose email modal - sendBulkEmail button
  // Note: openComposeEmailBtn handler is set in users.js setupUserEventHandlers
  document.getElementById('sendBulkEmail')?.addEventListener('click', sendBulkEmail);

  // Broadcast history refresh and filter
  document.getElementById('refreshBroadcastHistory')?.addEventListener('click', loadBroadcastHistory);
  document.getElementById('historyTypeFilter')?.addEventListener('change', loadBroadcastHistory);

  // Close compose modal on data-action
  document.querySelectorAll('[data-action="closeComposeEmailModal"]').forEach(el => {
    el.addEventListener('click', closeComposeEmailModal);
  });

  // Broadcast type description updates
  const broadcastType = document.getElementById('broadcastType');
  if (broadcastType) {
    const descriptions = {
      system_announcement: 'Maintenance notices, new features, terms updates',
      security_alert: 'Security incidents, password resets, suspicious activity',
      admin_message: 'Custom messages from administrators'
    };
    broadcastType.onchange = () => {
      const descEl = document.getElementById('broadcastTypeDesc');
      if (descEl) descEl.textContent = descriptions[broadcastType.value] || '';
    };
  }
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

  // Wire up showConfirm for modular admin code (uses openGenericConfirmModal from core.js)
  setShowConfirm(openGenericConfirmModal);

  // Setup module-specific event handlers
  setupUserEventHandlers();
  setupInviteEventHandlers();
  setupAdminsEventHandlers();
  setupMembershipEventHandlers();
  setupProposalEventHandlers();
  setupServicesEventHandlers();
  setupHandlersEventHandlers();
  setupNotificationEventHandlers();
  setupWaitlistEventHandlers();
  setupHelpRequestsEventHandlers();
  setupCommunicationsTabSwitching();

  // Initialize date/time pickers
  setupDateTimePickers();

  // Setup refresh buttons
  setupRefreshButtons();

  // Initialize authentication
  initAuth();
});

// ─────────────────────────────────────────────────────────────────────────────
// Refresh Button Handlers
// ─────────────────────────────────────────────────────────────────────────────

function setupRefreshButtons() {
  // Users refresh
  const refreshUsers = document.getElementById('refreshUsers');
  if (refreshUsers) {
    refreshUsers.onclick = () => {
      store.users = []; // Clear cache to force refetch
      loadUsers(true);
    };
  }

  // Invites refresh
  const refreshInvites = document.getElementById('refreshInvites');
  if (refreshInvites) {
    refreshInvites.onclick = () => {
      store.invites = []; // Clear cache to force refetch
      loadInvites(true);
    };
  }

  // Admins refresh
  const refreshAdmins = document.getElementById('refreshAdmins');
  if (refreshAdmins) {
    refreshAdmins.onclick = () => {
      store.admins = []; // Clear cache to force refetch
      store.pendingAdmins = [];
      loadAdmins(true);
      loadPendingAdmins();
    };
  }

  // Subscriptions refresh
  const refreshSubscriptions = document.getElementById('refreshSubscriptions');
  if (refreshSubscriptions) {
    refreshSubscriptions.onclick = () => {
      store.subscriptions = []; // Clear cache to force refetch
      loadAllSubscriptions(true);
    };
  }

  // Subscription Types refresh
  const refreshSubTypes = document.getElementById('refreshSubTypes');
  if (refreshSubTypes) {
    refreshSubTypes.onclick = () => {
      store.subscriptionTypes = []; // Clear cache to force refetch
      loadSubscriptionTypes();
    };
  }

  // Waitlist refresh
  const refreshWaitlist = document.getElementById('refreshWaitlist');
  if (refreshWaitlist) {
    refreshWaitlist.onclick = () => loadWaitlist(true);
  }

  // Services refresh
  const refreshServices = document.getElementById('refreshServices');
  if (refreshServices) {
    refreshServices.onclick = () => {
      store.services = []; // Clear cache to force refetch
      loadServices(true);
    };
  }

  // Admin form buttons
  const toggleAdminForm = document.getElementById('toggleAdminForm');
  if (toggleAdminForm) {
    toggleAdminForm.onclick = () => openAddAdminModal();
  }

  const addAdminBtn = document.getElementById('addAdminBtn');
  if (addAdminBtn) {
    addAdminBtn.onclick = () => addAdmin();
  }

  // Invite form buttons
  const toggleInviteForm = document.getElementById('toggleInviteForm');
  if (toggleInviteForm) {
    toggleInviteForm.onclick = () => openCreateInviteModal();
  }

  const createInviteBtn = document.getElementById('createInviteBtn');
  if (createInviteBtn) {
    createInviteBtn.onclick = () => createInvite();
  }

  // Generic confirm button
  const genericConfirmBtn = document.getElementById('genericConfirmBtn');
  if (genericConfirmBtn) {
    genericConfirmBtn.onclick = () => closeGenericConfirmModal(true);
  }

  // Refresh subscription analytics button
  const refreshAnalyticsBtn = document.getElementById('refreshAnalyticsBtn');
  if (refreshAnalyticsBtn) {
    refreshAnalyticsBtn.onclick = () => loadAllSubscriptions(true).then(() => updateSubscriptionAnalytics());
  }

  // Refresh vault metrics button
  const refreshVaultMetricsBtn = document.getElementById('refreshVaultMetricsBtn');
  if (refreshVaultMetricsBtn) {
    refreshVaultMetricsBtn.onclick = () => loadVaultMetrics();
  }

  // Batch import button
  const batchImportBtn = document.getElementById('batchImportBtn');
  if (batchImportBtn) {
    batchImportBtn.onclick = () => openCsvImportModal();
  }
}

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
      document.querySelectorAll('.waitlist-checkbox:not([disabled])').forEach(cb => {
        cb.checked = selectAll.checked;
      });
      updateWaitlistSelectedCount();
    };
  }

  // Individual checkbox changes
  document.addEventListener('change', e => {
    if (e.target.classList.contains('waitlist-checkbox')) {
      updateWaitlistSelectedCount();
    }
  });

  // Waitlist action buttons
  setupWaitlistActionButtons();
}

function updateWaitlistSelectedCount() {
  const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
  const count = checkboxes.length;

  // Update bulk bar visibility and count
  const bulkBar = document.getElementById('waitlistBulkBar');
  const countEl = document.getElementById('selectedWaitlistCount');
  if (bulkBar) bulkBar.classList.toggle('active', count > 0);
  if (countEl) countEl.textContent = count;
}

let pendingInviteWaitlistIds = [];

function setupWaitlistActionButtons() {
  // Send invites button - opens modal
  const sendBtn = document.getElementById('sendInvitesBtn');
  if (sendBtn) {
    sendBtn.onclick = () => {
      const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
      if (checkboxes.length === 0) {
        showToast('Please select at least one waitlist entry', 'warning');
        return;
      }
      pendingInviteWaitlistIds = Array.from(checkboxes).map(cb => cb.dataset.waitlistId);
      const countDisplay = document.getElementById('inviteCountDisplay');
      if (countDisplay) countDisplay.textContent = pendingInviteWaitlistIds.length;
      openModal('customMessageModal');
    };
  }

  // Confirm send invites
  const confirmBtn = document.getElementById('confirmSendInvites');
  if (confirmBtn) {
    confirmBtn.onclick = async () => {
      if (pendingInviteWaitlistIds.length === 0) return;

      const customMessage = document.getElementById('customMessageText')?.value || '';
      closeModal('customMessageModal');

      try {
        const res = await api('/admin/waitlist/send-invites', {
          method: 'POST',
          body: JSON.stringify({ waitlist_ids: pendingInviteWaitlistIds, custom_message: customMessage })
        });

        showToast(`Sent ${res.sent || pendingInviteWaitlistIds.length} invite(s)`, 'success');
        pendingInviteWaitlistIds = [];
        loadWaitlist(false);
      } catch (err) {
        showToast(err.message || 'Failed to send invites', 'error');
      }
    };
  }

  // Cancel send invites
  const cancelBtn = document.getElementById('cancelSendInvites');
  if (cancelBtn) {
    cancelBtn.onclick = () => {
      pendingInviteWaitlistIds = [];
      closeModal('customMessageModal');
    };
  }

  // Close button (X) on modal
  const closeBtn = document.getElementById('closeCustomMessageModal');
  if (closeBtn) {
    closeBtn.onclick = () => {
      pendingInviteWaitlistIds = [];
      closeModal('customMessageModal');
    };
  }

  // Reject waitlist button - Note: No backend endpoint exists for reject
  // Use delete instead to remove unwanted entries
  const rejectBtn = document.getElementById('rejectWaitlistBtn');
  if (rejectBtn) {
    rejectBtn.onclick = () => {
      showToast('Reject functionality not implemented. Use Delete to remove entries.', 'warning');
    };
  }

  // Delete waitlist button
  const deleteBtn = document.getElementById('deleteWaitlistBtn');
  if (deleteBtn) {
    deleteBtn.onclick = async () => {
      const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
      if (checkboxes.length === 0) return;

      const waitlistIds = Array.from(checkboxes).map(cb => cb.dataset.waitlistId);

      if (!confirm(`Delete ${waitlistIds.length} waitlist entr${waitlistIds.length === 1 ? 'y' : 'ies'}? This cannot be undone.`)) {
        return;
      }

      try {
        await api('/admin/waitlist', {
          method: 'DELETE',
          body: JSON.stringify({ waitlist_ids: waitlistIds })
        });

        showToast(`Deleted ${waitlistIds.length} entr${waitlistIds.length === 1 ? 'y' : 'ies'}`, 'success');
        loadWaitlist(false);
      } catch (err) {
        showToast(err.message || 'Failed to delete entries', 'error');
      }
    };
  }
}

async function loadWaitlist(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) waitlistPaginationState.currentPage = 1;

  // Check if table exists before proceeding
  const table = document.getElementById('waitlistTable');
  if (!table) return;

  showLoadingSkeleton('waitlistTable');

  try {
    const data = await api('/admin/waitlist');
    waitlistData = data.waitlist || [];
    renderWaitlist();
  } catch (e) {
    // Query tbody fresh for error display
    const tbody = document.querySelector('#waitlistTable tbody');
    if (tbody) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'muted';
      td.textContent = 'Error: ' + (e.message || String(e));
      tr.appendChild(td);
      tbody.replaceChildren(tr);
    }
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
    cb.dataset.waitlistId = w.waitlist_id;
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
