/**
 * Admin Portal Users Module
 *
 * User management, registration workflow, bulk actions.
 * Note: innerHTML usage is intentional - all user data is sanitized via escapeHtml()
 */

import {
  store,
  escapeHtml,
  api,
  showToast,
  isAdmin,
  updatePagination,
  showLoadingSkeleton,
  debounce
} from './core.js';

// ============================================
// State
// ============================================

// Filters for Users tab
export const userFilters = {
  registration: '',
  membership: '',
  subscription: '',
  quickFilter: 'action',
  dateFrom: '',
  dateTo: '',
  lastActive: ''
};

// Sorting state
export const sortState = {
  users: { column: null, direction: 'asc' }
};

// Pagination state reference
const pagination = store.pagination.users;

// ============================================
// Status Badge Rendering
// ============================================

export function renderStatusBadges(user) {
  const badges = [];

  // Registration status badge
  const statusColors = {
    pending: '#f59e0b',
    approved: '#10b981',
    rejected: '#ef4444',
    disabled: '#6b7280',
    deleted: '#991b1b'
  };
  const statusLabels = {
    pending: 'Pending Reg',
    approved: 'Approved',
    rejected: 'Rejected',
    disabled: 'Disabled',
    deleted: 'Deleted'
  };

  if (user.status && statusColors[user.status]) {
    badges.push(`<span style="display:inline-block;background:${statusColors[user.status]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">${statusLabels[user.status]}</span>`);
  }

  // Membership status badge
  const membershipStatus = user.membership_status || 'none';
  if (membershipStatus === 'pending') {
    badges.push('<span style="display:inline-block;background:#8b5cf6;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member Req</span>');
  } else if (membershipStatus === 'approved') {
    badges.push('<span style="display:inline-block;background:#3b82f6;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member</span>');
  } else if (membershipStatus === 'denied') {
    badges.push('<span style="display:inline-block;background:#dc2626;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member Denied</span>');
  }

  // Subscription status badge
  const subStatus = user.subscription_status || 'none';
  if (subStatus === 'active') {
    badges.push('<span style="display:inline-block;background:#a855f7;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Active Sub</span>');
  } else if (subStatus === 'cancelled') {
    badges.push('<span style="display:inline-block;background:#f97316;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Cancelled Sub</span>');
  } else if (subStatus === 'expired') {
    badges.push('<span style="display:inline-block;background:#78716c;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Expired Sub</span>');
  }

  return badges.join('');
}

// ============================================
// Search Highlighting
// ============================================

export function highlightText(text, searchTerm) {
  if (!text || !searchTerm) return escapeHtml(text || '');
  const escaped = escapeHtml(text);
  const regex = new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  return escaped.replace(regex, '<mark style="background:#ffd93d;color:#000;padding:0 2px;border-radius:2px;">$1</mark>');
}

// ============================================
// Sorting
// ============================================

export function sortData(data, column, direction) {
  return [...data].sort((a, b) => {
    let aVal = a[column];
    let bVal = b[column];

    // Handle dates
    if (column.includes('_at') || column.includes('date')) {
      aVal = aVal ? new Date(aVal).getTime() : 0;
      bVal = bVal ? new Date(bVal).getTime() : 0;
    }

    // Handle strings
    if (typeof aVal === 'string') aVal = aVal.toLowerCase();
    if (typeof bVal === 'string') bVal = bVal.toLowerCase();

    if (aVal < bVal) return direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return direction === 'asc' ? 1 : -1;
    return 0;
  });
}

// ============================================
// User Loading
// ============================================

export async function loadUsers(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) pagination.page = 0;

  const tbody = document.querySelector('#usersTable tbody');
  showLoadingSkeleton('usersTable');

  try {
    // Fetch all user data if needed
    if (resetPage || store.users.length === 0) {
      const [regData, memberData, subData, waitlistData] = await Promise.all([
        api('/admin/registrations'),
        api('/admin/membership-requests'),
        api('/admin/subscriptions?status=active'),
        api('/admin/waitlist')
      ]);

      // Create maps for quick lookup
      const memberMap = new Map();
      (memberData.registrations || []).forEach(m => {
        memberMap.set(m.registration_id, m);
      });

      const subMap = new Map();
      (subData.subscriptions || []).forEach(s => {
        subMap.set(s.user_guid, s);
      });

      // Combine all data
      const registrations = regData.items || regData || [];
      store.users = registrations.map(r => {
        const member = memberMap.get(r.registration_id) || {};
        const sub = subMap.get(r.user_guid) || {};
        return {
          ...r,
          membership_status: member.membership_status || 'none',
          membership_requested_at: member.membership_requested_at,
          subscription_status: sub.status || 'none',
          subscription_plan: sub.plan || sub.subscription_type_name,
          subscription_expires: sub.expires_at
        };
      });

      // Get invited users from waitlist who haven't registered yet
      const waitlist = waitlistData.waitlist || [];
      const registeredEmails = new Set(registrations.map(r => r.email?.toLowerCase()));
      store.invitedWaitlistUsers = waitlist.filter(w =>
        w.status === 'invited' && !registeredEmails.has(w.email?.toLowerCase())
      );
    }

    // Filter and render
    const filtered = applyUserFilters();
    renderUsers(filtered, tbody);

  } catch (e) {
    const errMsg = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'muted';
    td.textContent = 'Error: ' + (e.message || String(e));
    errMsg.appendChild(td);
    tbody.replaceChildren(errMsg);
  }
}

function applyUserFilters() {
  const showingInvited = userFilters.quickFilter === 'invited';

  if (showingInvited) {
    // Filter invited waitlist users
    return (store.invitedWaitlistUsers || []).filter(u => {
      if (pagination.search) {
        const query = pagination.search.toLowerCase();
        const searchMatch = [u.first_name, u.last_name, u.email, u.invite_code]
          .some(f => (f || '').toLowerCase().includes(query));
        if (!searchMatch) return false;
      }
      return true;
    });
  }

  // Apply filters to registered users
  return store.users.filter(u => {
    // Search filter
    if (pagination.search) {
      const query = pagination.search.toLowerCase();
      const searchMatch = [u.first_name, u.last_name, u.email, u.invite_code, u.user_guid]
        .some(f => (f || '').toLowerCase().includes(query));
      if (!searchMatch) return false;
    }

    // Registration status filter
    if (userFilters.registration && u.status !== userFilters.registration) return false;

    // Membership status filter
    if (userFilters.membership) {
      const memberStatus = u.membership_status || 'none';
      if (memberStatus !== userFilters.membership) return false;
    }

    // Subscription status filter
    if (userFilters.subscription) {
      const subStatus = u.subscription_status || 'none';
      if (subStatus !== userFilters.subscription) return false;
    }

    // Date range filter
    if (userFilters.dateFrom) {
      const fromDate = new Date(userFilters.dateFrom);
      fromDate.setHours(0, 0, 0, 0);
      const regDate = new Date(u.created_at);
      if (regDate < fromDate) return false;
    }
    if (userFilters.dateTo) {
      const toDate = new Date(userFilters.dateTo);
      toDate.setHours(23, 59, 59, 999);
      const regDate = new Date(u.created_at);
      if (regDate > toDate) return false;
    }

    // Last active filter
    if (userFilters.lastActive) {
      const now = new Date();
      const lastLogin = u.last_login_at ? new Date(u.last_login_at) : null;
      const thresholds = { '1': 24, '7': 168, '30': 720, '90': 2160 };

      if (userFilters.lastActive.startsWith('inactive-')) {
        const days = parseInt(userFilters.lastActive.split('-')[1]);
        if (!lastLogin || now - lastLogin <= days * 24 * 60 * 60 * 1000) return false;
      } else {
        const hours = thresholds[userFilters.lastActive];
        if (hours && (!lastLogin || now - lastLogin > hours * 60 * 60 * 1000)) return false;
      }
    }

    // Quick filter
    if (userFilters.quickFilter === 'action') {
      const needsAction = u.status === 'pending' || u.membership_status === 'pending';
      if (!needsAction) return false;
    } else if (userFilters.quickFilter === 'registered') {
      const isRegistered = u.status === 'approved' || u.subscription_status === 'active';
      if (!isRegistered) return false;
    } else if (userFilters.quickFilter === 'disabled') {
      if (u.status !== 'disabled') return false;
    }

    return true;
  });
}

export function renderUsers(filtered, tbody) {
  const showingInvited = userFilters.quickFilter === 'invited';

  // Apply sorting
  if (sortState.users.column) {
    filtered = sortData(filtered, sortState.users.column, sortState.users.direction);
  }

  // Update counts
  const actionCount = store.users.filter(u => u.status === 'pending' || u.membership_status === 'pending').length;
  const registeredCount = store.users.filter(u => u.status === 'approved' || u.subscription_status === 'active').length;
  const disabledCount = store.users.filter(u => u.status === 'disabled').length;
  const invitedCount = (store.invitedWaitlistUsers || []).length;

  const countEls = {
    action: document.getElementById('actionCount'),
    registered: document.getElementById('registeredCount'),
    disabled: document.getElementById('disabledCount'),
    invited: document.getElementById('invitedCount')
  };
  if (countEls.action) countEls.action.textContent = actionCount;
  if (countEls.registered) countEls.registered.textContent = registeredCount;
  if (countEls.disabled) countEls.disabled.textContent = disabledCount;
  if (countEls.invited) countEls.invited.textContent = invitedCount;

  // Pagination
  const page = updatePagination('users', filtered);
  tbody.replaceChildren();

  // Clear checkboxes
  const selectAll = document.getElementById('selectAllUsers');
  if (selectAll) selectAll.checked = false;

  const searchTerm = pagination.search;

  if (page.length === 0) {
    const emptyMsg = showingInvited
      ? 'No invited users pending registration.'
      : 'No users found matching the current filters.';
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'muted';
    td.style.cssText = 'text-align:center;padding:40px;';
    td.textContent = emptyMsg;
    tr.appendChild(td);
    tbody.appendChild(tr);
  } else if (showingInvited) {
    // Render invited waitlist users
    page.forEach(u => {
      const tr = document.createElement('tr');
      const name = `${u.first_name || ''} ${u.last_name || ''}`.trim();

      // Checkbox cell (disabled)
      const td1 = document.createElement('td');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.disabled = true;
      cb.style.opacity = '0.3';
      td1.appendChild(cb);

      // Name cell
      const td2 = document.createElement('td');
      td2.textContent = name || '—';

      // Email cell
      const td3 = document.createElement('td');
      td3.textContent = u.email;

      // Status cell
      const td4 = document.createElement('td');
      const badge = document.createElement('span');
      badge.style.cssText = 'display:inline-block;background:#6366f1;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;';
      badge.textContent = 'Invited';
      td4.appendChild(badge);
      if (u.invite_code) {
        const code = document.createElement('span');
        code.style.cssText = 'font-family:monospace;font-size:0.75rem;color:var(--gray);margin-left:4px;';
        code.textContent = u.invite_code;
        td4.appendChild(code);
      }
      if (u.invited_at) {
        const invDate = document.createElement('span');
        invDate.style.cssText = 'font-size:0.7rem;color:var(--gray);margin-left:8px;';
        invDate.textContent = new Date(u.invited_at).toLocaleDateString();
        td4.appendChild(invDate);
      }

      tr.append(td1, td2, td3, td4);
      tbody.appendChild(tr);
    });
  } else {
    // Render registered users
    page.forEach(u => {
      const tr = document.createElement('tr');
      const name = `${u.first_name || ''} ${u.last_name || ''}`.trim();

      // Checkbox cell
      const td1 = document.createElement('td');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.name = 'user-select';
      cb.className = 'user-checkbox';
      cb.dataset.id = u.registration_id;
      cb.dataset.status = u.status;
      cb.dataset.member = u.membership_status || 'none';
      td1.appendChild(cb);

      // Name cell
      const td2 = document.createElement('td');
      td2.textContent = name || '—';

      // Email cell
      const td3 = document.createElement('td');
      td3.textContent = u.email;

      // Status badges cell - using safe DOM methods
      const td4 = document.createElement('td');
      appendStatusBadges(td4, u);

      tr.append(td1, td2, td3, td4);
      tbody.appendChild(tr);
    });
  }

  updateUsersSelectedCount();
  renderUsersCards(page, showingInvited);
}

// Helper function to append status badges using safe DOM methods
function appendStatusBadges(container, user) {
  const statusColors = {
    pending: '#f59e0b', approved: '#10b981', rejected: '#ef4444',
    disabled: '#6b7280', deleted: '#991b1b'
  };
  const statusLabels = {
    pending: 'Pending Reg', approved: 'Approved', rejected: 'Rejected',
    disabled: 'Disabled', deleted: 'Deleted'
  };

  // Registration status
  if (user.status && statusColors[user.status]) {
    const badge = document.createElement('span');
    badge.style.cssText = `display:inline-block;background:${statusColors[user.status]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;`;
    badge.textContent = statusLabels[user.status];
    container.appendChild(badge);
  }

  // Membership status
  const membershipStatus = user.membership_status || 'none';
  const memberColors = { pending: '#8b5cf6', approved: '#3b82f6', denied: '#dc2626' };
  const memberLabels = { pending: 'Member Req', approved: 'Member', denied: 'Member Denied' };
  if (memberColors[membershipStatus]) {
    const badge = document.createElement('span');
    badge.style.cssText = `display:inline-block;background:${memberColors[membershipStatus]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;`;
    badge.textContent = memberLabels[membershipStatus];
    container.appendChild(badge);
  }

  // Subscription status
  const subStatus = user.subscription_status || 'none';
  const subColors = { active: '#a855f7', cancelled: '#f97316', expired: '#78716c' };
  const subLabels = { active: 'Active Sub', cancelled: 'Cancelled Sub', expired: 'Expired Sub' };
  if (subColors[subStatus]) {
    const badge = document.createElement('span');
    badge.style.cssText = `display:inline-block;background:${subColors[subStatus]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;`;
    badge.textContent = subLabels[subStatus];
    container.appendChild(badge);
  }
}

// ============================================
// Selection Management
// ============================================

export function updateUsersSelectedCount() {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const count = checkboxes.length;
  const countEl = document.getElementById('usersBulkCount');
  if (countEl) countEl.textContent = count > 0 ? `${count} selected` : '';

  // Check selection states
  const hasPendingReg = Array.from(checkboxes).some(cb => cb.dataset.status === 'pending');
  const hasApproved = Array.from(checkboxes).some(cb => cb.dataset.status === 'approved');
  const hasDisabled = Array.from(checkboxes).some(cb => cb.dataset.status === 'disabled');
  const hasRejected = Array.from(checkboxes).some(cb => cb.dataset.status === 'rejected');

  // Enable/disable buttons
  const btns = {
    approve: document.getElementById('bulkApproveReg'),
    reject: document.getElementById('bulkRejectReg'),
    disable: document.getElementById('bulkDisableUsers'),
    enable: document.getElementById('bulkEnableUsers'),
    delete: document.getElementById('bulkDeleteUsers')
  };

  if (btns.approve) btns.approve.disabled = count === 0 || !hasPendingReg;
  if (btns.reject) btns.reject.disabled = count === 0 || !hasPendingReg;
  if (btns.disable) btns.disable.disabled = count === 0 || !hasApproved;
  if (btns.enable) btns.enable.disabled = count === 0 || !hasDisabled;
  if (btns.delete) btns.delete.disabled = count === 0 || !(hasDisabled || hasRejected);
}

// ============================================
// Bulk Actions
// ============================================

export async function bulkApproveRegistrations(showConfirm) {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.status === 'pending');
  if (items.length === 0) {
    showToast('No pending registrations selected', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Approve Registrations',
    `Approve ${items.length} registration(s)? Users will be granted access to the platform.`,
    'Approve',
    'Cancel',
    false
  );
  if (!confirmed) return;

  await processBulkAction(items, (cb) =>
    api(`/admin/registrations/${cb.dataset.id}/approve`, { method: 'POST' }),
    'Approved'
  );
}

export async function bulkRejectRegistrations(showConfirm) {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.status === 'pending');
  if (items.length === 0) {
    showToast('No pending registrations selected', 'warning');
    return;
  }

  const reason = prompt('Enter rejection reason (optional):');
  if (reason === null) return;

  const confirmed = await showConfirm(
    'Reject Registrations',
    `Reject ${items.length} registration(s)? Users will be notified${reason ? ' with the reason provided' : ''}.`,
    'Reject',
    'Cancel',
    true
  );
  if (!confirmed) return;

  await processBulkAction(items, (cb) =>
    api(`/admin/registrations/${cb.dataset.id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
    'Rejected'
  );
}

export async function bulkDisableUsers(showConfirm) {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.status === 'approved');
  if (items.length === 0) {
    showToast('No approved users selected', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Disable Users',
    `Disable ${items.length} user(s)? They will lose access to the platform until re-enabled.`,
    'Disable',
    'Cancel',
    true
  );
  if (!confirmed) return;

  await processBulkAction(items, (cb) =>
    api(`/admin/users/${cb.dataset.id}/disable`, { method: 'POST' }),
    'Disabled'
  );
}

export async function bulkEnableUsers(showConfirm) {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.status === 'disabled');
  if (items.length === 0) {
    showToast('No disabled users selected', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Enable Users',
    `Enable ${items.length} user(s)? They will regain access to the platform.`,
    'Enable',
    'Cancel',
    false
  );
  if (!confirmed) return;

  await processBulkAction(items, (cb) =>
    api(`/admin/users/${cb.dataset.id}/enable`, { method: 'POST' }),
    'Enabled'
  );
}

export async function bulkDeleteUsers(showConfirm) {
  const checkboxes = document.querySelectorAll('.user-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb =>
    cb.dataset.status === 'disabled' || cb.dataset.status === 'rejected'
  );
  if (items.length === 0) {
    showToast('No disabled or rejected users selected', 'warning');
    return;
  }

  // Two-step confirmation
  const firstConfirm = await showConfirm(
    'Permanent Deletion Warning',
    `WARNING: This will PERMANENTLY DELETE ${items.length} user(s).\n\nThis action cannot be undone. All user data will be removed from the system.\n\nAre you sure you want to continue?`,
    'Continue',
    'Cancel',
    true
  );
  if (!firstConfirm) return;

  const finalConfirm = await showConfirm(
    'Final Confirmation',
    `FINAL CONFIRMATION: Permanently delete ${items.length} user(s)?`,
    'Delete Permanently',
    'Cancel',
    true
  );
  if (!finalConfirm) return;

  await processBulkAction(items, (cb) =>
    api(`/admin/users/${cb.dataset.id}/permanently-delete`, { method: 'DELETE' }),
    'Deleted'
  );
}

async function processBulkAction(items, actionFn, actionName) {
  const progressToast = showToast(`Processing 0 of ${items.length}...`, 'info', 0);
  const results = await Promise.allSettled(items.map((cb, i) =>
    actionFn(cb).then(() => {
      const span = progressToast.querySelector('span');
      if (span) span.textContent = `Processing ${i + 1} of ${items.length}...`;
    })
  ));
  progressToast.remove();

  const succeeded = results.filter(r => r.status === 'fulfilled').length;
  const failed = results.filter(r => r.status === 'rejected').length;

  if (failed > 0) {
    showToast(`${succeeded} succeeded, ${failed} failed`, 'warning');
  } else {
    showToast(`${actionName} ${succeeded} user(s) successfully`, 'success');
  }
  await loadUsers();
}

// ============================================
// Filter Reset
// ============================================

export function resetUserFilters() {
  Object.assign(userFilters, {
    registration: '',
    membership: '',
    subscription: '',
    quickFilter: 'action',
    dateFrom: '',
    dateTo: '',
    lastActive: ''
  });
  pagination.search = '';

  // Reset UI elements
  const elements = [
    'filterRegistration', 'filterMembership', 'filterSubscription',
    'filterDateFrom', 'filterDateTo', 'filterLastActive', 'usersSearch'
  ];
  elements.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });

  // Reset quick filter buttons
  document.querySelectorAll('#users .btn').forEach(btn => {
    if (btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
  });
  const actionBtn = document.getElementById('quickFilterAction');
  if (actionBtn) actionBtn.classList.add('filter-active');

  loadUsers(true);
}

// ============================================
// Debounced Search
// ============================================

export const debouncedLoadUsers = debounce(() => loadUsers(false), 300);

// ============================================
// Card Rendering for Mobile
// ============================================

export function renderUsersCards(users, isInvited = false) {
  const cardContainer = document.getElementById('usersCardContainer');
  if (!cardContainer) return;

  cardContainer.replaceChildren();

  users.forEach(u => {
    const name = `${u.first_name || ''} ${u.last_name || ''}`.trim() || '—';
    const card = document.createElement('div');
    card.className = 'data-card';

    if (isInvited) {
      // Header
      const header = document.createElement('div');
      header.className = 'data-card-header';
      const title = document.createElement('div');
      title.className = 'data-card-title';
      title.textContent = name;
      header.appendChild(title);

      // Body
      const body = document.createElement('div');
      body.className = 'data-card-body';

      // Email row
      const emailRow = document.createElement('div');
      emailRow.className = 'data-card-row';
      const emailLabel = document.createElement('span');
      emailLabel.className = 'data-card-label';
      emailLabel.textContent = 'Email:';
      const emailValue = document.createElement('span');
      emailValue.className = 'data-card-value';
      emailValue.textContent = u.email;
      emailRow.append(emailLabel, emailValue);
      body.appendChild(emailRow);

      // Status row
      const statusRow = document.createElement('div');
      statusRow.className = 'data-card-row';
      const statusLabel = document.createElement('span');
      statusLabel.className = 'data-card-label';
      statusLabel.textContent = 'Status:';
      const statusBadge = document.createElement('span');
      statusBadge.className = 'data-card-badge';
      statusBadge.style.cssText = 'background:#6366f1;font-size:0.65rem;';
      statusBadge.textContent = 'Invited';
      statusRow.append(statusLabel, statusBadge);
      body.appendChild(statusRow);

      if (u.invite_code) {
        const codeRow = document.createElement('div');
        codeRow.className = 'data-card-row';
        const codeLabel = document.createElement('span');
        codeLabel.className = 'data-card-label';
        codeLabel.textContent = 'Invite Code:';
        const codeValue = document.createElement('span');
        codeValue.className = 'data-card-value';
        codeValue.style.fontFamily = 'monospace';
        codeValue.textContent = u.invite_code;
        codeRow.append(codeLabel, codeValue);
        body.appendChild(codeRow);
      }

      card.append(header, body);
    } else {
      const statusColors = {
        pending: '#f59e0b', approved: '#10b981', rejected: '#ef4444',
        disabled: '#ec4899', deleted: '#7f1d1d'
      };
      const memberColors = {
        none: '#6b7280', pending: '#f59e0b', approved: '#10b981', denied: '#ef4444'
      };
      const regColor = statusColors[u.status] || '#6b7280';
      const memberStatus = u.membership_status || 'none';
      const memberColor = memberColors[memberStatus] || '#6b7280';

      // Header with checkbox
      const header = document.createElement('div');
      header.className = 'data-card-header';
      const headerInner = document.createElement('div');
      headerInner.style.cssText = 'display:flex;align-items:center;gap:12px;flex:1;';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.name = 'user-select';
      cb.className = 'user-checkbox';
      cb.dataset.id = u.registration_id;
      cb.dataset.status = u.status;
      cb.dataset.member = memberStatus;
      cb.dataset.action = 'user-select';
      cb.style.cssText = 'width:18px;height:18px;cursor:pointer;';
      const title = document.createElement('div');
      title.className = 'data-card-title';
      title.textContent = name;
      headerInner.append(cb, title);
      header.appendChild(headerInner);

      // Body
      const body = document.createElement('div');
      body.className = 'data-card-body';

      // Email row
      const emailRow = document.createElement('div');
      emailRow.className = 'data-card-row';
      const emailLabel = document.createElement('span');
      emailLabel.className = 'data-card-label';
      emailLabel.textContent = 'Email:';
      const emailValue = document.createElement('span');
      emailValue.className = 'data-card-value';
      emailValue.textContent = u.email;
      emailRow.append(emailLabel, emailValue);
      body.appendChild(emailRow);

      // Registration row
      const regRow = document.createElement('div');
      regRow.className = 'data-card-row';
      const regLabel = document.createElement('span');
      regLabel.className = 'data-card-label';
      regLabel.textContent = 'Registration:';
      const regBadge = document.createElement('span');
      regBadge.className = 'data-card-badge';
      regBadge.style.cssText = `background:${regColor};font-size:0.65rem;`;
      regBadge.textContent = u.status;
      regRow.append(regLabel, regBadge);
      body.appendChild(regRow);

      // Membership row (if applicable)
      if (memberStatus !== 'none') {
        const memRow = document.createElement('div');
        memRow.className = 'data-card-row';
        const memLabel = document.createElement('span');
        memLabel.className = 'data-card-label';
        memLabel.textContent = 'Membership:';
        const memBadge = document.createElement('span');
        memBadge.className = 'data-card-badge';
        memBadge.style.cssText = `background:${memberColor};font-size:0.65rem;`;
        memBadge.textContent = memberStatus === 'approved' ? 'member' : memberStatus;
        memRow.append(memLabel, memBadge);
        body.appendChild(memRow);
      }

      // Created row
      const createdRow = document.createElement('div');
      createdRow.className = 'data-card-row';
      const createdLabel = document.createElement('span');
      createdLabel.className = 'data-card-label';
      createdLabel.textContent = 'Created:';
      const createdValue = document.createElement('span');
      createdValue.className = 'data-card-value';
      createdValue.textContent = u.created_at ? new Date(u.created_at).toLocaleDateString() : '—';
      createdRow.append(createdLabel, createdValue);
      body.appendChild(createdRow);

      card.append(header, body);
    }
    cardContainer.appendChild(card);
  });
}

// ============================================
// Email Modal Functions
// ============================================

let selectedEmailRecipients = [];

export function openComposeEmailModal() {
  const modal = document.getElementById('composeEmailModal');
  const selectedUsers = document.querySelectorAll('input[name="user-select"]:checked');
  selectedEmailRecipients = Array.from(selectedUsers).map(cb => cb.value);

  if (selectedEmailRecipients.length === 0) {
    showToast('Please select at least one user', 'warning');
    return;
  }

  const recipientCount = document.getElementById('emailRecipientCount');
  if (recipientCount) {
    recipientCount.textContent = selectedEmailRecipients.length + ' recipient(s)';
  }

  if (modal) modal.classList.add('active');
}

export function closeComposeEmailModal() {
  const modal = document.getElementById('composeEmailModal');
  if (modal) modal.classList.remove('active');

  const subject = document.getElementById('emailSubject');
  const body = document.getElementById('emailBody');
  if (subject) subject.value = '';
  if (body) body.value = '';
}

export async function sendEmail() {
  const subject = document.getElementById('emailSubject')?.value;
  const body = document.getElementById('emailBody')?.value;

  if (!subject || !body) {
    showToast('Please fill in subject and body', 'warning');
    return;
  }

  try {
    await api('/admin/users/email', {
      method: 'POST',
      body: JSON.stringify({
        recipients: selectedEmailRecipients,
        subject,
        body
      })
    });
    showToast('Email sent successfully', 'success');
    closeComposeEmailModal();
  } catch (e) {
    showToast('Failed to send email: ' + (e.message || e), 'error');
  }
}

export function setupUserBulkActions() {
  // Event handlers are set up via event delegation in main.js
}

// ============================================
// User Filter Event Handlers
// ============================================

export function setupUserEventHandlers() {
  // Quick filter buttons for User Management tab
  const actionBtn = document.getElementById('quickFilterAction');
  const registeredBtn = document.getElementById('quickFilterRegistered');
  const disabledBtn = document.getElementById('quickFilterDisabled');
  const invitedBtn = document.getElementById('quickFilterInvited');

  if (actionBtn) {
    actionBtn.onclick = () => {
      userFilters.quickFilter = 'action';
      document.querySelectorAll('#users .btn').forEach(btn => {
        if (btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
      });
      actionBtn.classList.add('filter-active');
      pagination.page = 0;
      loadUsers(false);
    };
  }

  if (registeredBtn) {
    registeredBtn.onclick = () => {
      userFilters.quickFilter = 'registered';
      document.querySelectorAll('#users .btn').forEach(btn => {
        if (btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
      });
      registeredBtn.classList.add('filter-active');
      pagination.page = 0;
      loadUsers(false);
    };
  }

  if (disabledBtn) {
    disabledBtn.onclick = () => {
      userFilters.quickFilter = 'disabled';
      document.querySelectorAll('#users .btn').forEach(btn => {
        if (btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
      });
      disabledBtn.classList.add('filter-active');
      pagination.page = 0;
      loadUsers(false);
    };
  }

  if (invitedBtn) {
    invitedBtn.onclick = () => {
      userFilters.quickFilter = 'invited';
      document.querySelectorAll('#users .btn').forEach(btn => {
        if (btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
      });
      invitedBtn.classList.add('filter-active');
      pagination.page = 0;
      loadUsers(false);
    };
  }

  // Select all checkbox
  const selectAll = document.getElementById('selectAllUsers');
  if (selectAll) {
    selectAll.onchange = () => {
      document.querySelectorAll('.user-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
      });
      updateUsersSelectedCount();
    };
  }

  // User checkbox change handler (delegated)
  document.addEventListener('change', (e) => {
    if (e.target.classList.contains('user-checkbox')) {
      updateUsersSelectedCount();
    }
  });

  // Search input
  const searchInput = document.getElementById('usersSearch');
  if (searchInput) {
    searchInput.oninput = (e) => {
      pagination.search = e.target.value;
      debouncedLoadUsers();
    };
  }
}
