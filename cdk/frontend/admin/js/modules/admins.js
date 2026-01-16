/**
 * Admin Portal Admins Module
 *
 * Admin user management, pending invitations, bulk actions.
 * Uses safe DOM methods throughout.
 */

import {
  store,
  escapeHtml,
  api,
  showToast,
  isAdmin,
  updatePagination,
  showLoadingSkeleton,
  searchFilter,
  debounce
} from './core.js';

// ============================================
// State
// ============================================

export let adminQuickFilter = 'active';
export let pendingAdminsData = [];
export let currentManageAdmin = null;
export let currentActivityData = [];
export let currentActivityFilter = 'all';

// Sorting state
export const sortState = {
  admins: { column: null, direction: 'asc' }
};

// ============================================
// Admin Loading
// ============================================

export async function loadAdmins(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) store.pagination.admins.page = 0;

  const tbody = document.querySelector('#adminsTable tbody');
  showLoadingSkeleton('adminsTable');

  try {
    if (resetPage || store.admins.length === 0) {
      const response = await api('/admin/admins');
      store.admins = response.admins || [];
    }

    // Update counts
    const activeCt = store.admins.filter(a => a.enabled).length;
    const disabledCt = store.admins.filter(a => !a.enabled).length;
    const activeCountEl = document.getElementById('activeAdminsCount');
    const disabledCountEl = document.getElementById('disabledAdminsCount');
    if (activeCountEl) activeCountEl.textContent = activeCt;
    if (disabledCountEl) disabledCountEl.textContent = disabledCt;

    // Apply quick filter
    let filtered = store.admins.filter(a => {
      if (adminQuickFilter === 'active' && !a.enabled) return false;
      if (adminQuickFilter === 'disabled' && a.enabled) return false;
      return searchFilter(a, store.pagination.admins.search, ['name', 'email', 'given_name', 'family_name']);
    });

    renderAdmins(filtered, tbody);
  } catch (e) {
    showToast('Failed to load admins: ' + (e.message || e), 'error');
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.className = 'muted';
    td.textContent = e.message || String(e);
    tr.appendChild(td);
    tbody.replaceChildren(tr);
  }
}

export function renderAdmins(filtered, tbody) {
  // Check for empty state
  if (filtered.length === 0) {
    tbody.replaceChildren();
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.style.cssText = 'text-align:center;padding:40px;';
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty-state';
    const emptyTitle = document.createElement('div');
    emptyTitle.className = 'empty-state-title';
    emptyTitle.textContent = 'No admin users yet';
    const emptyText = document.createElement('div');
    emptyText.className = 'empty-state-text';
    emptyText.textContent = 'Add admin users using the form above';
    emptyDiv.append(emptyTitle, emptyText);
    td.appendChild(emptyDiv);
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  tbody.replaceChildren();
  const page = updatePagination('admins', filtered);
  const searchTerm = store.pagination.admins.search;

  const adminTypeLabels = { admin: 'A', user_admin: 'U', subscriber_admin: 'S', vote_admin: 'V' };
  const adminTypeColors = {
    admin: 'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)',
    user_admin: 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)',
    subscriber_admin: 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)',
    vote_admin: 'linear-gradient(135deg,#10b981 0%,#059669 100%)'
  };

  page.forEach(a => {
    const tr = document.createElement('tr');
    const name = (a.given_name || '') + (a.family_name ? ' ' + a.family_name : '');
    const createdDate = a.created_at ? new Date(a.created_at).toLocaleString() : '—';
    const adminType = a.admin_type || 'admin';

    // Checkbox cell
    const td1 = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.name = 'admin-select';
    cb.className = 'admin-checkbox';
    cb.dataset.email = a.email;
    cb.dataset.enabled = a.enabled;
    td1.appendChild(cb);

    // Name cell
    const td2 = document.createElement('td');
    td2.textContent = name || '—';
    if (searchTerm) highlightCell(td2, name, searchTerm);

    // Email cell
    const td3 = document.createElement('td');
    td3.textContent = a.email;
    if (searchTerm) highlightCell(td3, a.email, searchTerm);

    // Admin type badge cell
    const td4 = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.style.cssText = `display:inline-block;background:${adminTypeColors[adminType]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;`;
    typeBadge.textContent = adminTypeLabels[adminType];
    td4.appendChild(typeBadge);

    // Status badge cell
    const td5 = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
    if (a.enabled) {
      statusBadge.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
      statusBadge.style.color = '#fff';
      statusBadge.textContent = 'Active';
    } else {
      statusBadge.style.background = 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
      statusBadge.style.color = '#fff';
      statusBadge.textContent = 'Disabled';
    }
    td5.appendChild(statusBadge);

    // Last login cell
    const td6 = document.createElement('td');
    if (a.last_login_at) {
      const lastLogin = new Date(a.last_login_at);
      const relativeTime = formatRelativeTime(lastLogin);
      const span = document.createElement('span');
      span.title = lastLogin.toLocaleString();
      span.style.color = 'var(--text)';
      span.textContent = relativeTime;
      td6.appendChild(span);
    } else {
      td6.textContent = '—';
    }

    // Created at cell
    const td7 = document.createElement('td');
    td7.textContent = createdDate;

    // Actions dropdown cell
    const td8 = document.createElement('td');
    const dropdown = createAdminActionDropdown(a.email, name || a.email, adminType, a.enabled);
    td8.appendChild(dropdown);

    tr.append(td1, td2, td3, td4, td5, td6, td7, td8);
    tbody.appendChild(tr);
  });

  // Attach checkbox handlers
  tbody.querySelectorAll('.admin-checkbox').forEach(cb => cb.onchange = updateAdminsBulkButtons);

  renderAdminsCards(page);
}

function createAdminActionDropdown(email, name, adminType, enabled) {
  const dropdown = document.createElement('div');
  dropdown.className = 'action-dropdown';

  const btn = document.createElement('button');
  btn.className = 'action-dropdown-btn';
  btn.title = 'Actions';
  btn.textContent = '⋮';
  btn.onclick = (e) => {
    e.stopPropagation();
    const menu = dropdown.querySelector('.action-dropdown-menu');
    document.querySelectorAll('.action-dropdown-menu.active').forEach(m => {
      if (m !== menu) m.classList.remove('active');
    });
    menu.classList.toggle('active');
  };

  const menu = document.createElement('div');
  menu.className = 'action-dropdown-menu';

  const manageBtn = document.createElement('button');
  manageBtn.className = 'action-dropdown-item';
  manageBtn.textContent = 'Manage Access';
  manageBtn.onclick = (e) => {
    e.stopPropagation();
    menu.classList.remove('active');
    openManageAccessModal(email, name, adminType, enabled);
  };

  const activityBtn = document.createElement('button');
  activityBtn.className = 'action-dropdown-item';
  activityBtn.textContent = 'View Activity';
  activityBtn.onclick = async (e) => {
    e.stopPropagation();
    menu.classList.remove('active');
    await openActivityLogModal(email, name);
  };

  menu.append(manageBtn, activityBtn);
  dropdown.append(btn, menu);
  return dropdown;
}

// ============================================
// Pending Admins
// ============================================

export async function loadPendingAdmins() {
  if (!isAdmin()) return;
  try {
    const response = await api('/admin/pending-admins');
    pendingAdminsData = response.pending_admins || [];
    renderPendingAdmins();
  } catch (e) {
    console.error('Error loading pending admins:', e);
    pendingAdminsData = [];
    renderPendingAdmins();
  }
}

export function renderPendingAdmins() {
  const section = document.getElementById('pendingAdminsSection');
  const list = document.getElementById('pendingAdminsList');
  const countBadge = document.getElementById('pendingAdminsCount');

  if (!section || !list) return;

  if (pendingAdminsData.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  if (countBadge) countBadge.textContent = pendingAdminsData.length;
  list.replaceChildren();

  const adminTypeLabels = { admin: 'Admin', user_admin: 'User Admin', subscriber_admin: 'Subscriber Admin', vote_admin: 'Vote Admin' };

  pendingAdminsData.forEach(admin => {
    const card = document.createElement('div');
    card.style.cssText = 'padding:16px;background:var(--bg-input);border-radius:8px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;';

    const isVerified = admin.ses_verified === true || admin.ses_status === 'Success';
    const statusColor = isVerified ? '#10b981' : '#f59e0b';
    const statusText = isVerified ? 'Verified - Ready to Activate' : 'Awaiting Email Verification';

    const infoDiv = document.createElement('div');
    const nameDiv = document.createElement('div');
    nameDiv.style.cssText = 'font-weight:600;color:var(--text);margin-bottom:4px;';
    nameDiv.textContent = `${admin.first_name || ''} ${admin.last_name || ''}`;
    const emailDiv = document.createElement('div');
    emailDiv.style.cssText = 'font-size:0.85rem;color:var(--gray);margin-bottom:4px;';
    emailDiv.textContent = admin.email;
    const statusDiv = document.createElement('div');
    statusDiv.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;';
    const statusSpan = document.createElement('span');
    statusSpan.style.cssText = `font-size:0.75rem;color:${statusColor};font-weight:600;`;
    statusSpan.textContent = statusText;
    const typeSpan = document.createElement('span');
    typeSpan.style.cssText = 'font-size:0.75rem;color:var(--gray);';
    typeSpan.textContent = adminTypeLabels[admin.admin_type] || 'Admin';
    statusDiv.append(statusSpan, typeSpan);
    infoDiv.append(nameDiv, emailDiv, statusDiv);

    const actionsDiv = document.createElement('div');
    actionsDiv.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';

    if (isVerified) {
      const activateBtn = document.createElement('button');
      activateBtn.className = 'btn';
      activateBtn.style.cssText = 'background:linear-gradient(135deg,#10b981 0%,#059669 100%);padding:8px 16px;font-size:0.85rem;';
      activateBtn.textContent = 'Activate';
      activateBtn.onclick = () => activatePendingAdmin(admin.email);
      actionsDiv.appendChild(activateBtn);
    } else {
      const resendBtn = document.createElement('button');
      resendBtn.className = 'btn';
      resendBtn.style.cssText = 'background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);padding:8px 16px;font-size:0.85rem;';
      resendBtn.textContent = 'Resend';
      resendBtn.onclick = () => resendAdminVerification(admin.email);
      actionsDiv.appendChild(resendBtn);
    }

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn';
    cancelBtn.style.cssText = 'background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);padding:8px 16px;font-size:0.85rem;';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.onclick = () => cancelPendingAdmin(admin.email);
    actionsDiv.appendChild(cancelBtn);

    card.append(infoDiv, actionsDiv);
    list.appendChild(card);
  });
}

export async function activatePendingAdmin(email) {
  const confirmed = await showConfirmDialog(
    'Activate Admin Account',
    `Are you sure you want to activate the admin account for ${email}? They will receive an email with their login credentials.`,
    'Activate',
    'Cancel',
    false
  );
  if (!confirmed) return;

  try {
    const result = await api(`/admin/pending-admins/${encodeURIComponent(email)}/activate`, { method: 'POST' });
    showToast(result.message || `Admin ${email} activated successfully!`, 'success');
    await loadPendingAdmins();
    await loadAdmins();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function resendAdminVerification(email) {
  try {
    const result = await api(`/admin/pending-admins/${encodeURIComponent(email)}/resend`, { method: 'POST' });
    if (result.already_verified) {
      showToast(result.message || 'Email already verified - ready to activate!', 'success');
      await loadPendingAdmins();
    } else {
      showToast(result.message || 'Verification email resent!', 'success');
    }
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function cancelPendingAdmin(email) {
  const confirmed = await showConfirmDialog(
    'Cancel Invitation',
    `Are you sure you want to cancel the invitation for ${email}? This cannot be undone.`,
    'Cancel Invitation',
    'Keep',
    true
  );
  if (!confirmed) return;

  try {
    const result = await api(`/admin/pending-admins/${encodeURIComponent(email)}`, { method: 'DELETE' });
    showToast(result.message || `Invitation for ${email} cancelled.`, 'success');
    await loadPendingAdmins();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

// ============================================
// Bulk Actions
// ============================================

export function updateAdminsBulkButtons() {
  const checkboxes = document.querySelectorAll('.admin-checkbox:checked');
  const count = checkboxes.length;
  const countEl = document.getElementById('adminsBulkCount');
  if (countEl) countEl.textContent = count > 0 ? `${count} selected` : '';

  const hasEnabled = Array.from(checkboxes).some(cb => cb.dataset.enabled === 'true');
  const hasDisabled = Array.from(checkboxes).some(cb => cb.dataset.enabled === 'false');

  const disableBtn = document.getElementById('bulkDisableAdmins');
  const enableBtn = document.getElementById('bulkEnableAdmins');
  if (disableBtn) disableBtn.disabled = count === 0 || !hasEnabled;
  if (enableBtn) enableBtn.disabled = count === 0 || !hasDisabled;
}

export async function bulkDisableAdmins() {
  const checkboxes = document.querySelectorAll('.admin-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.enabled === 'true');
  if (items.length === 0) {
    showToast('No enabled admins selected', 'warning');
    return;
  }

  const confirmed = await showConfirmDialog(
    'Disable Admins',
    `Are you sure you want to disable ${items.length} admin user(s)? They will lose access to the admin panel.`,
    'Disable',
    'Cancel',
    true
  );
  if (!confirmed) return;

  const progressToast = showToast(`Processing 0 of ${items.length}...`, 'info', 0);
  const results = await Promise.allSettled(items.map((cb, i) =>
    api(`/admin/users/${encodeURIComponent(cb.dataset.email)}/disable`, { method: 'POST' }).then(() => {
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
    showToast(`Disabled ${succeeded} admin(s) successfully`, 'success');
  }
  const selectAll = document.getElementById('selectAllAdmins');
  if (selectAll) selectAll.checked = false;
  await loadAdmins();
}

export async function bulkEnableAdmins() {
  const checkboxes = document.querySelectorAll('.admin-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.dataset.enabled === 'false');
  if (items.length === 0) {
    showToast('No disabled admins selected', 'warning');
    return;
  }

  if (!confirm(`Enable ${items.length} admin user(s)?`)) return;

  const progressToast = showToast(`Processing 0 of ${items.length}...`, 'info', 0);
  const results = await Promise.allSettled(items.map((cb, i) =>
    api(`/admin/users/${encodeURIComponent(cb.dataset.email)}/enable`, { method: 'POST' }).then(() => {
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
    showToast(`Enabled ${succeeded} admin(s) successfully`, 'success');
  }
  const selectAll = document.getElementById('selectAllAdmins');
  if (selectAll) selectAll.checked = false;
  await loadAdmins();
}

// ============================================
// Quick Filter
// ============================================

export function setAdminQuickFilter(filter) {
  adminQuickFilter = filter;
  document.querySelectorAll('#admins .btn').forEach(btn => {
    if (btn.id && btn.id.includes('Admins')) btn.classList.remove('filter-active');
  });
  const activeBtn = document.getElementById(`quickFilter${filter.charAt(0).toUpperCase() + filter.slice(1)}Admins`);
  if (activeBtn) activeBtn.classList.add('filter-active');
  store.pagination.admins.page = 0;
  loadAdmins(false);
}

// ============================================
// Manage Access Modal
// ============================================

export function openManageAccessModal(email, name, adminType, enabled) {
  currentManageAdmin = { email, name, adminType, enabled };
  const modal = document.getElementById('manageAccessModal');
  if (!modal) return;

  const titleEl = document.getElementById('manageAccessTitle');
  const emailEl = document.getElementById('manageAccessEmail');
  const statusEl = document.getElementById('manageAccessCurrentStatus');
  const typeSelect = document.getElementById('manageAccessType');
  const toggleBtn = document.getElementById('toggleAdminStatusBtn');

  if (titleEl) titleEl.textContent = name;
  if (emailEl) emailEl.textContent = email;
  if (statusEl) {
    statusEl.textContent = enabled ? 'Active' : 'Disabled';
    statusEl.style.color = enabled ? '#10b981' : '#ef4444';
  }
  if (typeSelect) typeSelect.value = adminType;
  if (toggleBtn) {
    toggleBtn.textContent = enabled ? 'Disable Account' : 'Enable Account';
    toggleBtn.style.background = enabled
      ? 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)'
      : 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
  }

  modal.classList.add('active');
}

export function closeManageAccessModal() {
  const modal = document.getElementById('manageAccessModal');
  if (modal) modal.classList.remove('active');
  currentManageAdmin = null;
}

export async function handleToggleAdminStatus() {
  if (!currentManageAdmin) return;

  const endpoint = currentManageAdmin.enabled ? 'disable' : 'enable';
  const actionText = currentManageAdmin.enabled ? 'disable' : 'enable';

  try {
    await api(`/admin/users/${encodeURIComponent(currentManageAdmin.email)}/${endpoint}`, { method: 'POST' });
    showToast(`Admin ${actionText}d successfully`, 'success');
    closeManageAccessModal();
    await loadAdmins();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function handleUpdateAdminType() {
  if (!currentManageAdmin) return;

  const typeSelect = document.getElementById('manageAccessType');
  const newType = typeSelect?.value;
  if (!newType || newType === currentManageAdmin.adminType) {
    showToast('No changes to save', 'info');
    return;
  }

  try {
    await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}/type`, {
      method: 'PUT',
      body: JSON.stringify({ admin_type: newType })
    });
    showToast('Admin type updated successfully', 'success');
    closeManageAccessModal();
    await loadAdmins();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function handleResetAdminPassword() {
  if (!currentManageAdmin) return;

  const adminName = currentManageAdmin.name || currentManageAdmin.email;
  const confirmed = await showConfirmDialog(
    'Reset Password',
    `Reset password for ${adminName}?\n\nA temporary password will be generated and emailed to ${currentManageAdmin.email}. They will be required to change it on first login.`,
    'Reset Password',
    'Cancel',
    false
  );
  if (!confirmed) return;

  try {
    await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}/reset-password`, { method: 'POST' });
    showToast(`Password reset successfully. Temporary password has been emailed to ${currentManageAdmin.email}`, 'success');
    closeManageAccessModal();
  } catch (e) {
    showToast('Error resetting password: ' + (e.message || e), 'error');
  }
}

// ============================================
// Activity Log Modal
// ============================================

export async function openActivityLogModal(email, name) {
  currentActivityData = [];
  currentActivityFilter = 'all';

  const modal = document.getElementById('activityLogModal');
  const titleEl = document.getElementById('activityLogTitle');
  const contentEl = document.getElementById('activityLogContent');

  if (!modal || !contentEl) return;

  if (titleEl) titleEl.textContent = `Activity Log: ${name}`;
  contentEl.textContent = 'Loading...';
  modal.classList.add('active');

  try {
    const data = await api(`/admin/audit?email=${encodeURIComponent(email)}&limit=100`);
    currentActivityData = data.entries || data || [];
    renderActivityLog();
  } catch (e) {
    contentEl.textContent = 'Error loading activity: ' + (e.message || e);
  }
}

export function renderActivityLog() {
  const contentEl = document.getElementById('activityLogContent');
  if (!contentEl) return;

  let filtered = currentActivityData;
  if (currentActivityFilter === 'login') {
    filtered = currentActivityData.filter(a => {
      const actionType = (a.action || a.type || '').toLowerCase();
      return actionType.includes('login') || actionType.includes('auth');
    });
  } else if (currentActivityFilter === 'action') {
    filtered = currentActivityData.filter(a => {
      const actionType = (a.action || a.type || '').toLowerCase();
      return actionType && !actionType.includes('login') && !actionType.includes('auth') && !actionType.includes('error') && !actionType.includes('failed');
    });
  } else if (currentActivityFilter === 'error') {
    filtered = currentActivityData.filter(a => {
      const actionType = a.action || a.type || '';
      return actionType.includes('error') || actionType.includes('failed');
    });
  }

  if (filtered.length === 0) {
    contentEl.textContent = 'No activity found';
    contentEl.style.cssText = 'color:var(--gray);text-align:center;padding:40px 20px;';
    return;
  }

  // Sort by timestamp descending
  filtered.sort((a, b) => {
    const aTime = new Date(a.timestamp || a.created_at || a.ts).getTime();
    const bTime = new Date(b.timestamp || b.created_at || b.ts).getTime();
    return bTime - aTime;
  });

  contentEl.replaceChildren();
  contentEl.style.cssText = '';

  filtered.forEach(activity => {
    const timestamp = new Date(activity.timestamp || activity.created_at || activity.ts);
    const relativeTime = formatRelativeTime(timestamp);
    const action = (activity.action || activity.type || '').toLowerCase();

    let typeColor = '#3b82f6';
    if (action.includes('login') || action.includes('auth')) {
      typeColor = '#10b981';
    } else if (action.includes('error') || action.includes('failed')) {
      typeColor = '#ef4444';
    }

    const displayAction = (activity.action || activity.type || 'Unknown Action')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());

    const item = document.createElement('div');
    item.style.cssText = `padding:12px;margin-bottom:12px;background:var(--bg-card);border-left:3px solid ${typeColor};border-radius:4px;`;

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:start;margin-bottom:6px;';

    const actionDiv = document.createElement('div');
    actionDiv.style.cssText = 'font-weight:600;color:var(--text);';
    actionDiv.textContent = displayAction;

    const timeSpan = document.createElement('span');
    timeSpan.style.cssText = 'font-size:0.75rem;color:var(--gray);white-space:nowrap;margin-left:12px;';
    timeSpan.title = timestamp.toLocaleString();
    timeSpan.textContent = relativeTime;

    header.append(actionDiv, timeSpan);
    item.appendChild(header);

    if (activity.description) {
      const descDiv = document.createElement('div');
      descDiv.style.cssText = 'font-size:0.85rem;color:var(--gray);margin-bottom:4px;';
      descDiv.textContent = activity.description;
      item.appendChild(descDiv);
    }

    if (activity.ip_address) {
      const ipDiv = document.createElement('div');
      ipDiv.style.cssText = 'font-size:0.75rem;color:var(--gray);';
      ipDiv.textContent = 'IP: ' + activity.ip_address;
      item.appendChild(ipDiv);
    }

    contentEl.appendChild(item);
  });
}

export function closeActivityLogModal() {
  const modal = document.getElementById('activityLogModal');
  if (modal) modal.classList.remove('active');
  currentActivityData = [];
  currentActivityFilter = 'all';
}

// ============================================
// Add Admin
// ============================================

export async function addAdmin() {
  const firstName = document.getElementById('adminFirstName')?.value.trim();
  const lastName = document.getElementById('adminLastName')?.value.trim();
  const email = document.getElementById('adminEmail')?.value.trim().toLowerCase();
  const adminType = document.getElementById('adminType')?.value;
  const msgEl = document.getElementById('adminMsg');

  if (!firstName) { showToast('Please enter a first name', 'warning'); return; }
  if (!lastName) { showToast('Please enter a last name', 'warning'); return; }
  if (!email) { showToast('Please enter an email address', 'warning'); return; }

  try {
    const result = await api('/admin/pending-admins', {
      method: 'POST',
      body: JSON.stringify({ first_name: firstName, last_name: lastName, email, admin_type: adminType })
    });
    showToast(result.message || `Invitation sent to ${email}!`, 'success');

    // Clear form
    document.getElementById('adminFirstName').value = '';
    document.getElementById('adminLastName').value = '';
    document.getElementById('adminEmail').value = '';
    document.getElementById('adminType').value = 'admin';

    closeAddAdminModal();
    await loadPendingAdmins();
    await loadAdmins();
  } catch (e) {
    if (msgEl) {
      msgEl.textContent = 'Error: ' + (e.message || e);
      msgEl.style.color = '#ef4444';
    }
  }
}

export function closeAddAdminModal() {
  const modal = document.getElementById('addAdminModal');
  if (modal) modal.classList.remove('active');
  const msgEl = document.getElementById('adminMsg');
  if (msgEl) msgEl.textContent = '';
}

// ============================================
// Helper Functions
// ============================================

function formatRelativeTime(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} min${diffMins !== 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
  return date.toLocaleDateString();
}

function highlightCell(cell, text, searchTerm) {
  if (!searchTerm || !text) return;
  const regex = new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  const parts = text.split(regex);
  cell.textContent = '';
  parts.forEach(part => {
    if (part.toLowerCase() === searchTerm.toLowerCase()) {
      const mark = document.createElement('mark');
      mark.style.cssText = 'background:#ffd93d;color:#000;padding:0 2px;border-radius:2px;';
      mark.textContent = part;
      cell.appendChild(mark);
    } else {
      cell.appendChild(document.createTextNode(part));
    }
  });
}

// Placeholder for showConfirm from main module
let showConfirmDialog = async (title, msg, confirmText, cancelText, isDanger) => {
  return confirm(`${title}\n\n${msg}`);
};

export function setShowConfirm(fn) {
  showConfirmDialog = fn;
}

// ============================================
// Debounced Search
// ============================================

export const debouncedLoadAdmins = debounce(() => loadAdmins(false), 300);

// ============================================
// Card Rendering for Mobile
// ============================================

export function renderAdminsCards(admins) {
  const cardContainer = document.getElementById('adminsCardContainer');
  if (!cardContainer) return;

  cardContainer.replaceChildren();

  const adminTypeLabels = { admin: 'Admin', user_admin: 'User Admin', subscriber_admin: 'Subscriber Admin', vote_admin: 'Vote Admin' };
  const adminTypeColors = {
    admin: '#a855f7', user_admin: '#3b82f6', subscriber_admin: '#f59e0b', vote_admin: '#10b981'
  };

  admins.forEach(a => {
    const card = document.createElement('div');
    card.className = 'data-card';

    const name = (a.given_name || '') + (a.family_name ? ' ' + a.family_name : '');
    const adminType = a.admin_type || 'admin';

    // Header
    const header = document.createElement('div');
    header.className = 'data-card-header';
    const headerInner = document.createElement('div');
    headerInner.style.cssText = 'display:flex;align-items:center;gap:12px;flex:1;';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.name = 'admin-select';
    cb.className = 'admin-checkbox';
    cb.dataset.email = a.email;
    cb.dataset.enabled = a.enabled;
    cb.dataset.action = 'admin-select';
    cb.style.cssText = 'width:18px;height:18px;cursor:pointer;';
    const title = document.createElement('div');
    title.className = 'data-card-title';
    title.textContent = name || a.email;
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
    emailValue.textContent = a.email;
    emailRow.append(emailLabel, emailValue);
    body.appendChild(emailRow);

    // Type row
    const typeRow = document.createElement('div');
    typeRow.className = 'data-card-row';
    const typeLabel = document.createElement('span');
    typeLabel.className = 'data-card-label';
    typeLabel.textContent = 'Type:';
    const typeBadge = document.createElement('span');
    typeBadge.className = 'data-card-badge';
    typeBadge.style.cssText = `background:${adminTypeColors[adminType]};font-size:0.65rem;`;
    typeBadge.textContent = adminTypeLabels[adminType];
    typeRow.append(typeLabel, typeBadge);
    body.appendChild(typeRow);

    // Status row
    const statusRow = document.createElement('div');
    statusRow.className = 'data-card-row';
    const statusLabel = document.createElement('span');
    statusLabel.className = 'data-card-label';
    statusLabel.textContent = 'Status:';
    const statusBadge = document.createElement('span');
    statusBadge.className = 'data-card-badge';
    statusBadge.style.cssText = `background:${a.enabled ? '#10b981' : '#6b7280'};font-size:0.65rem;`;
    statusBadge.textContent = a.enabled ? 'Active' : 'Disabled';
    statusRow.append(statusLabel, statusBadge);
    body.appendChild(statusRow);

    // Actions row
    const actionsRow = document.createElement('div');
    actionsRow.className = 'data-card-actions';
    const manageBtn = document.createElement('button');
    manageBtn.className = 'btn btn-sm';
    manageBtn.style.cssText = 'background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);';
    manageBtn.textContent = 'Manage';
    manageBtn.dataset.action = 'admin-manage';
    manageBtn.dataset.email = a.email;
    manageBtn.dataset.name = name || a.email;
    manageBtn.dataset.enabled = a.enabled;
    manageBtn.dataset.adminType = adminType;
    actionsRow.appendChild(manageBtn);
    body.appendChild(actionsRow);

    card.append(header, body);
    cardContainer.appendChild(card);
  });
}

// ============================================
// Missing Modal Functions (Stubs)
// ============================================

export function openAddAdminModal() {
  const modal = document.getElementById('addAdminModal');
  if (modal) modal.classList.add('active');
}

export function openChangeAdminTypeModal(email, currentType) {
  const modal = document.getElementById('changeAdminTypeModal');
  if (modal) {
    const emailEl = document.getElementById('changeTypeAdminEmail');
    const selectEl = document.getElementById('newAdminType');
    if (emailEl) emailEl.value = email;
    if (selectEl) selectEl.value = currentType;
    modal.classList.add('active');
  }
}

export function closeChangeAdminTypeModal() {
  const modal = document.getElementById('changeAdminTypeModal');
  if (modal) modal.classList.remove('active');
}

export async function handleChangeAdminType() {
  const email = document.getElementById('changeTypeAdminEmail')?.value;
  const newType = document.getElementById('newAdminType')?.value;
  if (!email || !newType) return;

  try {
    await api('/admin/admins/' + encodeURIComponent(email) + '/type', {
      method: 'PUT',
      body: JSON.stringify({ admin_type: newType })
    });
    showToast('Admin type updated', 'success');
    closeChangeAdminTypeModal();
    loadAdmins();
  } catch (e) {
    showToast('Failed to update admin type: ' + (e.message || e), 'error');
  }
}

export async function handleDeleteAdmin() {
  const email = currentManageAdmin;
  if (!email) return;

  try {
    await api('/admin/admins/' + encodeURIComponent(email), { method: 'DELETE' });
    showToast('Admin deleted', 'success');
    closeManageAccessModal();
    loadAdmins();
  } catch (e) {
    showToast('Failed to delete admin: ' + (e.message || e), 'error');
  }
}

export function setupAdminsEventHandlers() {
  // Quick filter buttons for Admins tab
  const activeBtn = document.getElementById('quickFilterActiveAdmins');
  const disabledBtn = document.getElementById('quickFilterDisabledAdmins');

  if (activeBtn) {
    activeBtn.onclick = () => setAdminQuickFilter('active');
  }

  if (disabledBtn) {
    disabledBtn.onclick = () => setAdminQuickFilter('disabled');
  }

  // Select all checkbox
  const selectAll = document.getElementById('selectAllAdmins');
  if (selectAll) {
    selectAll.onchange = () => {
      document.querySelectorAll('.admin-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
      });
    };
  }

  // Search input
  const searchInput = document.getElementById('adminsSearch');
  if (searchInput) {
    searchInput.oninput = (e) => {
      store.pagination.admins.search = e.target.value;
      loadAdmins(false);
    };
  }
}
