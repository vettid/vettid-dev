/**
 * Admin Portal Invites Module
 *
 * Invite code management, creation, expiration, bulk actions.
 * Uses safe DOM methods throughout - no innerHTML with user data.
 */

import {
  store,
  escapeHtml,
  api,
  showToast,
  isAdmin,
  updatePagination,
  showLoadingSkeleton,
  parseTimestamp,
  debounce
} from './core.js';

// ============================================
// State
// ============================================

export let inviteQuickFilter = 'active';

// Sorting state
export const sortState = {
  invites: { column: null, direction: 'asc' }
};

// ============================================
// Helper Functions
// ============================================

function createProgressBarElement(percentage, color) {
  const container = document.createElement('div');
  container.style.cssText = 'width:100%;height:6px;background:var(--bg-tertiary);border-radius:3px;overflow:hidden;';
  const fill = document.createElement('div');
  fill.style.cssText = `width:${percentage}%;height:100%;background:${color};border-radius:3px;transition:width 0.3s ease;`;
  container.appendChild(fill);
  return container;
}

// ============================================
// Invite Loading
// ============================================

export async function loadInvites(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) store.pagination.invites.page = 0;

  // Check if table exists before proceeding
  const table = document.getElementById('invitesTable');
  if (!table) return; // Table not in DOM yet

  showLoadingSkeleton('invitesTable');

  try {
    if (resetPage || store.invites.length === 0) {
      const data = await api('/admin/invites');
      // Backend returns { items, count, limit } - extract items array
      store.invites = data.items || data.invites || (Array.isArray(data) ? data : []);
    }
    renderInvites();
  } catch (e) {
    console.error('Error loading invites:', e);
    // Query tbody fresh for error display
    const tbody = document.querySelector('#invitesTable tbody');
    if (tbody) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 9;
      td.className = 'muted';
      td.textContent = 'Error: ' + (e.message || String(e));
      tr.appendChild(td);
      tbody.replaceChildren(tr);
    }
  }
}

// ============================================
// Invite Rendering
// ============================================

export function renderInvites() {
  const tbody = document.querySelector('#invitesTable tbody');
  if (!tbody) return;

  tbody.replaceChildren();
  const now = Date.now();

  // Apply filters
  let filtered = store.invites.filter(i => {
    // Quick filter
    const expiresParsed = parseTimestamp(i.expires_at);
    const expiresAt = expiresParsed ? expiresParsed.getTime() : null;
    const daysLeft = expiresAt ? Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)) : null;
    const isExpired = expiresAt && expiresAt < now;
    const isExpiringSoon = daysLeft && daysLeft < 7 && daysLeft > 0;

    if (inviteQuickFilter === 'active' && i.status !== 'active' && i.status !== 'new') return false;
    if (inviteQuickFilter === 'expiring' && (!isExpiringSoon || i.status === 'exhausted' || i.status === 'expired' || isExpired)) return false;
    if (inviteQuickFilter === 'used' && !(i.status === 'exhausted' || i.status === 'expired' || isExpired)) return false;

    // Search filter
    const search = store.pagination.invites.search.toLowerCase();
    const matchesCode = i.code.toLowerCase().includes(search);
    const matchesSentTo = (i.sent_to || '').toLowerCase().includes(search);
    if (search && !matchesCode && !matchesSentTo) return false;

    return true;
  });

  // Check for empty state
  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 9;
    td.style.cssText = 'text-align:center;padding:40px;';
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty-state';
    const emptyTitle = document.createElement('div');
    emptyTitle.className = 'empty-state-title';
    emptyTitle.textContent = 'No invites found';
    const emptyText = document.createElement('div');
    emptyText.className = 'empty-state-text';
    emptyText.textContent = 'Try adjusting your filters';
    emptyDiv.append(emptyTitle, emptyText);
    td.appendChild(emptyDiv);
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  // Paginate
  const page = updatePagination('invites', filtered);
  const searchTerm = store.pagination.invites.search;

  page.forEach(i => {
    const tr = document.createElement('tr');
    const createdDate = i.created_at ? new Date(i.created_at).toLocaleString() : '—';
    const expiresParsed = parseTimestamp(i.expires_at);
    const expiresDate = expiresParsed ? expiresParsed.toLocaleString() : '—';
    const autoApprove = i.auto_approve ? 'Yes' : 'No';

    // Calculate status with expiration check
    const expiresAt = expiresParsed ? expiresParsed.getTime() : null;
    const daysLeft = expiresAt ? Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)) : null;
    const isExpired = expiresAt && expiresAt < now;
    const isExpiringSoon = daysLeft && daysLeft < 7 && daysLeft > 0;

    let actualStatus = i.status;
    if (i.status === 'expired' || isExpired) {
      actualStatus = 'expired';
    }

    // Checkbox cell
    const td1 = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.name = 'invite-select';
    cb.className = 'invites-checkbox';
    cb.dataset.code = i.code;
    cb.dataset.status = actualStatus;
    td1.appendChild(cb);

    // Code cell (with highlight)
    const td2 = document.createElement('td');
    td2.textContent = i.code;
    if (searchTerm) highlightCell(td2, i.code, searchTerm);

    // Sent to cell
    const td3 = document.createElement('td');
    td3.textContent = i.sent_to || '—';
    if (searchTerm) highlightCell(td3, i.sent_to || '—', searchTerm);

    // Usage progress cell
    const td4 = document.createElement('td');
    const used = i.used || 0;
    const maxUses = i.max_uses || 1;
    const percentage = Math.min(100, (used / maxUses) * 100);
    let barColor = '#10b981';
    if (percentage > 80) barColor = '#ef4444';
    else if (percentage > 50) barColor = '#f59e0b';

    const progressContainer = document.createElement('div');
    progressContainer.style.cssText = 'display:flex;align-items:center;gap:8px;';
    const progressWrapper = document.createElement('div');
    progressWrapper.style.width = '100px';
    progressWrapper.appendChild(createProgressBarElement(percentage, barColor));
    const usageText = document.createElement('span');
    usageText.style.cssText = 'font-size:0.75rem;color:var(--gray);';
    usageText.textContent = `${used}/${maxUses}`;
    progressContainer.append(progressWrapper, usageText);
    td4.appendChild(progressContainer);

    // Status badge cell
    const td5 = document.createElement('td');
    const badge = document.createElement('span');
    badge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
    if (actualStatus === 'expired') {
      badge.style.background = 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)';
      badge.style.color = '#fff';
      badge.textContent = 'Expired';
    } else if (i.status === 'exhausted') {
      badge.style.background = 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
      badge.style.color = '#fff';
      badge.textContent = 'Exhausted';
    } else if (isExpiringSoon) {
      badge.style.background = 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)';
      badge.style.color = '#000';
      badge.textContent = 'Expiring Soon';
    } else {
      badge.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
      badge.style.color = '#fff';
      badge.textContent = 'Active';
    }
    td5.appendChild(badge);

    // Auto-approve cell
    const td6 = document.createElement('td');
    td6.textContent = autoApprove;

    // Created at cell
    const td7 = document.createElement('td');
    td7.textContent = createdDate;

    // Created by cell
    const td8 = document.createElement('td');
    td8.textContent = i.created_by || '—';

    // Expires at cell
    const td9 = document.createElement('td');
    td9.textContent = expiresDate;

    tr.append(td1, td2, td3, td4, td5, td6, td7, td8, td9);
    tbody.appendChild(tr);
  });

  updateInvitesSelectedCount();
  renderInvitesCards(page);
}

// Helper function to highlight search term in a cell
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

// ============================================
// Selection Management
// ============================================

export function updateInvitesSelectedCount() {
  const checkboxes = document.querySelectorAll('.invites-checkbox:checked');
  const count = checkboxes.length;
  const countEl = document.getElementById('invitesSelectedCount');
  if (countEl) countEl.textContent = count > 0 ? `${count} selected` : '';

  const statuses = Array.from(checkboxes).map(cb => cb.getAttribute('data-status'));
  const hasActive = statuses.includes('active');

  const expireBtn = document.getElementById('bulkExpireInvites');
  const deleteBtn = document.getElementById('bulkDeleteInvites');
  if (expireBtn) expireBtn.disabled = !hasActive;
  if (deleteBtn) deleteBtn.disabled = count === 0;
}

// ============================================
// Bulk Actions
// ============================================

export async function bulkExpireInvites(showConfirm) {
  const checkboxes = document.querySelectorAll('.invites-checkbox:checked');
  const items = Array.from(checkboxes).filter(cb => cb.getAttribute('data-status') === 'active');
  const codes = items.map(cb => cb.getAttribute('data-code'));

  if (codes.length === 0) {
    showToast('No active invites selected', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Expire Invites',
    `Expire ${codes.length} invite(s)? They will no longer be valid for registration.`,
    'Expire',
    'Cancel',
    false
  );
  if (!confirmed) return;

  try {
    for (const code of codes) {
      await api(`/admin/invites/${code}/expire`, { method: 'POST' });
    }
    showToast(`Expired ${codes.length} invite(s) successfully`, 'success');
    await loadInvites();
    const selectAll = document.getElementById('selectAllInvites');
    if (selectAll) selectAll.checked = false;
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function bulkDeleteInvites(showConfirm) {
  const checkboxes = document.querySelectorAll('.invites-checkbox:checked');
  const codes = Array.from(checkboxes).map(cb => cb.getAttribute('data-code'));

  if (codes.length === 0) {
    showToast('No invites selected', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Delete Invites',
    `Permanently delete ${codes.length} invite(s)? This action cannot be undone.`,
    'Delete',
    'Cancel',
    true
  );
  if (!confirmed) return;

  try {
    for (const code of codes) {
      await api(`/admin/invites/${code}`, { method: 'DELETE' });
    }
    showToast(`Deleted ${codes.length} invite(s) successfully`, 'success');
    await loadInvites();
    const selectAll = document.getElementById('selectAllInvites');
    if (selectAll) selectAll.checked = false;
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

// ============================================
// Create Invite
// ============================================

export async function createInvite() {
  const customCode = document.getElementById('customCode').value.trim();
  const n = Number(document.getElementById('maxUses').value || '1');
  const autoApprove = document.getElementById('autoApprove').checked;
  const expiresAtInput = document.getElementById('expiresAt').value;
  const msgEl = document.getElementById('inviteMsg');

  const payload = { max_uses: n, auto_approve: autoApprove };
  if (customCode) payload.code = customCode;
  if (expiresAtInput) {
    const expiresDate = new Date(expiresAtInput);
    payload.expires_at = Math.floor(expiresDate.getTime() / 1000);
  }

  try {
    const data = await api('/admin/invites', { method: 'POST', body: JSON.stringify(payload) });

    // Show success with clickable code
    showInviteCodeSuccess(data);

    // Clear form
    document.getElementById('customCode').value = '';
    document.getElementById('maxUses').value = '1';
    document.getElementById('expiresAt').value = '';
    document.getElementById('autoApprove').checked = false;

    closeCreateInviteModal();
    await loadInvites();
  } catch (e) {
    if (msgEl) {
      msgEl.textContent = 'Error: ' + (e.message || e);
      msgEl.style.color = '#ef4444';
    }
  }
}

// ============================================
// Invite Code Success Display
// ============================================

function showInviteCodeSuccess(data) {
  // Remove any existing success overlay
  const existing = document.getElementById('inviteCodeSuccessOverlay');
  if (existing) existing.remove();

  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'inviteCodeSuccessOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:10000;';

  // Create card
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--bg-card);border-radius:12px;padding:32px;max-width:400px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5);';

  // Success icon (using text checkmark for safety)
  const iconDiv = document.createElement('div');
  iconDiv.style.cssText = 'width:64px;height:64px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:32px;color:#fff;';
  iconDiv.textContent = '\u2713';

  // Title
  const title = document.createElement('h3');
  title.style.cssText = 'margin:0 0 8px;font-size:1.25rem;color:var(--text);';
  title.textContent = 'Invite Created!';

  // Subtitle
  const subtitle = document.createElement('p');
  subtitle.style.cssText = 'margin:0 0 20px;color:var(--gray);font-size:0.9rem;';
  subtitle.textContent = 'Click the code below to copy it to clipboard';

  // Code display (clickable)
  const codeBox = document.createElement('div');
  codeBox.style.cssText = 'background:var(--bg-tertiary);border:2px dashed var(--accent);border-radius:8px;padding:16px;margin-bottom:16px;cursor:pointer;transition:all 0.2s ease;';
  codeBox.onmouseenter = () => { codeBox.style.borderColor = '#ffd93d'; codeBox.style.background = 'var(--bg-input)'; };
  codeBox.onmouseleave = () => { codeBox.style.borderColor = 'var(--accent)'; codeBox.style.background = 'var(--bg-tertiary)'; };

  const codeText = document.createElement('div');
  codeText.style.cssText = 'font-family:monospace;font-size:1.5rem;font-weight:700;color:var(--accent);letter-spacing:2px;';
  codeText.textContent = data.code;

  const clickHint = document.createElement('div');
  clickHint.style.cssText = 'font-size:0.75rem;color:var(--gray);margin-top:8px;';
  clickHint.textContent = 'Click to copy';

  codeBox.append(codeText, clickHint);

  // Copy handler
  codeBox.onclick = async () => {
    try {
      await navigator.clipboard.writeText(data.code);
      clickHint.textContent = 'Copied!';
      clickHint.style.color = '#10b981';
      codeBox.style.borderColor = '#10b981';
      setTimeout(() => {
        clickHint.textContent = 'Click to copy';
        clickHint.style.color = 'var(--gray)';
        codeBox.style.borderColor = 'var(--accent)';
      }, 2000);
    } catch (e) {
      clickHint.textContent = 'Copy failed';
      clickHint.style.color = '#ef4444';
    }
  };

  // Details
  const details = document.createElement('div');
  details.style.cssText = 'font-size:0.8rem;color:var(--gray);margin-bottom:20px;';
  let detailText = 'Max uses: ' + data.max_uses;
  if (data.auto_approve) detailText += ' \u2022 Auto-approve';
  if (data.expires_at) detailText += ' \u2022 Expires ' + new Date(data.expires_at * 1000).toLocaleDateString();
  details.textContent = detailText;

  // Close button
  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn';
  closeBtn.style.cssText = 'width:100%;padding:12px;background:linear-gradient(135deg,#7c3aed 0%,#6d28d9 100%);font-weight:600;';
  closeBtn.textContent = 'Done';
  closeBtn.onclick = () => overlay.remove();

  // Assemble
  card.append(iconDiv, title, subtitle, codeBox, details, closeBtn);
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  // Close on overlay click (not card)
  overlay.onclick = (e) => {
    if (e.target === overlay) overlay.remove();
  };

  // Close on Escape
  const escHandler = (e) => {
    if (e.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', escHandler);
    }
  };
  document.addEventListener('keydown', escHandler);
}

// ============================================
// Quick Filter
// ============================================

export function setInviteQuickFilter(filter) {
  inviteQuickFilter = filter;
  document.querySelectorAll('#invites .btn').forEach(btn => {
    if (btn.id && btn.id.includes('Invites')) btn.classList.remove('filter-active');
  });
  const activeBtn = document.getElementById(`quickFilter${filter.charAt(0).toUpperCase() + filter.slice(1)}Invites`);
  if (activeBtn) activeBtn.classList.add('filter-active');
  store.pagination.invites.page = 0;
  renderInvites();
}

// ============================================
// Debounced Search
// ============================================

export const debouncedRenderInvites = debounce(() => renderInvites(), 300);

// ============================================
// Card Rendering for Mobile
// ============================================

export function renderInvitesCards(invites) {
  const cardContainer = document.getElementById('invitesCardContainer');
  if (!cardContainer) return;

  cardContainer.replaceChildren();
  const now = Date.now();

  invites.forEach(i => {
    const card = document.createElement('div');
    card.className = 'data-card';

    const expiresParsed = parseTimestamp(i.expires_at);
    const expiresAt = expiresParsed ? expiresParsed.getTime() : null;
    const daysLeft = expiresAt ? Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)) : null;
    const isExpired = expiresAt && expiresAt < now;
    const isExpiringSoon = daysLeft && daysLeft < 7 && daysLeft > 0;

    let statusText = 'Active';
    let statusColor = '#10b981';
    let actualStatus = i.status;
    if (i.status === 'expired' || isExpired) {
      statusText = 'Expired';
      statusColor = '#ef4444';
      actualStatus = 'expired';
    } else if (i.status === 'exhausted') {
      statusText = 'Exhausted';
      statusColor = '#6b7280';
    } else if (isExpiringSoon) {
      statusText = 'Expiring Soon';
      statusColor = '#f59e0b';
    }

    // Header
    const header = document.createElement('div');
    header.className = 'data-card-header';
    const headerInner = document.createElement('div');
    headerInner.style.cssText = 'display:flex;align-items:center;gap:12px;flex:1;';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.name = 'invite-select';
    cb.className = 'invites-checkbox';
    cb.dataset.code = i.code;
    cb.dataset.status = actualStatus;
    cb.dataset.action = 'invite-select';
    cb.style.cssText = 'width:18px;height:18px;cursor:pointer;';
    const title = document.createElement('div');
    title.className = 'data-card-title';
    title.style.fontFamily = 'monospace';
    title.textContent = i.code;
    headerInner.append(cb, title);
    header.appendChild(headerInner);

    // Body
    const body = document.createElement('div');
    body.className = 'data-card-body';

    // Status row
    const statusRow = document.createElement('div');
    statusRow.className = 'data-card-row';
    const statusLabel = document.createElement('span');
    statusLabel.className = 'data-card-label';
    statusLabel.textContent = 'Status:';
    const statusBadge = document.createElement('span');
    statusBadge.className = 'data-card-badge';
    statusBadge.style.cssText = `background:${statusColor};font-size:0.65rem;`;
    statusBadge.textContent = statusText;
    statusRow.append(statusLabel, statusBadge);
    body.appendChild(statusRow);

    // Usage row
    const used = i.used || 0;
    const maxUses = i.max_uses || 1;
    const usageRow = document.createElement('div');
    usageRow.className = 'data-card-row';
    const usageLabel = document.createElement('span');
    usageLabel.className = 'data-card-label';
    usageLabel.textContent = 'Usage:';
    const usageValue = document.createElement('span');
    usageValue.className = 'data-card-value';
    usageValue.textContent = `${used} / ${maxUses}`;
    usageRow.append(usageLabel, usageValue);
    body.appendChild(usageRow);

    // Sent to row
    if (i.sent_to) {
      const sentRow = document.createElement('div');
      sentRow.className = 'data-card-row';
      const sentLabel = document.createElement('span');
      sentLabel.className = 'data-card-label';
      sentLabel.textContent = 'Sent to:';
      const sentValue = document.createElement('span');
      sentValue.className = 'data-card-value';
      sentValue.textContent = i.sent_to;
      sentRow.append(sentLabel, sentValue);
      body.appendChild(sentRow);
    }

    // Expires row
    if (expiresParsed) {
      const expiresRow = document.createElement('div');
      expiresRow.className = 'data-card-row';
      const expiresLabel = document.createElement('span');
      expiresLabel.className = 'data-card-label';
      expiresLabel.textContent = 'Expires:';
      const expiresValue = document.createElement('span');
      expiresValue.className = 'data-card-value';
      expiresValue.textContent = expiresParsed.toLocaleDateString();
      expiresRow.append(expiresLabel, expiresValue);
      body.appendChild(expiresRow);
    }

    card.append(header, body);
    cardContainer.appendChild(card);
  });
}

// ============================================
// Modal Helper
// ============================================

export function openCreateInviteModal() {
  const modal = document.getElementById('createInviteModal');
  if (modal) {
    // Reset form fields
    const maxUsesEl = document.getElementById('inviteMaxUses');
    const expiresEl = document.getElementById('inviteExpires');
    const sendToEl = document.getElementById('inviteSendTo');
    if (maxUsesEl) maxUsesEl.value = '1';
    if (expiresEl) expiresEl.value = '';
    if (sendToEl) sendToEl.value = '';
    modal.classList.add('active');
  }
}

export function closeCreateInviteModal() {
  const modal = document.getElementById('createInviteModal');
  if (modal) modal.classList.remove('active');
  const msgEl = document.getElementById('inviteMsg');
  if (msgEl) msgEl.textContent = '';
}

export function setupInviteEventHandlers() {
  // Quick filter buttons for Invites tab
  const activeBtn = document.getElementById('quickFilterActiveInvites');
  const expiringBtn = document.getElementById('quickFilterExpiringSoonInvites');
  const usedBtn = document.getElementById('quickFilterUsedInvites');

  if (activeBtn) {
    activeBtn.onclick = () => setInviteQuickFilter('active');
  }

  if (expiringBtn) {
    expiringBtn.onclick = () => setInviteQuickFilter('expiring');
  }

  if (usedBtn) {
    usedBtn.onclick = () => setInviteQuickFilter('used');
  }

  // Select all checkbox
  const selectAll = document.getElementById('selectAllInvites');
  if (selectAll) {
    selectAll.onchange = () => {
      document.querySelectorAll('.invites-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
      });
      updateInvitesSelectedCount();
    };
  }

  // Invite checkbox change handler (delegated)
  document.addEventListener('change', (e) => {
    if (e.target.classList.contains('invites-checkbox')) {
      updateInvitesSelectedCount();
    }
  });

  // Search input
  const searchInput = document.getElementById('invitesSearch');
  if (searchInput) {
    searchInput.oninput = (e) => {
      store.pagination.invites.search = e.target.value;
      debouncedRenderInvites();
    };
  }

  // Refresh button
  const refreshBtn = document.getElementById('refreshInvites');
  if (refreshBtn) {
    refreshBtn.onclick = () => loadInvites();
  }
}
