/**
 * Admin Portal Help Offers Module
 *
 * Volunteer help offer management, filtering, and status updates.
 * Note: API endpoints still use "help-requests" for backwards compatibility.
 */

import {
  api,
  showToast,
  isAdmin,
  showLoadingSkeleton,
  debounce,
  parseTimestamp
} from './core.js';

// ============================================
// State
// ============================================

let helpRequests = [];
let helpQuickFilter = 'new';
let helpSearchQuery = '';
let currentHelpRequest = null;

const helpPagination = { page: 0, perPage: 10 };

// Help type labels for display
const helpTypeLabels = {
  legal: 'Legal',
  developer: 'Developer',
  beta_tester: 'Beta Tester',
  donation: 'Donation/Funding',
  marketing: 'Marketing/PR',
  design: 'Design/UX',
  community: 'Community/Advocacy',
  other: 'Other',
};

// Status colors for badges
const statusColors = {
  new: '#3b82f6',
  contacted: '#f59e0b',
  in_progress: '#10b981',
  archived: '#6b7280',
};

// ============================================
// Load Help Offers
// ============================================

export async function loadHelpRequests(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) helpPagination.page = 0;

  const tbody = document.getElementById('helpRequestsBody');
  if (!tbody) return;

  // Show loading skeleton
  showLoadingSkeleton('helpRequestsTable');

  try {
    // Build query params
    const params = new URLSearchParams();
    if (helpQuickFilter) params.set('status', helpQuickFilter);

    const data = await api('/admin/help-requests?' + params.toString());
    helpRequests = data.help_requests || [];

    // Update status counts
    updateHelpStatusCounts();
    renderHelpRequests();
  } catch (e) {
    console.error('Error loading help offers:', e);
    tbody.replaceChildren();
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.className = 'muted';
    td.textContent = 'Error: ' + (e.message || String(e));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

// ============================================
// Update Status Badge Counts
// ============================================

function updateHelpStatusCounts() {
  // Count by status - need to load all to get accurate counts
  api('/admin/help-requests').then(data => {
    const all = data.help_requests || [];
    const counts = {
      new: 0,
      contacted: 0,
      in_progress: 0,
      archived: 0,
    };
    all.forEach(r => {
      if (counts.hasOwnProperty(r.status)) counts[r.status]++;
    });

    const newCount = document.getElementById('newHelpCount');
    const contactedCount = document.getElementById('contactedHelpCount');
    const inProgressCount = document.getElementById('inProgressHelpCount');
    const archivedCount = document.getElementById('archivedHelpCount');

    if (newCount) newCount.textContent = counts.new;
    if (contactedCount) contactedCount.textContent = counts.contacted;
    if (inProgressCount) inProgressCount.textContent = counts.in_progress;
    if (archivedCount) archivedCount.textContent = counts.archived;
  }).catch(console.error);
}

// ============================================
// Render Help Offers Table
// ============================================

export function renderHelpRequests() {
  const tbody = document.getElementById('helpRequestsBody');
  const cardContainer = document.getElementById('helpRequestsCardContainer');
  if (!tbody) return;

  tbody.replaceChildren();
  if (cardContainer) cardContainer.replaceChildren();

  // Apply search filter
  let filtered = helpRequests;
  if (helpSearchQuery) {
    const q = helpSearchQuery.toLowerCase();
    filtered = filtered.filter(r =>
      (r.name || '').toLowerCase().includes(q) ||
      (r.email || '').toLowerCase().includes(q) ||
      (r.message || '').toLowerCase().includes(q)
    );
  }

  // Apply pagination
  const start = helpPagination.page * helpPagination.perPage;
  const end = start + helpPagination.perPage;
  const paginated = filtered.slice(start, end);

  if (paginated.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.className = 'muted';
    td.style.textAlign = 'center';
    td.style.padding = '40px';
    td.textContent = filtered.length === 0 ? 'No help offers found' : 'No matching results';
    tr.appendChild(td);
    tbody.appendChild(tr);
    updateHelpSelectedCount();
    return;
  }

  paginated.forEach(request => {
    // Desktop table row
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = () => openHelpDetailModal(request);

    // Checkbox cell
    const tdCheck = document.createElement('td');
    tdCheck.onclick = e => e.stopPropagation();
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'help-checkbox';
    cb.dataset.id = request.request_id;
    cb.dataset.status = request.status || 'new';
    cb.onchange = updateHelpSelectedCount;
    tdCheck.appendChild(cb);
    tr.appendChild(tdCheck);

    // Name
    const tdName = document.createElement('td');
    tdName.textContent = request.name || '-';
    tr.appendChild(tdName);

    // Email
    const tdEmail = document.createElement('td');
    const emailLink = document.createElement('a');
    emailLink.href = 'mailto:' + encodeURIComponent(request.email);
    emailLink.textContent = request.email;
    emailLink.style.color = 'var(--accent)';
    emailLink.onclick = e => e.stopPropagation();
    tdEmail.appendChild(emailLink);
    tr.appendChild(tdEmail);

    // Phone
    const tdPhone = document.createElement('td');
    const phoneLink = document.createElement('a');
    phoneLink.href = 'tel:' + encodeURIComponent(request.phone);
    phoneLink.textContent = request.phone;
    phoneLink.style.color = 'var(--accent)';
    phoneLink.onclick = e => e.stopPropagation();
    tdPhone.appendChild(phoneLink);
    tr.appendChild(tdPhone);

    // Help Types
    const tdTypes = document.createElement('td');
    const typesContainer = document.createElement('div');
    typesContainer.style.display = 'flex';
    typesContainer.style.flexWrap = 'wrap';
    typesContainer.style.gap = '4px';
    (request.help_types || []).forEach(type => {
      const badge = document.createElement('span');
      badge.textContent = helpTypeLabels[type] || type;
      badge.style.cssText = 'background:var(--bg-tertiary);color:var(--text);padding:2px 8px;border-radius:4px;font-size:0.75rem;';
      typesContainer.appendChild(badge);
    });
    tdTypes.appendChild(typesContainer);
    tr.appendChild(tdTypes);

    // Status
    const tdStatus = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.textContent = (request.status || 'new').replace('_', ' ');
    statusBadge.style.cssText = 'background:' + (statusColors[request.status] || '#6b7280') + ';color:#fff;padding:4px 10px;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:capitalize;';
    tdStatus.appendChild(statusBadge);
    tr.appendChild(tdStatus);

    // Submitted date
    const tdDate = document.createElement('td');
    const date = parseTimestamp(request.created_at);
    tdDate.textContent = date ? date.toLocaleDateString() : '-';
    tr.appendChild(tdDate);

    // Actions
    const tdActions = document.createElement('td');
    const viewBtn = document.createElement('button');
    viewBtn.className = 'btn';
    viewBtn.style.cssText = 'padding:6px 12px;font-size:0.8rem;';
    viewBtn.textContent = 'View';
    viewBtn.onclick = e => {
      e.stopPropagation();
      openHelpDetailModal(request);
    };
    tdActions.appendChild(viewBtn);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);

    // Mobile card
    if (cardContainer) {
      const card = document.createElement('div');
      card.className = 'data-card';
      card.onclick = () => openHelpDetailModal(request);

      const header = document.createElement('div');
      header.className = 'data-card-header';

      const title = document.createElement('div');
      title.className = 'data-card-title';
      title.textContent = request.name || 'Unknown';
      header.appendChild(title);

      const badge = document.createElement('div');
      badge.className = 'data-card-badge';
      badge.textContent = (request.status || 'new').replace('_', ' ');
      badge.style.background = statusColors[request.status] || '#6b7280';
      header.appendChild(badge);

      card.appendChild(header);

      const body = document.createElement('div');
      body.className = 'data-card-body';

      body.appendChild(createHelpCardRow('Email', request.email));
      body.appendChild(createHelpCardRow('Phone', request.phone));
      body.appendChild(createHelpCardRow('Help Types', (request.help_types || []).map(t => helpTypeLabels[t] || t).join(', ')));
      body.appendChild(createHelpCardRow('Submitted', date ? date.toLocaleDateString() : '-'));

      card.appendChild(body);
      cardContainer.appendChild(card);
    }
  });

  // Update pagination info
  const infoEl = document.getElementById('helpInfo');
  if (infoEl) {
    const total = filtered.length;
    const showing = Math.min(end, total);
    infoEl.textContent = (start + 1) + '-' + showing + ' of ' + total;
  }

  // Update pagination buttons
  const prevBtn = document.getElementById('helpPrev');
  const nextBtn = document.getElementById('helpNext');
  if (prevBtn) prevBtn.disabled = helpPagination.page === 0;
  if (nextBtn) nextBtn.disabled = end >= filtered.length;

  // Reset select all and update bulk bar
  const selectAll = document.getElementById('selectAllHelp');
  if (selectAll) selectAll.checked = false;
  updateHelpSelectedCount();
}

// Helper function for mobile card rows
function createHelpCardRow(label, value) {
  const row = document.createElement('div');
  row.className = 'data-card-row';
  const labelSpan = document.createElement('span');
  labelSpan.className = 'data-card-label';
  labelSpan.textContent = label + ':';
  const valueSpan = document.createElement('span');
  valueSpan.className = 'data-card-value';
  valueSpan.textContent = value;
  row.appendChild(labelSpan);
  row.appendChild(valueSpan);
  return row;
}

// ============================================
// Help Offer Detail Modal
// ============================================

export function openHelpDetailModal(request) {
  currentHelpRequest = request;
  const modal = document.getElementById('helpDetailModal');
  if (!modal) return;

  // Populate modal fields
  document.getElementById('helpDetailName').textContent = request.name || '-';

  const emailLink = document.getElementById('helpDetailEmailLink');
  emailLink.href = 'mailto:' + encodeURIComponent(request.email);
  emailLink.textContent = request.email;

  const phoneLink = document.getElementById('helpDetailPhoneLink');
  phoneLink.href = 'tel:' + encodeURIComponent(request.phone);
  phoneLink.textContent = request.phone;

  // LinkedIn section
  const linkedinSection = document.getElementById('helpDetailLinkedInSection');
  const linkedinLink = document.getElementById('helpDetailLinkedInLink');
  if (request.linkedin_url) {
    linkedinSection.style.display = 'block';
    linkedinLink.href = request.linkedin_url;
    linkedinLink.textContent = request.linkedin_url;
  } else {
    linkedinSection.style.display = 'none';
  }

  // Help types
  const typesContainer = document.getElementById('helpDetailTypes');
  typesContainer.replaceChildren();
  (request.help_types || []).forEach(type => {
    const badge = document.createElement('span');
    badge.textContent = helpTypeLabels[type] || type;
    badge.style.cssText = 'display:inline-block;background:var(--bg-tertiary);color:var(--text);padding:4px 12px;border-radius:4px;font-size:0.85rem;margin-right:8px;margin-bottom:8px;';
    typesContainer.appendChild(badge);
  });

  // Message
  const messageEl = document.getElementById('helpDetailMessage');
  if (messageEl) messageEl.textContent = request.message || '-';

  // Status select (HTML uses helpDetailStatus)
  const statusSelect = document.getElementById('helpDetailStatus');
  if (statusSelect) {
    statusSelect.value = request.status || 'new';
  }

  // Admin notes (HTML uses helpDetailNotes)
  const notesTextarea = document.getElementById('helpDetailNotes');
  if (notesTextarea) {
    notesTextarea.value = request.admin_notes || '';
  }

  // Submitted date
  const date = parseTimestamp(request.created_at);
  const submittedEl = document.getElementById('helpDetailSubmitted');
  if (submittedEl) submittedEl.textContent = date ? date.toLocaleString() : '-';

  modal.classList.add('active');
}

export function closeHelpDetailModal() {
  const modal = document.getElementById('helpDetailModal');
  if (modal) modal.classList.remove('active');
  currentHelpRequest = null;
}

// ============================================
// Save Help Offer
// ============================================

export async function saveHelpRequest() {
  if (!currentHelpRequest) return;

  const statusSelect = document.getElementById('helpDetailStatus');
  const notesTextarea = document.getElementById('helpDetailNotes');

  const newStatus = statusSelect?.value;
  const adminNotes = notesTextarea?.value || '';

  try {
    await api('/admin/help-requests/' + currentHelpRequest.request_id, {
      method: 'PATCH',
      body: JSON.stringify({
        status: newStatus,
        admin_notes: adminNotes,
      }),
    });
    showToast('Help offer updated', 'success');
    closeHelpDetailModal();
    loadHelpRequests(false);
  } catch (e) {
    console.error('Error updating help offer:', e);
    showToast('Error: ' + (e.message || 'Failed to update'), 'error');
  }
}

// ============================================
// Filter Setters
// ============================================

export function setHelpQuickFilter(filter) {
  helpQuickFilter = filter;
  document.querySelectorAll('.help-filter').forEach(b => b.classList.remove('active'));
  const filterMap = {
    new: 'helpFilterNew',
    contacted: 'helpFilterContacted',
    in_progress: 'helpFilterInProgress',
    archived: 'helpFilterArchived',
  };
  const btnId = filterMap[filter];
  if (btnId) document.getElementById(btnId)?.classList.add('active');
  loadHelpRequests();
}

export function setHelpSearchQuery(query) {
  helpSearchQuery = query;
  helpPagination.page = 0;
  renderHelpRequests();
}

// ============================================
// Event Handlers Setup
// ============================================

export function setupHelpRequestsEventHandlers() {
  // Filter buttons
  document.getElementById('helpFilterNew')?.addEventListener('click', () => setHelpQuickFilter('new'));
  document.getElementById('helpFilterContacted')?.addEventListener('click', () => setHelpQuickFilter('contacted'));
  document.getElementById('helpFilterInProgress')?.addEventListener('click', () => setHelpQuickFilter('in_progress'));
  document.getElementById('helpFilterArchived')?.addEventListener('click', () => setHelpQuickFilter('archived'));

  // Refresh button
  document.getElementById('refreshHelpRequests')?.addEventListener('click', () => loadHelpRequests());

  // Search input
  const helpSearchInput = document.getElementById('helpSearch');
  if (helpSearchInput) {
    helpSearchInput.addEventListener('input', debounce(() => {
      setHelpSearchQuery(helpSearchInput.value.trim());
    }, 300));
  }

  // Pagination controls
  document.getElementById('helpPerPage')?.addEventListener('change', (e) => {
    helpPagination.perPage = parseInt(e.target.value, 10);
    helpPagination.page = 0;
    renderHelpRequests();
  });

  document.getElementById('helpPrev')?.addEventListener('click', () => {
    if (helpPagination.page > 0) {
      helpPagination.page--;
      renderHelpRequests();
    }
  });

  document.getElementById('helpNext')?.addEventListener('click', () => {
    helpPagination.page++;
    renderHelpRequests();
  });

  // Modal close handlers
  document.getElementById('closeHelpDetailModal')?.addEventListener('click', closeHelpDetailModal);
  document.getElementById('helpDetailModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'helpDetailModal') closeHelpDetailModal();
  });

  // Save button handler
  document.getElementById('saveHelpRequest')?.addEventListener('click', saveHelpRequest);

  // Quick action buttons in detail modal
  document.getElementById('helpCopyEmail')?.addEventListener('click', () => {
    if (currentHelpRequest?.email) {
      navigator.clipboard.writeText(currentHelpRequest.email);
      showToast('Email copied to clipboard', 'success');
    }
  });

  document.getElementById('helpCopyPhone')?.addEventListener('click', () => {
    if (currentHelpRequest?.phone) {
      navigator.clipboard.writeText(currentHelpRequest.phone);
      showToast('Phone copied to clipboard', 'success');
    }
  });

  document.getElementById('helpSendEmail')?.addEventListener('click', () => {
    if (currentHelpRequest?.email) {
      // Open default mail client with pre-filled email
      window.location.href = 'mailto:' + encodeURIComponent(currentHelpRequest.email);
    }
  });

  document.getElementById('helpQuickArchive')?.addEventListener('click', async () => {
    if (currentHelpRequest) {
      try {
        await api('/admin/help-requests/' + currentHelpRequest.request_id, {
          method: 'PATCH',
          body: JSON.stringify({ status: 'archived' }),
        });
        showToast('Help offer archived', 'success');
        closeHelpDetailModal();
        loadHelpRequests(false);
      } catch (e) {
        showToast('Error: ' + (e.message || e), 'error');
      }
    }
  });

  // Select all checkbox
  const selectAllHelp = document.getElementById('selectAllHelp');
  if (selectAllHelp) {
    selectAllHelp.onchange = () => {
      document.querySelectorAll('.help-checkbox').forEach(cb => {
        cb.checked = selectAllHelp.checked;
      });
      updateHelpSelectedCount();
    };
  }

  // Bulk action buttons
  document.getElementById('helpBulkContacted')?.addEventListener('click', () => bulkUpdateHelpStatus('contacted'));
  document.getElementById('helpBulkInProgress')?.addEventListener('click', () => bulkUpdateHelpStatus('in_progress'));
  document.getElementById('helpBulkArchive')?.addEventListener('click', () => bulkUpdateHelpStatus('archived'));
}

// ============================================
// Selection Management
// ============================================

export function updateHelpSelectedCount() {
  const checkboxes = document.querySelectorAll('.help-checkbox:checked');
  const count = checkboxes.length;

  // Update bulk bar visibility and count
  const bulkBar = document.getElementById('helpBulkBar');
  const countEl = document.getElementById('helpBulkCount');
  if (bulkBar) bulkBar.classList.toggle('active', count > 0);
  if (countEl) countEl.textContent = count;

  // Update select all checkbox state
  const selectAll = document.getElementById('selectAllHelp');
  const allCheckboxes = document.querySelectorAll('.help-checkbox');
  if (selectAll && allCheckboxes.length > 0) {
    selectAll.checked = checkboxes.length === allCheckboxes.length;
    selectAll.indeterminate = checkboxes.length > 0 && checkboxes.length < allCheckboxes.length;
  }
}

// ============================================
// Bulk Actions
// ============================================

async function bulkUpdateHelpStatus(newStatus) {
  const checkboxes = document.querySelectorAll('.help-checkbox:checked');
  if (checkboxes.length === 0) {
    showToast('No items selected', 'warning');
    return;
  }

  const statusLabels = {
    contacted: 'Contacted',
    in_progress: 'In Progress',
    archived: 'Archived'
  };

  const confirmMsg = `Update ${checkboxes.length} help offer(s) to "${statusLabels[newStatus]}"?`;
  if (!confirm(confirmMsg)) return;

  let successCount = 0;
  let errorCount = 0;

  for (const cb of checkboxes) {
    try {
      await api('/admin/help-requests/' + cb.dataset.id, {
        method: 'PATCH',
        body: JSON.stringify({ status: newStatus }),
      });
      successCount++;
    } catch (e) {
      console.error('Error updating help offer:', cb.dataset.id, e);
      errorCount++;
    }
  }

  if (successCount > 0) {
    showToast(`Updated ${successCount} help offer(s)`, 'success');
  }
  if (errorCount > 0) {
    showToast(`Failed to update ${errorCount} offer(s)`, 'error');
  }

  // Clear selection and reload
  const selectAll = document.getElementById('selectAllHelp');
  if (selectAll) selectAll.checked = false;
  loadHelpRequests(false);
}
