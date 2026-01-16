/**
 * Admin Portal Membership Module
 *
 * Membership terms, subscriptions, subscription types management.
 * Uses safe DOM methods throughout.
 */

import {
  store,
  escapeHtml,
  api,
  showToast,
  isAdmin,
  idToken,
  refresh,
  showGridLoadingSkeleton,
  updatePagination,
  showLoadingSkeleton,
  config
} from './core.js';

// ============================================
// Membership Terms State
// ============================================

let termsNextCursor = null;
let termsHasMore = false;

// ============================================
// Membership Terms Functions
// ============================================

export async function loadCurrentTerms(append = false) {
  if (!isAdmin()) return;

  const currentDisplay = document.getElementById('currentTermsDisplay');
  const previousDisplay = document.getElementById('previousTermsDisplay');

  if (!currentDisplay || !previousDisplay) return;

  // Show loading skeletons only on initial load
  if (!append) {
    showGridLoadingSkeleton('currentTermsDisplay', 1);
    showGridLoadingSkeleton('previousTermsDisplay', 2);
    termsNextCursor = null;
  }

  try {
    await refresh();

    // Load terms with pagination
    let url = config.apiUrl + '/admin/membership-terms?limit=20';
    if (append && termsNextCursor) {
      url += '&cursor=' + encodeURIComponent(termsNextCursor);
    }
    const res = await fetch(url, {
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });
    if (!res.ok) throw new Error('Failed to load membership terms');

    const data = await res.json();
    const current = data.current;
    const previous = data.previous || [];
    termsHasMore = data.pagination?.has_more || false;
    termsNextCursor = data.pagination?.next_cursor || null;

    // Display current version (only on initial load)
    if (!append) {
      currentDisplay.replaceChildren();
      if (current) {
        const createdDate = new Date(current.created_at).toLocaleString();
        const card = createCurrentTermsCard(current, createdDate);
        currentDisplay.appendChild(card);
      } else {
        const emptyMsg = document.createElement('p');
        emptyMsg.className = 'muted';
        emptyMsg.style.cssText = 'grid-column:1/-1;text-align:center;padding:40px;';
        emptyMsg.textContent = 'No current terms found. Create the first version above.';
        currentDisplay.appendChild(emptyMsg);
      }
    }

    // Display previous versions
    if (previous.length > 0) {
      if (!append) previousDisplay.replaceChildren();
      else {
        // Remove existing load more button
        const existingBtn = previousDisplay.querySelector('.load-more-terms');
        if (existingBtn) existingBtn.remove();
      }

      previous.forEach(term => {
        const row = createPreviousTermsRow(term);
        previousDisplay.appendChild(row);
      });

      // Add load more button if there are more results
      if (termsHasMore) {
        const loadMoreDiv = document.createElement('div');
        loadMoreDiv.className = 'load-more-terms';
        loadMoreDiv.style.cssText = 'grid-column:1/-1;text-align:center;padding:12px;';
        const loadMoreBtn = document.createElement('button');
        loadMoreBtn.className = 'btn btn-secondary';
        loadMoreBtn.style.padding = '8px 24px';
        loadMoreBtn.textContent = 'Load More';
        loadMoreBtn.dataset.action = 'load-more-terms';
        loadMoreDiv.appendChild(loadMoreBtn);
        previousDisplay.appendChild(loadMoreDiv);
      }
    } else if (!append) {
      previousDisplay.replaceChildren();
      const emptyMsg = document.createElement('p');
      emptyMsg.className = 'muted';
      emptyMsg.style.cssText = 'text-align:center;padding:20px;';
      emptyMsg.textContent = 'No previous versions';
      previousDisplay.appendChild(emptyMsg);
    }
  } catch (e) {
    console.error('Error loading membership terms:', e);
    if (!append) {
      currentDisplay.replaceChildren();
      previousDisplay.replaceChildren();
      const errMsg = document.createElement('p');
      errMsg.className = 'muted';
      errMsg.style.cssText = 'grid-column:1/-1;text-align:center;padding:20px;';
      errMsg.textContent = 'Error loading membership terms. Please try refreshing the page.';
      currentDisplay.appendChild(errMsg);
    } else {
      showToast('Failed to load more terms', 'error');
    }
  }
}

function createCurrentTermsCard(current, createdDate) {
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--bg-card);border:1px solid #10b981;border-radius:8px;padding:12px;box-sizing:border-box;min-width:0;display:flex;flex-direction:column;';

  // Badge
  const badgeDiv = document.createElement('div');
  badgeDiv.style.marginBottom = '8px';
  const badge = document.createElement('span');
  badge.style.cssText = 'display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
  badge.textContent = 'Current Version';
  badgeDiv.appendChild(badge);

  // Title
  const title = document.createElement('h4');
  title.style.cssText = 'margin:0 0 8px 0;font-weight:700;font-size:0.95rem;';
  title.textContent = 'Version ' + current.version_id;

  // Info box
  const infoBox = document.createElement('div');
  infoBox.style.cssText = 'margin-bottom:12px;padding:10px;background:var(--bg-input);border-radius:6px;border:1px solid var(--border);';

  const createdRow = document.createElement('div');
  createdRow.style.cssText = 'margin-bottom:6px;font-size:0.8rem;';
  const createdLabel = document.createElement('span');
  createdLabel.style.color = 'var(--gray)';
  createdLabel.textContent = 'Created: ';
  const createdValue = document.createElement('span');
  createdValue.style.fontWeight = '600';
  createdValue.textContent = createdDate;
  createdRow.append(createdLabel, createdValue);

  const byRow = document.createElement('div');
  byRow.style.cssText = 'margin-bottom:6px;font-size:0.8rem;';
  const byLabel = document.createElement('span');
  byLabel.style.color = 'var(--gray)';
  byLabel.textContent = 'Created by: ';
  const byValue = document.createElement('span');
  byValue.style.fontWeight = '600';
  byValue.textContent = current.created_by;
  byRow.append(byLabel, byValue);

  infoBox.append(createdRow, byRow);

  // View button
  const btnWrapper = document.createElement('div');
  btnWrapper.style.marginTop = 'auto';
  const viewBtn = document.createElement('button');
  viewBtn.className = 'btn';
  viewBtn.style.cssText = 'display:block;width:100%;box-sizing:border-box;text-align:center;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;padding:8px 12px;font-size:0.8rem;font-weight:600;border-radius:12px;border:none;cursor:pointer;';
  viewBtn.textContent = 'View Terms';
  viewBtn.dataset.action = 'view-terms';
  viewBtn.dataset.versionId = current.version_id;
  btnWrapper.appendChild(viewBtn);

  card.append(badgeDiv, title, infoBox, btnWrapper);
  return card;
}

function createPreviousTermsRow(term) {
  const row = document.createElement('div');
  row.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;';

  const infoDiv = document.createElement('div');
  infoDiv.style.cssText = 'flex:1;min-width:200px;';

  const versionBtn = document.createElement('button');
  versionBtn.style.cssText = 'background:none;border:none;color:var(--accent);cursor:pointer;font-weight:700;font-size:0.95rem;display:inline-flex;align-items:center;gap:6px;padding:0;';
  versionBtn.textContent = 'Version ' + term.version_id;
  versionBtn.dataset.action = 'view-terms';
  versionBtn.dataset.versionId = term.version_id;

  const metaDiv = document.createElement('div');
  metaDiv.style.cssText = 'font-size:0.8rem;color:var(--gray);margin-top:4px;';
  const createdDate = new Date(term.created_at).toLocaleString();
  metaDiv.textContent = `Created: ${createdDate} • By: ${term.created_by}`;

  infoDiv.append(versionBtn, metaDiv);
  row.appendChild(infoDiv);
  return row;
}

export async function viewTerms(versionId, btn) {
  const originalText = btn.textContent;
  btn.textContent = 'Loading...';
  btn.disabled = true;

  try {
    await refresh();
    const res = await fetch(config.apiUrl + '/admin/membership-terms/' + encodeURIComponent(versionId) + '/download', {
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });
    if (!res.ok) throw new Error('Failed to get download URL');
    const data = await res.json();
    window.open(data.download_url, '_blank');
  } catch (e) {
    showToast('Failed to load terms: ' + (e.message || e), 'error');
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

export async function createMembershipTerms() {
  const termsText = document.getElementById('newTermsText')?.value.trim();
  const msgEl = document.getElementById('termsMsg');
  const createBtn = document.getElementById('createTermsBtn');
  const textArea = document.getElementById('newTermsText');

  if (!termsText) {
    if (msgEl) {
      msgEl.textContent = 'Please enter terms text';
      msgEl.style.color = '#ef4444';
    }
    return;
  }

  // Show loading state
  if (msgEl) {
    msgEl.textContent = 'Creating new version...';
    msgEl.style.color = 'var(--accent)';
  }
  if (createBtn) createBtn.disabled = true;
  if (textArea) textArea.disabled = true;

  try {
    const data = await api('/admin/membership-terms', {
      method: 'POST',
      body: JSON.stringify({ terms_text: termsText })
    });
    showToast(`New version created successfully! Version: ${data.version_id}`, 'success');
    if (textArea) textArea.value = '';
    if (msgEl) msgEl.textContent = '';
    closeCreateTermsModal();
    await loadCurrentTerms();
  } catch (e) {
    if (msgEl) {
      msgEl.textContent = 'Error: ' + (e.message || e);
      msgEl.style.color = '#ef4444';
    }
  } finally {
    if (createBtn) createBtn.disabled = false;
    if (textArea) textArea.disabled = false;
  }
}

export function closeCreateTermsModal() {
  const modal = document.getElementById('createTermsModal');
  if (modal) modal.classList.remove('active');
  const msgEl = document.getElementById('termsMsg');
  if (msgEl) msgEl.textContent = '';
}

export function closeConfirmTermsModal() {
  const modal = document.getElementById('confirmTermsModal');
  if (modal) modal.classList.remove('active');
}

// ============================================
// Subscription Types State
// ============================================

let subscriptionTypesFilter = 'all';

// ============================================
// Subscription Types Functions
// ============================================

export async function loadSubscriptionTypes() {
  if (!isAdmin()) return;

  const container = document.getElementById('subscriptionTypesContainer');
  if (!container) return;

  showGridLoadingSkeleton('subscriptionTypesContainer', 3);

  try {
    const data = await api('/admin/subscription-types');
    const types = data.subscription_types || data || [];
    store.subscriptionTypes = types;
    renderSubscriptionTypes();
  } catch (e) {
    container.replaceChildren();
    const errMsg = document.createElement('div');
    errMsg.className = 'empty-state';
    const errTitle = document.createElement('div');
    errTitle.className = 'empty-state-title';
    errTitle.textContent = 'Error loading subscription types';
    const errText = document.createElement('div');
    errText.className = 'empty-state-text';
    errText.textContent = e.message || String(e);
    errMsg.append(errTitle, errText);
    container.appendChild(errMsg);
  }
}

export function renderSubscriptionTypes() {
  const container = document.getElementById('subscriptionTypesContainer');
  if (!container) return;

  const types = store.subscriptionTypes || [];
  let filtered = types;
  if (subscriptionTypesFilter === 'enabled') {
    filtered = types.filter(t => t.is_enabled);
  }

  container.replaceChildren();

  if (filtered.length === 0) {
    const emptyMsg = document.createElement('div');
    emptyMsg.className = 'empty-state';
    const emptyTitle = document.createElement('div');
    emptyTitle.className = 'empty-state-title';
    emptyTitle.textContent = 'No subscription types found';
    const emptyText = document.createElement('div');
    emptyText.className = 'empty-state-text';
    emptyText.textContent = 'Create a subscription type using the form above';
    emptyMsg.append(emptyTitle, emptyText);
    container.appendChild(emptyMsg);
    return;
  }

  filtered.forEach(type => {
    const card = createSubscriptionTypeCard(type);
    container.appendChild(card);
  });
}

function createSubscriptionTypeCard(type) {
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;';

  // Header
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;';

  const titleDiv = document.createElement('div');
  const title = document.createElement('h4');
  title.style.cssText = 'margin:0 0 4px 0;font-weight:700;';
  title.textContent = type.name;
  titleDiv.appendChild(title);

  const statusBadge = document.createElement('span');
  statusBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
  if (type.is_enabled) {
    statusBadge.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
    statusBadge.style.color = '#fff';
    statusBadge.textContent = 'Enabled';
  } else {
    statusBadge.style.background = 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
    statusBadge.style.color = '#fff';
    statusBadge.textContent = 'Disabled';
  }
  header.append(titleDiv, statusBadge);

  // Description
  const desc = document.createElement('p');
  desc.style.cssText = 'font-size:0.85rem;color:var(--gray);margin:0 0 12px 0;';
  desc.textContent = type.description || 'No description';

  // Details
  const details = document.createElement('div');
  details.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;';

  // Term
  const termDiv = document.createElement('div');
  const termLabel = document.createElement('span');
  termLabel.style.cssText = 'font-size:0.75rem;color:var(--gray);';
  termLabel.textContent = 'Term';
  const termValue = document.createElement('div');
  termValue.style.fontWeight = '600';
  termValue.textContent = `${type.term_value} ${type.term_unit}${type.term_value > 1 ? 's' : ''}`;
  termDiv.append(termLabel, termValue);

  // Price
  const priceDiv = document.createElement('div');
  const priceLabel = document.createElement('span');
  priceLabel.style.cssText = 'font-size:0.75rem;color:var(--gray);';
  priceLabel.textContent = 'Price';
  const priceValue = document.createElement('div');
  priceValue.style.fontWeight = '600';
  priceValue.textContent = type.price === 0 ? 'Free' : `${type.currency} ${type.price}`;
  priceDiv.append(priceLabel, priceValue);

  details.append(termDiv, priceDiv);

  // Toggle button
  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'btn';
  toggleBtn.style.cssText = 'width:100%;';
  toggleBtn.textContent = type.is_enabled ? 'Disable' : 'Enable';
  toggleBtn.style.background = type.is_enabled
    ? 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)'
    : 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
  toggleBtn.dataset.action = 'toggle-subscription-type';
  toggleBtn.dataset.typeId = type.type_id;
  toggleBtn.dataset.isEnabled = type.is_enabled;

  card.append(header, desc, details, toggleBtn);
  return card;
}

export async function toggleSubscriptionType(typeId, isEnabled) {
  const endpoint = isEnabled ? 'disable' : 'enable';
  try {
    await api(`/admin/subscription-types/${typeId}/${endpoint}`, { method: 'POST' });
    showToast(`Subscription type ${endpoint}d successfully`, 'success');
    await loadSubscriptionTypes();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function createSubscriptionType() {
  const name = document.getElementById('subTypeName')?.value.trim();
  const description = document.getElementById('subTypeDescription')?.value.trim();
  const termValue = parseInt(document.getElementById('subTermValue')?.value);
  const termUnit = document.getElementById('subTermUnit')?.value;
  const isFree = document.getElementById('subTypeFree')?.checked;
  const currency = document.getElementById('subTypeCurrency')?.value;
  const price = isFree ? 0 : parseFloat(document.getElementById('subTypePrice')?.value);
  const isOneTime = document.getElementById('subTypeOneTime')?.checked;
  const enabled = document.getElementById('subTypeEnabled')?.checked;
  const msgEl = document.getElementById('subscriptionTypeMsg');

  if (!name) { showFieldError(msgEl, 'Please enter a name'); return; }
  if (!description) { showFieldError(msgEl, 'Please enter a description'); return; }
  if (!termValue || termValue < 1) { showFieldError(msgEl, 'Please enter a valid term duration'); return; }
  if (!isFree && (isNaN(price) || price < 0)) { showFieldError(msgEl, 'Please enter a valid price'); return; }

  try {
    await api('/admin/subscription-types', {
      method: 'POST',
      body: JSON.stringify({
        name,
        description,
        term_value: termValue,
        term_unit: termUnit,
        currency,
        price,
        is_one_time_offer: isOneTime,
        enable_immediately: enabled
      })
    });
    showToast('Subscription type created successfully!', 'success');

    // Clear form
    document.getElementById('subTypeName').value = '';
    document.getElementById('subTypeDescription').value = '';
    document.getElementById('subTermValue').value = '';
    document.getElementById('subTypeFree').checked = false;
    document.getElementById('subTypePrice').value = '';
    document.getElementById('subTypeOneTime').checked = false;
    document.getElementById('subTypeEnabled').checked = false;
    document.getElementById('pricingFields').style.opacity = '1';
    document.getElementById('subTypeCurrency').disabled = false;
    document.getElementById('subTypePrice').disabled = false;

    closeCreateSubscriptionTypeModal();
    await loadSubscriptionTypes();
  } catch (e) {
    showFieldError(msgEl, 'Error: ' + (e.message || e));
  }
}

export function filterSubscriptionTypes(filter) {
  subscriptionTypesFilter = filter;
  document.querySelectorAll('#subscription-types .btn').forEach(btn => {
    if (btn.id && (btn.id === 'filterEnabledTypes' || btn.id === 'filterAllTypes')) {
      btn.classList.remove('filter-active');
    }
  });
  const activeBtn = document.getElementById(filter === 'enabled' ? 'filterEnabledTypes' : 'filterAllTypes');
  if (activeBtn) activeBtn.classList.add('filter-active');
  renderSubscriptionTypes();
}

export function closeCreateSubscriptionTypeModal() {
  const modal = document.getElementById('createSubscriptionTypeModal');
  if (modal) modal.classList.remove('active');
  const msgEl = document.getElementById('subscriptionTypeMsg');
  if (msgEl) msgEl.textContent = '';
}

// ============================================
// Subscriptions Management (All Subscriptions tab)
// ============================================

export async function loadAllSubscriptions(resetPage = true) {
  if (!isAdmin()) return;
  if (resetPage) store.pagination.subscriptions.page = 0;

  const tbody = document.querySelector('#subscriptionsTable tbody');
  showLoadingSkeleton('subscriptionsTable');

  try {
    if (resetPage || store.subscriptions.length === 0) {
      const data = await api('/admin/subscriptions');
      store.subscriptions = data.subscriptions || [];
    }
    renderSubscriptions();
  } catch (e) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'muted';
    td.textContent = 'Error: ' + (e.message || String(e));
    tr.appendChild(td);
    tbody.replaceChildren(tr);
  }
}

export function renderSubscriptions() {
  const tbody = document.querySelector('#subscriptionsTable tbody');
  if (!tbody) return;

  tbody.replaceChildren();

  // Apply quick filter
  let filtered = store.subscriptions.filter(s => {
    const quickFilter = store.filters.subscriptions || 'all';
    if (quickFilter === 'active' && s.status !== 'active') return false;
    if (quickFilter === 'expiring') {
      if (s.status !== 'active') return false;
      const expires = s.expires_at ? new Date(s.expires_at) : null;
      if (!expires) return false;
      const daysLeft = Math.ceil((expires - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysLeft > 30) return false;
    }
    if (quickFilter === 'expired' && s.status !== 'expired') return false;

    // Search filter
    const search = store.pagination.subscriptions.search?.toLowerCase() || '';
    if (search) {
      const matchesEmail = (s.email || '').toLowerCase().includes(search);
      const matchesName = (s.user_name || '').toLowerCase().includes(search);
      const matchesPlan = (s.subscription_type_name || '').toLowerCase().includes(search);
      if (!matchesEmail && !matchesName && !matchesPlan) return false;
    }

    return true;
  });

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.style.cssText = 'text-align:center;padding:40px;';
    td.textContent = 'No subscriptions found';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  const page = updatePagination('subscriptions', filtered);

  page.forEach(s => {
    const tr = document.createElement('tr');

    // Checkbox
    const td1 = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'subscription-checkbox';
    cb.dataset.id = s.subscription_id;
    cb.dataset.status = s.status;
    td1.appendChild(cb);

    // User
    const td2 = document.createElement('td');
    td2.textContent = s.user_name || s.email || '—';

    // Plan
    const td3 = document.createElement('td');
    td3.textContent = s.subscription_type_name || s.plan || '—';

    // Status
    const td4 = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
    const statusColors = { active: '#10b981', expired: '#ef4444', cancelled: '#f59e0b' };
    statusBadge.style.background = statusColors[s.status] || '#6b7280';
    statusBadge.style.color = '#fff';
    statusBadge.textContent = s.status || 'Unknown';
    td4.appendChild(statusBadge);

    // Start Date
    const td5 = document.createElement('td');
    td5.textContent = s.started_at ? new Date(s.started_at).toLocaleDateString() : '—';

    // Expiry Date
    const td6 = document.createElement('td');
    td6.textContent = s.expires_at ? new Date(s.expires_at).toLocaleDateString() : '—';

    // Actions
    const td7 = document.createElement('td');
    const actionsDiv = document.createElement('div');
    actionsDiv.style.cssText = 'display:flex;gap:4px;';

    if (s.status === 'active') {
      const extendBtn = document.createElement('button');
      extendBtn.className = 'btn btn-sm';
      extendBtn.style.background = 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)';
      extendBtn.textContent = 'Extend';
      extendBtn.onclick = () => extendSubscription(s.subscription_id);
      actionsDiv.appendChild(extendBtn);
    } else if (s.status === 'expired') {
      const reactivateBtn = document.createElement('button');
      reactivateBtn.className = 'btn btn-sm';
      reactivateBtn.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
      reactivateBtn.textContent = 'Reactivate';
      reactivateBtn.onclick = () => reactivateSubscription(s.subscription_id);
      actionsDiv.appendChild(reactivateBtn);
    }
    td7.appendChild(actionsDiv);

    tr.append(td1, td2, td3, td4, td5, td6, td7);
    tbody.appendChild(tr);
  });

  // Attach checkbox handlers
  tbody.querySelectorAll('.subscription-checkbox').forEach(cb => cb.onchange = updateSubscriptionsSelectedCount);
}

export function updateSubscriptionsSelectedCount() {
  const checkboxes = document.querySelectorAll('.subscription-checkbox:checked');
  const count = checkboxes.length;
  const countEl = document.getElementById('subscriptionsBulkCount');
  if (countEl) countEl.textContent = count > 0 ? `${count} selected` : '';
}

export async function extendSubscription(subscriptionId) {
  const days = prompt('Enter number of days to extend:', '30');
  if (!days) return;
  const daysNum = parseInt(days);
  if (isNaN(daysNum) || daysNum <= 0) {
    showToast('Please enter a valid number of days', 'warning');
    return;
  }

  try {
    await api(`/admin/subscriptions/${subscriptionId}/extend`, {
      method: 'POST',
      body: JSON.stringify({ days: daysNum })
    });
    showToast(`Subscription extended by ${daysNum} days`, 'success');
    await loadAllSubscriptions(false);
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

export async function reactivateSubscription(subscriptionId) {
  try {
    await api(`/admin/subscriptions/${subscriptionId}/reactivate`, { method: 'POST' });
    showToast('Subscription reactivated successfully', 'success');
    await loadAllSubscriptions(false);
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

// ============================================
// Helpers
// ============================================

function showFieldError(msgEl, message) {
  if (msgEl) {
    msgEl.textContent = message;
    msgEl.style.color = '#ef4444';
  }
}

// ============================================
// Missing Modal Exports
// ============================================

export function openCreateTermsModal() {
  const modal = document.getElementById('createTermsModal');
  if (modal) {
    const textArea = document.getElementById('termsText');
    if (textArea) textArea.value = '';
    modal.classList.add('active');
  }
}

export function openConfirmTermsModal() {
  const modal = document.getElementById('confirmTermsModal');
  if (modal) modal.classList.add('active');
}

export function openCreateSubscriptionTypeModal() {
  const modal = document.getElementById('createSubscriptionTypeModal');
  if (modal) {
    const nameEl = document.getElementById('subscriptionTypeName');
    const descEl = document.getElementById('subscriptionTypeDescription');
    const priceEl = document.getElementById('subscriptionTypePrice');
    const durationEl = document.getElementById('subscriptionTypeDuration');
    if (nameEl) nameEl.value = '';
    if (descEl) descEl.value = '';
    if (priceEl) priceEl.value = '';
    if (durationEl) durationEl.value = '30';
    modal.classList.add('active');
  }
}

export function setupMembershipEventHandlers() {
  // Subscription quick filter buttons
  const allSubsBtn = document.getElementById('quickFilterAllSubs');
  const paidSubsBtn = document.getElementById('quickFilterPaidSubs');
  const freeSubsBtn = document.getElementById('quickFilterFreeSubs');

  if (allSubsBtn) {
    allSubsBtn.onclick = () => {
      store.filters.subscriptions = 'all';
      document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
      allSubsBtn.classList.add('filter-active');
      store.pagination.subscriptions.page = 0;
      renderSubscriptions();
    };
  }

  if (paidSubsBtn) {
    paidSubsBtn.onclick = () => {
      store.filters.subscriptions = 'paid';
      document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
      paidSubsBtn.classList.add('filter-active');
      store.pagination.subscriptions.page = 0;
      renderSubscriptions();
    };
  }

  if (freeSubsBtn) {
    freeSubsBtn.onclick = () => {
      store.filters.subscriptions = 'free';
      document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
      freeSubsBtn.classList.add('filter-active');
      store.pagination.subscriptions.page = 0;
      renderSubscriptions();
    };
  }

  // Subscription types filter buttons
  const filterAllTypes = document.getElementById('filterAllTypes');
  const filterEnabledTypes = document.getElementById('filterEnabledTypes');

  if (filterAllTypes) {
    filterAllTypes.onclick = () => filterSubscriptionTypes('all');
  }

  if (filterEnabledTypes) {
    filterEnabledTypes.onclick = () => filterSubscriptionTypes('enabled');
  }

  // Select all subscriptions checkbox
  const selectAll = document.getElementById('selectAllSubscriptions');
  if (selectAll) {
    selectAll.onchange = () => {
      document.querySelectorAll('.subscription-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
      });
      updateSubscriptionsSelectedCount();
    };
  }

  // Search input
  const searchInput = document.getElementById('subscriptionsSearch');
  if (searchInput) {
    searchInput.oninput = (e) => {
      store.pagination.subscriptions.search = e.target.value;
      renderSubscriptions();
    };
  }
}
