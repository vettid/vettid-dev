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

  // Buttons
  const btnWrapper = document.createElement('div');
  btnWrapper.style.cssText = 'margin-top:auto;display:flex;flex-direction:column;gap:8px;';

  const viewBtn = document.createElement('button');
  viewBtn.className = 'btn';
  viewBtn.style.cssText = 'display:block;width:100%;box-sizing:border-box;text-align:center;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;padding:8px 12px;font-size:0.8rem;font-weight:600;border-radius:12px;border:none;cursor:pointer;';
  viewBtn.textContent = 'View Terms PDF';
  viewBtn.dataset.action = 'view-terms';
  viewBtn.dataset.versionId = current.version_id;

  const regenerateBtn = document.createElement('button');
  regenerateBtn.className = 'btn';
  regenerateBtn.style.cssText = 'display:block;width:100%;box-sizing:border-box;text-align:center;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:8px 12px;font-size:0.8rem;font-weight:600;border-radius:12px;border:none;cursor:pointer;';
  regenerateBtn.textContent = 'Regenerate PDF';
  regenerateBtn.dataset.action = 'regenerate-terms-pdf';
  regenerateBtn.dataset.versionId = current.version_id;

  btnWrapper.append(viewBtn, regenerateBtn);

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

export async function regenerateTermsPdf(versionId, btn) {
  const originalText = btn.textContent;
  btn.textContent = 'Regenerating...';
  btn.disabled = true;

  try {
    await refresh();
    const res = await fetch(config.apiUrl + '/admin/membership-terms/' + encodeURIComponent(versionId) + '/regenerate-pdf', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      }
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.message || 'Failed to regenerate PDF');
    }
    const data = await res.json();
    showToast('PDF regenerated successfully! The download will now show the updated terms.', 'success');
  } catch (e) {
    showToast('Failed to regenerate PDF: ' + (e.message || e), 'error');
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

let subscriptionTypesFilter = 'enabled';

// ============================================
// Subscription Types Functions
// ============================================

export async function loadSubscriptionTypes() {
  if (!isAdmin()) return;

  const container = document.getElementById('subscriptionTypesList');
  if (!container) return;

  showGridLoadingSkeleton('subscriptionTypesList', 3);

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
  const container = document.getElementById('subscriptionTypesList');
  if (!container) return;

  const types = store.subscriptionTypes || [];

  // Update badge counts
  const enabledCount = types.filter(t => t.is_enabled === true || t.is_enabled === 'true').length;
  const paidCount = types.filter(t => parseFloat(t.price) > 0).length;
  const freeCount = types.filter(t => !t.price || parseFloat(t.price) === 0).length;

  const enabledCountEl = document.getElementById('enabledTypesCount');
  const allCountEl = document.getElementById('allTypesCount');
  const paidCountEl = document.getElementById('paidTypesCount');
  const freeCountEl = document.getElementById('freeTypesCount');

  if (enabledCountEl) enabledCountEl.textContent = enabledCount;
  if (allCountEl) allCountEl.textContent = types.length;
  if (paidCountEl) paidCountEl.textContent = paidCount;
  if (freeCountEl) freeCountEl.textContent = freeCount;

  let filtered = types;
  switch (subscriptionTypesFilter) {
    case 'enabled':
      // Handle both boolean and string 'true'/'false' values
      filtered = types.filter(t => t.is_enabled === true || t.is_enabled === 'true');
      break;
    case 'paid':
      filtered = types.filter(t => parseFloat(t.price) > 0);
      break;
    case 'free':
      filtered = types.filter(t => !t.price || parseFloat(t.price) === 0);
      break;
    // 'all' - no filtering
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
  // Normalize is_enabled to handle both boolean and string values
  const typeIsEnabled = type.is_enabled === true || type.is_enabled === 'true';

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
  if (typeIsEnabled) {
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
  // Handle pluralization - don't add 's' if unit already ends with 's'
  const unit = type.term_unit || 'month';
  const pluralUnit = type.term_value > 1 && !unit.endsWith('s') ? unit + 's' : unit;
  termValue.textContent = `${type.term_value} ${pluralUnit}`;
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
  toggleBtn.textContent = typeIsEnabled ? 'Disable' : 'Enable';
  toggleBtn.style.background = typeIsEnabled
    ? 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)'
    : 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
  toggleBtn.dataset.action = 'toggle-subscription-type';
  toggleBtn.dataset.typeId = type.subscription_type_id;
  toggleBtn.dataset.isEnabled = typeIsEnabled ? 'true' : 'false';

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

  // Define button configs with their active gradients
  const buttons = {
    enabled: { el: document.getElementById('filterEnabledTypes'), active: 'linear-gradient(135deg,#10b981 0%,#059669 100%)' },
    paid: { el: document.getElementById('filterPaidTypes'), active: 'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)' },
    free: { el: document.getElementById('filterFreeTypes'), active: 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)' },
    all: { el: document.getElementById('filterAllTypes'), active: 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)' }
  };
  const inactiveGradient = 'linear-gradient(135deg,#374151 0%,#1f2937 100%)';

  // Update all button styles
  Object.keys(buttons).forEach(key => {
    const btn = buttons[key];
    if (btn.el) {
      if (key === filter) {
        btn.el.classList.add('active');
        btn.el.style.background = btn.active;
      } else {
        btn.el.classList.remove('active');
        btn.el.style.background = inactiveGradient;
      }
    }
  });

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

  // Check if table exists before proceeding
  const table = document.getElementById('subscriptionsTable');
  if (!table) return; // Table not in DOM yet

  showLoadingSkeleton('subscriptionsTable');

  try {
    if (resetPage || store.subscriptions.length === 0) {
      const data = await api('/admin/subscriptions');
      store.subscriptions = data.subscriptions || [];
    }
    renderSubscriptions();
  } catch (e) {
    console.error('Error loading subscriptions:', e);
    // Query tbody fresh for error display
    const tbody = document.querySelector('#subscriptionsTable tbody');
    if (tbody) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 10;
      td.className = 'muted';
      td.textContent = 'Error: ' + (e.message || String(e));
      tr.appendChild(td);
      tbody.replaceChildren(tr);
    }
  }
}

export function renderSubscriptions() {
  const tbody = document.querySelector('#subscriptionsTable tbody');
  if (!tbody) return;

  tbody.replaceChildren();
  const now = new Date();

  // Apply quick filter
  let filtered = store.subscriptions.filter(s => {
    const quickFilter = store.filters.subscriptions || 'all';
    const expiresDate = s.expires_at ? new Date(s.expires_at) : null;
    const daysLeft = expiresDate ? Math.ceil((expiresDate - now) / (1000 * 60 * 60 * 24)) : null;
    const amount = s.amount || 0;

    // Status-based filters
    if (quickFilter === 'active' && s.status !== 'active') return false;
    if (quickFilter === 'expiring') {
      if (s.status !== 'active') return false;
      if (!daysLeft || daysLeft > 30) return false;
    }
    if (quickFilter === 'expired' && s.status !== 'expired') return false;

    // Payment-based filters (Paid/Free badges)
    if (quickFilter === 'paid' && amount <= 0) return false;
    if (quickFilter === 'free' && amount > 0) return false;

    // Search filter
    const search = store.pagination.subscriptions.search?.toLowerCase() || '';
    if (search) {
      const name = `${s.first_name || ''} ${s.last_name || ''}`.trim();
      const matchesEmail = (s.email || '').toLowerCase().includes(search);
      const matchesName = name.toLowerCase().includes(search);
      const matchesPlan = (s.plan || '').toLowerCase().includes(search);
      if (!matchesEmail && !matchesName && !matchesPlan) return false;
    }

    return true;
  });

  // Update filter badge counts
  updateSubscriptionFilterCounts();

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 11;
    td.style.cssText = 'text-align:center;padding:40px;';
    td.textContent = 'No subscriptions found';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  const page = updatePagination('subscriptions', filtered);

  page.forEach(s => {
    const tr = document.createElement('tr');
    const expiresDate = s.expires_at ? new Date(s.expires_at) : null;
    const daysLeft = expiresDate ? Math.ceil((expiresDate - now) / (1000 * 60 * 60 * 24)) : null;
    const name = `${s.first_name || ''} ${s.last_name || ''}`.trim() || '—';

    // 1. Checkbox
    const td1 = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'subscription-checkbox';
    cb.dataset.guid = s.user_guid || '';
    cb.dataset.status = s.status;
    td1.appendChild(cb);

    // 2. Name
    const td2 = document.createElement('td');
    td2.textContent = name;

    // 3. Email
    const td3 = document.createElement('td');
    td3.textContent = s.email || '—';

    // 4. User GUID (truncated with copy-to-clipboard)
    const td4 = document.createElement('td');
    const guid = s.user_guid || '';
    if (guid) {
      const guidSpan = document.createElement('span');
      guidSpan.style.cssText = 'font-family:monospace;font-size:0.75rem;cursor:pointer;color:var(--accent);';
      guidSpan.title = `Click to copy: ${guid}`;
      guidSpan.textContent = guid.length > 12 ? guid.slice(0, 12) + '…' : guid;
      guidSpan.onclick = (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(guid);
        showToast('GUID copied', 'success');
      };
      td4.appendChild(guidSpan);
    } else {
      td4.textContent = '—';
    }

    // 5. Plan
    const td5 = document.createElement('td');
    td5.textContent = s.plan || '—';

    // 6. Status badge
    const td6 = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;color:#fff;';
    const statusColors = { active: 'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)', expired: 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)', cancelled: 'linear-gradient(135deg,#f97316 0%,#ea580c 100%)' };
    statusBadge.style.background = statusColors[s.status] || 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
    statusBadge.textContent = (s.status || 'Unknown').charAt(0).toUpperCase() + (s.status || 'unknown').slice(1);
    td6.appendChild(statusBadge);

    // 7. PIN badge
    const td7 = document.createElement('td');
    const pinBadge = document.createElement('span');
    pinBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;color:#fff;';
    pinBadge.style.background = s.pin_enabled ? 'linear-gradient(135deg,#10b981 0%,#059669 100%)' : 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
    pinBadge.textContent = s.pin_enabled ? 'Yes' : 'No';
    td7.appendChild(pinBadge);

    // 8. Vault badge (placeholder - would need vault status API)
    const td8 = document.createElement('td');
    const vaultBadge = document.createElement('span');
    vaultBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;color:#fff;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);';
    vaultBadge.textContent = 'No';
    td8.appendChild(vaultBadge);

    // 9. Emails badge
    const td9 = document.createElement('td');
    const emailBadge = document.createElement('span');
    emailBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;color:#fff;';
    emailBadge.style.background = s.system_emails_enabled ? 'linear-gradient(135deg,#10b981 0%,#059669 100%)' : 'linear-gradient(135deg,#6b7280 0%,#4b5563 100%)';
    emailBadge.textContent = s.system_emails_enabled ? 'On' : 'Off';
    td9.appendChild(emailBadge);

    // 10. Expires date
    const td10 = document.createElement('td');
    td10.textContent = expiresDate ? expiresDate.toLocaleString() : '—';

    // 11. Days left badge
    const td11 = document.createElement('td');
    if (s.status === 'active' && daysLeft !== null) {
      const daysLeftBadge = document.createElement('span');
      daysLeftBadge.style.cssText = 'display:inline-block;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
      if (daysLeft < 7) {
        daysLeftBadge.style.background = 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)';
        daysLeftBadge.style.color = '#fff';
      } else if (daysLeft <= 30) {
        daysLeftBadge.style.background = 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)';
        daysLeftBadge.style.color = '#000';
      } else {
        daysLeftBadge.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
        daysLeftBadge.style.color = '#fff';
      }
      daysLeftBadge.textContent = `${daysLeft}d`;
      td11.appendChild(daysLeftBadge);
    } else {
      td11.textContent = '—';
      td11.style.color = '#6b7280';
    }

    tr.append(td1, td2, td3, td4, td5, td6, td7, td8, td9, td10, td11);
    tbody.appendChild(tr);
  });

  // Attach checkbox handlers
  tbody.querySelectorAll('.subscription-checkbox').forEach(cb => cb.onchange = updateSubscriptionsSelectedCount);
}

/**
 * Update the filter badge counts (All, Paid, Free)
 */
function updateSubscriptionFilterCounts() {
  let paidCount = 0;
  let freeCount = 0;

  store.subscriptions.forEach(s => {
    const amount = s.amount || 0;
    if (amount > 0) {
      paidCount++;
    } else {
      freeCount++;
    }
  });

  const allEl = document.getElementById('allSubsCount');
  const paidEl = document.getElementById('paidSubsCount');
  const freeEl = document.getElementById('freeSubsCount');

  if (allEl) allEl.textContent = store.subscriptions.length;
  if (paidEl) paidEl.textContent = paidCount;
  if (freeEl) freeEl.textContent = freeCount;
}

export function updateSubscriptionsSelectedCount() {
  const checkboxes = document.querySelectorAll('.subscription-checkbox:checked');
  const count = checkboxes.length;

  // Update bulk bar visibility and count
  const bulkBar = document.getElementById('subscriptionsBulkBar');
  const countEl = document.getElementById('selectedSubscriptionsCount');
  if (bulkBar) bulkBar.classList.toggle('active', count > 0);
  if (countEl) countEl.textContent = count;
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
// Subscription Analytics
// ============================================

/**
 * Update all subscription analytics metrics (Revenue, Growth, Churn)
 * This function populates the subscription-analytics sub-tab
 */
export function updateSubscriptionAnalytics() {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

  // Calculate revenue metrics
  let monthlyRevenue = 0;
  const revenueByPlan = new Map();

  store.subscriptions.forEach(s => {
    const amount = s.amount || 0;
    if (s.status === 'active' && amount > 0) {
      monthlyRevenue += amount;
      const plan = s.plan || 'Unknown';
      revenueByPlan.set(plan, (revenueByPlan.get(plan) || 0) + amount);
    }
  });

  // Update estimated monthly revenue
  const revenueEl = document.getElementById('estimatedMonthlyRevenue');
  if (revenueEl) revenueEl.textContent = '$' + monthlyRevenue.toFixed(2);

  // Update revenue by plan using safe DOM methods
  const revenueByPlanEl = document.getElementById('revenueByPlan');
  if (revenueByPlanEl) {
    revenueByPlanEl.replaceChildren();

    if (revenueByPlan.size === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.style.cssText = 'color:var(--gray);font-size:0.85rem;';
      emptyMsg.textContent = 'No active paid subscriptions';
      revenueByPlanEl.appendChild(emptyMsg);
    } else {
      Array.from(revenueByPlan.entries())
        .sort((a, b) => b[1] - a[1])
        .forEach(([plan, revenue]) => {
          const row = document.createElement('div');
          row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:var(--bg-tertiary);border-radius:4px;';

          const planSpan = document.createElement('span');
          planSpan.style.cssText = 'color:var(--text);font-size:0.85rem;';
          planSpan.textContent = plan;

          const revenueSpan = document.createElement('span');
          revenueSpan.style.cssText = 'font-weight:600;color:#10b981;';
          revenueSpan.textContent = '$' + revenue.toFixed(2) + '/mo';

          row.appendChild(planSpan);
          row.appendChild(revenueSpan);
          revenueByPlanEl.appendChild(row);
        });
    }
  }

  // Calculate subscription growth
  let thisMonthCount = 0;
  let last30DaysCount = 0;
  let previousMonthCount = 0;
  const previousMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const previousMonthEnd = new Date(now.getFullYear(), now.getMonth(), 1);

  store.subscriptions.forEach(s => {
    const createdAt = new Date(s.created_at);
    if (createdAt >= startOfMonth) thisMonthCount++;
    if (createdAt >= thirtyDaysAgo) last30DaysCount++;
    if (createdAt >= previousMonthStart && createdAt < previousMonthEnd) previousMonthCount++;
  });

  const growthRate = previousMonthCount > 0
    ? ((thisMonthCount - previousMonthCount) / previousMonthCount * 100)
    : 0;
  const growthRateColor = growthRate >= 0 ? '#10b981' : '#ef4444';
  const growthRatePrefix = growthRate >= 0 ? '+' : '';

  const growthThisMonthEl = document.getElementById('growthThisMonth');
  const growthLast30DaysEl = document.getElementById('growthLast30Days');
  const growthRateEl = document.getElementById('growthRate');

  if (growthThisMonthEl) growthThisMonthEl.textContent = '+' + thisMonthCount;
  if (growthLast30DaysEl) growthLast30DaysEl.textContent = '+' + last30DaysCount;
  if (growthRateEl) {
    growthRateEl.textContent = growthRatePrefix + growthRate.toFixed(1) + '%';
    growthRateEl.style.color = growthRateColor;
  }

  // Calculate churn metrics
  let cancelledLast30Days = 0;
  let expiredLast30Days = 0;

  store.subscriptions.forEach(s => {
    // Check if cancelled in last 30 days
    if (s.status === 'cancelled' && s.cancelled_at) {
      const cancelledDate = new Date(s.cancelled_at);
      if (cancelledDate >= thirtyDaysAgo) cancelledLast30Days++;
    }
    // Check if expired in last 30 days
    const expiresDate = new Date(s.expires_at);
    if (expiresDate >= thirtyDaysAgo && expiresDate <= now && s.status !== 'active') {
      expiredLast30Days++;
    }
  });

  const activeSubscriptions = store.subscriptions.filter(s => s.status === 'active').length;
  const totalChurned = cancelledLast30Days + expiredLast30Days;
  const totalBase = activeSubscriptions + totalChurned;
  const churnRate = totalBase > 0 ? (totalChurned / totalBase * 100) : 0;
  const retentionRate = 100 - churnRate;

  const churnCancelledEl = document.getElementById('churnCancelled');
  const churnExpiredEl = document.getElementById('churnExpired');
  const churnRateEl = document.getElementById('churnRate');
  const retentionRateEl = document.getElementById('retentionRate');

  if (churnCancelledEl) churnCancelledEl.textContent = cancelledLast30Days;
  if (churnExpiredEl) churnExpiredEl.textContent = expiredLast30Days;
  if (churnRateEl) churnRateEl.textContent = churnRate.toFixed(1) + '%';
  if (retentionRateEl) retentionRateEl.textContent = retentionRate.toFixed(1) + '%';
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
    // Reset all form fields using correct IDs from HTML
    const nameEl = document.getElementById('subTypeName');
    const descEl = document.getElementById('subTypeDescription');
    const termValueEl = document.getElementById('subTermValue');
    const termUnitEl = document.getElementById('subTermUnit');
    const freeEl = document.getElementById('subTypeFree');
    const currencyEl = document.getElementById('subTypeCurrency');
    const priceEl = document.getElementById('subTypePrice');
    const oneTimeEl = document.getElementById('subTypeOneTime');
    const enabledEl = document.getElementById('subTypeEnabled');
    const pricingFields = document.getElementById('pricingFields');
    const msgEl = document.getElementById('subscriptionTypeMsg');

    if (nameEl) nameEl.value = '';
    if (descEl) descEl.value = '';
    if (termValueEl) termValueEl.value = '1';
    if (termUnitEl) termUnitEl.value = 'months';
    if (freeEl) freeEl.checked = false;
    if (currencyEl) { currencyEl.value = 'USD'; currencyEl.disabled = false; }
    if (priceEl) { priceEl.value = ''; priceEl.disabled = false; }
    if (oneTimeEl) oneTimeEl.checked = false;
    if (enabledEl) enabledEl.checked = true;
    if (pricingFields) pricingFields.style.opacity = '1';
    if (msgEl) msgEl.textContent = '';

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
  const filterPaidTypes = document.getElementById('filterPaidTypes');
  const filterFreeTypes = document.getElementById('filterFreeTypes');

  if (filterAllTypes) {
    filterAllTypes.onclick = () => filterSubscriptionTypes('all');
  }

  if (filterEnabledTypes) {
    filterEnabledTypes.onclick = () => filterSubscriptionTypes('enabled');
  }

  if (filterPaidTypes) {
    filterPaidTypes.onclick = () => filterSubscriptionTypes('paid');
  }

  if (filterFreeTypes) {
    filterFreeTypes.onclick = () => filterSubscriptionTypes('free');
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

  // Create subscription type button
  const toggleSubscriptionTypeForm = document.getElementById('toggleSubscriptionTypeForm');
  if (toggleSubscriptionTypeForm) {
    toggleSubscriptionTypeForm.onclick = () => openCreateSubscriptionTypeModal();
  }

  // Create subscription type submit button
  const createSubscriptionTypeBtn = document.getElementById('createSubscriptionTypeBtn');
  if (createSubscriptionTypeBtn) {
    createSubscriptionTypeBtn.onclick = () => createSubscriptionType();
  }

  // Create terms button (opens modal)
  const toggleTermsForm = document.getElementById('toggleTermsForm');
  if (toggleTermsForm) {
    toggleTermsForm.onclick = () => openCreateTermsModal();
  }

  // Create terms submit button (opens confirmation)
  const createTermsBtn = document.getElementById('createTermsBtn');
  if (createTermsBtn) {
    createTermsBtn.onclick = () => openConfirmTermsModal();
  }

  // Confirm create terms button (submits)
  const confirmCreateTermsBtn = document.getElementById('confirmCreateTermsBtn');
  if (confirmCreateTermsBtn) {
    confirmCreateTermsBtn.onclick = () => createMembershipTerms();
  }
}
