/**
 * Admin Portal Core Module
 *
 * Core utilities, authentication, API client, and shared state management.
 * All other modules depend on this.
 */

// ============================================
// Configuration (from centralized config)
// ============================================
export const config = {
  cognitoDomain: window.VettIDConfig?.admin?.cognitoDomain || '',
  clientId: window.VettIDConfig?.admin?.clientId || '',
  redirectUri: window.VettIDConfig?.admin?.redirectUri || '',
  apiUrl: window.VettIDConfig?.apiUrl || ''
};

// ============================================
// Shared State Store
// ============================================
export const store = {
  // User/Auth state
  tokens: null,

  // Data caches
  users: [],
  invites: [],
  admins: [],
  pendingAdmins: [],
  subscriptions: [],
  subscriptionTypes: [],
  proposals: { active: [], upcoming: [], closed: [] },
  waitlist: [],
  services: [],
  handlers: [],

  // UI state
  pagination: {
    users: { page: 0, perPage: 10, total: 0, search: '' },
    invites: { page: 0, perPage: 10, total: 0, search: '' },
    admins: { page: 0, perPage: 10, total: 0, search: '' },
    subscriptions: { page: 0, perPage: 10, total: 0, search: '' },
    waitlist: { page: 0, perPage: 10, total: 0, search: '' }
  },

  // Filters
  filters: {
    users: { registration: '', membership: '', subscription: '', quickFilter: 'action', dateFrom: '', dateTo: '', lastActive: '' },
    invites: { quickFilter: 'active' },
    admins: { quickFilter: 'active' },
    subscriptions: { status: '', plan: '', quickFilter: 'all' },
    proposals: { current: 'active' },
    services: { status: 'all', type: 'all', search: '' }
  },

  // View preferences
  views: {
    waitlist: 'table',
    users: 'table',
    subscriptions: 'table',
    invites: 'table',
    admins: 'table'
  }
};

// ============================================
// Security Utilities
// ============================================

/**
 * Escape HTML to prevent XSS attacks
 */
export function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Parse timestamps that could be seconds, milliseconds, or ISO strings
 */
export function parseTimestamp(value) {
  if (!value) return null;
  if (typeof value === 'string' && value.includes('-')) {
    const d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }
  const num = Number(value);
  if (isNaN(num)) return null;
  const ms = num < 10000000000 ? num * 1000 : num;
  const d = new Date(ms);
  return isNaN(d.getTime()) ? null : d;
}

// ============================================
// Cryptographic Utilities
// ============================================

export function b64url(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export async function sha256(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return b64url(buf);
}

export function rand(n = 64) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a.buffer).substring(0, n);
}

export function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  return atob(str + '='.repeat(pad));
}

// ============================================
// JWT Utilities
// ============================================

export function parseJwt(idt) {
  try {
    const [h, p, s] = idt.split('.');
    return {
      header: JSON.parse(b64urlDecode(h)),
      payload: JSON.parse(b64urlDecode(p)),
      signature: s
    };
  } catch {
    return { header: {}, payload: {}, signature: '' };
  }
}

// ============================================
// Token Management
// ============================================

export function saveTokens(t) {
  store.tokens = t;
  localStorage.setItem('tokens', JSON.stringify(t));
}

export function loadTokens() {
  if (store.tokens) return store.tokens;
  try {
    store.tokens = JSON.parse(localStorage.getItem('tokens') || 'null');
    return store.tokens;
  } catch {
    return null;
  }
}

export function clearTokens() {
  store.tokens = null;
  localStorage.removeItem('tokens');
}

export function idToken() {
  return (loadTokens() || {}).id_token;
}

export function accessToken() {
  return (loadTokens() || {}).access_token;
}

export function refreshToken() {
  return (loadTokens() || {}).refresh_token;
}

export function signedIn() {
  return !!idToken();
}

export function tokenIsExpired() {
  const idt = idToken();
  if (!idt) return true;
  try {
    const { payload } = parseJwt(idt);
    const expiryTime = payload.exp * 1000;
    const now = Date.now();
    return expiryTime < (now + 60000);
  } catch {
    return true;
  }
}

export function isAdmin() {
  if (!signedIn()) return false;
  const { payload } = parseJwt(idToken());
  const groups = payload['cognito:groups'] || [];
  return Array.isArray(groups) && groups.includes('admin');
}

export function getAdminType() {
  if (!signedIn()) return null;
  const { payload } = parseJwt(idToken());
  return payload['custom:admin_type'] || 'admin';
}

export function getAdminEmail() {
  if (!signedIn()) return null;
  const { payload } = parseJwt(idToken());
  return payload.email || null;
}

// ============================================
// OAuth/PKCE URLs
// ============================================

export function authUrl(codeChallenge, state) {
  const u = new URL(config.cognitoDomain + '/oauth2/authorize');
  u.searchParams.set('client_id', config.clientId);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', 'openid email');
  u.searchParams.set('redirect_uri', config.redirectUri);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('code_challenge', codeChallenge);
  u.searchParams.set('state', state);
  return u.toString();
}

export function tokenUrl() {
  return config.cognitoDomain + '/oauth2/token';
}

export function logoutUrl() {
  const u = new URL(config.cognitoDomain + '/logout');
  u.searchParams.set('client_id', config.clientId);
  u.searchParams.set('logout_uri', config.redirectUri);
  return u.toString();
}

// ============================================
// Token Exchange & Refresh
// ============================================

let refreshPromise = null;

export async function exchange(code) {
  const v = sessionStorage.getItem('pkce_verifier');
  if (!v) throw new Error('Missing verifier');

  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('client_id', config.clientId);
  body.set('code', code);
  body.set('redirect_uri', config.redirectUri);
  body.set('code_verifier', v);

  const res = await fetch(tokenUrl(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (!res.ok) throw new Error(await res.text());
  const t = await res.json();
  saveTokens(t);
  sessionStorage.removeItem('pkce_verifier');
  return t;
}

export async function refresh() {
  const r = refreshToken();
  if (!r) return;

  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('client_id', config.clientId);
  body.set('refresh_token', r);

  const res = await fetch(tokenUrl(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  if (res.ok) {
    const t = await res.json();
    if (!t.refresh_token) t.refresh_token = r;
    saveTokens(t);
  } else {
    clearTokens();
  }
}

// ============================================
// API Client
// ============================================

export async function api(path, opts = {}) {
  if (tokenIsExpired()) {
    if (!refreshPromise) {
      refreshPromise = refresh().finally(() => refreshPromise = null);
    }
    await refreshPromise;
  }

  const res = await fetch(config.apiUrl + path, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + idToken(),
      'Content-Type': 'application/json',
      ...(opts.headers || {})
    }
  });

  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// ============================================
// Login/Logout
// ============================================

export function beginLogin() {
  const v = rand(64);
  sessionStorage.setItem('pkce_verifier', v);
  sha256(v).then(ch => {
    const st = rand(24);
    sessionStorage.setItem('oauth_state', st);
    location.href = authUrl(ch, st);
  });
}

export function signOut() {
  clearTokens();
  location.href = logoutUrl();
}

// ============================================
// UI Utilities
// ============================================

let toastTimeout = null;

export function showToast(message, type = 'info', duration = 4000, options = {}) {
  const existing = document.querySelector('.toast-notification');
  if (existing) existing.remove();

  const colors = {
    success: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
    error: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
    warning: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
    info: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)'
  };

  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ'
  };

  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 16px 20px;
    background: ${colors[type] || colors.info};
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    z-index: 10001;
    display: flex;
    align-items: center;
    gap: 12px;
    max-width: 400px;
    animation: slideIn 0.3s ease;
  `;

  const iconSpan = document.createElement('span');
  iconSpan.style.fontSize = '1.2rem';
  iconSpan.textContent = icons[type] || icons.info;

  const msgSpan = document.createElement('span');
  msgSpan.style.flex = '1';
  msgSpan.textContent = message;

  const closeBtn = document.createElement('button');
  closeBtn.style.cssText = 'background: none; border: none; color: white; cursor: pointer; font-size: 1.2rem; padding: 0;';
  closeBtn.textContent = '×';
  closeBtn.onclick = () => toast.remove();

  toast.appendChild(iconSpan);
  toast.appendChild(msgSpan);
  toast.appendChild(closeBtn);
  document.body.appendChild(toast);

  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.remove(), duration);
}

export function debounce(func, delay = 300) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), delay);
  };
}

export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatDateTime(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function formatRelativeTime(date) {
  const now = new Date();
  const then = new Date(date);
  const diff = now - then;

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return then.toLocaleDateString();
}

// ============================================
// Pagination Utilities
// ============================================

export function updatePagination(list, items) {
  const state = store.pagination[list];
  if (!state) return items;

  const start = state.page * state.perPage;
  const end = start + state.perPage;
  const page = items.slice(start, end);
  state.total = items.length;

  const infoEl = document.getElementById(list + 'Info');
  const prevBtn = document.getElementById(list + 'Prev');
  const nextBtn = document.getElementById(list + 'Next');

  if (items.length === 0) {
    if (infoEl) infoEl.textContent = 'No items';
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
  } else {
    if (infoEl) infoEl.textContent = `${start + 1}-${Math.min(end, items.length)} of ${items.length}`;
    if (prevBtn) prevBtn.disabled = state.page === 0;
    if (nextBtn) nextBtn.disabled = end >= items.length;
  }

  return page;
}

export function searchFilter(item, query, fields) {
  if (!query) return true;
  const q = query.toLowerCase();
  return fields.some(f => (item[f] || '').toLowerCase().includes(q));
}

// ============================================
// View State Management
// ============================================

export function initViewPreferences() {
  const saved = localStorage.getItem('vettid-admin-views');
  if (saved) {
    try {
      Object.assign(store.views, JSON.parse(saved));
    } catch (e) {
      console.warn('Failed to load view preferences:', e);
    }
  }
}

export function saveViewPreferences() {
  localStorage.setItem('vettid-admin-views', JSON.stringify(store.views));
}

// ============================================
// Theme Management
// ============================================

export function initTheme() {
  const savedTheme = localStorage.getItem('vettid-theme') || 'dark';
  const root = document.documentElement;
  const themeIcon = document.getElementById('themeIcon');

  if (savedTheme === 'light') {
    root.setAttribute('data-theme', 'light');
    if (themeIcon) themeIcon.textContent = '🌙';
  } else {
    root.removeAttribute('data-theme');
    if (themeIcon) themeIcon.textContent = '☀️';
  }
}

export function toggleTheme() {
  const root = document.documentElement;
  const themeIcon = document.getElementById('themeIcon');
  const currentTheme = root.getAttribute('data-theme');

  if (currentTheme === 'light') {
    root.removeAttribute('data-theme');
    localStorage.setItem('vettid-theme', 'dark');
    if (themeIcon) themeIcon.textContent = '☀️';
  } else {
    root.setAttribute('data-theme', 'light');
    localStorage.setItem('vettid-theme', 'light');
    if (themeIcon) themeIcon.textContent = '🌙';
  }
}

// ============================================
// Idle Timer Management
// ============================================

const IDLE_TIMEOUT = 30 * 60 * 1000;
const IDLE_WARNING_TIME = 28 * 60 * 1000;
let idleTimer = null;
let warningTimer = null;

export function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  if (warningTimer) clearTimeout(warningTimer);

  warningTimer = setTimeout(() => {
    if (signedIn()) {
      showToast('Your session will expire in 2 minutes due to inactivity. Click anywhere to stay signed in.', 'warning', 120000);
    }
  }, IDLE_WARNING_TIME);

  idleTimer = setTimeout(() => {
    if (signedIn()) {
      showToast('Session expired due to inactivity', 'warning');
      setTimeout(() => signOut(), 2000);
    }
  }, IDLE_TIMEOUT);
}

// ============================================
// Loading States
// ============================================

export function showLoadingSkeleton(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 10;
  td.style.cssText = 'padding: 40px; text-align: center; color: var(--gray);';

  const spinner = document.createElement('div');
  spinner.style.cssText = 'display: inline-block; animation: spin 1s linear infinite;';
  spinner.textContent = '⟳';

  td.appendChild(spinner);
  td.appendChild(document.createTextNode(' Loading...'));
  tr.appendChild(td);
  container.replaceChildren(tr);
}

export function showEmptyState(containerId, text, subtext = '') {
  const container = document.getElementById(containerId);
  if (!container) return;

  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 10;
  td.style.cssText = 'padding: 40px; text-align: center; color: var(--gray);';

  const icon = document.createElement('div');
  icon.style.cssText = 'font-size: 1.5rem; margin-bottom: 8px;';
  icon.textContent = '📋';

  const textDiv = document.createElement('div');
  textDiv.textContent = text;

  td.appendChild(icon);
  td.appendChild(textDiv);

  if (subtext) {
    const subtextDiv = document.createElement('div');
    subtextDiv.style.cssText = 'font-size: 0.85rem; margin-top: 4px; opacity: 0.7;';
    subtextDiv.textContent = subtext;
    td.appendChild(subtextDiv);
  }

  tr.appendChild(td);
  container.replaceChildren(tr);
}

/**
 * Show grid-style loading skeleton for card layouts
 */
export function showGridLoadingSkeleton(containerId, count = 3) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const fragment = document.createDocumentFragment();
  for (let i = 0; i < count; i++) {
    const card = document.createElement('div');
    card.style.cssText = 'padding:20px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border);';

    const line1 = document.createElement('div');
    line1.className = 'skeleton';
    line1.style.cssText = 'height:24px;margin-bottom:12px;border-radius:4px;width:60%;';

    const line2 = document.createElement('div');
    line2.className = 'skeleton';
    line2.style.cssText = 'height:16px;margin-bottom:8px;border-radius:4px;width:80%;';

    const line3 = document.createElement('div');
    line3.className = 'skeleton';
    line3.style.cssText = 'height:16px;margin-bottom:8px;border-radius:4px;width:70%;';

    const line4 = document.createElement('div');
    line4.className = 'skeleton';
    line4.style.cssText = 'height:36px;margin-top:16px;border-radius:4px;width:100%;';

    card.appendChild(line1);
    card.appendChild(line2);
    card.appendChild(line3);
    card.appendChild(line4);
    fragment.appendChild(card);
  }
  container.replaceChildren(fragment);
}

// ============================================
// Super Admin Check
// ============================================

export function isSuperAdmin() {
  return !!store.isSuperAdmin;
}

// ============================================
// View Toggle (Table/Card)
// ============================================

export function toggleView(tabName) {
  const newView = store.views[tabName] === 'table' ? 'card' : 'table';
  store.views[tabName] = newView;
  saveViewPreferences();
  applyView(tabName, newView);
}

export function applyView(tabName, view) {
  const tableContainer = document.getElementById(tabName + 'TableContainer');
  const cardContainer = document.getElementById(tabName + 'CardContainer');
  const viewToggle = document.getElementById(tabName + 'ViewToggle');

  if (tableContainer && cardContainer) {
    if (view === 'card') {
      tableContainer.style.display = 'none';
      cardContainer.classList.add('active');
      if (viewToggle) viewToggle.textContent = 'Table View';
    } else {
      tableContainer.style.display = 'block';
      cardContainer.classList.remove('active');
      if (viewToggle) viewToggle.textContent = 'Card View';
    }
  }
}

// ============================================
// Action Dropdown
// ============================================

export function toggleActionDropdown(btn) {
  const menu = btn.nextElementSibling;
  // Close all other dropdowns first
  document.querySelectorAll('.action-dropdown-menu.active').forEach(m => {
    if (m !== menu) {
      m.classList.remove('active');
      m.style.cssText = '';
    }
  });

  // Use fixed positioning to escape any overflow:hidden containers
  const btnRect = btn.getBoundingClientRect();
  const menuHeight = 120;
  const spaceBelow = window.innerHeight - btnRect.bottom;

  menu.style.position = 'fixed';
  menu.style.right = (window.innerWidth - btnRect.right) + 'px';

  if (spaceBelow < menuHeight && btnRect.top > menuHeight) {
    menu.style.bottom = (window.innerHeight - btnRect.top + 4) + 'px';
    menu.style.top = 'auto';
  } else {
    menu.style.top = (btnRect.bottom + 4) + 'px';
    menu.style.bottom = 'auto';
  }

  menu.classList.toggle('active');
}

// ============================================
// Generic Confirmation Modal
// ============================================

let confirmResolve = null;

export function openGenericConfirmModal(title, message, confirmText = 'Confirm', cancelText = 'Cancel', isDanger = false) {
  return new Promise((resolve) => {
    confirmResolve = resolve;

    const titleEl = document.getElementById('genericConfirmTitle');
    const messageEl = document.getElementById('genericConfirmMessage');
    const confirmBtn = document.getElementById('genericConfirmBtn');

    if (titleEl) titleEl.textContent = title;
    if (messageEl) messageEl.textContent = message;

    if (confirmBtn) {
      confirmBtn.textContent = confirmText;
      if (isDanger) {
        confirmBtn.style.background = 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)';
      } else {
        confirmBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
      }
      confirmBtn.onclick = () => closeGenericConfirmModal(true);
    }

    const modal = document.getElementById('genericConfirmModal');
    if (modal) modal.classList.add('active');
  });
}

export function closeGenericConfirmModal(confirmed) {
  const modal = document.getElementById('genericConfirmModal');
  if (modal) modal.classList.remove('active');
  if (confirmResolve) {
    confirmResolve(confirmed);
    confirmResolve = null;
  }
}

// ============================================
// Password Change Functions
// ============================================

export function clearPasswordFields() {
  const currentPw = document.getElementById('currentPassword');
  const newPw = document.getElementById('newPassword');
  const confirmPw = document.getElementById('confirmPassword');
  const strengthFill = document.getElementById('passwordStrengthFill');
  const strengthText = document.getElementById('passwordStrengthText');
  const matchIndicator = document.getElementById('passwordMatchIndicator');

  if (currentPw) currentPw.value = '';
  if (newPw) newPw.value = '';
  if (confirmPw) confirmPw.value = '';
  if (strengthFill) strengthFill.style.width = '0%';
  if (strengthText) strengthText.textContent = '';
  if (matchIndicator) matchIndicator.textContent = '';
}

export async function submitPasswordChange() {
  const currentPw = document.getElementById('currentPassword');
  const newPw = document.getElementById('newPassword');
  const confirmPw = document.getElementById('confirmPassword');
  const submitBtn = document.getElementById('submitPasswordChange');

  if (!currentPw || !newPw || !confirmPw) {
    showToast('Password fields not found', 'error');
    return;
  }

  if (newPw.value !== confirmPw.value) {
    showToast('Passwords do not match', 'error');
    return;
  }

  if (newPw.value.length < 8) {
    showToast('Password must be at least 8 characters', 'error');
    return;
  }

  try {
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Changing...';
    }

    await api('/admin/change-password', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword: currentPw.value,
        newPassword: newPw.value
      })
    });

    showToast('Password changed successfully', 'success');
    clearPasswordFields();

    const modal = document.getElementById('passwordModal');
    if (modal) modal.classList.remove('active');
  } catch (e) {
    showToast('Failed to change password: ' + (e.message || e), 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Change Password';
    }
  }
}
