// Load configuration from centralized config file
const COGNITO_DOMAIN = window.VettIDConfig.admin.cognitoDomain;
const CLIENT_ID = window.VettIDConfig.admin.clientId;
const REDIRECT_URI = window.VettIDConfig.admin.redirectUri;
const API_URL = window.VettIDConfig.apiUrl;

// Security: HTML escape function to prevent XSS attacks
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Parse timestamps that could be seconds, milliseconds, or ISO strings
function parseTimestamp(value) {
  if (!value) return null;
  // If it's a string that looks like ISO date, parse directly
  if (typeof value === 'string' && value.includes('-')) {
    const d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }
  // If numeric, detect if seconds or milliseconds
  // Timestamps < 10000000000 are likely seconds (before year 2286)
  // Timestamps >= 10000000000 are likely milliseconds
  const num = Number(value);
  if (isNaN(num)) return null;
  const ms = num < 10000000000 ? num * 1000 : num;
  const d = new Date(ms);
  return isNaN(d.getTime()) ? null : d;
}

// Security: Session idle timeout (30 minutes)
const IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes in milliseconds
const IDLE_WARNING_TIME = 28 * 60 * 1000; // 28 minutes - show warning
let idleTimer = null;
let warningTimer = null;

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  if (warningTimer) clearTimeout(warningTimer);

  // Show warning at 28 minutes
  warningTimer = setTimeout(() => {
    if (signedIn()) {
      showToast('Your session will expire in 2 minutes due to inactivity. Click anywhere to stay signed in.', 'warning', 120000);
    }
  }, IDLE_WARNING_TIME);

  // Sign out at 30 minutes
  idleTimer = setTimeout(() => {
    if (signedIn()) {
      showToast('Session expired due to inactivity', 'warning');
      setTimeout(() => signOut(), 2000);
    }
  }, IDLE_TIMEOUT);
}

// Theme Management
function initTheme() {
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

function toggleTheme() {
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

// View Management (Table vs Card)
const viewState = {
  waitlist: 'table',
  users: 'table',
  subscriptions: 'table',
  invites: 'table',
  admins: 'table'
};

function initViewPreferences() {
  const saved = localStorage.getItem('vettid-view-preferences');
  if (saved) {
    try {
      Object.assign(viewState, JSON.parse(saved));
    } catch (e) {
      console.error('Failed to parse view preferences', e);
    }
  }
}

function saveViewPreferences() {
  localStorage.setItem('vettid-view-preferences', JSON.stringify(viewState));
}

function toggleView(tabName) {
  const newView = viewState[tabName] === 'table' ? 'card' : 'table';
  viewState[tabName] = newView;
  saveViewPreferences();
  applyView(tabName, newView);
}

function applyView(tabName, view) {
  const tableContainer = document.getElementById(`${tabName}TableContainer`);
  const cardContainer = document.getElementById(`${tabName}CardContainer`);
  const viewToggle = document.getElementById(`${tabName}ViewToggle`);

  if (tableContainer && cardContainer) {
    if (view === 'card') {
      tableContainer.style.display = 'none';
      cardContainer.classList.add('active');
      if (viewToggle) viewToggle.innerHTML = '📋 Table View';
    } else {
      tableContainer.style.display = 'block';
      cardContainer.classList.remove('active');
      if (viewToggle) viewToggle.innerHTML = '🗂 Card View';
    }

    // Re-render the data in the appropriate view
    if (tabName === 'waitlist') {
      renderWaitlist();
    }
  }
}

// Render waitlist data as cards
function renderWaitlistCards(entries) {
  const cardContainer = document.getElementById('waitlistCardContainer');
  if (!cardContainer) return;

  cardContainer.innerHTML = '';

  entries.forEach(entry => {
    const statusColors = {
      pending: '#3b82f6',
      invited: '#10b981',
      rejected: '#ef4444'
    };
    const statusColor = statusColors[entry.status] || '#6b7280';
    const statusLabel = entry.status ? entry.status.charAt(0).toUpperCase() + entry.status.slice(1) : 'Pending';
    const isDisabled = entry.status === 'invited' || entry.status === 'rejected';

    const card = document.createElement('div');
    card.className = 'data-card';
    card.innerHTML = `
      <div class="data-card-header">
        <div style="display:flex;align-items:center;gap:12px;flex:1;">
          <input type="checkbox" name="waitlist-select" class="waitlist-checkbox" data-id="${escapeHtml(entry.waitlist_id)}" data-action="waitlist-select" style="width:18px;height:18px;cursor:pointer;" ${isDisabled ? 'disabled title="Already processed"' : ''}/>
          <div class="data-card-title">${escapeHtml(entry.first_name || '')} ${escapeHtml(entry.last_name || '')}</div>
        </div>
        <span class="data-card-badge" style="background:${statusColor}">${statusLabel}</span>
      </div>
      <div class="data-card-body">
        <div class="data-card-row">
          <span class="data-card-label">Email:</span>
          <span class="data-card-value">${escapeHtml(entry.email)}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Created:</span>
          <span class="data-card-value">${entry.created_at ? new Date(entry.created_at).toLocaleDateString() : '—'}</span>
        </div>
        ${entry.invited_at ? `
        <div class="data-card-row">
          <span class="data-card-label">Invited:</span>
          <span class="data-card-value">${new Date(entry.invited_at).toLocaleDateString()}</span>
        </div>` : ''}
        ${entry.invited_by ? `
        <div class="data-card-row">
          <span class="data-card-label">Invited By:</span>
          <span class="data-card-value">${escapeHtml(entry.invited_by)}</span>
        </div>` : ''}
      </div>
      ${entry.status === 'pending' || !entry.status ? `
      <div class="data-card-actions">
        <button class="btn" data-action="waitlist-invite" data-id="${escapeHtml(entry.waitlist_id)}" style="background:linear-gradient(135deg,#0e9e4d 0%,#0a7a3a 100%);">Invite</button>
        <button class="btn" data-action="waitlist-reject" data-id="${escapeHtml(entry.waitlist_id)}" style="background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);">Reject</button>
      </div>` : ''}
    `;
    cardContainer.appendChild(card);
  });
}

// Render users data as cards
function renderUsersCards(users, isInvited = false) {
  const cardContainer = document.getElementById('usersCardContainer');
  if (!cardContainer) return;

  cardContainer.innerHTML = '';

  users.forEach(u => {
    const name = `${u.first_name || ''} ${u.last_name || ''}`.trim() || '—';
    const card = document.createElement('div');
    card.className = 'data-card';

    if (isInvited) {
      // Render invited waitlist user card
      card.innerHTML = `
        <div class="data-card-header">
          <div style="display:flex;align-items:center;gap:12px;flex:1;">
            <div class="data-card-title">${escapeHtml(name)}</div>
          </div>
        </div>
        <div class="data-card-body">
          <div class="data-card-row">
            <span class="data-card-label">Email:</span>
            <span class="data-card-value">${escapeHtml(u.email)}</span>
          </div>
          <div class="data-card-row">
            <span class="data-card-label">Status:</span>
            <span class="data-card-badge" style="background:#6366f1;font-size:0.65rem;">Invited</span>
          </div>
          ${u.invite_code ? `
          <div class="data-card-row">
            <span class="data-card-label">Invite Code:</span>
            <span class="data-card-value" style="font-family:monospace;">${escapeHtml(u.invite_code)}</span>
          </div>` : ''}
          ${u.invited_at ? `
          <div class="data-card-row">
            <span class="data-card-label">Invited:</span>
            <span class="data-card-value">${new Date(u.invited_at).toLocaleDateString()}</span>
          </div>` : ''}
        </div>
      `;
    } else {
      // Render regular registered user card
      const statusColors = {
        pending: '#f59e0b',
        approved: '#10b981',
        rejected: '#ef4444',
        disabled: '#ec4899',
        deleted: '#7f1d1d'
      };
      const regColor = statusColors[u.status] || '#6b7280';

      const memberColors = {
        none: '#6b7280',
        pending: '#f59e0b',
        approved: '#10b981',
        denied: '#ef4444'
      };
      const memberStatus = u.membership_status || 'none';
      const memberColor = memberColors[memberStatus] || '#6b7280';

      card.innerHTML = `
        <div class="data-card-header">
          <div style="display:flex;align-items:center;gap:12px;flex:1;">
            <input type="checkbox" name="user-select" class="user-checkbox" data-id="${escapeHtml(u.registration_id)}" data-status="${escapeHtml(u.status)}" data-member="${escapeHtml(memberStatus)}" data-action="user-select" style="width:18px;height:18px;cursor:pointer;"/>
            <div class="data-card-title">${escapeHtml(name)}</div>
          </div>
        </div>
        <div class="data-card-body">
          <div class="data-card-row">
            <span class="data-card-label">Email:</span>
            <span class="data-card-value">${escapeHtml(u.email)}</span>
          </div>
          <div class="data-card-row">
            <span class="data-card-label">Registration:</span>
            <span class="data-card-badge" style="background:${regColor};font-size:0.65rem;">${escapeHtml(u.status)}</span>
          </div>
          ${memberStatus !== 'none' ? `
          <div class="data-card-row">
            <span class="data-card-label">Membership:</span>
            <span class="data-card-badge" style="background:${memberColor};font-size:0.65rem;">${memberStatus === 'approved' ? 'member' : escapeHtml(memberStatus)}</span>
          </div>` : ''}
          ${u.subscription_status && u.subscription_status !== 'none' ? `
          <div class="data-card-row">
            <span class="data-card-label">Subscription:</span>
            <span class="data-card-badge" style="background:#8b5cf6;font-size:0.65rem;">${escapeHtml(u.subscription_plan || u.subscription_status)}</span>
          </div>` : ''}
          <div class="data-card-row">
            <span class="data-card-label">Created:</span>
            <span class="data-card-value">${u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</span>
          </div>
        </div>
      `;
    }
    cardContainer.appendChild(card);
  });
}

// Render invites data as cards
function renderInvitesCards(invites) {
  const cardContainer = document.getElementById('invitesCardContainer');
  if (!cardContainer) return;

  cardContainer.innerHTML = '';
  const now = Date.now();

  invites.forEach(i => {
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

    const used = i.used || 0;
    const maxUses = i.max_uses || 1;
    const percentage = Math.min(100, (used / maxUses) * 100);
    let barColor = '#10b981';
    if (percentage > 80) barColor = '#ef4444';
    else if (percentage > 50) barColor = '#f59e0b';

    const createdDate = i.created_at ? new Date(i.created_at).toLocaleDateString() : '—';
    const expiresDate = expiresParsed ? expiresParsed.toLocaleDateString() : '—';

    const card = document.createElement('div');
    card.className = 'data-card';
    card.innerHTML = `
      <div class="data-card-header">
        <div style="display:flex;align-items:center;gap:12px;flex:1;">
          <input type="checkbox" name="invite-select" class="invites-checkbox" data-code="${escapeHtml(i.code)}" data-status="${escapeHtml(actualStatus)}" data-action="invite-select" style="width:18px;height:18px;cursor:pointer;"/>
          <div class="data-card-title" style="font-family:monospace;font-size:0.9rem;">${escapeHtml(i.code)}</div>
        </div>
        <span class="data-card-badge" style="background:${statusColor}">${statusText}</span>
      </div>
      <div class="data-card-body">
        ${i.sent_to ? `
        <div class="data-card-row">
          <span class="data-card-label">Sent To:</span>
          <span class="data-card-value">${escapeHtml(i.sent_to)}</span>
        </div>` : ''}
        <div class="data-card-row">
          <span class="data-card-label">Progress:</span>
          <span class="data-card-value" style="display:flex;align-items:center;gap:8px;">
            <div style="width:80px;height:8px;background:var(--bg-button-secondary);border-radius:4px;overflow:hidden;">
              <div style="width:${percentage}%;height:100%;background:${barColor};"></div>
            </div>
            <span style="font-size:0.8rem;">${used}/${maxUses}</span>
          </span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Auto-Approve:</span>
          <span class="data-card-value">${i.auto_approve ? 'Yes' : 'No'}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Created:</span>
          <span class="data-card-value">${createdDate}</span>
        </div>
        ${i.created_by ? `
        <div class="data-card-row">
          <span class="data-card-label">Created By:</span>
          <span class="data-card-value">${escapeHtml(i.created_by)}</span>
        </div>` : ''}
        <div class="data-card-row">
          <span class="data-card-label">Expires:</span>
          <span class="data-card-value">${expiresDate}</span>
        </div>
      </div>
    `;
    cardContainer.appendChild(card);
  });
}

// Render subscriptions data as cards
function renderSubscribersCards(subscriptions) {
  const cardContainer = document.getElementById('subscriptionsCardContainer');
  if (!cardContainer) return;

  cardContainer.innerHTML = '';
  const now = new Date();

  subscriptions.forEach(s => {
    const expiresDate = new Date(s.expires_at);
    const daysLeft = Math.ceil((expiresDate - now) / (1000 * 60 * 60 * 24));
    const name = `${s.first_name || ''} ${s.last_name || ''}`.trim() || '—';

    let statusText = 'Active';
    let statusColor = '#a855f7';
    if (s.status === 'cancelled') {
      statusText = 'Cancelled';
      statusColor = '#f97316';
    } else if (s.status !== 'active') {
      statusText = 'Expired';
      statusColor = '#6b7280';
    }

    let daysLeftColor = '#10b981';
    if (s.status === 'active') {
      if (daysLeft < 7) daysLeftColor = '#ef4444';
      else if (daysLeft <= 30) daysLeftColor = '#f59e0b';
    }

    const card = document.createElement('div');
    card.className = 'data-card';
    card.innerHTML = `
      <div class="data-card-header">
        <div style="display:flex;align-items:center;gap:12px;flex:1;">
          <input type="checkbox" name="subscription-select" class="subscription-checkbox" data-guid="${escapeHtml(s.user_guid)}" data-action="subscription-select" style="width:18px;height:18px;cursor:pointer;"/>
          <div class="data-card-title">${escapeHtml(name)}</div>
        </div>
        <span class="data-card-badge" style="background:${statusColor}">${statusText}</span>
      </div>
      <div class="data-card-body">
        <div class="data-card-row">
          <span class="data-card-label">Email:</span>
          <span class="data-card-value">${escapeHtml(s.email)}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Plan:</span>
          <span class="data-card-value">${escapeHtml(s.plan) || '—'}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">PIN Enabled:</span>
          <span class="data-card-value">${s.pin_enabled ? 'Yes' : 'No'}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Emails:</span>
          <span class="data-card-value">${s.system_emails_enabled ? 'On' : 'Off'}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Expires:</span>
          <span class="data-card-value">${expiresDate.toLocaleDateString()}</span>
        </div>
        ${s.status === 'active' ? `
        <div class="data-card-row">
          <span class="data-card-label">Days Left:</span>
          <span class="data-card-value" style="color:${daysLeftColor};font-weight:600;">${daysLeft}d</span>
        </div>` : ''}
      </div>
    `;
    cardContainer.appendChild(card);
  });
}

function renderAdminsCards(admins) {
  const cardContainer = document.getElementById('adminsCardContainer');
  if (!cardContainer) return;
  cardContainer.innerHTML = '';

  const adminTypeLabels = {
    'admin': 'Admin',
    'user_admin': 'User',
    'subscriber_admin': 'Subscriber',
    'vote_admin': 'Vote'
  };
  const adminTypeColors = {
    'admin': 'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)',
    'user_admin': 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)',
    'subscriber_admin': 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)',
    'vote_admin': 'linear-gradient(135deg,#10b981 0%,#059669 100%)'
  };

  admins.forEach(a => {
    const name = (a.given_name || '') + (a.family_name ? ' ' + a.family_name : '');
    const adminType = a.admin_type || 'admin';
    const createdDate = a.created_at ? new Date(a.created_at).toLocaleDateString() : '—';

    // Last login relative time
    let lastLoginDisplay = '—';
    if (a.last_login_at) {
      const lastLogin = new Date(a.last_login_at);
      const now = new Date();
      const diffMs = now - lastLogin;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);
      if (diffMins < 1) {
        lastLoginDisplay = 'Just now';
      } else if (diffMins < 60) {
        lastLoginDisplay = `${diffMins}m ago`;
      } else if (diffHours < 24) {
        lastLoginDisplay = `${diffHours}h ago`;
      } else if (diffDays < 7) {
        lastLoginDisplay = `${diffDays}d ago`;
      } else {
        lastLoginDisplay = lastLogin.toLocaleDateString();
      }
    }

    // Status badge
    const statusBadge = a.enabled
      ? '<span class="data-card-badge" style="background:linear-gradient(135deg,#10b981 0%,#059669 100%);">Active</span>'
      : '<span class="data-card-badge" style="background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);">Disabled</span>';

    // Admin type badge
    const adminTypeBadge = `<span class="data-card-badge" style="background:${adminTypeColors[adminType]};">${adminTypeLabels[adminType]}</span>`;

    const card = document.createElement('div');
    card.className = 'data-card';
    card.innerHTML = `
      <div class="data-card-header">
        <input type="checkbox" name="admin-select" class="admin-checkbox" data-email="${escapeHtml(a.email)}" data-enabled="${a.enabled}" data-action="admin-select" />
        <span class="data-card-title">${escapeHtml(name) || '—'}</span>
        ${statusBadge}
      </div>
      <div class="data-card-body">
        <div class="data-card-row">
          <span class="data-card-label">Email:</span>
          <span class="data-card-value">${escapeHtml(a.email)}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Type:</span>
          ${adminTypeBadge}
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Last Login:</span>
          <span class="data-card-value">${lastLoginDisplay}</span>
        </div>
        <div class="data-card-row">
          <span class="data-card-label">Created:</span>
          <span class="data-card-value">${escapeHtml(createdDate)}</span>
        </div>
      </div>
      <div class="data-card-actions">
        <button class="btn" style="background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);" data-action="admin-manage" data-email="${escapeHtml(a.email)}" data-name="${escapeHtml(name)}" data-enabled="${a.enabled}" data-admin-type="${adminType}">Manage</button>
        <button class="btn" style="background:linear-gradient(135deg,#8b5cf6 0%,#7c3aed 100%);" data-action="admin-activity" data-email="${escapeHtml(a.email)}" data-name="${escapeHtml(name)}">Activity</button>
      </div>
    `;
    cardContainer.appendChild(card);
  });
}

// Track user activity
['mousedown', 'keydown', 'scroll', 'touchstart', 'click'].forEach(event => {
  document.addEventListener(event, resetIdleTimer, true);
});

// Toast notification system with optional action button
function showToast(message,type='info',duration=4000,options={}){
  const container=document.getElementById('toastContainer');
  const toast=document.createElement('div');
  toast.className=`toast ${type}`;
  let html=`<span>${escapeHtml(message)}</span>`;
  if(options.action&&options.onAction){
    html+=`<button class="toast-action">${escapeHtml(options.action)}</button>`;
  }
  toast.innerHTML=html;
  container.appendChild(toast);

  if(options.action&&options.onAction){
    toast.querySelector('.toast-action').onclick=async()=>{
      toast.remove();
      try{
        await options.onAction();
        showToast('Action completed','success');
      }catch(e){
        showToast('Action failed: '+(e.message||e),'error');
      }
    };
  }

  if(duration>0){
    setTimeout(()=>{
      toast.classList.add('removing');
      setTimeout(()=>toast.remove(),300);
    },duration);
  }

  return toast;
}

// Generic confirmation modal
let confirmResolve = null;

function showConfirm(title, message, confirmText = 'Confirm', cancelText = 'Cancel', isDanger = false) {
  return new Promise((resolve) => {
    confirmResolve = resolve;

    // Set modal content
    document.getElementById('genericConfirmTitle').textContent = title;
    document.getElementById('genericConfirmMessage').textContent = message;

    const confirmBtn = document.getElementById('genericConfirmBtn');
    confirmBtn.textContent = confirmText;

    // Set button style based on danger flag
    if (isDanger) {
      confirmBtn.style.background = 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)';
    } else {
      confirmBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
    }

    // Set up confirm button click handler
    confirmBtn.onclick = () => closeGenericConfirmModal(true);

    // Show modal
    document.getElementById('genericConfirmModal').classList.add('active');
  });
}

function closeGenericConfirmModal(confirmed) {
  document.getElementById('genericConfirmModal').classList.remove('active');
  if (confirmResolve) {
    confirmResolve(confirmed);
    confirmResolve = null;
  }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Ctrl+F or Cmd+F: Focus search
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault();
    const activeTab = document.querySelector('.tab.active')?.getAttribute('data-tab');
    const searchInput = document.getElementById(activeTab+'Search');
    if (searchInput) {
      searchInput.focus();
      searchInput.select();
    }
  }
  // Ctrl+R or Cmd+R: Refresh current tab (override browser refresh)
  if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
    e.preventDefault();
    const activeTab = document.querySelector('.tab.active')?.getAttribute('data-tab');
    if (activeTab === 'waitlist') loadWaitlist(true);
    else if (activeTab === 'users') loadUsers(true);
    else if (activeTab === 'invites') loadInvites(true);
    else if (activeTab === 'admin') loadAdmins(true);
    else if (activeTab === 'subscriptions') loadAllSubscriptions(true);
    showToast('Refreshed', 'info', 2000);
  }
  // Esc: Clear filters and search
  if (e.key === 'Escape') {
    const activeTab = document.querySelector('.tab.active')?.getAttribute('data-tab');
    if (activeTab === 'users') {
      userFilters.registration='';userFilters.membership='';userFilters.subscription='';userFilters.quickFilter='action';
      paginationState.users.search='';
      document.getElementById('filterRegistration').value='';
      document.getElementById('filterMembership').value='';
      document.getElementById('filterSubscription').value='';
      document.getElementById('usersSearch').value='';
      document.querySelectorAll('#users .btn').forEach(btn=>{if(btn.id&&btn.id.startsWith('quickFilter'))btn.classList.remove('filter-active');});
      document.getElementById('quickFilterAction').classList.add('filter-active');
      loadUsers(true);
      showToast('Filters cleared', 'info', 2000);
    }
  }
});

// Search highlighting utility
function highlightText(text, searchTerm) {
  if (!searchTerm || searchTerm.length < 2) return escapeHtml(text);
  const escaped = escapeHtml(text);
  const escapedTerm = escapeHtml(searchTerm);
  const regex = new RegExp(`(${escapedTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
  return escaped.replace(regex, '<mark>$1</mark>');
}

// Sorting state
const sortState = {
  users: { column: null, direction: 'asc' },
  invites: { column: null, direction: 'asc' },
  admins: { column: null, direction: 'asc' },
  subscriptions: { column: null, direction: 'asc' }
};

// Sort array by column
function sortData(data, column, direction = 'asc') {
  return [...data].sort((a, b) => {
    let aVal = a[column] ?? '';
    let bVal = b[column] ?? '';

    // Handle different data types
    if (typeof aVal === 'string') aVal = aVal.toLowerCase();
    if (typeof bVal === 'string') bVal = bVal.toLowerCase();

    if (aVal < bVal) return direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return direction === 'asc' ? 1 : -1;
    return 0;
  });
}

// Helper functions for empty states and loading skeletons
function showEmptyState(tableId,text,subtext='',actionHtml=''){
  const tbody=document.querySelector(`#${tableId} tbody`);
  const colSpan=tbody.closest('table').querySelectorAll('thead th').length;
  tbody.innerHTML=`<tr><td colspan="${colSpan}" class="empty-state"><div class="empty-state-icon">📭</div><div class="empty-state-text">${text}</div>${subtext?`<div class="empty-state-subtext">${subtext}</div>`:''}${actionHtml}</td></tr>`;
}

function showLoadingSkeleton(tableId){
  const tbody=document.querySelector(`#${tableId} tbody`);
  const colSpan=tbody.closest('table').querySelectorAll('thead th').length;
  tbody.innerHTML=`<tr><td colspan="${colSpan}"><div class="skeleton" style="height:40px;margin:8px 0;border-radius:4px;"></div><div class="skeleton" style="height:40px;margin:8px 0;border-radius:4px;"></div><div class="skeleton" style="height:40px;margin:8px 0;border-radius:4px;"></div></td></tr>`;
}

function showGridLoadingSkeleton(containerId, count = 3) {
  const container = document.getElementById(containerId);
  let skeletonHTML = '';
  for (let i = 0; i < count; i++) {
    skeletonHTML += `
      <div style="padding:20px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border);">
        <div class="skeleton" style="height:24px;margin-bottom:12px;border-radius:4px;width:60%;"></div>
        <div class="skeleton" style="height:16px;margin-bottom:8px;border-radius:4px;width:80%;"></div>
        <div class="skeleton" style="height:16px;margin-bottom:8px;border-radius:4px;width:70%;"></div>
        <div class="skeleton" style="height:36px;margin-top:16px;border-radius:4px;width:100%;"></div>
      </div>
    `;
  }
  container.innerHTML = skeletonHTML;
}

function createProgressBar(percentage,color='#10b981'){
  return `<div class="progress-bar"><div class="progress-bar-fill" style="width:${percentage}%;background:${color};"></div></div>`;
}

// PKCE helpers
function b64url(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function sha256(str){const enc=new TextEncoder().encode(str);const buf=await crypto.subtle.digest('SHA-256',enc);return b64url(buf);}
// SECURITY FIX: Use proper base64url encoding to avoid modulo bias
function rand(n=64){const a=new Uint8Array(n);crypto.getRandomValues(a);return b64url(a.buffer).substring(0,n);}
function authUrl(codeChallenge,state){const u=new URL(COGNITO_DOMAIN+'/oauth2/authorize');u.searchParams.set('client_id',CLIENT_ID);u.searchParams.set('response_type','code');u.searchParams.set('scope','openid email');u.searchParams.set('redirect_uri',REDIRECT_URI);u.searchParams.set('code_challenge_method','S256');u.searchParams.set('code_challenge',codeChallenge);u.searchParams.set('state',state);return u.toString();}
function tokenUrl(){return COGNITO_DOMAIN+'/oauth2/token';}
function logoutUrl(){const u=new URL(COGNITO_DOMAIN+'/logout');u.searchParams.set('client_id',CLIENT_ID);u.searchParams.set('logout_uri',REDIRECT_URI);return u.toString();}
function saveTokens(t){localStorage.setItem('tokens',JSON.stringify(t));}
function loadTokens(){try{return JSON.parse(localStorage.getItem('tokens')||'null')}catch{return null}}
function clearTokens(){localStorage.removeItem('tokens');}
function idToken(){return (loadTokens()||{}).id_token;}
function accessToken(){return (loadTokens()||{}).access_token;}
function refreshToken(){return (loadTokens()||{}).refresh_token;}
function signedIn(){return !!idToken();}
function b64urlDecode(str){str=str.replace(/-/g,'+').replace(/_/g,'/');const pad=str.length%4?4-(str.length%4):0;return atob(str+'='.repeat(pad));}
/* SECURITY NOTE: Frontend JWT parsing is for display/UX purposes only.
 * JWT signature validation is performed server-side by API Gateway's Cognito authorizer.
 * Never trust client-side JWT claims for authorization - they can be tampered with.
 * All protected API endpoints validate the JWT signature and claims on the backend. */
function parseJwt(idt){try{const [h,p,s]=idt.split('.');return{header:JSON.parse(b64urlDecode(h)),payload:JSON.parse(b64urlDecode(p)),signature:s};}catch{return{header:{},payload:{},signature:''};}}
function tokenIsExpired(){const idt=idToken();if(!idt)return true;try{const{payload}=parseJwt(idt);const expiryTime=payload.exp*1000;const now=Date.now();return expiryTime<(now+60000);}catch{return true;}}

// Periodic token expiry check - redirects to login if session expired
let tokenExpiryInterval=null;
function startTokenExpiryCheck(){
  if(tokenExpiryInterval)return;
  tokenExpiryInterval=setInterval(()=>{
    if(signedIn()&&tokenIsExpired()){
      clearTokens();
      showToast('Session expired. Redirecting to login...','warning');
      setTimeout(()=>{location.href=logoutUrl();},2000);
    }
  },30000); // Check every 30 seconds
}
function stopTokenExpiryCheck(){
  if(tokenExpiryInterval){clearInterval(tokenExpiryInterval);tokenExpiryInterval=null;}
}

/* NOTE: isAdmin() check is for UI/UX only. API Gateway enforces authorization server-side. */
function isAdmin(){if(!signedIn())return false;const{payload}=parseJwt(idToken());const groups=payload['cognito:groups']||[];return Array.isArray(groups)&&groups.includes('admin');}
function getAdminType(){if(!signedIn())return null;const{payload}=parseJwt(idToken());return payload['custom:admin_type']||'admin';}
async function exchange(code){const v=sessionStorage.getItem('pkce_verifier');if(!v) throw new Error('Missing verifier');const body=new URLSearchParams();body.set('grant_type','authorization_code');body.set('client_id',CLIENT_ID);body.set('code',code);body.set('redirect_uri',REDIRECT_URI);body.set('code_verifier',v);const res=await fetch(tokenUrl(),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()});if(!res.ok) throw new Error(await res.text());const t=await res.json();saveTokens(t);sessionStorage.removeItem('pkce_verifier');return t;}
let refreshPromise=null;
async function refresh(){const r=refreshToken();if(!r) return;const body=new URLSearchParams();body.set('grant_type','refresh_token');body.set('client_id',CLIENT_ID);body.set('refresh_token',r);const res=await fetch(tokenUrl(),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()});if(res.ok){const t=await res.json();if(!t.refresh_token) t.refresh_token=r;saveTokens(t);}else{clearTokens();}}
function beginLogin(){const v=rand(64);sessionStorage.setItem('pkce_verifier',v);sha256(v).then(ch=>{const st=rand(24);sessionStorage.setItem('oauth_state',st);location.href=authUrl(ch,st);});}
function handleRedirect(){const p=new URLSearchParams(location.search);const code=p.get('code');const st=p.get('state');if(code&&st&&st===sessionStorage.getItem('oauth_state')){history.replaceState(null,'',location.pathname);exchange(code).then(()=>{renderAuth();if(isAdmin()){const adminType=getAdminType();if(adminType==='user_admin'){loadUsers();}else if(adminType==='subscriber_admin'){loadInvites();}else if(adminType==='vote_admin'){loadAllProposalsAdmin();}else{loadUsers();}}}).catch(err=>{document.querySelector('.wrap').insertAdjacentHTML('afterbegin',"<div class='card'>Login error: "+escapeHtml(err.message||err)+"</div>");});}}
function signOut(){clearTokens();location.href=logoutUrl();}
async function api(path,opts={}){if(tokenIsExpired()){if(!refreshPromise){refreshPromise=refresh().finally(()=>refreshPromise=null);}await refreshPromise;}const res=await fetch(API_URL+path,{...opts,headers:{'Authorization':'Bearer '+idToken(),'Content-Type':'application/json',...(opts.headers||{})}});if(!res.ok) throw new Error(await res.text());return res.json();}
function renderAuth(){
  const signed=signedIn();
  const admin=isAdmin();
  const adminType=getAdminType();

  document.getElementById('signin').style.display=signed?'none':'inline-block';
  document.getElementById('signout').style.display=signed?'inline-block':'none';
  document.querySelectorAll('.admin-only').forEach(el=>el.style.display=admin?'flex':'none');
  document.getElementById('notAdminError').style.display=(signed&&!admin)?'block':'none';

  const emailEl=document.getElementById('userEmail');
  const adminTypeEl=document.getElementById('userAdminType');
  const dropdownContainer=document.getElementById('userDropdownContainer');

  if(signed){
    const{payload}=parseJwt(idToken());
    emailEl.textContent=payload.email||'';
    dropdownContainer.style.display='block';

    // Show admin type badge
    if(admin&&adminType){
      const adminTypeLabels={
        'admin':'A',
        'user_admin':'U',
        'subscriber_admin':'S',
        'vote_admin':'V'
      };
      const adminTypeColors={
        'admin':'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)',
        'user_admin':'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)',
        'subscriber_admin':'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)',
        'vote_admin':'linear-gradient(135deg,#10b981 0%,#059669 100%)'
      };
      adminTypeEl.innerHTML=`<span style="display:inline-block;background:${adminTypeColors[adminType]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">${adminTypeLabels[adminType]}</span>`;
    }else{
      adminTypeEl.innerHTML='';
    }
  }else{
    dropdownContainer.style.display='none';
  }

  // Show/hide tabs based on admin type
  if(admin){
    const tabPermissions={
      'admin':['waitlist','users','subscriptions','invites','help-requests','vote-management','site-management','admin'],
      'user_admin':['waitlist','users'],
      'subscriber_admin':['subscriptions','invites'],
      'vote_admin':['vote-management']
    };
    // Default to 'admin' if adminType is missing
    const effectiveAdminType=adminType||'admin';
    const allowedTabs=tabPermissions[effectiveAdminType]||tabPermissions['admin'];

    // Hide/show tab buttons
    document.querySelectorAll('.tab').forEach(tab=>{
      const tabName=tab.getAttribute('data-tab');
      if(allowedTabs.includes(tabName)){
        tab.style.display='inline-block';
      }else{
        tab.style.display='none';
      }
    });

    // Activate first allowed tab
    const firstAllowedTab=allowedTabs[0];
    if(firstAllowedTab){
      document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
      const targetTab=document.querySelector(`.tab[data-tab="${firstAllowedTab}"]`);
      const targetContent=document.getElementById(firstAllowedTab);
      if(targetTab)targetTab.classList.add('active');
      if(targetContent)targetContent.classList.add('active');
    }
  }
}
document.getElementById('signin').onclick=beginLogin;

// Initialize and attach theme toggle
initTheme();
document.getElementById('themeToggle').onclick=toggleTheme;

// Initialize view preferences
initViewPreferences();

// Pagination state
const paginationState={users:{page:0,perPage:10,total:0,search:''},invites:{page:0,perPage:10,total:0,search:''},admins:{page:0,perPage:10,total:0,search:''},subscriptions:{page:0,perPage:10,total:0,search:''}};
// Track which tabs have been loaded
const tabsLoaded={waitlist:false,users:false,invites:false,admins:false,subscriptions:false,'site-management':false,'vote-management':false};
// Debounce utility function
function debounce(func,delay=300){let timeout;return function(...args){clearTimeout(timeout);timeout=setTimeout(()=>func.apply(this,args),delay);}}
// Filter state for Users tab
const userFilters={registration:'',membership:'',subscription:'',quickFilter:'action',dateFrom:'',dateTo:'',lastActive:''};
// Filter state for Subscriptions tab
const subFilters={status:'',plan:'',quickFilter:'all'};

// Unified user data storage
let allUsersData=[];
// Invited users from waitlist (haven't registered yet)
let invitedWaitlistUsers=[];
// Unified subscriptions data storage
let allSubscriptionsData=[];

// Status badge rendering
function renderStatusBadges(user){
  const badges=[];

  // Registration status badge
  if(user.status==='pending'){
    badges.push('<span style="display:inline-block;background:#f59e0b;color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Pending Reg</span>');
  }else if(user.status==='approved'){
    badges.push('<span style="display:inline-block;background:#10b981;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Approved</span>');
  }else if(user.status==='rejected'){
    badges.push('<span style="display:inline-block;background:#ef4444;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Rejected</span>');
  }else if(user.status==='disabled'){
    badges.push('<span style="display:inline-block;background:#6b7280;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Disabled</span>');
  }else if(user.status==='deleted'){
    badges.push('<span style="display:inline-block;background:#991b1b;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Deleted</span>');
  }

  // Membership status badge
  const membershipStatus=user.membership_status||'none';
  if(membershipStatus==='pending'){
    badges.push('<span style="display:inline-block;background:#8b5cf6;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member Req</span>');
  }else if(membershipStatus==='approved'){
    badges.push('<span style="display:inline-block;background:#3b82f6;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member</span>');
  }else if(membershipStatus==='denied'){
    badges.push('<span style="display:inline-block;background:#dc2626;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Member Denied</span>');
  }

  // Subscription status badge
  const subStatus=user.subscription_status||'none';
  if(subStatus==='active'){
    badges.push('<span style="display:inline-block;background:#a855f7;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Active Sub</span>');
  }else if(subStatus==='cancelled'){
    badges.push('<span style="display:inline-block;background:#f97316;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Cancelled Sub</span>');
  }else if(subStatus==='expired'){
    badges.push('<span style="display:inline-block;background:#78716c;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Expired Sub</span>');
  }

  return badges.join('');
}

// Comprehensive user data loading
async function loadUsers(resetPage=true){
  if(!isAdmin())return;
  if(resetPage)paginationState.users.page=0;
  const tbody=document.querySelector('#usersTable tbody');
  showLoadingSkeleton('usersTable');

  try{
    // Fetch all user data if needed
    if(resetPage||allUsersData.length===0){
      const [regData,memberData,subData,waitlistData]=await Promise.all([
        api('/admin/registrations'),
        api('/admin/membership-requests'),
        api('/admin/subscriptions?status=active'),
        api('/admin/waitlist')
      ]);

      // Create a map of memberships by registration_id
      const memberMap=new Map();
      (memberData.registrations||[]).forEach(m=>{
        memberMap.set(m.registration_id,m);
      });

      // Create a map of subscriptions by user_guid
      const subMap=new Map();
      (subData.subscriptions||[]).forEach(s=>{
        subMap.set(s.user_guid,s);
      });

      // Combine all data - regData returns {items: [...]} not a direct array
      const registrations = regData.items || regData || [];
      allUsersData=registrations.map(r=>{
        const member=memberMap.get(r.registration_id)||{};
        const sub=subMap.get(r.user_guid)||{};
        return{
          ...r,
          membership_status:member.membership_status||'none',
          membership_requested_at:member.membership_requested_at,
          subscription_status:sub.status||'none',
          subscription_plan:sub.plan||sub.subscription_type_name,
          subscription_expires:sub.expires_at
        };
      });

      // Get invited users from waitlist who haven't registered yet
      const waitlist=waitlistData.waitlist||[];
      const registeredEmails=new Set(registrations.map(r=>r.email?.toLowerCase()));
      invitedWaitlistUsers=waitlist.filter(w=>w.status==='invited'&&!registeredEmails.has(w.email?.toLowerCase()));
    }

    // Special handling for invited users (from waitlist, not registrations)
    const showingInvited=userFilters.quickFilter==='invited';
    let filtered;

    if(showingInvited){
      // Filter invited waitlist users
      filtered=invitedWaitlistUsers.filter(u=>{
        if(paginationState.users.search){
          const query=paginationState.users.search.toLowerCase();
          const searchMatch=[u.first_name,u.last_name,u.email,u.invite_code].some(f=>(f||'').toLowerCase().includes(query));
          if(!searchMatch)return false;
        }
        return true;
      });
    }else{
      // Apply filters to registered users
      filtered=allUsersData.filter(u=>{
        // Search filter
        if(paginationState.users.search){
          const query=paginationState.users.search.toLowerCase();
          const searchMatch=[u.first_name,u.last_name,u.email,u.invite_code,u.user_guid].some(f=>(f||'').toLowerCase().includes(query));
          if(!searchMatch)return false;
        }

        // Registration status filter
        if(userFilters.registration&&u.status!==userFilters.registration)return false;

        // Membership status filter
        if(userFilters.membership){
          const memberStatus=u.membership_status||'none';
          if(memberStatus!==userFilters.membership)return false;
        }

        // Subscription status filter
        if(userFilters.subscription){
          const subStatus=u.subscription_status||'none';
          if(subStatus!==userFilters.subscription)return false;
        }

        // Date range filter - registration date
        if(userFilters.dateFrom){
          const fromDate=new Date(userFilters.dateFrom);
          fromDate.setHours(0,0,0,0);
          const regDate=new Date(u.created_at);
          if(regDate<fromDate)return false;
        }
        if(userFilters.dateTo){
          const toDate=new Date(userFilters.dateTo);
          toDate.setHours(23,59,59,999);
          const regDate=new Date(u.created_at);
          if(regDate>toDate)return false;
        }

        // Last active filter - based on last_login_at field
        if(userFilters.lastActive){
          const now=new Date();
          const lastLogin=u.last_login_at?new Date(u.last_login_at):null;

          if(userFilters.lastActive==='1'){
            // Last 24 hours
            if(!lastLogin||now-lastLogin>24*60*60*1000)return false;
          }else if(userFilters.lastActive==='7'){
            // Last 7 days
            if(!lastLogin||now-lastLogin>7*24*60*60*1000)return false;
          }else if(userFilters.lastActive==='30'){
            // Last 30 days
            if(!lastLogin||now-lastLogin>30*24*60*60*1000)return false;
          }else if(userFilters.lastActive==='90'){
            // Last 90 days
            if(!lastLogin||now-lastLogin>90*24*60*60*1000)return false;
          }else if(userFilters.lastActive==='inactive-30'){
            // Inactive 30+ days
            if(!lastLogin||now-lastLogin<=30*24*60*60*1000)return false;
          }else if(userFilters.lastActive==='inactive-90'){
            // Inactive 90+ days
            if(!lastLogin||now-lastLogin<=90*24*60*60*1000)return false;
          }
        }

        // Quick filter
        if(userFilters.quickFilter==='action'){
          const needsAction=u.status==='pending'||u.membership_status==='pending';
          if(!needsAction)return false;
        }else if(userFilters.quickFilter==='registered'){
          const isRegistered=(u.status==='approved')||(u.subscription_status==='active');
          if(!isRegistered)return false;
        }else if(userFilters.quickFilter==='disabled'){
          const isDisabled=u.status==='disabled';
          if(!isDisabled)return false;
        }

        return true;
      });
    }

    // Apply sorting
    if(sortState.users.column){
      filtered=sortData(filtered,sortState.users.column,sortState.users.direction);
    }

    // Update counts
    const actionCount=allUsersData.filter(u=>u.status==='pending'||u.membership_status==='pending').length;
    const registeredCount=allUsersData.filter(u=>(u.status==='approved')||(u.subscription_status==='active')).length;
    const disabledCount=allUsersData.filter(u=>u.status==='disabled').length;
    const invitedCount=invitedWaitlistUsers.length;
    document.getElementById('actionCount').textContent=actionCount;
    document.getElementById('registeredCount').textContent=registeredCount;
    document.getElementById('disabledCount').textContent=disabledCount;
    const invitedCountEl=document.getElementById('invitedCount');
    if(invitedCountEl)invitedCountEl.textContent=invitedCount;

    // Pagination
    const page=updatePagination('users',filtered);
    tbody.innerHTML='';

    // Clear checkboxes
    document.getElementById('selectAllUsers').checked=false;

    const searchTerm=paginationState.users.search;

    if(page.length===0){
      const emptyMsg=showingInvited?'No invited users pending registration.':'No users found matching the current filters.';
      tbody.innerHTML=`<tr><td colspan="4" class="muted" style="text-align:center;padding:40px;">${emptyMsg}</td></tr>`;
    }else if(showingInvited){
      // Render invited waitlist users
      page.forEach(u=>{
        const tr=document.createElement('tr');
        const name=`${u.first_name||''} ${u.last_name||''}`.trim();
        const highlightedName=highlightText(name,searchTerm);
        const highlightedEmail=highlightText(u.email,searchTerm);

        // Invited badge and invite code
        const invitedBadge='<span style="display:inline-block;background:#6366f1;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;margin-right:4px;">Invited</span>';
        const inviteCode=u.invite_code?`<span style="font-family:monospace;font-size:0.75rem;color:var(--gray);margin-left:4px;">${escapeHtml(u.invite_code)}</span>`:'';
        const invitedAt=u.invited_at?`<span style="font-size:0.7rem;color:var(--gray);margin-left:8px;">${new Date(u.invited_at).toLocaleDateString()}</span>`:'';

        tr.innerHTML=`
          <td><input type='checkbox' disabled style="opacity:0.3;" /></td>
          <td>${highlightedName||'—'}</td>
          <td>${highlightedEmail}</td>
          <td>${invitedBadge}${inviteCode}${invitedAt}</td>
        `;
        tbody.appendChild(tr);
      });
    }else{
      page.forEach(u=>{
        const tr=document.createElement('tr');
        const name=`${u.first_name||''} ${u.last_name||''}`.trim();
        const badges=renderStatusBadges(u);

        // Apply search highlighting
        const highlightedName=highlightText(name,searchTerm);
        const highlightedEmail=highlightText(u.email,searchTerm);

        tr.innerHTML=`
          <td><input type='checkbox' name='user-select' class='user-checkbox' data-id='${escapeHtml(u.registration_id)}' data-status='${escapeHtml(u.status)}' data-member='${escapeHtml(u.membership_status||'none')}' /></td>
          <td>${highlightedName||'—'}</td>
          <td>${highlightedEmail}</td>
          <td>${badges}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    updateUsersSelectedCount();

    // Render cards for mobile view
    renderUsersCards(page,showingInvited);
  }catch(e){
    tbody.innerHTML=`<tr><td colspan="4" class="muted">Error: ${escapeHtml(e.message||String(e))}</td></tr>`;
  }
}

// Users tab event handlers
function updateUsersSelectedCount(){
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const count=checkboxes.length;
  const countText=count>0?`${count} selected`:'';
  document.getElementById('usersBulkCount').textContent=countText;

  // Check if any selected users have pending registration status
  const hasPendingReg=Array.from(checkboxes).some(cb=>cb.dataset.status==='pending');

  // Check if any selected users are approved (for disable button)
  const hasApproved=Array.from(checkboxes).some(cb=>cb.dataset.status==='approved');

  // Check if any selected users are disabled or rejected (for permanent delete button)
  const hasDisabled=Array.from(checkboxes).some(cb=>cb.dataset.status==='disabled');
  const hasRejected=Array.from(checkboxes).some(cb=>cb.dataset.status==='rejected');

  // Enable/disable buttons based on selection
  document.getElementById('bulkApproveReg').disabled=count===0||!hasPendingReg;
  document.getElementById('bulkRejectReg').disabled=count===0||!hasPendingReg;
  document.getElementById('bulkDisableUsers').disabled=count===0||!hasApproved;
  document.getElementById('bulkEnableUsers').disabled=count===0||!hasDisabled;
  document.getElementById('bulkDeleteUsers').disabled=count===0||!(hasDisabled||hasRejected);
}

// Quick filter buttons
document.getElementById('quickFilterAction').onclick=()=>{
  userFilters.quickFilter='action';
  document.querySelectorAll('#users .btn').forEach(btn => {
    if(btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterAction').classList.add('filter-active');
  paginationState.users.page=0;
  loadUsers(false);
};
document.getElementById('quickFilterRegistered').onclick=()=>{
  userFilters.quickFilter='registered';
  document.querySelectorAll('#users .btn').forEach(btn => {
    if(btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterRegistered').classList.add('filter-active');
  paginationState.users.page=0;
  loadUsers(false);
};
document.getElementById('quickFilterDisabled').onclick=()=>{
  userFilters.quickFilter='disabled';
  document.querySelectorAll('#users .btn').forEach(btn => {
    if(btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterDisabled').classList.add('filter-active');
  paginationState.users.page=0;
  loadUsers(false);
};
// Invited filter (shows users invited from waitlist who haven't registered yet)
const usersInvitedBtn=document.getElementById('quickFilterInvited');
if(usersInvitedBtn){
  usersInvitedBtn.onclick=()=>{
    userFilters.quickFilter='invited';
    document.querySelectorAll('#users .btn').forEach(btn => {
      if(btn.id && btn.id.startsWith('quickFilter')) btn.classList.remove('filter-active');
    });
    usersInvitedBtn.classList.add('filter-active');
    paginationState.users.page=0;
    loadUsers(false);
  };
}

// Advanced filters
document.getElementById('filterRegistration').onchange=e=>{userFilters.registration=e.target.value;paginationState.users.page=0;loadUsers(false);};
document.getElementById('filterMembership').onchange=e=>{userFilters.membership=e.target.value;paginationState.users.page=0;loadUsers(false);};
document.getElementById('filterSubscription').onchange=e=>{userFilters.subscription=e.target.value;paginationState.users.page=0;loadUsers(false);};
document.getElementById('filterDateFrom').onchange=e=>{userFilters.dateFrom=e.target.value;paginationState.users.page=0;loadUsers(false);};
document.getElementById('filterDateTo').onchange=e=>{userFilters.dateTo=e.target.value;paginationState.users.page=0;loadUsers(false);};
document.getElementById('filterLastActive').onchange=e=>{userFilters.lastActive=e.target.value;paginationState.users.page=0;loadUsers(false);};

// Reset filters
document.getElementById('resetFilters').onclick=()=>{
  userFilters.registration='';userFilters.membership='';userFilters.subscription='';userFilters.quickFilter='action';userFilters.dateFrom='';userFilters.dateTo='';userFilters.lastActive='';paginationState.users.search='';
  document.getElementById('filterRegistration').value='';document.getElementById('filterMembership').value='';document.getElementById('filterSubscription').value='';document.getElementById('filterDateFrom').value='';document.getElementById('filterDateTo').value='';document.getElementById('filterLastActive').value='';document.getElementById('usersSearch').value='';
  document.querySelectorAll('#users .btn').forEach(btn=>{if(btn.id&&btn.id.startsWith('quickFilter'))btn.classList.remove('filter-active');});
  document.getElementById('quickFilterAction').classList.add('filter-active');
  loadUsers(true);
};

// Search with debouncing
const debouncedLoadUsers=debounce(()=>loadUsers(false),300);
document.getElementById('usersSearch').oninput=e=>{paginationState.users.search=e.target.value;paginationState.users.page=0;document.getElementById('selectAllUsers').checked=false;debouncedLoadUsers();};

// Refresh button
document.getElementById('refreshUsers').onclick=()=>loadUsers(true);

// Bulk actions with Promise.allSettled for parallel processing
document.getElementById('bulkApproveReg').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.status==='pending');
  if(items.length===0){showToast('No pending registrations selected','warning');return;}

  const confirmed = await showConfirm(
    'Approve Registrations',
    `Approve ${items.length} registration(s)? Users will be granted access to the platform.`,
    'Approve',
    'Cancel',
    false
  );
  if(!confirmed)return;

  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/registrations/${cb.dataset.id}/approve`,{method:'POST'}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Approved ${succeeded} registration(s) successfully`,'success');
  }
  await loadUsers();
};

document.getElementById('bulkRejectReg').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.status==='pending');
  if(items.length===0){showToast('No pending registrations selected','warning');return;}
  const reason=prompt('Enter rejection reason (optional):');
  if(reason===null)return; // User cancelled

  const confirmed = await showConfirm(
    'Reject Registrations',
    `Reject ${items.length} registration(s)? Users will be notified${reason ? ' with the reason provided' : ''}.`,
    'Reject',
    'Cancel',
    true  // isDanger
  );
  if(!confirmed)return;

  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/registrations/${cb.dataset.id}/reject`,{method:'POST',body:JSON.stringify({reason})}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Rejected ${succeeded} registration(s) successfully`,'success');
  }
  await loadUsers();
};

document.getElementById('bulkDisableUsers').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.status==='approved');
  if(items.length===0){showToast('No approved users selected','warning');return;}

  const confirmed = await showConfirm(
    'Disable Users',
    `Disable ${items.length} user(s)? They will lose access to the platform until re-enabled.`,
    'Disable',
    'Cancel',
    true  // isDanger
  );
  if(!confirmed)return;

  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/users/${cb.dataset.id}/disable`,{method:'POST'}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Disabled ${succeeded} user(s) successfully`,'success');
  }
  await loadUsers();
};

document.getElementById('bulkEnableUsers').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.status==='disabled');
  if(items.length===0){showToast('No disabled users selected','warning');return;}

  const confirmed = await showConfirm(
    'Enable Users',
    `Enable ${items.length} user(s)? They will regain access to the platform.`,
    'Enable',
    'Cancel',
    false
  );
  if(!confirmed)return;

  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/users/${cb.dataset.id}/enable`,{method:'POST'}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Enabled ${succeeded} user(s) successfully`,'success');
  }
  await loadUsers();
};

document.getElementById('bulkDeleteUsers').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.user-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.status==='disabled'||cb.dataset.status==='rejected');
  if(items.length===0){showToast('No disabled or rejected users selected','warning');return;}

  // First confirmation
  const firstConfirm = await showConfirm(
    'Permanent Deletion Warning',
    `WARNING: This will PERMANENTLY DELETE ${items.length} user(s).\n\nThis action cannot be undone. All user data will be removed from the system.\n\nAre you sure you want to continue?`,
    'Continue',
    'Cancel',
    true
  );
  if(!firstConfirm) return;

  // Final confirmation
  const finalConfirm = await showConfirm(
    'Final Confirmation',
    `FINAL CONFIRMATION: Permanently delete ${items.length} user(s)?`,
    'Delete Permanently',
    'Cancel',
    true
  );
  if(!finalConfirm) return;

  const progressToast=showToast(`Deleting 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/users/${cb.dataset.id}/permanently-delete`,{method:'DELETE'}).then(()=>{
      progressToast.querySelector('span').textContent=`Deleting ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} deleted, ${failed} failed`,'warning');
  }else{
    showToast(`Permanently deleted ${succeeded} user(s)`,'success');
  }
  await loadUsers();
};

// Pagination controls - clear selection on page change
document.getElementById('usersPerPage').onchange=e=>{
  paginationState.users.perPage=Number(e.target.value);
  paginationState.users.page=0;
  document.getElementById('selectAllUsers').checked=false;
  loadUsers(false);
};
document.getElementById('usersPrev').onclick=()=>{
  if(paginationState.users.page>0){
    paginationState.users.page--;
    document.getElementById('selectAllUsers').checked=false;
    loadUsers(false);
  }
};
document.getElementById('usersNext').onclick=()=>{
  if((paginationState.users.page+1)*paginationState.users.perPage<paginationState.users.total){
    paginationState.users.page++;
    document.getElementById('selectAllUsers').checked=false;
    loadUsers(false);
  }
};

document.getElementById('selectAllUsers').onchange=function(){document.querySelectorAll('.user-checkbox').forEach(cb=>cb.checked=this.checked);updateUsersSelectedCount();};
document.addEventListener('change',e=>{
  if(e.target.classList.contains('user-checkbox')){
    updateUsersSelectedCount();
    const total=document.querySelectorAll('.user-checkbox').length;
    const checked=document.querySelectorAll('.user-checkbox:checked').length;
    document.getElementById('selectAllUsers').checked=total>0&&checked===total;
  }
});

function updatePagination(list,items){const state=paginationState[list];const start=state.page*state.perPage;const end=start+state.perPage;const page=items.slice(start,end);state.total=items.length;const infoEl=document.getElementById(list+'Info');const prevBtn=document.getElementById(list+'Prev');const nextBtn=document.getElementById(list+'Next');if(items.length===0){infoEl.textContent='No items';prevBtn.disabled=true;nextBtn.disabled=true;}else{infoEl.textContent=`${start+1}-${Math.min(end,items.length)} of ${items.length}`;prevBtn.disabled=state.page===0;nextBtn.disabled=end>=items.length;}return page;}
function searchFilter(item,query,fields){if(!query)return true;const q=query.toLowerCase();return fields.some(f=>(item[f]||'').toLowerCase().includes(q));}

handleRedirect();renderAuth();
// Start periodic token expiry check if signed in
if(signedIn()){startTokenExpiryCheck();}
// Mark users tab as loaded and load it on page load (default active tab)
if(signedIn()&&isAdmin()){tabsLoaded.users=true;loadUsers();}
let invitesData=[];
let inviteQuickFilter='active';
async function loadInvites(resetPage=true){
  if(!isAdmin())return;
  if(resetPage)paginationState.invites.page=0;
  const tbody=document.querySelector('#invitesTable tbody');

  // Show loading skeleton
  showLoadingSkeleton('invitesTable');

  try{
    // Fetch all invites (no status filter in API call)
    if(resetPage||invitesData.length===0){
      const response=await api('/admin/invites');
      // API returns { items, count, limit, nextCursor } - extract items array
      invitesData=Array.isArray(response)?response:(response.items||[]);
    }

    // Update quick filter counts
    updateInviteFilterCounts();

    // Render invites
    renderInvites();
  }catch(e){
    showToast('Failed to load invites: '+(e.message||e),'error');
    tbody.innerHTML=`<tr><td colspan="8" class="muted">${escapeHtml(e.message||String(e))}</td></tr>`;
  }
}

function updateInviteFilterCounts(){
  const now=Date.now();
  let activeCt=0,expiringSoonCt=0,usedCt=0;

  invitesData.forEach(i=>{
    const expiresAt=i.expires_at?i.expires_at*1000:null;
    const daysLeft=expiresAt?Math.ceil((expiresAt-now)/(1000*60*60*24)):null;
    const isExpired=expiresAt&&expiresAt<now;
    const isExpiringSoon=daysLeft&&daysLeft<7&&daysLeft>0;

    if(i.status==='exhausted' || i.status==='expired' || isExpired){
      usedCt++;
    }else if(i.status==='active'||i.status==='new'){
      activeCt++;
      if(isExpiringSoon)expiringSoonCt++;
    }
  });

  document.getElementById('activeInvitesCount').textContent=activeCt;
  document.getElementById('expiringSoonInvitesCount').textContent=expiringSoonCt;
  document.getElementById('usedInvitesCount').textContent=usedCt;
}

// Invites multi-select functionality
function updateInvitesSelectedCount(){
  const checkboxes=document.querySelectorAll('.invites-checkbox:checked');
  const count=checkboxes.length;
  const countEl=document.getElementById('invitesSelectedCount');
  countEl.textContent=count>0?`${count} selected`:'';

  const statuses=Array.from(checkboxes).map(cb=>cb.getAttribute('data-status'));
  const hasActive=statuses.includes('active');

  document.getElementById('bulkExpireInvites').disabled=!hasActive;
  document.getElementById('bulkDeleteInvites').disabled=count===0;
}

function renderInvites(){
  const tbody=document.querySelector('#invitesTable tbody');
  tbody.innerHTML='';
  const now=Date.now();

  // Apply filters
  let filtered=invitesData.filter(i=>{
    // Quick filter
    const expiresParsed=parseTimestamp(i.expires_at);
    const expiresAt=expiresParsed?expiresParsed.getTime():null;
    const daysLeft=expiresAt?Math.ceil((expiresAt-now)/(1000*60*60*24)):null;
    const isExpired=expiresAt&&expiresAt<now;
    const isExpiringSoon=daysLeft&&daysLeft<7&&daysLeft>0;

    if(inviteQuickFilter==='active'&&i.status!=='active'&&i.status!=='new')return false;
    if(inviteQuickFilter==='expiring'&&(!isExpiringSoon||i.status==='exhausted'||i.status==='expired'||isExpired))return false;
    if(inviteQuickFilter==='used'&&!(i.status==='exhausted'||i.status==='expired'||isExpired))return false;

    // Search filter (searches code and sent_to email)
    const search=paginationState.invites.search.toLowerCase();
    const matchesCode=i.code.toLowerCase().includes(search);
    const matchesSentTo=(i.sent_to||'').toLowerCase().includes(search);
    if(search&&!matchesCode&&!matchesSentTo)return false;

    return true;
  });

  // Check for empty state
  if(filtered.length===0){
    showEmptyState('invitesTable','No invites found','Try adjusting your filters');
    return;
  }

  // Paginate
  const page=updatePagination('invites',filtered);
  const searchTerm=paginationState.invites.search;

  page.forEach(i=>{
    const tr=document.createElement('tr');
    const createdDate=i.created_at?new Date(i.created_at).toLocaleString():'—';
    const expiresParsed=parseTimestamp(i.expires_at);
    const expiresDate=expiresParsed?expiresParsed.toLocaleString():'—';
    const autoApprove=i.auto_approve?'Yes':'No';

    // Apply search highlighting
    const highlightedCode=highlightText(i.code,searchTerm);
    const highlightedSentTo=highlightText(i.sent_to||'—',searchTerm);

    // Calculate status with expiration check
    const expiresAt=expiresParsed?expiresParsed.getTime():null;
    const daysLeft=expiresAt?Math.ceil((expiresAt-now)/(1000*60*60*24)):null;
    const isExpired=expiresAt&&expiresAt<now;
    const isExpiringSoon=daysLeft&&daysLeft<7&&daysLeft>0;

    let statusBadge='';
    let actualStatus=i.status;
    // Check database status first, then fall back to date-based expiration
    if(i.status==='expired'||isExpired){
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Expired</span>';
      actualStatus='expired';
    }else if(i.status==='exhausted'){
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Exhausted</span>';
    }else if(isExpiringSoon){
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Expiring Soon</span>';
    }else{
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>';
    }

    // Progress bar for usage
    const used=i.used||0;
    const maxUses=i.max_uses||1;
    const percentage=Math.min(100,(used/maxUses)*100);
    let barColor='#10b981';
    if(percentage>80)barColor='#ef4444';
    else if(percentage>50)barColor='#f59e0b';
    const progressBar=`<div style="display:flex;align-items:center;gap:8px;"><div style="width:100px;">${createProgressBar(percentage,barColor)}</div><span style="font-size:0.75rem;color:var(--gray);">${used}/${maxUses}</span></div>`;

    tr.innerHTML=`<td><input type='checkbox' name='invite-select' class='invites-checkbox' data-code='${escapeHtml(i.code)}' data-status='${escapeHtml(actualStatus)}' /></td><td>${highlightedCode}</td><td>${highlightedSentTo}</td><td>${progressBar}</td><td>${statusBadge}</td><td>${autoApprove}</td><td>${escapeHtml(createdDate)}</td><td>${escapeHtml(i.created_by||'—')}</td><td>${escapeHtml(expiresDate)}</td>`;
    tbody.appendChild(tr);
  });

  updateInvitesSelectedCount();
  renderInvitesCards(page);
}

// Pending Admin Invitations
let pendingAdminsData = [];
async function loadPendingAdmins() {
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

function renderPendingAdmins() {
  const section = document.getElementById('pendingAdminsSection');
  const list = document.getElementById('pendingAdminsList');
  const countBadge = document.getElementById('pendingAdminsCount');

  if (pendingAdminsData.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  countBadge.textContent = pendingAdminsData.length;
  list.innerHTML = '';

  pendingAdminsData.forEach(admin => {
    const card = document.createElement('div');
    card.style.cssText = 'padding:16px;background:var(--bg-input);border-radius:8px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;';

    const isVerified = admin.ses_verified === true || admin.ses_status === 'Success';
    const statusColor = isVerified ? '#10b981' : '#f59e0b';
    const statusText = isVerified ? 'Verified - Ready to Activate' : 'Awaiting Email Verification';

    const adminTypeLabels = {
      'admin': 'Admin',
      'user_admin': 'User Admin',
      'subscriber_admin': 'Subscriber Admin',
      'vote_admin': 'Vote Admin'
    };

    card.innerHTML = `
      <div>
        <div style="font-weight:600;color:var(--text);margin-bottom:4px;">${admin.first_name || ''} ${admin.last_name || ''}</div>
        <div style="font-size:0.85rem;color:var(--gray);margin-bottom:4px;">${admin.email}</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span style="font-size:0.75rem;color:${statusColor};font-weight:600;">${statusText}</span>
          <span style="font-size:0.75rem;color:var(--gray);">${adminTypeLabels[admin.admin_type] || 'Admin'}</span>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${isVerified
          ? `<button class="btn pending-admin-activate" data-email="${escapeHtml(admin.email)}" style="background:linear-gradient(135deg,#10b981 0%,#059669 100%);padding:8px 16px;font-size:0.85rem;">Activate</button>`
          : `<button class="btn pending-admin-resend" data-email="${escapeHtml(admin.email)}" style="background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);padding:8px 16px;font-size:0.85rem;">Resend</button>`
        }
        <button class="btn pending-admin-cancel" data-email="${escapeHtml(admin.email)}" style="background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);padding:8px 16px;font-size:0.85rem;">Cancel</button>
      </div>
    `;
    // Add event listeners (CSP-compliant - no inline handlers)
    const activateBtn = card.querySelector('.pending-admin-activate');
    if (activateBtn) activateBtn.onclick = () => activatePendingAdmin(admin.email);
    const resendBtn = card.querySelector('.pending-admin-resend');
    if (resendBtn) resendBtn.onclick = () => resendAdminVerification(admin.email);
    card.querySelector('.pending-admin-cancel').onclick = () => cancelPendingAdmin(admin.email);
    list.appendChild(card);
  });
}

async function activatePendingAdmin(email) {
  const confirmed = await showConfirm(
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

async function resendAdminVerification(email) {
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

async function cancelPendingAdmin(email) {
  const confirmed = await showConfirm(
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

let adminsData=[];
let adminQuickFilter='active';
async function loadAdmins(resetPage=true){
  if(!isAdmin())return;
  if(resetPage)paginationState.admins.page=0;
  const tbody=document.querySelector('#adminsTable tbody');

  // Show loading skeleton
  showLoadingSkeleton('adminsTable');

  try{
    if(resetPage||adminsData.length===0){
      const response = await api('/admin/admins');
      adminsData = response.admins || [];
    }

    // Update counts
    const activeCt=adminsData.filter(a=>a.enabled).length;
    const disabledCt=adminsData.filter(a=>!a.enabled).length;
    document.getElementById('activeAdminsCount').textContent=activeCt;
    document.getElementById('disabledAdminsCount').textContent=disabledCt;

    // Apply quick filter
    let filtered=adminsData.filter(a=>{
      if(adminQuickFilter==='active'&&!a.enabled)return false;
      if(adminQuickFilter==='disabled'&&a.enabled)return false;
      return searchFilter(a,paginationState.admins.search,['name','email','given_name','family_name']);
    });

    // Check for empty state
    if(filtered.length===0){
      showEmptyState('adminsTable','No admin users yet','Add admin users using the form above');
      return;
    }

    tbody.innerHTML='';
    const page=updatePagination('admins',filtered);
    const searchTerm=paginationState.admins.search;

    page.forEach(a=>{
      const tr=document.createElement('tr');
      const name=(a.given_name||'')+(a.family_name?' '+a.family_name:'');
      const createdDate=a.created_at?new Date(a.created_at).toLocaleString():'—';

      // Apply search highlighting
      const highlightedName=highlightText(name,searchTerm);
      const highlightedEmail=highlightText(a.email,searchTerm);

      // Admin type badge
      const adminTypeLabels={
        'admin':'A',
        'user_admin':'U',
        'subscriber_admin':'S',
        'vote_admin':'V'
      };
      const adminTypeColors={
        'admin':'linear-gradient(135deg,#a855f7 0%,#7c3aed 100%)',
        'user_admin':'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)',
        'subscriber_admin':'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)',
        'vote_admin':'linear-gradient(135deg,#10b981 0%,#059669 100%)'
      };
      const adminType=a.admin_type||'admin';
      const adminTypeBadge=`<span style="display:inline-block;background:${adminTypeColors[adminType]};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">${adminTypeLabels[adminType]}</span>`;

      // Status badge
      const statusBadge=a.enabled
        ?'<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>'
        :'<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Disabled</span>';

      // Last login display with relative time
      let lastLoginDisplay = '—';
      if (a.last_login_at) {
        const lastLogin = new Date(a.last_login_at);
        const now = new Date();
        const diffMs = now - lastLogin;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        let relativeTime = '';
        if (diffMins < 1) {
          relativeTime = 'Just now';
        } else if (diffMins < 60) {
          relativeTime = `${diffMins} min${diffMins !== 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
          relativeTime = `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
          relativeTime = `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
        } else {
          relativeTime = lastLogin.toLocaleDateString();
        }

        lastLoginDisplay = `<span title="${lastLogin.toLocaleString()}" style="color:var(--text);">${relativeTime}</span>`;
      }

      // Action dropdown menu
      const actionDropdown = `<div class="action-dropdown">
        <button class="action-dropdown-btn" title="Actions">⋮</button>
        <div class="action-dropdown-menu">
          <button class="action-dropdown-item" data-manage-email='${escapeHtml(a.email)}' data-manage-name='${escapeHtml(name||a.email)}' data-manage-type='${escapeHtml(adminType)}' data-manage-enabled='${escapeHtml(a.enabled)}'>Manage Access</button>
          <button class="action-dropdown-item" data-activity-email='${escapeHtml(a.email)}' data-activity-name='${escapeHtml(name||a.email)}'>View Activity</button>
        </div>
      </div>`;

      tr.innerHTML=`<td><input type="checkbox" name="admin-select" class="admin-checkbox" data-email="${escapeHtml(a.email)}" data-enabled="${a.enabled}" /></td><td>${highlightedName||'—'}</td><td>${highlightedEmail}</td><td>${adminTypeBadge}</td><td>${statusBadge}</td><td>${lastLoginDisplay}</td><td>${escapeHtml(createdDate)}</td><td>${actionDropdown}</td>`;
      tbody.appendChild(tr);
    });

    // Action dropdown toggle handlers
    tbody.querySelectorAll('.action-dropdown-btn').forEach(btn=>{
      btn.onclick=(e)=>{
        e.stopPropagation();
        const menu=btn.nextElementSibling;
        // Close all other dropdowns first
        document.querySelectorAll('.action-dropdown-menu.active').forEach(m=>{
          if(m!==menu)m.classList.remove('active');
        });
        menu.classList.toggle('active');
      };
    });

    // Manage Access button handler
    tbody.querySelectorAll("button[data-manage-email]").forEach(btn=>btn.onclick=(e)=>{
      e.stopPropagation();
      const email=btn.getAttribute('data-manage-email');
      const name=btn.getAttribute('data-manage-name');
      const type=btn.getAttribute('data-manage-type');
      const enabled=btn.getAttribute('data-manage-enabled')==='true';
      // Close dropdown
      btn.closest('.action-dropdown-menu')?.classList.remove('active');
      openManageAccessModal(email,name,type,enabled);
    });

    // View Activity button handler
    tbody.querySelectorAll("button[data-activity-email]").forEach(btn=>btn.onclick=async (e)=>{
      e.stopPropagation();
      const email=btn.getAttribute('data-activity-email');
      const name=btn.getAttribute('data-activity-name');
      // Close dropdown
      btn.closest('.action-dropdown-menu')?.classList.remove('active');
      await openActivityLogModal(email,name);
    });

    // Checkbox event handlers
    tbody.querySelectorAll('.admin-checkbox').forEach(cb=>cb.onchange=updateAdminsBulkButtons);

    // Render cards for mobile view
    renderAdminsCards(page);
  }catch(e){
    showToast('Failed to load admins: '+(e.message||e),'error');
    tbody.innerHTML=`<tr><td colspan="8" class="muted">${escapeHtml(e.message||String(e))}</td></tr>`;
  }
}

// Admin Users multi-select functions
function updateAdminsBulkButtons(){
  const checkboxes=document.querySelectorAll('.admin-checkbox:checked');
  const count=checkboxes.length;
  const countText=count>0?`${count} selected`:'';
  document.getElementById('adminsBulkCount').textContent=countText;

  // Check if any selected admins are enabled (for disable button)
  const hasEnabled=Array.from(checkboxes).some(cb=>cb.dataset.enabled==='true');

  // Check if any selected admins are disabled (for enable button)
  const hasDisabled=Array.from(checkboxes).some(cb=>cb.dataset.enabled==='false');

  // Enable/disable buttons based on selection
  document.getElementById('bulkDisableAdmins').disabled=count===0||!hasEnabled;
  document.getElementById('bulkEnableAdmins').disabled=count===0||!hasDisabled;
}

// Select all admins checkbox
document.getElementById('selectAllAdmins').onchange=e=>{
  document.querySelectorAll('.admin-checkbox').forEach(cb=>cb.checked=e.target.checked);
  updateAdminsBulkButtons();
};

// Bulk disable admins
document.getElementById('bulkDisableAdmins').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.admin-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.enabled==='true');
  if(items.length===0){showToast('No enabled admins selected','warning');return;}

  const confirmed = await showConfirm(
    'Disable Admins',
    `Are you sure you want to disable ${items.length} admin user(s)? They will lose access to the admin panel.`,
    'Disable',
    'Cancel',
    true  // isDanger
  );
  if(!confirmed)return;

  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/users/${encodeURIComponent(cb.dataset.email)}/disable`,{method:'POST'}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Disabled ${succeeded} admin(s) successfully`,'success');
  }
  document.getElementById('selectAllAdmins').checked=false;
  await loadAdmins();
};

// Bulk enable admins
document.getElementById('bulkEnableAdmins').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.admin-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.dataset.enabled==='false');
  if(items.length===0){showToast('No disabled admins selected','warning');return;}
  if(!confirm(`Enable ${items.length} admin user(s)?`))return;
  const progressToast=showToast(`Processing 0 of ${items.length}...`,'info',0);
  const results=await Promise.allSettled(items.map((cb,i)=>
    api(`/admin/users/${encodeURIComponent(cb.dataset.email)}/enable`,{method:'POST'}).then(()=>{
      progressToast.querySelector('span').textContent=`Processing ${i+1} of ${items.length}...`;
    })
  ));
  progressToast.remove();
  const succeeded=results.filter(r=>r.status==='fulfilled').length;
  const failed=results.filter(r=>r.status==='rejected').length;
  if(failed>0){
    showToast(`${succeeded} succeeded, ${failed} failed`,'warning');
  }else{
    showToast(`Enabled ${succeeded} admin(s) successfully`,'success');
  }
  document.getElementById('selectAllAdmins').checked=false;
  await loadAdmins();
};

// Quick filter handlers for invites
document.getElementById('quickFilterActiveInvites').onclick=()=>{
  inviteQuickFilter='active';
  document.querySelectorAll('#invites .btn').forEach(btn => {
    if(btn.id && btn.id.includes('Invites')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterActiveInvites').classList.add('filter-active');
  paginationState.invites.page=0;
  renderInvites();
};
document.getElementById('quickFilterExpiringSoonInvites').onclick=()=>{
  inviteQuickFilter='expiring';
  document.querySelectorAll('#invites .btn').forEach(btn => {
    if(btn.id && btn.id.includes('Invites')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterExpiringSoonInvites').classList.add('filter-active');
  paginationState.invites.page=0;
  renderInvites();
};
document.getElementById('quickFilterUsedInvites').onclick=()=>{
  inviteQuickFilter='used';
  document.querySelectorAll('#invites .btn').forEach(btn => {
    if(btn.id && btn.id.includes('Invites')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterUsedInvites').classList.add('filter-active');
  paginationState.invites.page=0;
  renderInvites();
};

// Quick filter handlers for admins
document.getElementById('quickFilterActiveAdmins').onclick=()=>{
  adminQuickFilter='active';
  document.querySelectorAll('#admins .btn').forEach(btn => {
    if(btn.id && btn.id.includes('Admins')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterActiveAdmins').classList.add('filter-active');
  paginationState.admins.page=0;
  loadAdmins(false);
};
document.getElementById('quickFilterDisabledAdmins').onclick=()=>{
  adminQuickFilter='disabled';
  document.querySelectorAll('#admins .btn').forEach(btn => {
    if(btn.id && btn.id.includes('Admins')) btn.classList.remove('filter-active');
  });
  document.getElementById('quickFilterDisabledAdmins').classList.add('filter-active');
  paginationState.admins.page=0;
  loadAdmins(false);
};

document.getElementById('refreshInvites').onclick=loadInvites;
document.getElementById('refreshAdmins').onclick=()=>{ loadAdmins(); loadPendingAdmins(); };
document.getElementById('toggleInviteForm').onclick=()=>document.getElementById('createInviteModal').classList.add('active');
document.getElementById('toggleAdminForm').onclick=()=>document.getElementById('addAdminModal').classList.add('active');

// Modal button handlers - wrapped in DOMContentLoaded since modals are at end of HTML
document.addEventListener('DOMContentLoaded', function() {
document.getElementById('createInviteBtn').onclick=async()=>{
  try{
    const customCode=document.getElementById('customCode').value.trim();
    const n=Number(document.getElementById('maxUses').value||'1');
    const autoApprove=document.getElementById('autoApprove').checked;
    const expiresAtInput=document.getElementById('expiresAt').value;
    const payload={max_uses:n,auto_approve:autoApprove};
    if(customCode)payload.code=customCode;
    if(expiresAtInput){
      const expiresDate=new Date(expiresAtInput);
      payload.expires_at=Math.floor(expiresDate.getTime()/1000);
    }
    const data=await api('/admin/invites',{method:'POST',body:JSON.stringify(payload)});
    let msg='Invite code: '+data.code+' (max uses '+data.max_uses;
    if(data.auto_approve)msg+=' • Auto-approve enabled';
    if(data.expires_at)msg+=' • Expires '+new Date(data.expires_at*1000).toLocaleString();
    msg+=')';
    showToast(msg,'success');
    document.getElementById('customCode').value='';
    document.getElementById('maxUses').value='1';
    document.getElementById('expiresAt').value='';
    document.getElementById('autoApprove').checked=false;
    closeCreateInviteModal();
    await loadInvites();
  }catch(e){
    const msgEl=document.getElementById('inviteMsg');
    msgEl.textContent='Error: '+(e.message||e);
    msgEl.style.color='#ef4444';
  }
};
document.getElementById('addAdminBtn').onclick=async()=>{
  const firstName=document.getElementById('adminFirstName').value.trim();
  const lastName=document.getElementById('adminLastName').value.trim();
  const email=document.getElementById('adminEmail').value.trim().toLowerCase();
  const adminType=document.getElementById('adminType').value;
  if(!firstName){showToast('Please enter a first name','warning');return;}
  if(!lastName){showToast('Please enter a last name','warning');return;}
  if(!email){showToast('Please enter an email address','warning');return;}
  try{
    const result = await api('/admin/pending-admins',{method:'POST',body:JSON.stringify({first_name:firstName,last_name:lastName,email,admin_type:adminType})});
    showToast(result.message || `Invitation sent to ${email}!`,'success');
    document.getElementById('adminFirstName').value='';
    document.getElementById('adminLastName').value='';
    document.getElementById('adminEmail').value='';
    document.getElementById('adminType').value='admin';
    closeAddAdminModal();
    await loadPendingAdmins();
    await loadAdmins();
  }catch(e){
    const msgEl=document.getElementById('adminMsg');
    msgEl.textContent='Error: '+(e.message||e);
    msgEl.style.color='#ef4444';
  }
};

// Pagination event handlers
document.getElementById('invitesPerPage').onchange=(e)=>{paginationState.invites.perPage=Number(e.target.value);paginationState.invites.page=0;renderInvites();};
document.getElementById('invitesPrev').onclick=()=>{if(paginationState.invites.page>0){paginationState.invites.page--;renderInvites();}};
document.getElementById('invitesNext').onclick=()=>{if((paginationState.invites.page+1)*paginationState.invites.perPage<paginationState.invites.total){paginationState.invites.page++;renderInvites();}};
document.getElementById('adminsPerPage').onchange=(e)=>{paginationState.admins.perPage=Number(e.target.value);paginationState.admins.page=0;loadAdmins(false);};
document.getElementById('adminsPrev').onclick=()=>{if(paginationState.admins.page>0){paginationState.admins.page--;loadAdmins(false);}};
document.getElementById('adminsNext').onclick=()=>{if((paginationState.admins.page+1)*paginationState.admins.perPage<paginationState.admins.total){paginationState.admins.page++;loadAdmins(false);}};

// Search event handlers with debouncing
const debouncedRenderInvites=debounce(()=>renderInvites(),300);
const debouncedLoadAdmins=debounce(()=>loadAdmins(false),300);
document.getElementById('invitesSearch').oninput=(e)=>{paginationState.invites.search=e.target.value;paginationState.invites.page=0;document.getElementById('selectAllInvites').checked=false;debouncedRenderInvites();};
document.getElementById('adminsSearch').oninput=(e)=>{paginationState.admins.search=e.target.value;paginationState.admins.page=0;document.getElementById('selectAllAdmins').checked=false;debouncedLoadAdmins();};

// Sortable table headers
document.querySelectorAll('th.sortable').forEach(th=>{
  th.onclick=()=>{
    const column=th.getAttribute('data-column');
    const list=th.getAttribute('data-list');
    const state=sortState[list];

    // Toggle sort direction
    if(state.column===column){
      state.direction=state.direction==='asc'?'desc':'asc';
    }else{
      state.column=column;
      state.direction='asc';
    }

    // Update header classes
    document.querySelectorAll(`th.sortable[data-list="${list}"]`).forEach(h=>{
      h.classList.remove('asc','desc');
    });
    th.classList.add(state.direction);

    // Reload data
    if(list==='users')loadUsers(false);
    else if(list==='invites')renderInvites();
    else if(list==='admins')loadAdmins(false);
    else if(list==='subscriptions')loadAllSubscriptions(false);
  };
});

// Tab switching with hierarchical navigation support
document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    const target = tab.getAttribute('data-tab');
    const subTab = tab.getAttribute('data-sub-tab');

    // Handle parent tab clicks (expand/collapse)
    if (tab.classList.contains('tab-parent')) {
      // Determine which parent was clicked
      const isSubscribers = tab.id === 'subscribersParent';
      const isVoteManagement = tab.id === 'voteManagementParent';
      const isSiteManagement = tab.id === 'siteManagementParent';
      const isAdmin = tab.id === 'adminParent';

      const children = isSubscribers ? document.getElementById('subscribersChildren') :
                       isVoteManagement ? document.getElementById('voteManagementChildren') :
                       isSiteManagement ? document.getElementById('siteManagementChildren') :
                       document.getElementById('adminChildren');
      const parent = tab;

      // Toggle expand/collapse
      children.classList.toggle('expanded');
      parent.classList.toggle('expanded');

      // If expanding, activate the tab and show default sub-tab
      if (parent.classList.contains('expanded')) {
        // Collapse other parent tabs
        if (isSubscribers) {
          const vmChildren = document.getElementById('voteManagementChildren');
          const vmParent = document.getElementById('voteManagementParent');
          const smChildren = document.getElementById('siteManagementChildren');
          const smParent = document.getElementById('siteManagementParent');
          const adminChildren = document.getElementById('adminChildren');
          const adminParent = document.getElementById('adminParent');
          if (vmChildren) vmChildren.classList.remove('expanded');
          if (vmParent) vmParent.classList.remove('expanded');
          if (smChildren) smChildren.classList.remove('expanded');
          if (smParent) smParent.classList.remove('expanded');
          if (adminChildren) adminChildren.classList.remove('expanded');
          if (adminParent) adminParent.classList.remove('expanded');
        } else if (isVoteManagement) {
          const subChildren = document.getElementById('subscribersChildren');
          const subParent = document.getElementById('subscribersParent');
          const smChildren = document.getElementById('siteManagementChildren');
          const smParent = document.getElementById('siteManagementParent');
          const adminChildren = document.getElementById('adminChildren');
          const adminParent = document.getElementById('adminParent');
          if (subChildren) subChildren.classList.remove('expanded');
          if (subParent) subParent.classList.remove('expanded');
          if (smChildren) smChildren.classList.remove('expanded');
          if (smParent) smParent.classList.remove('expanded');
          if (adminChildren) adminChildren.classList.remove('expanded');
          if (adminParent) adminParent.classList.remove('expanded');
        } else if (isSiteManagement) {
          const subChildren = document.getElementById('subscribersChildren');
          const subParent = document.getElementById('subscribersParent');
          const vmChildren = document.getElementById('voteManagementChildren');
          const vmParent = document.getElementById('voteManagementParent');
          const adminChildren = document.getElementById('adminChildren');
          const adminParent = document.getElementById('adminParent');
          if (subChildren) subChildren.classList.remove('expanded');
          if (subParent) subParent.classList.remove('expanded');
          if (vmChildren) vmChildren.classList.remove('expanded');
          if (vmParent) vmParent.classList.remove('expanded');
          if (adminChildren) adminChildren.classList.remove('expanded');
          if (adminParent) adminParent.classList.remove('expanded');
        } else if (isAdmin) {
          const subChildren = document.getElementById('subscribersChildren');
          const subParent = document.getElementById('subscribersParent');
          const vmChildren = document.getElementById('voteManagementChildren');
          const vmParent = document.getElementById('voteManagementParent');
          const smChildren = document.getElementById('siteManagementChildren');
          const smParent = document.getElementById('siteManagementParent');
          if (subChildren) subChildren.classList.remove('expanded');
          if (subParent) subParent.classList.remove('expanded');
          if (vmChildren) vmChildren.classList.remove('expanded');
          if (vmParent) vmParent.classList.remove('expanded');
          if (smChildren) smChildren.classList.remove('expanded');
          if (smParent) smParent.classList.remove('expanded');
        }

        // Remove active from all tabs and tab contents
        document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        // Activate parent tab and content
        parent.classList.add('active');
        document.getElementById(target).classList.add('active');

        // Show default sub-tab based on which parent was clicked
        document.querySelectorAll('.sub-tab-content').forEach(s => s.classList.remove('active'));
        if (isSubscribers) {
          document.getElementById('subscriber-management').classList.add('active');
          document.querySelector('[data-sub-tab="subscriber-management"]').classList.add('active');
        } else if (isVoteManagement) {
          document.getElementById('in-progress').classList.add('active');
          document.querySelector('[data-sub-tab="in-progress"]').classList.add('active');
        } else if (isSiteManagement) {
          document.getElementById('system-health').classList.add('active');
          document.querySelector('[data-sub-tab="system-health"]').classList.add('active');
        } else if (isAdmin) {
          document.getElementById('admin-users').classList.add('active');
          document.querySelector('[data-sub-tab="admin-users"]').classList.add('active');
        }

        // Always refresh data when switching to a tab
        if (isSubscribers) loadAllSubscriptions();
        if (isVoteManagement) loadAllProposalsAdmin();
        if (isSiteManagement) {
          loadSystemHealth();
          loadSystemLogs();
        }
        if (isAdmin) { loadAdmins(); loadPendingAdmins(); }
      }
      return;
    }

    // Handle child tab clicks (sub-tab switching)
    if (tab.classList.contains('tab-child')) {
      // Remove active from all child tabs
      document.querySelectorAll('.tab-child').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      // Switch sub-tab content
      document.querySelectorAll('.sub-tab-content').forEach(s => s.classList.remove('active'));
      document.getElementById(subTab).classList.add('active');

      // Always refresh data when switching to a sub-tab
      if (subTab === 'admin-users') { loadAdmins(); loadPendingAdmins(); }
      if (subTab === 'subscription-types') loadSubscriptionTypes();
      if (subTab === 'membership-terms') loadCurrentTerms();
      // Communications page uses internal tabs - no initial load needed
      if (subTab === 'notifications') loadAllNotifications();
      if (subTab === 'event-handlers') loadHandlers();
      if (subTab === 'supported-services') loadServices();
      if (subTab === 'vault-metrics') loadVaultMetrics();
      if (subTab === 'security-events') {
        loadSecurityEvents();
        loadRecoveryRequests();
        loadDeletionRequests();
      }

      // Close sidebar on mobile
      if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.add('collapsed');
      }
      return;
    }

    // Handle regular tab clicks
    // Collapse any expanded parent tabs
    const subscribersChildren = document.getElementById('subscribersChildren');
    const subscribersParent = document.getElementById('subscribersParent');
    const voteManagementChildren = document.getElementById('voteManagementChildren');
    const voteManagementParent = document.getElementById('voteManagementParent');
    const siteManagementChildren = document.getElementById('siteManagementChildren');
    const siteManagementParent = document.getElementById('siteManagementParent');
    const adminChildren = document.getElementById('adminChildren');
    const adminParent = document.getElementById('adminParent');
    if (subscribersChildren) subscribersChildren.classList.remove('expanded');
    if (subscribersParent) subscribersParent.classList.remove('expanded');
    if (voteManagementChildren) voteManagementChildren.classList.remove('expanded');
    if (voteManagementParent) voteManagementParent.classList.remove('expanded');
    if (siteManagementChildren) siteManagementChildren.classList.remove('expanded');
    if (siteManagementParent) siteManagementParent.classList.remove('expanded');
    if (adminChildren) adminChildren.classList.remove('expanded');
    if (adminParent) adminParent.classList.remove('expanded');

    // Remove active from all tabs and tab contents
    document.querySelectorAll('.tab:not(.tab-child)').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    // Activate clicked tab and its content
    tab.classList.add('active');
    document.getElementById(target).classList.add('active');

    // Always refresh data when switching to a tab
    if (target === 'waitlist') loadWaitlist();
    if (target === 'users') loadUsers();
    if (target === 'invites') loadInvites();
    if (target === 'admins') loadAdmins();
    if (target === 'subscriptions') loadAllSubscriptions();
    if (target === 'help-requests') loadHelpRequests();

    // Close sidebar on mobile after selecting tab
    if (window.innerWidth <= 768) {
      document.getElementById('sidebar').classList.add('collapsed');
    }
  };
});

// Sidebar toggle
document.getElementById('sidebarToggle').onclick=()=>{
  const sidebar=document.getElementById('sidebar');
  const toggle=document.getElementById('sidebarToggle');
  sidebar.classList.toggle('collapsed');
  toggle.innerHTML=sidebar.classList.contains('collapsed')?'&gt;':'&lt;';
};

// User dropdown toggle
const userDropdownBtn=document.querySelector('.user-dropdown-btn');
const userDropdownMenu=document.getElementById('userDropdownMenu');
if(userDropdownBtn){
  userDropdownBtn.onclick=(e)=>{
    e.stopPropagation();
    userDropdownMenu.classList.toggle('active');
  };
}

// Global action dropdown toggle function
window.toggleActionDropdown = function(btn) {
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
  const menuHeight = 120; // Approximate menu height
  const spaceBelow = window.innerHeight - btnRect.bottom;

  menu.style.position = 'fixed';
  menu.style.right = (window.innerWidth - btnRect.right) + 'px';

  if (spaceBelow < menuHeight && btnRect.top > menuHeight) {
    // Open upward
    menu.style.bottom = (window.innerHeight - btnRect.top + 4) + 'px';
    menu.style.top = 'auto';
  } else {
    // Open downward (default)
    menu.style.top = (btnRect.bottom + 4) + 'px';
    menu.style.bottom = 'auto';
  }

  menu.classList.toggle('active');
};

// Close dropdown when clicking outside
document.addEventListener('click',()=>{
  if(userDropdownMenu)userDropdownMenu.classList.remove('active');
  // Close action dropdowns
  document.querySelectorAll('.action-dropdown-menu.active').forEach(m=>m.classList.remove('active'));
});

// Password change modal handlers
const passwordModal=document.getElementById('passwordModal');
const changePasswordBtn=document.getElementById('changePasswordBtn');
const closePasswordModal=document.getElementById('closePasswordModal');
const cancelPasswordChange=document.getElementById('cancelPasswordChange');
const submitPasswordChange=document.getElementById('submitPasswordChange');
const newPasswordInput=document.getElementById('newPassword');

if(changePasswordBtn){
  changePasswordBtn.onclick=()=>{
    passwordModal.classList.add('active');
    userDropdownMenu.classList.remove('active');
  };
}

if(closePasswordModal){
  closePasswordModal.onclick=()=>{
    passwordModal.classList.remove('active');
    clearPasswordFields();
  };
}

if(cancelPasswordChange){
  cancelPasswordChange.onclick=()=>{
    passwordModal.classList.remove('active');
    clearPasswordFields();
  };
}

// Sign out handler
const signoutBtn=document.getElementById('signout');
if(signoutBtn){
  signoutBtn.onclick=(e)=>{
    e.stopPropagation();
    signOut();
  };
}

// Close modal when clicking outside
passwordModal.onclick=(e)=>{
  if(e.target===passwordModal){
    passwordModal.classList.remove('active');
    clearPasswordFields();
  }
};

function clearPasswordFields(){
  document.getElementById('currentPassword').value='';
  document.getElementById('newPassword').value='';
  document.getElementById('confirmPassword').value='';
  document.getElementById('passwordStrengthFill').style.width='0%';
  document.getElementById('passwordStrengthText').textContent='';
  document.getElementById('passwordMatchIndicator').textContent='';
}

// Password strength indicator
if(newPasswordInput){
  newPasswordInput.oninput=()=>{
    const password=newPasswordInput.value;
    const strength=calculatePasswordStrength(password);
    const fill=document.getElementById('passwordStrengthFill');
    const text=document.getElementById('passwordStrengthText');

    fill.style.width=`${strength.percentage}%`;
    fill.className=`password-strength-fill strength-${strength.level}`;
    text.textContent=strength.text;
    text.className=`password-strength-text strength-${strength.level}`;

    checkPasswordMatch();
  };
}

// Password match indicator
const confirmPasswordInput=document.getElementById('confirmPassword');
if(confirmPasswordInput){
  confirmPasswordInput.oninput=checkPasswordMatch;
}

function checkPasswordMatch(){
  const newPassword=document.getElementById('newPassword').value;
  const confirmPassword=document.getElementById('confirmPassword').value;
  const indicator=document.getElementById('passwordMatchIndicator');

  if(!confirmPassword){
    indicator.textContent='';
    return;
  }

  if(newPassword===confirmPassword){
    indicator.textContent='✓ Passwords match';
    indicator.className='password-match-indicator password-match';
  }else{
    indicator.textContent='✗ Passwords do not match';
    indicator.className='password-match-indicator password-no-match';
  }
}

function calculatePasswordStrength(password){
  if(!password)return{percentage:0,level:'weak',text:''};

  let score=0;
  if(password.length>=8)score+=25;
  if(password.length>=12)score+=25;
  if(/[a-z]/.test(password)&&/[A-Z]/.test(password))score+=25;
  if(/\d/.test(password))score+=12;
  if(/[^a-zA-Z0-9]/.test(password))score+=13;

  let level='weak';
  let text='Weak';
  if(score>=75){level='strong';text='Strong';}
  else if(score>=50){level='good';text='Good';}
  else if(score>=25){level='fair';text='Fair';}

  return{percentage:score,level,text};
}

// Submit password change
if(submitPasswordChange){
  submitPasswordChange.onclick=async()=>{
    const currentPassword=document.getElementById('currentPassword').value;
    const newPassword=document.getElementById('newPassword').value;
    const confirmPassword=document.getElementById('confirmPassword').value;

    if(!currentPassword||!newPassword||!confirmPassword){
      showToast('Please fill in all fields','error');
      return;
    }

    if(newPassword!==confirmPassword){
      showToast('New passwords do not match','error');
      return;
    }

    const strength=calculatePasswordStrength(newPassword);
    if(strength.percentage<50){
      showToast('Password is too weak. Use at least 8 characters with uppercase, lowercase, and numbers','warning');
      return;
    }

    submitPasswordChange.disabled=true;
    submitPasswordChange.textContent='Changing...';

    try{
      await changePassword(currentPassword,newPassword);
      showToast('Password changed successfully! Please sign in again.','success');
      passwordModal.classList.remove('active');
      clearPasswordFields();
      setTimeout(()=>signOut(),2000);
    }catch(e){
      showToast('Failed to change password: '+(e.message||e),'error');
      submitPasswordChange.disabled=false;
      submitPasswordChange.textContent='Change Password';
    }
  };
}

// Change Password via Backend API
// Uses access token (required by Cognito ChangePasswordCommand)
async function changePassword(oldPassword,newPassword){
  const token = accessToken();
  if (!token) {
    throw new Error('No access token available');
  }

  const res = await fetch(API_URL + '/admin/change-password', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      currentPassword: oldPassword,
      newPassword: newPassword
    })
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || 'Password change failed');
  }

  return res.json();
}

// ===== MFA Status Handlers =====
const mfaModal = document.getElementById('mfaModal');
const setupMfaBtn = document.getElementById('setupMfaBtn');
const closeMfaModal = document.getElementById('closeMfaModal');
const mfaStatusIcon = document.getElementById('mfaStatusIcon');

async function checkMfaStatus() {
  try {
    const token = idToken();
    if (!token) return false;
    const res = await fetch(API_URL + '/admin/mfa', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (res.ok) {
      const data = await res.json();
      if (data.mfa_enabled) {
        mfaStatusIcon.textContent = '✓';
        mfaStatusIcon.style.color = '#10b981';
      } else {
        mfaStatusIcon.textContent = '';
      }
      return data.mfa_enabled;
    }
  } catch (e) {
    console.error('Failed to check MFA status:', e);
  }
  return false;
}

async function showMfaStatus() {
  const mfaEnabled = document.getElementById('mfaEnabled');
  const mfaNotEnabled = document.getElementById('mfaNotEnabled');
  const mfaLoading = document.getElementById('mfaLoading');
  const mfaError = document.getElementById('mfaError');

  mfaEnabled.style.display = 'none';
  mfaNotEnabled.style.display = 'none';
  mfaLoading.style.display = 'block';
  mfaError.style.display = 'none';

  try {
    const isEnabled = await checkMfaStatus();
    mfaLoading.style.display = 'none';
    if (isEnabled) {
      mfaEnabled.style.display = 'block';
    } else {
      mfaNotEnabled.style.display = 'block';
    }
  } catch (e) {
    mfaLoading.style.display = 'none';
    mfaError.textContent = 'Failed to check MFA status';
    mfaError.style.display = 'block';
  }
}

if (setupMfaBtn) {
  setupMfaBtn.onclick = () => {
    mfaModal.classList.add('active');
    userDropdownMenu.classList.remove('active');
    showMfaStatus();
  };
}

if (closeMfaModal) {
  closeMfaModal.onclick = () => {
    mfaModal.classList.remove('active');
  };
}

document.getElementById('mfaSignOutBtn').onclick = () => {
  mfaModal.classList.remove('active');
  signOut();
};

mfaModal.onclick = (e) => {
  if (e.target === mfaModal) {
    mfaModal.classList.remove('active');
  }
};

// Check MFA status on page load
setTimeout(() => {
  if (signedIn()) checkMfaStatus();
}, 1000);

document.getElementById('selectAllInvites').onchange=(e)=>{
  const checked=e.target.checked;
  document.querySelectorAll('.invites-checkbox').forEach(cb=>cb.checked=checked);
  updateInvitesSelectedCount();
};

document.addEventListener('change',(e)=>{
  if(e.target.classList.contains('invites-checkbox')){
    updateInvitesSelectedCount();
    const total=document.querySelectorAll('.invites-checkbox').length;
    const checked=document.querySelectorAll('.invites-checkbox:checked').length;
    document.getElementById('selectAllInvites').checked=total>0&&checked===total;
  }
});

document.getElementById('bulkExpireInvites').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.invites-checkbox:checked');
  const items=Array.from(checkboxes).filter(cb=>cb.getAttribute('data-status')==='active');
  const codes=items.map(cb=>cb.getAttribute('data-code'));
  if(codes.length===0){showToast('No active invites selected','warning');return;}

  const confirmed = await showConfirm(
    'Expire Invites',
    `Expire ${codes.length} invite(s)? They will no longer be valid for registration.`,
    'Expire',
    'Cancel',
    false
  );
  if(!confirmed)return;

  try{
    for(const code of codes){
      await api(`/admin/invites/${code}/expire`,{method:'POST'});
    }
    showToast(`Expired ${codes.length} invite(s) successfully`,'success');
    await loadInvites();
    document.getElementById('selectAllInvites').checked=false;
  }catch(e){
    showToast('Error: '+(e.message||e),'error');
  }
};

document.getElementById('bulkDeleteInvites').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.invites-checkbox:checked');
  const codes=Array.from(checkboxes).map(cb=>cb.getAttribute('data-code'));
  if(codes.length===0){showToast('No invites selected','warning');return;}

  const confirmed = await showConfirm(
    'Delete Invites',
    `Permanently delete ${codes.length} invite(s)? This action cannot be undone.`,
    'Delete',
    'Cancel',
    true  // isDanger
  );
  if(!confirmed)return;

  try{
    for(const code of codes){
      await api(`/admin/invites/${code}`,{method:'DELETE'});
    }
    showToast(`Deleted ${codes.length} invite(s) successfully`,'success');
    await loadInvites();
    document.getElementById('selectAllInvites').checked=false;
  }catch(e){
    showToast('Error: '+(e.message||e),'error');
  }
};

// Membership Terms Management
// Lazy load download URL for a terms version
async function getTermsDownloadUrl(versionId){
  await refresh();
  const res=await fetch(API_URL+'/admin/membership-terms/'+encodeURIComponent(versionId)+'/download',{
    headers:{'Authorization':'Bearer '+idToken()}
  });
  if(!res.ok)throw new Error('Failed to get download URL');
  const data=await res.json();
  return data.download_url;
}

// View terms button click handler (lazy loads URL)
async function viewTerms(versionId,btn){
  const originalText=btn.textContent;
  btn.textContent='Loading...';
  btn.disabled=true;
  try{
    const url=await getTermsDownloadUrl(versionId);
    window.open(url,'_blank');
  }catch(e){
    showToast('Failed to load terms: '+(e.message||e),'error');
  }finally{
    btn.textContent=originalText;
    btn.disabled=false;
  }
}

// State for pagination
let termsNextCursor=null;
let termsHasMore=false;

async function loadCurrentTerms(append=false){
  if(!isAdmin())return;
  const currentDisplay=document.getElementById('currentTermsDisplay');
  const previousDisplay=document.getElementById('previousTermsDisplay');

  // Show loading skeletons only on initial load
  if(!append){
    showGridLoadingSkeleton('currentTermsDisplay', 1);
    showGridLoadingSkeleton('previousTermsDisplay', 2);
    termsNextCursor=null;
  }

  try{
    await refresh();

    // Load terms with pagination
    let url=API_URL+'/admin/membership-terms?limit=20';
    if(append&&termsNextCursor){
      url+='&cursor='+encodeURIComponent(termsNextCursor);
    }
    const allRes=await fetch(url,{
      headers:{'Authorization':'Bearer '+idToken()}
    });
    if(!allRes.ok){
      throw new Error('Failed to load membership terms');
    }
    const data=await allRes.json();
    const current=data.current;
    const previous=data.previous||[];
    termsHasMore=data.pagination?.has_more||false;
    termsNextCursor=data.pagination?.next_cursor||null;

    // Display current version (only on initial load)
    if(!append){
      if(current){
        const createdDate=new Date(current.created_at).toLocaleString();
        currentDisplay.innerHTML=`
          <div style="background:var(--bg-card);border:1px solid #10b981;border-radius:8px;padding:12px;box-sizing:border-box;min-width:0;display:flex;flex-direction:column;">
            <div style="margin-bottom:8px;">
              <span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Current Version</span>
            </div>
            <h4 style="margin:0 0 8px 0;font-weight:700;font-size:0.95rem;">Version ${current.version_id}</h4>
            <div style="margin-bottom:12px;padding:10px;background:var(--bg-input);border-radius:6px;border:1px solid var(--border);">
              <div style="margin-bottom:6px;font-size:0.8rem;">
                <span style="color:var(--gray);">Created:</span> <span style="font-weight:600;">${createdDate}</span>
              </div>
              <div style="margin-bottom:6px;font-size:0.8rem;">
                <span style="color:var(--gray);">Created by:</span> <span style="font-weight:600;">${current.created_by}</span>
              </div>
            </div>
            <div style="margin-top:auto;">
              <button class='btn' data-action="view-terms" data-version-id="${current.version_id}" style='display:block;width:100%;box-sizing:border-box;text-align:center;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;padding:8px 12px;font-size:0.8rem;font-weight:600;border-radius:12px;border:none;cursor:pointer;'>View Terms</button>
            </div>
          </div>
        `;
      }else{
        currentDisplay.innerHTML="<p class='muted' style='grid-column:1/-1;text-align:center;padding:40px;'>No current terms found. Create the first version above.</p>";
      }
    }

    // Display previous versions
    if(previous.length>0){
      const termsHtml=previous.map(term=>{
        const createdDate=new Date(term.created_at).toLocaleString();
        return `
          <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
            <div style="flex:1;min-width:200px;">
              <div style="margin-bottom:4px;">
                <button data-action="view-terms" data-version-id="${term.version_id}" style="background:none;border:none;color:var(--accent);cursor:pointer;font-weight:700;font-size:0.95rem;display:inline-flex;align-items:center;gap:6px;padding:0;">
                  Version ${term.version_id}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 3v4a1 1 0 0 0 1 1h4"></path>
                    <path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path>
                  </svg>
                </button>
              </div>
              <div style="font-size:0.8rem;color:var(--gray);">
                <span>Created: ${createdDate}</span>
                <span style="margin-left:16px;">By: ${term.created_by}</span>
              </div>
            </div>
          </div>
        `;
      }).join('');

      if(append){
        // Remove existing load more button before appending
        const existingBtn=previousDisplay.querySelector('.load-more-terms');
        if(existingBtn)existingBtn.remove();
        previousDisplay.insertAdjacentHTML('beforeend',termsHtml);
      }else{
        previousDisplay.innerHTML=termsHtml;
      }

      // Add load more button if there are more results
      if(termsHasMore){
        previousDisplay.insertAdjacentHTML('beforeend',`
          <div class="load-more-terms" style="grid-column:1/-1;text-align:center;padding:12px;">
            <button data-action="load-more-terms" class="btn btn-secondary" style="padding:8px 24px;">Load More</button>
          </div>
        `);
      }
    }else if(!append){
      previousDisplay.innerHTML="<p class='muted' style='text-align:center;padding:20px;'>No previous versions</p>";
    }
  }catch(e){
    console.error('Error loading membership terms:',e);
    if(!append){
      currentDisplay.innerHTML="<p class='muted' style='grid-column:1/-1;text-align:center;padding:20px;'>Error loading membership terms. Please try refreshing the page.</p>";
      previousDisplay.innerHTML="<p class='muted' style='text-align:center;padding:20px;'>Error loading previous versions.</p>";
    }else{
      showToast('Failed to load more terms','error');
    }
  }
}

document.getElementById('toggleTermsForm').onclick=()=>document.getElementById('createTermsModal').classList.add('active');

document.getElementById('createTermsBtn').onclick=()=>{
  const termsText=document.getElementById('newTermsText').value.trim();
  const msgEl=document.getElementById('termsMsg');

  if(!termsText){
    msgEl.textContent='Please enter terms text';
    msgEl.style.color='#ef4444';
    return;
  }

  // Show confirmation modal instead of native confirm
  document.getElementById('confirmTermsModal').classList.add('active');
};

// Handle the actual creation when user confirms
document.getElementById('confirmCreateTermsBtn').onclick=async()=>{
  const termsText=document.getElementById('newTermsText').value.trim();
  const msgEl=document.getElementById('termsMsg');
  const createBtn=document.getElementById('createTermsBtn');
  const textArea=document.getElementById('newTermsText');

  // Close confirmation modal
  closeConfirmTermsModal();

  // Show loading state in the create terms modal
  msgEl.textContent='Creating new version...';
  msgEl.style.color='var(--accent)';
  createBtn.disabled=true;
  textArea.disabled=true;

  try{
    const data=await api('/admin/membership-terms',{
      method:'POST',
      body:JSON.stringify({terms_text:termsText})
    });
    showToast(`New version created successfully! Version: ${data.version_id}`,'success');
    textArea.value='';
    msgEl.textContent='';
    closeCreateTermsModal();
    await loadCurrentTerms();
  }catch(e){
    msgEl.textContent='Error: '+(e.message||e);
    msgEl.style.color='#ef4444';
  }finally{
    // Re-enable form in case of error
    createBtn.disabled=false;
    textArea.disabled=false;
  }
};

// Removed initial loading - now handled by lazy tab loading

// Subscription Type Management Functions
document.getElementById('toggleSubscriptionTypeForm').onclick=()=>document.getElementById('createSubscriptionTypeModal').classList.add('active');

// Handle free subscription checkbox
document.getElementById('subTypeFree').onchange=function(){
  const pricingFields=document.getElementById('pricingFields');
  const currencyField=document.getElementById('subTypeCurrency');
  const priceField=document.getElementById('subTypePrice');
  if(this.checked){
    pricingFields.style.opacity='0.5';
    currencyField.disabled=true;
    priceField.disabled=true;
    priceField.value='0';
  }else{
    pricingFields.style.opacity='1';
    currencyField.disabled=false;
    priceField.disabled=false;
    priceField.value='';
  }
};

document.getElementById('createSubscriptionTypeBtn').onclick=async()=>{
  const name=document.getElementById('subTypeName').value.trim();
  const description=document.getElementById('subTypeDescription').value.trim();
  const termValue=parseInt(document.getElementById('subTermValue').value);
  const termUnit=document.getElementById('subTermUnit').value;
  const isFree=document.getElementById('subTypeFree').checked;
  const currency=document.getElementById('subTypeCurrency').value;
  const price=isFree?0:parseFloat(document.getElementById('subTypePrice').value);
  const isOneTime=document.getElementById('subTypeOneTime').checked;
  const enabled=document.getElementById('subTypeEnabled').checked;
  const msgEl=document.getElementById('subscriptionTypeMsg');

  if(!name){
    msgEl.textContent='Please enter a name';
    msgEl.style.color='#ef4444';
    return;
  }
  if(!description){
    msgEl.textContent='Please enter a description';
    msgEl.style.color='#ef4444';
    return;
  }
  if(!termValue||termValue<1){
    msgEl.textContent='Please enter a valid term duration';
    msgEl.style.color='#ef4444';
    return;
  }
  if(!isFree&&(isNaN(price)||price<0)){
    msgEl.textContent='Please enter a valid price';
    msgEl.style.color='#ef4444';
    return;
  }

  try{
    const data=await api('/admin/subscription-types',{
      method:'POST',
      body:JSON.stringify({
        name:name,
        description:description,
        term_value:termValue,
        term_unit:termUnit,
        currency:currency,
        price:price,
        is_one_time_offer:isOneTime,
        enable_immediately:enabled
      })
    });
    showToast('Subscription type created successfully!','success');
    document.getElementById('subTypeName').value='';
    document.getElementById('subTypeDescription').value='';
    document.getElementById('subTermValue').value='';
    document.getElementById('subTypeFree').checked=false;
    document.getElementById('subTypePrice').value='';
    document.getElementById('subTypeOneTime').checked=false;
    document.getElementById('subTypeEnabled').checked=false;
    document.getElementById('pricingFields').style.opacity='1';
    document.getElementById('subTypeCurrency').disabled=false;
    document.getElementById('subTypePrice').disabled=false;
    closeCreateSubscriptionTypeModal();
    await loadSubscriptionTypes();
  }catch(e){
    msgEl.textContent='Error: '+(e.message||e);
    msgEl.style.color='#ef4444';
  }
};

document.getElementById('refreshSubscriptionTypes').onclick=loadSubscriptionTypes;
document.getElementById('filterEnabledTypes').onclick=()=>filterSubscriptionTypes('enabled');
document.getElementById('filterAllTypes').onclick=()=>filterSubscriptionTypes('all');

// System Health Event Handlers
document.getElementById('refreshSystemHealth').onclick=loadSystemHealth;
document.getElementById('refreshLogs').onclick=loadSystemLogs;
document.getElementById('logSourceFilter').onchange=loadSystemLogs;

// Removed initial loading - now handled by lazy tab loading

// Proposal filter buttons
document.querySelectorAll('.proposal-filter').forEach(btn=>{
  btn.onclick=()=>{
    const filter=btn.getAttribute('data-filter');
    currentProposalFilter=filter;
    document.querySelectorAll('.proposal-filter').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    renderProposals();
  };
});

document.getElementById('toggleProposalForm').onclick=()=>document.getElementById('createProposalModal').classList.add('active');
document.getElementById('createProposalBtn').onclick=createProposal;

// Notification button handlers
document.getElementById('addWaitlistNotification').onclick=()=>openAddNotificationModal('waitlist');
document.getElementById('addUserNotification').onclick=()=>openAddNotificationModal('user');
document.getElementById('addVoteNotification').onclick=()=>openAddNotificationModal('vote');
document.getElementById('addSystemHealthNotification').onclick=()=>openAddNotificationModal('system_health');

// Proposal quorum type change handler (CSP-compliant - no inline handlers)
const quorumTypeSelect = document.getElementById('proposalQuorumType');
if (quorumTypeSelect) quorumTypeSelect.onchange = toggleQuorumValue;

// Event delegation for proposal tile buttons (CSP-compliant - no inline onclick handlers)
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

  // Handle data-action attributes (CSP-compliant event delegation)
  const actionEl = e.target.closest('[data-action]');
  if (actionEl) {
    const action = actionEl.getAttribute('data-action');

    // Stop propagation for container elements
    if (action === 'stop-propagation') {
      e.stopPropagation();
      return;
    }

    // Checkbox select actions (stop propagation for all)
    if (action === 'waitlist-select' || action === 'user-select' || action === 'invite-select' ||
        action === 'subscription-select' || action === 'admin-select') {
      e.stopPropagation();
      if (action === 'waitlist-select') updateWaitlistSelectedCount();
      else if (action === 'user-select') updateUserSelectedCount();
      else if (action === 'invite-select') updateInvitesSelectedCount();
      else if (action === 'subscription-select') updateSubscriptionsSelectedCount();
      else if (action === 'admin-select') updateAdminsBulkButtons();
      return;
    }

    // Waitlist row actions
    if (action === 'waitlist-invite') {
      e.stopPropagation();
      const email = actionEl.getAttribute('data-email');
      sendInviteToWaitlistEntry(email);
      return;
    }
    if (action === 'waitlist-reject') {
      e.stopPropagation();
      const email = actionEl.getAttribute('data-email');
      rejectWaitlistEntry(email);
      return;
    }

    // Admin card actions
    if (action === 'admin-manage') {
      e.stopPropagation();
      const email = actionEl.getAttribute('data-email');
      const name = actionEl.getAttribute('data-name');
      const enabled = actionEl.getAttribute('data-enabled') === 'true';
      const adminType = actionEl.getAttribute('data-admin-type');
      openManageAccessModal(email, name, enabled, adminType);
      return;
    }
    if (action === 'admin-activity') {
      e.stopPropagation();
      const email = actionEl.getAttribute('data-email');
      const name = actionEl.getAttribute('data-name');
      openActivityLogModal(email, name);
      return;
    }

    // Membership terms actions
    if (action === 'view-terms') {
      const versionId = actionEl.getAttribute('data-version-id');
      viewTerms(versionId, actionEl);
      return;
    }
    if (action === 'load-more-terms') {
      loadCurrentTerms(true);
      return;
    }

    // Subscription type actions
    if (action === 'toggle-subscription-type') {
      const typeId = actionEl.getAttribute('data-type-id');
      const isEnabled = actionEl.getAttribute('data-is-enabled') === 'true';
      toggleSubscriptionType(typeId, isEnabled);
      return;
    }

    // Notification actions
    if (action === 'remove-notification') {
      const type = actionEl.getAttribute('data-type');
      const email = actionEl.getAttribute('data-email');
      removeNotification(type, email);
      return;
    }

    // Handler action dropdown
    if (action === 'toggle-action-dropdown') {
      toggleActionDropdown(actionEl);
      return;
    }
    if (action === 'handler-details') {
      const handlerId = actionEl.getAttribute('data-handler-id');
      openHandlerDetails(handlerId);
      return;
    }
    if (action === 'handler-sign') {
      const handlerId = actionEl.getAttribute('data-handler-id');
      signHandler(handlerId);
      return;
    }
    if (action === 'handler-revoke') {
      const handlerId = actionEl.getAttribute('data-handler-id');
      const handlerName = actionEl.getAttribute('data-handler-name');
      openRevokeModal(handlerId, handlerName);
      return;
    }
    if (action === 'handler-delete') {
      const handlerId = actionEl.getAttribute('data-handler-id');
      const handlerName = actionEl.getAttribute('data-handler-name');
      openDeleteHandlerModal(handlerId, handlerName);
      return;
    }

    // Service table actions
    if (action === 'service-details') {
      const serviceId = actionEl.getAttribute('data-service-id');
      openServiceDetails(serviceId);
      return;
    }
    if (action === 'toggle-service-dropdown') {
      e.stopPropagation();
      toggleServiceDropdown(actionEl, e);
      return;
    }
    if (action === 'service-edit') {
      e.preventDefault();
      const serviceId = actionEl.getAttribute('data-service-id');
      openEditServiceModal(serviceId);
      return;
    }
    if (action === 'service-toggle-status') {
      e.preventDefault();
      const serviceId = actionEl.getAttribute('data-service-id');
      const newStatus = actionEl.getAttribute('data-new-status');
      toggleServiceStatus(serviceId, newStatus);
      return;
    }
    if (action === 'service-delete') {
      e.preventDefault();
      const serviceId = actionEl.getAttribute('data-service-id');
      openDeleteServiceModal(serviceId);
      return;
    }
  }
});
}); // End DOMContentLoaded

// Proposal Management Functions (must be global for onclick handlers)
let currentProposalFilter='active';
let totalActiveSubscribers=0;
let allProposalsData={active:[],upcoming:[],closed:[]};

async function createProposal(){
  const title=document.getElementById('proposalTitle').value.trim();
  const text=document.getElementById('proposalText').value.trim();
  const openDate=document.getElementById('proposalOpenDate').value;
  const closeDate=document.getElementById('proposalCloseDate').value;
  const msgEl=document.getElementById('proposalMsg');

  if(!title){
    msgEl.textContent='Please enter a proposal title';
    msgEl.style.color='#ef4444';
    return;
  }
  if(!text){
    msgEl.textContent='Please enter proposal text';
    msgEl.style.color='#ef4444';
    return;
  }
  if(!openDate||!closeDate){
    msgEl.textContent='Please select opening and closing date/time';
    msgEl.style.color='#ef4444';
    return;
  }

  const openDateTime=new Date(openDate);
  const closeDateTime=new Date(closeDate);
  const now=new Date();

  if(openDateTime<now){
    msgEl.textContent='Opening date/time must be in the future';
    msgEl.style.color='#ef4444';
    return;
  }

  if(closeDateTime<=openDateTime){
    msgEl.textContent='Closing date/time must be after opening date/time';
    msgEl.style.color='#ef4444';
    return;
  }

  const category=document.getElementById('proposalCategory').value;
  const quorumType=document.getElementById('proposalQuorumType').value;
  const quorumValueEl=document.getElementById('proposalQuorumValue');
  const quorumValue=quorumType!=='none'?parseInt(quorumValueEl.value,10):0;

  if(quorumType!=='none'&&(!quorumValue||quorumValue<=0)){
    msgEl.textContent='Please enter a valid quorum value';
    msgEl.style.color='#ef4444';
    return;
  }

  try{
    const data=await api('/admin/proposals',{
      method:'POST',
      body:JSON.stringify({
        proposal_title:title,
        proposal_text:text,
        opens_at:openDateTime.toISOString(),
        closes_at:closeDateTime.toISOString(),
        category:category,
        quorum_type:quorumType,
        quorum_value:quorumValue
      })
    });
    showToast('Proposal created successfully!','success');
    document.getElementById('proposalTitle').value='';
    document.getElementById('proposalText').value='';
    document.getElementById('proposalOpenDate').value='';
    document.getElementById('proposalCloseDate').value='';
    document.getElementById('proposalCategory').value='other';
    document.getElementById('proposalQuorumType').value='none';
    document.getElementById('proposalQuorumValue').value='';
    toggleQuorumValue();
    closeCreateProposalModal();
    await loadAllProposalsAdmin();
  }catch(e){
    msgEl.textContent='Error: '+(e.message||e);
    msgEl.style.color='#ef4444';
  }
}

function toggleQuorumValue(){
  const quorumType=document.getElementById('proposalQuorumType').value;
  const valueInput=document.getElementById('proposalQuorumValue');
  const valueLabel=document.getElementById('quorumValueLabel');
  if(quorumType==='none'){
    valueInput.style.display='none';
    valueLabel.style.display='none';
  }else{
    valueInput.style.display='block';
    valueLabel.style.display='flex';
    valueLabel.textContent=quorumType==='percentage'?'% of members':'votes required';
  }
}

function formatDateTime(isoString){
  const date=new Date(isoString);
  const options={month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit',hour12:true};
  return date.toLocaleString('en-US',options);
}

function calculateTimeRemaining(targetDate){
  const now=new Date();
  const target=new Date(targetDate);
  const diff=target-now;

  if(diff<=0)return'Closed';

  const days=Math.floor(diff/(1000*60*60*24));
  const hours=Math.floor((diff%(1000*60*60*24))/(1000*60*60));
  const minutes=Math.floor((diff%(1000*60*60))/(1000*60));

  if(days>0){
    return`${days} day${days>1?'s':''} ${hours} hour${hours>1?'s':''}`;
  }else if(hours>0){
    return`${hours} hour${hours>1?'s':''} ${minutes} minute${minutes>1?'s':''}`;
  }else{
    return`${minutes} minute${minutes>1?'s':''}`;
  }
}

function toggleProposalText(proposalId){
  const element=document.getElementById(`text-${proposalId}`);
  const button=event.target;
  if(element.style.display==='none'){
    element.style.display='block';
    button.textContent='Hide Proposal';
  }else{
    element.style.display='none';
    button.textContent='View Proposal';
  }
}

async function toggleProposalResults(proposalId){
  const element=document.getElementById(`results-${proposalId}`);
  const button=event.target;

  if(element.style.display==='block'){
    element.style.display='none';
    button.textContent='View Results';
    return;
  }

  if(element.innerHTML){
    element.style.display='block';
    button.textContent='Hide Results';
    return;
  }

  try{
    button.textContent='Loading...';
    button.disabled=true;
    const data=await api(`/admin/proposals/${proposalId}/vote-counts`);
    const total=data.totalVotes||0;
    const yes=data.results.yes||0;
    const no=data.results.no||0;
    const abstain=data.results.abstain||0;
    const yesPercent=total>0?Math.round((yes/total)*100):0;
    const noPercent=total>0?Math.round((no/total)*100):0;
    const abstainPercent=total>0?Math.round((abstain/total)*100):0;
    const turnout=totalActiveSubscribers>0?Math.round((total/totalActiveSubscribers)*100):0;

    // Determine pass/fail
    const passed=yes>no;
    const passfailBadge=document.getElementById(`passfail-${proposalId}`);
    if(passfailBadge){
      passfailBadge.innerHTML=passed?
        '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 8px;border-radius:8px;font-size:0.7rem;font-weight:700;margin-left:8px;">PASSED</span>':
        '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 8px;border-radius:8px;font-size:0.7rem;font-weight:700;margin-left:8px;">FAILED</span>';
    }

    element.innerHTML=`
      <div style="padding:16px;background:var(--bg-input);border-radius:6px;border:1px solid var(--border);margin-top:12px;">
        <div style="margin-bottom:12px;font-size:0.9rem;color:var(--gray);">
          <strong style="color:var(--text);">Total votes cast:</strong> ${total}
        </div>
        <div style="margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:0.85rem;color:#10b981;font-weight:600;">Yes</span>
            <span style="font-size:0.85rem;font-weight:600;">${yes} votes (${yesPercent}%)</span>
          </div>
          ${createProgressBar(yesPercent,'#10b981')}
        </div>
        <div style="margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:0.85rem;color:#ef4444;font-weight:600;">No</span>
            <span style="font-size:0.85rem;font-weight:600;">${no} votes (${noPercent}%)</span>
          </div>
          ${createProgressBar(noPercent,'#ef4444')}
        </div>
        <div style="margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:0.85rem;color:#6b7280;font-weight:600;">Abstain</span>
            <span style="font-size:0.85rem;font-weight:600;">${abstain} votes (${abstainPercent}%)</span>
          </div>
          ${createProgressBar(abstainPercent,'#6b7280')}
        </div>
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);text-align:center;">
          <span style="font-size:0.85rem;color:var(--accent);font-weight:600;">Voter turnout: ${turnout}% of subscribers voted</span>
        </div>
      </div>
    `;
    element.style.display='block';
    button.textContent='Hide Results';
  }catch(e){
    showToast('Failed to load results: '+(e.message||e),'error');
    button.textContent='View Results';
  }finally{
    button.disabled=false;
  }
}

async function loadAllProposalsAdmin(){
  // Show loading skeleton while fetching data for both containers
  showGridLoadingSkeleton('inProgressProposalsContainer', 3);
  showGridLoadingSkeleton('completedProposalsContainer', 3);

  try{
    // Fetch all proposal types and total active subscribers
    const [active,upcoming,closed,subsData]=await Promise.all([
      api('/admin/proposals?status=active'),
      api('/admin/proposals?status=upcoming'),
      api('/admin/proposals?status=closed'),
      api('/admin/subscriptions?status=active')
    ]);

    allProposalsData={active,upcoming,closed};
    totalActiveSubscribers=(subsData.subscriptions||[]).length;

    // Update counts
    document.getElementById('activeVotesCount').textContent=active.length;
    document.getElementById('pendingVotesCount').textContent=upcoming.length;

    // Render proposals
    renderProposals();

    // Update vote analytics if there are active proposals
    if(active.length>0){
      await updateVoteAnalytics(active);
    }
  }catch(e){
    showToast('Failed to load proposals: '+(e.message||e),'error');
  }
}

async function updateVoteAnalytics(activeProposals){
  const dashboard=document.getElementById('voteAnalyticsDashboard');
  if(!dashboard){
    // Dashboard element doesn't exist (analytics moved to modal)
    return;
  }
  if(activeProposals.length===0){
    dashboard.style.display='none';
    return;
  }
  dashboard.style.display='block';

  try{
    let totalVotesCast=0;
    let totalUniqueVoters=0;
    let yesVotes=0;
    let noVotes=0;
    let abstainVotes=0;
    const uniqueVoters=new Set();

    // Fetch vote counts for all active proposals
    const voteDataPromises=activeProposals.map(p=>api(`/admin/proposals/${p.proposal_id}/vote-counts`).catch(()=>null));
    const voteResults=await Promise.all(voteDataPromises);

    voteResults.forEach((voteData)=>{
      if(!voteData)return;
      const votes=voteData.totalVotes||0;
      totalVotesCast+=votes;
      yesVotes+=(voteData.results?.yes||0);
      noVotes+=(voteData.results?.no||0);
      abstainVotes+=(voteData.results?.abstain||0);

      // Track unique voters if voter list is available
      if(voteData.voters&&Array.isArray(voteData.voters)){
        voteData.voters.forEach(v=>uniqueVoters.add(v));
      }
    });

    totalUniqueVoters=uniqueVoters.size||totalVotesCast;

    // Calculate turnout percentage
    const turnoutPercent=totalActiveSubscribers>0?Math.round((totalUniqueVoters/totalActiveSubscribers)*100):0;

    // Determine current leading vote choice
    let leadingChoice='—';
    if(totalVotesCast>0){
      const max=Math.max(yesVotes,noVotes,abstainVotes);
      if(max===yesVotes)leadingChoice=`Yes (${yesVotes} votes)`;
      else if(max===noVotes)leadingChoice=`No (${noVotes} votes)`;
      else leadingChoice=`Abstain (${abstainVotes} votes)`;
    }

    // Update UI
    document.getElementById('voterTurnoutPercent').textContent=`${turnoutPercent}%`;
    document.getElementById('voterTurnoutCount').textContent=`${totalUniqueVoters} of ${totalActiveSubscribers} voted`;
    document.getElementById('totalVotesCast').textContent=totalVotesCast;
    document.getElementById('votesBreakdown').textContent=`Across ${activeProposals.length} active proposal${activeProposals.length!==1?'s':''}`;
    document.getElementById('currentLeadingVote').textContent=leadingChoice;
    document.getElementById('avgResponseTime').textContent='Coming soon';

  }catch(e){
    console.error('Failed to update vote analytics:',e);
  }
}

function exportVoteResults(){
  try{
    if(!allProposalsData||(!allProposalsData.active.length&&!allProposalsData.closed.length)){
      showToast('No vote data available to export','warning');
      return;
    }

    // Prepare CSV data
    const proposalsToExport=[...allProposalsData.active,...allProposalsData.closed];
    const csvRows=[];

    // CSV Header
    csvRows.push('Proposal Title,Status,Created At,Opens At,Closes At,Yes Votes,No Votes,Abstain Votes,Total Votes,Turnout %');

    proposalsToExport.forEach(p=>{
      const row=[
        `"${(p.proposal_title||'Untitled').replace(/"/g,'""')}"`,
        p.status||'unknown',
        p.created_at||'',
        p.opens_at||'',
        p.closes_at||'',
        '0','0','0','0','0%' // Placeholder - would need to fetch actual vote counts
      ];
      csvRows.push(row.join(','));
    });

    const csvContent=csvRows.join('\n');
    const blob=new Blob([csvContent],{type:'text/csv;charset=utf-8;'});
    const url=URL.createObjectURL(blob);
    const link=document.createElement('a');
    link.href=url;
    link.download=`vote-results-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);

    showToast('Vote results exported successfully','success');
  }catch(e){
    showToast('Failed to export vote results: '+(e.message||e),'error');
  }
}

async function renderProposals(){
  const inProgressContainer=document.getElementById('inProgressProposalsContainer');
  const completedContainer=document.getElementById('completedProposalsContainer');

  // Render in-progress proposals (active and upcoming based on filter)
  let inProgressProposals=[];
  if(currentProposalFilter==='active'){
    inProgressProposals=allProposalsData.active;
  }else if(currentProposalFilter==='upcoming'){
    inProgressProposals=allProposalsData.upcoming;
  }else{
    // Default: show both active and upcoming
    inProgressProposals=[...allProposalsData.active,...allProposalsData.upcoming];
  }

  if(inProgressProposals.length===0){
    const emptyText=currentProposalFilter==='active'?'No active proposals':(currentProposalFilter==='upcoming'?'No scheduled proposals':'No in-progress proposals');
    inProgressContainer.innerHTML=`<div class="empty-state"><div class="empty-state-text">${emptyText}</div></div>`;
  }else{
    let inProgressHtml='';
    for(const p of inProgressProposals){
      const now=new Date();
      const opensAt=new Date(p.opens_at);
      const closesAt=new Date(p.closes_at);

      let proposalType='unknown';
      if(now<opensAt)proposalType='upcoming';
      else if(now>=opensAt&&now<closesAt)proposalType='active';
      else proposalType='closed';

      if(proposalType==='active'){
        inProgressHtml+=await renderActiveTile(p);
      }else if(proposalType==='upcoming'){
        inProgressHtml+=renderUpcomingTile(p);
      }
    }
    inProgressContainer.innerHTML=inProgressHtml;
  }

  // Render completed proposals
  const completedProposals=allProposalsData.closed;
  if(completedProposals.length===0){
    completedContainer.innerHTML=`<div class="empty-state"><div class="empty-state-text">No closed proposals</div></div>`;
  }else{
    let completedHtml='';
    for(const p of completedProposals){
      completedHtml+=await renderClosedTile(p);
    }
    completedContainer.innerHTML=completedHtml;
  }
}

async function renderActiveTile(p){
  const opensDate=formatDateTime(p.opens_at);
  const closesDate=formatDateTime(p.closes_at);
  const timeRemaining=calculateTimeRemaining(p.closes_at);
  const createdBy=p.created_by||'Admin';
  const proposalNumber=p.proposal_number||'';
  const category=p.category||'other';
  const categoryColors={governance:'#8b5cf6',policy:'#3b82f6',budget:'#10b981',funding:'#ec4899',operational:'#f59e0b',other:'#6b7280'};
  const categoryColor=categoryColors[category]||'#6b7280';
  const quorumText=p.quorum_type==='percentage'?`${p.quorum_value}% quorum`:p.quorum_type==='count'?`${p.quorum_value} votes required`:'';

  return`
    <div style="background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;">
      ${proposalNumber?`<div style="margin-bottom:4px;"><span style="font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;">${escapeHtml(proposalNumber)}</span></div>`:''}
      <h4 style="margin:0 0 6px 0;font-weight:700;font-size:0.95rem;">${escapeHtml(p.proposal_title||'Untitled Proposal')}</h4>
      <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;">
        <span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>
        <span style="display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;">${escapeHtml(category)}</span>
        ${quorumText?`<span style="display:inline-block;background:#374151;color:#9ca3af;padding:4px 10px;border-radius:12px;font-size:0.7rem;">${escapeHtml(quorumText)}</span>`:''}
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        <div style="margin-bottom:4px;">Opens: ${escapeHtml(opensDate)}</div>
        <div>Closes: ${escapeHtml(closesDate)}</div>
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        Created by: ${escapeHtml(createdBy)}
      </div>
      <div style="margin-bottom:8px;padding:8px;background:var(--bg-tertiary);border-radius:6px;text-align:center;">
        <span style="font-size:0.85rem;color:var(--accent);font-weight:600;">Closes in ${escapeHtml(timeRemaining)}</span>
      </div>
      <button data-toggle-proposal="${escapeHtml(p.proposal_id)}" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;">View Proposal</button>
      <div id="text-${escapeHtml(p.proposal_id)}" style="display:none;padding:10px;background:var(--bg-input);border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;">${escapeHtml(p.proposal_text)}</div>
      <button data-analytics-proposal="${escapeHtml(p.proposal_id)}" data-analytics-title="${escapeHtml(p.proposal_title||'Untitled Proposal')}" data-analytics-status="active" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;">View Analytics</button>
    </div>
  `;
}

function renderUpcomingTile(p){
  const opensDate=formatDateTime(p.opens_at);
  const closesDate=formatDateTime(p.closes_at);
  const timeUntilOpens=calculateTimeRemaining(p.opens_at);
  const createdBy=p.created_by||'Admin';
  const proposalNumber=p.proposal_number||'';
  const category=p.category||'other';
  const categoryColors={governance:'#8b5cf6',policy:'#3b82f6',budget:'#10b981',funding:'#ec4899',operational:'#f59e0b',other:'#6b7280'};
  const categoryColor=categoryColors[category]||'#6b7280';
  const quorumText=p.quorum_type==='percentage'?`${p.quorum_value}% quorum`:p.quorum_type==='count'?`${p.quorum_value} votes required`:'';

  return`
    <div style="background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;">
      ${proposalNumber?`<div style="margin-bottom:4px;"><span style="font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;">${escapeHtml(proposalNumber)}</span></div>`:''}
      <h4 style="margin:0 0 6px 0;font-weight:700;font-size:0.95rem;color:#9ca3af;">${escapeHtml(p.proposal_title||'Untitled Proposal')}</h4>
      <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;">
        <span style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Upcoming</span>
        <span style="display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;">${escapeHtml(category)}</span>
        ${quorumText?`<span style="display:inline-block;background:#374151;color:#9ca3af;padding:4px 10px;border-radius:12px;font-size:0.7rem;">${escapeHtml(quorumText)}</span>`:''}
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        <div style="margin-bottom:4px;">Opens: ${escapeHtml(opensDate)}</div>
        <div>Closes: ${escapeHtml(closesDate)}</div>
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        Created by: ${escapeHtml(createdBy)}
      </div>
      <div style="margin-bottom:8px;padding:8px;background:var(--bg-tertiary);border-radius:6px;text-align:center;">
        <span style="font-size:0.85rem;color:var(--accent);font-weight:600;">Opens in ${escapeHtml(timeUntilOpens)}</span>
      </div>
      <button data-toggle-proposal="${escapeHtml(p.proposal_id)}" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;">View Proposal</button>
      <div id="text-${escapeHtml(p.proposal_id)}" style="display:none;padding:10px;background:var(--bg-input);border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;">${escapeHtml(p.proposal_text)}</div>
      <button data-analytics-proposal="${escapeHtml(p.proposal_id)}" data-analytics-title="${escapeHtml(p.proposal_title||'Untitled Proposal')}" data-analytics-status="upcoming" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;">View Analytics</button>
    </div>
  `;
}

async function renderClosedTile(p){
  const opensDate=formatDateTime(p.opens_at);
  const closesDate=formatDateTime(p.closes_at);
  const createdBy=p.created_by||'Admin';
  const proposalNumber=p.proposal_number||'';
  const category=p.category||'other';
  const categoryColors={governance:'#8b5cf6',policy:'#3b82f6',budget:'#10b981',funding:'#ec4899',operational:'#f59e0b',other:'#6b7280'};
  const categoryColor=categoryColors[category]||'#6b7280';

  // Use stored final results if available, otherwise fetch
  let passfailBadge='';
  let quorumBadge='';
  if(p.passed!==undefined){
    // Use stored results from closeExpiredProposals
    passfailBadge=p.passed?
      '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">PASSED</span>':
      '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">FAILED</span>';
    if(p.quorum_type&&p.quorum_type!=='none'){
      quorumBadge=p.quorum_met?
        '<span style="display:inline-block;background:#065f46;color:#10b981;padding:4px 10px;border-radius:12px;font-size:0.7rem;">Quorum Met</span>':
        '<span style="display:inline-block;background:#7f1d1d;color:#fca5a5;padding:4px 10px;border-radius:12px;font-size:0.7rem;">No Quorum</span>';
    }
  }else{
    try{
      const data=await api(`/admin/proposals/${p.proposal_id}/vote-counts`);
      const yes=data.results?.yes||0;
      const no=data.results?.no||0;
      const passed=yes>no;
      passfailBadge=passed?
        '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">PASSED</span>':
        '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">FAILED</span>';
    }catch(e){
      console.error('Error fetching vote counts for closed proposal:',e);
    }
  }

  return`
    <div style="background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;display:flex;flex-direction:column;min-height:100%;">
      ${proposalNumber?`<div style="margin-bottom:4px;"><span style="font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;">${escapeHtml(proposalNumber)}</span></div>`:''}
      <h4 style="margin:0 0 6px 0;font-weight:700;font-size:0.95rem;">${escapeHtml(p.proposal_title||'Untitled Proposal')}</h4>
      <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;">
        <span style="display:inline-block;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Closed</span>
        ${passfailBadge}
        ${quorumBadge}
        <span style="display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;">${escapeHtml(category)}</span>
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        <div style="margin-bottom:4px;">Opened: ${escapeHtml(opensDate)}</div>
        <div>Closed: ${escapeHtml(closesDate)}</div>
      </div>
      <div style="margin-bottom:8px;font-size:0.8rem;color:var(--gray);">
        Created by: ${escapeHtml(createdBy)}
      </div>
      <div style="margin-top:auto;">
        <button data-toggle-proposal="${escapeHtml(p.proposal_id)}" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;">View Proposal</button>
        <div id="text-${escapeHtml(p.proposal_id)}" style="display:none;padding:10px;background:var(--bg-input);border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;">${escapeHtml(p.proposal_text)}</div>
        <button data-analytics-proposal="${escapeHtml(p.proposal_id)}" data-analytics-title="${escapeHtml(p.proposal_title||'Untitled Proposal')}" data-analytics-status="closed" class="btn" style="width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;">View Analytics</button>
      </div>
    </div>
  `;
}

// Subscription Type Management Functions (must be global for onclick handlers)
let allSubscriptionTypes=[];
let currentSubscriptionTypeFilter='enabled';

async function loadSubscriptionTypes(){
  const container=document.getElementById('subscriptionTypesList');
  // Show loading skeleton while fetching data
  showGridLoadingSkeleton('subscriptionTypesList', 3);

  try{
    const data=await api('/admin/subscription-types');
    if(!data.subscription_types||data.subscription_types.length===0){
      container.innerHTML='<p class="muted" style="grid-column:1/-1;text-align:center;padding:40px;">No subscription types created yet.</p>';
      allSubscriptionTypes=[];
      updateSubscriptionTypeCounts();
      return;
    }
    allSubscriptionTypes=data.subscription_types;
    updateSubscriptionTypeCounts();
    renderSubscriptionTypes();
  }catch(e){
    console.error('Error loading subscription types:',e);
    container.innerHTML="<p style='color:#ef4444;grid-column:1/-1;text-align:center;padding:20px;'>Error loading subscription types. Please try refreshing.</p>";
  }
}

function updateSubscriptionTypeCounts(){
  const enabledCount=allSubscriptionTypes.filter(st=>st.is_enabled).length;
  document.getElementById('enabledTypesCount').textContent=enabledCount;
  document.getElementById('allTypesCount').textContent=allSubscriptionTypes.length;
}

function renderSubscriptionTypes(){
  const container=document.getElementById('subscriptionTypesList');

  // Filter based on current filter
  let filteredTypes=allSubscriptionTypes;
  if(currentSubscriptionTypeFilter==='enabled'){
    filteredTypes=allSubscriptionTypes.filter(st=>st.is_enabled);
  }

  // Sort: enabled types first, then disabled types
  filteredTypes=filteredTypes.sort((a,b)=>{
    if(a.is_enabled===b.is_enabled)return 0;
    return a.is_enabled?-1:1;
  });

  if(filteredTypes.length===0){
    container.innerHTML='<p class="muted" style="grid-column:1/-1;text-align:center;padding:40px;">No subscription types match the current filter.</p>';
    return;
  }

  container.innerHTML=filteredTypes.map(st=>{
    const statusColor=st.is_enabled?'#10b981':'#ef4444';
    const statusBadge=st.is_enabled?
      '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Enabled</span>':
      '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Disabled</span>';
    const btnText=st.is_enabled?'Disable':'Enable';
    const btnStyle=st.is_enabled?'background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);':'background:linear-gradient(135deg,#10b981 0%,#059669 100%);';
    const priceDisplay=st.price===0||st.price==='0'?'<span style="color:#10b981;font-weight:600;">FREE</span>':`${escapeHtml(st.currency)} ${escapeHtml(parseFloat(st.price).toFixed(2))}`;

    return `
      <div style="background:var(--bg-card);border:1px solid ${st.is_enabled?'#10b981':'#333'};border-radius:8px;padding:12px;box-sizing:border-box;min-width:0;display:flex;flex-direction:column;">
        <div style="margin-bottom:8px;">
          ${statusBadge}
        </div>
        <h4 style="margin:0 0 8px 0;font-weight:700;font-size:0.95rem;">${escapeHtml(st.name)}</h4>
        <p style="margin:0 0 12px 0;color:var(--gray);font-size:0.85rem;line-height:1.4;">${escapeHtml(st.description)}</p>
        <div style="margin-bottom:12px;padding:10px;background:var(--bg-input);border-radius:6px;border:1px solid var(--border);">
          <div style="margin-bottom:6px;font-size:0.8rem;">
            <span style="color:var(--gray);">Term:</span> <span style="font-weight:600;">${escapeHtml(st.term_value)} ${escapeHtml(st.term_unit)}</span>
          </div>
          <div style="margin-bottom:6px;font-size:0.8rem;">
            <span style="color:var(--gray);">Price:</span> <span style="font-weight:600;">${priceDisplay}</span>
          </div>
          ${st.is_one_time_offer?'<div style="margin-top:6px;padding:6px;background:#422006;border-radius:4px;border:1px solid #fbbf24;"><p style="margin:0;color:#fbbf24;font-size:0.75rem;font-weight:600;text-align:center;">One-Time Offer</p></div>':''}
        </div>
        <div style="margin-top:auto;">
          <button class="btn" data-action="toggle-subscription-type" data-type-id="${escapeHtml(st.subscription_type_id)}" data-is-enabled="${st.is_enabled}" style="width:100%;${btnStyle}color:#fff;padding:8px 12px;font-size:0.8rem;font-weight:600;">${escapeHtml(btnText)}</button>
        </div>
      </div>
    `;
  }).join('');
}

function filterSubscriptionTypes(filter){
  currentSubscriptionTypeFilter=filter;

  // Update button active states
  document.querySelectorAll('.subscription-type-filter').forEach(btn=>{
    btn.classList.remove('active');
    if(btn.dataset.filter===filter){
      btn.classList.add('active');
    }
  });

  renderSubscriptionTypes();
}

async function toggleSubscriptionType(subscriptionTypeId,currentStatus){
  const action=currentStatus?'disable':'enable';

  const confirmed = await showConfirm(
    `${action.charAt(0).toUpperCase() + action.slice(1)} Subscription Type`,
    `${action.charAt(0).toUpperCase() + action.slice(1)} this subscription type?`,
    action.charAt(0).toUpperCase() + action.slice(1),
    'Cancel',
    currentStatus  // isDanger if disabling
  );
  if(!confirmed)return;

  try{
    await api(`/admin/subscription-types/${subscriptionTypeId}/${action}`,{
      method:'POST'
    });
    await loadSubscriptionTypes();
  }catch(e){
    showToast('Error: '+(e.message||e),'error');
  }
}

// Proposal filter function
function filterProposals(type){
  currentProposalFilter=type;
  document.querySelectorAll('.proposal-filter').forEach(btn=>{
    btn.classList.remove('active');
    btn.style.opacity='0.7';
  });
  event.target.closest('.proposal-filter').classList.add('active');
  event.target.closest('.proposal-filter').style.opacity='1';
  renderProposals();
}

// Removed initial loading and duplicate event listener - now handled by lazy tab loading
// Note: Filter button event listeners are now handled in DOMContentLoaded via querySelectorAll('.proposal-filter')

// Subscription Management Functions - Unified View
async function loadAllSubscriptions(resetPage=true){
  if(!isAdmin())return;
  if(resetPage)paginationState.subscriptions.page=0;
  const tbody=document.querySelector('#subscriptionsTable tbody');

  // Show loading skeleton
  showLoadingSkeleton('subscriptionsTable');

  try{
    // Fetch ALL subscriptions (no status filter)
    const data=await api('/admin/subscriptions');
    allSubscriptionsData=data.subscriptions||[];

    // Update quick filter counts
    updateSubscriptionFilterCounts();

    // Populate plan filter dropdown
    populatePlanFilter();

    // Render the filtered data
    await renderSubscriptions();
  }catch(e){
    showToast('Failed to load subscriptions: '+(e.message||e),'error');
    tbody.innerHTML=`<tr><td colspan="10" class="muted">${escapeHtml(e.message||String(e))}</td></tr>`;
  }
}

function updateSubscriptionFilterCounts(){
  let paidCt=0,freeCt=0,monthlyRevenue=0;

  allSubscriptionsData.forEach(s=>{
    // Count paid vs free and calculate revenue
    const amount=s.amount||0;
    if(amount>0){
      paidCt++;
      // Only count active subscriptions for revenue estimate
      if(s.status==='active'){
        monthlyRevenue+=amount;
      }
    }else{
      freeCt++;
    }
  });

  document.getElementById('allSubsCount').textContent=allSubscriptionsData.length;
  document.getElementById('paidSubsCount').textContent=paidCt;
  document.getElementById('freeSubsCount').textContent=freeCt;
  document.getElementById('estimatedMonthlyRevenue').textContent='$'+monthlyRevenue.toFixed(2);

  // Update revenue insights
  updateRevenueInsights();
}

function updateRevenueInsights(){
  const now=new Date();
  const thirtyDaysAgo=new Date(now.getTime()-30*24*60*60*1000);
  const startOfMonth=new Date(now.getFullYear(),now.getMonth(),1);

  // Revenue by plan type
  const revenueByPlan=new Map();
  allSubscriptionsData.forEach(s=>{
    if(s.status==='active'&&s.amount>0){
      const plan=s.plan||'Unknown';
      revenueByPlan.set(plan,(revenueByPlan.get(plan)||0)+s.amount);
    }
  });

  const revenueHtml=Array.from(revenueByPlan.entries())
    .sort((a,b)=>b[1]-a[1])
    .map(([plan,revenue])=>`
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:var(--bg-tertiary);border-radius:4px;">
        <span style="color:var(--text);font-size:0.85rem;">${escapeHtml(plan)}</span>
        <span style="font-weight:600;color:#10b981;">$${revenue.toFixed(2)}/mo</span>
      </div>
    `).join('')||'<div style="color:var(--gray);font-size:0.85rem;">No active paid subscriptions</div>';

  document.getElementById('revenueByPlan').innerHTML=revenueHtml;

  // Subscription growth
  let thisMonthCount=0;
  let last30DaysCount=0;
  let previousMonthCount=0;

  allSubscriptionsData.forEach(s=>{
    const createdAt=new Date(s.created_at);
    if(createdAt>=startOfMonth){
      thisMonthCount++;
    }
    if(createdAt>=thirtyDaysAgo){
      last30DaysCount++;
    }
    // Count subscriptions from previous month for growth rate calculation
    const previousMonthStart=new Date(now.getFullYear(),now.getMonth()-1,1);
    const previousMonthEnd=new Date(now.getFullYear(),now.getMonth(),1);
    if(createdAt>=previousMonthStart&&createdAt<previousMonthEnd){
      previousMonthCount++;
    }
  });

  const growthRate=previousMonthCount>0?((thisMonthCount-previousMonthCount)/previousMonthCount*100):0;
  const growthRateColor=growthRate>=0?'#10b981':'#ef4444';
  const growthRatePrefix=growthRate>=0?'+':'';

  document.getElementById('growthThisMonth').textContent=`+${thisMonthCount}`;
  document.getElementById('growthLast30Days').textContent=`+${last30DaysCount}`;
  document.getElementById('growthRate').textContent=`${growthRatePrefix}${growthRate.toFixed(1)}%`;
  document.getElementById('growthRate').style.color=growthRateColor;

  // Churn metrics
  let cancelledLast30Days=0;
  let expiredLast30Days=0;

  allSubscriptionsData.forEach(s=>{
    // Check if cancelled in last 30 days
    if(s.status==='cancelled'&&s.cancelled_at){
      const cancelledDate=new Date(s.cancelled_at);
      if(cancelledDate>=thirtyDaysAgo){
        cancelledLast30Days++;
      }
    }

    // Check if expired in last 30 days
    const expiresDate=new Date(s.expires_at);
    if(expiresDate>=thirtyDaysAgo&&expiresDate<=now&&s.status!=='active'){
      expiredLast30Days++;
    }
  });

  const activeSubscriptions=allSubscriptionsData.filter(s=>s.status==='active').length;
  const totalChurned=cancelledLast30Days+expiredLast30Days;
  const totalBase=activeSubscriptions+totalChurned;
  const churnRate=totalBase>0?(totalChurned/totalBase*100):0;
  const retentionRate=100-churnRate;

  document.getElementById('churnCancelled').textContent=cancelledLast30Days;
  document.getElementById('churnExpired').textContent=expiredLast30Days;
  document.getElementById('churnRate').textContent=`${churnRate.toFixed(1)}%`;
  document.getElementById('retentionRate').textContent=`${retentionRate.toFixed(1)}%`;
}

function populatePlanFilter(){
  const plans=new Set();
  allSubscriptionsData.forEach(s=>{
    if(s.plan)plans.add(s.plan);
  });
  const select=document.getElementById('filterSubPlan');
  const currentValue=select.value;
  select.innerHTML='<option value="">All Plans</option>';
  Array.from(plans).sort().forEach(plan=>{
    const opt=document.createElement('option');
    opt.value=plan;
    opt.textContent=plan;
    select.appendChild(opt);
  });
  select.value=currentValue;
}

async function renderSubscriptions(){
  const tbody=document.querySelector('#subscriptionsTable tbody');
  tbody.innerHTML='';

  // Apply filters
  let filtered=allSubscriptionsData.filter(s=>{
    // Quick filter
    const now=new Date();
    const expiresDate=new Date(s.expires_at);
    const daysLeft=Math.ceil((expiresDate-now)/(1000*60*60*24));

    // Status dropdown filter
    if(subFilters.status==='active'&&s.status!=='active')return false;
    if(subFilters.status==='expiring'&&(s.status!=='active'||daysLeft>=7))return false;
    if(subFilters.status==='cancelled'&&s.status!=='cancelled')return false;
    if(subFilters.status==='expired'&&(s.status==='expired'||daysLeft<=0))return false;

    // Quick filter buttons (paid/free/all)
    if(subFilters.quickFilter==='paid'&&((s.amount||0)<=0))return false;
    if(subFilters.quickFilter==='free'&&((s.amount||0)>0))return false;

    // Plan filter
    if(subFilters.plan&&s.plan!==subFilters.plan)return false;

    // Search filter (names, email, and GUID)
    const search=paginationState.subscriptions.search.toLowerCase();
    if(search){
      const searchable=[s.first_name,s.last_name,s.email,s.user_guid].filter(Boolean).join(' ').toLowerCase();
      if(!searchable.includes(search))return false;
    }

    return true;
  });

  // Sort by expires_at (soonest first)
  filtered.sort((a,b)=>new Date(a.expires_at).getTime()-new Date(b.expires_at).getTime());

  // Check for empty state
  if(filtered.length===0){
    showEmptyState('subscriptionsTable','No subscriptions found','Try adjusting your filters');
    return;
  }

  // Paginate
  const page=updatePagination('subscriptions',filtered);
  const now=new Date();
  const searchTerm=paginationState.subscriptions.search;

  // Fetch vault statuses for users on this page
  let vaultStatuses = {};
  const userGuids = page.map(s => s.user_guid).filter(Boolean);
  if (userGuids.length > 0) {
    try {
      const vaultData = await api(`/admin/vault-status?user_guids=${encodeURIComponent(userGuids.join(','))}`);
      vaultStatuses = vaultData.vault_statuses || {};
    } catch (e) {
      console.error('Failed to fetch vault statuses:', e);
    }
  }

  page.forEach(s=>{
    const tr=document.createElement('tr');
    const expiresDate=new Date(s.expires_at);
    const daysLeft=Math.ceil((expiresDate-now)/(1000*60*60*24));
    const name=`${s.first_name||''} ${s.last_name||''}`.trim()||'—';

    // Apply search highlighting
    const highlightedName=highlightText(name,searchTerm);
    const highlightedEmail=highlightText(s.email,searchTerm);

    // Status badge with gradient
    let statusBadge='';
    if(s.status==='active'){
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#a855f7 0%,#7c3aed 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>';
    }else if(s.status==='cancelled'){
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#f97316 0%,#ea580c 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Cancelled</span>';
    }else{
      statusBadge='<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Expired</span>';
    }

    // Days left badge with color coding
    let daysLeftBadge='';
    if(s.status==='active'){
      if(daysLeft<7){
        daysLeftBadge=`<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">${daysLeft}d</span>`;
      }else if(daysLeft<=30){
        daysLeftBadge=`<span style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">${daysLeft}d</span>`;
      }else{
        daysLeftBadge=`<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">${daysLeft}d</span>`;
      }
    }else{
      daysLeftBadge='<span style="color:#6b7280;">—</span>';
    }

    // PIN and Email preferences badges
    const pinBadge=s.pin_enabled
      ?'<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Yes</span>'
      :'<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">No</span>';
    const emailBadge=s.system_emails_enabled
      ?'<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">On</span>'
      :'<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Off</span>';

    // Vault status badge
    const vaultInfo = vaultStatuses[s.user_guid] || { status: 'not_enrolled' };
    let vaultBadge = '';
    switch (vaultInfo.status) {
      case 'active':
        vaultBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Active</span>';
        break;
      case 'enrolled':
        vaultBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Enrolled</span>';
        break;
      case 'enrolling':
        vaultBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Enrolling</span>';
        break;
      default:
        vaultBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Not Enrolled</span>';
    }

    tr.innerHTML=`<td><input type='checkbox' name='subscription-select' class='subscription-checkbox' data-guid='${escapeHtml(s.user_guid)}' /></td><td>${highlightedName}</td><td>${highlightedEmail}</td><td>${escapeHtml(s.plan)||'—'}</td><td>${statusBadge}</td><td>${pinBadge}</td><td>${vaultBadge}</td><td>${emailBadge}</td><td>${escapeHtml(expiresDate.toLocaleString())}</td><td>${daysLeftBadge}</td>`;
    tbody.appendChild(tr);
  });

  updateSubscriptionsSelectedCount();
  renderSubscribersCards(page);
}

function updateSubscriptionsSelectedCount(){
  const checkboxes=document.querySelectorAll('.subscription-checkbox:checked');
  const count=checkboxes.length;
  document.getElementById('selectedSubscriptionsCount').textContent=count>0?`${count} selected`:'';
}

document.getElementById('selectAllSubscriptions').onchange=function(){
  document.querySelectorAll('.subscription-checkbox').forEach(cb=>cb.checked=this.checked);
  updateSubscriptionsSelectedCount();
};
document.addEventListener('change',e=>{
  if(e.target.classList.contains('subscription-checkbox'))updateSubscriptionsSelectedCount();
});

document.getElementById('bulkExtendSubscriptions').onclick=async()=>{
  const checkboxes=document.querySelectorAll('.subscription-checkbox:checked');
  if(checkboxes.length===0){
    showToast('Please select at least one subscription','warning');
    return;
  }

  const confirmed = await showConfirm(
    'Extend Subscriptions',
    `Extend ${checkboxes.length} subscription(s) by 7 days?`,
    'Extend',
    'Cancel',
    false
  );
  if(!confirmed)return;

  try{
    const guids=Array.from(checkboxes).map(cb=>cb.getAttribute('data-guid')).filter(guid=>guid&&guid.trim()!=='');
    if(guids.length===0){
      showToast('No valid subscriptions selected (missing user GUIDs)','warning');
      return;
    }
    for(const guid of guids){
      await api(`/admin/subscriptions/${encodeURIComponent(guid)}/extend`,{method:'POST',body:JSON.stringify({days:7})});
    }
    showToast(`Extended ${guids.length} subscription(s) by 7 days`,'success');
    await loadAllSubscriptions(true);
  }catch(e){
    showToast('Error: '+(e.message||e),'error');
  }
};

// Quick filter buttons with active highlighting
// Status dropdown filter
document.getElementById('filterSubStatus').onchange=e=>{
  subFilters.status=e.target.value;
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};

// Quick filter buttons
document.getElementById('quickFilterAllSubs').onclick=()=>{
  subFilters.quickFilter='all';
  document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
  document.getElementById('quickFilterAllSubs').classList.add('filter-active');
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};
document.getElementById('quickFilterPaidSubs').onclick=()=>{
  subFilters.quickFilter='paid';
  document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
  document.getElementById('quickFilterPaidSubs').classList.add('filter-active');
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};
document.getElementById('quickFilterFreeSubs').onclick=()=>{
  subFilters.quickFilter='free';
  document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
  document.getElementById('quickFilterFreeSubs').classList.add('filter-active');
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};

// Plan filter
document.getElementById('filterSubPlan').onchange=e=>{
  subFilters.plan=e.target.value;
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};

// Reset filters
document.getElementById('resetSubFilters').onclick=()=>{
  subFilters.status='';
  subFilters.plan='';
  subFilters.quickFilter='all';
  paginationState.subscriptions.search='';
  document.getElementById('subscriptionsSearch').value='';
  document.getElementById('filterSubStatus').value='';
  document.getElementById('filterSubPlan').value='';
  document.querySelectorAll('#subscriptions .btn').forEach(btn => btn.classList.remove('filter-active'));
  document.getElementById('quickFilterAllSubs').classList.add('filter-active');
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};

// Refresh button
document.getElementById('refreshSubscriptions').onclick=()=>loadAllSubscriptions(true);
document.getElementById('refreshAnalyticsBtn').onclick=()=>loadAllSubscriptions(true);

// Search handler
document.getElementById('subscriptionsSearch').oninput=e=>{
  paginationState.subscriptions.search=e.target.value;
  paginationState.subscriptions.page=0;
  document.getElementById('selectAllSubscriptions').checked=false;
  renderSubscriptions();
};

// Pagination
document.getElementById('subscriptionsPerPage').onchange=e=>{
  paginationState.subscriptions.perPage=parseInt(e.target.value);
  paginationState.subscriptions.page=0;
  renderSubscriptions();
};
document.getElementById('subscriptionsPrev').onclick=()=>{
  if(paginationState.subscriptions.page>0){
    paginationState.subscriptions.page--;
    renderSubscriptions();
  }
};
document.getElementById('subscriptionsNext').onclick=()=>{
  const maxPage=Math.ceil(paginationState.subscriptions.total/paginationState.subscriptions.perPage)-1;
  if(paginationState.subscriptions.page<maxPage){
    paginationState.subscriptions.page++;
    renderSubscriptions();
  }
};

// Admin Access Management Modal
let currentManageAdmin = null;

function openManageAccessModal(adminEmail, adminName, adminType, isEnabled) {
  currentManageAdmin = { email: adminEmail, name: adminName, type: adminType, enabled: isEnabled };
  const modal = document.getElementById('manageAccessModal');
  const modalTitle = document.getElementById('manageAccessTitle');
  modalTitle.textContent = `Manage Access: ${adminName}`;

  // Update status action text
  const statusAction = document.getElementById('statusActionTitle');
  const statusDesc = document.getElementById('statusActionDesc');
  if (isEnabled) {
    statusAction.textContent = 'Disable Admin';
    statusDesc.textContent = 'Prevent this admin from logging in';
  } else {
    statusAction.textContent = 'Enable Admin';
    statusDesc.textContent = 'Allow this admin to log in again';
  }

  modal.classList.add('active');
}

function closeManageAccessModal() {
  document.getElementById('manageAccessModal').classList.remove('active');
  currentManageAdmin = null;
}

async function handleToggleAdminStatus() {
  if (!currentManageAdmin) return;

  const action = currentManageAdmin.enabled ? 'disable' : 'enable';
  const confirmMsg = currentManageAdmin.enabled
    ? `Disable admin account for ${currentManageAdmin.email}? They will not be able to log in until re-enabled.`
    : `Enable admin account for ${currentManageAdmin.email}? They will be able to log in again.`;

  const confirmed = await showConfirm(
    `${action.charAt(0).toUpperCase() + action.slice(1)} Admin`,
    confirmMsg,
    action.charAt(0).toUpperCase() + action.slice(1),
    'Cancel',
    currentManageAdmin.enabled  // isDanger if disabling
  );
  if (!confirmed) return;

  try {
    await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}/${action}`, { method: 'POST' });
    showToast(`Admin user ${action}d successfully`, 'success');
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
    return;
  } finally {
    // Always close modal
    closeManageAccessModal();
  }

  // Reload admin list after successful update
  await loadAdmins();
}

async function handleDeleteAdmin() {
  if (!currentManageAdmin) return;

  const confirmed = await showConfirm(
    'Delete Admin Account',
    `Permanently delete admin account for ${currentManageAdmin.email}? This will delete their Cognito account and they will need to be re-invited to regain access.`,
    'Delete',
    'Cancel',
    true  // isDanger
  );
  if (!confirmed) return;

  try {
    await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}`, { method: 'DELETE' });
    showToast('Admin user deleted successfully', 'success');
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
    return;
  } finally {
    // Always close modal
    closeManageAccessModal();
  }

  // Reload admin list after successful update
  await loadAdmins();
}

function openChangeAdminTypeModal() {
  if (!currentManageAdmin) return;

  const changeTypeModal = document.getElementById('changeAdminTypeModal');
  const currentTypeDisplay = document.getElementById('currentAdminType');

  const adminTypeLabels = {
    'admin': 'Admin - Full Access',
    'user_admin': 'User Admin - Waitlist and Users',
    'subscriber_admin': 'Subscriber Admin - Waitlist, Users, Subscribers and Invites',
    'vote_admin': 'Vote Admin - Vote Management'
  };

  currentTypeDisplay.textContent = `Current: ${adminTypeLabels[currentManageAdmin.type] || 'Admin'}`;

  // Set the select to current type
  document.getElementById('newAdminType').value = currentManageAdmin.type || 'admin';

  changeTypeModal.classList.add('active');
}

function closeChangeAdminTypeModal() {
  document.getElementById('changeAdminTypeModal').classList.remove('active');
}

async function handleChangeAdminType() {
  if (!currentManageAdmin) return;

  const newType = document.getElementById('newAdminType').value;

  if (newType === currentManageAdmin.type) {
    showToast('Admin type is already set to this value', 'warning');
    return;
  }

  const adminTypeLabels = {
    'admin': 'Admin - Full Access',
    'user_admin': 'User Admin - Waitlist and Users',
    'subscriber_admin': 'Subscriber Admin - Waitlist, Users, Subscribers and Invites',
    'vote_admin': 'Vote Admin - Vote Management'
  };

  const confirmed = await showConfirm(
    'Change Admin Type',
    `Change admin type for ${currentManageAdmin.email} to ${adminTypeLabels[newType]}?`,
    'Update Type',
    'Cancel',
    false
  );
  if (!confirmed) return;

  try {
    await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}/type`, {
      method: 'PUT',
      body: JSON.stringify({ admin_type: newType })
    });
    showToast('Admin type updated successfully', 'success');
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
    return;
  } finally {
    // Always close modals and reload, even on error
    closeChangeAdminTypeModal();
    closeManageAccessModal();
  }

  // Reload admin list after successful update
  await loadAdmins();
}

// Activity Log Modal Functions
let currentActivityData = [];
let currentActivityFilter = 'all';

async function openActivityLogModal(email, name) {
  try {
    const modal = document.getElementById('activityLogModal');
    const modalTitle = document.getElementById('activityLogTitle');
    modalTitle.textContent = `Activity Log: ${name}`;

    // Show modal with loading skeleton
    modal.classList.add('active');
    document.getElementById('activityLogContent').innerHTML = `
      <div style="padding:12px 0;">
        <div class="skeleton" style="height:60px;margin-bottom:12px;border-radius:6px;"></div>
        <div class="skeleton" style="height:60px;margin-bottom:12px;border-radius:6px;"></div>
        <div class="skeleton" style="height:60px;margin-bottom:12px;border-radius:6px;"></div>
      </div>`;

    // Fetch activity/audit log for this admin
    const auditData = await api(`/admin/audit?email=${encodeURIComponent(email)}`);
    currentActivityData = auditData || [];

    // Calculate statistics
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const last7Days = currentActivityData.filter(a => {
      const activityDate = new Date(a.timestamp || a.created_at);
      return activityDate >= sevenDaysAgo;
    }).length;

    const last30Days = currentActivityData.filter(a => {
      const activityDate = new Date(a.timestamp || a.created_at);
      return activityDate >= thirtyDaysAgo;
    }).length;

    document.getElementById('activityTotalCount').textContent = currentActivityData.length;
    document.getElementById('activityLast7Days').textContent = last7Days;
    document.getElementById('activityLast30Days').textContent = last30Days;

    // Setup filter button handlers
    document.querySelectorAll('.activity-filter').forEach(btn => {
      btn.onclick = () => {
        currentActivityFilter = btn.dataset.filter;
        document.querySelectorAll('.activity-filter').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        renderActivityLog();
      };
    });

    // Initial render
    currentActivityFilter = 'all';
    document.querySelectorAll('.activity-filter').forEach(b => b.classList.remove('active'));
    document.getElementById('filterAllActivity').classList.add('active');
    renderActivityLog();

  } catch (e) {
    showToast('Failed to load activity log: ' + (e.message || e), 'error');
    document.getElementById('activityLogContent').innerHTML = `<div style="color:#ef4444;text-align:center;padding:40px 20px;">Error loading activity: ${escapeHtml(e.message || e)}</div>`;
  }
}

function renderActivityLog() {
  const content = document.getElementById('activityLogContent');

  // Filter activities based on current filter
  // Support both 'action' and 'type' field names from audit entries
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
    // Support both 'action' and 'type' field names
    filtered = currentActivityData.filter(a => {
      const actionType = a.action || a.type || '';
      return actionType.includes('error') || actionType.includes('failed');
    });
  }

  if (filtered.length === 0) {
    content.innerHTML = '<div style="color:var(--gray);text-align:center;padding:40px 20px;">No activity found</div>';
    return;
  }

  // Sort by timestamp descending (most recent first)
  // Support both 'timestamp'/'created_at' and 'ts' field names
  filtered.sort((a, b) => {
    const aTime = new Date(a.timestamp || a.created_at || a.ts).getTime();
    const bTime = new Date(b.timestamp || b.created_at || b.ts).getTime();
    return bTime - aTime;
  });

  // Render activity items
  const html = filtered.map(activity => {
    // Support both 'timestamp'/'created_at' and 'ts' field names
    const timestamp = new Date(activity.timestamp || activity.created_at || activity.ts);
    const relativeTime = formatRelativeTime(timestamp);

    // Determine activity type color
    // Support both 'action' and 'type' field names
    let typeColor = '#3b82f6';
    let typeBg = 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)';
    const action = (activity.action || activity.type || '').toLowerCase();

    if (action.includes('login') || action.includes('auth')) {
      typeColor = '#10b981';
      typeBg = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
    } else if (action.includes('error') || action.includes('failed')) {
      typeColor = '#ef4444';
      typeBg = 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)';
    }

    // Build details from audit entry fields (excluding standard fields)
    const excludeFields = ['id', 'type', 'action', 'ts', 'timestamp', 'created_at', 'email', 'createdAtTimestamp', 'request_id', 'description', 'ip_address', 'details'];
    const extraDetails = Object.entries(activity)
      .filter(([key]) => !excludeFields.includes(key))
      .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});
    const hasExtraDetails = Object.keys(extraDetails).length > 0;
    const details = hasExtraDetails ? `<div style="font-size:0.8rem;color:var(--gray);margin-top:4px;"><pre style="margin:0;white-space:pre-wrap;font-family:inherit;">${escapeHtml(JSON.stringify(extraDetails, null, 2))}</pre></div>` : '';

    // Format action type for display (e.g., 'invite_created' -> 'Invite Created')
    const displayAction = (activity.action || activity.type || 'Unknown Action')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());

    return `
      <div style="padding:12px;margin-bottom:12px;background:var(--bg-card);border-left:3px solid ${typeColor};border-radius:4px;">
        <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:6px;">
          <div style="font-weight:600;color:var(--text);">${escapeHtml(displayAction)}</div>
          <span style="font-size:0.75rem;color:var(--gray);white-space:nowrap;margin-left:12px;" title="${timestamp.toLocaleString()}">${relativeTime}</span>
        </div>
        ${activity.description ? `<div style="font-size:0.85rem;color:var(--gray);margin-bottom:4px;">${escapeHtml(activity.description)}</div>` : ''}
        ${activity.ip_address ? `<div style="font-size:0.75rem;color:var(--gray);">IP: ${escapeHtml(activity.ip_address)}</div>` : ''}
        ${details}
      </div>
    `;
  }).join('');

  content.innerHTML = html;
}

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

function closeActivityLogModal() {
  document.getElementById('activityLogModal').classList.remove('active');
  currentActivityData = [];
  currentActivityFilter = 'all';
}

async function handleResetAdminPassword() {
  if (!currentManageAdmin) return;

  const adminName = currentManageAdmin.name || currentManageAdmin.email;

  const confirmed = await showConfirm(
    'Reset Password',
    `Reset password for ${adminName}?\n\nA temporary password will be generated and emailed to ${currentManageAdmin.email}. They will be required to change it on first login.`,
    'Reset Password',
    'Cancel',
    false
  );
  if (!confirmed) {
    return;
  }

  try {
    const result = await api(`/admin/admins/${encodeURIComponent(currentManageAdmin.email)}/reset-password`, {
      method: 'POST'
    });
    showToast(`Password reset successfully. Temporary password has been emailed to ${currentManageAdmin.email}`, 'success');
    closeManageAccessModal();
  } catch (e) {
    showToast('Error resetting password: ' + (e.message || e), 'error');
  }
}

// Modal close functions
function closeCreateInviteModal() {
  document.getElementById('createInviteModal').classList.remove('active');
  document.getElementById('inviteMsg').textContent = '';
}

function closeAddAdminModal() {
  document.getElementById('addAdminModal').classList.remove('active');
  document.getElementById('adminMsg').textContent = '';
}

function closeCreateSubscriptionTypeModal() {
  document.getElementById('createSubscriptionTypeModal').classList.remove('active');
  document.getElementById('subscriptionTypeMsg').textContent = '';
}

function closeCreateTermsModal() {
  document.getElementById('createTermsModal').classList.remove('active');
  document.getElementById('termsMsg').textContent = '';
}

function closeConfirmTermsModal() {
  document.getElementById('confirmTermsModal').classList.remove('active');
}

function closeCreateProposalModal() {
  document.getElementById('createProposalModal').classList.remove('active');
  document.getElementById('proposalMsg').textContent = '';
}

// ===== NOTIFICATION MANAGEMENT =====
const NOTIFICATION_TYPES = {
  'waitlist': 'Waitlist',
  'user': 'User',
  'vote': 'Vote',
  'system_health': 'System Health'
};

async function loadNotifications(type) {
  try {
    const data = await api(`/admin/notifications/${type}`);
    renderNotifications(type, data.admins || []);
  } catch (error) {
    console.error(`Error loading ${type} notifications:`, error);
    showToast(`Failed to load ${NOTIFICATION_TYPES[type]} notifications`, 'error');
  }
}

function renderNotifications(type, admins) {
  const containerId = `${type}NotificationsList`;
  const container = document.getElementById(containerId);

  if (!container) return;

  if (admins.length === 0) {
    container.innerHTML = '<p style="color:var(--gray);font-size:0.9rem;margin:0;">No admins assigned yet.</p>';
    return;
  }

  container.innerHTML = admins.map(email => `
    <div style="display:flex;align-items:center;justify-content:space-between;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin-bottom:8px;">
      <span style="color:var(--text);font-size:0.9rem;">${escapeHtml(email)}</span>
      <button class="btn" data-action="remove-notification" data-type="${type}" data-email="${escapeHtml(email)}" style="background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);padding:6px 12px;font-size:0.85rem;">Remove</button>
    </div>
  `).join('');
}

// State for notification admin selection
let currentNotificationType = null;
let availableNotificationAdmins = [];

async function openAddNotificationModal(type) {
  const typeName = NOTIFICATION_TYPES[type];
  currentNotificationType = type;

  // Get list of all admins
  try {
    const adminData = await api('/admin/admins');
    const allAdmins = adminData.admins || [];

    // Get currently assigned admins (already array of email strings)
    const notifData = await api(`/admin/notifications/${type}`);
    const assignedEmails = (notifData.admins || []);

    // Filter out already assigned admins
    availableNotificationAdmins = allAdmins.filter(a => !assignedEmails.includes(a.email));

    if (availableNotificationAdmins.length === 0) {
      showToast(`All admins are already assigned to ${typeName} notifications`, 'info');
      return;
    }

    // Populate modal
    const modal = document.getElementById('selectNotificationAdminModal');
    const modalTitle = document.getElementById('selectNotificationAdminTitle');
    const adminList = document.getElementById('notificationAdminList');

    modalTitle.textContent = `Add Admin to ${typeName} Notifications`;

    // Create clickable admin options
    adminList.innerHTML = '';
    availableNotificationAdmins.forEach(admin => {
      const name = `${admin.given_name || ''} ${admin.family_name || ''}`.trim() || admin.email;
      const option = document.createElement('div');
      option.className = 'modal-option';
      option.onclick = () => handleSelectNotificationAdmin(admin.email);
      option.innerHTML = `
        <div class="modal-option-title">${escapeHtml(name)}</div>
        <div class="modal-option-desc">${escapeHtml(admin.email)}</div>
      `;
      adminList.appendChild(option);
    });

    // Show modal
    modal.classList.add('active');

  } catch (error) {
    console.error('Error loading admins for notification:', error);
    showToast(`Failed to load available admins`, 'error');
  }
}

function closeSelectNotificationAdminModal() {
  document.getElementById('selectNotificationAdminModal').classList.remove('active');
  currentNotificationType = null;
  availableNotificationAdmins = [];
}

async function handleSelectNotificationAdmin(email) {
  if (!currentNotificationType) return;

  const typeName = NOTIFICATION_TYPES[currentNotificationType];

  try {
    // Add the admin to notifications
    await api(`/admin/notifications/${currentNotificationType}`, {
      method: 'POST',
      body: JSON.stringify({ admin_email: email })
    });
    showToast(`Added ${email} to ${typeName} notifications`, 'success');
    await loadNotifications(currentNotificationType);
    closeSelectNotificationAdminModal();
  } catch (error) {
    console.error('Error adding notification:', error);
    showToast(`Failed to add admin to ${typeName} notifications`, 'error');
  }
}

async function removeNotification(type, email) {
  const typeName = NOTIFICATION_TYPES[type];

  if (!confirm(`Remove ${email} from ${typeName} notifications?`)) return;

  try {
    await api(`/admin/notifications/${type}/${encodeURIComponent(email)}`, 'DELETE');
    showToast(`Removed ${email} from ${typeName} notifications`, 'success');
    loadNotifications(type);
  } catch (error) {
    console.error('Error removing notification:', error);
    showToast(`Failed to remove admin from ${typeName} notifications`, 'error');
  }
}

// Load all notification lists when notifications tab is active
function loadAllNotifications() {
  loadNotifications('waitlist');
  loadNotifications('user');
  loadNotifications('vote');
  loadNotifications('system_health');
}

// ===== PROPOSAL ANALYTICS =====
let currentProposalAnalytics = null;

async function openProposalAnalytics(proposalId, proposalTitle, status) {
  currentProposalAnalytics = { proposal_id: proposalId, title: proposalTitle, status };

  // Update modal title and status
  document.getElementById('analyticsProposalTitle').textContent = proposalTitle;

  // Show status badge
  let statusBadge = '';
  if (status === 'active') {
    statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 12px;border-radius:12px;font-size:0.75rem;font-weight:600;">Active</span>';
  } else if (status === 'upcoming') {
    statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 12px;border-radius:12px;font-size:0.75rem;font-weight:600;">Upcoming</span>';
  } else if (status === 'closed') {
    statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;padding:4px 12px;border-radius:12px;font-size:0.75rem;font-weight:600;">Closed</span>';
  }
  document.getElementById('analyticsProposalStatus').innerHTML = statusBadge;

  // Open modal
  document.getElementById('proposalAnalyticsModal').classList.add('active');

  // Load analytics data
  await loadProposalAnalytics(proposalId, status);
}

async function loadProposalAnalytics(proposalId, status) {
  try {
    const token = idToken();
    const res = await fetch(`${API_URL}/admin/proposals/${proposalId}/vote-counts`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const voteData = await res.json();
    const total = voteData.totalVotes || 0;
    const yes = voteData.results.yes || 0;
    const no = voteData.results.no || 0;
    const abstain = voteData.results.abstain || 0;

    const yesPercent = total > 0 ? Math.round((yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((abstain / total) * 100) : 0;

    const turnout = totalActiveSubscribers > 0 ? Math.round((total / totalActiveSubscribers) * 100) : 0;

    // Update stats cards
    document.getElementById('analyticsTotalVotes').textContent = total.toLocaleString();
    document.getElementById('analyticsTurnout').textContent = turnout + '%';

    // Show result card for closed proposals
    if (status === 'closed') {
      const passed = yes > no;
      const resultCard = document.getElementById('analyticsResultCard');
      const resultText = document.getElementById('analyticsResult');

      resultCard.style.display = 'block';
      resultText.textContent = passed ? 'PASSED' : 'FAILED';
      resultText.style.color = passed ? '#10b981' : '#ef4444';
    } else {
      document.getElementById('analyticsResultCard').style.display = 'none';
    }

    // Update vote breakdown
    document.getElementById('analyticsYesCount').textContent = `${yes} (${yesPercent}%)`;
    document.getElementById('analyticsNoCount').textContent = `${no} (${noPercent}%)`;
    document.getElementById('analyticsAbstainCount').textContent = `${abstain} (${abstainPercent}%)`;

    // Update progress bars
    const yesBar = document.querySelector('#analyticsYesBar > div');
    const noBar = document.querySelector('#analyticsNoBar > div');
    const abstainBar = document.querySelector('#analyticsAbstainBar > div');

    if (yesBar) yesBar.style.width = `${yesPercent}%`;
    if (noBar) noBar.style.width = `${noPercent}%`;
    if (abstainBar) abstainBar.style.width = `${abstainPercent}%`;

    // Clear any previous messages
    document.getElementById('analyticsMsg').textContent = '';

  } catch (e) {
    console.error('Error loading proposal analytics:', e);
    document.getElementById('analyticsMsg').textContent = 'Error loading analytics: ' + (e.message || e);
    document.getElementById('analyticsMsg').style.color = '#ef4444';
  }
}

function closeProposalAnalyticsModal() {
  document.getElementById('proposalAnalyticsModal').classList.remove('active');
  currentProposalAnalytics = null;
}

// Export proposal results
const exportBtn = document.getElementById('exportProposalResults');
if (exportBtn) {
  exportBtn.onclick = async function() {
    if (!currentProposalAnalytics) return;

  try {
    const token = idToken();
    const res = await fetch(`${API_URL}/admin/proposals/${currentProposalAnalytics.proposal_id}/vote-counts`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const voteData = await res.json();
    const total = voteData.totalVotes || 0;
    const yes = voteData.results.yes || 0;
    const no = voteData.results.no || 0;
    const abstain = voteData.results.abstain || 0;

    const yesPercent = total > 0 ? ((yes / total) * 100).toFixed(2) : '0.00';
    const noPercent = total > 0 ? ((no / total) * 100).toFixed(2) : '0.00';
    const abstainPercent = total > 0 ? ((abstain / total) * 100).toFixed(2) : '0.00';
    const turnout = totalActiveSubscribers > 0 ? ((total / totalActiveSubscribers) * 100).toFixed(2) : '0.00';

    const csvContent = `Proposal Results Export\n` +
      `Proposal Title,${currentProposalAnalytics.title}\n` +
      `Status,${currentProposalAnalytics.status}\n` +
      `Export Date,${new Date().toISOString()}\n` +
      `\n` +
      `Vote Type,Count,Percentage\n` +
      `Yes,${yes},${yesPercent}%\n` +
      `No,${no},${noPercent}%\n` +
      `Abstain,${abstain},${abstainPercent}%\n` +
      `Total Votes,${total},100%\n` +
      `\n` +
      `Turnout Statistics\n` +
      `Total Active Subscribers,${totalActiveSubscribers}\n` +
      `Voter Turnout,${turnout}%\n`;

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `proposal-results-${currentProposalAnalytics.proposal_id}-${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    showToast('Results exported successfully!', 'success');
  } catch (e) {
    console.error('Error exporting results:', e);
    showToast('Error exporting results: ' + (e.message || e), 'error');
  }
  };
}

// ===== CSV BATCH IMPORT =====
let csvData = [];

function openCsvImportModal() {
  document.getElementById('csvImportModal').classList.add('active');
  resetCsvImport();
}

function closeCsvImportModal() {
  document.getElementById('csvImportModal').classList.remove('active');
  resetCsvImport();
}

function resetCsvImport() {
  csvData = [];
  document.getElementById('csvFileInput').value = '';
  document.getElementById('csvPreviewSection').style.display = 'none';
  document.getElementById('importProgressSection').style.display = 'none';
  document.getElementById('startImportBtn').disabled = true;
  document.getElementById('csvRecordCount').textContent = '0';
  document.getElementById('csvPreviewTable').querySelector('tbody').innerHTML = '';
  document.getElementById('csvValidationMsg').innerHTML = '';
}

// CSV file input handler
const csvInput = document.getElementById('csvFileInput');
if (csvInput) {
  csvInput.addEventListener('change', async function(e) {
    const file = e.target.files[0];
    if (!file) return;

    try {
      const text = await file.text();
      parseCsv(text);
    } catch (e) {
      showToast('Error reading CSV file: ' + (e.message || e), 'error');
    }
  });
}

function parseCsv(text) {
  const lines = text.trim().split('\n');
  if (lines.length < 2) {
    showToast('CSV file must have at least a header row and one data row', 'error');
    return;
  }

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());

  // Validate headers
  const requiredHeaders = ['first_name', 'last_name', 'email'];
  const missingHeaders = requiredHeaders.filter(h => !headers.includes(h));

  if (missingHeaders.length > 0) {
    showToast(`Missing required columns: ${missingHeaders.join(', ')}`, 'error');
    return;
  }

  // Parse data rows
  csvData = [];
  const errors = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const values = line.split(',').map(v => v.trim());
    const row = {};

    headers.forEach((header, index) => {
      row[header] = values[index] || '';
    });

    // Validate row
    if (!row.email || !row.email.includes('@')) {
      errors.push(`Row ${i}: Invalid email`);
      continue;
    }
    if (!row.first_name) {
      errors.push(`Row ${i}: Missing first name`);
      continue;
    }
    if (!row.last_name) {
      errors.push(`Row ${i}: Missing last name`);
      continue;
    }

    csvData.push(row);
  }

  // Display preview
  if (csvData.length > 0) {
    displayCsvPreview(csvData, errors);
    document.getElementById('startImportBtn').disabled = false;
  } else {
    showToast('No valid records found in CSV', 'error');
  }
}

function displayCsvPreview(data, errors) {
  const tbody = document.getElementById('csvPreviewTable').querySelector('tbody');
  tbody.innerHTML = '';

  // Show first 10 records in preview
  const previewData = data.slice(0, 10);
  previewData.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="padding:8px;">${escapeHtml(row.first_name)}</td>
      <td style="padding:8px;">${escapeHtml(row.last_name)}</td>
      <td style="padding:8px;">${escapeHtml(row.email)}</td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById('csvRecordCount').textContent = data.length;
  document.getElementById('csvPreviewSection').style.display = 'block';

  // Show validation messages
  let validationHtml = `<div style="color:#10b981;">✓ ${data.length} valid records found</div>`;
  if (errors.length > 0) {
    validationHtml += `<div style="color:#f59e0b;margin-top:4px;">⚠ ${errors.length} rows skipped due to errors</div>`;
  }
  if (data.length > 10) {
    validationHtml += `<div style="color:var(--gray);margin-top:4px;">Showing first 10 records</div>`;
  }
  document.getElementById('csvValidationMsg').innerHTML = validationHtml;
}

// Start import handler
const startImportBtn = document.getElementById('startImportBtn');
if (startImportBtn) {
  startImportBtn.onclick = async function() {
    if (csvData.length === 0) return;

    startImportBtn.disabled = true;
    document.getElementById('csvFileInput').disabled = true;
    document.getElementById('importProgressSection').style.display = 'block';

    let completed = 0;
    let failed = 0;
    const total = csvData.length;

    try {
      for (const row of csvData) {
        try {
          // Submit to waitlist endpoint
          const res = await fetch(`${API_URL}/waitlist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              first_name: row.first_name,
              last_name: row.last_name,
              email: row.email
            })
          });

          if (res.ok) {
            completed++;
          } else {
            failed++;
            console.warn(`Failed to import ${row.email}:`, await res.text());
          }
        } catch (e) {
          failed++;
          console.error(`Error importing ${row.email}:`, e);
        }

        // Update progress
        const progress = Math.round(((completed + failed) / total) * 100);
        document.getElementById('importProgressBar').style.width = `${progress}%`;
        document.getElementById('importProgressText').textContent = `${progress}%`;
        document.getElementById('importResultMsg').innerHTML = `
          <div style="color:#10b981;">✓ ${completed} imported</div>
          ${failed > 0 ? `<div style="color:#ef4444;">✗ ${failed} failed</div>` : ''}
        `;
      }

      // Show final result
      showToast(`Import complete! ${completed} imported, ${failed} failed`, completed > 0 ? 'success' : 'error');

      setTimeout(() => {
        closeCsvImportModal();
        loadWaitlist(true);
      }, 2000);

    } catch (e) {
      showToast('Error during import: ' + (e.message || e), 'error');
      startImportBtn.disabled = false;
      document.getElementById('csvFileInput').disabled = false;
    }
  };
}

// Close modals when clicking overlay
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('active');
    currentManageAdmin = null;
  }
});

// ===== SYSTEM HEALTH MONITORING =====
async function loadSystemHealth() {
  try {
    const token = idToken();

    // Fetch system health metrics from the backend
    const res = await fetch(`${API_URL}/admin/system-health`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();

    // Update SES Quota
    const sesUsed = data.ses?.sent24h || 0;
    const sesLimit = data.ses?.limit || 0;
    const sesPercentage = sesLimit > 0 ? Math.round((sesUsed / sesLimit) * 100) : 0;

    document.getElementById('sesQuotaUsed').textContent = sesUsed.toLocaleString();
    document.getElementById('sesQuotaLimit').textContent = `of ${sesLimit.toLocaleString()} emails sent today`;

    const sesBar = document.querySelector('#sesQuotaBar > div');
    if (sesBar) {
      sesBar.style.width = `${sesPercentage}%`;

      // Change color based on usage
      if (sesPercentage > 80) {
        sesBar.style.background = 'linear-gradient(90deg,#ef4444,#dc2626)';
      } else if (sesPercentage > 60) {
        sesBar.style.background = 'linear-gradient(90deg,#f59e0b,#d97706)';
      } else {
        sesBar.style.background = 'linear-gradient(90deg,#10b981,#059669)';
      }
    }

    // Update DynamoDB Storage
    const dynamoSize = data.dynamodb?.totalSize || 0;
    const dynamoTableCount = data.dynamodb?.tableCount || 0;
    const dynamoSizeFormatted = formatBytes(dynamoSize);

    document.getElementById('dynamoTotalSize').textContent = dynamoSizeFormatted;
    document.getElementById('dynamoTableCount').textContent = `across ${dynamoTableCount} tables`;

    // Update Lambda Errors
    const lambdaErrors = data.lambda?.errors24h || 0;
    // Note: Backend doesn't provide invocations count, so we just show error count

    document.getElementById('lambdaErrorCount').textContent = lambdaErrors.toLocaleString();
    document.getElementById('lambdaErrorRate').textContent = `in the last 24 hours`;

    // Update API Health
    const apiStatus = data.api?.status || 'Unknown';
    const apiResponseTime = data.api?.avgResponseTimeMs || 0;

    document.getElementById('apiHealthStatus').textContent = apiStatus;
    document.getElementById('apiResponseTime').textContent = `Avg: ${apiResponseTime}ms`;

    // Change status color
    const statusEl = document.getElementById('apiHealthStatus');
    const statusLower = apiStatus.toLowerCase();
    if (statusLower === 'operational' || statusLower === 'healthy') {
      statusEl.style.color = '#10b981';
    } else if (statusLower === 'degraded') {
      statusEl.style.color = '#f59e0b';
    } else {
      statusEl.style.color = '#ef4444';
    }

    // Update NATS Cluster Health
    const natsStatus = data.nats?.status || 'unknown';
    const natsHealthyNodes = data.nats?.healthyNodes || 0;
    const natsTotalNodes = data.nats?.totalNodes || 0;

    const natsStatusEl = document.getElementById('natsClusterStatus');
    const natsNodeCountEl = document.getElementById('natsNodeCount');

    // Display status text
    if (natsStatus === 'healthy') {
      natsStatusEl.textContent = 'Healthy';
      natsStatusEl.style.color = '#10b981';
    } else if (natsStatus === 'degraded') {
      natsStatusEl.textContent = 'Degraded';
      natsStatusEl.style.color = '#f59e0b';
    } else if (natsStatus === 'unhealthy') {
      natsStatusEl.textContent = 'Unhealthy';
      natsStatusEl.style.color = '#ef4444';
    } else {
      natsStatusEl.textContent = 'Unknown';
      natsStatusEl.style.color = '#9ca3af';
    }

    // Display node count
    natsNodeCountEl.textContent = `${natsHealthyNodes} of ${natsTotalNodes} nodes healthy`;

    // Update Nitro Enclave ASG Health
    const nitroStatus = data.nitro?.status || 'unknown';
    const nitroHealthyInstances = data.nitro?.healthyInstances || 0;
    const nitroDesiredCapacity = data.nitro?.desiredCapacity || 0;
    const nitroAmiUpToDate = data.nitro?.amiUpToDate || false;
    const nitroCurrentAmi = data.nitro?.currentAmi || '';
    const nitroLatestAmi = data.nitro?.latestAmi || '';
    const nitroRefresh = data.nitro?.instanceRefresh;

    const nitroStatusEl = document.getElementById('nitroAsgStatus');
    const nitroInstanceCountEl = document.getElementById('nitroInstanceCount');
    const nitroAmiStatusEl = document.getElementById('nitroAmiStatus');
    const nitroAmiIndicatorEl = document.getElementById('nitroAmiIndicator');
    const nitroAmiTextEl = document.getElementById('nitroAmiText');
    const nitroRefreshStatusEl = document.getElementById('nitroRefreshStatus');
    const nitroRefreshProgressEl = document.getElementById('nitroRefreshProgress');

    // Display status text
    if (nitroStatus === 'healthy') {
      nitroStatusEl.textContent = 'Healthy';
      nitroStatusEl.style.color = '#10b981';
    } else if (nitroStatus === 'degraded') {
      nitroStatusEl.textContent = 'Degraded';
      nitroStatusEl.style.color = '#f59e0b';
    } else if (nitroStatus === 'unhealthy') {
      nitroStatusEl.textContent = 'Unhealthy';
      nitroStatusEl.style.color = '#ef4444';
    } else {
      nitroStatusEl.textContent = 'Unknown';
      nitroStatusEl.style.color = '#9ca3af';
    }

    // Display instance count
    nitroInstanceCountEl.textContent = `${nitroHealthyInstances} of ${nitroDesiredCapacity} instances healthy`;

    // Display AMI status
    if (nitroCurrentAmi || nitroLatestAmi) {
      nitroAmiStatusEl.style.display = 'block';
      if (nitroAmiUpToDate) {
        nitroAmiIndicatorEl.style.backgroundColor = '#10b981';
        nitroAmiTextEl.textContent = `AMI up to date`;
      } else if (nitroLatestAmi && nitroCurrentAmi && nitroLatestAmi !== nitroCurrentAmi) {
        nitroAmiIndicatorEl.style.backgroundColor = '#f59e0b';
        nitroAmiTextEl.textContent = `Update available`;
      } else {
        nitroAmiIndicatorEl.style.backgroundColor = '#9ca3af';
        nitroAmiTextEl.textContent = `AMI: ${nitroCurrentAmi.slice(-12) || '—'}`;
      }
    } else {
      nitroAmiStatusEl.style.display = 'none';
    }

    // Display instance refresh status
    if (nitroRefresh && (nitroRefresh.status === 'InProgress' || nitroRefresh.status === 'Pending')) {
      nitroRefreshStatusEl.style.display = 'block';
      nitroRefreshProgressEl.textContent = `${nitroRefresh.percentComplete || 0}% (${nitroRefresh.status})`;
    } else {
      nitroRefreshStatusEl.style.display = 'none';
    }

  } catch (e) {
    console.error('Error loading system health:', e);
    showToast('Error loading system health: ' + (e.message || e), 'error');
  }
}

async function loadSystemLogs() {
  try {
    const token = idToken();
    const filter = document.getElementById('logSourceFilter').value;

    // Fetch system logs from the backend
    const res = await fetch(`${API_URL}/admin/system-logs?source=${filter}&limit=100`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();
    // API returns array directly, not wrapped in { logs: [...] }
    const logs = Array.isArray(data) ? data : (data.logs || []);

    const container = document.getElementById('systemLogsContainer');

    if (logs.length === 0) {
      container.innerHTML = '<div style="color:var(--gray);">No logs found.</div>';
      return;
    }

    // Render logs
    const html = logs.map(log => {
      const timestamp = new Date(log.timestamp);
      const timeStr = timestamp.toLocaleString();
      const level = log.level || 'INFO';
      const source = log.source || 'Unknown';
      const message = log.message || '';

      // Color code by log level
      let levelColor = '#3b82f6';
      if (level === 'ERROR' || level === 'FATAL') levelColor = '#ef4444';
      else if (level === 'WARN') levelColor = '#f59e0b';
      else if (level === 'DEBUG') levelColor = '#9ca3af';

      return `
        <div style="margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid #1a1a1a;">
          <div style="display:flex;gap:12px;align-items:baseline;">
            <span style="color:var(--gray);white-space:nowrap;">${timeStr}</span>
            <span style="color:${levelColor};font-weight:700;min-width:60px;">[${level}]</span>
            <span style="color:#8b5cf6;">${escapeHtml(source)}</span>
          </div>
          <div style="color:var(--text);margin-top:4px;margin-left:12px;">${escapeHtml(message)}</div>
        </div>
      `;
    }).join('');

    container.innerHTML = html;

  } catch (e) {
    console.error('Error loading system logs:', e);
    const container = document.getElementById('systemLogsContainer');
    container.innerHTML = `<div style="color:#ef4444;">Error loading logs: ${escapeHtml(e.message || e)}</div>`;
  }
}

// ===== VAULT METRICS DASHBOARD =====
async function loadVaultMetrics() {
  try {
    const data = await api('/admin/vault-metrics');

    // Update key metrics
    document.getElementById('metricTotalEnrolled').textContent = data.key_metrics?.total_enrolled ?? '—';
    document.getElementById('metricActiveVaults').textContent = data.key_metrics?.active_vaults ?? '—';
    document.getElementById('metricPendingEnrollments').textContent = data.key_metrics?.pending_enrollments ?? '—';
    document.getElementById('metricEnrollmentRate').textContent = `${data.key_metrics?.enrollment_rate_percent ?? '—'}%`;

    // Update enrollment outcomes
    const outcomes = data.enrollment_outcomes_30d || {};
    const totalOutcomes = (outcomes.success || 0) + (outcomes.failed || 0) + (outcomes.abandoned || 0) + (outcomes.pending || 0);

    document.getElementById('outcomeSuccessCount').textContent = outcomes.success || 0;
    document.getElementById('outcomeFailedCount').textContent = outcomes.failed || 0;
    document.getElementById('outcomeAbandonedCount').textContent = outcomes.abandoned || 0;
    document.getElementById('outcomePendingCount').textContent = outcomes.pending || 0;

    // Calculate percentages for progress bars
    if (totalOutcomes > 0) {
      document.getElementById('outcomeSuccessBar').style.width = `${(outcomes.success / totalOutcomes) * 100}%`;
      document.getElementById('outcomeFailedBar').style.width = `${(outcomes.failed / totalOutcomes) * 100}%`;
      document.getElementById('outcomeAbandonedBar').style.width = `${(outcomes.abandoned / totalOutcomes) * 100}%`;
      document.getElementById('outcomePendingBar').style.width = `${(outcomes.pending / totalOutcomes) * 100}%`;
    }

    // Update vault status distribution (Nitro model - 3 states only)
    const status = data.vault_status_distribution || {};
    document.getElementById('statusActiveCount').textContent = status.active || 0;
    document.getElementById('statusSuspendedCount').textContent = status.suspended || 0;
    document.getElementById('statusDeletedCount').textContent = status.deleted || 0;

    // Update recent enrollments table
    const recentEnrollments = data.recent_enrollments || [];
    const tbody = document.getElementById('recentEnrollmentsBody');

    if (recentEnrollments.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="padding:20px;text-align:center;color:var(--gray);">No recent enrollments.</td></tr>';
    } else {
      tbody.innerHTML = recentEnrollments.map(e => `
        <tr style="border-bottom:1px solid var(--border);">
          <td style="padding:12px 8px;color:var(--text);">${escapeHtml(e.email || '—')}</td>
          <td style="padding:12px 8px;color:var(--gray);font-family:monospace;font-size:0.8rem;">${escapeHtml(e.user_guid?.substring(0, 20) || '—')}...</td>
          <td style="padding:12px 8px;color:var(--gray);">${e.completed_at ? new Date(e.completed_at).toLocaleString() : new Date(e.created_at).toLocaleString()}</td>
        </tr>
      `).join('');
    }

    // Update generated timestamp
    document.getElementById('vaultMetricsGeneratedAt').textContent = `Last updated: ${data.generated_at ? new Date(data.generated_at).toLocaleString() : '—'}`;

  } catch (e) {
    console.error('Error loading vault metrics:', e);
    showToast('Error loading vault metrics: ' + (e.message || e), 'error');
  }
}

// Vault metrics refresh button
document.getElementById('refreshVaultMetricsBtn').onclick = loadVaultMetrics;

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Initialize the active tab on page load - wait for auth to complete
let authCheckInterval = setInterval(() => {
  if (idToken()) {
    clearInterval(authCheckInterval);
    const activeTab = document.querySelector('.tab.active');
    if (activeTab) {
      const target = activeTab.getAttribute('data-tab');
      if (!tabsLoaded[target]) {
        tabsLoaded[target] = true;
        if (target === 'waitlist') loadWaitlist();
      }
    }
  }
}, 250); // Check every 250ms until auth is ready

// Clear interval after 10 seconds to prevent infinite loop
setTimeout(() => clearInterval(authCheckInterval), 10000);

// ===== WAITLIST MANAGEMENT =====
let allWaitlistData = [];
let waitlistPaginationState = { currentPage: 1, perPage: 10, search: '' };
let waitlistQuickFilter = 'pending'; // Default to pending

async function loadWaitlist(resetPage = true) {
  if (resetPage) waitlistPaginationState.currentPage = 1;

  // Show loading state
  showLoadingSkeleton('waitlistTable');

  try {
    const token = idToken();
    const res = await fetch(`${API_URL}/admin/waitlist`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to load waitlist');
    allWaitlistData = data.waitlist || [];
    updateWaitlistCounts();
    renderWaitlist();
  } catch (err) {
    const tbody = document.querySelector('#waitlistTable tbody');
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:#f44;">Failed to load waitlist. Please refresh and try again.</td></tr>';
    showToast(err.message || 'Failed to load waitlist', 'error');
  }
}

function updateWaitlistCounts() {
  const pending = allWaitlistData.filter(w => w.status === 'pending' || !w.status).length;
  const invited = allWaitlistData.filter(w => w.status === 'invited').length;
  const rejected = allWaitlistData.filter(w => w.status === 'rejected').length;

  document.getElementById('pendingWaitlistCount').textContent = pending;
  document.getElementById('invitedWaitlistCount').textContent = invited;
  document.getElementById('rejectedWaitlistCount').textContent = rejected;
}

function renderWaitlist() {
  // Apply filters
  let filtered = allWaitlistData.filter(w => {
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

  // Check for empty state - update both table and cards
  if (filtered.length === 0) {
    const cardContainer = document.getElementById('waitlistCardContainer');
    cardContainer.innerHTML = '<div class="empty-state"><div class="empty-state-text">No waitlist entries found</div><div class="empty-state-subtext">Try adjusting your filters</div></div>';
    showEmptyState('waitlistTable', 'No waitlist entries found', 'Try adjusting your filters');
    document.getElementById('waitlistInfo').textContent = 'Page 0 of 0 (0 total)';
    document.getElementById('waitlistPrev').disabled = true;
    document.getElementById('waitlistNext').disabled = true;
    return;
  }

  // Paginate
  const totalPages = Math.ceil(filtered.length / waitlistPaginationState.perPage);
  waitlistPaginationState.currentPage = Math.min(waitlistPaginationState.currentPage, Math.max(1, totalPages));
  const start = (waitlistPaginationState.currentPage - 1) * waitlistPaginationState.perPage;
  const end = start + waitlistPaginationState.perPage;
  const page = filtered.slice(start, end);

  document.getElementById('waitlistInfo').textContent = `Page ${waitlistPaginationState.currentPage} of ${totalPages} (${filtered.length} total)`;
  document.getElementById('waitlistPrev').disabled = waitlistPaginationState.currentPage === 1;
  document.getElementById('waitlistNext').disabled = waitlistPaginationState.currentPage === totalPages || filtered.length === 0;

  // Always render both table and cards - CSS controls which is visible based on screen size
  // Render table
  const tbody = document.querySelector('#waitlistTable tbody');
  tbody.innerHTML = '';

  const searchTerm = waitlistPaginationState.search;
  page.forEach(w => {
    const tr = document.createElement('tr');
    const name = `${w.first_name || ''} ${w.last_name || ''}`.trim() || '—';
    const createdDate = w.created_at ? new Date(w.created_at).toLocaleString() : '—';
    const invitedDate = w.invited_at ? new Date(w.invited_at).toLocaleString() : '—';
    const invitedBy = w.invited_by ? escapeHtml(w.invited_by) : '—';

    // Apply search highlighting
    const highlightedName = highlightText(name, searchTerm);
    const highlightedEmail = highlightText(w.email, searchTerm);

    let statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Pending</span>';
    if (w.status === 'invited') {
      statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Invited</span>';
    } else if (w.status === 'rejected') {
      statusBadge = '<span style="display:inline-block;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">Rejected</span>';
    }

    const isDisabled = w.status === 'invited' || w.status === 'rejected';
    tr.innerHTML = `<td><input type='checkbox' name='waitlist-select' class='waitlist-checkbox' data-id='${escapeHtml(w.waitlist_id)}' ${isDisabled ? 'disabled title="Already processed"' : ''} /></td><td>${highlightedName}</td><td>${highlightedEmail}</td><td>${statusBadge}</td><td>${createdDate}</td><td>${invitedDate}</td><td>${invitedBy}</td>`;
    tbody.appendChild(tr);
  });

  // Render cards (for mobile view)
  renderWaitlistCards(page);

  updateWaitlistSelectedCount();
}

function updateWaitlistSelectedCount() {
  const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
  const count = checkboxes.length;
  const countText = count > 0 ? `${count} selected` : '';
  document.getElementById('selectedWaitlistCount').textContent = countText;
  document.getElementById('sendInvitesBtn').disabled = count === 0;
  document.getElementById('rejectWaitlistBtn').disabled = count === 0;
  document.getElementById('deleteWaitlistBtn').disabled = count === 0;
}

document.getElementById('selectAllWaitlist').onchange = function() {
  document.querySelectorAll('.waitlist-checkbox:not([disabled])').forEach(cb => cb.checked = this.checked);
  updateWaitlistSelectedCount();
};

document.addEventListener('change', e => {
  if (e.target.classList.contains('waitlist-checkbox')) updateWaitlistSelectedCount();
});

document.getElementById('refreshWaitlist').onclick = () => loadWaitlist(true);

// Global variable to store selected waitlist IDs for invite modal
let pendingInviteWaitlistIds = [];

// Show custom message modal before sending invites
document.getElementById('sendInvitesBtn').onclick = () => {
  const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
  if (checkboxes.length === 0) {
    showToast('Please select at least one waitlist entry', 'warning');
    return;
  }

  pendingInviteWaitlistIds = Array.from(checkboxes).map(cb => cb.getAttribute('data-id'));
  document.getElementById('inviteCountDisplay').textContent = pendingInviteWaitlistIds.length;
  document.getElementById('customMessageText').value = '';
  document.getElementById('customMessageModal').classList.add('active');
};

// Invite All Pending button - automatically select all pending entries
document.getElementById('inviteAllPendingBtn').onclick = () => {
  const pendingEntries = allWaitlistData.filter(entry => entry.status !== 'invited');
  if (pendingEntries.length === 0) {
    showToast('No pending waitlist entries to invite', 'warning');
    return;
  }

  pendingInviteWaitlistIds = pendingEntries.map(entry => entry.waitlist_id);
  document.getElementById('inviteCountDisplay').textContent = pendingInviteWaitlistIds.length;
  document.getElementById('customMessageText').value = '';
  document.getElementById('customMessageModal').classList.add('active');
};

// Custom message modal handlers
document.getElementById('closeCustomMessageModal').onclick = () => {
  document.getElementById('customMessageModal').classList.remove('active');
  pendingInviteWaitlistIds = [];
};

document.getElementById('cancelSendInvites').onclick = () => {
  document.getElementById('customMessageModal').classList.remove('active');
  pendingInviteWaitlistIds = [];
};

// Shared function to send invites with optional custom message
async function sendWaitlistInvites(waitlist_ids, customMessage = '') {
  try {
    const token = idToken();
    const payload = { waitlist_ids };

    // Add custom message if provided
    if (customMessage && customMessage.trim()) {
      payload.custom_message = customMessage.trim();
    }

    const res = await fetch(`${API_URL}/admin/waitlist/send-invites`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to send invites');

    showToast(data.message || `Sent ${data.sent?.length || 0} invites`, 'success');

    if (data.failed && data.failed.length > 0) {
      showToast(`${data.failed.length} failed: ${data.failed.map(f => f.email).join(', ')}`, 'warning', 8000);
    }

    loadWaitlist(false);
  } catch (err) {
    showToast(err.message || 'Failed to send invites', 'error');
  }
}

// Confirm send invites button
document.getElementById('confirmSendInvites').onclick = async () => {
  if (pendingInviteWaitlistIds.length === 0) {
    showToast('No waitlist entries selected', 'warning');
    return;
  }

  const customMessage = document.getElementById('customMessageText').value;

  // Close modal
  document.getElementById('customMessageModal').classList.remove('active');

  // Send invites
  await sendWaitlistInvites(pendingInviteWaitlistIds, customMessage);

  // Clear pending IDs
  pendingInviteWaitlistIds = [];
};

// Waitlist search
document.getElementById('waitlistSearch').oninput = (e) => {
  waitlistPaginationState.search = e.target.value;
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

document.getElementById('resetWaitlistFilters').onclick = () => {
  document.getElementById('waitlistSearch').value = '';
  waitlistPaginationState.search = '';
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

// Waitlist pagination
document.getElementById('waitlistPerPage').onchange = (e) => {
  waitlistPaginationState.perPage = parseInt(e.target.value);
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

document.getElementById('waitlistPrev').onclick = () => {
  if (waitlistPaginationState.currentPage > 1) {
    waitlistPaginationState.currentPage--;
    renderWaitlist();
  }
};

document.getElementById('waitlistNext').onclick = () => {
  const totalPages = Math.ceil(allWaitlistData.filter(w => {
    const search = waitlistPaginationState.search.toLowerCase();
    if (search) {
      const searchable = [w.first_name, w.last_name, w.email].filter(Boolean).join(' ').toLowerCase();
      return searchable.includes(search);
    }
    return true;
  }).length / waitlistPaginationState.perPage);

  if (waitlistPaginationState.currentPage < totalPages) {
    waitlistPaginationState.currentPage++;
    renderWaitlist();
  }
};

// Waitlist filter buttons
document.getElementById('quickFilterPending').onclick = () => {
  waitlistQuickFilter = 'pending';
  document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
  document.getElementById('quickFilterPending').classList.add('active');
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

document.getElementById('waitlistFilterInvited').onclick = () => {
  waitlistQuickFilter = 'invited';
  document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
  document.getElementById('waitlistFilterInvited').classList.add('active');
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

document.getElementById('quickFilterRejected').onclick = () => {
  waitlistQuickFilter = 'rejected';
  document.querySelectorAll('.waitlist-filter').forEach(btn => btn.classList.remove('active'));
  document.getElementById('quickFilterRejected').classList.add('active');
  waitlistPaginationState.currentPage = 1;
  renderWaitlist();
};

// Reject waitlist functionality
document.getElementById('rejectWaitlistBtn').onclick = async () => {
  const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
  if (checkboxes.length === 0) {
    showToast('Please select at least one waitlist entry', 'warning');
    return;
  }

  const reason = prompt('Enter rejection reason (optional):');
  if (reason === null) return; // User cancelled

  const confirmed = await showConfirm(
    'Reject Waitlist Entries',
    `Reject ${checkboxes.length} waitlist ${checkboxes.length === 1 ? 'entry' : 'entries'}?`,
    'Reject',
    'Cancel',
    true  // isDanger
  );
  if (!confirmed) return;

  const waitlist_ids = Array.from(checkboxes).map(cb => cb.getAttribute('data-id'));

  // Update locally (we'll create a backend endpoint later)
  waitlist_ids.forEach(id => {
    const entry = allWaitlistData.find(w => w.waitlist_id === id);
    if (entry) {
      entry.status = 'rejected';
      entry.rejected_at = new Date().toISOString();
      entry.rejection_reason = reason;
    }
  });

  showToast(`Rejected ${waitlist_ids.length} ${waitlist_ids.length === 1 ? 'entry' : 'entries'}`, 'success');
  updateWaitlistCounts();
  renderWaitlist();
};

document.getElementById('deleteWaitlistBtn').onclick = async () => {
  const checkboxes = document.querySelectorAll('.waitlist-checkbox:checked');
  if (checkboxes.length === 0) {
    showToast('Please select at least one waitlist entry', 'warning');
    return;
  }

  const confirmed = await showConfirm(
    'Delete Waitlist Entries',
    `Permanently delete ${checkboxes.length} waitlist ${checkboxes.length === 1 ? 'entry' : 'entries'}? This action cannot be undone.`,
    'Delete',
    'Cancel',
    true  // isDanger
  );
  if (!confirmed) return;

  const waitlist_ids = Array.from(checkboxes).map(cb => cb.getAttribute('data-id'));

  try {
    const token = idToken();
    const res = await fetch(`${API_URL}/admin/waitlist`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ waitlist_ids })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to delete waitlist entries');

    // Remove deleted entries from local data
    data.deleted.forEach(id => {
      const idx = allWaitlistData.findIndex(w => w.waitlist_id === id);
      if (idx !== -1) allWaitlistData.splice(idx, 1);
    });

    const successMsg = `Deleted ${data.deleted.length} ${data.deleted.length === 1 ? 'entry' : 'entries'}`;
    if (data.failed && data.failed.length > 0) {
      showToast(`${successMsg}. ${data.failed.length} failed.`, 'warning');
    } else {
      showToast(successMsg, 'success');
    }
    updateWaitlistCounts();
    renderWaitlist();
  } catch (err) {
    showToast(err.message, 'error');
  }
};

// ===== EMAIL MANAGEMENT =====

// Load sent emails from API
async function loadSentEmails() {
  if (!isAdmin()) return;

  const list = document.getElementById('sentEmailsList');
  if (!list) return;

  try {
    await refresh();

    const res = await fetch(API_URL + '/admin/sent-emails', {
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });

    if (!res.ok) throw new Error('Failed to load sent emails');

    const emails = await res.json();

    if (!emails || emails.length === 0) {
      list.innerHTML = '<p class="muted" style="text-align:center;padding:20px;">No emails sent yet</p>';
      return;
    }

    // Display emails (newest first - should already be sorted by backend)
    list.innerHTML = emails.map(email => {
      const sentDate = new Date(email.sent_at).toLocaleString();
      const recipientLabel = {
        'waitlist': 'Waitlisted Users',
        'registered': 'Registered Users',
        'members': 'Members',
        'subscribers': 'Subscribers'
      }[email.recipient_type] || email.recipient_type;

      return `
        <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:8px;padding:16px;">
          <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;flex-wrap:wrap;gap:8px;">
            <div style="flex:1;min-width:200px;">
              <h4 style="margin:0 0 4px 0;font-size:1rem;">${escapeHtml(email.subject)}</h4>
              <p class="muted" style="font-size:0.85rem;margin:0;">To: <strong>${recipientLabel}</strong></p>
            </div>
            <span style="background:#10b981;color:#fff;padding:4px 10px;border-radius:12px;font-size:0.75rem;font-weight:600;">${email.recipient_count || 0} recipients</span>
          </div>
          <div style="font-size:0.85rem;color:var(--gray);margin-bottom:8px;">
            <span>Sent: ${sentDate}</span>
            <span style="margin-left:16px;">By: ${escapeHtml(email.sent_by)}</span>
          </div>
          <details style="margin-top:12px;">
            <summary style="cursor:pointer;color:var(--accent);font-size:0.9rem;font-weight:600;">View Message</summary>
            <div style="margin-top:12px;padding:12px;background:var(--bg-card);border-radius:4px;border:1px solid var(--border);font-size:0.9rem;max-height:300px;overflow-y:auto;">
              ${email.body_html || escapeHtml(email.body_text || '')}
            </div>
          </details>
        </div>
      `;
    }).join('');

  } catch (err) {
    console.error('Error loading sent emails:', err);
    list.innerHTML = '<p class="muted" style="text-align:center;padding:20px;color:var(--error);">Error loading sent emails. Please try again.</p>';
  }
}

// Compose Email Modal functions
function openComposeEmailModal() {
  document.getElementById('composeEmailModal').classList.add('active');
}

function closeComposeEmailModal() {
  document.getElementById('composeEmailModal').classList.remove('active');
  // Clear form
  document.getElementById('emailRecipientType').value = '';
  document.getElementById('emailSubject').value = '';
  document.getElementById('emailBody').value = '';
}

// Open compose email modal button
document.getElementById('openComposeEmailBtn')?.addEventListener('click', openComposeEmailModal);

// Send bulk email
document.getElementById('sendBulkEmail')?.addEventListener('click', async () => {
  const recipientType = document.getElementById('emailRecipientType').value;
  const subject = document.getElementById('emailSubject').value.trim();
  const body = document.getElementById('emailBody').value.trim();

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

  const confirmed = await showConfirm(
    'Send Bulk Email',
    `Send this email to ${recipientLabel}? This action cannot be undone.`,
    'Send Email',
    'Cancel',
    false
  );
  if (!confirmed) return;

  const btn = document.getElementById('sendBulkEmail');
  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = 'Sending...';

  try {
    await refresh();

    const res = await fetch(API_URL + '/admin/send-bulk-email', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + idToken(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        recipient_type: recipientType,
        subject,
        body_html: body,
        body_text: body.replace(/<[^>]*>/g, '') // Strip HTML for text version
      })
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ message: 'Failed to send email' }));
      throw new Error(errorData.message || 'Failed to send email');
    }

    const data = await res.json();
    showToast(`Email sent successfully to ${data.recipient_count} recipients!`, 'success');

    // Close modal and clear form
    closeComposeEmailModal();

    // Reload sent emails list
    await loadSentEmails();

  } catch (err) {
    console.error('Error sending email:', err);
    showToast(err.message || 'Failed to send email', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
});

// Refresh sent emails button
document.getElementById('refreshSentEmails')?.addEventListener('click', loadSentEmails);

// ===== COMMUNICATIONS PAGE =====

// Communications tab switching
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
    document.getElementById(`${targetPanel}-panel`).style.display = 'block';

    // Load data for history panel
    if (targetPanel === 'broadcast-history') {
      loadBroadcastHistory();
    }
  });
});

// Broadcast type description updates
const broadcastTypeDescriptions = {
  system_announcement: 'Maintenance notices, new features, terms updates',
  security_alert: 'Urgent security notifications, breach alerts, action required',
  admin_message: 'Custom messages from administrators'
};

document.getElementById('broadcastType')?.addEventListener('change', (e) => {
  const desc = broadcastTypeDescriptions[e.target.value] || '';
  document.getElementById('broadcastTypeDesc').textContent = desc;
});

// Send vault broadcast
document.getElementById('sendVaultBroadcastBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('sendVaultBroadcastBtn');
  const originalText = btn.innerHTML;

  const type = document.getElementById('broadcastType').value;
  const priority = document.querySelector('input[name="broadcastPriority"]:checked')?.value || 'normal';
  const title = document.getElementById('broadcastTitle').value.trim();
  const message = document.getElementById('broadcastMessage').value.trim();

  // Validation
  if (!title || title.length < 3) {
    showToast('Title must be at least 3 characters', 'warning');
    return;
  }
  if (!message || message.length < 10) {
    showToast('Message must be at least 10 characters', 'warning');
    return;
  }

  // Confirm for high/critical priority
  if (priority === 'critical') {
    const confirmed = await showConfirm(
      'Critical Broadcast',
      'Critical broadcasts interrupt user flow. Are you sure you want to send this?',
      'Send Anyway',
      'Cancel',
      true
    );
    if (!confirmed) return;
  }

  try {
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-block;animation:spin 1s linear infinite;">⟳</span> Sending...';

    const result = await api('/admin/broadcasts', {
      method: 'POST',
      body: JSON.stringify({ type, priority, title, message })
    });

    showToast(`Broadcast sent: ${result.title}`, 'success');

    // Clear form
    document.getElementById('broadcastTitle').value = '';
    document.getElementById('broadcastMessage').value = '';
    document.querySelector('input[name="broadcastPriority"][value="normal"]').checked = true;

  } catch (e) {
    showToast('Failed to send broadcast: ' + (e.message || e), 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
});

// Load broadcast history
async function loadBroadcastHistory() {
  const container = document.getElementById('broadcastHistoryList');
  const filter = document.getElementById('historyTypeFilter')?.value || 'all';

  container.innerHTML = '<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">Loading...</div>';

  try {
    // Fetch vault broadcasts
    let vaultBroadcasts = [];
    if (filter === 'all' || filter === 'vault') {
      const vaultData = await api('/admin/broadcasts');
      vaultBroadcasts = (vaultData.broadcasts || []).map(b => ({
        ...b,
        source: 'vault',
        sent_at: b.sent_at
      }));
    }

    // Fetch email broadcasts (from sent emails)
    // API returns array directly, not { emails: [...] }
    let emailBroadcasts = [];
    if (filter === 'all' || filter === 'email') {
      const emailData = await api('/admin/sent-emails');
      // Handle both array format (current API) and object format (future proofing)
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
    }

    // Combine and sort by sent_at
    const allBroadcasts = [...vaultBroadcasts, ...emailBroadcasts].sort((a, b) => {
      return new Date(b.sent_at).getTime() - new Date(a.sent_at).getTime();
    });

    if (allBroadcasts.length === 0) {
      container.innerHTML = '<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">No broadcasts found.</div>';
      return;
    }

    // Render broadcasts
    container.innerHTML = allBroadcasts.slice(0, 50).map(b => {
      const isVault = b.source === 'vault';
      const typeColor = b.type === 'security_alert' ? '#ef4444' :
                        b.type === 'system_announcement' ? '#3b82f6' :
                        b.type === 'admin_message' ? '#10b981' : '#6b7280';
      const priorityBadge = b.priority === 'critical' ? '<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem;margin-left:8px;">CRITICAL</span>' :
                           b.priority === 'high' ? '<span style="background:#f59e0b;color:#000;padding:2px 8px;border-radius:4px;font-size:0.7rem;margin-left:8px;">HIGH</span>' : '';

      // Delivery status badge for vault broadcasts
      let deliveryBadge = '';
      if (isVault && b.delivery_status) {
        const statusColor = b.delivery_status === 'delivered' ? '#10b981' :
                           b.delivery_status === 'failed' ? '#ef4444' :
                           b.delivery_status === 'sending' ? '#f59e0b' : '#6b7280';
        const statusText = b.delivery_status.charAt(0).toUpperCase() + b.delivery_status.slice(1);
        deliveryBadge = `<span style="background:${statusColor}22;color:${statusColor};padding:2px 8px;border-radius:4px;font-size:0.7rem;margin-left:8px;">${statusText}</span>`;
      } else if (!isVault) {
        deliveryBadge = '<span style="background:#10b98122;color:#10b981;padding:2px 8px;border-radius:4px;font-size:0.7rem;margin-left:8px;">Sent</span>';
      }

      const sourceIcon = isVault ?
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>' :
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>';

      return `
        <div style="padding:16px;background:#050505;border-radius:8px;border-left:4px solid ${typeColor};">
          <div style="display:flex;justify-content:space-between;align-items:start;gap:12px;margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <span style="color:${typeColor};">${sourceIcon}</span>
              <span style="font-weight:600;color:var(--text);">${escapeHtml(b.title)}</span>
              ${priorityBadge}
              ${deliveryBadge}
            </div>
            <span style="color:var(--gray);font-size:0.8rem;white-space:nowrap;">${new Date(b.sent_at).toLocaleString()}</span>
          </div>
          <p style="margin:0 0 8px 0;color:var(--gray);font-size:0.9rem;line-height:1.5;">${escapeHtml(b.message?.substring(0, 200) || '')}${b.message?.length > 200 ? '...' : ''}</p>
          <div style="display:flex;gap:16px;color:var(--gray);font-size:0.8rem;flex-wrap:wrap;">
            <span>Type: <span style="color:${typeColor};">${b.type?.replace('_', ' ') || 'email'}</span></span>
            <span>By: ${escapeHtml(b.sent_by || '—')}</span>
            ${b.recipient_count ? `<span>Recipients: ${b.recipient_count}</span>` : ''}
            ${isVault && b.nats_subject ? `<span>Subject: ${escapeHtml(b.nats_subject)}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');

  } catch (e) {
    console.error('Error loading broadcast history:', e);
    container.innerHTML = `<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;">Error loading history: ${escapeHtml(e.message || e)}</div>`;
  }
}

// Refresh broadcast history
document.getElementById('refreshBroadcastHistory')?.addEventListener('click', loadBroadcastHistory);
document.getElementById('historyTypeFilter')?.addEventListener('change', loadBroadcastHistory);

// ===== SECURITY EVENTS =====

async function loadSecurityEvents() {
  const range = document.getElementById('securityTimeRange')?.value || '24h';
  const severity = document.getElementById('securitySeverityFilter')?.value || 'all';

  try {
    const data = await api(`/admin/security-events?range=${range}&severity=${severity}&limit=100`);

    // Update metrics
    document.getElementById('secMetricTotal').textContent = data.metrics?.total_events ?? '--';
    document.getElementById('secMetricCritical').textContent = data.metrics?.critical ?? '0';
    document.getElementById('secMetricHigh').textContent = data.metrics?.high ?? '0';
    document.getElementById('secMetricAuth').textContent = data.metrics?.auth_failures ?? '0';
    document.getElementById('secMetricRecovery').textContent = data.metrics?.pending_recovery_requests ?? '0';
    document.getElementById('secMetricDeletion').textContent = data.metrics?.pending_deletion_requests ?? '0';

    // Render events list
    const container = document.getElementById('securityEventsList');
    if (!data.events || data.events.length === 0) {
      container.innerHTML = `<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">No security events found for the selected time range.</div>`;
      return;
    }

    const severityColors = {
      critical: { bg: 'rgba(239,68,68,0.2)', border: '#ef4444', text: '#ef4444' },
      high: { bg: 'rgba(245,158,11,0.15)', border: '#f59e0b', text: '#f59e0b' },
      medium: { bg: 'rgba(99,102,241,0.1)', border: '#6366f1', text: '#6366f1' },
      low: { bg: 'rgba(156,163,175,0.1)', border: '#6b7280', text: '#9ca3af' }
    };

    container.innerHTML = data.events.map(event => {
      const colors = severityColors[event.severity] || severityColors.low;
      const time = event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown';
      const typeLabel = event.type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

      return `
        <div style="padding:12px 16px;background:${colors.bg};border-radius:8px;border-left:4px solid ${colors.border};display:flex;justify-content:space-between;align-items:center;">
          <div style="flex:1;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
              <span style="padding:2px 8px;background:${colors.border};color:#000;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase;">${event.severity}</span>
              <span style="color:${colors.text};font-weight:600;font-size:0.9rem;">${escapeHtml(typeLabel)}</span>
            </div>
            <p style="margin:0;color:var(--gray);font-size:0.85rem;">
              ${event.email ? `User: ${escapeHtml(event.email)} | ` : ''}
              ${event.path ? `Path: ${escapeHtml(event.path)} | ` : ''}
              ${event.reason ? `Reason: ${escapeHtml(event.reason)}` : ''}
            </p>
          </div>
          <span style="color:var(--gray);font-size:0.8rem;white-space:nowrap;">${time}</span>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error('Error loading security events:', e);
    document.getElementById('securityEventsList').innerHTML = `<div style="padding:16px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;">Error: ${escapeHtml(e.message || e)}</div>`;
  }
}

async function loadRecoveryRequests() {
  const container = document.getElementById('recoveryRequestsList');

  try {
    const data = await api('/admin/credential-recovery-requests?status=pending');

    if (!data.requests || data.requests.length === 0) {
      container.innerHTML = `<div style="padding:16px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">No pending credential recovery requests.</div>`;
      return;
    }

    container.innerHTML = data.requests.map(req => `
      <div style="padding:16px;background:linear-gradient(135deg,rgba(99,102,241,0.1) 0%,rgba(79,70,229,0.05) 100%);border-radius:8px;border:1px solid #6366f1;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
        <div>
          <p style="margin:0 0 4px 0;color:var(--text);font-weight:600;">${escapeHtml(req.member_email || 'Unknown User')}</p>
          <p style="margin:0;color:var(--gray);font-size:0.85rem;">
            Type: ${escapeHtml(req.recovery_type || 'lost_device')} |
            Requested: ${req.requested_at ? new Date(req.requested_at).toLocaleString() : 'Unknown'}
          </p>
          <p style="margin:4px 0 0 0;color:#6366f1;font-size:0.9rem;font-weight:600;">
            ⏱ ${req.time_remaining_readable || 'Ready'}
          </p>
        </div>
        <button data-cancel-recovery="${escapeHtml(req.recovery_id)}" class="btn" style="padding:8px 16px;background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);font-size:0.85rem;">
          Cancel
        </button>
      </div>
    `).join('');

    // Event delegation for cancel recovery buttons
    container.querySelectorAll('[data-cancel-recovery]').forEach(btn => {
      btn.addEventListener('click', () => cancelRecoveryRequest(btn.dataset.cancelRecovery));
    });
  } catch (e) {
    console.error('Error loading recovery requests:', e);
    container.innerHTML = `<div style="padding:16px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;">Error: ${escapeHtml(e.message || e)}</div>`;
  }
}

async function loadDeletionRequests() {
  const container = document.getElementById('deletionRequestsList');

  try {
    const data = await api('/admin/vault-deletion-requests?status=pending');

    if (!data.requests || data.requests.length === 0) {
      container.innerHTML = `<div style="padding:16px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">No pending vault deletion requests.</div>`;
      return;
    }

    container.innerHTML = data.requests.map(req => `
      <div style="padding:16px;background:linear-gradient(135deg,rgba(239,68,68,0.15) 0%,rgba(185,28,28,0.05) 100%);border-radius:8px;border:1px solid #dc2626;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
        <div>
          <p style="margin:0 0 4px 0;color:var(--text);font-weight:600;">${escapeHtml(req.member_email || 'Unknown User')}</p>
          <p style="margin:0;color:var(--gray);font-size:0.85rem;">
            ${req.reason ? `Reason: ${escapeHtml(req.reason)} | ` : ''}
            Requested: ${req.requested_at ? new Date(req.requested_at).toLocaleString() : 'Unknown'}
          </p>
          <p style="margin:4px 0 0 0;color:#ef4444;font-size:0.9rem;font-weight:600;">
            ⏱ ${req.time_remaining_readable || 'Ready for deletion'}
          </p>
        </div>
        <button data-cancel-deletion="${escapeHtml(req.request_id)}" class="btn" style="padding:8px 16px;background:#333;font-size:0.85rem;">
          Cancel Deletion
        </button>
      </div>
    `).join('');

    // Event delegation for cancel deletion buttons
    container.querySelectorAll('[data-cancel-deletion]').forEach(btn => {
      btn.addEventListener('click', () => cancelDeletionRequest(btn.dataset.cancelDeletion));
    });
  } catch (e) {
    console.error('Error loading deletion requests:', e);
    container.innerHTML = `<div style="padding:16px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;">Error: ${escapeHtml(e.message || e)}</div>`;
  }
}

async function cancelRecoveryRequest(recoveryId) {
  if (!confirm('Are you sure you want to cancel this credential recovery request?')) return;

  try {
    await api(`/admin/credential-recovery-requests/${recoveryId}/cancel`, {
      method: 'POST',
      body: { reason: 'Cancelled by admin' }
    });

    showToast('Recovery request cancelled successfully', 'success');
    loadRecoveryRequests();
    loadSecurityEvents();
  } catch (e) {
    console.error('Error cancelling recovery request:', e);
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function cancelDeletionRequest(requestId) {
  if (!confirm('Are you sure you want to cancel this vault deletion request?')) return;

  try {
    await api(`/admin/vault-deletion-requests/${requestId}/cancel`, {
      method: 'POST',
      body: { reason: 'Cancelled by admin' }
    });

    showToast('Deletion request cancelled successfully', 'success');
    loadDeletionRequests();
    loadSecurityEvents();
  } catch (e) {
    console.error('Error cancelling deletion request:', e);
    showToast(`Error: ${e.message}`, 'error');
  }
}

// Security Events tab event listeners
document.getElementById('refreshSecurityEvents')?.addEventListener('click', () => {
  loadSecurityEvents();
  loadRecoveryRequests();
  loadDeletionRequests();
});
document.getElementById('securityTimeRange')?.addEventListener('change', loadSecurityEvents);
document.getElementById('securitySeverityFilter')?.addEventListener('change', loadSecurityEvents);
document.getElementById('refreshRecoveryRequests')?.addEventListener('click', loadRecoveryRequests);
document.getElementById('refreshDeletionRequests')?.addEventListener('click', loadDeletionRequests);

// ===== FLATPICKR DATE PICKER INITIALIZATION =====
// Initialize Flatpickr on date inputs for better UX
document.addEventListener('DOMContentLoaded', function() {
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

      const monthDropdown = cal.querySelector('.flatpickr-monthDropdown-months');
      if (monthDropdown) {
        monthDropdown.style.setProperty('color', '#000', 'important');
        monthDropdown.style.setProperty('background', 'transparent', 'important');
        monthDropdown.style.setProperty('font-weight', '600', 'important');
      }

      cal.querySelectorAll('.flatpickr-prev-month, .flatpickr-next-month').forEach(el => {
        el.style.setProperty('fill', '#000', 'important');
      });
      cal.querySelectorAll('.flatpickr-prev-month svg, .flatpickr-next-month svg').forEach(el => {
        el.style.setProperty('fill', '#000', 'important');
      });

      const weekdays = cal.querySelector('.flatpickr-weekdays');
      if (weekdays) {
        weekdays.style.setProperty('background', '#f9fafb', 'important');
      }
      cal.querySelectorAll('.flatpickr-weekday').forEach(el => {
        el.style.setProperty('color', '#6b7280', 'important');
        el.style.setProperty('background', 'transparent', 'important');
      });

      cal.querySelectorAll('.flatpickr-day').forEach(el => {
        el.style.setProperty('color', '#1f2937', 'important');
      });
    } else {
      // Dark theme styles - reset to flatpickr defaults or apply dark styles
      cal.style.setProperty('background', '#1e1e2e', 'important');
      cal.style.setProperty('border', '1px solid #3d3d5c', 'important');
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

      const monthDropdown = cal.querySelector('.flatpickr-monthDropdown-months');
      if (monthDropdown) {
        monthDropdown.style.setProperty('color', '#000', 'important');
        monthDropdown.style.setProperty('background', 'transparent', 'important');
        monthDropdown.style.setProperty('font-weight', '600', 'important');
      }

      cal.querySelectorAll('.flatpickr-prev-month, .flatpickr-next-month').forEach(el => {
        el.style.setProperty('fill', '#000', 'important');
      });
      cal.querySelectorAll('.flatpickr-prev-month svg, .flatpickr-next-month svg').forEach(el => {
        el.style.setProperty('fill', '#000', 'important');
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

  // Date-only pickers for invite filters
  if (document.getElementById('filterDateFrom')) {
    flatpickr('#filterDateFrom', {
      ...baseConfig,
      dateFormat: 'Y-m-d',
      onChange: function(selectedDates, dateStr) {
        // Trigger filter update
        paginationState.invites.page = 0;
        renderInvites();
      }
    });
  }

  if (document.getElementById('filterDateTo')) {
    flatpickr('#filterDateTo', {
      ...baseConfig,
      dateFormat: 'Y-m-d',
      onChange: function(selectedDates, dateStr) {
        paginationState.invites.page = 0;
        renderInvites();
      }
    });
  }

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

  // DateTime pickers for proposal dates with future-only constraint
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
});

// ============================================
// HANDLER MARKETPLACE MANAGEMENT
// ============================================

let deployedHandlers = [];

// Format bytes to human readable
function formatHandlerBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Handler tab (just deployed handlers now - VettID-managed only)
document.querySelectorAll('.handler-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    tab.classList.add('active');
    tab.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
    loadDeployedHandlers();
  });
});

// Load deployed handlers
async function loadDeployedHandlers() {
  if (!isAdmin()) return;

  const grid = document.getElementById('deployedHandlersGrid');
  grid.innerHTML = '<div style="grid-column:1/-1;padding:40px;text-align:center;color:var(--gray);">Loading deployed handlers...</div>';

  try {
    const response = await api('/admin/handlers/deployed');
    deployedHandlers = response.handlers || [];
    renderDeployedHandlers();
  } catch (err) {
    console.error('Error loading deployed handlers:', err);
    grid.innerHTML = `<div style="grid-column:1/-1;padding:40px;text-align:center;color:#ef4444;">Error loading handlers: ${escapeHtml(err.message)}</div>`;
    showToast('Failed to load deployed handlers', 'error');
  }
}

// Render deployed handlers grid
function renderDeployedHandlers() {
  const grid = document.getElementById('deployedHandlersGrid');
  const countEl = document.getElementById('deployedHandlersCount');

  if (countEl) countEl.textContent = deployedHandlers.length;

  if (deployedHandlers.length === 0) {
    grid.innerHTML = `<div style="grid-column:1/-1;padding:40px;text-align:center;color:var(--gray);">
      <div style="font-size:2rem;margin-bottom:8px;">📦</div>
      <div>No VettID handlers deployed yet</div>
    </div>`;
    return;
  }

  grid.innerHTML = deployedHandlers.map(h => {
    // Signed handlers are production-ready (green), revoked = red, pending = yellow
    const statusColor = h.status === 'signed' ? '#10b981' : h.status === 'revoked' ? '#ef4444' : h.status === 'pending' ? '#f59e0b' : '#6b7280';
    const statusLabel = h.status === 'signed' ? 'Deployed' : h.status;
    return `
      <div class="handler-card" style="padding:20px;background:#050505;border-radius:12px;border:1px solid var(--border);transition:border-color 0.2s;">
        <div style="display:flex;align-items:start;gap:12px;margin-bottom:12px;">
          <div style="width:48px;height:48px;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;">
            ${h.icon || '📦'}
          </div>
          <div style="flex:1;min-width:0;">
            <div style="font-weight:600;color:var(--text);margin-bottom:2px;">${escapeHtml(h.name || h.handler_id)}</div>
            <div style="font-size:0.8rem;color:var(--gray);font-family:monospace;">${escapeHtml(h.handler_id)}</div>
          </div>
          <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${statusColor};" title="${statusLabel}"></span>
        </div>
        <p style="margin:0 0 12px 0;color:var(--gray);font-size:0.85rem;line-height:1.4;min-height:40px;">
          ${escapeHtml((h.description || 'No description').substring(0, 100))}${h.description?.length > 100 ? '...' : ''}
        </p>
        <div style="display:flex;gap:8px;align-items:center;">
          <code style="background:var(--bg-card);padding:4px 8px;border-radius:4px;font-size:0.8rem;color:var(--accent);">v${escapeHtml(h.version || '1.0.0')}</code>
          ${h.category ? `<span style="background:#222;padding:4px 8px;border-radius:4px;font-size:0.75rem;color:var(--gray);">${escapeHtml(h.category)}</span>` : ''}
        </div>
        ${h.install_count > 0 ? `<div style="margin-top:8px;font-size:0.75rem;color:var(--gray);">📥 ${h.install_count} installs</div>` : ''}
      </div>
    `;
  }).join('');
}

// Load handlers (VettID-managed only, simplified since no submission workflow)
async function loadHandlers() {
  return loadDeployedHandlers();
}

// Event listeners for handler management
document.addEventListener('DOMContentLoaded', function() {
  // Refresh handlers button
  const refreshBtn = document.getElementById('refreshHandlersBtn');
  if (refreshBtn) refreshBtn.onclick = loadDeployedHandlers;
});

// ========================================
// Supported Services Management
// ========================================

let servicesData = [];
let serviceStatusFilter = 'all';
let serviceTypeFilter = 'all';
let serviceSearchTerm = '';
let currentServiceId = null;
let isEditingService = false;

async function loadServices() {
  try {
    showLoadingSkeleton('servicesTable');
    const res = await api('/admin/services');
    servicesData = res.services || [];
    renderServices();
  } catch (err) {
    console.error('Error loading services:', err);
    showToast('Failed to load services', 'error');
    const tbody = document.getElementById('servicesTableBody');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#f44;padding:2rem;">Failed to load services. Please try again.</td></tr>`;
    }
  }
}

function renderServices() {
  const tbody = document.getElementById('servicesTableBody');
  if (!tbody) return;

  let filtered = servicesData;

  // Apply status filter
  if (serviceStatusFilter !== 'all') {
    filtered = filtered.filter(s => s.status === serviceStatusFilter);
  }

  // Apply type filter
  if (serviceTypeFilter !== 'all') {
    filtered = filtered.filter(s => s.service_type === serviceTypeFilter);
  }

  // Apply search
  if (serviceSearchTerm) {
    const term = serviceSearchTerm.toLowerCase();
    filtered = filtered.filter(s =>
      (s.name || '').toLowerCase().includes(term) ||
      (s.description || '').toLowerCase().includes(term) ||
      (s.service_id || '').toLowerCase().includes(term)
    );
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--gray);padding:2rem;">No results</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(service => {
    const statusClass = service.status === 'active' ? 'status-active' :
                        service.status === 'coming-soon' ? 'status-pending' : 'status-rejected';
    const statusText = service.status === 'coming-soon' ? 'Coming Soon' :
                       service.status.charAt(0).toUpperCase() + service.status.slice(1);
    const typeLabel = (service.service_type || 'other').charAt(0).toUpperCase() + (service.service_type || 'other').slice(1);

    return `
      <tr data-action="service-details" data-service-id="${service.service_id}" style="cursor:pointer;">
        <td>
          <div style="display:flex;align-items:center;gap:0.75rem;">
            ${service.icon_url ? `<img src="${service.icon_url}" alt="" style="width:32px;height:32px;border-radius:6px;object-fit:cover;">` :
              `<div style="width:32px;height:32px;border-radius:6px;background:var(--light);display:flex;align-items:center;justify-content:center;font-weight:600;color:var(--gray);">${(service.name || '?').charAt(0).toUpperCase()}</div>`}
            <div>
              <div style="font-weight:500;">${service.name || 'Unnamed'}</div>
              <div style="font-size:0.75rem;color:var(--gray);">${service.service_id}</div>
            </div>
          </div>
        </td>
        <td><span class="badge" style="background:var(--light);color:var(--dark);">${typeLabel}</span></td>
        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
        <td>${service.connect_count || 0}</td>
        <td>${service.updated_at ? new Date(service.updated_at).toLocaleDateString() : '-'}</td>
        <td data-action="stop-propagation">
          <div class="dropdown" style="position:relative;">
            <button class="btn btn-secondary btn-sm dropdown-toggle" data-action="toggle-service-dropdown">Actions</button>
            <div class="dropdown-menu" style="display:none;position:absolute;right:0;top:100%;background:white;border:1px solid var(--border);border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);min-width:140px;z-index:100;">
              <a href="#" data-action="service-edit" data-service-id="${service.service_id}" style="display:block;padding:0.5rem 1rem;color:var(--dark);text-decoration:none;">Edit</a>
              <a href="#" data-action="service-toggle-status" data-service-id="${service.service_id}" data-new-status="${service.status === 'active' ? 'deprecated' : 'active'}" style="display:block;padding:0.5rem 1rem;color:var(--dark);text-decoration:none;">${service.status === 'active' ? 'Deprecate' : 'Activate'}</a>
              <a href="#" data-action="service-delete" data-service-id="${service.service_id}" style="display:block;padding:0.5rem 1rem;color:#ef4444;text-decoration:none;">Delete</a>
            </div>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function toggleServiceDropdown(btn, event) {
  event.stopPropagation();
  const menu = btn.nextElementSibling;
  const wasVisible = menu.style.display === 'block';

  // Close all dropdowns first
  document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');

  if (!wasVisible) {
    menu.style.display = 'block';
    // Close on outside click
    setTimeout(() => {
      document.addEventListener('click', function closeDropdown() {
        menu.style.display = 'none';
        document.removeEventListener('click', closeDropdown);
      }, { once: true });
    }, 0);
  }
}

function openServiceModal(editing = false) {
  isEditingService = editing;
  const modal = document.getElementById('serviceModal');
  const title = document.getElementById('serviceModalTitle');
  const form = document.getElementById('serviceForm');

  title.textContent = editing ? 'Edit Service' : 'Add New Service';

  if (!editing) {
    form.reset();
    currentServiceId = null;
    document.getElementById('serviceIdInput').disabled = false;
  }

  modal.classList.add('active');
}

function openEditServiceModal(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;
  isEditingService = true;

  document.getElementById('serviceIdInput').value = service.service_id;
  document.getElementById('serviceIdInput').disabled = true;
  document.getElementById('serviceNameInput').value = service.name || '';
  document.getElementById('serviceDescInput').value = service.description || '';
  document.getElementById('serviceTypeSelect').value = service.service_type || 'other';
  document.getElementById('serviceStatusSelect').value = service.status || 'active';
  document.getElementById('serviceIconInput').value = service.icon_url || '';
  document.getElementById('serviceWebsiteInput').value = service.website_url || '';
  document.getElementById('serviceConnectInput').value = service.connect_url || '';
  document.getElementById('serviceOrderInput').value = service.sort_order || 100;
  document.getElementById('serviceDataKeysInput').value = (service.required_user_data || []).join(', ');

  document.getElementById('serviceModalTitle').textContent = 'Edit Service';
  document.getElementById('serviceModal').classList.add('active');
}

function closeServiceModal() {
  document.getElementById('serviceModal').classList.remove('active');
  currentServiceId = null;
  isEditingService = false;
}

async function saveService() {
  const serviceId = document.getElementById('serviceIdInput').value.trim();
  const name = document.getElementById('serviceNameInput').value.trim();
  const description = document.getElementById('serviceDescInput').value.trim();
  const serviceType = document.getElementById('serviceTypeSelect').value;
  const status = document.getElementById('serviceStatusSelect').value;
  const iconUrl = document.getElementById('serviceIconInput').value.trim();
  const websiteUrl = document.getElementById('serviceWebsiteInput').value.trim();
  const connectUrl = document.getElementById('serviceConnectInput').value.trim();
  const sortOrder = parseInt(document.getElementById('serviceOrderInput').value) || 100;
  const dataKeysStr = document.getElementById('serviceDataKeysInput').value.trim();
  const requiredUserData = dataKeysStr ? dataKeysStr.split(',').map(s => s.trim()).filter(s => s) : [];

  if (!serviceId || !name) {
    showToast('Service ID and Name are required', 'error');
    return;
  }

  const payload = {
    service_id: serviceId,
    name,
    description,
    service_type: serviceType,
    status,
    icon_url: iconUrl || undefined,
    website_url: websiteUrl || undefined,
    connect_url: connectUrl || undefined,
    sort_order: sortOrder,
    required_user_data: requiredUserData.length > 0 ? requiredUserData : undefined
  };

  try {
    if (isEditingService) {
      await api('/admin/services', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      showToast('Service updated successfully', 'success');
    } else {
      await api('/admin/services', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      showToast('Service created successfully', 'success');
    }
    closeServiceModal();
    loadServices();
  } catch (err) {
    console.error('Error saving service:', err);
    showToast('Failed to save service: ' + err.message, 'error');
  }
}

function openServiceDetails(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;

  const statusClass = service.status === 'active' ? 'status-active' :
                      service.status === 'coming-soon' ? 'status-pending' : 'status-rejected';
  const statusText = service.status === 'coming-soon' ? 'Coming Soon' :
                     service.status.charAt(0).toUpperCase() + service.status.slice(1);
  const typeLabel = (service.service_type || 'other').charAt(0).toUpperCase() + (service.service_type || 'other').slice(1);

  const content = document.getElementById('serviceDetailsContent');
  content.innerHTML = `
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;">
      ${service.icon_url ? `<img src="${service.icon_url}" alt="" style="width:64px;height:64px;border-radius:12px;object-fit:cover;">` :
        `<div style="width:64px;height:64px;border-radius:12px;background:var(--light);display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:600;color:var(--gray);">${(service.name || '?').charAt(0).toUpperCase()}</div>`}
      <div>
        <h3 style="margin:0;font-size:1.25rem;">${service.name || 'Unnamed Service'}</h3>
        <div style="color:var(--gray);font-size:0.875rem;">${service.service_id}</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem;">
      <div>
        <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;">Status</div>
        <span class="status-badge ${statusClass}">${statusText}</span>
      </div>
      <div>
        <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;">Type</div>
        <span class="badge" style="background:var(--light);color:var(--dark);">${typeLabel}</span>
      </div>
      <div>
        <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;">Connections</div>
        <div style="font-weight:500;">${service.connect_count || 0}</div>
      </div>
      <div>
        <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;">Sort Order</div>
        <div style="font-weight:500;">${service.sort_order || 100}</div>
      </div>
    </div>

    ${service.description ? `
    <div style="margin-bottom:1.5rem;">
      <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;">Description</div>
      <div>${service.description}</div>
    </div>
    ` : ''}

    <div style="margin-bottom:1.5rem;">
      <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.5rem;">Links</div>
      ${service.website_url ? `<div style="margin-bottom:0.5rem;"><a href="${service.website_url}" target="_blank" style="color:var(--primary);">Website</a></div>` : ''}
      ${service.connect_url ? `<div><a href="${service.connect_url}" target="_blank" style="color:var(--primary);">Connect URL</a></div>` : ''}
      ${!service.website_url && !service.connect_url ? '<div style="color:var(--gray);">No links configured</div>' : ''}
    </div>

    ${service.required_user_data && service.required_user_data.length > 0 ? `
    <div style="margin-bottom:1.5rem;">
      <div style="color:var(--gray);font-size:0.75rem;margin-bottom:0.5rem;">Required User Data</div>
      <div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
        ${service.required_user_data.map(key => `<span class="badge" style="background:var(--light);color:var(--dark);">${key}</span>`).join('')}
      </div>
    </div>
    ` : ''}

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;font-size:0.875rem;color:var(--gray);">
      <div>
        <div style="font-size:0.75rem;">Created</div>
        <div>${service.created_at ? new Date(service.created_at).toLocaleString() : '-'}</div>
        ${service.created_by ? `<div style="font-size:0.75rem;">${service.created_by}</div>` : ''}
      </div>
      <div>
        <div style="font-size:0.75rem;">Updated</div>
        <div>${service.updated_at ? new Date(service.updated_at).toLocaleString() : '-'}</div>
        ${service.updated_by ? `<div style="font-size:0.75rem;">${service.updated_by}</div>` : ''}
      </div>
    </div>
  `;

  document.getElementById('serviceDetailsModal').classList.add('active');
}

function closeServiceDetailsModal() {
  document.getElementById('serviceDetailsModal').classList.remove('active');
}

function editServiceFromDetails() {
  closeServiceDetailsModal();
  openEditServiceModal(currentServiceId);
}

async function toggleServiceStatus(serviceId, newStatus) {
  try {
    await api('/admin/services/status', {
      method: 'POST',
      body: JSON.stringify({
        service_id: serviceId,
        status: newStatus
      })
    });
    showToast(`Service ${newStatus === 'active' ? 'activated' : 'deprecated'}`, 'success');
    loadServices();
  } catch (err) {
    console.error('Error toggling service status:', err);
    showToast('Failed to update status', 'error');
  }
}

function openDeleteServiceModal(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;
  document.getElementById('deleteServiceName').textContent = service.name || serviceId;
  document.getElementById('confirmDeleteServiceInput').value = '';
  document.getElementById('deleteServiceMsg').textContent = '';
  document.getElementById('confirmDeleteServiceBtn').disabled = false;
  document.getElementById('deleteServiceModal').classList.add('active');
}

function closeDeleteServiceModal() {
  document.getElementById('deleteServiceModal').classList.remove('active');
  currentServiceId = null;
}

async function deleteService() {
  const confirmInput = document.getElementById('confirmDeleteServiceInput').value.trim();
  const service = servicesData.find(s => s.service_id === currentServiceId);
  if (!service) return;

  if (confirmInput !== service.name) {
    showToast('Service name does not match', 'error');
    return;
  }

  const msgEl = document.getElementById('deleteServiceMsg');
  const confirmBtn = document.getElementById('confirmDeleteServiceBtn');

  try {
    confirmBtn.disabled = true;
    msgEl.textContent = 'Deleting service...';
    msgEl.style.color = 'var(--gray)';

    await api('/admin/services/delete', {
      method: 'POST',
      body: JSON.stringify({
        service_id: currentServiceId
      })
    });

    showToast('Service deleted successfully', 'success');
    closeDeleteServiceModal();
    loadServices();
  } catch (err) {
    console.error('Error deleting service:', err);
    msgEl.textContent = 'Error: ' + err.message;
    msgEl.style.color = '#ef4444';
    confirmBtn.disabled = false;
    showToast('Failed to delete service', 'error');
  }
}

// Event listeners for supported services
document.addEventListener('DOMContentLoaded', function() {
  // Add service button
  const addServiceBtn = document.getElementById('addServiceBtn');
  if (addServiceBtn) addServiceBtn.onclick = () => openServiceModal(false);

  // Refresh services button
  const refreshServicesBtn = document.getElementById('refreshServicesBtn');
  if (refreshServicesBtn) refreshServicesBtn.onclick = loadServices;

  // Save service button
  const saveServiceBtn = document.getElementById('saveServiceBtn');
  if (saveServiceBtn) saveServiceBtn.onclick = saveService;

  // Edit from details button
  const editServiceFromDetailsBtn = document.getElementById('editServiceFromDetailsBtn');
  if (editServiceFromDetailsBtn) editServiceFromDetailsBtn.onclick = editServiceFromDetails;

  // Confirm delete button
  const confirmDeleteServiceBtn = document.getElementById('confirmDeleteServiceBtn');
  if (confirmDeleteServiceBtn) confirmDeleteServiceBtn.onclick = deleteService;

  // Status filter buttons
  document.querySelectorAll('.service-filter').forEach(btn => {
    btn.onclick = function() {
      document.querySelectorAll('.service-filter').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      serviceStatusFilter = this.dataset.filter;
      renderServices();
    };
  });

  // Type filter
  const typeFilter = document.getElementById('serviceTypeFilter');
  if (typeFilter) {
    typeFilter.onchange = function() {
      serviceTypeFilter = this.value;
      renderServices();
    };
  }

  // Search input
  const searchInput = document.getElementById('serviceSearchInput');
  if (searchInput) {
    let searchTimeout;
    searchInput.oninput = function() {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        serviceSearchTerm = this.value;
        renderServices();
      }, 300);
    };
  }
});

// Event delegation for data-action handlers
// This replaces inline onclick handlers for CSP compliance
document.addEventListener('click', (e) => {
  const target = e.target.closest('[data-action]');
  if (!target) return;

  const action = target.dataset.action;

  // Map action names to functions
  const actions = {
    'applyCustomIconUrl': applyCustomIconUrl,
    'clearIconSelection': clearIconSelection,
    'closeActivityLogModal': closeActivityLogModal,
    'closeAddAdminModal': closeAddAdminModal,
    'closeChangeAdminTypeModal': closeChangeAdminTypeModal,
    'closeComposeEmailModal': closeComposeEmailModal,
    'closeConfirmTermsModal': closeConfirmTermsModal,
    'closeCreateInviteModal': closeCreateInviteModal,
    'closeCreateProposalModal': closeCreateProposalModal,
    'closeCreateSubscriptionTypeModal': closeCreateSubscriptionTypeModal,
    'closeCreateTermsModal': closeCreateTermsModal,
    'closeCsvImportModal': closeCsvImportModal,
    'closeDeleteServiceModal': closeDeleteServiceModal,
    'closeGenericConfirmModal': () => closeGenericConfirmModal(false),
    'closeHandlerDetailsModal': closeHandlerDetailsModal,
    'closeManageAccessModal': closeManageAccessModal,
    'closeProposalAnalyticsModal': closeProposalAnalyticsModal,
    'closeRevokeHandlerModal': closeRevokeHandlerModal,
    'closeSelectNotificationAdminModal': closeSelectNotificationAdminModal,
    'closeServiceDetailsModal': closeServiceDetailsModal,
    'closeServiceModal': closeServiceModal,
    'handleChangeAdminType': handleChangeAdminType,
    'handleDeleteAdmin': handleDeleteAdmin,
    'handleResetAdminPassword': handleResetAdminPassword,
    'handleToggleAdminStatus': handleToggleAdminStatus,
    'openChangeAdminTypeModal': openChangeAdminTypeModal,
    'openCsvImportModal': openCsvImportModal,
    'toggleIconPicker': toggleIconPicker,
    'selectPresetIcon': () => {
      const iconId = target.dataset.iconId;
      const iconEmoji = target.dataset.iconEmoji;
      if (iconId && iconEmoji) {
        selectPresetIcon(iconId, iconEmoji);
      }
    }
  };

  if (actions[action]) {
    e.preventDefault();
    actions[action]();
  }
});

// ============================================
// HELP REQUESTS MANAGEMENT
// ============================================

// Help requests state
let helpRequests = [];
let helpQuickFilter = 'new';
let helpSearchQuery = '';
let currentHelpRequest = null;
const helpPagination = { page: 0, perPage: 10 };

// Help type labels for display
const helpTypeLabels = {
  'legal': 'Legal',
  'developer': 'Developer',
  'beta_tester': 'Beta Tester',
  'donation': 'Donation/Funding',
  'marketing': 'Marketing/PR',
  'design': 'Design/UX',
  'community': 'Community/Advocacy',
  'other': 'Other'
};

// Helper to create a card row with label and value using safe DOM methods
function createHelpCardRow(label, value) {
  const row = document.createElement('div');
  row.className = 'data-card-row';
  const labelSpan = document.createElement('span');
  labelSpan.className = 'data-card-label';
  labelSpan.textContent = label;
  const valueSpan = document.createElement('span');
  valueSpan.className = 'data-card-value';
  valueSpan.textContent = value;
  row.appendChild(labelSpan);
  row.appendChild(valueSpan);
  return row;
}

// Load help requests from API
async function loadHelpRequests(resetPage = true) {
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
    console.error('Error loading help requests:', e);
    tbody.replaceChildren();
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'muted';
    td.textContent = 'Error: ' + (e.message || String(e));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

// Update status badge counts
function updateHelpStatusCounts() {
  // Count by status - need to load all to get accurate counts
  api('/admin/help-requests').then(data => {
    const all = data.help_requests || [];
    const counts = {
      'new': 0,
      'contacted': 0,
      'in_progress': 0,
      'archived': 0
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

// Render help requests table
function renderHelpRequests() {
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
    td.colSpan = 7;
    td.className = 'muted';
    td.style.textAlign = 'center';
    td.style.padding = '40px';
    td.textContent = filtered.length === 0 ? 'No help requests found' : 'No matching results';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  paginated.forEach(request => {
    // Desktop table row
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.onclick = () => openHelpDetailModal(request);

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
    const statusColors = {
      'new': '#3b82f6',
      'contacted': '#f59e0b',
      'in_progress': '#10b981',
      'archived': '#6b7280'
    };
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
}

// Open help request detail modal
function openHelpDetailModal(request) {
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
  const linkedInSection = document.getElementById('helpDetailLinkedInSection');
  const linkedInLink = document.getElementById('helpDetailLinkedInLink');
  if (request.linkedin_url) {
    linkedInSection.style.display = 'block';
    linkedInLink.href = request.linkedin_url;
    linkedInLink.textContent = request.linkedin_url;
  } else {
    linkedInSection.style.display = 'none';
  }

  // Help types badges
  const typesContainer = document.getElementById('helpDetailTypes');
  typesContainer.replaceChildren();
  (request.help_types || []).forEach(type => {
    const badge = document.createElement('span');
    badge.textContent = helpTypeLabels[type] || type;
    badge.style.cssText = 'background:var(--accent);color:#000;padding:4px 12px;border-radius:4px;font-size:0.85rem;font-weight:600;';
    typesContainer.appendChild(badge);
  });

  // Message
  document.getElementById('helpDetailMessage').textContent = request.message || '-';

  // Status dropdown
  document.getElementById('helpDetailStatus').value = request.status || 'new';

  // Admin notes
  document.getElementById('helpDetailNotes').value = request.admin_notes || '';

  // Show modal
  modal.classList.add('active');
}

// Close help detail modal
function closeHelpDetailModal() {
  const modal = document.getElementById('helpDetailModal');
  if (modal) modal.classList.remove('active');
  currentHelpRequest = null;
}

// Save help request changes
async function saveHelpRequest() {
  if (!currentHelpRequest) return;

  const status = document.getElementById('helpDetailStatus').value;
  const adminNotes = document.getElementById('helpDetailNotes').value;

  try {
    await api('/admin/help-requests/' + currentHelpRequest.request_id, {
      method: 'PATCH',
      body: JSON.stringify({
        status: status,
        admin_notes: adminNotes || null
      })
    });

    showToast('Help request updated successfully', 'success');
    closeHelpDetailModal();
    loadHelpRequests(false);
  } catch (e) {
    console.error('Error updating help request:', e);
    showToast('Error: ' + (e.message || 'Failed to update'), 'error');
  }
}

// Help request filter button handlers
document.getElementById('helpFilterNew')?.addEventListener('click', () => {
  helpQuickFilter = 'new';
  document.querySelectorAll('.help-filter').forEach(b => b.classList.remove('active'));
  document.getElementById('helpFilterNew').classList.add('active');
  loadHelpRequests();
});

document.getElementById('helpFilterContacted')?.addEventListener('click', () => {
  helpQuickFilter = 'contacted';
  document.querySelectorAll('.help-filter').forEach(b => b.classList.remove('active'));
  document.getElementById('helpFilterContacted').classList.add('active');
  loadHelpRequests();
});

document.getElementById('helpFilterInProgress')?.addEventListener('click', () => {
  helpQuickFilter = 'in_progress';
  document.querySelectorAll('.help-filter').forEach(b => b.classList.remove('active'));
  document.getElementById('helpFilterInProgress').classList.add('active');
  loadHelpRequests();
});

document.getElementById('helpFilterArchived')?.addEventListener('click', () => {
  helpQuickFilter = 'archived';
  document.querySelectorAll('.help-filter').forEach(b => b.classList.remove('active'));
  document.getElementById('helpFilterArchived').classList.add('active');
  loadHelpRequests();
});

// Refresh button
document.getElementById('refreshHelpRequests')?.addEventListener('click', () => loadHelpRequests());

// Search input
const helpSearchInput = document.getElementById('helpSearch');
if (helpSearchInput) {
  helpSearchInput.addEventListener('input', debounce(() => {
    helpSearchQuery = helpSearchInput.value.trim();
    helpPagination.page = 0;
    renderHelpRequests();
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

