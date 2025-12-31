// Security: HTML escape function to prevent XSS
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Security: Validate URL to prevent open redirect and javascript: attacks
function validateUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    // Only allow https protocol
    if (parsed.protocol !== 'https:') return '';
    // Only allow trusted domains (S3, CloudFront, vettid.dev)
    const trustedDomains = ['amazonaws.com', 'cloudfront.net', 'vettid.dev'];
    if (!trustedDomains.some(domain => parsed.hostname.endsWith(domain))) return '';
    return url;
  } catch {
    return '';
  }
}

// Theme management
function initTheme() {
  const savedTheme = localStorage.getItem('vettid-theme') || 'dark';
  const root = document.documentElement;
  const themeIcon = document.getElementById('themeIcon');
  if (savedTheme === 'light') {
    root.setAttribute('data-theme', 'light');
    if (themeIcon) themeIcon.innerHTML = '&#127769;'; // Moon
  } else {
    root.removeAttribute('data-theme');
    if (themeIcon) themeIcon.innerHTML = '&#9728;&#65039;'; // Sun
  }
}

function toggleTheme() {
  const root = document.documentElement;
  const themeIcon = document.getElementById('themeIcon');
  const currentTheme = root.getAttribute('data-theme');
  if (currentTheme === 'light') {
    root.removeAttribute('data-theme');
    localStorage.setItem('vettid-theme', 'dark');
    if (themeIcon) themeIcon.innerHTML = '&#9728;&#65039;'; // Sun
  } else {
    root.setAttribute('data-theme', 'light');
    localStorage.setItem('vettid-theme', 'light');
    if (themeIcon) themeIcon.innerHTML = '&#127769;'; // Moon
  }
}

// Initialize theme immediately
initTheme();

// Confirm Modal Functions
let confirmModalResolve = null;

function showConfirmModal(options = {}) {
  const modal = document.getElementById('confirmModal');
  const title = document.getElementById('confirmModalTitle');
  const message = document.getElementById('confirmModalMessage');
  const cancelBtn = document.getElementById('confirmModalCancel');
  const confirmBtn = document.getElementById('confirmModalConfirm');

  title.textContent = options.title || 'Confirm Action';
  message.innerHTML = options.message || 'Are you sure you want to proceed?';
  cancelBtn.textContent = options.cancelText || 'Cancel';
  confirmBtn.textContent = options.confirmText || 'Confirm';

  // Set button color based on type
  if (options.type === 'danger') {
    confirmBtn.style.background = 'linear-gradient(135deg,#f44336 0%,#c62828 100%)';
  } else if (options.type === 'warning') {
    confirmBtn.style.background = 'linear-gradient(135deg,#ff9800 0%,#f57c00 100%)';
  } else {
    confirmBtn.style.background = 'linear-gradient(135deg,var(--accent) 0%,#ffc125 100%)';
    confirmBtn.style.color = '#000';
  }

  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';

  return new Promise((resolve) => {
    confirmModalResolve = resolve;
  });
}

function closeConfirmModal(result) {
  const modal = document.getElementById('confirmModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
  if (confirmModalResolve) {
    confirmModalResolve(result);
    confirmModalResolve = null;
  }
}

// Alert Modal Functions (for success/error messages)
let alertModalResolve = null;

function showAlertModal(options = {}) {
  const modal = document.getElementById('alertModal');
  const title = document.getElementById('alertModalTitle');
  const message = document.getElementById('alertModalMessage');
  const okBtn = document.getElementById('alertModalOk');

  // Set icon and title based on type
  let icon = '';
  let titleColor = 'var(--accent)';
  let borderColor = 'var(--accent)';

  if (options.type === 'success') {
    icon = '<svg width="24" height="24" fill="none" stroke="#4caf50" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
    titleColor = '#4caf50';
    borderColor = '#4caf50';
  } else if (options.type === 'error') {
    icon = '<svg width="24" height="24" fill="none" stroke="#f44336" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>';
    titleColor = '#f44336';
    borderColor = '#f44336';
  } else if (options.type === 'warning') {
    icon = '<svg width="24" height="24" fill="none" stroke="#ff9800" stroke-width="2"><path d="M12 2L2 22h20L12 2z"/><path d="M12 9v4M12 17h.01"/></svg>';
    titleColor = '#ff9800';
    borderColor = '#ff9800';
  } else {
    icon = '<svg width="24" height="24" fill="none" stroke="var(--accent)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>';
  }

  title.innerHTML = icon + '<span>' + (options.title || 'Notice') + '</span>';
  title.style.color = titleColor;
  message.innerHTML = options.message || '';
  okBtn.textContent = options.okText || 'OK';

  // Update border color
  modal.querySelector('div > div').style.borderColor = borderColor;

  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';

  return new Promise((resolve) => {
    alertModalResolve = resolve;
  });
}

function closeAlertModal() {
  const modal = document.getElementById('alertModal');
  modal.style.display = 'none';
  document.body.style.overflow = '';
  if (alertModalResolve) {
    alertModalResolve();
    alertModalResolve = null;
  }
}

// Setup confirm modal event listeners
document.addEventListener('DOMContentLoaded', () => {
  const cancelBtn = document.getElementById('confirmModalCancel');
  const confirmBtn = document.getElementById('confirmModalConfirm');
  const modal = document.getElementById('confirmModal');

  cancelBtn?.addEventListener('click', () => closeConfirmModal(false));
  confirmBtn?.addEventListener('click', () => closeConfirmModal(true));

  // Close on backdrop click
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) closeConfirmModal(false);
  });

  // Setup alert modal event listeners
  const alertOkBtn = document.getElementById('alertModalOk');
  const alertModal = document.getElementById('alertModal');

  alertOkBtn?.addEventListener('click', () => closeAlertModal());

  // Close on backdrop click
  alertModal?.addEventListener('click', (e) => {
    if (e.target === alertModal) closeAlertModal();
  });
});

// Subscription type state
let availableSubscriptionTypes = [];
let subscriptionStatus = null; // Global state for subscription status
let membershipStatus = null; // Global state for membership status
let pinStatusData = null; // Global state for PIN status (cached)
let vaultStatusData = null; // Global state for vault status (cached)
let votingHistoryData = null; // Global state for voting history (cached)

// Load subscription types
async function loadSubscriptionTypes() {
  const container = document.getElementById('subscriptionOptionsSection');

  try {
    const res = await fetch(API_URL + '/account/subscription-types', {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + idToken() }
    });

    if (!res.ok) {
      container.innerHTML = '<p class="muted" style="text-align:center;">Unable to load subscription options. Please try again later.</p>';
      return;
    }

    const data = await res.json();
    let subscriptionTypes = data.subscription_types || [];

    if (subscriptionTypes.length === 0) {
      container.innerHTML = '<p class="muted" style="text-align:center;">No subscription options are currently available.</p>';
      return;
    }

    // Filter out one-time offers that have already been used
    // Check subscription status for used one-time offers
    if (subscriptionStatus?.has_used_trial) {
      subscriptionTypes = subscriptionTypes.filter(st => {
        // If it's a one-time offer and user has used trial, filter it out
        // Assuming free trials are marked as one-time offers
        if (st.is_one_time_offer && parseFloat(st.price) === 0) {
          return false;
        }
        return true;
      });
    }

    // Sort: one-time offers first, then by price (free first, then ascending)
    subscriptionTypes.sort((a, b) => {
      if (a.is_one_time_offer && !b.is_one_time_offer) return -1;
      if (!a.is_one_time_offer && b.is_one_time_offer) return 1;
      const priceA = parseFloat(a.price) || 0;
      const priceB = parseFloat(b.price) || 0;
      return priceA - priceB;
    });

    availableSubscriptionTypes = subscriptionTypes;

    if (subscriptionTypes.length === 0) {
      container.innerHTML = '<p class="muted" style="text-align:center;">No subscription options are currently available.</p>';
      return;
    }

    container.innerHTML = '<div style="display:flex;flex-direction:column;gap:16px;">' + subscriptionTypes.map((st, index) => {
      const isFree = parseFloat(st.price) === 0;
      const priceDisplay = isFree
        ? '<div style="font-size:2rem;font-weight:700;color:#10b981;">FREE</div>'
        : `<div style="font-size:2rem;font-weight:700;color:var(--text);">${st.currency} ${parseFloat(st.price).toFixed(2)}</div>`;

      // Handle pluralization - remove trailing 's' for singular, keep for plural
      let termUnit = st.term_unit;
      if (st.term_value === 1 && termUnit.endsWith('s')) {
        termUnit = termUnit.slice(0, -1); // Remove trailing 's' for singular
      }
      const termDisplay = `${st.term_value} ${termUnit}`;
      const isPopular = index === 0; // First one is popular
      const borderColor = isPopular ? 'var(--accent)' : '#333';
      const boxShadow = isPopular ? '0 0 20px rgba(255,193,37,0.2)' : 'none';

      // Brighter button colors for all subscribe buttons
      let buttonBg;
      let buttonColor;
      if (isFree) {
        buttonBg = 'linear-gradient(135deg,#4caf50 0%,#2e7d32 100%)';
        buttonColor = '#fff';
      } else if (isPopular) {
        buttonBg = 'linear-gradient(135deg,var(--accent) 0%,#ffc125 100%)';
        buttonColor = '#000';
      } else {
        buttonBg = 'linear-gradient(135deg,#2196f3 0%,#1976d2 100%)';
        buttonColor = '#fff';
      }

      return `
        <div style="padding:20px;background:#050505;border-radius:8px;border:2px solid ${borderColor};box-shadow:${boxShadow};transition:all 0.2s;position:relative;display:flex;align-items:center;justify-content:space-between;gap:20px;">
          ${isPopular ? '<div style="position:absolute;top:-12px;left:20px;background:var(--accent);color:#000;padding:4px 12px;border-radius:12px;font-size:0.7rem;font-weight:700;text-transform:uppercase;">Popular</div>' : ''}

          <div style="flex:1;">
            <h4 style="margin:0 0 4px;color:${isPopular ? 'var(--accent)' : 'var(--text)'};font-size:1.2rem;">${st.name}</h4>
            <p style="color:var(--gray);font-size:0.85rem;margin:0 0 8px;">${st.description}</p>
            ${st.is_one_time_offer ? '<span style="display:inline-block;background:#fbbf24;color:#000;padding:3px 10px;border-radius:8px;font-size:0.7rem;font-weight:700;text-transform:uppercase;">One-Time Offer</span>' : ''}
          </div>

          <div style="text-align:center;min-width:120px;">
            ${priceDisplay}
            <div style="color:var(--gray);font-size:0.8rem;margin-top:2px;">${termDisplay}</div>
          </div>

          <button class="btn subscription-btn" id="sub-btn-${st.subscription_type_id}" data-subscription-id="${st.subscription_type_id}" onclick="selectSubscriptionType('${st.subscription_type_id}')" style="background:${buttonBg};color:${buttonColor};padding:12px 24px;font-size:0.95rem;font-weight:700;white-space:nowrap;">
            ${isFree ? 'Start Free' : 'Subscribe'}
          </button>
        </div>
      `;
    }).join('') + '</div>';
  } catch (err) {
    console.error('Error loading subscription types:', err);
    container.innerHTML = '<p class="muted" style="text-align:center;color:#f44336;">Failed to load subscription options. Please try again later.</p>';
  }
}

// Select and subscribe to a subscription type
async function selectSubscriptionType(subscriptionTypeId) {
  const btn = document.getElementById('sub-btn-' + subscriptionTypeId);
  if (!btn) return;

  // Store original button content
  const originalContent = btn.innerHTML;
  const originalStyle = btn.style.cssText;

  // Disable all subscription buttons and show loading on clicked button
  const allButtons = document.querySelectorAll('.subscription-btn');
  allButtons.forEach(b => {
    b.disabled = true;
    b.style.opacity = '0.6';
    b.style.cursor = 'not-allowed';
  });

  // Show processing state on clicked button
  btn.innerHTML = 'Processing...';
  btn.style.opacity = '1';

  try {
    await createSubscription(subscriptionTypeId);
  } finally {
    // Re-enable all buttons
    allButtons.forEach(b => {
      b.disabled = false;
      b.style.opacity = '1';
      b.style.cursor = 'pointer';
    });

    // Restore original content if button still exists
    if (document.getElementById('sub-btn-' + subscriptionTypeId)) {
      btn.innerHTML = originalContent;
      btn.style.cssText = originalStyle;
    }
  }
}
