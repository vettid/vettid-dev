// VettID Registration Page Script
// Handles invite registration and waitlist signup

// Load configuration from centralized config file
const API = window.VettIDConfig.apiUrl;

// Tab switching function
function switchTab(tabName, clickedTab) {
  // Update tab buttons
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(tab => tab.classList.remove('active'));
  clickedTab.classList.add('active');

  // Update tab content
  document.getElementById('inviteTab').classList.remove('active');
  document.getElementById('waitlistTab').classList.remove('active');

  if (tabName === 'invite') {
    document.getElementById('inviteTab').classList.add('active');
  } else {
    document.getElementById('waitlistTab').classList.add('active');
  }
}

// Set up tab event listeners
document.querySelectorAll('.tab[data-tab]').forEach(tab => {
  tab.addEventListener('click', () => {
    switchTab(tab.dataset.tab, tab);
  });
});

// Check for #waitlist hash in URL and switch to waitlist tab
if (window.location.hash === '#waitlist') {
  const waitlistTab = document.querySelector('.tab[data-tab="waitlist"]');
  if (waitlistTab) {
    switchTab('waitlist', waitlistTab);
  }
}

const form = document.getElementById('regForm');
const msgEl = document.getElementById('msg');
const firstEl = document.getElementById('first');
const lastEl = document.getElementById('last');
const emailEl = document.getElementById('email');
const codeEl = document.getElementById('code');
const emailConsentEl = document.getElementById('emailConsent');

// Set custom validation message for email consent checkbox
emailConsentEl.addEventListener('invalid', function() {
  this.setCustomValidity('You must agree to accept emails from VettID in order to proceed');
});
emailConsentEl.addEventListener('change', function() {
  this.setCustomValidity('');
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Disable submit button to prevent duplicate submissions
  const submitBtn = form.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Submitting...';
  submitBtn.style.opacity = '0.7';

  msgEl.textContent = "Submitting...";
  msgEl.classList.remove('error');
  const payload = {
    first_name: firstEl.value.trim(),
    last_name: lastEl.value.trim(),
    email: emailEl.value.trim(),
    invite_code: codeEl.value.trim(),
    email_consent: emailConsentEl.checked
  };
  try {
    const res = await fetch(API + "/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    let bodyText = await res.text();
    let data;
    try {
      data = bodyText ? JSON.parse(bodyText) : {};
    } catch {
      data = { raw: bodyText };
    }

    if (!res.ok) {
      const message = data.message || data.error || bodyText || "Registration failed";
      msgEl.textContent = "Error: " + message + " (HTTP " + res.status + ")";
      msgEl.classList.add('error');
      // Re-enable submit button on error
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit';
      submitBtn.style.opacity = '1';
    } else {
      const message = data.message || "Registration submitted. Please check your email after admin approval.";
      // Clear previous content
      msgEl.textContent = '';
      msgEl.style.background = '#050505';

      // Container for main message
      const mainMessage = document.createElement('div');

      // Safely parse and create links without using innerHTML (XSS prevention)
      const urlRegex = /(https?:\/\/[^\s]+)/g;
      const parts = message.split(urlRegex);

      parts.forEach((part, index) => {
        if (index % 2 === 0) {
          // Text part - use textContent for safety
          if (part) mainMessage.appendChild(document.createTextNode(part));
        } else {
          // URL part - create anchor element programmatically
          const link = document.createElement('a');
          link.href = part;
          link.textContent = part;
          link.style.color = 'var(--accent)';
          link.style.textDecoration = 'underline';
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          mainMessage.appendChild(link);
        }
      });

      msgEl.appendChild(mainMessage);

      // Show prominent verification notice if email verification was sent
      if (data.email_verification_sent) {
        const verifyNotice = document.createElement('div');
        verifyNotice.style.background = 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)';
        verifyNotice.style.color = '#fff';
        verifyNotice.style.padding = '20px';
        verifyNotice.style.borderRadius = '8px';
        verifyNotice.style.marginTop = '16px';
        verifyNotice.style.fontSize = '1rem';
        verifyNotice.style.border = '2px solid #ffc125';
        verifyNotice.style.boxShadow = '0 4px 12px rgba(255, 193, 37, 0.3)';
        verifyNotice.style.lineHeight = '1.6';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.alignItems = 'center';
        header.style.gap = '12px';
        header.style.marginBottom = '12px';

        const icon = document.createElement('span');
        icon.style.fontSize = '1.5rem';
        icon.textContent = '\u{1F4E7}'; // Email emoji
        header.appendChild(icon);

        const title = document.createElement('strong');
        title.style.color = '#ffc125';
        title.style.fontSize = '1.1rem';
        title.textContent = 'Email Verification Required';
        header.appendChild(title);

        verifyNotice.appendChild(header);

        const p1 = document.createElement('p');
        p1.style.margin = '0 0 12px 0';
        p1.textContent = 'Check your inbox for a verification email from ';
        const awsStrong = document.createElement('strong');
        awsStrong.style.color = '#ffc125';
        awsStrong.textContent = 'Amazon Web Services';
        p1.appendChild(awsStrong);
        p1.appendChild(document.createTextNode(' and click the link to confirm your email address.'));
        verifyNotice.appendChild(p1);

        const p2 = document.createElement('p');
        p2.style.margin = '0';
        p2.style.color = '#ccc';
        p2.style.fontSize = '0.9rem';
        p2.textContent = 'This step is required to receive future communications from VettID. The email may take a few minutes to arrive.';
        verifyNotice.appendChild(p2);

        msgEl.appendChild(verifyNotice);
      }

      // Scroll message into view on mobile
      msgEl.scrollIntoView({ behavior: 'smooth', block: 'center' });

      form.reset();
      // Re-enable submit button after successful submission
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit';
      submitBtn.style.opacity = '1';
    }
  } catch (err) {
    msgEl.textContent = "Network or server error: " + (err.message || err);
    msgEl.classList.add('error');
    // Re-enable submit button on error
    submitBtn.disabled = false;
    submitBtn.textContent = 'Submit';
    submitBtn.style.opacity = '1';
  }
});

// Set custom validation message for waitlist email consent checkbox
const waitlistEmailConsent = document.getElementById('waitlistEmailConsent');
waitlistEmailConsent.addEventListener('invalid', function() {
  this.setCustomValidity('You must agree to accept emails from VettID in order to proceed');
});
waitlistEmailConsent.addEventListener('change', function() {
  this.setCustomValidity('');
});

// Waitlist form submission
document.getElementById('waitlistForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  // Disable submit button to prevent duplicate submissions
  const waitlistForm = document.getElementById('waitlistForm');
  const waitlistSubmitBtn = waitlistForm.querySelector('button[type="submit"]');
  waitlistSubmitBtn.disabled = true;
  waitlistSubmitBtn.textContent = 'Submitting...';
  waitlistSubmitBtn.style.opacity = '0.7';

  const messageEl = document.getElementById('waitlistMessage');
  messageEl.textContent = 'Submitting...';
  messageEl.classList.remove('error');

  const payload = {
    first_name: document.getElementById('waitlistFirst').value.trim(),
    last_name: document.getElementById('waitlistLast').value.trim(),
    email: document.getElementById('waitlistEmail').value.trim(),
    email_consent: document.getElementById('waitlistEmailConsent').checked
  };

  try {
    const res = await fetch(API + '/waitlist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (!res.ok) {
      messageEl.textContent = 'Error: ' + (data.message || 'Failed to join waitlist');
      messageEl.classList.add('error');
      // Re-enable submit button on error
      waitlistSubmitBtn.disabled = false;
      waitlistSubmitBtn.textContent = 'Join Wait List';
      waitlistSubmitBtn.style.opacity = '1';
    } else {
      // Clear previous content
      messageEl.textContent = '';
      messageEl.style.background = '#050505';

      // Container for main message
      const mainMessage = document.createElement('div');
      mainMessage.textContent = 'Successfully joined the wait list!';
      mainMessage.style.fontWeight = '600';
      mainMessage.style.marginBottom = '8px';
      messageEl.appendChild(mainMessage);

      // Show verification notice if email verification was sent
      if (data.email_verification_sent) {
        const verifyNotice = document.createElement('div');
        verifyNotice.style.background = 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)';
        verifyNotice.style.color = '#fff';
        verifyNotice.style.padding = '16px';
        verifyNotice.style.borderRadius = '8px';
        verifyNotice.style.marginTop = '12px';
        verifyNotice.style.fontSize = '0.95rem';
        verifyNotice.style.border = '2px solid #ffc125';
        verifyNotice.style.boxShadow = '0 4px 12px rgba(255, 193, 37, 0.3)';
        verifyNotice.style.lineHeight = '1.5';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.alignItems = 'center';
        header.style.gap = '10px';
        header.style.marginBottom = '10px';

        const icon = document.createElement('span');
        icon.style.fontSize = '1.3rem';
        icon.textContent = '\u{1F4E7}'; // Email emoji
        header.appendChild(icon);

        const title = document.createElement('strong');
        title.style.color = '#ffc125';
        title.textContent = 'Email Verification Required';
        header.appendChild(title);

        verifyNotice.appendChild(header);

        const p = document.createElement('p');
        p.style.margin = '0';
        p.textContent = 'Check your inbox for a verification email from ';
        const awsStrong = document.createElement('strong');
        awsStrong.style.color = '#ffc125';
        awsStrong.textContent = 'Amazon Web Services';
        p.appendChild(awsStrong);
        p.appendChild(document.createTextNode(' and click the link to confirm your email address.'));
        verifyNotice.appendChild(p);

        messageEl.appendChild(verifyNotice);
      }

      // Scroll message into view on mobile
      messageEl.scrollIntoView({ behavior: 'smooth', block: 'center' });

      document.getElementById('waitlistForm').reset();
      // Re-enable submit button after success
      waitlistSubmitBtn.disabled = false;
      waitlistSubmitBtn.textContent = 'Join Wait List';
      waitlistSubmitBtn.style.opacity = '1';
    }
  } catch (err) {
    messageEl.textContent = 'Network error: ' + err.message;
    messageEl.classList.add('error');
    // Re-enable submit button on error
    waitlistSubmitBtn.disabled = false;
    waitlistSubmitBtn.textContent = 'Join Wait List';
    waitlistSubmitBtn.style.opacity = '1';
  }
});
