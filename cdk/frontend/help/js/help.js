(function() {
  'use strict';

  const form = document.getElementById('helpForm');
  const msgEl = document.getElementById('msg');
  const submitBtn = document.getElementById('submitBtn');
  const checkboxItems = document.querySelectorAll('.checkbox-item');
  const phoneInput = document.getElementById('phone');

  // Toggle selected class on checkbox items
  checkboxItems.forEach(item => {
    const checkbox = item.querySelector('input[type="checkbox"]');
    checkbox.addEventListener('change', () => {
      item.classList.toggle('selected', checkbox.checked);
    });
  });

  /**
   * Format phone number as user types
   * Supports US format: +1 (XXX) XXX-XXXX
   * Supports international: preserves + prefix and formats digits
   */
  function formatPhoneNumber(value) {
    // Remove all non-digit characters except +
    const hasPlus = value.startsWith('+');
    const digits = value.replace(/\D/g, '');

    if (digits.length === 0) return hasPlus ? '+' : '';

    // US/Canada number (10 or 11 digits starting with 1)
    if (digits.length <= 11 && (digits.length === 10 || (digits.length === 11 && digits.startsWith('1')))) {
      const normalizedDigits = digits.length === 11 ? digits : '1' + digits;
      const country = normalizedDigits.slice(0, 1);
      const area = normalizedDigits.slice(1, 4);
      const prefix = normalizedDigits.slice(4, 7);
      const line = normalizedDigits.slice(7, 11);

      if (normalizedDigits.length <= 1) return '+' + country;
      if (normalizedDigits.length <= 4) return '+' + country + ' (' + area;
      if (normalizedDigits.length <= 7) return '+' + country + ' (' + area + ') ' + prefix;
      return '+' + country + ' (' + area + ') ' + prefix + '-' + line;
    }

    // International number - just format with + and spaces every 3-4 digits
    if (hasPlus || digits.length > 10) {
      return '+' + digits.replace(/(\d{1,3})(?=\d)/g, '$1 ').trim();
    }

    // Partial US number being entered (less than 10 digits, no +)
    if (digits.length <= 3) return '(' + digits;
    if (digits.length <= 6) return '(' + digits.slice(0, 3) + ') ' + digits.slice(3);
    return '(' + digits.slice(0, 3) + ') ' + digits.slice(3, 6) + '-' + digits.slice(6, 10);
  }

  // Format phone as user types
  if (phoneInput) {
    phoneInput.addEventListener('input', (e) => {
      const cursorPos = e.target.selectionStart;
      const oldLength = e.target.value.length;
      const formatted = formatPhoneNumber(e.target.value);
      e.target.value = formatted;
      // Adjust cursor position after formatting
      const newLength = formatted.length;
      const diff = newLength - oldLength;
      e.target.setSelectionRange(cursorPos + diff, cursorPos + diff);
    });

    // Ensure proper format on blur
    phoneInput.addEventListener('blur', () => {
      phoneInput.value = formatPhoneNumber(phoneInput.value);
    });
  }

  function showMessage(text, type) {
    msgEl.textContent = text;
    msgEl.className = 'msg visible ' + type;
  }

  function hideMessage() {
    msgEl.className = 'msg';
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideMessage();

    // Get selected help types
    const helpTypes = Array.from(document.querySelectorAll('input[name="help_types"]:checked'))
      .map(cb => cb.value);

    if (helpTypes.length === 0) {
      showMessage('Please select at least one way you would like to help.', 'error');
      return;
    }

    const payload = {
      name: document.getElementById('name').value.trim(),
      email: document.getElementById('email').value.trim(),
      phone: document.getElementById('phone').value.trim(),
      linkedin_url: document.getElementById('linkedin').value.trim() || undefined,
      help_types: helpTypes,
      message: document.getElementById('message').value.trim(),
      // Include honeypot field
      website: document.getElementById('website').value,
    };

    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
      // Use VettIDConfig.apiUrl for API endpoint
      const apiUrl = window.VettIDConfig?.apiUrl || '';
      const response = await fetch(apiUrl + '/help-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        showMessage(data.message || 'Thank you! We will be in touch soon.', 'success');
        form.reset();
        // Clear selected state from checkboxes
        checkboxItems.forEach(item => item.classList.remove('selected'));
      } else {
        showMessage(data.message || 'Something went wrong. Please try again.', 'error');
      }
    } catch (err) {
      console.error('Submit error:', err);
      showMessage('Network error. Please check your connection and try again.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit';
    }
  });
})();
