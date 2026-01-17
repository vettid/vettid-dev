(function() {
  'use strict';

  const form = document.getElementById('helpForm');
  const msgEl = document.getElementById('msg');
  const submitBtn = document.getElementById('submitBtn');
  const checkboxItems = document.querySelectorAll('.checkbox-item');

  // Toggle selected class on checkbox items
  checkboxItems.forEach(item => {
    const checkbox = item.querySelector('input[type="checkbox"]');
    checkbox.addEventListener('change', () => {
      item.classList.toggle('selected', checkbox.checked);
    });
  });

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
