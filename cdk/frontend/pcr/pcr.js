(function() {
  'use strict';

  // PCR manifest endpoint - served from CloudFront
  var PCR_ENDPOINT = 'https://pcr-manifest.vettid.dev/pcr-manifest.json';

  // DOM elements
  var statusDot = document.getElementById('status-dot');
  var statusText = document.getElementById('status-text');
  var currentPcrValues = document.getElementById('current-pcr-values');
  var currentVersion = document.getElementById('current-version');
  var currentUpdated = document.getElementById('current-updated');
  var previousVersionsContainer = document.getElementById('previous-versions-container');
  var lastRefresh = document.getElementById('last-refresh');

  // Maximum number of previous versions to show (plus current = 4 total)
  var MAX_PREVIOUS_VERSIONS = 3;

  // Validate PCR value format (96 hex characters)
  function isValidPcr(value) {
    return typeof value === 'string' && /^[a-fA-F0-9]{96}$/.test(value);
  }

  // Format date for display
  function formatDate(dateString) {
    if (!dateString) return '--';
    try {
      var date = new Date(dateString);
      if (isNaN(date.getTime())) return '--';
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short'
      });
    } catch (e) {
      return '--';
    }
  }

  // Create PCR row using safe DOM methods
  function createPcrRow(label, value) {
    // Validate the value
    if (!isValidPcr(value)) {
      value = 'Invalid PCR value';
    }

    var row = document.createElement('div');
    row.className = 'pcr-row';

    var labelDiv = document.createElement('div');
    labelDiv.className = 'pcr-label';
    labelDiv.textContent = label;

    var valueDiv = document.createElement('div');
    valueDiv.className = 'pcr-value';

    var code = document.createElement('code');
    code.textContent = value;

    var copyHint = document.createElement('span');
    copyHint.className = 'copy-hint';
    copyHint.textContent = 'Click to copy';

    valueDiv.appendChild(code);
    valueDiv.appendChild(copyHint);

    // Add click to copy (only if valid PCR)
    if (isValidPcr(value)) {
      valueDiv.addEventListener('click', async function() {
        try {
          await navigator.clipboard.writeText(value);
          valueDiv.classList.add('copied');
          copyHint.textContent = 'Copied!';
          setTimeout(function() {
            valueDiv.classList.remove('copied');
            copyHint.textContent = 'Click to copy';
          }, 2000);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      });
    }

    row.appendChild(labelDiv);
    row.appendChild(valueDiv);

    return row;
  }

  // Helper to create a labeled value element (e.g., "Version: <strong>v1</strong>")
  function createLabeledValue(label, value) {
    var div = document.createElement('div');
    var labelText = document.createTextNode(label + ': ');
    var strong = document.createElement('strong');
    strong.textContent = value;
    div.appendChild(labelText);
    div.appendChild(strong);
    return div;
  }

  // Create a PCR card element for a version
  function createPcrCard(pcrSet, isCurrent) {
    var card = document.createElement('div');
    card.className = 'pcr-card' + (isCurrent ? '' : ' previous');

    var header = document.createElement('div');
    header.className = 'pcr-card-header';

    var titleDiv = document.createElement('div');
    titleDiv.className = 'pcr-card-title';

    var h2 = document.createElement('h2');
    h2.textContent = isCurrent ? 'Current PCR Values' : 'Previous Version';

    var badge = document.createElement('span');
    badge.className = 'badge ' + (isCurrent ? 'badge-current' : 'badge-previous');
    badge.textContent = isCurrent ? 'Active' : (pcrSet.valid_until ? 'Transition' : 'Historical');

    titleDiv.appendChild(h2);
    titleDiv.appendChild(badge);

    var metaDiv = document.createElement('div');
    metaDiv.className = 'pcr-meta';

    metaDiv.appendChild(createLabeledValue('Version', pcrSet.id || '--'));

    if (isCurrent) {
      metaDiv.appendChild(createLabeledValue('Updated', formatDate(pcrSet.valid_from)));
    } else if (pcrSet.valid_until) {
      metaDiv.appendChild(createLabeledValue('Valid until', formatDate(pcrSet.valid_until)));
    } else {
      metaDiv.appendChild(createLabeledValue('Valid from', formatDate(pcrSet.valid_from)));
    }

    header.appendChild(titleDiv);
    header.appendChild(metaDiv);

    var valuesDiv = document.createElement('div');
    valuesDiv.className = 'pcr-values';
    valuesDiv.appendChild(createPcrRow('PCR0', pcrSet.pcr0));
    valuesDiv.appendChild(createPcrRow('PCR1', pcrSet.pcr1));
    valuesDiv.appendChild(createPcrRow('PCR2', pcrSet.pcr2));

    card.appendChild(header);
    card.appendChild(valuesDiv);

    return card;
  }

  // Clear and render PCR values using safe DOM methods
  function renderPcrs(pcrSets) {
    if (!Array.isArray(pcrSets)) {
      throw new Error('Invalid PCR data format');
    }

    // Find current version
    var current = pcrSets.find(function(p) { return p.is_current; });

    if (!current) {
      throw new Error('No current PCR set found');
    }

    // Sort non-current versions by valid_from date (newest first)
    var previousVersions = pcrSets
      .filter(function(p) { return !p.is_current; })
      .sort(function(a, b) {
        var dateA = new Date(a.valid_from || 0).getTime();
        var dateB = new Date(b.valid_from || 0).getTime();
        return dateB - dateA; // Newest first
      })
      .slice(0, MAX_PREVIOUS_VERSIONS);

    // Clear and render current PCRs
    while (currentPcrValues.firstChild) {
      currentPcrValues.removeChild(currentPcrValues.firstChild);
    }
    currentPcrValues.appendChild(createPcrRow('PCR0', current.pcr0));
    currentPcrValues.appendChild(createPcrRow('PCR1', current.pcr1));
    currentPcrValues.appendChild(createPcrRow('PCR2', current.pcr2));
    currentVersion.textContent = String(current.id || '--');
    currentUpdated.textContent = formatDate(current.valid_from);

    // Clear and render previous versions
    while (previousVersionsContainer.firstChild) {
      previousVersionsContainer.removeChild(previousVersionsContainer.firstChild);
    }

    previousVersions.forEach(function(pcrSet) {
      previousVersionsContainer.appendChild(createPcrCard(pcrSet, false));
    });
  }

  // Show error state using safe DOM methods
  function showError(message) {
    while (currentPcrValues.firstChild) {
      currentPcrValues.removeChild(currentPcrValues.firstChild);
    }

    var errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';

    var mainText = document.createElement('span');
    mainText.textContent = 'Unable to fetch PCR values. Please try again later.';

    var br = document.createElement('br');

    var smallText = document.createElement('small');
    smallText.textContent = message;

    errorDiv.appendChild(mainText);
    errorDiv.appendChild(br);
    errorDiv.appendChild(smallText);

    currentPcrValues.appendChild(errorDiv);
  }

  // Update status
  function setStatus(status, message) {
    statusDot.className = 'status-dot ' + status;
    statusText.textContent = message;
  }

  // Fetch PCRs
  async function fetchPcrs() {
    try {
      setStatus('loading', 'Fetching PCR values...');

      var response = await fetch(PCR_ENDPOINT, {
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('HTTP ' + response.status + ': ' + response.statusText);
      }

      var data = await response.json();

      if (!data.pcr_sets || data.pcr_sets.length === 0) {
        throw new Error('No PCR sets in response');
      }

      renderPcrs(data.pcr_sets);
      setStatus('', 'PCR values verified and up to date');
      lastRefresh.textContent = new Date().toLocaleTimeString();

    } catch (error) {
      console.error('Failed to fetch PCRs:', error);
      setStatus('error', 'Failed to load PCR values');
      showError(error.message);
    }
  }

  // Generate QR code
  function generateQrCode() {
    var qrContainer = document.getElementById('qr-code');
    if (typeof QRCode !== 'undefined') {
      try {
        // Clear any existing content
        while (qrContainer.firstChild) {
          qrContainer.removeChild(qrContainer.firstChild);
        }
        // Use the self-hosted QRCode library constructor API
        new QRCode(qrContainer, {
          text: 'https://vettid.dev/pcr',
          width: 150,
          height: 150,
          colorDark: '#000000',
          colorLight: '#ffffff',
          correctLevel: QRCode.CorrectLevel.H
        });
      } catch (error) {
        console.error('QR code error:', error);
        var errorText = document.createElement('p');
        errorText.style.color = 'var(--text-subtle)';
        errorText.textContent = 'QR code unavailable';
        while (qrContainer.firstChild) {
          qrContainer.removeChild(qrContainer.firstChild);
        }
        qrContainer.appendChild(errorText);
      }
    }
  }

  // Initialize
  function init() {
    fetchPcrs();
    generateQrCode();

    // Auto-refresh every 5 minutes
    setInterval(fetchPcrs, 5 * 60 * 1000);
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
