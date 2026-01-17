(function() {
  'use strict';

  // Bitcoin address - replace 'PLACEHOLDER' with actual address
  var BTC_ADDRESS = 'PLACEHOLDER';

  var placeholder = document.getElementById('placeholder');
  var qrContainer = document.getElementById('qr-container');
  var addressDisplay = document.getElementById('address-display');
  var btcAddressEl = document.getElementById('btcAddress');
  var addressBox = document.getElementById('addressBox');
  var copyHint = document.getElementById('copyHint');

  // Check if we have a real address
  if (BTC_ADDRESS && BTC_ADDRESS !== 'PLACEHOLDER' && BTC_ADDRESS.length > 20) {
    // Show address elements
    placeholder.style.display = 'none';
    qrContainer.style.display = 'inline-block';
    addressDisplay.style.display = 'block';
    btcAddressEl.textContent = BTC_ADDRESS;

    // Generate QR code
    if (typeof QRCode !== 'undefined') {
      new QRCode(document.getElementById('qr-code'), {
        text: 'bitcoin:' + BTC_ADDRESS,
        width: 180,
        height: 180,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }
  }

  // Copy address function
  window.copyAddress = function() {
    if (!BTC_ADDRESS || BTC_ADDRESS === 'PLACEHOLDER') return;

    navigator.clipboard.writeText(BTC_ADDRESS).then(function() {
      addressBox.classList.add('copied');
      copyHint.textContent = 'Copied!';

      setTimeout(function() {
        addressBox.classList.remove('copied');
        copyHint.textContent = 'Click to copy';
      }, 2000);
    }).catch(function(err) {
      // Fallback for older browsers
      var textArea = document.createElement('textarea');
      textArea.value = BTC_ADDRESS;
      textArea.style.position = 'fixed';
      textArea.style.left = '-9999px';
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        addressBox.classList.add('copied');
        copyHint.textContent = 'Copied!';
        setTimeout(function() {
          addressBox.classList.remove('copied');
          copyHint.textContent = 'Click to copy';
        }, 2000);
      } catch (e) {
        console.error('Copy failed:', e);
      }
      document.body.removeChild(textArea);
    });
  };
})();
