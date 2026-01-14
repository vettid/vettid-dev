// VettID Auth Callback Page Script
// Handles magic link validation and PIN verification

// Load configuration from centralized config file
const USER_POOL_ID = window.VettIDConfig.member.userPoolId;
const CLIENT_ID = window.VettIDConfig.member.clientId;
const API_URL = window.VettIDConfig.apiUrl;

// Setup Cognito
const poolData = { UserPoolId: USER_POOL_ID, ClientId: CLIENT_ID };
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

// Store tokens securely:
// - Refresh token: stored as httpOnly cookie (protected from XSS, set by backend)
// - ID/Access tokens: stored in sessionStorage (cleared on tab close, more secure than localStorage)
// - Never store refresh token in JavaScript-accessible storage
async function saveTokens(idToken, accessToken, refreshToken) {
  try {
    const response = await fetch(API_URL + '/auth/token-exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // Required for httpOnly cookie to be set
      body: JSON.stringify({
        id_token: idToken,
        access_token: accessToken,
        refresh_token: refreshToken
      })
    });

    if (!response.ok) {
      console.error('[AUTH] Token exchange failed:', response.status);
      return false;
    }

    // Backend sets refresh_token as httpOnly cookie
    // Response body contains id_token and access_token for frontend use
    const data = await response.json();

    if (!data.success || !data.id_token || !data.access_token) {
      console.error('[AUTH] Invalid token exchange response');
      return false;
    }

    // Store short-lived tokens in sessionStorage (more secure than localStorage)
    // sessionStorage is cleared when the tab is closed
    // On page refresh within the same tab, these tokens persist
    sessionStorage.setItem('vettid_tokens', JSON.stringify({
      id_token: data.id_token,
      access_token: data.access_token,
      expires_at: Date.now() + (data.expires_in * 1000)
    }));

    // Also keep in localStorage for backward compatibility during transition
    // TODO: Remove this after confirming sessionStorage approach works
    localStorage.setItem('tokens', JSON.stringify({
      id_token: data.id_token,
      access_token: data.access_token
    }));

    return true;
  } catch (error) {
    console.error('[AUTH] Token exchange error:', error);
    return false;
  }
}

function showMessage(text, type) {
  const messageEl = document.getElementById('message');
  messageEl.textContent = text;
  messageEl.className = 'message ' + (type || '');

  if (type === 'error' || type === 'success') {
    document.getElementById('spinner').style.display = 'none';
  }
}

async function validateMagicLink() {
  // Get token and email from URL fragment (more secure than query params)
  // Fragment (#token=...&email=...) is not sent to server or logged
  const fragment = location.hash.substring(1); // Remove the '#'
  const params = new URLSearchParams(fragment);
  const token = params.get('token');
  const email = params.get('email');

  if (!token || !email) {
    showMessage('Invalid magic link. Redirecting to sign in...', 'error');
    window.location.href = '/signin';
    return;
  }

  // Clear URL fragment for security
  history.replaceState(null, '', location.pathname);

  try {
    const userData = { Username: email, Pool: userPool };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');

    // Start auth flow to get the challenge
    const authDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username: email
    });

    cognitoUser.initiateAuth(authDetails, {
      onSuccess: async (result) => {
        // Shouldn't happen on first call, but handle it
        const saved = await saveTokens(
          result.getIdToken().getJwtToken(),
          result.getAccessToken().getJwtToken(),
          result.getRefreshToken().getToken()
        );
        if (saved) {
          window.location.href = '/account';
        } else {
          showMessage('Failed to save authentication. Please try again.', 'error');
          setTimeout(() => { window.location.href = '/signin'; }, 2000);
        }
      },
      onFailure: (err) => {
        console.error('[AUTH] Auth failed:', err);
        showMessage('Authentication failed: ' + (err.message || 'Invalid or expired link'), 'error');
        setTimeout(() => { window.location.href = '/signin'; }, 2000);
      },
      customChallenge: (challengeParameters) => {
        // We got the challenge, check if PIN is required
        const pinRequired = challengeParameters.pinRequired === 'true';

        // If PIN is not required, auto-submit without prompting
        if (!pinRequired) {
          cognitoUser.sendCustomChallengeAnswer(token, {
            onSuccess: async (result) => {
              const saved = await saveTokens(
                result.getIdToken().getJwtToken(),
                result.getAccessToken().getJwtToken(),
                result.getRefreshToken().getToken()
              );
              if (saved) {
                window.location.href = '/account';
              } else {
                showMessage('Failed to save authentication. Please try again.', 'error');
                setTimeout(() => { window.location.href = '/signin'; }, 2000);
              }
            },
            onFailure: (err) => {
              console.error('[AUTH] Auth failed after auto-submit:', err);
              showMessage('Authentication failed: ' + (err.message || 'Unknown error'), 'error');
              setTimeout(() => { window.location.href = '/signin'; }, 2000);
            }
          });
          return;
        }

        // PIN is required - show PIN prompt
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('message').textContent = 'Magic link verified! Please enter your PIN.';
        document.getElementById('pinPrompt').classList.add('show');
        document.getElementById('skipPinBtn').style.display = 'none';
        document.getElementById('pinInput').required = true;
        document.getElementById('pinInput').focus();

        // Function to submit challenge answer
        function submitChallengeAnswer(answerValue) {
          // Hide PIN prompt, show spinner
          document.getElementById('pinPrompt').classList.remove('show');
          document.getElementById('spinner').style.display = 'block';
          showMessage('Authenticating...');

          cognitoUser.sendCustomChallengeAnswer(answerValue, {
            onSuccess: async (result) => {
              const saved = await saveTokens(
                result.getIdToken().getJwtToken(),
                result.getAccessToken().getJwtToken(),
                result.getRefreshToken().getToken()
              );
              if (saved) {
                // Mark PIN as verified for this session so account page doesn't prompt again
                if (pinRequired) {
                  sessionStorage.setItem('pinVerified', 'true');
                }
                window.location.href = '/account';
              } else {
                showMessage('Failed to save authentication. Please try again.', 'error');
                setTimeout(() => { window.location.href = '/signin'; }, 2000);
              }
            },
            onFailure: (err) => {
              console.error('[AUTH] Challenge answer failed:', err);
              let errorMsg = 'Authentication failed: ';
              if (err.message && err.message.includes('Pin')) {
                errorMsg = 'Invalid PIN. Please try again with a new magic link.';
              } else {
                errorMsg += (err.message || 'Invalid or expired link');
              }
              showMessage(errorMsg, 'error');
              setTimeout(() => { window.location.href = '/signin'; }, 2000);
            },
            customChallenge: () => {
              console.error('[AUTH] Unexpected additional challenge');
              showMessage('Authentication failed. Please try again.', 'error');
              setTimeout(() => { window.location.href = '/signin'; }, 2000);
            }
          });
        }

        // Handle PIN submission
        document.getElementById('submitPinBtn').onclick = () => {
          // Sanitize PIN: strip all non-digit characters (handles invisible chars, whitespace, etc.)
          const rawPin = document.getElementById('pinInput').value;
          const pin = rawPin.replace(/\D/g, '');

          // If PIN is required, validate it's entered
          if (pinRequired && !pin) {
            alert('PIN is required for your account. Please enter your PIN.');
            return;
          }

          if (pin) {
            // Send token:pin format
            submitChallengeAnswer(token + ':' + pin);
          } else {
            // No PIN entered, just send token
            submitChallengeAnswer(token);
          }
        };

        // Handle skip PIN button
        document.getElementById('skipPinBtn').onclick = () => {
          submitChallengeAnswer(token);
        };

        // Allow Enter key to submit
        document.getElementById('pinInput').onkeypress = (e) => {
          if (e.key === 'Enter') {
            document.getElementById('submitPinBtn').click();
          }
        };
      }
    });

  } catch (error) {
    console.error('[AUTH] Unexpected error:', error);
    showMessage('An error occurred. Redirecting...', 'error');
    setTimeout(() => { window.location.href = '/signin'; }, 2000);
  }
}

// Start validation immediately
validateMagicLink();
