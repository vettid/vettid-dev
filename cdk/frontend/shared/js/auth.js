// VettID Auth Callback Page Script
// Handles magic link validation and PIN verification

// Load configuration from centralized config file
const USER_POOL_ID = window.VettIDConfig.member.userPoolId;
const CLIENT_ID = window.VettIDConfig.member.clientId;
const API_URL = window.VettIDConfig.apiUrl;

// Setup Cognito
const poolData = { UserPoolId: USER_POOL_ID, ClientId: CLIENT_ID };
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

// Store tokens in httpOnly cookies via backend API
// This protects tokens from XSS attacks - they're never accessible to JavaScript
async function saveTokens(idToken, accessToken, refreshToken) {
  try {
    const response = await fetch(API_URL + '/auth/token-exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // Include cookies in request/response
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

    // Clear any legacy localStorage tokens
    localStorage.removeItem('tokens');
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
          const pin = document.getElementById('pinInput').value.trim();

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
