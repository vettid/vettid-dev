// VettID Sign In Page Script
// Handles magic link authentication flow

// ====== CONFIG ======
// Load configuration from centralized config file
const USER_POOL_ID = window.VettIDConfig.member.userPoolId;
const CLIENT_ID = window.VettIDConfig.member.clientId;
const AWS_REGION = window.VettIDConfig.region;
// ====================

// Setup Cognito
const poolData = { UserPoolId: USER_POOL_ID, ClientId: CLIENT_ID };
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

// Note: With httpOnly cookies, we can't check token presence in JavaScript
// Users will be redirected to signin from account page if session is invalid
// Clear any legacy localStorage tokens (migration to httpOnly cookies)
localStorage.removeItem('tokens');

// ---- JWT helpers ----
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  return atob(str + '='.repeat(pad));
}
function parseJwt(idt) {
  try {
    const [h, p, s] = idt.split('.');
    return { header: JSON.parse(b64urlDecode(h)), payload: JSON.parse(b64urlDecode(p)), signature: s };
  } catch { return { header: {}, payload: {}, signature: '' }; }
}

// ---- UI helpers ----
function showStatus(message, type) {
  const statusDiv = document.getElementById('loginStatus');
  statusDiv.textContent = message;
  statusDiv.className = type;
}

// ---- Magic link authentication ----
async function sendMagicLink(e) {
  e.preventDefault();

  const email = document.getElementById('emailInput').value.trim();
  if (!email) {
    showStatus('Please enter your email address', 'error');
    return;
  }

  const sendBtn = document.getElementById('sendLinkBtn');
  sendBtn.disabled = true;
  showStatus('Sending magic link...', 'info');

  const authDetails = new AmazonCognitoIdentity.AuthenticationDetails({
    Username: email
  });

  const userData = { Username: email, Pool: userPool };
  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

  cognitoUser.setAuthenticationFlowType('CUSTOM_AUTH');

  cognitoUser.initiateAuth(authDetails, {
    onSuccess: (result) => {
      // Unexpected - magic link flow should go through customChallenge
    },
    onFailure: (err) => {
      console.error('Auth error:', err);
      showStatus('Error: ' + (err.message || 'Failed to send magic link'), 'error');
      sendBtn.disabled = false;
    },
    customChallenge: (challengeParameters) => {
      // Magic link email sent
      localStorage.setItem('authEmail', email);
      showStatus('Magic link sent! Check your email and click the link to sign in.', 'success');
      sendBtn.disabled = false;
    }
  });
}

// Event listeners
document.getElementById('signinForm').addEventListener('submit', sendMagicLink);
