// VettID Sign Out Page Script
// Handles clearing authentication data and redirecting

// Load configuration from centralized config file
const USER_POOL_ID = window.VettIDConfig.member.userPoolId;
const CLIENT_ID = window.VettIDConfig.member.clientId;
const API_URL = window.VettIDConfig.apiUrl;

// Clear httpOnly cookies via backend API
async function clearHttpOnlyCookies() {
  try {
    await fetch(API_URL + '/auth/token-clear', {
      method: 'POST',
      credentials: 'include' // Include cookies so they can be cleared
    });
  } catch (error) {
    console.error('Failed to clear cookies:', error);
  }
}

// Clear all authentication data
function clearAllAuthData() {
  // Clear any legacy localStorage tokens
  localStorage.removeItem('tokens');
  localStorage.removeItem('authEmail');

  // Clear any Cognito SDK data
  localStorage.removeItem('CognitoIdentityServiceProvider.' + CLIENT_ID + '.LastAuthUser');

  // Clear all keys that might be related to Cognito
  const keysToRemove = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith('CognitoIdentityServiceProvider')) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach(key => localStorage.removeItem(key));

  // Clear session storage as well
  sessionStorage.clear();
}

// Perform sign out
async function signOut() {
  try {
    // Clear httpOnly cookies (tokens)
    await clearHttpOnlyCookies();

    // Clear any remaining localStorage/sessionStorage data
    clearAllAuthData();

    // Show success message
    document.getElementById('message').textContent = 'Successfully signed out';

    // Wait a moment, then redirect
    setTimeout(() => {
      window.location.href = '/signin';
    }, 1000);
  } catch (error) {
    console.error('Sign out error:', error);
    document.getElementById('message').textContent = 'Signed out (with errors)';
    setTimeout(() => {
      window.location.href = '/signin';
    }, 1000);
  }
}

// Execute sign out immediately
signOut();
