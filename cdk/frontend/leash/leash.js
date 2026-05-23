// LEASH gamified demo — vettid.dev/leash
//
// Sandbox mode:
//   1. User picks scope tokens + duration, clicks "Mint LEASH".
//   2. Server mints a fresh LEASH for Demo Alice's agent (Ed25519
//      attestation key lives in Secrets Manager; pubkey published to
//      LeashAttestKeys so the public verifier resolves it normally).
//   3. The page generates an in-browser agent Ed25519 keypair (so the
//      LEASH can carry its pubkey for PoP).
//   4. User clicks attack buttons. Each one constructs a verify
//      envelope that demonstrates one specific failure mode, posts to
//      the verifier, and renders the rejection chain.
//
// Live mode:
//   - "Spawn live session" → POST /v1/public/leash/demo/session →
//     returns session_token + CLI hint.
//   - Page polls /v1/public/leash/demo/session/{token} every 2s.
//   - Tester runs `vettid-agent demo validate --session <token> ...`
//     against their real LEASH; verifier appends results to the
//     session row; page renders them as they arrive.
//
// Note: the agent Ed25519 keypair generated here lives only in memory
// for the page lifetime. It is NEVER persisted — refresh the page
// and you'll get a fresh key, but any LEASH minted against the old
// key will fail PoP. Acceptable for a demo.

const API = 'https://api.vettid.dev';

// Sandbox state
let currentLeash = null;       // { leash, jti, kid, issued_at, expires_at }
let currentClaims = null;      // decoded claims
let agentKeyPair = null;       // CryptoKeyPair (Ed25519)
let agentPubB64 = null;        // base64url of raw pubkey
let countdownTimer = null;

// Live state
let liveSession = null;        // { session_token, expires_at, poll_url, cli_hint }
let liveSeenResults = 0;
let livePollTimer = null;

const SCOPE_OPTIONS = [
  'profile.email:read',
  'profile.phone:read',
  'profile.name:read',
  'credential.sign:cred-demo-1',
  'wallet.balance:read',
  'message:send',
];

// =====================================================================
// Tab switching
// =====================================================================
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const mode = btn.dataset.mode;
    document.getElementById('sandboxMode').style.display = mode === 'sandbox' ? '' : 'none';
    document.getElementById('liveMode').style.display = mode === 'live' ? '' : 'none';
  });
});

// =====================================================================
// Sandbox: scope selector
// =====================================================================
function renderScopeGrid() {
  const grid = document.getElementById('scopeGrid');
  grid.innerHTML = '';
  SCOPE_OPTIONS.forEach((s, i) => {
    const id = `scope_${i}`;
    const label = document.createElement('label');
    label.className = 'scope-chip';
    const checked = i < 2; // pre-select the first two so the demo "works" on first click
    if (checked) label.classList.add('selected');
    label.innerHTML = `<input type="checkbox" id="${id}" value="${s}" ${checked ? 'checked' : ''}><span>${s}</span>`;
    label.querySelector('input').addEventListener('change', (e) => {
      label.classList.toggle('selected', e.target.checked);
    });
    grid.appendChild(label);
  });
}
renderScopeGrid();

function selectedScopes() {
  return Array.from(document.querySelectorAll('#scopeGrid input:checked')).map((i) => i.value);
}

// =====================================================================
// Agent keypair (in-memory, page lifetime)
// =====================================================================
async function ensureAgentKey() {
  if (agentKeyPair) return;
  agentKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = await crypto.subtle.exportKey('raw', agentKeyPair.publicKey);
  agentPubB64 = b64UrlEncode(new Uint8Array(raw));
}

// =====================================================================
// Mint LEASH
// =====================================================================
document.getElementById('mintBtn').addEventListener('click', async () => {
  const btn = document.getElementById('mintBtn');
  const err = document.getElementById('mintErr');
  err.style.display = 'none';
  const scope = selectedScopes();
  if (scope.length === 0) {
    showErr(err, 'Select at least one scope.');
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Minting…';
  try {
    await ensureAgentKey();
    const duration = parseInt(document.getElementById('durationSel').value, 10);
    const resp = await fetch(`${API}/v1/public/leash/demo/mint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope,
        agent_pubkey: agentPubB64,
        duration_secs: duration,
      }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      showErr(err, body.error || `HTTP ${resp.status}`);
      return;
    }
    currentLeash = body;
    currentClaims = decodeClaims(body.leash);
    showLeashPanel();
    clearResults();
    startCountdown(body.expires_at);
  } catch (e) {
    showErr(err, `Network error: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Mint LEASH for Demo Alice\'s agent';
  }
});

function showLeashPanel() {
  document.getElementById('leashPanel').style.display = '';
  document.getElementById('attackPanel').style.display = '';
  document.getElementById('resultsPanel').style.display = '';
  document.getElementById('jwtBlock').textContent = currentLeash.leash;
  const kv = document.getElementById('claimsKv');
  kv.innerHTML = '';
  const pairs = [
    ['Issuer (Demo Alice)', currentClaims.iss],
    ['Subject (her agent)', currentClaims.sub],
    ['Scopes', currentClaims['vettid:scope'].join(', ')],
    ['Grant version', currentClaims['vettid:grant_version']],
    ['Issued at', new Date(currentClaims.iat * 1000).toLocaleTimeString()],
    ['Expires at', new Date(currentClaims.exp * 1000).toLocaleTimeString()],
    ['Agent pubkey', truncate(currentClaims['vettid:agent_pubkey'], 32)],
    ['JTI', currentClaims.jti],
  ];
  for (const [k, v] of pairs) {
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd'); dd.textContent = String(v);
    kv.appendChild(dt); kv.appendChild(dd);
  }
}

// =====================================================================
// Countdown
// =====================================================================
function startCountdown(expiresAt) {
  if (countdownTimer) clearInterval(countdownTimer);
  const pill = document.getElementById('countdown');
  function tick() {
    const remaining = expiresAt - Math.floor(Date.now() / 1000);
    if (remaining <= 0) {
      pill.textContent = '⏱ EXPIRED';
      pill.className = 'countdown-pill expired';
      clearInterval(countdownTimer);
      countdownTimer = null;
      return;
    }
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    pill.textContent = `⏱ ${mins}:${String(secs).padStart(2, '0')} remaining`;
    pill.className = remaining < 15 ? 'countdown-pill warning' : 'countdown-pill';
  }
  tick();
  countdownTimer = setInterval(tick, 1000);
}

// =====================================================================
// Attack buttons
// =====================================================================
document.querySelectorAll('.attack').forEach((btn) => {
  btn.addEventListener('click', async () => {
    if (!currentLeash) return;
    btn.disabled = true;
    btn.style.opacity = 0.6;
    try {
      const attack = btn.dataset.attack;
      const label = btn.querySelector('.ax-label').textContent;
      const result = await runAttack(attack);
      renderResult(label, attack, result);
    } catch (e) {
      renderResult(btn.querySelector('.ax-label').textContent, btn.dataset.attack, { network_error: e.message });
    } finally {
      btn.disabled = false;
      btn.style.opacity = 1;
    }
  });
});

async function runAttack(name) {
  const grantedScope = currentClaims['vettid:scope'][0];
  switch (name) {
    case 'goodVerify':
      return await postVerify(currentLeash.leash, grantedScope, /*goodSig*/true);
    case 'widenScope': {
      // Pick a scope the LEASH doesn't grant.
      const granted = new Set(currentClaims['vettid:scope']);
      const target = SCOPE_OPTIONS.find((s) => !granted.has(s)) || 'wallet.balance:read';
      return await postVerify(currentLeash.leash, target, true);
    }
    case 'forgeSig': {
      // Re-sign the SAME claims with an attacker keypair, swap into the JWT.
      const [hb64, cb64] = currentLeash.leash.split('.');
      const evilKp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign']);
      const signingInput = `${hb64}.${cb64}`;
      const evilSig = await crypto.subtle.sign('Ed25519', evilKp.privateKey, new TextEncoder().encode(signingInput));
      const forged = `${signingInput}.${b64UrlEncode(new Uint8Array(evilSig))}`;
      return await postVerify(forged, grantedScope, true);
    }
    case 'replayBearer':
      // Send a real JWT but a bogus agent_sig (zeros). The PoP check fails.
      return await postVerify(currentLeash.leash, grantedScope, false);
    case 'staleEnvelope':
      return await postVerify(currentLeash.leash, grantedScope, true, /*timestampOffset*/-120);
    case 'revokeAndReplay': {
      // Step 1: revoke. Step 2: re-verify — validator should return revoked.
      const r = await fetch(`${API}/v1/public/leash/demo/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jti: currentLeash.jti }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({ error: r.statusText }));
        return { network_error: `revoke step failed: ${body.error || r.statusText}` };
      }
      // Then verify honestly.
      return await postVerify(currentLeash.leash, grantedScope, true);
    }
    default:
      return { network_error: `unknown attack ${name}` };
  }
}

async function postVerify(leash, action, goodAgentSig, timestampOffset = 0) {
  const nonce = b64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const timestamp = Math.floor(Date.now() / 1000) + timestampOffset;
  const request = { action };
  const canon = canonicalJSON({ leash, request, nonce, timestamp });
  let agentSig;
  if (goodAgentSig) {
    const sigBuf = await crypto.subtle.sign('Ed25519', agentKeyPair.privateKey, new TextEncoder().encode(canon));
    agentSig = b64UrlEncode(new Uint8Array(sigBuf));
  } else {
    agentSig = b64UrlEncode(new Uint8Array(64));
  }
  const resp = await fetch(`${API}/v1/public/leash/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ leash, request, nonce, timestamp, agent_sig: agentSig }),
  });
  return resp.json();
}

function renderResult(label, attack, body) {
  const list = document.getElementById('resultsList');
  const card = document.createElement('div');
  card.className = 'result-card';
  const verified = body.verified === true;
  card.innerHTML = `
    <div class="result-head">
      <span class="result-attack-name">${escapeHtml(label)}</span>
      <span class="verdict-pill ${verified ? 'pass' : 'fail'}">${verified ? 'VERIFIED ✓' : 'REJECTED ✗'}</span>
    </div>`;
  if (body.network_error) {
    const p = document.createElement('p');
    p.className = 'check-detail';
    p.textContent = `Network: ${body.network_error}`;
    card.appendChild(p);
  } else {
    if (body.rejection_reason) {
      const p = document.createElement('p');
      p.className = 'check-detail';
      p.style.color = 'var(--fail)';
      p.textContent = `Reason: ${body.rejection_reason}`;
      card.appendChild(p);
    }
    const ol = document.createElement('ol');
    ol.className = 'check-list';
    (body.checks || []).forEach((c) => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="check-mark ${c.status}">${c.status === 'pass' ? '✓' : '✗'}</span>
                      <span class="check-name">${escapeHtml(c.name)}</span>
                      <span class="check-detail">${escapeHtml(c.detail)}</span>`;
      ol.appendChild(li);
    });
    card.appendChild(ol);
  }
  list.prepend(card);
}

function clearResults() {
  document.getElementById('resultsList').innerHTML = '';
}

// =====================================================================
// Live mode
// =====================================================================
document.getElementById('liveSpawnBtn').addEventListener('click', async () => {
  const btn = document.getElementById('liveSpawnBtn');
  btn.disabled = true;
  btn.textContent = 'Spawning…';
  try {
    const r = await fetch(`${API}/v1/public/leash/demo/session`, { method: 'POST' });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || 'spawn failed');
    liveSession = body;
    liveSeenResults = 0;
    document.getElementById('liveSessionPanel').style.display = '';
    document.getElementById('liveResultsPanel').style.display = '';
    document.getElementById('liveResultsList').innerHTML = '';
    document.getElementById('liveToken').textContent = body.session_token;
    document.getElementById('liveExpiry').textContent = new Date(body.expires_at * 1000).toLocaleTimeString();
    document.getElementById('liveCliHint').textContent = body.cli_hint;
    startLivePolling();
  } catch (e) {
    alert(`Spawn failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Spawn live session';
  }
});

function startLivePolling() {
  if (livePollTimer) clearInterval(livePollTimer);
  async function poll() {
    if (!liveSession) return;
    try {
      const r = await fetch(liveSession.poll_url);
      if (!r.ok) return;
      const body = await r.json();
      const fresh = (body.results || []).slice(liveSeenResults);
      fresh.forEach((entry) => {
        renderLiveResult(entry);
        liveSeenResults += 1;
      });
      // Stop polling once the session expires.
      if (body.expires_at && body.expires_at * 1000 < Date.now()) {
        clearInterval(livePollTimer);
        livePollTimer = null;
      }
    } catch (_) { /* swallow; next tick tries again */ }
  }
  poll();
  livePollTimer = setInterval(poll, 2000);
}

function renderLiveResult(entry) {
  const list = document.getElementById('liveResultsList');
  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div class="result-head">
      <span class="result-attack-name">Agent verify at ${new Date(entry.at * 1000).toLocaleTimeString()}</span>
      <span class="verdict-pill ${entry.verified ? 'pass' : 'fail'}">${entry.verified ? 'VERIFIED ✓' : 'REJECTED ✗'}</span>
    </div>`;
  if (entry.rejection_reason) {
    const p = document.createElement('p');
    p.className = 'check-detail';
    p.style.color = 'var(--fail)';
    p.textContent = `Reason: ${entry.rejection_reason}`;
    card.appendChild(p);
  }
  const ol = document.createElement('ol');
  ol.className = 'check-list';
  (entry.checks || []).forEach((c) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="check-mark ${c.status}">${c.status === 'pass' ? '✓' : '✗'}</span>
                    <span class="check-name">${escapeHtml(c.name)}</span>
                    <span class="check-detail">${escapeHtml(c.detail)}</span>`;
    ol.appendChild(li);
  });
  card.appendChild(ol);
  list.prepend(card);
}

// =====================================================================
// Helpers
// =====================================================================
function decodeClaims(jwt) {
  const cb64 = jwt.split('.')[1];
  const json = atob(cb64.replace(/-/g, '+').replace(/_/g, '/').padEnd(cb64.length + ((4 - cb64.length % 4) % 4), '='));
  return JSON.parse(json);
}

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

function b64UrlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function showErr(el, msg) {
  el.textContent = msg;
  el.style.display = 'block';
}
