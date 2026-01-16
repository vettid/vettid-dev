/**
 * Admin Portal System Module
 *
 * System health monitoring, logs, security events, vault metrics.
 * Uses safe DOM methods throughout.
 */

import {
  api,
  showToast,
  isAdmin,
  idToken,
  config
} from './core.js';

// ============================================
// System Health
// ============================================

export async function loadSystemHealth() {
  try {
    const token = idToken();
    const res = await fetch(`${config.apiUrl}/admin/system-health`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const data = await res.json();

    // Update SES Quota
    const sesUsed = data.ses?.sent24h || 0;
    const sesLimit = data.ses?.limit || 0;
    const sesPercentage = sesLimit > 0 ? Math.round((sesUsed / sesLimit) * 100) : 0;

    const sesQuotaUsedEl = document.getElementById('sesQuotaUsed');
    const sesQuotaLimitEl = document.getElementById('sesQuotaLimit');
    if (sesQuotaUsedEl) sesQuotaUsedEl.textContent = sesUsed.toLocaleString();
    if (sesQuotaLimitEl) sesQuotaLimitEl.textContent = `of ${sesLimit.toLocaleString()} emails sent today`;

    const sesBar = document.querySelector('#sesQuotaBar > div');
    if (sesBar) {
      sesBar.style.width = `${sesPercentage}%`;
      if (sesPercentage > 80) {
        sesBar.style.background = 'linear-gradient(90deg,#ef4444,#dc2626)';
      } else if (sesPercentage > 60) {
        sesBar.style.background = 'linear-gradient(90deg,#f59e0b,#d97706)';
      } else {
        sesBar.style.background = 'linear-gradient(90deg,#10b981,#059669)';
      }
    }

    // Update DynamoDB Storage
    const dynamoSize = data.dynamodb?.totalSize || 0;
    const dynamoTableCount = data.dynamodb?.tableCount || 0;
    const dynamoTotalSizeEl = document.getElementById('dynamoTotalSize');
    const dynamoTableCountEl = document.getElementById('dynamoTableCount');
    if (dynamoTotalSizeEl) dynamoTotalSizeEl.textContent = formatBytes(dynamoSize);
    if (dynamoTableCountEl) dynamoTableCountEl.textContent = `across ${dynamoTableCount} tables`;

    // Update Lambda Errors
    const lambdaErrors = data.lambda?.errors24h || 0;
    const lambdaErrorCountEl = document.getElementById('lambdaErrorCount');
    const lambdaErrorRateEl = document.getElementById('lambdaErrorRate');
    if (lambdaErrorCountEl) lambdaErrorCountEl.textContent = lambdaErrors.toLocaleString();
    if (lambdaErrorRateEl) lambdaErrorRateEl.textContent = 'in the last 24 hours';

    // Update API Health
    const apiStatus = data.api?.status || 'Unknown';
    const apiResponseTime = data.api?.avgResponseTimeMs || 0;
    const apiHealthStatusEl = document.getElementById('apiHealthStatus');
    const apiResponseTimeEl = document.getElementById('apiResponseTime');
    if (apiHealthStatusEl) {
      apiHealthStatusEl.textContent = apiStatus;
      const statusLower = apiStatus.toLowerCase();
      if (statusLower === 'operational' || statusLower === 'healthy') {
        apiHealthStatusEl.style.color = '#10b981';
      } else if (statusLower === 'degraded') {
        apiHealthStatusEl.style.color = '#f59e0b';
      } else {
        apiHealthStatusEl.style.color = '#ef4444';
      }
    }
    if (apiResponseTimeEl) apiResponseTimeEl.textContent = `Avg: ${apiResponseTime}ms`;

    // Update NATS Cluster Health
    updateNatsHealth(data.nats);

    // Update Nitro Enclave ASG Health
    updateNitroHealth(data.nitro);

  } catch (e) {
    console.error('Error loading system health:', e);
    showToast('Failed to load system health', 'error');
  }
}

function updateNatsHealth(nats) {
  if (!nats) return;

  const statusEl = document.getElementById('natsClusterStatus');
  const nodeCountEl = document.getElementById('natsNodeCount');

  const status = nats.status || 'unknown';
  const healthyNodes = nats.healthyNodes || 0;
  const totalNodes = nats.totalNodes || 0;

  if (statusEl) {
    if (status === 'healthy') {
      statusEl.textContent = 'Healthy';
      statusEl.style.color = '#10b981';
    } else if (status === 'degraded') {
      statusEl.textContent = 'Degraded';
      statusEl.style.color = '#f59e0b';
    } else if (status === 'unhealthy') {
      statusEl.textContent = 'Unhealthy';
      statusEl.style.color = '#ef4444';
    } else {
      statusEl.textContent = 'Unknown';
      statusEl.style.color = '#9ca3af';
    }
  }

  if (nodeCountEl) {
    nodeCountEl.textContent = `${healthyNodes} of ${totalNodes} nodes healthy`;
  }
}

function updateNitroHealth(nitro) {
  if (!nitro) return;

  const statusEl = document.getElementById('nitroAsgStatus');
  const instanceCountEl = document.getElementById('nitroInstanceCount');
  const amiStatusEl = document.getElementById('nitroAmiStatus');
  const amiIndicatorEl = document.getElementById('nitroAmiIndicator');
  const amiTextEl = document.getElementById('nitroAmiText');
  const refreshStatusEl = document.getElementById('nitroRefreshStatus');
  const refreshProgressEl = document.getElementById('nitroRefreshProgress');

  const status = nitro.status || 'unknown';
  const healthyInstances = nitro.healthyInstances || 0;
  const desiredCapacity = nitro.desiredCapacity || 0;
  const amiUpToDate = nitro.amiUpToDate || false;
  const currentAmi = nitro.currentAmi || '';
  const latestAmi = nitro.latestAmi || '';
  const refresh = nitro.instanceRefresh;

  // Status
  if (statusEl) {
    if (status === 'healthy') {
      statusEl.textContent = 'Healthy';
      statusEl.style.color = '#10b981';
    } else if (status === 'degraded') {
      statusEl.textContent = 'Degraded';
      statusEl.style.color = '#f59e0b';
    } else if (status === 'unhealthy') {
      statusEl.textContent = 'Unhealthy';
      statusEl.style.color = '#ef4444';
    } else {
      statusEl.textContent = 'Unknown';
      statusEl.style.color = '#9ca3af';
    }
  }

  // Instance count
  if (instanceCountEl) {
    instanceCountEl.textContent = `${healthyInstances} of ${desiredCapacity} instances healthy`;
  }

  // AMI status
  if (amiStatusEl && (currentAmi || latestAmi)) {
    amiStatusEl.style.display = 'block';
    if (amiIndicatorEl) {
      if (amiUpToDate) {
        amiIndicatorEl.style.backgroundColor = '#10b981';
      } else if (latestAmi && currentAmi && latestAmi !== currentAmi) {
        amiIndicatorEl.style.backgroundColor = '#f59e0b';
      } else {
        amiIndicatorEl.style.backgroundColor = '#9ca3af';
      }
    }
    if (amiTextEl) {
      amiTextEl.textContent = amiUpToDate ? 'AMI up to date' : 'Update available';
    }
  }

  // Instance refresh
  if (refresh && refreshStatusEl && refreshProgressEl) {
    refreshStatusEl.style.display = 'block';
    refreshProgressEl.textContent = refresh.status || 'Unknown';
  } else if (refreshStatusEl) {
    refreshStatusEl.style.display = 'none';
  }
}

// ============================================
// System Logs
// ============================================

export async function loadSystemLogs() {
  try {
    const sourceFilter = document.getElementById('logSourceFilter')?.value || 'all';
    const logsContainer = document.getElementById('systemLogsContainer');
    if (!logsContainer) return;

    logsContainer.textContent = 'Loading logs...';

    let url = config.apiUrl + '/admin/system-logs?limit=50';
    if (sourceFilter !== 'all') {
      url += '&source=' + encodeURIComponent(sourceFilter);
    }

    const token = idToken();
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      logsContainer.textContent = 'No logs found';
      return;
    }

    logsContainer.replaceChildren();

    logs.forEach(log => {
      const logEntry = document.createElement('div');
      logEntry.style.cssText = 'padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-size:0.8rem;';

      const timestamp = document.createElement('span');
      timestamp.style.cssText = 'color:var(--gray);margin-right:12px;';
      timestamp.textContent = log.timestamp ? new Date(log.timestamp).toLocaleString() : '—';

      const level = document.createElement('span');
      level.style.cssText = 'margin-right:12px;font-weight:600;';
      const levelColors = { error: '#ef4444', warn: '#f59e0b', info: '#3b82f6', debug: '#6b7280' };
      level.style.color = levelColors[log.level?.toLowerCase()] || '#6b7280';
      level.textContent = (log.level || 'INFO').toUpperCase();

      const message = document.createElement('span');
      message.style.color = 'var(--text)';
      message.textContent = log.message || '';

      logEntry.append(timestamp, level, message);
      logsContainer.appendChild(logEntry);
    });
  } catch (e) {
    console.error('Error loading system logs:', e);
    const logsContainer = document.getElementById('systemLogsContainer');
    if (logsContainer) logsContainer.textContent = 'Error loading logs: ' + (e.message || e);
  }
}

// ============================================
// Security Events
// ============================================

export async function loadSecurityEvents() {
  try {
    const container = document.getElementById('securityEventsContent');
    if (!container) return;

    container.textContent = 'Loading...';

    const data = await api('/admin/security-events?limit=50');
    const events = data.events || [];

    if (events.length === 0) {
      container.textContent = 'No security events found';
      return;
    }

    container.replaceChildren();

    events.forEach(event => {
      const eventEl = document.createElement('div');
      eventEl.style.cssText = 'padding:12px;border-bottom:1px solid var(--border);';

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;margin-bottom:4px;';

      const type = document.createElement('span');
      type.style.cssText = 'font-weight:600;color:var(--text);';
      type.textContent = event.event_type || event.type || 'Unknown Event';

      const time = document.createElement('span');
      time.style.cssText = 'font-size:0.8rem;color:var(--gray);';
      time.textContent = event.created_at ? new Date(event.created_at).toLocaleString() : '—';

      header.append(type, time);

      const details = document.createElement('div');
      details.style.cssText = 'font-size:0.85rem;color:var(--gray);';
      if (event.email) {
        const emailSpan = document.createElement('span');
        emailSpan.textContent = 'User: ' + event.email;
        details.appendChild(emailSpan);
      }
      if (event.ip_address) {
        const ipSpan = document.createElement('span');
        ipSpan.style.marginLeft = event.email ? '12px' : '0';
        ipSpan.textContent = 'IP: ' + event.ip_address;
        details.appendChild(ipSpan);
      }

      eventEl.append(header);
      if (details.childNodes.length > 0) eventEl.appendChild(details);
      container.appendChild(eventEl);
    });
  } catch (e) {
    console.error('Error loading security events:', e);
    const container = document.getElementById('securityEventsContent');
    if (container) container.textContent = 'Error loading events: ' + (e.message || e);
  }
}

// ============================================
// Recovery Requests
// ============================================

export async function loadRecoveryRequests() {
  try {
    const container = document.getElementById('recoveryRequestsContent');
    if (!container) return;

    container.textContent = 'Loading...';

    const data = await api('/admin/credential-recovery-requests');
    const requests = data.requests || [];

    if (requests.length === 0) {
      container.textContent = 'No pending recovery requests';
      return;
    }

    container.replaceChildren();

    requests.forEach(req => {
      const reqEl = document.createElement('div');
      reqEl.style.cssText = 'padding:12px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;';

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;';

      const emailDiv = document.createElement('div');
      emailDiv.style.cssText = 'font-weight:600;';
      emailDiv.textContent = req.email || '—';

      const statusBadge = document.createElement('span');
      statusBadge.style.cssText = 'display:inline-block;padding:4px 8px;border-radius:8px;font-size:0.7rem;font-weight:600;';
      const statusColors = { pending: '#f59e0b', approved: '#10b981', denied: '#ef4444' };
      statusBadge.style.background = statusColors[req.status] || '#6b7280';
      statusBadge.style.color = '#fff';
      statusBadge.textContent = (req.status || 'pending').toUpperCase();

      header.append(emailDiv, statusBadge);

      const metaDiv = document.createElement('div');
      metaDiv.style.cssText = 'font-size:0.8rem;color:var(--gray);margin-bottom:8px;';
      metaDiv.textContent = 'Requested: ' + (req.created_at ? new Date(req.created_at).toLocaleString() : '—');

      reqEl.append(header, metaDiv);

      if (req.status === 'pending') {
        const actionsDiv = document.createElement('div');
        actionsDiv.style.cssText = 'display:flex;gap:8px;';

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-sm';
        cancelBtn.style.background = 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)';
        cancelBtn.textContent = 'Cancel Request';
        cancelBtn.onclick = () => handleRecoveryRequest(req.recovery_id || req.request_id, 'cancel');

        actionsDiv.append(cancelBtn);
        reqEl.appendChild(actionsDiv);
      }

      container.appendChild(reqEl);
    });
  } catch (e) {
    console.error('Error loading recovery requests:', e);
    const container = document.getElementById('recoveryRequestsContent');
    if (container) container.textContent = 'Error: ' + (e.message || e);
  }
}

async function handleRecoveryRequest(requestId, action) {
  try {
    // Backend only supports cancel action
    await api(`/admin/credential-recovery-requests/${requestId}/cancel`, { method: 'POST' });
    showToast('Recovery request cancelled successfully', 'success');
    await loadRecoveryRequests();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

// ============================================
// Deletion Requests
// ============================================

export async function loadDeletionRequests() {
  try {
    const container = document.getElementById('deletionRequestsContent');
    if (!container) return;

    container.textContent = 'Loading...';

    const data = await api('/admin/vault-deletion-requests');
    const requests = data.requests || [];

    if (requests.length === 0) {
      container.textContent = 'No pending deletion requests';
      return;
    }

    container.replaceChildren();

    requests.forEach(req => {
      const reqEl = document.createElement('div');
      reqEl.style.cssText = 'padding:12px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;';

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;';

      const emailDiv = document.createElement('div');
      emailDiv.style.cssText = 'font-weight:600;';
      emailDiv.textContent = req.email || '—';

      const statusBadge = document.createElement('span');
      statusBadge.style.cssText = 'display:inline-block;padding:4px 8px;border-radius:8px;font-size:0.7rem;font-weight:600;';
      const statusColors = { pending: '#f59e0b', completed: '#10b981', cancelled: '#6b7280' };
      statusBadge.style.background = statusColors[req.status] || '#6b7280';
      statusBadge.style.color = '#fff';
      statusBadge.textContent = (req.status || 'pending').toUpperCase();

      header.append(emailDiv, statusBadge);

      const metaDiv = document.createElement('div');
      metaDiv.style.cssText = 'font-size:0.8rem;color:var(--gray);margin-bottom:8px;';
      metaDiv.textContent = 'Requested: ' + (req.created_at ? new Date(req.created_at).toLocaleString() : '—');

      reqEl.append(header, metaDiv);

      if (req.status === 'pending') {
        const actionsDiv = document.createElement('div');
        actionsDiv.style.cssText = 'display:flex;gap:8px;';

        const processBtn = document.createElement('button');
        processBtn.className = 'btn btn-sm';
        processBtn.style.background = 'linear-gradient(135deg,#ef4444 0%,#dc2626 100%)';
        processBtn.textContent = 'Cancel Request';
        processBtn.onclick = () => cancelDeletionRequest(req.request_id);

        actionsDiv.appendChild(processBtn);
        reqEl.appendChild(actionsDiv);
      }

      container.appendChild(reqEl);
    });
  } catch (e) {
    console.error('Error loading deletion requests:', e);
    const container = document.getElementById('deletionRequestsContent');
    if (container) container.textContent = 'Error: ' + (e.message || e);
  }
}

async function cancelDeletionRequest(requestId) {
  if (!confirm('Are you sure you want to cancel this deletion request?')) {
    return;
  }

  try {
    await api(`/admin/vault-deletion-requests/${requestId}/cancel`, { method: 'POST' });
    showToast('Deletion request cancelled successfully', 'success');
    await loadDeletionRequests();
  } catch (e) {
    showToast('Error: ' + (e.message || e), 'error');
  }
}

// ============================================
// Vault Metrics
// ============================================

export async function loadVaultMetrics() {
  try {
    const container = document.getElementById('vaultMetricsContent');
    if (!container) return;

    container.textContent = 'Loading vault metrics...';

    const data = await api('/admin/vault-metrics');

    container.replaceChildren();

    // Create metrics cards
    const metricsGrid = document.createElement('div');
    metricsGrid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;';

    const metrics = [
      { label: 'Total Vaults', value: data.total_vaults || 0 },
      { label: 'Active Vaults', value: data.active_vaults || 0 },
      { label: 'Enrollments Today', value: data.enrollments_today || 0 },
      { label: 'Auth Success Rate', value: (data.auth_success_rate || 0) + '%' }
    ];

    metrics.forEach(metric => {
      const card = document.createElement('div');
      card.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center;';

      const value = document.createElement('div');
      value.style.cssText = 'font-size:2rem;font-weight:700;color:var(--accent);margin-bottom:4px;';
      value.textContent = metric.value;

      const label = document.createElement('div');
      label.style.cssText = 'font-size:0.85rem;color:var(--gray);';
      label.textContent = metric.label;

      card.append(value, label);
      metricsGrid.appendChild(card);
    });

    container.appendChild(metricsGrid);
  } catch (e) {
    console.error('Error loading vault metrics:', e);
    const container = document.getElementById('vaultMetricsContent');
    if (container) container.textContent = 'Error: ' + (e.message || e);
  }
}

// ============================================
// Deployed Handlers (VettID-managed handlers)
// ============================================

let deployedHandlers = [];

export async function loadDeployedHandlers() {
  if (!isAdmin()) return;

  const grid = document.getElementById('deployedHandlersGrid');
  if (!grid) return;

  // Show loading state
  grid.replaceChildren();
  const loadingDiv = document.createElement('div');
  loadingDiv.style.cssText = 'grid-column:1/-1;padding:40px;text-align:center;color:var(--gray);';
  loadingDiv.textContent = 'Loading deployed handlers...';
  grid.appendChild(loadingDiv);

  try {
    const response = await api('/admin/handlers/deployed');
    deployedHandlers = response.handlers || [];
    renderDeployedHandlers();
  } catch (err) {
    console.error('Error loading deployed handlers:', err);
    grid.replaceChildren();
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'grid-column:1/-1;padding:40px;text-align:center;color:#ef4444;';
    errorDiv.textContent = 'Error loading handlers: ' + (err.message || err);
    grid.appendChild(errorDiv);
    showToast('Failed to load deployed handlers', 'error');
  }
}

function renderDeployedHandlers() {
  const grid = document.getElementById('deployedHandlersGrid');
  const countEl = document.getElementById('deployedHandlersCount');

  if (countEl) countEl.textContent = deployedHandlers.length;

  grid.replaceChildren();

  if (deployedHandlers.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.style.cssText = 'grid-column:1/-1;padding:40px;text-align:center;color:var(--gray);';
    const iconDiv = document.createElement('div');
    iconDiv.style.cssText = 'font-size:2rem;margin-bottom:8px;';
    iconDiv.textContent = '📦';
    const textDiv = document.createElement('div');
    textDiv.textContent = 'No VettID handlers deployed yet';
    emptyDiv.append(iconDiv, textDiv);
    grid.appendChild(emptyDiv);
    return;
  }

  deployedHandlers.forEach(h => {
    const card = createHandlerCard(h);
    grid.appendChild(card);
  });
}

function createHandlerCard(h) {
  // Status colors: signed = green, revoked = red, pending = yellow
  const statusColor = h.status === 'signed' ? '#10b981' : h.status === 'revoked' ? '#ef4444' : h.status === 'pending' ? '#f59e0b' : '#6b7280';
  const statusLabel = h.status === 'signed' ? 'Deployed' : h.status;

  const card = document.createElement('div');
  card.className = 'handler-card';
  card.style.cssText = 'padding:20px;background:#050505;border-radius:12px;border:1px solid var(--border);transition:border-color 0.2s;';

  // Header with icon and name
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:start;gap:12px;margin-bottom:12px;';

  const iconDiv = document.createElement('div');
  iconDiv.style.cssText = 'width:48px;height:48px;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;';
  iconDiv.textContent = h.icon || '📦';

  const infoDiv = document.createElement('div');
  infoDiv.style.cssText = 'flex:1;min-width:0;';

  const nameDiv = document.createElement('div');
  nameDiv.style.cssText = 'font-weight:600;color:var(--text);margin-bottom:2px;';
  nameDiv.textContent = h.name || h.handler_id;

  const idDiv = document.createElement('div');
  idDiv.style.cssText = 'font-size:0.8rem;color:var(--gray);font-family:monospace;';
  idDiv.textContent = h.handler_id;

  infoDiv.append(nameDiv, idDiv);

  const statusDot = document.createElement('span');
  statusDot.style.cssText = `display:inline-block;width:10px;height:10px;border-radius:50%;background:${statusColor};`;
  statusDot.title = statusLabel;

  header.append(iconDiv, infoDiv, statusDot);
  card.appendChild(header);

  // Description
  const descP = document.createElement('p');
  descP.style.cssText = 'margin:0 0 12px 0;color:var(--gray);font-size:0.85rem;line-height:1.4;min-height:40px;';
  const desc = h.description || 'No description';
  descP.textContent = desc.length > 100 ? desc.substring(0, 100) + '...' : desc;
  card.appendChild(descP);

  // Version and category
  const metaDiv = document.createElement('div');
  metaDiv.style.cssText = 'display:flex;gap:8px;align-items:center;';

  const versionCode = document.createElement('code');
  versionCode.style.cssText = 'background:var(--bg-card);padding:4px 8px;border-radius:4px;font-size:0.8rem;color:var(--accent);';
  versionCode.textContent = 'v' + (h.version || '1.0.0');
  metaDiv.appendChild(versionCode);

  if (h.category) {
    const categorySpan = document.createElement('span');
    categorySpan.style.cssText = 'background:#222;padding:4px 8px;border-radius:4px;font-size:0.75rem;color:var(--gray);';
    categorySpan.textContent = h.category;
    metaDiv.appendChild(categorySpan);
  }

  card.appendChild(metaDiv);

  // Install count
  if (h.install_count > 0) {
    const installDiv = document.createElement('div');
    installDiv.style.cssText = 'margin-top:8px;font-size:0.75rem;color:var(--gray);';
    installDiv.textContent = '📥 ' + h.install_count + ' installs';
    card.appendChild(installDiv);
  }

  return card;
}

// Alias for backward compatibility
export function loadHandlers() {
  return loadDeployedHandlers();
}

// Setup event handlers for handlers section
export function setupHandlersEventHandlers() {
  const refreshBtn = document.getElementById('refreshHandlersBtn');
  if (refreshBtn) refreshBtn.onclick = loadDeployedHandlers;

  // Handler tab clicks
  document.querySelectorAll('.handler-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      tab.classList.add('active');
      tab.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
      loadDeployedHandlers();
    });
  });
}

// ============================================
// Helpers
// ============================================

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
