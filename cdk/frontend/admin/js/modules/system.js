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
  config,
  escapeHtml
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
  const range = document.getElementById('securityTimeRange')?.value || '24h';
  const severity = document.getElementById('securitySeverityFilter')?.value || 'all';
  const container = document.getElementById('securityEventsList');

  try {
    if (container) container.textContent = 'Loading security events...';

    const data = await api(`/admin/security-events?range=${range}&severity=${severity}&limit=100`);

    // Update metrics
    const metricTotal = document.getElementById('secMetricTotal');
    const metricCritical = document.getElementById('secMetricCritical');
    const metricHigh = document.getElementById('secMetricHigh');
    const metricAuth = document.getElementById('secMetricAuth');
    const metricRecovery = document.getElementById('secMetricRecovery');
    const metricDeletion = document.getElementById('secMetricDeletion');

    if (metricTotal) metricTotal.textContent = data.metrics?.total_events ?? '--';
    if (metricCritical) metricCritical.textContent = data.metrics?.critical ?? '0';
    if (metricHigh) metricHigh.textContent = data.metrics?.high ?? '0';
    if (metricAuth) metricAuth.textContent = data.metrics?.auth_failures ?? '0';
    if (metricRecovery) metricRecovery.textContent = data.metrics?.pending_recovery_requests ?? '0';
    if (metricDeletion) metricDeletion.textContent = data.metrics?.pending_deletion_requests ?? '0';

    // Render events list
    if (!container) return;

    const events = data.events || [];
    if (events.length === 0) {
      container.innerHTML = '<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:var(--gray);">No security events found for the selected time range.</div>';
      return;
    }

    const severityColors = {
      critical: { bg: 'rgba(239,68,68,0.2)', border: '#ef4444', text: '#ef4444' },
      high: { bg: 'rgba(245,158,11,0.15)', border: '#f59e0b', text: '#f59e0b' },
      medium: { bg: 'rgba(99,102,241,0.1)', border: '#6366f1', text: '#6366f1' },
      low: { bg: 'rgba(156,163,175,0.1)', border: '#6b7280', text: '#9ca3af' }
    };

    container.innerHTML = events.map(event => {
      const colors = severityColors[event.severity] || severityColors.low;
      const time = event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown';
      const typeLabel = (event.type || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

      return `
        <div style="padding:12px 16px;background:${colors.bg};border-radius:8px;border-left:4px solid ${colors.border};display:flex;justify-content:space-between;align-items:center;">
          <div style="flex:1;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
              <span style="padding:2px 8px;background:${colors.border};color:#000;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase;">${event.severity || 'low'}</span>
              <span style="color:${colors.text};font-weight:600;font-size:0.9rem;">${escapeHtml(typeLabel)}</span>
            </div>
            <p style="margin:0;color:var(--gray);font-size:0.85rem;">
              ${event.email ? `User: ${escapeHtml(event.email)} | ` : ''}
              ${event.path ? `Path: ${escapeHtml(event.path)} | ` : ''}
              ${event.reason ? `Reason: ${escapeHtml(event.reason)}` : ''}
            </p>
          </div>
          <span style="color:var(--gray);font-size:0.8rem;white-space:nowrap;">${time}</span>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error('Error loading security events:', e);
    if (container) container.innerHTML = `<div style="padding:20px;background:#050505;border-radius:8px;text-align:center;color:#ef4444;">Error loading events: ${escapeHtml(e.message || String(e))}</div>`;
  }
}

// ============================================
// Recovery Requests
// ============================================

export async function loadRecoveryRequests() {
  try {
    const container = document.getElementById('recoveryRequestsList');
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
    const container = document.getElementById('recoveryRequestsList');
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
    const container = document.getElementById('deletionRequestsList');
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
    const container = document.getElementById('deletionRequestsList');
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
    const data = await api('/admin/vault-metrics');

    // Update key metrics
    const metricTotalEnrolled = document.getElementById('metricTotalEnrolled');
    const metricActiveVaults = document.getElementById('metricActiveVaults');
    const metricPendingEnrollments = document.getElementById('metricPendingEnrollments');
    const metricEnrollmentRate = document.getElementById('metricEnrollmentRate');

    if (metricTotalEnrolled) metricTotalEnrolled.textContent = data.key_metrics?.total_enrolled ?? '—';
    if (metricActiveVaults) metricActiveVaults.textContent = data.key_metrics?.active_vaults ?? '—';
    if (metricPendingEnrollments) metricPendingEnrollments.textContent = data.key_metrics?.pending_enrollments ?? '—';
    if (metricEnrollmentRate) metricEnrollmentRate.textContent = `${data.key_metrics?.enrollment_rate_percent ?? '—'}%`;

    // Update enrollment outcomes
    const outcomes = data.enrollment_outcomes_30d || {};
    const totalOutcomes = (outcomes.success || 0) + (outcomes.failed || 0) + (outcomes.abandoned || 0) + (outcomes.pending || 0);

    const outcomeSuccessCount = document.getElementById('outcomeSuccessCount');
    const outcomeFailedCount = document.getElementById('outcomeFailedCount');
    const outcomeAbandonedCount = document.getElementById('outcomeAbandonedCount');
    const outcomePendingCount = document.getElementById('outcomePendingCount');

    if (outcomeSuccessCount) outcomeSuccessCount.textContent = outcomes.success || 0;
    if (outcomeFailedCount) outcomeFailedCount.textContent = outcomes.failed || 0;
    if (outcomeAbandonedCount) outcomeAbandonedCount.textContent = outcomes.abandoned || 0;
    if (outcomePendingCount) outcomePendingCount.textContent = outcomes.pending || 0;

    // Calculate percentages for progress bars
    if (totalOutcomes > 0) {
      const outcomeSuccessBar = document.getElementById('outcomeSuccessBar');
      const outcomeFailedBar = document.getElementById('outcomeFailedBar');
      const outcomeAbandonedBar = document.getElementById('outcomeAbandonedBar');
      const outcomePendingBar = document.getElementById('outcomePendingBar');

      if (outcomeSuccessBar) outcomeSuccessBar.style.width = `${(outcomes.success / totalOutcomes) * 100}%`;
      if (outcomeFailedBar) outcomeFailedBar.style.width = `${(outcomes.failed / totalOutcomes) * 100}%`;
      if (outcomeAbandonedBar) outcomeAbandonedBar.style.width = `${(outcomes.abandoned / totalOutcomes) * 100}%`;
      if (outcomePendingBar) outcomePendingBar.style.width = `${(outcomes.pending / totalOutcomes) * 100}%`;
    }

    // Update vault status distribution (Nitro model - 3 states only)
    const status = data.vault_status_distribution || {};
    const statusActiveCount = document.getElementById('statusActiveCount');
    const statusSuspendedCount = document.getElementById('statusSuspendedCount');
    const statusDeletedCount = document.getElementById('statusDeletedCount');

    if (statusActiveCount) statusActiveCount.textContent = status.active || 0;
    if (statusSuspendedCount) statusSuspendedCount.textContent = status.suspended || 0;
    if (statusDeletedCount) statusDeletedCount.textContent = status.deleted || 0;

    // Update recent enrollments table
    const recentEnrollments = data.recent_enrollments || [];
    const tbody = document.getElementById('recentEnrollmentsBody');

    if (tbody) {
      if (recentEnrollments.length === 0) {
        tbody.replaceChildren();
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 3;
        td.style.cssText = 'padding:20px;text-align:center;color:var(--gray);';
        td.textContent = 'No recent enrollments.';
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else {
        tbody.replaceChildren();
        recentEnrollments.forEach(e => {
          const tr = document.createElement('tr');
          tr.style.borderBottom = '1px solid var(--border)';

          const td1 = document.createElement('td');
          td1.style.cssText = 'padding:12px 8px;color:var(--text);';
          td1.textContent = e.email || '—';

          const td2 = document.createElement('td');
          td2.style.cssText = 'padding:12px 8px;color:var(--gray);font-family:monospace;font-size:0.8rem;';
          td2.textContent = (e.user_guid?.substring(0, 20) || '—') + '...';

          const td3 = document.createElement('td');
          td3.style.cssText = 'padding:12px 8px;color:var(--gray);';
          td3.textContent = e.completed_at ? new Date(e.completed_at).toLocaleString() : new Date(e.created_at).toLocaleString();

          tr.append(td1, td2, td3);
          tbody.appendChild(tr);
        });
      }
    }

    // Update generated timestamp
    const vaultMetricsGeneratedAt = document.getElementById('vaultMetricsGeneratedAt');
    if (vaultMetricsGeneratedAt) {
      vaultMetricsGeneratedAt.textContent = `Last updated: ${data.generated_at ? new Date(data.generated_at).toLocaleString() : '—'}`;
    }

  } catch (e) {
    console.error('Error loading vault metrics:', e);
    showToast('Error loading vault metrics: ' + (e.message || e), 'error');
  }
}

// ============================================
// Native Go Handlers (Built into Nitro Enclave)
// ============================================

// Native handlers are compiled into the enclave binary - this is a static list
// that reflects the handlers defined in vault-manager/messages.go
const nativeHandlers = [
  // Authentication & Security
  {
    id: 'authenticate',
    name: 'Authentication',
    description: 'Validates user credentials and establishes secure sessions within the enclave.',
    category: 'Security',
    icon: '🔐',
    operations: ['validate', 'session']
  },
  {
    id: 'pin',
    name: 'PIN Management',
    description: 'Secure PIN-based credential protection with setup, unlock, and change operations.',
    category: 'Security',
    icon: '🔑',
    operations: ['setup', 'unlock', 'change']
  },
  {
    id: 'unseal',
    name: 'Credential Unsealing',
    description: 'Decrypts and loads user credentials into secure enclave memory using KMS attestation.',
    category: 'Security',
    icon: '📂',
    operations: ['unseal']
  },
  {
    id: 'sign',
    name: 'Cryptographic Signing',
    description: 'Ed25519 digital signatures for authentication challenges and document signing.',
    category: 'Security',
    icon: '✍️',
    operations: ['sign']
  },

  // Communication
  {
    id: 'message',
    name: 'Secure Messaging',
    description: 'End-to-end encrypted vault-to-vault messaging with read receipts.',
    category: 'Communication',
    icon: '💬',
    operations: ['send', 'read-receipt']
  },
  {
    id: 'notification',
    name: 'Notifications',
    description: 'Push notification delivery for profile updates, revocations, and alerts.',
    category: 'Communication',
    icon: '🔔',
    operations: ['profile-broadcast', 'revoke-notify']
  },
  {
    id: 'call',
    name: 'WebRTC Calls',
    description: 'Secure peer-to-peer video/audio calls with signaling and call history.',
    category: 'Communication',
    icon: '📞',
    operations: ['start', 'accept', 'reject', 'end', 'signal', 'history']
  },

  // Data Management
  {
    id: 'secrets',
    name: 'Secret Storage',
    description: 'Encrypted storage for sensitive data like passwords, keys, and secure notes.',
    category: 'Data',
    icon: '🗝️',
    operations: ['add', 'update', 'retrieve', 'delete', 'list']
  },
  {
    id: 'profile',
    name: 'Profile Management',
    description: 'User profile data storage and retrieval with encrypted attributes.',
    category: 'Data',
    icon: '👤',
    operations: ['get', 'update', 'delete']
  },
  {
    id: 'credential',
    name: 'Credential Operations',
    description: 'Core credential lifecycle management including storage, sync, and versioning.',
    category: 'Data',
    icon: '🎫',
    operations: ['store', 'sync', 'get', 'version']
  },
  {
    id: 'backup',
    name: 'Backup Operations',
    description: 'Encrypted credential backup creation and restoration.',
    category: 'Data',
    icon: '💾',
    operations: ['trigger', 'restore']
  },

  // Connections
  {
    id: 'connection',
    name: 'Connection Management',
    description: 'Manages trusted connections between vaults with invite creation and revocation.',
    category: 'Connections',
    icon: '🤝',
    operations: ['create-invite', 'store-credentials', 'revoke', 'list', 'get']
  },
  {
    id: 'block',
    name: 'Block List',
    description: 'Manages blocked users to prevent unwanted contact and messages.',
    category: 'Connections',
    icon: '🚫',
    operations: ['add', 'remove']
  },

  // Governance
  {
    id: 'vote',
    name: 'Voting',
    description: 'Cryptographically signed voting for governance and verification proposals.',
    category: 'Governance',
    icon: '🗳️',
    operations: ['cast']
  },

  // Bootstrap
  {
    id: 'bootstrap',
    name: 'Bootstrap',
    description: 'Initial vault setup and configuration during enrollment.',
    category: 'System',
    icon: '🚀',
    operations: ['initialize']
  }
];

export async function loadDeployedHandlers() {
  if (!isAdmin()) return;

  const grid = document.getElementById('deployedHandlersGrid');
  if (!grid) return;

  // Native handlers are static - no API call needed
  renderDeployedHandlers();
}

function renderDeployedHandlers() {
  const grid = document.getElementById('deployedHandlersGrid');
  const countEl = document.getElementById('deployedHandlersCount');

  if (countEl) countEl.textContent = nativeHandlers.length;

  grid.replaceChildren();

  // Group handlers by category
  const categories = {};
  nativeHandlers.forEach(h => {
    if (!categories[h.category]) categories[h.category] = [];
    categories[h.category].push(h);
  });

  // Render each category
  Object.keys(categories).forEach(category => {
    const categoryHeader = document.createElement('div');
    categoryHeader.style.cssText = 'grid-column:1/-1;padding:16px 0 8px 0;font-weight:600;color:var(--text);font-size:0.9rem;border-bottom:1px solid var(--border);margin-bottom:8px;';
    categoryHeader.textContent = category;
    grid.appendChild(categoryHeader);

    categories[category].forEach(h => {
      const card = createNativeHandlerCard(h);
      grid.appendChild(card);
    });
  });
}

function createNativeHandlerCard(h) {
  const card = document.createElement('div');
  card.className = 'handler-card';
  card.style.cssText = 'padding:20px;background:#050505;border-radius:12px;border:1px solid var(--border);transition:border-color 0.2s;';

  // Header with icon and name
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:start;gap:12px;margin-bottom:12px;';

  const iconDiv = document.createElement('div');
  iconDiv.style.cssText = 'width:48px;height:48px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;';
  iconDiv.textContent = h.icon || '📦';

  const infoDiv = document.createElement('div');
  infoDiv.style.cssText = 'flex:1;min-width:0;';

  const nameDiv = document.createElement('div');
  nameDiv.style.cssText = 'font-weight:600;color:var(--text);margin-bottom:2px;';
  nameDiv.textContent = h.name;

  const idDiv = document.createElement('div');
  idDiv.style.cssText = 'font-size:0.8rem;color:var(--gray);font-family:monospace;';
  idDiv.textContent = h.id;

  infoDiv.append(nameDiv, idDiv);

  // Native badge
  const nativeBadge = document.createElement('span');
  nativeBadge.style.cssText = 'display:inline-block;padding:4px 8px;border-radius:8px;font-size:0.65rem;font-weight:600;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;';
  nativeBadge.textContent = 'NATIVE';

  header.append(iconDiv, infoDiv, nativeBadge);
  card.appendChild(header);

  // Description
  const descP = document.createElement('p');
  descP.style.cssText = 'margin:0 0 12px 0;color:var(--gray);font-size:0.85rem;line-height:1.4;';
  descP.textContent = h.description;
  card.appendChild(descP);

  // Operations
  if (h.operations && h.operations.length > 0) {
    const opsDiv = document.createElement('div');
    opsDiv.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';

    h.operations.forEach(op => {
      const opTag = document.createElement('code');
      opTag.style.cssText = 'background:#1a1a1a;padding:3px 6px;border-radius:4px;font-size:0.7rem;color:var(--accent);';
      opTag.textContent = op;
      opsDiv.appendChild(opTag);
    });

    card.appendChild(opsDiv);
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
// Notification Management
// ============================================

const NOTIFICATION_TYPES = {
  'waitlist': 'Waitlist',
  'user': 'User',
  'vote': 'Vote',
  'help_offer': 'Help Offer',
  'system_health': 'System Health'
};

// State for notification admin selection
let currentNotificationType = null;
let availableNotificationAdmins = [];

export async function loadNotifications(type) {
  try {
    const data = await api(`/admin/notifications/${type}`);
    renderNotifications(type, data.admins || []);
  } catch (error) {
    console.error(`Error loading ${type} notifications:`, error);
    showToast(`Failed to load ${NOTIFICATION_TYPES[type]} notifications`, 'error');
  }
}

function renderNotifications(type, admins) {
  const containerId = `${type}NotificationsList`;
  const container = document.getElementById(containerId);

  if (!container) return;

  // Clear existing content
  container.replaceChildren();

  if (admins.length === 0) {
    const emptyMsg = document.createElement('p');
    emptyMsg.style.cssText = 'color:var(--gray);font-size:0.9rem;margin:0;';
    emptyMsg.textContent = 'No admins assigned yet.';
    container.appendChild(emptyMsg);
    return;
  }

  admins.forEach(email => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin-bottom:8px;';

    const emailSpan = document.createElement('span');
    emailSpan.style.cssText = 'color:var(--text);font-size:0.9rem;';
    emailSpan.textContent = email;

    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn';
    removeBtn.setAttribute('data-action', 'remove-notification');
    removeBtn.setAttribute('data-type', type);
    removeBtn.setAttribute('data-email', email);
    removeBtn.style.cssText = 'background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);padding:6px 12px;font-size:0.85rem;';
    removeBtn.textContent = 'Remove';

    row.append(emailSpan, removeBtn);
    container.appendChild(row);
  });
}

export async function openAddNotificationModal(type) {
  const typeName = NOTIFICATION_TYPES[type];
  currentNotificationType = type;

  try {
    const adminData = await api('/admin/admins');
    const allAdmins = adminData.admins || [];

    const notifData = await api(`/admin/notifications/${type}`);
    const assignedEmails = (notifData.admins || []);

    availableNotificationAdmins = allAdmins.filter(a => !assignedEmails.includes(a.email));

    if (availableNotificationAdmins.length === 0) {
      showToast(`All admins are already assigned to ${typeName} notifications`, 'info');
      return;
    }

    const modal = document.getElementById('selectNotificationAdminModal');
    const modalTitle = document.getElementById('selectNotificationAdminTitle');
    const adminList = document.getElementById('notificationAdminList');

    modalTitle.textContent = `Add Admin to ${typeName} Notifications`;

    adminList.replaceChildren();
    availableNotificationAdmins.forEach(admin => {
      const name = `${admin.given_name || ''} ${admin.family_name || ''}`.trim() || admin.email;
      const option = document.createElement('div');
      option.className = 'modal-option';
      option.onclick = () => handleSelectNotificationAdmin(admin.email);

      const titleDiv = document.createElement('div');
      titleDiv.className = 'modal-option-title';
      titleDiv.textContent = name;

      const descDiv = document.createElement('div');
      descDiv.className = 'modal-option-desc';
      descDiv.textContent = admin.email;

      option.append(titleDiv, descDiv);
      adminList.appendChild(option);
    });

    modal.classList.add('active');

  } catch (error) {
    console.error('Error loading admins for notification:', error);
    showToast(`Failed to load available admins`, 'error');
  }
}

export function closeSelectNotificationAdminModal() {
  document.getElementById('selectNotificationAdminModal')?.classList.remove('active');
  currentNotificationType = null;
  availableNotificationAdmins = [];
}

async function handleSelectNotificationAdmin(email) {
  if (!currentNotificationType) return;

  const typeName = NOTIFICATION_TYPES[currentNotificationType];

  try {
    await api(`/admin/notifications/${currentNotificationType}`, {
      method: 'POST',
      body: JSON.stringify({ admin_email: email })
    });
    showToast(`Added ${email} to ${typeName} notifications`, 'success');
    await loadNotifications(currentNotificationType);
    closeSelectNotificationAdminModal();
  } catch (error) {
    console.error('Error adding notification:', error);
    showToast(`Failed to add admin to ${typeName} notifications`, 'error');
  }
}

export async function removeNotification(type, email) {
  const typeName = NOTIFICATION_TYPES[type];

  if (!confirm(`Remove ${email} from ${typeName} notifications?`)) return;

  try {
    await api(`/admin/notifications/${type}/${encodeURIComponent(email)}`, 'DELETE');
    showToast(`Removed ${email} from ${typeName} notifications`, 'success');
    loadNotifications(type);
  } catch (error) {
    console.error('Error removing notification:', error);
    showToast(`Failed to remove admin from ${typeName} notifications`, 'error');
  }
}

export function loadAllNotifications() {
  loadNotifications('waitlist');
  loadNotifications('user');
  loadNotifications('vote');
  loadNotifications('help_offer');
  loadNotifications('system_health');
}

export function setupNotificationEventHandlers() {
  const addWaitlistBtn = document.getElementById('addWaitlistNotification');
  const addUserBtn = document.getElementById('addUserNotification');
  const addVoteBtn = document.getElementById('addVoteNotification');
  const addHelpOfferBtn = document.getElementById('addHelpOfferNotification');
  const addSystemHealthBtn = document.getElementById('addSystemHealthNotification');

  if (addWaitlistBtn) addWaitlistBtn.onclick = () => openAddNotificationModal('waitlist');
  if (addUserBtn) addUserBtn.onclick = () => openAddNotificationModal('user');
  if (addVoteBtn) addVoteBtn.onclick = () => openAddNotificationModal('vote');
  if (addHelpOfferBtn) addHelpOfferBtn.onclick = () => openAddNotificationModal('help_offer');
  if (addSystemHealthBtn) addSystemHealthBtn.onclick = () => openAddNotificationModal('system_health');

  // Close modal button
  const closeBtn = document.getElementById('closeSelectNotificationAdmin');
  if (closeBtn) closeBtn.onclick = closeSelectNotificationAdminModal;
}

// ============================================
// Security Events Setup
// ============================================

export function setupSecurityEventsHandlers() {
  // Filter change listeners
  const timeRangeEl = document.getElementById('securityTimeRange');
  const severityEl = document.getElementById('securitySeverityFilter');
  const refreshBtn = document.getElementById('refreshSecurityEvents');
  const refreshRecoveryBtn = document.getElementById('refreshRecoveryRequests');
  const refreshDeletionBtn = document.getElementById('refreshDeletionRequests');

  if (timeRangeEl) timeRangeEl.onchange = loadSecurityEvents;
  if (severityEl) severityEl.onchange = loadSecurityEvents;
  if (refreshBtn) refreshBtn.onclick = loadSecurityEvents;
  if (refreshRecoveryBtn) refreshRecoveryBtn.onclick = loadRecoveryRequests;
  if (refreshDeletionBtn) refreshDeletionBtn.onclick = loadDeletionRequests;
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
