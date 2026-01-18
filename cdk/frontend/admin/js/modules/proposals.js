/**
 * Admin Portal Proposals Module
 *
 * Proposal management, vote analytics, voting results.
 * Uses safe DOM methods throughout.
 */

import {
  escapeHtml,
  api,
  showToast,
  isAdmin,
  idToken,
  showGridLoadingSkeleton,
  config
} from './core.js';

// ============================================
// State
// ============================================

export let currentProposalFilter = 'active';
export let totalActiveSubscribers = 0;
export let allProposalsData = { active: [], upcoming: [], closed: [] };
export let currentProposalAnalytics = null;

// ============================================
// Proposal Loading
// ============================================

export async function loadAllProposalsAdmin() {
  showGridLoadingSkeleton('inProgressProposalsContainer', 3);
  showGridLoadingSkeleton('completedProposalsContainer', 3);

  try {
    // Fetch all proposal types and total active subscribers
    const [active, upcoming, closed, subsData] = await Promise.all([
      api('/admin/proposals?status=active'),
      api('/admin/proposals?status=upcoming'),
      api('/admin/proposals?status=closed'),
      api('/admin/subscriptions?status=active')
    ]);

    allProposalsData = { active, upcoming, closed };
    totalActiveSubscribers = (subsData.subscriptions || []).length;

    // Update counts
    const activeCountEl = document.getElementById('activeVotesCount');
    const pendingCountEl = document.getElementById('pendingVotesCount');
    if (activeCountEl) activeCountEl.textContent = active.length;
    if (pendingCountEl) pendingCountEl.textContent = upcoming.length;

    // Render proposals
    renderProposals();

  } catch (e) {
    showToast('Failed to load proposals: ' + (e.message || e), 'error');
  }
}

// ============================================
// Proposal Rendering
// ============================================

export async function renderProposals() {
  const inProgressContainer = document.getElementById('inProgressProposalsContainer');
  const completedContainer = document.getElementById('completedProposalsContainer');

  if (!inProgressContainer || !completedContainer) return;

  // Render in-progress proposals
  let inProgressProposals = [];
  if (currentProposalFilter === 'active') {
    inProgressProposals = allProposalsData.active;
  } else if (currentProposalFilter === 'upcoming') {
    inProgressProposals = allProposalsData.upcoming;
  } else {
    inProgressProposals = [...allProposalsData.active, ...allProposalsData.upcoming];
  }

  inProgressContainer.replaceChildren();

  if (inProgressProposals.length === 0) {
    const emptyText = currentProposalFilter === 'active' ? 'No active proposals'
      : currentProposalFilter === 'upcoming' ? 'No scheduled proposals'
      : 'No in-progress proposals';
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty-state';
    const emptyTextEl = document.createElement('div');
    emptyTextEl.className = 'empty-state-text';
    emptyTextEl.textContent = emptyText;
    emptyDiv.appendChild(emptyTextEl);
    inProgressContainer.appendChild(emptyDiv);
  } else {
    for (const p of inProgressProposals) {
      const now = new Date();
      const opensAt = new Date(p.opens_at);
      const closesAt = new Date(p.closes_at);

      let proposalType = 'unknown';
      if (now < opensAt) proposalType = 'upcoming';
      else if (now >= opensAt && now < closesAt) proposalType = 'active';
      else proposalType = 'closed';

      const tile = proposalType === 'active'
        ? createActiveTile(p)
        : createUpcomingTile(p);
      inProgressContainer.appendChild(tile);
    }
  }

  // Render completed proposals
  completedContainer.replaceChildren();
  const completedProposals = allProposalsData.closed;

  if (completedProposals.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'empty-state';
    const emptyTextEl = document.createElement('div');
    emptyTextEl.className = 'empty-state-text';
    emptyTextEl.textContent = 'No closed proposals';
    emptyDiv.appendChild(emptyTextEl);
    completedContainer.appendChild(emptyDiv);
  } else {
    for (const p of completedProposals) {
      const tile = await createClosedTile(p);
      completedContainer.appendChild(tile);
    }
  }
}

function createActiveTile(p) {
  const tile = document.createElement('div');
  tile.style.cssText = 'background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;';

  const opensDate = formatDateTime(p.opens_at);
  const closesDate = formatDateTime(p.closes_at);
  const timeRemaining = calculateTimeRemaining(p.closes_at);
  const createdBy = p.created_by || 'Admin';
  const proposalNumber = p.proposal_number || '';
  const category = p.category || 'other';
  const categoryColors = { governance: '#8b5cf6', policy: '#3b82f6', budget: '#10b981', funding: '#ec4899', operational: '#f59e0b', other: '#6b7280' };
  const categoryColor = categoryColors[category] || '#6b7280';
  const quorumText = p.quorum_type === 'percentage' ? `${p.quorum_value}% quorum` : p.quorum_type === 'count' ? `${p.quorum_value} votes required` : '';

  // Proposal number
  if (proposalNumber) {
    const numDiv = document.createElement('div');
    numDiv.style.marginBottom = '4px';
    const numSpan = document.createElement('span');
    numSpan.style.cssText = 'font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;';
    numSpan.textContent = proposalNumber;
    numDiv.appendChild(numSpan);
    tile.appendChild(numDiv);
  }

  // Title
  const title = document.createElement('h4');
  title.style.cssText = 'margin:0 0 6px 0;font-weight:700;font-size:0.95rem;';
  title.textContent = p.proposal_title || 'Untitled Proposal';
  tile.appendChild(title);

  // Badges
  const badgesDiv = document.createElement('div');
  badgesDiv.style.cssText = 'margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;';

  const activeBadge = document.createElement('span');
  activeBadge.style.cssText = 'display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
  activeBadge.textContent = 'Active';
  badgesDiv.appendChild(activeBadge);

  const catBadge = document.createElement('span');
  catBadge.style.cssText = `display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;`;
  catBadge.textContent = category;
  badgesDiv.appendChild(catBadge);

  if (quorumText) {
    const quorumBadge = document.createElement('span');
    quorumBadge.style.cssText = 'display:inline-block;background:#374151;color:#9ca3af;padding:4px 10px;border-radius:12px;font-size:0.7rem;';
    quorumBadge.textContent = quorumText;
    badgesDiv.appendChild(quorumBadge);
  }
  tile.appendChild(badgesDiv);

  // Dates
  const datesDiv = document.createElement('div');
  datesDiv.style.cssText = 'margin-bottom:8px;font-size:0.8rem;color:var(--gray);';
  const opensDiv = document.createElement('div');
  opensDiv.style.marginBottom = '4px';
  opensDiv.textContent = 'Opens: ' + opensDate;
  const closesDiv = document.createElement('div');
  closesDiv.textContent = 'Closes: ' + closesDate;
  datesDiv.append(opensDiv, closesDiv);
  tile.appendChild(datesDiv);

  // Created by
  const createdByDiv = document.createElement('div');
  createdByDiv.style.cssText = 'margin-bottom:8px;font-size:0.8rem;color:var(--gray);';
  createdByDiv.textContent = 'Created by: ' + createdBy;
  tile.appendChild(createdByDiv);

  // Time remaining
  const timeDiv = document.createElement('div');
  timeDiv.style.cssText = 'margin-bottom:8px;padding:8px;background:var(--bg-tertiary);border-radius:6px;text-align:center;';
  const timeSpan = document.createElement('span');
  timeSpan.style.cssText = 'font-size:0.85rem;color:var(--accent);font-weight:600;';
  timeSpan.textContent = 'Closes in ' + timeRemaining;
  timeDiv.appendChild(timeSpan);
  tile.appendChild(timeDiv);

  // View Proposal button
  const viewBtn = document.createElement('button');
  viewBtn.className = 'btn';
  viewBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;';
  viewBtn.textContent = 'View Proposal';
  viewBtn.dataset.toggleProposal = p.proposal_id;
  tile.appendChild(viewBtn);

  // Hidden text content
  const textDiv = document.createElement('div');
  textDiv.id = 'text-' + p.proposal_id;
  textDiv.style.cssText = 'display:none;padding:10px;background:var(--bg-input);border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;';
  textDiv.textContent = p.proposal_text;
  tile.appendChild(textDiv);

  // View Analytics button
  const analyticsBtn = document.createElement('button');
  analyticsBtn.className = 'btn';
  analyticsBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;';
  analyticsBtn.textContent = 'View Analytics';
  analyticsBtn.dataset.analyticsProposal = p.proposal_id;
  analyticsBtn.dataset.analyticsTitle = p.proposal_title || 'Untitled Proposal';
  analyticsBtn.dataset.analyticsStatus = 'active';
  tile.appendChild(analyticsBtn);

  return tile;
}

function createUpcomingTile(p) {
  const tile = document.createElement('div');
  tile.style.cssText = 'background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;';

  const opensDate = formatDateTime(p.opens_at);
  const closesDate = formatDateTime(p.closes_at);
  const timeUntilOpens = calculateTimeRemaining(p.opens_at);
  const createdBy = p.created_by || 'Admin';
  const proposalNumber = p.proposal_number || '';
  const category = p.category || 'other';
  const categoryColors = { governance: '#8b5cf6', policy: '#3b82f6', budget: '#10b981', funding: '#ec4899', operational: '#f59e0b', other: '#6b7280' };
  const categoryColor = categoryColors[category] || '#6b7280';
  const quorumText = p.quorum_type === 'percentage' ? `${p.quorum_value}% quorum` : p.quorum_type === 'count' ? `${p.quorum_value} votes required` : '';

  // Proposal number
  if (proposalNumber) {
    const numDiv = document.createElement('div');
    numDiv.style.marginBottom = '4px';
    const numSpan = document.createElement('span');
    numSpan.style.cssText = 'font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;';
    numSpan.textContent = proposalNumber;
    numDiv.appendChild(numSpan);
    tile.appendChild(numDiv);
  }

  // Title (grayed for upcoming)
  const title = document.createElement('h4');
  title.style.cssText = 'margin:0 0 6px 0;font-weight:700;font-size:0.95rem;color:#9ca3af;';
  title.textContent = p.proposal_title || 'Untitled Proposal';
  tile.appendChild(title);

  // Badges
  const badgesDiv = document.createElement('div');
  badgesDiv.style.cssText = 'margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;';

  const upcomingBadge = document.createElement('span');
  upcomingBadge.style.cssText = 'display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);color:#000;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
  upcomingBadge.textContent = 'Upcoming';
  badgesDiv.appendChild(upcomingBadge);

  const catBadge = document.createElement('span');
  catBadge.style.cssText = `display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;`;
  catBadge.textContent = category;
  badgesDiv.appendChild(catBadge);

  if (quorumText) {
    const quorumBadge = document.createElement('span');
    quorumBadge.style.cssText = 'display:inline-block;background:#374151;color:#9ca3af;padding:4px 10px;border-radius:12px;font-size:0.7rem;';
    quorumBadge.textContent = quorumText;
    badgesDiv.appendChild(quorumBadge);
  }
  tile.appendChild(badgesDiv);

  // Dates
  const datesDiv = document.createElement('div');
  datesDiv.style.cssText = 'margin-bottom:8px;font-size:0.8rem;color:var(--gray);';
  const opensDiv = document.createElement('div');
  opensDiv.style.marginBottom = '4px';
  opensDiv.textContent = 'Opens: ' + opensDate;
  const closesDiv = document.createElement('div');
  closesDiv.textContent = 'Closes: ' + closesDate;
  datesDiv.append(opensDiv, closesDiv);
  tile.appendChild(datesDiv);

  // Created by
  const createdByDiv = document.createElement('div');
  createdByDiv.style.cssText = 'margin-bottom:8px;font-size:0.8rem;color:var(--gray);';
  createdByDiv.textContent = 'Created by: ' + createdBy;
  tile.appendChild(createdByDiv);

  // Time until opens
  const timeDiv = document.createElement('div');
  timeDiv.style.cssText = 'margin-bottom:8px;padding:8px;background:var(--bg-tertiary);border-radius:6px;text-align:center;';
  const timeSpan = document.createElement('span');
  timeSpan.style.cssText = 'font-size:0.85rem;color:var(--accent);font-weight:600;';
  timeSpan.textContent = 'Opens in ' + timeUntilOpens;
  timeDiv.appendChild(timeSpan);
  tile.appendChild(timeDiv);

  // View Proposal button
  const viewBtn = document.createElement('button');
  viewBtn.className = 'btn';
  viewBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#ffd93d 0%,#ffc125 100%);color:#000;font-weight:600;margin-bottom:8px;';
  viewBtn.textContent = 'View Proposal';
  viewBtn.dataset.toggleProposal = p.proposal_id;
  tile.appendChild(viewBtn);

  // Hidden text content
  const textDiv = document.createElement('div');
  textDiv.id = 'text-' + p.proposal_id;
  textDiv.style.cssText = 'display:none;padding:10px;background:var(--bg-input);border-left:3px solid var(--accent);border-radius:4px;margin-bottom:8px;line-height:1.6;font-size:0.85rem;';
  textDiv.textContent = p.proposal_text;
  tile.appendChild(textDiv);

  // View Analytics button
  const analyticsBtn = document.createElement('button');
  analyticsBtn.className = 'btn';
  analyticsBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;';
  analyticsBtn.textContent = 'View Analytics';
  analyticsBtn.dataset.analyticsProposal = p.proposal_id;
  analyticsBtn.dataset.analyticsTitle = p.proposal_title || 'Untitled Proposal';
  analyticsBtn.dataset.analyticsStatus = 'upcoming';
  tile.appendChild(analyticsBtn);

  return tile;
}

async function createClosedTile(p) {
  const tile = document.createElement('div');
  tile.style.cssText = 'background:var(--bg-card);border:1px solid #333;border-radius:8px;padding:12px;display:flex;flex-direction:column;min-height:100%;';

  const opensDate = formatDateTime(p.opens_at);
  const closesDate = formatDateTime(p.closes_at);
  const createdBy = p.created_by || 'Admin';
  const proposalNumber = p.proposal_number || '';
  const category = p.category || 'other';
  const categoryColors = { governance: '#8b5cf6', policy: '#3b82f6', budget: '#10b981', funding: '#ec4899', operational: '#f59e0b', other: '#6b7280' };
  const categoryColor = categoryColors[category] || '#6b7280';

  // Get pass/fail status
  let passed = p.passed;
  if (passed === undefined) {
    try {
      const data = await api(`/admin/proposals/${p.proposal_id}/vote-counts`);
      const yes = data.results?.yes || 0;
      const no = data.results?.no || 0;
      passed = yes > no;
    } catch (e) {
      console.error('Error fetching vote counts:', e);
    }
  }

  // Proposal number
  if (proposalNumber) {
    const numDiv = document.createElement('div');
    numDiv.style.marginBottom = '4px';
    const numSpan = document.createElement('span');
    numSpan.style.cssText = 'font-family:monospace;font-size:0.7rem;color:var(--gray);background:var(--bg-tertiary);padding:2px 6px;border-radius:4px;';
    numSpan.textContent = proposalNumber;
    numDiv.appendChild(numSpan);
    tile.appendChild(numDiv);
  }

  // Title with result badge
  const titleRow = document.createElement('div');
  titleRow.style.cssText = 'display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:6px;';
  const title = document.createElement('h4');
  title.style.cssText = 'margin:0;font-weight:700;font-size:0.95rem;';
  title.textContent = p.proposal_title || 'Untitled Proposal';
  titleRow.appendChild(title);

  if (passed !== undefined) {
    const resultBadge = document.createElement('span');
    resultBadge.style.cssText = `display:inline-block;background:linear-gradient(135deg,${passed ? '#10b981 0%,#059669' : '#ef4444 0%,#dc2626'} 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;`;
    resultBadge.textContent = passed ? 'PASSED' : 'FAILED';
    titleRow.appendChild(resultBadge);
  }
  tile.appendChild(titleRow);

  // Badges
  const badgesDiv = document.createElement('div');
  badgesDiv.style.cssText = 'margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;';

  const closedBadge = document.createElement('span');
  closedBadge.style.cssText = 'display:inline-block;background:linear-gradient(135deg,#6b7280 0%,#4b5563 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
  closedBadge.textContent = 'Closed';
  badgesDiv.appendChild(closedBadge);

  const catBadge = document.createElement('span');
  catBadge.style.cssText = `display:inline-block;background:${categoryColor};color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;text-transform:capitalize;`;
  catBadge.textContent = category;
  badgesDiv.appendChild(catBadge);

  // Show "Results Published" badge if merkle_root exists
  if (p.results_published_at) {
    const publishedBadge = document.createElement('span');
    publishedBadge.style.cssText = 'display:inline-block;background:linear-gradient(135deg,#8b5cf6 0%,#7c3aed 100%);color:#fff;padding:4px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;';
    publishedBadge.textContent = 'Verified';
    publishedBadge.title = 'Results published with Merkle proof';
    badgesDiv.appendChild(publishedBadge);
  }
  tile.appendChild(badgesDiv);

  // Dates
  const datesDiv = document.createElement('div');
  datesDiv.style.cssText = 'margin-bottom:8px;font-size:0.8rem;color:var(--gray);';
  const openedDiv = document.createElement('div');
  openedDiv.style.marginBottom = '4px';
  openedDiv.textContent = 'Opened: ' + opensDate;
  const closedDiv = document.createElement('div');
  closedDiv.textContent = 'Closed: ' + closesDate;
  datesDiv.append(openedDiv, closedDiv);
  tile.appendChild(datesDiv);

  // Merkle root display (if results published)
  if (p.merkle_root) {
    const merkleDiv = document.createElement('div');
    merkleDiv.style.cssText = 'margin-bottom:8px;padding:8px;background:var(--bg-tertiary);border-radius:6px;border-left:3px solid #8b5cf6;';

    const merkleLabel = document.createElement('div');
    merkleLabel.style.cssText = 'font-size:0.7rem;color:var(--gray);margin-bottom:4px;';
    merkleLabel.textContent = 'Merkle Root:';

    const merkleHash = document.createElement('div');
    merkleHash.style.cssText = 'font-family:monospace;font-size:0.65rem;color:#8b5cf6;word-break:break-all;';
    merkleHash.textContent = p.merkle_root;
    merkleHash.title = 'Click to copy';
    merkleHash.style.cursor = 'pointer';
    merkleHash.onclick = () => {
      navigator.clipboard.writeText(p.merkle_root);
      showToast('Merkle root copied to clipboard', 'success');
    };

    merkleDiv.append(merkleLabel, merkleHash);
    tile.appendChild(merkleDiv);
  }

  // Spacer for consistent button positioning
  const spacer = document.createElement('div');
  spacer.style.flexGrow = '1';
  tile.appendChild(spacer);

  // Publish Results button (if not yet published)
  if (!p.results_published_at) {
    const publishBtn = document.createElement('button');
    publishBtn.className = 'btn';
    publishBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#8b5cf6 0%,#7c3aed 100%);font-weight:600;margin-bottom:8px;';
    publishBtn.textContent = 'Publish Results';
    publishBtn.dataset.publishProposal = p.proposal_id;
    publishBtn.onclick = async () => {
      publishBtn.disabled = true;
      publishBtn.textContent = 'Publishing...';
      try {
        await publishVoteResults(p.proposal_id);
        showToast('Results published successfully!', 'success');
        await loadAllProposalsAdmin(); // Refresh to show updated tile
      } catch (e) {
        showToast('Failed to publish results: ' + (e.message || e), 'error');
        publishBtn.disabled = false;
        publishBtn.textContent = 'Publish Results';
      }
    };
    tile.appendChild(publishBtn);
  }

  // View Public Votes link (if results published)
  if (p.results_published_at) {
    const publicLink = document.createElement('a');
    publicLink.style.cssText = 'display:block;width:100%;padding:8px 12px;font-size:0.8rem;background:var(--bg-tertiary);border:1px solid #8b5cf6;color:#8b5cf6;font-weight:600;margin-bottom:8px;text-align:center;border-radius:6px;text-decoration:none;';
    publicLink.textContent = 'View Public Vote List';
    publicLink.href = `${config.apiUrl}/votes/${p.proposal_id}/published`;
    publicLink.target = '_blank';
    publicLink.rel = 'noopener noreferrer';
    tile.appendChild(publicLink);
  }

  // View Analytics button
  const analyticsBtn = document.createElement('button');
  analyticsBtn.className = 'btn';
  analyticsBtn.style.cssText = 'width:100%;padding:8px 12px;font-size:0.8rem;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);font-weight:600;';
  analyticsBtn.textContent = 'View Analytics';
  analyticsBtn.dataset.analyticsProposal = p.proposal_id;
  analyticsBtn.dataset.analyticsTitle = p.proposal_title || 'Untitled Proposal';
  analyticsBtn.dataset.analyticsStatus = 'closed';
  tile.appendChild(analyticsBtn);

  return tile;
}

// ============================================
// Toggle Proposal Text
// ============================================

export function toggleProposalText(proposalId) {
  const element = document.getElementById('text-' + proposalId);
  if (!element) return;

  const button = document.querySelector(`[data-toggle-proposal="${proposalId}"]`);
  if (element.style.display === 'none' || element.style.display === '') {
    element.style.display = 'block';
    if (button) button.textContent = 'Hide Proposal';
  } else {
    element.style.display = 'none';
    if (button) button.textContent = 'View Proposal';
  }
}

// ============================================
// Proposal Analytics
// ============================================

export async function openProposalAnalytics(proposalId, proposalTitle, status) {
  currentProposalAnalytics = { proposal_id: proposalId, title: proposalTitle, status };

  const titleEl = document.getElementById('analyticsProposalTitle');
  const statusEl = document.getElementById('analyticsProposalStatus');
  const modal = document.getElementById('proposalAnalyticsModal');

  if (titleEl) titleEl.textContent = proposalTitle;

  if (statusEl) {
    statusEl.replaceChildren();
    const badge = document.createElement('span');
    badge.style.cssText = 'display:inline-block;padding:4px 12px;border-radius:12px;font-size:0.75rem;font-weight:600;';
    if (status === 'active') {
      badge.style.background = 'linear-gradient(135deg,#10b981 0%,#059669 100%)';
      badge.style.color = '#fff';
      badge.textContent = 'Active';
    } else if (status === 'upcoming') {
      badge.style.background = 'linear-gradient(135deg,#f59e0b 0%,#d97706 100%)';
      badge.style.color = '#000';
      badge.textContent = 'Upcoming';
    } else {
      badge.style.background = 'linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)';
      badge.style.color = '#fff';
      badge.textContent = 'Closed';
    }
    statusEl.appendChild(badge);
  }

  if (modal) modal.classList.add('active');

  await loadProposalAnalytics(proposalId, status);
}

export async function loadProposalAnalytics(proposalId, status) {
  try {
    const token = idToken();
    const res = await fetch(`${config.apiUrl}/admin/proposals/${proposalId}/vote-counts`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const voteData = await res.json();
    const total = voteData.totalVotes || 0;
    const yes = voteData.results.yes || 0;
    const no = voteData.results.no || 0;
    const abstain = voteData.results.abstain || 0;

    const yesPercent = total > 0 ? Math.round((yes / total) * 100) : 0;
    const noPercent = total > 0 ? Math.round((no / total) * 100) : 0;
    const abstainPercent = total > 0 ? Math.round((abstain / total) * 100) : 0;
    const turnout = totalActiveSubscribers > 0 ? Math.round((total / totalActiveSubscribers) * 100) : 0;

    // Update stats
    const totalVotesEl = document.getElementById('analyticsTotalVotes');
    const turnoutEl = document.getElementById('analyticsTurnout');
    if (totalVotesEl) totalVotesEl.textContent = total.toLocaleString();
    if (turnoutEl) turnoutEl.textContent = turnout + '%';

    // Show result for closed proposals
    const resultCard = document.getElementById('analyticsResultCard');
    const resultText = document.getElementById('analyticsResult');
    if (status === 'closed' && resultCard && resultText) {
      const passed = yes > no;
      resultCard.style.display = 'block';
      resultText.textContent = passed ? 'PASSED' : 'FAILED';
      resultText.style.color = passed ? '#10b981' : '#ef4444';
    } else if (resultCard) {
      resultCard.style.display = 'none';
    }

    // Update vote counts
    const yesCountEl = document.getElementById('analyticsYesCount');
    const noCountEl = document.getElementById('analyticsNoCount');
    const abstainCountEl = document.getElementById('analyticsAbstainCount');
    if (yesCountEl) yesCountEl.textContent = `${yes} (${yesPercent}%)`;
    if (noCountEl) noCountEl.textContent = `${no} (${noPercent}%)`;
    if (abstainCountEl) abstainCountEl.textContent = `${abstain} (${abstainPercent}%)`;

    // Update progress bars
    const yesBar = document.querySelector('#analyticsYesBar > div');
    const noBar = document.querySelector('#analyticsNoBar > div');
    const abstainBar = document.querySelector('#analyticsAbstainBar > div');
    if (yesBar) yesBar.style.width = `${yesPercent}%`;
    if (noBar) noBar.style.width = `${noPercent}%`;
    if (abstainBar) abstainBar.style.width = `${abstainPercent}%`;

    // Handle Merkle verification section for closed proposals
    const merkleSection = document.getElementById('analyticsMerkleSection');
    if (status === 'closed') {
      // Try to fetch published vote data for Merkle information
      try {
        const publishedRes = await fetch(`${config.apiUrl}/votes/${proposalId}/published`);
        if (publishedRes.ok) {
          const publishedData = await publishedRes.json();
          if (publishedData.merkle_root) {
            // Show Merkle section
            if (merkleSection) {
              merkleSection.style.display = 'block';
            } else {
              // Create Merkle section if it doesn't exist
              createMerkleSection(proposalId, publishedData);
            }
            updateMerkleSection(proposalId, publishedData);
          } else if (merkleSection) {
            merkleSection.style.display = 'none';
          }
        } else if (merkleSection) {
          merkleSection.style.display = 'none';
        }
      } catch (err) {
        console.log('Published vote data not available yet:', err);
        if (merkleSection) merkleSection.style.display = 'none';
      }
    } else if (merkleSection) {
      merkleSection.style.display = 'none';
    }

    const msgEl = document.getElementById('analyticsMsg');
    if (msgEl) msgEl.textContent = '';

  } catch (e) {
    console.error('Error loading proposal analytics:', e);
    const msgEl = document.getElementById('analyticsMsg');
    if (msgEl) {
      msgEl.textContent = 'Error loading analytics: ' + (e.message || e);
      msgEl.style.color = '#ef4444';
    }
  }
}

function createMerkleSection(proposalId, publishedData) {
  const modal = document.getElementById('proposalAnalyticsModal');
  if (!modal) return;

  const content = modal.querySelector('.modal-content');
  if (!content) return;

  const section = document.createElement('div');
  section.id = 'analyticsMerkleSection';
  section.style.cssText = 'margin-top:16px;padding:16px;background:var(--bg-tertiary);border-radius:8px;border-left:3px solid #8b5cf6;';

  // Insert before the close button
  const closeBtn = content.querySelector('[data-close-modal]');
  if (closeBtn) {
    content.insertBefore(section, closeBtn);
  } else {
    content.appendChild(section);
  }
}

function updateMerkleSection(proposalId, publishedData) {
  const section = document.getElementById('analyticsMerkleSection');
  if (!section) return;

  section.replaceChildren();

  // Header
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:12px;';

  const verifiedIcon = document.createElement('span');
  verifiedIcon.style.cssText = 'color:#8b5cf6;font-size:1.2rem;';
  verifiedIcon.textContent = '\u2713';

  const title = document.createElement('span');
  title.style.cssText = 'font-weight:600;color:#8b5cf6;';
  title.textContent = 'Cryptographically Verified Results';

  header.append(verifiedIcon, title);
  section.appendChild(header);

  // Description
  const desc = document.createElement('p');
  desc.style.cssText = 'font-size:0.8rem;color:var(--gray);margin-bottom:12px;';
  desc.textContent = 'Votes are signed by member vaults and published to a public bulletin board. Anyone can verify the results using the Merkle root hash.';
  section.appendChild(desc);

  // Merkle root
  const merkleRow = document.createElement('div');
  merkleRow.style.cssText = 'margin-bottom:12px;';

  const merkleLabel = document.createElement('div');
  merkleLabel.style.cssText = 'font-size:0.75rem;color:var(--gray);margin-bottom:4px;';
  merkleLabel.textContent = 'Merkle Root:';

  const merkleHash = document.createElement('div');
  merkleHash.style.cssText = 'font-family:monospace;font-size:0.7rem;color:#8b5cf6;word-break:break-all;cursor:pointer;padding:8px;background:var(--bg-card);border-radius:4px;';
  merkleHash.textContent = publishedData.merkle_root;
  merkleHash.title = 'Click to copy';
  merkleHash.onclick = () => {
    navigator.clipboard.writeText(publishedData.merkle_root);
    showToast('Merkle root copied to clipboard', 'success');
  };

  merkleRow.append(merkleLabel, merkleHash);
  section.appendChild(merkleRow);

  // Published timestamp
  if (publishedData.results_published_at) {
    const publishedRow = document.createElement('div');
    publishedRow.style.cssText = 'font-size:0.75rem;color:var(--gray);margin-bottom:12px;';
    publishedRow.textContent = 'Published: ' + new Date(publishedData.results_published_at).toLocaleString();
    section.appendChild(publishedRow);
  }

  // Vault votes count
  if (publishedData.vault_votes !== undefined) {
    const vaultRow = document.createElement('div');
    vaultRow.style.cssText = 'font-size:0.8rem;margin-bottom:12px;';
    const vaultBadge = document.createElement('span');
    vaultBadge.style.cssText = 'background:#8b5cf6;color:#fff;padding:4px 8px;border-radius:4px;font-size:0.7rem;';
    vaultBadge.textContent = `${publishedData.vault_votes} vault-signed votes`;
    vaultRow.appendChild(vaultBadge);
    section.appendChild(vaultRow);
  }

  // View public vote list button
  const linkRow = document.createElement('div');
  linkRow.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';

  const publicLink = document.createElement('a');
  publicLink.style.cssText = 'display:inline-block;padding:8px 16px;font-size:0.8rem;background:var(--bg-card);border:1px solid #8b5cf6;color:#8b5cf6;font-weight:600;border-radius:6px;text-decoration:none;';
  publicLink.textContent = 'View Public Vote List';
  publicLink.href = `${config.apiUrl}/votes/${proposalId}/published?include_votes=true`;
  publicLink.target = '_blank';
  publicLink.rel = 'noopener noreferrer';

  linkRow.appendChild(publicLink);
  section.appendChild(linkRow);
}

export function closeProposalAnalyticsModal() {
  const modal = document.getElementById('proposalAnalyticsModal');
  if (modal) modal.classList.remove('active');
  currentProposalAnalytics = null;
}

// ============================================
// Publish Vote Results
// ============================================

export async function publishVoteResults(proposalId) {
  const response = await api(`/admin/proposals/${proposalId}/publish-results`, {
    method: 'POST'
  });
  return response;
}

// ============================================
// Create Proposal
// ============================================

export async function createProposal() {
  const title = document.getElementById('proposalTitle')?.value.trim();
  const text = document.getElementById('proposalText')?.value.trim();
  const openDate = document.getElementById('proposalOpenDate')?.value;
  const closeDate = document.getElementById('proposalCloseDate')?.value;
  const msgEl = document.getElementById('proposalMsg');

  if (!title) { showFieldError(msgEl, 'Please enter a proposal title'); return; }
  if (!text) { showFieldError(msgEl, 'Please enter proposal text'); return; }
  if (!openDate || !closeDate) { showFieldError(msgEl, 'Please select opening and closing date/time'); return; }

  const openDateTime = new Date(openDate);
  const closeDateTime = new Date(closeDate);
  const now = new Date();

  if (openDateTime < now) { showFieldError(msgEl, 'Opening date/time must be in the future'); return; }
  if (closeDateTime <= openDateTime) { showFieldError(msgEl, 'Closing date/time must be after opening date/time'); return; }

  const category = document.getElementById('proposalCategory')?.value;
  const quorumType = document.getElementById('proposalQuorumType')?.value;
  const quorumValueEl = document.getElementById('proposalQuorumValue');
  const quorumValue = quorumType !== 'none' ? parseInt(quorumValueEl?.value, 10) : 0;

  if (quorumType !== 'none' && (!quorumValue || quorumValue <= 0)) {
    showFieldError(msgEl, 'Please enter a valid quorum value');
    return;
  }

  try {
    await api('/admin/proposals', {
      method: 'POST',
      body: JSON.stringify({
        proposal_title: title,
        proposal_text: text,
        opens_at: openDateTime.toISOString(),
        closes_at: closeDateTime.toISOString(),
        category: category,
        quorum_type: quorumType,
        quorum_value: quorumValue
      })
    });
    showToast('Proposal created successfully!', 'success');

    // Clear form
    document.getElementById('proposalTitle').value = '';
    document.getElementById('proposalText').value = '';
    document.getElementById('proposalOpenDate').value = '';
    document.getElementById('proposalCloseDate').value = '';
    document.getElementById('proposalCategory').value = 'other';
    document.getElementById('proposalQuorumType').value = 'none';
    document.getElementById('proposalQuorumValue').value = '';
    toggleQuorumValue();

    closeCreateProposalModal();
    await loadAllProposalsAdmin();
  } catch (e) {
    showFieldError(msgEl, 'Error: ' + (e.message || e));
  }
}

export function closeCreateProposalModal() {
  const modal = document.getElementById('createProposalModal');
  if (modal) modal.classList.remove('active');
  const msgEl = document.getElementById('proposalMsg');
  if (msgEl) msgEl.textContent = '';
}

export function toggleQuorumValue() {
  const quorumType = document.getElementById('proposalQuorumType')?.value;
  const valueInput = document.getElementById('proposalQuorumValue');
  const valueLabel = document.getElementById('quorumValueLabel');
  if (quorumType === 'none') {
    if (valueInput) valueInput.style.display = 'none';
    if (valueLabel) valueLabel.style.display = 'none';
  } else {
    if (valueInput) valueInput.style.display = 'block';
    if (valueLabel) {
      valueLabel.style.display = 'flex';
      valueLabel.textContent = quorumType === 'percentage' ? '% of members' : 'votes required';
    }
  }
}

export function setProposalFilter(filter) {
  currentProposalFilter = filter;
  document.querySelectorAll('.proposal-filter').forEach(b => b.classList.remove('active'));
  const activeBtn = document.querySelector(`.proposal-filter[data-filter="${filter}"]`);
  if (activeBtn) activeBtn.classList.add('active');
  renderProposals();
}

// ============================================
// Helpers
// ============================================

function formatDateTime(isoString) {
  const date = new Date(isoString);
  const options = { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true };
  return date.toLocaleString('en-US', options);
}

function calculateTimeRemaining(targetDate) {
  const now = new Date();
  const target = new Date(targetDate);
  const diff = target - now;

  if (diff <= 0) return 'Closed';

  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

  if (days > 0) {
    return `${days} day${days > 1 ? 's' : ''} ${hours} hour${hours > 1 ? 's' : ''}`;
  } else if (hours > 0) {
    return `${hours} hour${hours > 1 ? 's' : ''} ${minutes} minute${minutes > 1 ? 's' : ''}`;
  } else {
    return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  }
}

function showFieldError(msgEl, message) {
  if (msgEl) {
    msgEl.textContent = message;
    msgEl.style.color = '#ef4444';
  }
}

// ============================================
// Missing Modal Exports
// ============================================

export function openCreateProposalModal() {
  const modal = document.getElementById('createProposalModal');
  if (modal) {
    const titleEl = document.getElementById('proposalTitle');
    const textEl = document.getElementById('proposalText');
    const categoryEl = document.getElementById('proposalCategory');
    const quorumEl = document.getElementById('proposalQuorumType');
    const quorumValueEl = document.getElementById('proposalQuorumValue');
    const openEl = document.getElementById('proposalOpenDate');
    const closeEl = document.getElementById('proposalCloseDate');

    if (titleEl) titleEl.value = '';
    if (textEl) textEl.value = '';
    if (categoryEl) categoryEl.value = 'other';
    if (quorumEl) quorumEl.value = 'none';
    if (quorumValueEl) quorumValueEl.value = '';
    if (openEl) openEl.value = '';
    if (closeEl) closeEl.value = '';

    // Reset quorum value input visibility
    toggleQuorumValue();

    // Initialize flatpickr date pickers if not already done
    initProposalDatePickers();

    modal.classList.add('active');
  }
}

// Initialize flatpickr for proposal date fields
let proposalDatePickersInitialized = false;
function initProposalDatePickers() {
  if (proposalDatePickersInitialized) return;
  if (typeof flatpickr === 'undefined') return;

  const baseConfig = {
    theme: 'dark',
    disableMobile: true,
    enableTime: true,
    dateFormat: 'Y-m-d H:i',
    time_24hr: true,
    minDate: 'today'
  };

  const openEl = document.getElementById('proposalOpenDate');
  const closeEl = document.getElementById('proposalCloseDate');

  if (openEl && !openEl._flatpickr) {
    flatpickr(openEl, baseConfig);
  }

  if (closeEl && !closeEl._flatpickr) {
    flatpickr(closeEl, baseConfig);
  }

  proposalDatePickersInitialized = true;
}

export function setupProposalEventHandlers() {
  // Proposal filter buttons - Vote Management tab
  const filterBtns = document.querySelectorAll('.proposal-filter');
  filterBtns.forEach(btn => {
    btn.onclick = () => {
      const filter = btn.dataset.filter;
      if (filter) setProposalFilter(filter);
    };
  });

  // Also set up by ID in case data-filter approach doesn't work
  const activeVotesBtn = document.getElementById('filterActiveVotes');
  const pendingVotesBtn = document.getElementById('filterPendingVotes');

  if (activeVotesBtn) {
    activeVotesBtn.onclick = () => setProposalFilter('active');
  }

  if (pendingVotesBtn) {
    pendingVotesBtn.onclick = () => setProposalFilter('upcoming');
  }

  // Create proposal button (opens modal)
  const toggleProposalForm = document.getElementById('toggleProposalForm');
  if (toggleProposalForm) {
    toggleProposalForm.onclick = () => openCreateProposalModal();
  }

  // Create proposal submit button
  const createProposalBtn = document.getElementById('createProposalBtn');
  if (createProposalBtn) {
    createProposalBtn.onclick = () => createProposal();
  }
}
