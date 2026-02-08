// VettID Published Votes Page
// External script to comply with CSP

(function() {
  'use strict';

  // State
  let proposals = [];
  let currentProposal = null;

  // DOM elements
  const listView = document.getElementById('listView');
  const detailView = document.getElementById('detailView');
  const loadingState = document.getElementById('loadingState');
  const errorState = document.getElementById('errorState');
  const emptyState = document.getElementById('emptyState');
  const proposalList = document.getElementById('proposalList');
  const detailContent = document.getElementById('detailContent');
  const backBtn = document.getElementById('backBtn');

  // API base URL from config
  const API_URL = window.VettIDConfig?.apiUrl || '';

  // Utility: format date
  function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const d = new Date(isoString);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  // Utility: create element with text
  function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  // Show error
  function showError(message) {
    loadingState.style.display = 'none';
    emptyState.style.display = 'none';
    proposalList.style.display = 'none';
    errorState.textContent = message;
    errorState.style.display = 'block';
  }

  // Show empty state
  function showEmpty() {
    loadingState.style.display = 'none';
    errorState.style.display = 'none';
    proposalList.style.display = 'none';
    emptyState.style.display = 'block';
  }

  // Render proposal card
  function renderProposalCard(proposal) {
    const card = createEl('div', 'proposal-card');
    card.setAttribute('data-id', proposal.proposal_id);

    // Header
    const header = createEl('div', 'proposal-header');
    const number = createEl('span', 'proposal-number', '#' + (proposal.proposal_number || '—'));
    const date = createEl('span', 'proposal-date', 'Published: ' + formatDate(proposal.results_published_at));
    header.appendChild(number);
    header.appendChild(date);
    card.appendChild(header);

    // Title
    const title = createEl('h3', 'proposal-title', proposal.proposal_title || 'Untitled Proposal');
    card.appendChild(title);

    // Description
    if (proposal.proposal_description) {
      const desc = createEl('p', 'proposal-desc', proposal.proposal_description);
      card.appendChild(desc);
    }

    // Vote summary
    const voteSummary = createEl('div', 'vote-summary');
    const voteCounts = proposal.vote_counts || {};
    const countsObj = voteCounts.counts || voteCounts;
    const choices = proposal.choices || null;

    // Build stats dynamically from choices or fall back to yes/no/abstain
    var stats = [];
    if (choices && choices.length >= 2) {
      choices.forEach(function(c) {
        stats.push({ cls: c.id, label: c.label, value: countsObj[c.id] || 0 });
      });
    } else {
      stats.push({ cls: 'yes', label: 'Yes', value: countsObj.yes || 0 });
      stats.push({ cls: 'no', label: 'No', value: countsObj.no || 0 });
      stats.push({ cls: 'abstain', label: 'Abstain', value: countsObj.abstain || 0 });
    }
    stats.push({ cls: 'total', label: 'Total', value: proposal.total_votes || 0 });

    stats.forEach(function(s) {
      const stat = createEl('div', 'vote-stat ' + s.cls);
      const label = createEl('span', 'label', s.label + ':');
      const value = createEl('span', 'value', String(s.value));
      stat.appendChild(label);
      stat.appendChild(value);
      voteSummary.appendChild(stat);
    });

    card.appendChild(voteSummary);

    // Click handler
    card.addEventListener('click', function() {
      showDetail(proposal);
    });

    return card;
  }

  // Render proposals list
  function renderProposals() {
    loadingState.style.display = 'none';
    errorState.style.display = 'none';

    if (proposals.length === 0) {
      showEmpty();
      return;
    }

    emptyState.style.display = 'none';
    proposalList.style.display = 'flex';

    // Clear existing
    while (proposalList.firstChild) {
      proposalList.removeChild(proposalList.firstChild);
    }

    // Add cards
    proposals.forEach(function(p) {
      proposalList.appendChild(renderProposalCard(p));
    });
  }

  // Show detail view
  function showDetail(proposal) {
    currentProposal = proposal;
    listView.classList.add('hidden');
    detailView.classList.add('active');

    // Clear existing content
    while (detailContent.firstChild) {
      detailContent.removeChild(detailContent.firstChild);
    }

    // Main card
    const card = createEl('div', 'detail-card');

    // Header with number
    const header = createEl('div', 'proposal-header');
    const number = createEl('span', 'proposal-number', '#' + (proposal.proposal_number || '—'));
    header.appendChild(number);
    card.appendChild(header);

    // Title
    const title = createEl('h2', 'detail-title', proposal.proposal_title || 'Untitled Proposal');
    card.appendChild(title);

    // Meta info
    const meta = createEl('div', 'detail-meta');
    const metaItems = [
      { label: 'Status', value: proposal.status || 'closed' },
      { label: 'Voting Opened', value: formatDate(proposal.opens_at) },
      { label: 'Voting Closed', value: formatDate(proposal.closes_at) },
      { label: 'Results Published', value: formatDate(proposal.results_published_at) }
    ];
    metaItems.forEach(function(item) {
      const span = createEl('span', '', item.label + ': ' + item.value);
      meta.appendChild(span);
    });
    card.appendChild(meta);

    // Description
    if (proposal.proposal_description) {
      const desc = createEl('p', 'detail-description', proposal.proposal_description);
      card.appendChild(desc);
    }

    detailContent.appendChild(card);

    // Results section
    const resultsSection = createEl('div', 'detail-card results-section');
    const resultsTitle = createEl('h3', '', 'Voting Results');
    resultsSection.appendChild(resultsTitle);

    var detailVoteCounts = proposal.vote_counts || {};
    var detailCountsObj = detailVoteCounts.counts || detailVoteCounts;
    var detailChoices = proposal.choices || null;
    var total = proposal.total_votes || 0;
    if (!total && detailCountsObj) {
      var keys = Object.keys(detailCountsObj);
      for (var k = 0; k < keys.length; k++) {
        total += (detailCountsObj[keys[k]] || 0);
      }
    }

    // Build bars dynamically from choices or fall back to yes/no/abstain
    var detailBarColors = [
      '#10b981', '#ef4444', '#6b7280', '#3b82f6', '#8b5cf6',
      '#f59e0b', '#ec4899', '#14b8a6', '#f97316', '#06b6d4'
    ];
    var bars = [];
    if (detailChoices && detailChoices.length >= 2) {
      detailChoices.forEach(function(c, i) {
        bars.push({ cls: c.id, label: c.label, count: detailCountsObj[c.id] || 0, color: detailBarColors[i % detailBarColors.length] });
      });
    } else {
      bars.push({ cls: 'yes', label: 'Yes', count: detailCountsObj.yes || 0, color: null });
      bars.push({ cls: 'no', label: 'No', count: detailCountsObj.no || 0, color: null });
      bars.push({ cls: 'abstain', label: 'Abstain', count: detailCountsObj.abstain || 0, color: null });
    }

    bars.forEach(function(b) {
      const container = createEl('div', 'vote-bar-container');
      const labelDiv = createEl('div', 'vote-bar-label');
      const labelSpan = createEl('span', '', b.label);
      if (b.color) labelSpan.style.color = b.color;
      const pct = total > 0 ? Math.round((b.count / total) * 100) : 0;
      const valueSpan = createEl('span', '', b.count + ' (' + pct + '%)');
      labelDiv.appendChild(labelSpan);
      labelDiv.appendChild(valueSpan);
      container.appendChild(labelDiv);

      const bar = createEl('div', 'vote-bar');
      const fill = createEl('div', 'vote-bar-fill ' + b.cls);
      if (b.color) fill.style.background = b.color;
      fill.style.width = pct + '%';
      bar.appendChild(fill);
      container.appendChild(bar);

      resultsSection.appendChild(container);
    });

    // Total votes
    const totalDiv = createEl('p', '', 'Total votes cast: ' + total);
    totalDiv.style.marginTop = '16px';
    totalDiv.style.fontWeight = '600';
    resultsSection.appendChild(totalDiv);

    detailContent.appendChild(resultsSection);

    // Merkle verification section
    if (proposal.merkle_root) {
      const merkleCard = createEl('div', 'detail-card');
      const merkleSection = createEl('div', 'merkle-section');

      const merkleTitle = createEl('h4', '', 'Cryptographic Verification');
      merkleSection.appendChild(merkleTitle);

      const rootLabel = createEl('p', '', 'Merkle Root:');
      rootLabel.style.marginBottom = '6px';
      rootLabel.style.fontSize = '0.85rem';
      rootLabel.style.color = 'var(--text-dim)';
      merkleSection.appendChild(rootLabel);

      const rootValue = createEl('div', 'merkle-root', proposal.merkle_root);
      merkleSection.appendChild(rootValue);

      const info = createEl('p', 'merkle-info',
        'This Merkle root can be used to verify the integrity of the vote results. ' +
        'Each vote is cryptographically signed by the voter\'s vault and included in the Merkle tree. ' +
        'Members can verify their vote was counted by checking their Merkle proof.'
      );
      merkleSection.appendChild(info);

      // Load votes button
      const loadBtn = createEl('button', 'load-votes-btn', 'Load Individual Votes');
      loadBtn.addEventListener('click', function() {
        loadVotes(proposal.proposal_id, loadBtn);
      });
      merkleSection.appendChild(loadBtn);

      // Votes list container
      const votesList = createEl('div', 'votes-list');
      votesList.id = 'votesList';
      votesList.style.display = 'none';
      merkleSection.appendChild(votesList);

      merkleCard.appendChild(merkleSection);
      detailContent.appendChild(merkleCard);
    }

    // Update URL
    history.pushState({ proposal_id: proposal.proposal_id }, '', '?id=' + proposal.proposal_id);
  }

  // Load individual votes
  function loadVotes(proposalId, button) {
    button.disabled = true;
    button.textContent = 'Loading...';

    fetch(API_URL + '/votes/' + proposalId + '/published')
      .then(function(res) {
        if (!res.ok) throw new Error('Failed to load votes');
        return res.json();
      })
      .then(function(data) {
        const votesList = document.getElementById('votesList');
        while (votesList.firstChild) {
          votesList.removeChild(votesList.firstChild);
        }

        const title = createEl('h4', '', 'Individual Votes (' + (data.votes?.length || 0) + ')');
        votesList.appendChild(title);

        if (data.votes && data.votes.length > 0) {
          const table = document.createElement('table');
          table.className = 'votes-table';

          const thead = document.createElement('thead');
          const headerRow = document.createElement('tr');
          ['Voting Public Key', 'Vote', 'Verified'].forEach(function(h) {
            const th = createEl('th', '', h);
            headerRow.appendChild(th);
          });
          thead.appendChild(headerRow);
          table.appendChild(thead);

          const tbody = document.createElement('tbody');
          data.votes.forEach(function(v) {
            const row = document.createElement('tr');

            const keyCell = createEl('td', 'pubkey', v.voting_public_key || 'N/A');
            keyCell.title = v.voting_public_key || '';
            row.appendChild(keyCell);

            const voteCell = createEl('td', '', v.vote || 'N/A');
            row.appendChild(voteCell);

            const verifiedCell = createEl('td', '', v.vote_signature ? 'Signed' : 'N/A');
            row.appendChild(verifiedCell);

            tbody.appendChild(row);
          });
          table.appendChild(tbody);
          votesList.appendChild(table);
        } else {
          const noVotes = createEl('p', '', 'No individual vote data available.');
          votesList.appendChild(noVotes);
        }

        votesList.style.display = 'block';
        button.style.display = 'none';
      })
      .catch(function(err) {
        console.error('Error loading votes:', err);
        button.textContent = 'Failed to load - Retry';
        button.disabled = false;
      });
  }

  // Show list view
  function showList() {
    detailView.classList.remove('active');
    listView.classList.remove('hidden');
    currentProposal = null;
    history.pushState({}, '', window.location.pathname);
  }

  // Back button handler
  if (backBtn) {
    backBtn.addEventListener('click', showList);
  }

  // Handle browser back/forward
  window.addEventListener('popstate', function(e) {
    if (e.state && e.state.proposal_id) {
      const p = proposals.find(function(x) {
        return x.proposal_id === e.state.proposal_id;
      });
      if (p) showDetail(p);
    } else {
      showList();
    }
  });

  // Load proposals
  function loadProposals() {
    fetch(API_URL + '/votes')
      .then(function(res) {
        if (!res.ok) throw new Error('Failed to fetch proposals');
        return res.json();
      })
      .then(function(data) {
        proposals = data.proposals || [];
        renderProposals();

        // Check for proposal_id in URL
        const params = new URLSearchParams(window.location.search);
        const id = params.get('id');
        if (id) {
          const p = proposals.find(function(x) {
            return x.proposal_id === id;
          });
          if (p) showDetail(p);
        }
      })
      .catch(function(err) {
        console.error('Error loading proposals:', err);
        showError('Unable to load published votes. Please try again later.');
      });
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadProposals);
  } else {
    loadProposals();
  }
})();
