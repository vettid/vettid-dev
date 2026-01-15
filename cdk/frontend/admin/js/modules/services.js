/**
 * Services Module
 *
 * Manages service definitions (external integrations, service catalog)
 * including CRUD operations, status management, and filtering.
 */

import { api, showToast, escapeHtml, showLoadingSkeleton } from './core.js';

// ─────────────────────────────────────────────────────────────────────────────
// Module State
// ─────────────────────────────────────────────────────────────────────────────

let servicesData = [];
let serviceStatusFilter = 'all';
let serviceTypeFilter = 'all';
let serviceSearchTerm = '';
let currentServiceId = null;
let isEditingService = false;

// ─────────────────────────────────────────────────────────────────────────────
// Load Services
// ─────────────────────────────────────────────────────────────────────────────

export async function loadServices() {
  try {
    showLoadingSkeleton('servicesTable');
    const res = await api('/admin/services');
    servicesData = res.services || [];
    renderServices();
  } catch (err) {
    console.error('Error loading services:', err);
    showToast('Failed to load services', 'error');
    const tbody = document.getElementById('servicesTableBody');
    if (tbody) {
      tbody.replaceChildren();
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 7;
      cell.style.cssText = 'text-align:center;color:#f44;padding:2rem;';
      cell.textContent = 'Failed to load services. Please try again.';
      row.appendChild(cell);
      tbody.appendChild(row);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Render Services Table
// ─────────────────────────────────────────────────────────────────────────────

export function renderServices() {
  const tbody = document.getElementById('servicesTableBody');
  if (!tbody) return;

  let filtered = servicesData;

  // Apply status filter
  if (serviceStatusFilter !== 'all') {
    filtered = filtered.filter(s => s.status === serviceStatusFilter);
  }

  // Apply type filter
  if (serviceTypeFilter !== 'all') {
    filtered = filtered.filter(s => s.service_type === serviceTypeFilter);
  }

  // Apply search
  if (serviceSearchTerm) {
    const term = serviceSearchTerm.toLowerCase();
    filtered = filtered.filter(s =>
      (s.name || '').toLowerCase().includes(term) ||
      (s.description || '').toLowerCase().includes(term) ||
      (s.service_id || '').toLowerCase().includes(term)
    );
  }

  tbody.replaceChildren();

  if (filtered.length === 0) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 7;
    cell.style.cssText = 'text-align:center;color:var(--gray);padding:2rem;';
    cell.textContent = 'No results';
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  filtered.forEach(service => {
    const row = createServiceRow(service);
    tbody.appendChild(row);
  });
}

function createServiceRow(service) {
  const statusClass = service.status === 'active' ? 'status-active' :
                      service.status === 'coming-soon' ? 'status-pending' : 'status-rejected';
  const statusText = service.status === 'coming-soon' ? 'Coming Soon' :
                     service.status.charAt(0).toUpperCase() + service.status.slice(1);
  const typeLabel = (service.service_type || 'other').charAt(0).toUpperCase() + (service.service_type || 'other').slice(1);

  const row = document.createElement('tr');
  row.dataset.action = 'service-details';
  row.dataset.serviceId = service.service_id;
  row.style.cursor = 'pointer';

  // Name/ID cell with icon
  const nameCell = document.createElement('td');
  const nameContainer = document.createElement('div');
  nameContainer.style.cssText = 'display:flex;align-items:center;gap:0.75rem;';

  if (service.icon_url) {
    const icon = document.createElement('img');
    icon.src = service.icon_url;
    icon.alt = '';
    icon.style.cssText = 'width:32px;height:32px;border-radius:6px;object-fit:cover;';
    nameContainer.appendChild(icon);
  } else {
    const iconPlaceholder = document.createElement('div');
    iconPlaceholder.style.cssText = 'width:32px;height:32px;border-radius:6px;background:var(--light);display:flex;align-items:center;justify-content:center;font-weight:600;color:var(--gray);';
    iconPlaceholder.textContent = (service.name || '?').charAt(0).toUpperCase();
    nameContainer.appendChild(iconPlaceholder);
  }

  const nameInfo = document.createElement('div');
  const nameText = document.createElement('div');
  nameText.style.fontWeight = '500';
  nameText.textContent = service.name || 'Unnamed';
  const idText = document.createElement('div');
  idText.style.cssText = 'font-size:0.75rem;color:var(--gray);';
  idText.textContent = service.service_id;
  nameInfo.appendChild(nameText);
  nameInfo.appendChild(idText);
  nameContainer.appendChild(nameInfo);
  nameCell.appendChild(nameContainer);
  row.appendChild(nameCell);

  // Type cell
  const typeCell = document.createElement('td');
  const typeBadge = document.createElement('span');
  typeBadge.className = 'badge';
  typeBadge.style.cssText = 'background:var(--light);color:var(--dark);';
  typeBadge.textContent = typeLabel;
  typeCell.appendChild(typeBadge);
  row.appendChild(typeCell);

  // Status cell
  const statusCell = document.createElement('td');
  const statusBadge = document.createElement('span');
  statusBadge.className = `status-badge ${statusClass}`;
  statusBadge.textContent = statusText;
  statusCell.appendChild(statusBadge);
  row.appendChild(statusCell);

  // Connections cell
  const connectionsCell = document.createElement('td');
  connectionsCell.textContent = service.connect_count || 0;
  row.appendChild(connectionsCell);

  // Updated cell
  const updatedCell = document.createElement('td');
  updatedCell.textContent = service.updated_at ? new Date(service.updated_at).toLocaleDateString() : '-';
  row.appendChild(updatedCell);

  // Actions cell
  const actionsCell = document.createElement('td');
  actionsCell.dataset.action = 'stop-propagation';

  const dropdown = document.createElement('div');
  dropdown.className = 'dropdown';
  dropdown.style.position = 'relative';

  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'btn btn-secondary btn-sm dropdown-toggle';
  toggleBtn.dataset.action = 'toggle-service-dropdown';
  toggleBtn.textContent = 'Actions';
  dropdown.appendChild(toggleBtn);

  const menu = document.createElement('div');
  menu.className = 'dropdown-menu';
  menu.style.cssText = 'display:none;position:absolute;right:0;top:100%;background:white;border:1px solid var(--border);border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);min-width:140px;z-index:100;';

  // Edit action
  const editLink = document.createElement('a');
  editLink.href = '#';
  editLink.dataset.action = 'service-edit';
  editLink.dataset.serviceId = service.service_id;
  editLink.style.cssText = 'display:block;padding:0.5rem 1rem;color:var(--dark);text-decoration:none;';
  editLink.textContent = 'Edit';
  menu.appendChild(editLink);

  // Toggle status action
  const toggleLink = document.createElement('a');
  toggleLink.href = '#';
  toggleLink.dataset.action = 'service-toggle-status';
  toggleLink.dataset.serviceId = service.service_id;
  toggleLink.dataset.newStatus = service.status === 'active' ? 'deprecated' : 'active';
  toggleLink.style.cssText = 'display:block;padding:0.5rem 1rem;color:var(--dark);text-decoration:none;';
  toggleLink.textContent = service.status === 'active' ? 'Deprecate' : 'Activate';
  menu.appendChild(toggleLink);

  // Delete action
  const deleteLink = document.createElement('a');
  deleteLink.href = '#';
  deleteLink.dataset.action = 'service-delete';
  deleteLink.dataset.serviceId = service.service_id;
  deleteLink.style.cssText = 'display:block;padding:0.5rem 1rem;color:#ef4444;text-decoration:none;';
  deleteLink.textContent = 'Delete';
  menu.appendChild(deleteLink);

  dropdown.appendChild(menu);
  actionsCell.appendChild(dropdown);
  row.appendChild(actionsCell);

  return row;
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Modal (Add/Edit)
// ─────────────────────────────────────────────────────────────────────────────

export function toggleServiceDropdown(btn, event) {
  event.stopPropagation();
  const menu = btn.nextElementSibling;
  const wasVisible = menu.style.display === 'block';

  // Close all dropdowns first
  document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');

  if (!wasVisible) {
    menu.style.display = 'block';
    setTimeout(() => {
      document.addEventListener('click', function closeDropdown() {
        menu.style.display = 'none';
        document.removeEventListener('click', closeDropdown);
      }, { once: true });
    }, 0);
  }
}

export function openServiceModal(editing = false) {
  isEditingService = editing;
  const modal = document.getElementById('serviceModal');
  const title = document.getElementById('serviceModalTitle');
  const form = document.getElementById('serviceForm');

  title.textContent = editing ? 'Edit Service' : 'Add New Service';

  if (!editing) {
    form.reset();
    currentServiceId = null;
    document.getElementById('serviceIdInput').disabled = false;
  }

  modal.classList.add('active');
}

export function openEditServiceModal(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;
  isEditingService = true;

  document.getElementById('serviceIdInput').value = service.service_id;
  document.getElementById('serviceIdInput').disabled = true;
  document.getElementById('serviceNameInput').value = service.name || '';
  document.getElementById('serviceDescInput').value = service.description || '';
  document.getElementById('serviceTypeSelect').value = service.service_type || 'other';
  document.getElementById('serviceStatusSelect').value = service.status || 'active';
  document.getElementById('serviceIconInput').value = service.icon_url || '';
  document.getElementById('serviceWebsiteInput').value = service.website_url || '';
  document.getElementById('serviceConnectInput').value = service.connect_url || '';
  document.getElementById('serviceOrderInput').value = service.sort_order || 100;
  document.getElementById('serviceDataKeysInput').value = (service.required_user_data || []).join(', ');

  document.getElementById('serviceModalTitle').textContent = 'Edit Service';
  document.getElementById('serviceModal').classList.add('active');
}

export function closeServiceModal() {
  document.getElementById('serviceModal').classList.remove('active');
  currentServiceId = null;
  isEditingService = false;
}

export async function saveService() {
  const serviceId = document.getElementById('serviceIdInput').value.trim();
  const name = document.getElementById('serviceNameInput').value.trim();
  const description = document.getElementById('serviceDescInput').value.trim();
  const serviceType = document.getElementById('serviceTypeSelect').value;
  const status = document.getElementById('serviceStatusSelect').value;
  const iconUrl = document.getElementById('serviceIconInput').value.trim();
  const websiteUrl = document.getElementById('serviceWebsiteInput').value.trim();
  const connectUrl = document.getElementById('serviceConnectInput').value.trim();
  const sortOrder = parseInt(document.getElementById('serviceOrderInput').value) || 100;
  const dataKeysStr = document.getElementById('serviceDataKeysInput').value.trim();
  const requiredUserData = dataKeysStr ? dataKeysStr.split(',').map(s => s.trim()).filter(s => s) : [];

  if (!serviceId || !name) {
    showToast('Service ID and Name are required', 'error');
    return;
  }

  const payload = {
    service_id: serviceId,
    name,
    description,
    service_type: serviceType,
    status,
    icon_url: iconUrl || undefined,
    website_url: websiteUrl || undefined,
    connect_url: connectUrl || undefined,
    sort_order: sortOrder,
    required_user_data: requiredUserData.length > 0 ? requiredUserData : undefined
  };

  try {
    if (isEditingService) {
      await api('/admin/services', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      showToast('Service updated successfully', 'success');
    } else {
      await api('/admin/services', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      showToast('Service created successfully', 'success');
    }
    closeServiceModal();
    loadServices();
  } catch (err) {
    console.error('Error saving service:', err);
    showToast('Failed to save service: ' + err.message, 'error');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Details Modal
// ─────────────────────────────────────────────────────────────────────────────

export function openServiceDetails(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;

  const statusClass = service.status === 'active' ? 'status-active' :
                      service.status === 'coming-soon' ? 'status-pending' : 'status-rejected';
  const statusText = service.status === 'coming-soon' ? 'Coming Soon' :
                     service.status.charAt(0).toUpperCase() + service.status.slice(1);
  const typeLabel = (service.service_type || 'other').charAt(0).toUpperCase() + (service.service_type || 'other').slice(1);

  const content = document.getElementById('serviceDetailsContent');
  content.replaceChildren();

  // Header with icon and name
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;';

  if (service.icon_url) {
    const icon = document.createElement('img');
    icon.src = service.icon_url;
    icon.alt = '';
    icon.style.cssText = 'width:64px;height:64px;border-radius:12px;object-fit:cover;';
    header.appendChild(icon);
  } else {
    const iconPlaceholder = document.createElement('div');
    iconPlaceholder.style.cssText = 'width:64px;height:64px;border-radius:12px;background:var(--light);display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:600;color:var(--gray);';
    iconPlaceholder.textContent = (service.name || '?').charAt(0).toUpperCase();
    header.appendChild(iconPlaceholder);
  }

  const headerInfo = document.createElement('div');
  const headerName = document.createElement('h3');
  headerName.style.cssText = 'margin:0;font-size:1.25rem;';
  headerName.textContent = service.name || 'Unnamed Service';
  const headerId = document.createElement('div');
  headerId.style.cssText = 'color:var(--gray);font-size:0.875rem;';
  headerId.textContent = service.service_id;
  headerInfo.appendChild(headerName);
  headerInfo.appendChild(headerId);
  header.appendChild(headerInfo);
  content.appendChild(header);

  // Stats grid
  const statsGrid = document.createElement('div');
  statsGrid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem;';

  // Status
  const statusBox = createDetailBox('Status');
  const statusBadge = document.createElement('span');
  statusBadge.className = `status-badge ${statusClass}`;
  statusBadge.textContent = statusText;
  statusBox.appendChild(statusBadge);
  statsGrid.appendChild(statusBox);

  // Type
  const typeBox = createDetailBox('Type');
  const typeBadge = document.createElement('span');
  typeBadge.className = 'badge';
  typeBadge.style.cssText = 'background:var(--light);color:var(--dark);';
  typeBadge.textContent = typeLabel;
  typeBox.appendChild(typeBadge);
  statsGrid.appendChild(typeBox);

  // Connections
  const connectionsBox = createDetailBox('Connections');
  const connectionsValue = document.createElement('div');
  connectionsValue.style.fontWeight = '500';
  connectionsValue.textContent = service.connect_count || 0;
  connectionsBox.appendChild(connectionsValue);
  statsGrid.appendChild(connectionsBox);

  // Sort Order
  const orderBox = createDetailBox('Sort Order');
  const orderValue = document.createElement('div');
  orderValue.style.fontWeight = '500';
  orderValue.textContent = service.sort_order || 100;
  orderBox.appendChild(orderValue);
  statsGrid.appendChild(orderBox);

  content.appendChild(statsGrid);

  // Description
  if (service.description) {
    const descSection = document.createElement('div');
    descSection.style.marginBottom = '1.5rem';
    const descLabel = document.createElement('div');
    descLabel.style.cssText = 'color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;';
    descLabel.textContent = 'Description';
    const descText = document.createElement('div');
    descText.textContent = service.description;
    descSection.appendChild(descLabel);
    descSection.appendChild(descText);
    content.appendChild(descSection);
  }

  // Links section
  const linksSection = document.createElement('div');
  linksSection.style.marginBottom = '1.5rem';
  const linksLabel = document.createElement('div');
  linksLabel.style.cssText = 'color:var(--gray);font-size:0.75rem;margin-bottom:0.5rem;';
  linksLabel.textContent = 'Links';
  linksSection.appendChild(linksLabel);

  if (service.website_url) {
    const websiteDiv = document.createElement('div');
    websiteDiv.style.marginBottom = '0.5rem';
    const websiteLink = document.createElement('a');
    websiteLink.href = service.website_url;
    websiteLink.target = '_blank';
    websiteLink.style.color = 'var(--primary)';
    websiteLink.textContent = 'Website';
    websiteDiv.appendChild(websiteLink);
    linksSection.appendChild(websiteDiv);
  }

  if (service.connect_url) {
    const connectDiv = document.createElement('div');
    const connectLink = document.createElement('a');
    connectLink.href = service.connect_url;
    connectLink.target = '_blank';
    connectLink.style.color = 'var(--primary)';
    connectLink.textContent = 'Connect URL';
    connectDiv.appendChild(connectLink);
    linksSection.appendChild(connectDiv);
  }

  if (!service.website_url && !service.connect_url) {
    const noLinks = document.createElement('div');
    noLinks.style.color = 'var(--gray)';
    noLinks.textContent = 'No links configured';
    linksSection.appendChild(noLinks);
  }

  content.appendChild(linksSection);

  // Required User Data
  if (service.required_user_data && service.required_user_data.length > 0) {
    const dataSection = document.createElement('div');
    dataSection.style.marginBottom = '1.5rem';
    const dataLabel = document.createElement('div');
    dataLabel.style.cssText = 'color:var(--gray);font-size:0.75rem;margin-bottom:0.5rem;';
    dataLabel.textContent = 'Required User Data';
    dataSection.appendChild(dataLabel);

    const badgeContainer = document.createElement('div');
    badgeContainer.style.cssText = 'display:flex;flex-wrap:wrap;gap:0.5rem;';
    service.required_user_data.forEach(key => {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.style.cssText = 'background:var(--light);color:var(--dark);';
      badge.textContent = key;
      badgeContainer.appendChild(badge);
    });
    dataSection.appendChild(badgeContainer);
    content.appendChild(dataSection);
  }

  // Timestamps
  const timestampGrid = document.createElement('div');
  timestampGrid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:1rem;font-size:0.875rem;color:var(--gray);';

  // Created
  const createdBox = document.createElement('div');
  const createdLabel = document.createElement('div');
  createdLabel.style.fontSize = '0.75rem';
  createdLabel.textContent = 'Created';
  createdBox.appendChild(createdLabel);
  const createdDate = document.createElement('div');
  createdDate.textContent = service.created_at ? new Date(service.created_at).toLocaleString() : '-';
  createdBox.appendChild(createdDate);
  if (service.created_by) {
    const createdBy = document.createElement('div');
    createdBy.style.fontSize = '0.75rem';
    createdBy.textContent = service.created_by;
    createdBox.appendChild(createdBy);
  }
  timestampGrid.appendChild(createdBox);

  // Updated
  const updatedBox = document.createElement('div');
  const updatedLabel = document.createElement('div');
  updatedLabel.style.fontSize = '0.75rem';
  updatedLabel.textContent = 'Updated';
  updatedBox.appendChild(updatedLabel);
  const updatedDate = document.createElement('div');
  updatedDate.textContent = service.updated_at ? new Date(service.updated_at).toLocaleString() : '-';
  updatedBox.appendChild(updatedDate);
  if (service.updated_by) {
    const updatedBy = document.createElement('div');
    updatedBy.style.fontSize = '0.75rem';
    updatedBy.textContent = service.updated_by;
    updatedBox.appendChild(updatedBy);
  }
  timestampGrid.appendChild(updatedBox);

  content.appendChild(timestampGrid);

  document.getElementById('serviceDetailsModal').classList.add('active');
}

function createDetailBox(labelText) {
  const box = document.createElement('div');
  const label = document.createElement('div');
  label.style.cssText = 'color:var(--gray);font-size:0.75rem;margin-bottom:0.25rem;';
  label.textContent = labelText;
  box.appendChild(label);
  return box;
}

export function closeServiceDetailsModal() {
  document.getElementById('serviceDetailsModal').classList.remove('active');
}

export function editServiceFromDetails() {
  closeServiceDetailsModal();
  openEditServiceModal(currentServiceId);
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Status Toggle
// ─────────────────────────────────────────────────────────────────────────────

export async function toggleServiceStatus(serviceId, newStatus) {
  try {
    await api('/admin/services/status', {
      method: 'POST',
      body: JSON.stringify({
        service_id: serviceId,
        status: newStatus
      })
    });
    showToast(`Service ${newStatus === 'active' ? 'activated' : 'deprecated'}`, 'success');
    loadServices();
  } catch (err) {
    console.error('Error toggling service status:', err);
    showToast('Failed to update status', 'error');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Delete Service
// ─────────────────────────────────────────────────────────────────────────────

export function openDeleteServiceModal(serviceId) {
  const service = servicesData.find(s => s.service_id === serviceId);
  if (!service) return;

  currentServiceId = serviceId;
  document.getElementById('deleteServiceName').textContent = service.name || serviceId;
  document.getElementById('confirmDeleteServiceInput').value = '';
  document.getElementById('deleteServiceMsg').textContent = '';
  document.getElementById('confirmDeleteServiceBtn').disabled = false;
  document.getElementById('deleteServiceModal').classList.add('active');
}

export function closeDeleteServiceModal() {
  document.getElementById('deleteServiceModal').classList.remove('active');
  currentServiceId = null;
}

export async function deleteService() {
  const confirmInput = document.getElementById('confirmDeleteServiceInput').value.trim();
  const service = servicesData.find(s => s.service_id === currentServiceId);
  if (!service) return;

  if (confirmInput !== service.name) {
    showToast('Service name does not match', 'error');
    return;
  }

  const msgEl = document.getElementById('deleteServiceMsg');
  const confirmBtn = document.getElementById('confirmDeleteServiceBtn');

  try {
    confirmBtn.disabled = true;
    msgEl.textContent = 'Deleting service...';
    msgEl.style.color = 'var(--gray)';

    await api('/admin/services/delete', {
      method: 'POST',
      body: JSON.stringify({
        service_id: currentServiceId
      })
    });

    showToast('Service deleted successfully', 'success');
    closeDeleteServiceModal();
    loadServices();
  } catch (err) {
    console.error('Error deleting service:', err);
    msgEl.textContent = 'Error: ' + err.message;
    msgEl.style.color = '#ef4444';
    confirmBtn.disabled = false;
    showToast('Failed to delete service', 'error');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filter Functions
// ─────────────────────────────────────────────────────────────────────────────

export function setServiceStatusFilter(filter) {
  serviceStatusFilter = filter;
  renderServices();
}

export function setServiceTypeFilter(filter) {
  serviceTypeFilter = filter;
  renderServices();
}

export function setServiceSearchTerm(term) {
  serviceSearchTerm = term;
  renderServices();
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Handlers Setup (called from main.js)
// ─────────────────────────────────────────────────────────────────────────────

export function setupServicesEventHandlers() {
  // Add service button
  const addServiceBtn = document.getElementById('addServiceBtn');
  if (addServiceBtn) addServiceBtn.onclick = () => openServiceModal(false);

  // Refresh services button
  const refreshServicesBtn = document.getElementById('refreshServicesBtn');
  if (refreshServicesBtn) refreshServicesBtn.onclick = loadServices;

  // Save service button
  const saveServiceBtn = document.getElementById('saveServiceBtn');
  if (saveServiceBtn) saveServiceBtn.onclick = saveService;

  // Edit from details button
  const editServiceFromDetailsBtn = document.getElementById('editServiceFromDetailsBtn');
  if (editServiceFromDetailsBtn) editServiceFromDetailsBtn.onclick = editServiceFromDetails;

  // Confirm delete button
  const confirmDeleteServiceBtn = document.getElementById('confirmDeleteServiceBtn');
  if (confirmDeleteServiceBtn) confirmDeleteServiceBtn.onclick = deleteService;

  // Status filter buttons
  document.querySelectorAll('.service-filter').forEach(btn => {
    btn.onclick = function() {
      document.querySelectorAll('.service-filter').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      setServiceStatusFilter(this.dataset.filter);
    };
  });

  // Type filter
  const typeFilter = document.getElementById('serviceTypeFilter');
  if (typeFilter) {
    typeFilter.onchange = function() {
      setServiceTypeFilter(this.value);
    };
  }

  // Search input with debounce
  const searchInput = document.getElementById('serviceSearchInput');
  if (searchInput) {
    let searchTimeout;
    searchInput.oninput = function() {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        setServiceSearchTerm(this.value);
      }, 300);
    };
  }
}
