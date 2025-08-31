let allCriticalItems = [];
let currentCategory = 'all';
let currentSearchText = '';

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the officials/admin view
    const isAdminView = document.getElementById('criticalItemsTabs') !== null;
    
    if (isAdminView) {
        if (typeof criticalItems !== 'undefined') {
            allCriticalItems = criticalItems;
            populateTables();
            updateTabCounts();
            addTabListeners();
        }
    } else {
        initializeUserView();
    }
    
    initializeSearchAndFilter();
    initializeModals();
});

function initializeSearchAndFilter() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            currentSearchText = this.value.toLowerCase();
            filterTable();
        });
    }
}

function addTabListeners() {
    const tabs = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', event => {
            // Reapply filters when switching tabs
            filterItemsByCategory(currentCategory);
            if (currentSearchText) {
                filterBySearchText(currentSearchText);
            }
        });
    });
}

function initializeUserView() {
    const table = document.getElementById('criticalItemsTable');
    if (table) {
        const rows = table.querySelectorAll('tbody tr');
        
        // Categorize rows for filtering
        rows.forEach(row => {
            const categoryCell = row.querySelector('td:nth-child(2)');
            if (categoryCell) {
                const categoryText = categoryCell.textContent.trim();
                if (categoryText.includes('Medical')) {
                    row.dataset.category = 'Medical';
                } else if (categoryText.includes('Grocery')) {
                    row.dataset.category = 'Grocery';
                } else {
                    row.dataset.category = 'Other';
                }
            }
        });
    }
}

function initializeModals() {
    // Merchant item details modal
    const viewDetailsModal = document.getElementById('viewDetailsModal');
    if (viewDetailsModal) {
        viewDetailsModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const itemName = button.getAttribute('data-item-name');
            const itemCategory = button.getAttribute('data-item-category');
            const itemDescription = button.getAttribute('data-item-description');
            const itemStatus = button.getAttribute('data-item-status');
            const itemNotes = button.getAttribute('data-item-notes');
            const itemReviewer = button.getAttribute('data-item-reviewer');
            
            document.getElementById('view-item-name').textContent = itemName;
            
            const categoryEl = document.getElementById('view-item-category');
            categoryEl.innerHTML = `<span class="badge ${itemCategory === 'Medical' ? 'badge-medical' : 'badge-grocery'}">${itemCategory}</span>`;
            
            const statusEl = document.getElementById('view-item-status');
            let statusClass = 'bg-secondary';
            if (itemStatus === 'Approved') statusClass = 'bg-success';
            else if (itemStatus === 'Rejected') statusClass = 'bg-danger';
            else if (itemStatus === 'Pending') statusClass = 'bg-warning text-dark';
            
            statusEl.innerHTML = `<span class="badge ${statusClass}">${itemStatus}</span>`;
            
            document.getElementById('view-item-description').textContent = itemDescription || 'No justification provided.';
            
            const notesEl = document.getElementById('view-item-notes');
            notesEl.textContent = itemNotes || 'No comments provided.';
            
            const reviewerEl = document.getElementById('view-item-reviewer');
            reviewerEl.textContent = itemReviewer || 'Not yet reviewed';
            
            // Hide reviewer info for pending items
            const reviewerSections = document.querySelectorAll('.reviewer-section');
            reviewerSections.forEach(section => {
                if (itemStatus === 'Pending') {
                    section.style.display = 'none';
                } else {
                    section.style.display = 'block';
                }
            });
        });
    }
    
    // Citizen item details modal
    const viewCitizenDetailsModal = document.getElementById('viewCitizenDetailsModal');
    if (viewCitizenDetailsModal) {
        viewCitizenDetailsModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const itemName = button.getAttribute('data-item-name');
            const itemCategory = button.getAttribute('data-item-category');
            const itemMerchant = button.getAttribute('data-item-merchant');
            const itemWeeklyLimit = button.getAttribute('data-item-weekly-limit');
            const itemPurchaseFrequency = button.getAttribute('data-item-purchase-frequency');
            
            document.getElementById('citizen-item-name').textContent = itemName;
            
            const categoryEl = document.getElementById('citizen-item-category');
            categoryEl.innerHTML = `<span class="badge ${itemCategory === 'Medical' ? 'badge-medical' : 'badge-grocery'}">${itemCategory}</span>`;
            
            document.getElementById('citizen-item-merchant').textContent = itemMerchant;
            
            // Build purchase limits display
            const limitsEl = document.getElementById('citizen-item-limits');
            let limitsContent = '';
            
            if (parseInt(itemWeeklyLimit) > 0) {
                limitsContent += `<div class="alert alert-warning mb-2">
                    <i class="bi bi-exclamation-circle me-2"></i>
                    <strong>Weekly Limit:</strong> ${itemWeeklyLimit} units per week
                </div>`;
            }
            
            if (parseInt(itemPurchaseFrequency) > 0) {
                limitsContent += `<div class="alert alert-warning mb-0">
                    <i class="bi bi-calendar-event me-2"></i>
                    <strong>Purchase Frequency:</strong> Once every ${itemPurchaseFrequency} days
                </div>`;
            }
            
            if (!limitsContent) {
                limitsContent = `<div class="alert alert-secondary mb-0">
                    <i class="bi bi-info-circle me-2"></i>
                    No specific purchase limits for this item
                </div>`;
            }
            
            limitsEl.innerHTML = limitsContent;
        });
    }
    
    // Suggest item modal with form validation
    const suggestItemModal = document.getElementById('suggestItemModal');
    if (suggestItemModal) {
        const suggestForm = suggestItemModal.querySelector('form');
        if (suggestForm) {
            suggestForm.addEventListener('submit', function(event) {
                const stockId = document.getElementById('stock_id').value;
                const description = document.getElementById('description').value;
                
                if (!stockId) {
                    event.preventDefault();
                    alert('Please select an item from the inventory.');
                    return false;
                }
                
                if (!description || description.length < 10) {
                    event.preventDefault();
                    alert('Please provide a detailed explanation of why this item is critical (minimum 10 characters).');
                    return false;
                }
                
                return true;
            });
        }
    }
}

function filterTable() {
    const isAdminView = document.getElementById('criticalItemsTabs') !== null;
    
    if (isAdminView) {
        // Filter active tab content
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const rows = activeTab.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            if (!row.dataset.category) return;
            
            const passesCategory = (currentCategory === 'all' || row.dataset.category === currentCategory);
            const text = row.textContent.toLowerCase();
            const passesSearch = !currentSearchText || text.includes(currentSearchText);
            
            row.style.display = (passesCategory && passesSearch) ? '' : 'none';
        });
    } else {
        // Filter regular table view
        const table = document.getElementById('criticalItemsTable');
        if (!table) return;
        
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            if (!row.dataset.category) return;
            
            const passesCategory = (currentCategory === 'all' || row.dataset.category === currentCategory);
            const text = row.textContent.toLowerCase();
            const passesSearch = !currentSearchText || text.includes(currentSearchText);
            
            row.style.display = (passesCategory && passesSearch) ? '' : 'none';
        });
        
        updateVisibleCount(table);
    }
}

function filterItems(category) {
    currentCategory = category;
    filterTable();
}

function updateVisibleCount(table) {
    const rows = table.querySelectorAll('tbody tr');
    const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none').length;
    
    const totalItemsElement = document.getElementById('totalItems');
    if (totalItemsElement) {
        totalItemsElement.textContent = visibleRows;
        
        // Update singular/plural text
        const itemsTextElement = totalItemsElement.nextSibling;
        if (itemsTextElement && itemsTextElement.nodeType === Node.TEXT_NODE) {
            itemsTextElement.nodeValue = visibleRows !== 1 ? ' items' : ' item';
        }
    }
}

function populateTables() {
    if (!allCriticalItems) return;
    
    const pendingTableBody = document.getElementById('pendingTableBody');
    const approvedTableBody = document.getElementById('approvedTableBody');
    const rejectedTableBody = document.getElementById('rejectedTableBody');
    const allTableBody = document.getElementById('allTableBody');
    
    if (!pendingTableBody || !approvedTableBody || !rejectedTableBody || !allTableBody) return;
    
    pendingTableBody.innerHTML = '';
    approvedTableBody.innerHTML = '';
    rejectedTableBody.innerHTML = '';
    allTableBody.innerHTML = '';
    
    let pendingCount = 0;
    let approvedCount = 0;
    let rejectedCount = 0;
    
    allCriticalItems.forEach(item => {
        const statusClass = getStatusClass(item.status);
        
        const allRow = createRow(item, 'all');
        allTableBody.appendChild(allRow);
        
        if (item.status === 'Pending') {
            const pendingRow = createRow(item, 'pending');
            pendingTableBody.appendChild(pendingRow);
            pendingCount++;
        } else if (item.status === 'Approved') {
            const approvedRow = createRow(item, 'approved');
            approvedTableBody.appendChild(approvedRow);
            approvedCount++;
        } else if (item.status === 'Rejected') {
            const rejectedRow = createRow(item, 'rejected');
            rejectedTableBody.appendChild(rejectedRow);
            rejectedCount++;
        }
    });
    
    // Empty state messages
    if (pendingCount === 0) {
        pendingTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No pending items found</td></tr>';
    }
    
    if (approvedCount === 0) {
        approvedTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No approved items found</td></tr>';
    }
    
    if (rejectedCount === 0) {
        rejectedTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No rejected items found</td></tr>';
    }
    
    if (allCriticalItems.length === 0) {
        allTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No critical items found</td></tr>';
    }
}

// Generate table rows with different columns based on context
function createRow(item, tableType) {
    const row = document.createElement('tr');
    row.dataset.category = item.category;
    
    if (tableType === 'pending') {
        row.innerHTML = `
            <td>${escapeHTML(item.item_name)}</td>
            <td>
                <span class="badge ${item.category === 'Medical' ? 'badge-medical' : 'badge-grocery'}">
                    ${escapeHTML(item.category)}
                </span>
            </td>
            <td>${escapeHTML(item.merchant_name)}</td>
            <td>${formatDate(item.suggested_at)}</td>
            <td>
                <span class="badge ${getStatusClass(item.status)}">
                    ${escapeHTML(item.status)}
                </span>
            </td>
            <td>
                <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                    <i class="bi bi-check-circle"></i> Review
                </a>
            </td>
        `;
    } else if (tableType === 'approved') {
        row.innerHTML = `
            <td>${escapeHTML(item.item_name)}</td>
            <td>
                <span class="badge ${item.category === 'Medical' ? 'badge-medical' : 'badge-grocery'}">
                    ${escapeHTML(item.category)}
                </span>
            </td>
            <td>${escapeHTML(item.merchant_name)}</td>
            <td>
                ${item.weekly_limit ? 
                  `<span class="badge bg-info">${item.weekly_limit} per week</span>` : 
                  `<span class="badge bg-secondary">No limits set</span>`}
            </td>
            <td>${item.reviewer_name ? escapeHTML(item.reviewer_name) : 'N/A'}</td>
            <td>
                <a href="critical_items.php?action=edit_limits&id=${item.item_id}" class="btn btn-sm btn-warning">
                    <i class="bi bi-sliders"></i> Set Limits
                </a>
                <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                    <i class="bi bi-pencil"></i> Edit
                </a>
            </td>
        `;
    } else if (tableType === 'rejected') {
        row.innerHTML = `
            <td>${escapeHTML(item.item_name)}</td>
            <td>
                <span class="badge ${item.category === 'Medical' ? 'badge-medical' : 'badge-grocery'}">
                    ${escapeHTML(item.category)}
                </span>
            </td>
            <td>${escapeHTML(item.merchant_name)}</td>
            <td>${formatDate(item.reviewed_at || item.suggested_at)}</td>
            <td>${item.reviewer_name ? escapeHTML(item.reviewer_name) : 'N/A'}</td>
            <td>
                <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                    <i class="bi bi-arrow-repeat"></i> Re-Review
                </a>
            </td>
        `;
    } else if (tableType === 'all') {
        row.innerHTML = `
            <td>${escapeHTML(item.item_name)}</td>
            <td>
                <span class="badge ${item.category === 'Medical' ? 'badge-medical' : 'badge-grocery'}">
                    ${escapeHTML(item.category)}
                </span>
            </td>
            <td>${escapeHTML(item.merchant_name)}</td>
            <td>
                <span class="badge ${getStatusClass(item.status)}">
                    ${escapeHTML(item.status)}
                </span>
            </td>
            <td>${formatDate(item.suggested_at)}</td>
            <td>
                <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                    <i class="bi bi-pencil"></i> Edit
                </a>
                ${item.status === 'Approved' ? 
                `<a href="critical_items.php?action=edit_limits&id=${item.item_id}" class="btn btn-sm btn-warning">
                    <i class="bi bi-sliders"></i> Limits
                </a>` : ''}
            </td>
        `;
    }
    
    return row;
}

function updateTabCounts() {
    if (!allCriticalItems) return;
    
    const pendingCount = allCriticalItems.filter(item => item.status === 'Pending').length;
    const approvedCount = allCriticalItems.filter(item => item.status === 'Approved').length;
    const rejectedCount = allCriticalItems.filter(item => item.status === 'Rejected').length;
    
    const pendingBadge = document.getElementById('pending-count');
    const approvedBadge = document.getElementById('approved-count');
    const rejectedBadge = document.getElementById('rejected-count');
    const allBadge = document.getElementById('all-count');
    
    if (pendingBadge) pendingBadge.textContent = pendingCount;
    if (approvedBadge) approvedBadge.textContent = approvedCount;
    if (rejectedBadge) rejectedBadge.textContent = rejectedCount;
    if (allBadge) allBadge.textContent = allCriticalItems.length;
}

function getStatusClass(status) {
    switch (status) {
        case 'Approved': return 'bg-success';
        case 'Rejected': return 'bg-danger';
        case 'Pending': return 'bg-warning text-dark';
        default: return 'bg-secondary';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return date.toLocaleDateString('en-US', options);
}

// Prevent XSS attacks in dynamic content
function escapeHTML(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function confirmDelete(itemId, itemName) {
    if (confirm(`Are you sure you want to remove "${itemName}" from critical items? This action cannot be undone.`)) {
        window.location.href = `critical_items.php?action=delete&id=${itemId}`;
    }
}