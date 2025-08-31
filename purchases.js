let purchases = [];
let currentPage = 1;
const rowsPerPage = 10;

document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("purchasesTable")) {
        fetchData("purchases");
    }
    
    initializeEligibilityChecks();
    initializeLocationSearch();
    
    // Custom styling for purple badges if not already in stylesheet
    if (!document.getElementById('custom-badge-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'custom-badge-styles';
        styleEl.textContent = `
            .bg-purple {
                background-color: #6f42c1 !important;
                color: white !important;
            }
            .badge-prs {
                background-color: #6f42c1;
                color: white;
                padding: 0.4em 0.6em;
                border-radius: 0.25rem;
            }
        `;
        document.head.appendChild(styleEl);
    }
});

function fetchData(table) {
    fetch(`fetch_data.php?table=${encodeURIComponent(table)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#purchasesTable tbody").innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            purchases = data;
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#purchasesTable tbody").innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable(data = purchases) {
    const tableBody = document.querySelector("#purchasesTable tbody");
    tableBody.innerHTML = "";

    if (!tableBody) {
        console.error("Table body element not found");
        return;
    }

    if (data.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" class="text-center">No purchases found</td></tr>`;
        return;
    }

    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;
    let paginatedData = data.slice(start, end);

    paginatedData.forEach(purchase => {
        const row = `<tr>
            <td>${purchase.purchase_id}</td>
            <td>${purchase.user_name || purchase.user_id}</td>
            <td>${purchase.merchant_name || purchase.merchant_id}</td>
            <td>${purchase.item_name}</td>
            <td>${purchase.item_quantity}</td>
            <td>${formatDate(purchase.purchase_date)}</td>
            <td>
                ${purchase.eligible_purchase == 1 ? 
                  '<span class="badge bg-success">Yes</span>' : 
                  '<span class="badge bg-secondary">No</span>'}
            </td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewPurchase(${purchase.purchase_id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editPurchase(${purchase.purchase_id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${purchase.purchase_id}, '${escapeString(purchase.item_name)}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });

    const totalPages = Math.ceil(data.length / rowsPerPage);
    if (document.getElementById("pageNumber")) {
        document.getElementById("pageNumber").innerText = `Page ${currentPage} of ${totalPages}`;
    }
}

function nextPage() {
    if (currentPage * rowsPerPage < purchases.length) {
        currentPage++;
        renderTable();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        renderTable();
    }
}

function sortTable(colIndex) {
    const compareValues = (v1, v2) => {
        if (v1 === undefined) return -1;
        if (v2 === undefined) return 1;
        
        if (!isNaN(v1) && !isNaN(v2)) {
            return parseFloat(v1) - parseFloat(v2);
        }
        
        return String(v1).localeCompare(String(v2));
    };

    purchases.sort((a, b) => {
        let aValue, bValue;
        
        switch(colIndex) {
            case 0:
                return compareValues(a.purchase_id, b.purchase_id);
            case 1:
                return compareValues(a.user_name || a.user_id, b.user_name || b.user_id);
            case 2:
                return compareValues(a.merchant_name || a.merchant_id, b.merchant_name || b.merchant_id);
            case 3:
                return compareValues(a.item_name, b.item_name);
            case 4:
                return compareValues(a.item_quantity, b.item_quantity);
            case 5:
                return compareValues(new Date(a.purchase_date), new Date(b.purchase_date));
            case 6:
                return compareValues(a.eligible_purchase, b.eligible_purchase);
            default:
                return 0;
        }
    });

    renderTable();
}

// Multi-field search across purchase data
function filterTable() {
    const filter = document.getElementById("searchInput").value.toLowerCase();
    
    if (!filter) {
        renderTable(purchases);
        return;
    }
    
    const filteredData = purchases.filter(purchase => 
        (purchase.user_name && purchase.user_name.toString().toLowerCase().includes(filter)) ||
        (purchase.merchant_name && purchase.merchant_name.toString().toLowerCase().includes(filter)) ||
        (purchase.item_name && purchase.item_name.toString().toLowerCase().includes(filter)) ||
        (purchase.purchase_id && purchase.purchase_id.toString().toLowerCase().includes(filter))
    );

    renderTable(filteredData);
}

function viewPurchase(id) {
    window.location.href = `purchases.php?action=view&id=${id}`;
}

function editPurchase(id) {
    window.location.href = `purchases.php?action=edit&id=${id}`;
}

function confirmDelete(id, name) {
    if (confirm(`Are you sure you want to delete purchase record "${name}" (ID: ${id})?`)) {
        window.location.href = `purchases.php?action=delete&id=${id}`;
    }
}

function escapeString(str) {
    if (!str) return '';
    return str.replace(/['"\\\n\r\u2028\u2029]/g, function (character) {
        switch (character) {
            case "'":
            case '"':
            case '\\':
                return '\\' + character;
            case '\n': return '\\n';
            case '\r': return '\\r';
            case '\u2028': return '\\u2028';
            case '\u2029': return '\\u2029';
        }
    });
}

function formatDate(dateString) {
    if (!dateString) return '';
    
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        return dateString;
    }
    
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return date.toLocaleDateString('en-US', options);
}

function calculateTotal() {
    const quantityInput = document.getElementById('item_quantity');
    const unitPriceInput = document.getElementById('unit_price');
    const totalPriceInput = document.getElementById('total_price');
    
    if (quantityInput && unitPriceInput && totalPriceInput) {
        const quantity = parseFloat(quantityInput.value) || 0;
        const unitPrice = parseFloat(unitPriceInput.value) || 0;
        const totalPrice = quantity * unitPrice;
        
        totalPriceInput.value = totalPrice.toFixed(2);
    }
}

function calculateModalTotal() {
    const quantityInput = document.getElementById('modal_item_quantity');
    const unitPriceInput = document.getElementById('modal_unit_price');
    const totalPriceInput = document.getElementById('modal_total_price');
    
    if (quantityInput && unitPriceInput && totalPriceInput) {
        const quantity = parseFloat(quantityInput.value) || 0;
        const unitPrice = parseFloat(unitPriceInput.value) || 0;
        const totalPrice = quantity * unitPrice;
        
        totalPriceInput.value = totalPrice.toFixed(2);
    }
}

function initializeEligibilityChecks() {
    const userSelect = document.getElementById('user_id');
    if (userSelect) {
        userSelect.addEventListener('change', checkUserEligibility);
        
        if (userSelect.value) {
            checkUserEligibility();
        }
    }
    
    const modalUserSelect = document.getElementById('modal_user_id');
    if (modalUserSelect) {
        modalUserSelect.addEventListener('change', checkModalUserEligibility);
    }
    
    const dateField = document.getElementById('purchase_date');
    if (dateField) {
        dateField.addEventListener('change', checkUserEligibility);
    }
    
    const modalDateField = document.getElementById('modal_purchase_date');
    if (modalDateField) {
        modalDateField.addEventListener('change', checkModalUserEligibility);
    }
}

function initializeLocationSearch() {
    const locationSearchBtn = document.getElementById('locationSearchBtn');
    if (locationSearchBtn) {
        locationSearchBtn.addEventListener('click', searchByLocation);
    }
    
    const prsSearchBtn = document.getElementById('prsSearchBtn');
    if (prsSearchBtn) {
        prsSearchBtn.addEventListener('click', searchByPRSID);
    }
}

function searchByLocation() {
    const cityInput = document.getElementById('citySearch').value.trim();
    
    if (!cityInput) {
        alert('Please enter a city name to search');
        return;
    }
    
    const resultsDiv = document.getElementById('locationSearchResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p>Searching merchants...</p></div>';
    }
    
    fetch(`location_search.php?city=${encodeURIComponent(cityInput)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            if (data.length === 0) {
                resultsDiv.innerHTML = `<div class="alert alert-info">No merchants found in ${cityInput}</div>`;
                return;
            }
            
            let resultHtml = `
                <h5 class="mt-3 mb-3">Merchants in ${cityInput} (${data.length} found)</h5>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Merchant</th>
                                <th>PRS ID</th>
                                <th>Address</th>
                                <th>Contact</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>`;
            
            data.forEach(merchant => {
                resultHtml += `
                    <tr>
                        <td>${merchant.merchant_name}</td>
                        <td><span class="badge-prs">${merchant.prs_id || 'N/A'}</span></td>
                        <td>${merchant.address || ''}, ${merchant.city || ''}</td>
                        <td>${merchant.contact_phone || ''} ${merchant.contact_email ? '<br>' + merchant.contact_email : ''}</td>
                        <td>
                            <a href="merchants.php?action=view&id=${merchant.merchant_id}" class="btn btn-sm btn-info">
                                <i class="bi bi-eye"></i> View
                            </a>
                        </td>
                    </tr>`;
            });
            
            resultHtml += `
                        </tbody>
                    </table>
                </div>`;
            
            resultsDiv.innerHTML = resultHtml;
        })
        .catch(error => {
            console.error("Error searching by location:", error);
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error searching for merchants. Please try again.</div>`;
        });
}

// Search by PRS ID to find merchants in the same city as the user
function searchByPRSID() {
    const prsIdInput = document.getElementById('prsIdSearch').value.trim();
    
    if (!prsIdInput) {
        alert('Please enter a PRS ID to search');
        return;
    }
    
    const resultsDiv = document.getElementById('prsSearchResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p>Searching merchants...</p></div>';
    }
    
    fetch(`location_search.php?prs_id=${encodeURIComponent(prsIdInput)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                resultsDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            if (data.length === 0) {
                resultsDiv.innerHTML = `<div class="alert alert-info">No merchants found near user with PRS ID: ${prsIdInput}</div>`;
                return;
            }
            
            let resultHtml = `
                <h5 class="mt-3 mb-3">Merchants near user with PRS ID: ${prsIdInput} (${data.length} found)</h5>
                <p class="text-muted">Showing merchants in ${data[0].city || 'the same city'}</p>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Merchant</th>
                                <th>PRS ID</th>
                                <th>Address</th>
                                <th>Contact</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>`;
            
            data.forEach(merchant => {
                resultHtml += `
                    <tr>
                        <td>${merchant.merchant_name}</td>
                        <td><span class="badge-prs">${merchant.prs_id || 'N/A'}</span></td>
                        <td>${merchant.address || ''}, ${merchant.city || ''}</td>
                        <td>${merchant.contact_phone || ''} ${merchant.contact_email ? '<br>' + merchant.contact_email : ''}</td>
                        <td>
                            <a href="merchants.php?action=view&id=${merchant.merchant_id}" class="btn btn-sm btn-info">
                                <i class="bi bi-eye"></i> View
                            </a>
                        </td>
                    </tr>`;
            });
            
            resultHtml += `
                        </tbody>
                    </table>
                </div>`;
            
            resultsDiv.innerHTML = resultHtml;
        })
        .catch(error => {
            console.error("Error searching by PRS ID:", error);
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error searching for merchants. Please try again.</div>`;
        });
}

// Complex face mask eligibility rules based on birth year and day of week
function checkUserEligibility() {
    const userSelect = document.getElementById('user_id');
    const alertDiv = document.getElementById('eligibilityAlert');
    const alertMessage = document.getElementById('eligibilityMessage');
    
    if (!userSelect || !alertDiv || !alertMessage || userSelect.value === '') {
        if (alertDiv) {
            alertDiv.classList.add('d-none');
        }
        return;
    }
    
    const selectedOption = userSelect.options[userSelect.selectedIndex];
    const dob = selectedOption.getAttribute('data-dob');
    
    if (!dob) {
        alertDiv.classList.add('d-none');
        return;
    }
    
    let purchaseDate = new Date();
    const dateField = document.getElementById('purchase_date');
    if (dateField && dateField.value) {
        const selectedDate = new Date(dateField.value);
        if (!isNaN(selectedDate.getTime())) {
            purchaseDate = selectedDate;
        }
    }
    
    const birthYear = new Date(dob).getFullYear();
    const lastDigit = birthYear % 10;
    
    let dayOfWeek = purchaseDate.getDay();
    
    let isEligible = false;
    let eligibleDays = [];
    
    if (lastDigit === 0 || lastDigit === 2) {
        eligibleDays.push('Monday');
        if (dayOfWeek === 1) isEligible = true;
    }
    
    if (lastDigit === 1 || lastDigit === 3) {
        eligibleDays.push('Tuesday');
        if (dayOfWeek === 2) isEligible = true;
    }
    
    if (lastDigit === 2 || lastDigit === 4) {
        eligibleDays.push('Wednesday');
        if (dayOfWeek === 3) isEligible = true;
    }
    
    if (lastDigit === 3 || lastDigit === 5) {
        eligibleDays.push('Thursday');
        if (dayOfWeek === 4) isEligible = true;
    }
    
    if (lastDigit === 4 || lastDigit === 6) {
        eligibleDays.push('Friday');
        if (dayOfWeek === 5) isEligible = true;
    }
    
    if (lastDigit === 5 || lastDigit === 7) {
        eligibleDays.push('Saturday');
        if (dayOfWeek === 6) isEligible = true;
    }
    
    if (lastDigit === 6 || lastDigit === 8 || lastDigit === 9) {
        eligibleDays.push('Sunday');
        if (dayOfWeek === 0) isEligible = true;
    }
    
    if (isEligible) {
        alertDiv.classList.remove('d-none', 'alert-danger');
        alertDiv.classList.add('alert-success');
        alertMessage.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i> <strong>Eligible!</strong> With birth year ending in ${lastDigit}, this user is eligible to purchase face masks today.`;
    } else {
        alertDiv.classList.remove('d-none', 'alert-success');
        alertDiv.classList.add('alert-danger');
        alertMessage.innerHTML = `<i class="bi bi-x-circle-fill me-2"></i> <strong>Not Eligible!</strong> With birth year ending in ${lastDigit}, this user can only purchase face masks on ${eligibleDays.join(' and ')}.`;
    }
}

function checkModalUserEligibility() {
    const userSelect = document.getElementById('modal_user_id');
    const alertDiv = document.getElementById('modalEligibilityAlert');
    const alertMessage = document.getElementById('modalEligibilityMessage');
    
    if (!userSelect || !alertDiv || !alertMessage || userSelect.value === '') {
        if (alertDiv) {
            alertDiv.classList.add('d-none');
        }
        return;
    }
    
    const selectedOption = userSelect.options[userSelect.selectedIndex];
    const dob = selectedOption.getAttribute('data-dob');
    
    if (!dob) {
        alertDiv.classList.add('d-none');
        return;
    }
    
    let purchaseDate = new Date();
    const dateField = document.getElementById('modal_purchase_date');
    if (dateField && dateField.value) {
        const selectedDate = new Date(dateField.value);
        if (!isNaN(selectedDate.getTime())) {
            purchaseDate = selectedDate;
        }
    }
    
    const birthYear = new Date(dob).getFullYear();
    const lastDigit = birthYear % 10;
    
    let dayOfWeek = purchaseDate.getDay();
    
    let isEligible = false;
    let eligibleDays = [];
    
    if (lastDigit === 0 || lastDigit === 2) {
        eligibleDays.push('Monday');
        if (dayOfWeek === 1) isEligible = true;
    }
    
    if (lastDigit === 1 || lastDigit === 3) {
        eligibleDays.push('Tuesday');
        if (dayOfWeek === 2) isEligible = true;
    }
    
    if (lastDigit === 2 || lastDigit === 4) {
        eligibleDays.push('Wednesday');
        if (dayOfWeek === 3) isEligible = true;
    }
    
    if (lastDigit === 3 || lastDigit === 5) {
        eligibleDays.push('Thursday');
        if (dayOfWeek === 4) isEligible = true;
    }
    
    if (lastDigit === 4 || lastDigit === 6) {
        eligibleDays.push('Friday');
        if (dayOfWeek === 5) isEligible = true;
    }
    
    if (lastDigit === 5 || lastDigit === 7) {
        eligibleDays.push('Saturday');
        if (dayOfWeek === 6) isEligible = true;
    }
    
    if (lastDigit === 6 || lastDigit === 8 || lastDigit === 9) {
        eligibleDays.push('Sunday');
        if (dayOfWeek === 0) isEligible = true;
    }
    
    if (isEligible) {
        alertDiv.classList.remove('d-none', 'alert-danger');
        alertDiv.classList.add('alert-success');
        alertMessage.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i> <strong>Eligible!</strong> With birth year ending in ${lastDigit}, this user is eligible to purchase face masks today.`;
    } else {
        alertDiv.classList.remove('d-none', 'alert-success');
        alertDiv.classList.add('alert-danger');
        alertMessage.innerHTML = `<i class="bi bi-x-circle-fill me-2"></i> <strong>Not Eligible!</strong> With birth year ending in ${lastDigit}, this user can only purchase face masks on ${eligibleDays.join(' and ')}.`;
    }
}