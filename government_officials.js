let currentPage = 1;
const itemsPerPage = 10;
let officialsData = [];

async function fetchOfficials() {
    try {
        const response = await fetch('fetch_data.php?table=government_officials');
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json();
        officialsData = data;
        renderTable();
    } catch (error) {
        console.error('Error fetching officials data:', error);
        document.getElementById('government_officialsTable').innerHTML =
            `<tr><td colspan="8" class="text-center text-danger">Error loading data: ${error.message}</td></tr>`;
    }
}

function renderTable() {
    const table = document.getElementById('government_officialsTable');
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, officialsData.length);
    
    if (officialsData.length === 0) {
        table.innerHTML = `<tr><td colspan="8" class="text-center">No officials found</td></tr>`;
        return;
    }
    
    let html = '';
    for (let i = startIndex; i < endIndex; i++) {
        const official = officialsData[i];
        html += `
        <tr>
            <td>${official.official_id || ''}</td>
            <td>${official.first_name || ''}</td>
            <td>${official.last_name || ''}</td>
            <td>${official.role || ''}</td>
            <td>${official.contact_phone || ''}</td>
            <td>${official.contact_email || ''}</td>
            <td>${official.authorized_area || ''}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-primary" onclick="viewOfficial(${official.official_id})">View</button>
                    <button class="btn btn-outline-secondary" onclick="editOfficial(${official.official_id})">Edit</button>
                    <button class="btn btn-outline-danger" onclick="deleteOfficial(${official.official_id})">Delete</button>
                </div>
            </td>
        </tr>`;
    }
    
    table.innerHTML = html;
    document.getElementById('pageNumber').textContent = `Page ${currentPage} of ${Math.ceil(officialsData.length / itemsPerPage)}`;
}

function filterTable() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    if (searchTerm === '') {
        renderTable();
        return;
    }
    
    // Multi-field search across all official data
    const filteredData = officialsData.filter(official => 
        (official.first_name && official.first_name.toLowerCase().includes(searchTerm)) ||
        (official.last_name && official.last_name.toLowerCase().includes(searchTerm)) ||
        (official.email && official.email.toLowerCase().includes(searchTerm)) ||
        (official.official_id && official.official_id.toString().toLowerCase().includes(searchTerm)) ||
        (official.contact_phone && official.contact_phone.toLowerCase().includes(searchTerm)) ||
        (official.authorized_area && official.authorized_area.toLowerCase().includes(searchTerm))
    );
    
    const table = document.getElementById('government_officialsTable');
    
    if (filteredData.length === 0) {
        table.innerHTML = `<tr><td colspan="8" class="text-center">No matching officials found</td></tr>`;
        return;
    }
    
    let html = '';
    filteredData.forEach(official => {
        html += `
        <tr>
            <td>${official.official_id || ''}</td>
            <td>${official.first_name || ''}</td>
            <td>${official.last_name || ''}</td>
            <td>${official.role || ''}</td>
            <td>${official.contact_phone || ''}</td>
            <td>${official.contact_email || ''}</td>
            <td>${official.authorized_area || ''}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-primary" onclick="viewOfficial(${official.official_id})">View</button>
                    <button class="btn btn-outline-secondary" onclick="editOfficial(${official.official_id})">Edit</button>
                    <button class="btn btn-outline-danger" onclick="deleteOfficial(${official.official_id})">Delete</button>
                </div>
            </td>
        </tr>`;
    });
    
    table.innerHTML = html;
}

function sortTable(columnIndex) {
    const headers = document.querySelectorAll('th');
    
    // Reset sort indicators on other columns
    headers.forEach((header, index) => {
        if (index !== columnIndex) {
            header.textContent = header.textContent.replace(' ▲', ' ⬍').replace(' ▼', ' ⬍');
        }
    });
    
    const headerText = headers[columnIndex].textContent;
    const isAscending = !headerText.includes('▲');
    
    headers[columnIndex].textContent = headerText.replace(' ⬍', '').replace(' ▲', '').replace(' ▼', '') + 
        (isAscending ? ' ▲' : ' ▼');
    
    const properties = ['official_id', 'first_name', 'last_name', 'role', 'contact_phone', 'contact_email', 'authorized_area'];
    const property = properties[columnIndex];
    
    officialsData.sort((a, b) => {
        const valA = (a[property] || '').toString();
        const valB = (b[property] || '').toString();
        
        if (isAscending) {
            return valA.localeCompare(valB);
        } else {
            return valB.localeCompare(valA);
        }
    });
    
    currentPage = 1;
    renderTable();
}

function nextPage() {
    const maxPage = Math.ceil(officialsData.length / itemsPerPage);
    if (currentPage < maxPage) {
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

function viewOfficial(id) {
    window.location.href = `view_official.php?id=${id}`;
}

function editOfficial(id) {
    window.location.href = `edit_official.php?id=${id}`;
}

function deleteOfficial(id) {
    if (confirm(`Are you sure you want to delete official with ID: ${id}?`)) {
        window.location.href = `government_officials.php?action=delete&id=${id}`;
    }
}

document.addEventListener('DOMContentLoaded', fetchOfficials);