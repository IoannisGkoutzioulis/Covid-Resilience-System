let usersData = [];
let currentPage = 1;
const rowsPerPage = 10;
let originalUsersData = []; // Preserve original dataset for search functionality

document.addEventListener("DOMContentLoaded", function () {
    fetchUsers();
});

function fetchUsers() {
    fetch('fetch_data.php?table=users')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#usersTable").innerHTML = 
                    `<tr><td colspan="8" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            usersData = data;
            originalUsersData = [...data];
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#usersTable").innerHTML = 
                `<tr><td colspan="8" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable() {
    const tableBody = document.querySelector("#usersTable");
    tableBody.innerHTML = "";
    
    if (usersData.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center">No users found</td></tr>`;
        return;
    }
    
    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;    
    let paginatedData = usersData.slice(start, end);
    
    paginatedData.forEach(user => {
        // Role-based color scheme for user identification
        let roleBadgeClass = 'bg-secondary';
        if (user.role === 'Citizen') roleBadgeClass = 'bg-success';
        if (user.role === 'Merchant') roleBadgeClass = 'bg-warning';
        if (user.role === 'Official') roleBadgeClass = 'bg-danger';
        
        const row = `<tr>
            <td>${user.user_id}</td>
            <td>${user.prs_id}</td>
            <td>${user.full_name}</td>
            <td>${user.national_id}</td>
            <td>${user.dob}</td>
            <td><span class="badge ${roleBadgeClass}">${user.role}</span></td>
            <td>${user.username}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewUser(${user.user_id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editUser(${user.user_id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${user.user_id}, '${user.full_name}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });
    
    document.getElementById("pageNumber").innerText = `Page ${currentPage} of ${Math.ceil(usersData.length / rowsPerPage)}`;
}

function nextPage() {
    if (currentPage * rowsPerPage < usersData.length) {
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
    usersData.sort((a, b) => {
        let aValue = Object.values(a)[colIndex].toString().toLowerCase();
        let bValue = Object.values(b)[colIndex].toString().toLowerCase();
        return aValue.localeCompare(bValue);
    });
    
    currentPage = 1;
    renderTable();
}

function filterTable() {  
    let filter = document.getElementById("searchInput").value.toLowerCase();
    
    if (filter === "") {
        usersData = [...originalUsersData];
    } else {
        // Multi-field search across name, username, PRS ID, and national ID
        usersData = originalUsersData.filter(user =>
            user.full_name.toLowerCase().includes(filter) ||
            user.username.toLowerCase().includes(filter) ||
            user.prs_id.toLowerCase().includes(filter) ||
            user.national_id.toLowerCase().includes(filter)
        );
    }
    
    currentPage = 1;
    renderTable();
}

function viewUser(id) {
    const user = usersData.find(u => u.user_id == id);
    if (user) {
        document.getElementById('view-id').textContent = user.user_id;
        document.getElementById('view-name').textContent = user.full_name;
        document.getElementById('view-prs-id').textContent = user.prs_id;
        document.getElementById('view-national-id').textContent = user.national_id;
        document.getElementById('view-dob').textContent = user.dob;
        document.getElementById('view-role').textContent = user.role;
        document.getElementById('view-username').textContent = user.username;
        document.getElementById('view-created').textContent = user.created_at;
        
        // Role-based color scheme for user identification
        let roleBadgeClass = 'bg-secondary';
        if (user.role === 'Citizen') roleBadgeClass = 'bg-success';
        if (user.role === 'Merchant') roleBadgeClass = 'bg-warning';
        if (user.role === 'Official') roleBadgeClass = 'bg-danger';
        document.getElementById('view-role').className = `badge ${roleBadgeClass}`;
        
        const modal = new bootstrap.Modal(document.getElementById('viewUserModal'));
        modal.show();
    }
}

function editUser(id) {
    window.location.href = `user_edit.php?id=${id}`;
}

function confirmDelete(id, name) {
    if (confirm(`Are you sure you want to delete user "${name}"?`)) {
        window.location.href = `users.php?action=delete&id=${id}`;
    }
}