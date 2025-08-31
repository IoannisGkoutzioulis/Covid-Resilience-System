let access_logsData = [];
let currentPage = 1;
const rowsPerPage = 15;
let originalData = [];

document.addEventListener("DOMContentLoaded", function () {
    fetchLogs();
});

function fetchLogs() {
    fetch('fetch_data.php?table=access_logs')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#access_logsTable").innerHTML = 
                    `<tr><td colspan="7" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            access_logsData = data;
            originalData = [...data]; // Keep original copy for filtering
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#access_logsTable").innerHTML = 
                `<tr><td colspan="7" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable() {
    const tableBody = document.querySelector("#access_logsTable");
    tableBody.innerHTML = "";
    
    if (access_logsData.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" class="text-center">No access logs found</td></tr>`;
        return;
    }
    
    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;    
    let paginatedData = access_logsData.slice(start, end);
    
    paginatedData.forEach(log => {
        const formattedDate = new Date(log.timestamp).toLocaleString();
        
        // Success/failure status badge
        const statusBadge = log.success == 1 
            ? '<span class="badge bg-success">Success</span>' 
            : '<span class="badge bg-danger">Failed</span>';
        
        const row = `<tr>
            <td>${log.log_id}</td>
            <td>${log.user_id}</td>
            <td>${log.access_type}</td>
            <td>${formattedDate}</td>
            <td>${log.ip_address}</td>
            <td>${log.location}</td>
            <td>${statusBadge}</td>
        </tr>`;
        tableBody.innerHTML += row;
    });
    
    document.getElementById("pageNumber").innerText = 
        `Page ${currentPage} of ${Math.ceil(access_logsData.length / rowsPerPage)}`;
}

function nextPage() {
    if (currentPage * rowsPerPage < access_logsData.length) {
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
    access_logsData.sort((a, b) => {
        let aValue, bValue;
        
        // Special handling for timestamp column (index 3)
        if (colIndex === 3) {
            aValue = new Date(a.timestamp).getTime();
            bValue = new Date(b.timestamp).getTime();
            return aValue - bValue;
        } else {
            aValue = Object.values(a)[colIndex].toString().toLowerCase();
            bValue = Object.values(b)[colIndex].toString().toLowerCase();
            return aValue.localeCompare(bValue);
        }
    });
    
    currentPage = 1;
    renderTable();
}

function filterTable() {  
    let filter = document.getElementById("searchInput").value.toLowerCase();
    
    if (filter === "") {
        access_logsData = [...originalData];
    } else {
        // Search across multiple fields
        access_logsData = originalData.filter(log =>
            log.access_type.toLowerCase().includes(filter) ||
            log.ip_address.toLowerCase().includes(filter) ||
            log.location.toLowerCase().includes(filter) ||
            log.log_id.toString().includes(filter) ||
            log.user_id.toString().includes(filter)
        );
    }
    
    currentPage = 1;
    renderTable();
}

function confirmClearOld() {
    if (confirm("Are you sure you want to clear access logs older than 30 days? This action cannot be undone.")) {
        window.location.href = "access_logs.php?action=clear_old";
    }
}