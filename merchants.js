let merchantsData = [];
let currentPage = 1;
const rowsPerPage = 10;

document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("merchantsTable")) {
        fetchData("merchants");
    }
});

function fetchData(table) {
    fetch(`fetch_data.php?table=${encodeURIComponent(table)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#merchantsTable").innerHTML = `<tr><td colspan="3" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            merchantsData = data;
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#merchantsTable").innerHTML = `<tr><td colspan="3" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable(data = merchantsData) {
    const tableBody = document.querySelector("#merchantsTable");
    tableBody.innerHTML = "";

    if (data.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="3" class="text-center">No merchants found</td></tr>`;
        return;
    }

    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;
    let paginatedData = data.slice(start, end);

    paginatedData.forEach(merchant => {
        const row = `<tr>
            <td>${merchant.merchant_id}</td>
            <td>${merchant.merchant_name}</td>
            <td>${merchant.contact_email}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewMerchant(${merchant.merchant_id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editMerchant(${merchant.merchant_id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${merchant.merchant_id}, '${merchant.merchant_name}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });

    document.getElementById("pageNumber").innerText = `Page ${currentPage}`;
}

function nextPage() {
    if (currentPage * rowsPerPage < merchantsData.length) {
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
    merchantsData.sort((a, b) => {
        let aValue = Object.values(a)[colIndex].toString().toLowerCase();
        let bValue = Object.values(b)[colIndex].toString().toLowerCase();
        return aValue.localeCompare(bValue);
    });

    renderTable();
}

function filterTable() {
    let filter = document.getElementById("searchInput").value.toLowerCase();
    // Multi-field search across merchant data
    let filteredData = merchantsData.filter(merchant =>
        (merchant.merchant_name && merchant.merchant_name.toLowerCase().includes(filter)) ||
        (merchant.contact_email && merchant.contact_email.toLowerCase().includes(filter)) ||
        (merchant.merchant_id && merchant.merchant_id.toString().includes(filter))
    );

    renderTable(filteredData);
}

function viewMerchant(id) {
    window.location.href = `view_merchant.php?id=${id}`;
}

function editMerchant(id) {
    window.location.href = `edit_merchant.php?id=${id}`;
}

function confirmDelete(id, name) {
    if (confirm(`Are you sure you want to delete merchant "${name}"?`)) {
        window.location.href = `merchants.php?action=delete&id=${id}`;
    }
}