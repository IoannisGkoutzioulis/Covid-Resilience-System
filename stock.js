let stockData = [];
let currentPage = 1;
const rowsPerPage = 10;

document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("stockTable")) {
        fetchData("stock");
    }
});

function fetchData(table) {
    fetch(`fetch_data.php?table=${encodeURIComponent(table)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#stockTable").innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            stockData = data;
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#stockTable").innerHTML = `<tr><td colspan="5" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable(data = stockData) {
    const tableBody = document.querySelector("#stockTable");
    tableBody.innerHTML = "";

    if (data.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center">No stock found</td></tr>`;
        return;
    }

    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;
    let paginatedData = data.slice(start, end);

    paginatedData.forEach(item => {
        const row = `<tr>
            <td>${item.stock_id}</td>
            <td>${item.merchant_id}</td>
            <td>${item.item_name}</td>
            <td>${item.quantity_available}</td>
            <td>${item.last_updated}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewStock(${item.stock_id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editStock(${item.stock_id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${item.stock_id}, '${item.item_name}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });

    document.getElementById("pageNumber").innerText = `Page ${currentPage}`;
}

function nextPage() {
    if (currentPage * rowsPerPage < stockData.length) {
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
    stockData.sort((a, b) => {
        let aValue = Object.values(a)[colIndex].toString().toLowerCase();
        let bValue = Object.values(b)[colIndex].toString().toLowerCase();
        return aValue.localeCompare(bValue);
    });

    renderTable();
}

function filterTable() {
    let filter = document.getElementById("searchInput").value.toLowerCase();
    let filteredData = stockData.filter(item =>
        (item.item_name && item.item_name.toLowerCase().includes(filter)) ||
        (item.merchant_id && item.merchant_id.toString().includes(filter)) ||
        (item.stock_id && item.stock_id.toString().includes(filter))
    );

    renderTable(filteredData);
}

function viewStock(id) {
    window.location.href = `stock.php?action=view&id=${id}`;
}

function editStock(id) {
    window.location.href = `stock.php?action=edit&id=${id}`;
}

function confirmDelete(id, name) {
    if (confirm(`Are you sure you want to delete stock item "${name}"?`)) {
        window.location.href = `stock.php?action=delete&id=${id}`;
    }
}