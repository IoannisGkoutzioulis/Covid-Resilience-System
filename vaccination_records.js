let vaccination_recordsData = [];
let currentPage = 1;
const rowsPerPage = 10;

document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("vaccination_recordsTable")) {
        fetchData("vaccination_records");
    }
});

function fetchData(table) {
    fetch(`fetch_data.php?table=${encodeURIComponent(table)}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#vaccination_recordsTable").innerHTML = `<tr><td colspan="8" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            vaccination_recordsData = data;
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#vaccination_recordsTable").innerHTML = `<tr><td colspan="8" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable(data = vaccination_recordsData) {
    const tableBody = document.querySelector("#vaccination_recordsTable");
    tableBody.innerHTML = "";

    if (data.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center">No vaccination records found</td></tr>`;
        return;
    }

    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;
    let paginatedData = data.slice(start, end);

    paginatedData.forEach(record => {
        const row = `<tr>
            <td>${record.vaccination_id}</td>
            <td>${record.user_id}</td>
            <td>${record.vaccine_type}</td>
            <td>${record.dose_number}</td>
            <td>${record.date_administered}</td>
            <td>${record.administered_by}</td>
            <td>${record.traveler_flag}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewVaccination(${record.vaccination_id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editVaccination(${record.vaccination_id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${record.vaccination_id})">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });

    document.getElementById("pageNumber").innerText = `Page ${currentPage}`;
}

function nextPage() {
    if (currentPage * rowsPerPage < vaccination_recordsData.length) {
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
    vaccination_recordsData.sort((a, b) => {
        let aValue = Object.values(a)[colIndex].toString().toLowerCase();
        let bValue = Object.values(b)[colIndex].toString().toLowerCase();
        return aValue.localeCompare(bValue);
    });

    renderTable();
}

function filterTable() {
    let filter = document.getElementById("searchInput").value.toLowerCase();
    // Multi-field search across vaccination record data
    let filteredData = vaccination_recordsData.filter(record =>
        (record.vaccine_type && record.vaccine_type.toLowerCase().includes(filter)) ||
        (record.user_id && record.user_id.toString().includes(filter)) ||
        (record.administered_by && record.administered_by.toLowerCase().includes(filter)) ||
        (record.vaccination_id && record.vaccination_id.toString().includes(filter))
    );

    renderTable(filteredData);
}

function viewVaccination(id) {
    window.location.href = `view_vaccination.php?id=${id}`;
}

function editVaccination(id) {
    window.location.href = `edit_vaccination.php?id=${id}`;
}

function confirmDelete(id) {
    if (confirm(`Are you sure you want to delete vaccination record with ID: ${id}?`)) {
        window.location.href = `delete_vaccination.php?id=${id}`;
    }
}