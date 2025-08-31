let doctorsData = [];
let currentPage = 1;
const rowsPerPage = 10;
let originalDoctorsData = [];

document.addEventListener("DOMContentLoaded", function () {
    fetchDoctors();
});

function fetchDoctors() {
    fetch('fetch_data.php?table=doctors')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                document.querySelector("#doctorsTable tbody").innerHTML = 
                    `<tr><td colspan="5" class="text-center text-danger">Error loading data</td></tr>`;
                return;
            }

            doctorsData = data;
            originalDoctorsData = [...data]; // Preserve original data for search reset
            renderTable();
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            document.querySelector("#doctorsTable tbody").innerHTML = 
                `<tr><td colspan="5" class="text-center text-danger">Failed to load data</td></tr>`;
        });
}

function renderTable() {
    const tableBody = document.querySelector("#doctorsTable tbody");
    tableBody.innerHTML = "";
    
    if (doctorsData.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center">No doctors found</td></tr>`;
        return;
    }
    
    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;    
    let paginatedData = doctorsData.slice(start, end);
    
    paginatedData.forEach(doctor => {
        const row = `<tr>
            <td>${doctor.id}</td>
            <td>${doctor.name}</td> 
            <td>${doctor.age}</td>  
            <td>${doctor.email}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewDoctor(${doctor.id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="editDoctor(${doctor.id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="confirmDelete(${doctor.id}, '${doctor.name}')">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });
    
    document.getElementById("doctorPageNumber").innerText = `Page ${currentPage} of ${Math.ceil(doctorsData.length / rowsPerPage)}`;
}

function nextDoctorPage() {
    if (currentPage * rowsPerPage < doctorsData.length) {
        currentPage++;
        renderTable();
    }
}

function prevDoctorPage() {
    if (currentPage > 1) {
        currentPage--;
        renderTable();
    }
}

function sortDoctors(colIndex) {
    doctorsData.sort((a, b) => {
        let aValue = Object.values(a)[colIndex].toString().toLowerCase();
        let bValue = Object.values(b)[colIndex].toString().toLowerCase();
        
        // Handle numeric sorting for ID and age columns
        if (colIndex === 0 || colIndex === 2) {
            return parseInt(aValue) - parseInt(bValue);
        }
        
        return aValue.localeCompare(bValue);
    });
    
    currentPage = 1;
    renderTable();
}

function filterDoctors() {  
    let filter = document.getElementById("searchDoctor").value.toLowerCase();
    
    if (filter === "") {
        doctorsData = [...originalDoctorsData];
    } else {
        // Multi-field search across name, email, and ID
        doctorsData = originalDoctorsData.filter(doctor =>
            doctor.name.toLowerCase().includes(filter) ||
            doctor.email.toLowerCase().includes(filter) ||
            doctor.id.toString().includes(filter)
        );
    }
    
    currentPage = 1;
    renderTable();
}

function viewDoctor(id) {
    const doctor = doctorsData.find(doc => doc.id == id);
    if (doctor) {
        document.getElementById('view-id').textContent = doctor.id;
        document.getElementById('view-name').textContent = doctor.name;
        document.getElementById('view-age').textContent = doctor.age;
        document.getElementById('view-email').textContent = doctor.email;
        
        const modal = new bootstrap.Modal(document.getElementById('viewDoctorModal'));
        modal.show();
    }
}

function editDoctor(id) {
    const doctor = doctorsData.find(doc => doc.id == id);
    if (doctor) {
        document.getElementById('edit-id').value = doctor.id;
        document.getElementById('edit-name').value = doctor.name;
        document.getElementById('edit-age').value = doctor.age;
        document.getElementById('edit-email').value = doctor.email;
        
        const modal = new bootstrap.Modal(document.getElementById('editDoctorModal'));
        modal.show();
    }
}

function confirmDelete(id, name) {
    if (confirm(`Are you sure you want to delete doctor "${name}"?`)) {
        window.location.href = `doctors.php?action=delete&id=${id}`;
    }
}