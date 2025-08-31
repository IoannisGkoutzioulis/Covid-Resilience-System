<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

// Role-based access: Only Admin and Official can manage doctors
$can_manage_doctors = ($is_admin || $is_official);

$success_message = $error_message = '';
$refresh_needed = false;

if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
    $refresh_needed = true;
}
if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

if ($can_manage_doctors) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_doctor') {
        $name = sanitizeInput($_POST['name']);
        $age = (int)$_POST['age'];
        $email = sanitizeInput($_POST['email']);
        
        $errors = [];
        if (empty($name)) {
            $errors[] = "Doctor name is required";
        }
        
        // Age validation: Medical professionals typically 20-100 years old
        if ($age < 20 || $age > 100) {
            $errors[] = "Age must be between 20 and 100";
        }
        
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }
        
        // Prevent duplicate email addresses
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM doctors WHERE email = ?");
                $checkStmt->execute([$email]);
                $emailExists = $checkStmt->fetchColumn() > 0;
                
                if ($emailExists) {
                    $error_message = "Error: Email address already exists";
                } else {
                    $stmt = $pdo->prepare("INSERT INTO doctors (name, age, email) VALUES (?, ?, ?)");
                    $stmt->execute([$name, $age, $email]);
                    
                    $success_message = "Doctor added successfully!";
                    $refresh_needed = true;
                    
                    $name = $age = $email = '';
                    
                    logAccess($_SESSION['user_id'], 'Added new doctor: ' . $name, true);
                }
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
            }
        } else {
            $error_message = "Please correct the following errors: " . implode(", ", $errors);
        }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_doctor') {
        $id = (int)$_POST['id'];
        $name = sanitizeInput($_POST['name']);
        $age = (int)$_POST['age'];
        $email = sanitizeInput($_POST['email']);
        
        $errors = [];
        if (empty($name)) {
            $errors[] = "Doctor name is required";
        }
        
        if ($age < 20 || $age > 100) {
            $errors[] = "Age must be between 20 and 100";
        }
        
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }
        
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                
                // Check email uniqueness excluding current doctor
                $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM doctors WHERE email = ? AND id != ?");
                $checkStmt->execute([$email, $id]);
                $emailExists = $checkStmt->fetchColumn() > 0;
                
                if ($emailExists) {
                    $error_message = "Error: Email address already exists for another doctor";
                } else {
                    $stmt = $pdo->prepare("UPDATE doctors SET name = ?, age = ?, email = ? WHERE id = ?");
                    $stmt->execute([$name, $age, $email, $id]);
                    
                    if ($stmt->rowCount() > 0) {
                        $success_message = "Doctor updated successfully!";
                        $refresh_needed = true;
                        
                        logAccess($_SESSION['user_id'], 'Updated doctor ID: ' . $id . ' (' . $name . ')', true);
                    } else {
                        $error_message = "No changes were made or doctor not found";
                    }
                }
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
            }
        } else {
            $error_message = "Please correct the following errors: " . implode(", ", $errors);
        }
    }

    if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
        $id = (int)$_GET['id'];
        
        try {
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("DELETE FROM doctors WHERE id = ?");
            $stmt->execute([$id]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "Doctor deleted successfully";
                $refresh_needed = true;
                
                logAccess($_SESSION['user_id'], 'Deleted doctor ID: ' . $id, true);
            } else {
                $error_message = "Doctor not found";
            }
        } catch (PDOException $e) {
            $error_message = "Error deleting doctor: " . $e->getMessage();
        }
    }
} else {
    // Log unauthorized access attempts
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['action']) && $_GET['action'] === 'delete')) {
        $error_message = "You don't have permission to manage doctors";
        logAccess($_SESSION['user_id'], 'Unauthorized attempt to manage doctors', false);
    }
}

$doctors = [];
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT * FROM doctors ORDER BY id DESC");
    $doctors = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching doctors: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Management - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        
        .top-bar {
            background: linear-gradient(90deg, #0d6efd, #0dcaf0);
            color: white;
            padding: 15px 0;
        }
        
        .card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .sidebar {
            background-color: #343a40;
            color: white;
            min-height: calc(100vh - 60px);
        }
        
        .sidebar .nav-link {
            color: rgba(255, 255, 255, 0.8);
            border-radius: 5px;
            margin-bottom: 5px;
        }
        
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
        }
        
        .user-profile {
            padding: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 15px;
        }
        
        .read-only-notice {
            background-color: #f8f9fa;
            border-left: 4px solid #0d6efd;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .role-badge {
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            display: inline-block;
            margin-left: 0.5rem;
        }
        
        .role-admin {
            background: #dc3545;
            color: white;
        }
        
        .role-official {
            background: #fd7e14;
            color: white;
        }
        
        .role-merchant {
            background: #6f42c1;
            color: white;
        }
        
        .role-citizen {
            background: #20c997;
            color: white;
        }
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="container-fluid">
            <div class="row align-items-center">
                <div class="col">
                    <h4 class="mb-0">
                        <i class="bi bi-shield-fill-check me-2"></i>
                        COVID Resilience System
                    </h4>
                </div>
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle d-flex align-items-center" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle me-1"></i>
                            <?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?>
                            <span class="role-badge role-<?php echo strtolower($_SESSION['role']); ?>"><?php echo $_SESSION['role']; ?></span>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="profile.php"><i class="bi bi-person-gear me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2 sidebar p-0">
                <div class="user-profile">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-person-circle fs-1 me-2"></i>
                        <div>
                            <h6 class="mb-0"><?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?></h6>
                            <small class="text-muted"><?php echo htmlspecialchars($_SESSION['role']); ?></small>
                        </div>
                    </div>
                </div>
                <ul class="nav flex-column px-3">
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">
                            <i class="bi bi-speedometer2 me-2"></i>Dashboard
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="users.php">
                            <i class="bi bi-people me-2"></i>Users
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link active" href="doctors.php">
                            <i class="bi bi-hospital me-2"></i>Doctors
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="government_officials.php">
                            <i class="bi bi-building me-2"></i>Officials
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="merchants.php">
                            <i class="bi bi-shop me-2"></i>Merchants
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="vaccination_records.php">
                            <i class="bi bi-clipboard2-pulse me-2"></i>Vaccinations
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="purchases.php">
                            <i class="bi bi-cart me-2"></i>Purchases
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="stock.php">
                            <i class="bi bi-box-seam me-2"></i>Stock
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="visualization_dashboard.php">
                            <i class="bi bi-bar-chart-fill me-2"></i>Visualizations
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="access_logs.php">
                            <i class="bi bi-file-earmark-text me-2"></i>Access Logs
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="document_upload.php">
                            <i class="bi bi-file-earmark-arrow-up me-2"></i>Documents
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="critical_items.php">
                            <i class="bi bi-shield-plus me-2"></i>Critical Items
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="profile.php">
                            <i class="bi bi-person-gear me-2"></i>My Profile
                        </a>
                    </li>
                    
                    <li class="nav-item mt-5">
                        <a class="nav-link text-danger" href="logout.php">
                            <i class="bi bi-box-arrow-right me-2"></i>Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="col-md-10 p-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-hospital me-2"></i>Doctor Management</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        
                        <?php if ($can_manage_doctors): ?>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addDoctorModal">
                            <i class="bi bi-plus-circle me-2"></i>Add New Doctor
                        </button>
                        <?php endif; ?>
                    </div>
                </div>
                
                <?php if (!empty($success_message)): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="bi bi-check-circle-fill me-2"></i><?php echo htmlspecialchars($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <?php if (!empty($error_message)): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <?php if (!$can_manage_doctors): ?>
                <div class="read-only-notice mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill text-primary me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">View-Only Access</h5>
                            <p class="mb-0">As a <?php echo htmlspecialchars($_SESSION['role']); ?>, you have read-only access to doctor information. Only Administrators and Government Officials can manage doctors.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchDoctor" class="form-control" placeholder="Search by name or email..." oninput="filterDoctors()">
                        </div>

                        <div class="table-responsive">
                            <table id="doctorsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Age <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Email <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if ($can_manage_doctors): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($doctors)): ?>
                                    <tr><td colspan="<?php echo $can_manage_doctors ? '5' : '4'; ?>" class="text-center">No doctors found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($doctors as $doctor): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($doctor['id']); ?></td>
                                        <td><?php echo htmlspecialchars($doctor['name']); ?></td>
                                        <td><?php echo htmlspecialchars($doctor['age'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($doctor['email'] ?? 'N/A'); ?></td>
                                        <?php if ($can_manage_doctors): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewDoctor(<?php echo htmlspecialchars($doctor['id']); ?>, '<?php echo htmlspecialchars($doctor['name']); ?>', <?php echo htmlspecialchars($doctor['age'] ?? 0); ?>, '<?php echo htmlspecialchars($doctor['email'] ?? ''); ?>')">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editDoctor(<?php echo htmlspecialchars($doctor['id']); ?>, '<?php echo htmlspecialchars($doctor['name']); ?>', <?php echo htmlspecialchars($doctor['age'] ?? 0); ?>, '<?php echo htmlspecialchars($doctor['email'] ?? ''); ?>')">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo htmlspecialchars($doctor['id']); ?>, '<?php echo htmlspecialchars($doctor['name']); ?>')">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </td>
                                        <?php endif; ?>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>

                        <div class="d-flex justify-content-between mt-3">
                            <div>
                                Total: <span id="totalDoctors"><?php echo count($doctors); ?></span> doctor<?php echo count($doctors) != 1 ? 's' : ''; ?>
                            </div>
                            <div>
                                <button type="button" class="btn btn-secondary" onclick="window.location.reload();">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <?php if ($can_manage_doctors): ?>
    <div class="modal fade" id="addDoctorModal" tabindex="-1" aria-labelledby="addDoctorModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addDoctorModalLabel"><i class="bi bi-person-plus me-2"></i>Add New Doctor</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="doctors.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_doctor">
                        
                        <div class="mb-3">
                            <label for="name" class="form-label">Name</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="age" class="form-label">Age</label>
                            <input type="number" class="form-control" id="age" name="age" min="20" max="100" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Doctor</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="viewDoctorModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-person-badge me-2"></i>Doctor Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-3">
                        <i class="bi bi-person-circle text-primary" style="font-size: 4rem;"></i>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <h6>Doctor ID</h6>
                            <p id="view-id" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Name</h6>
                            <p id="view-name" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Age</h6>
                            <p id="view-age" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Email</h6>
                            <p id="view-email" class="text-muted"></p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="editDoctorModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Doctor</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="editDoctorForm" action="doctors.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="update_doctor">
                        <input type="hidden" id="edit-id" name="id">
                        
                        <div class="mb-3">
                            <label for="edit-name" class="form-label">Name</label>
                            <input type="text" class="form-control" id="edit-name" name="name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-age" class="form-label">Age</label>
                            <input type="number" class="form-control" id="edit-age" name="age" min="20" max="100" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="edit-email" name="email" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Auto-close modals after successful operations
    <?php if ($refresh_needed): ?>
    document.addEventListener("DOMContentLoaded", function() {
        try {
            const addModal = document.getElementById('addDoctorModal');
            const editModal = document.getElementById('editDoctorModal');
            
            const addModalInstance = bootstrap.Modal.getInstance(addModal);
            if (addModalInstance) {
                addModalInstance.hide();
            }
            
            const editModalInstance = bootstrap.Modal.getInstance(editModal);
            if (editModalInstance) {
                editModalInstance.hide();
            }
        } catch (e) {
            console.error("Error closing modal:", e);
        }
    });
    <?php endif; ?>
    
    const allRows = Array.from(document.querySelectorAll('#doctorsTable tbody tr'));
    
    function filterDoctors() {
        const filter = document.getElementById("searchDoctor").value.toLowerCase();
        
        allRows.forEach(row => {
            const name = row.cells[1]?.textContent.toLowerCase() || '';
            const email = row.cells[3]?.textContent.toLowerCase() || '';
            const id = row.cells[0]?.textContent || '';
            
            if (name.includes(filter) || email.includes(filter) || id.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updateFilterCount();
    }
    
    function updateFilterCount() {
        const visibleRows = allRows.filter(row => row.style.display !== 'none').length;
        document.getElementById('totalDoctors').textContent = visibleRows;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('doctorsTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            const aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            const bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Handle numeric sorting for ID and age columns
            if (colIndex === 0 || colIndex === 2) {
                return parseInt(aValue) - parseInt(bValue);
            }
            
            return aValue.localeCompare(bValue);
        });
        
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }
        
        rows.forEach(row => {
            tbody.appendChild(row);
        });
    }
    
    <?php if ($can_manage_doctors): ?>
    function viewDoctor(id, name, age, email) {
        document.getElementById('view-id').textContent = id;
        document.getElementById('view-name').textContent = name;
        document.getElementById('view-age').textContent = age || 'N/A';
        document.getElementById('view-email').textContent = email || 'N/A';
        
        const modal = new bootstrap.Modal(document.getElementById('viewDoctorModal'));
        modal.show();
    }
    
    function editDoctor(id, name, age, email) {
        document.getElementById('edit-id').value = id;
        document.getElementById('edit-name').value = name;
        document.getElementById('edit-age').value = age || '';
        document.getElementById('edit-email').value = email || '';
        
        const modal = new bootstrap.Modal(document.getElementById('editDoctorModal'));
        modal.show();
    }
    
    function confirmDelete(id, name) {
        if (confirm(`Are you sure you want to delete doctor "${name}"?`)) {
            window.location.href = `doctors.php?action=delete&id=${id}`;
        }
    }
    <?php endif; ?>
    </script>
</body>
</html>