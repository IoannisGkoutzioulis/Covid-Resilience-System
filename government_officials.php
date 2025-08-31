<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

// Role-based access: Only Admin and Official can manage officials
$can_manage_officials = ($is_admin || $is_official);

$success_message = $error_message = '';
$refresh_needed = false;

if ($can_manage_officials) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_official') {
        $first_name = sanitizeInput($_POST['first_name']);
        $last_name = sanitizeInput($_POST['last_name']);
        $role = sanitizeInput($_POST['role']);
        $contact_phone = sanitizeInput($_POST['contact_phone']);
        $contact_email = sanitizeInput($_POST['contact_email']);
        $authorized_area = sanitizeInput($_POST['authorized_area']);
        
        $errors = [];
        if (empty($first_name)) {
            $errors[] = "First name is required";
        }
        
        if (empty($last_name)) {
            $errors[] = "Last name is required";
        }
        
        if (empty($role)) {
            $errors[] = "Role is required";
        }
        
        if (!empty($contact_email) && !filter_var($contact_email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }
        
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                
                // Prevent duplicate email addresses
                if (!empty($contact_email)) {
                    $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM government_officials WHERE contact_email = ?");
                    $checkStmt->execute([$contact_email]);
                    $emailExists = $checkStmt->fetchColumn() > 0;
                    
                    if ($emailExists) {
                        $error_message = "Error: Email address already exists";
                        goto skip_insertion;
                    }
                }
                
                $stmt = $pdo->prepare("INSERT INTO government_officials (first_name, last_name, role, contact_phone, contact_email, authorized_area) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$first_name, $last_name, $role, $contact_phone, $contact_email, $authorized_area]);
                
                $success_message = "Official added successfully!";
                $refresh_needed = true;
                
                logAccess($_SESSION['user_id'], 'Added new official: ' . $first_name . ' ' . $last_name, true);
                
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
            }
        } else {
            $error_message = "Please correct the following errors: " . implode(", ", $errors);
        }
        
        skip_insertion:
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_official') {
        $official_id = (int)$_POST['official_id'];
        $first_name = sanitizeInput($_POST['first_name']);
        $last_name = sanitizeInput($_POST['last_name']);
        $role = sanitizeInput($_POST['role']);
        $contact_phone = sanitizeInput($_POST['contact_phone']);
        $contact_email = sanitizeInput($_POST['contact_email']);
        $authorized_area = sanitizeInput($_POST['authorized_area']);
        
        $errors = [];
        if (empty($first_name)) {
            $errors[] = "First name is required";
        }
        
        if (empty($last_name)) {
            $errors[] = "Last name is required";
        }
        
        if (empty($role)) {
            $errors[] = "Role is required";
        }
        
        if (!empty($contact_email) && !filter_var($contact_email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }
        
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                
                // Check email uniqueness excluding current official
                if (!empty($contact_email)) {
                    $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM government_officials WHERE contact_email = ? AND official_id != ?");
                    $checkStmt->execute([$contact_email, $official_id]);
                    $emailExists = $checkStmt->fetchColumn() > 0;
                    
                    if ($emailExists) {
                        $error_message = "Error: Email address already exists for another official";
                        goto skip_update;
                    }
                }
                
                $stmt = $pdo->prepare("UPDATE government_officials SET first_name = ?, last_name = ?, role = ?, contact_phone = ?, contact_email = ?, authorized_area = ? WHERE official_id = ?");
                $stmt->execute([$first_name, $last_name, $role, $contact_phone, $contact_email, $authorized_area, $official_id]);
                
                if ($stmt->rowCount() > 0) {
                    $success_message = "Official updated successfully!";
                    $refresh_needed = true;
                    
                    logAccess($_SESSION['user_id'], 'Updated official ID: ' . $official_id . ' (' . $first_name . ' ' . $last_name . ')', true);
                } else {
                    $error_message = "No changes were made or official not found";
                }
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
            }
        } else {
            $error_message = "Please correct the following errors: " . implode(", ", $errors);
        }
        
        skip_update:
    }

    if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
        $id = (int)$_GET['id'];
        
        try {
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("DELETE FROM government_officials WHERE official_id = ?");
            $stmt->execute([$id]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "Official deleted successfully";
                $refresh_needed = true;
                
                logAccess($_SESSION['user_id'], 'Deleted official ID: ' . $id, true);
            } else {
                $error_message = "Official not found";
            }
        } catch (PDOException $e) {
            $error_message = "Error deleting official: " . $e->getMessage();
        }
    }
} else {
    // Log unauthorized access attempts
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['action']) && $_GET['action'] === 'delete')) {
        $error_message = "You don't have permission to manage government officials";
        logAccess($_SESSION['user_id'], 'Unauthorized attempt to manage officials', false);
    }
}

$officials = [];
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT * FROM government_officials ORDER BY official_id DESC");
    $officials = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching officials: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Government Officials - COVID Resilience System</title>
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
                        <a class="nav-link" href="doctors.php">
                            <i class="bi bi-hospital me-2"></i>Doctors
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link active" href="government_officials.php">
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
                    <h2><i class="bi bi-building me-2"></i>Government Officials</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        
                        <?php if ($can_manage_officials): ?>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addOfficialModal">
                            <i class="bi bi-plus-circle me-2"></i>Add New Official
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
                
                <?php if (!$can_manage_officials): ?>
                <div class="read-only-notice mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill text-primary me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">View-Only Access</h5>
                            <p class="mb-0">As a <?php echo htmlspecialchars($_SESSION['role']); ?>, you have read-only access to government officials information. Only Administrators and Government Officials can manage officials.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search officials..." oninput="filterTable()">
                        </div>

                        <div class="table-responsive">
                            <table id="officialsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">First Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Last Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Role <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">Contact Phone <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(5)">Email <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(6)">Area <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if ($can_manage_officials): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($officials)): ?>
                                    <tr><td colspan="<?php echo $can_manage_officials ? '8' : '7'; ?>" class="text-center">No officials found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($officials as $official): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($official['official_id']); ?></td>
                                        <td><?php echo htmlspecialchars($official['first_name']); ?></td>
                                        <td><?php echo htmlspecialchars($official['last_name']); ?></td>
                                        <td><?php echo htmlspecialchars($official['role']); ?></td>
                                        <td><?php echo htmlspecialchars($official['contact_phone'] ?? '-'); ?></td>
                                        <td><?php echo htmlspecialchars($official['contact_email'] ?? '-'); ?></td>
                                        <td><?php echo htmlspecialchars($official['authorized_area'] ?? '-'); ?></td>
                                        <?php if ($can_manage_officials): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewOfficial(<?php echo $official['official_id']; ?>)">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editOfficial(<?php echo $official['official_id']; ?>)">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $official['official_id']; ?>, '<?php echo htmlspecialchars($official['first_name'] . ' ' . $official['last_name']); ?>')">
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
                                Total: <span id="totalOfficials"><?php echo count($officials); ?></span> official<?php echo count($officials) != 1 ? 's' : ''; ?>
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
    
    <?php if ($can_manage_officials): ?>
    <div class="modal fade" id="addOfficialModal" tabindex="-1" aria-labelledby="addOfficialModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addOfficialModalLabel"><i class="bi bi-person-plus me-2"></i>Add New Official</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="government_officials.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_official">
                        
                        <div class="mb-3">
                            <label for="first_name" class="form-label">First Name</label>
                            <input type="text" class="form-control" id="first_name" name="first_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="last_name" class="form-label">Last Name</label>
                            <input type="text" class="form-control" id="last_name" name="last_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="role" class="form-label">Role</label>
                            <input type="text" class="form-control" id="role" name="role" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="contact_phone" class="form-label">Contact Phone</label>
                            <input type="text" class="form-control" id="contact_phone" name="contact_phone">
                        </div>
                        
                        <div class="mb-3">
                            <label for="contact_email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="contact_email" name="contact_email">
                        </div>
                        
                        <div class="mb-3">
                            <label for="authorized_area" class="form-label">Authorized Area</label>
                            <input type="text" class="form-control" id="authorized_area" name="authorized_area">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Official</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="viewOfficialModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-person-badge me-2"></i>Official Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-3">
                        <i class="bi bi-person-circle text-primary" style="font-size: 4rem;"></i>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <h6>Official ID</h6>
                            <p id="view-id" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Name</h6>
                            <p id="view-name" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Role</h6>
                            <p id="view-role" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Email</h6>
                            <p id="view-email" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Phone</h6>
                            <p id="view-phone" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Area</h6>
                            <p id="view-area" class="text-muted"></p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="editOfficialModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Official</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="editOfficialForm" action="government_officials.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="update_official">
                        <input type="hidden" id="edit-id" name="official_id">
                        
                        <div class="mb-3">
                            <label for="edit-first-name" class="form-label">First Name</label>
                            <input type="text" class="form-control" id="edit-first-name" name="first_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-last-name" class="form-label">Last Name</label>
                            <input type="text" class="form-control" id="edit-last-name" name="last_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-role" class="form-label">Role</label>
                            <input type="text" class="form-control" id="edit-role" name="role" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-phone" class="form-label">Contact Phone</label>
                            <input type="text" class="form-control" id="edit-phone" name="contact_phone">
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="edit-email" name="contact_email">
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-area" class="form-label">Authorized Area</label>
                            <input type="text" class="form-control" id="edit-area" name="authorized_area">
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
            const addModal = document.getElementById('addOfficialModal');
            const editModal = document.getElementById('editOfficialModal');
            
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
    
    const allRows = Array.from(document.querySelectorAll('#officialsTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        allRows.forEach(row => {
            const firstName = row.cells[1]?.textContent.toLowerCase() || '';
            const lastName = row.cells[2]?.textContent.toLowerCase() || '';
            const role = row.cells[3]?.textContent.toLowerCase() || '';
            const email = row.cells[5]?.textContent.toLowerCase() || '';
            const area = row.cells[6]?.textContent.toLowerCase() || '';
            const id = row.cells[0]?.textContent || '';
            
            if (firstName.includes(filter) || 
                lastName.includes(filter) || 
                role.includes(filter) || 
                email.includes(filter) || 
                area.includes(filter) || 
                id.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updateFilterCount();
    }
    
    function updateFilterCount() {
        const visibleRows = allRows.filter(row => row.style.display !== 'none').length;
        document.getElementById('totalOfficials').textContent = visibleRows;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('officialsTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            const aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            const bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Handle numeric sorting for ID column
            if (colIndex === 0) {
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
    
    <?php if ($can_manage_officials): ?>
    function viewOfficial(id) {
        // Find official data from table row
        const row = Array.from(document.querySelectorAll('#officialsTable tbody tr')).find(row => {
            return row.cells[0]?.textContent === id.toString();
        });
        
        if (row) {
            document.getElementById('view-id').textContent = row.cells[0].textContent;
            document.getElementById('view-name').textContent = row.cells[1].textContent + ' ' + row.cells[2].textContent;
            document.getElementById('view-role').textContent = row.cells[3].textContent;
            document.getElementById('view-phone').textContent = row.cells[4].textContent;
            document.getElementById('view-email').textContent = row.cells[5].textContent;
            document.getElementById('view-area').textContent = row.cells[6].textContent;
            
            const modal = new bootstrap.Modal(document.getElementById('viewOfficialModal'));
            modal.show();
        }
    }
    
    function editOfficial(id) {
        const row = Array.from(document.querySelectorAll('#officialsTable tbody tr')).find(row => {
            return row.cells[0]?.textContent === id.toString();
        });
        
        if (row) {
            document.getElementById('edit-id').value = row.cells[0].textContent;
            document.getElementById('edit-first-name').value = row.cells[1].textContent;
            document.getElementById('edit-last-name').value = row.cells[2].textContent;
            document.getElementById('edit-role').value = row.cells[3].textContent;
            document.getElementById('edit-phone').value = row.cells[4].textContent !== '-' ? row.cells[4].textContent : '';
            document.getElementById('edit-email').value = row.cells[5].textContent !== '-' ? row.cells[5].textContent : '';
            document.getElementById('edit-area').value = row.cells[6].textContent !== '-' ? row.cells[6].textContent : '';
            
            const modal = new bootstrap.Modal(document.getElementById('editOfficialModal'));
            modal.show();
        }
    }
    
    function confirmDelete(id, name) {
        if (confirm(`Are you sure you want to delete official "${name}"?`)) {
            window.location.href = `government_officials.php?action=delete&id=${id}`;
        }
    }
    <?php endif; ?>
    </script>
</body>
</html>