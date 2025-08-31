<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

// AJAX endpoint: Vaccination record details retrieval
if (isset($_GET['ajax']) && $_GET['ajax'] === 'get_vaccination_details' && isset($_GET['id'])) {
    header('Content-Type: application/json');
    
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT * FROM vaccination_records WHERE vaccination_id = ?");
        $stmt->execute([(int)$_GET['id']]);
        $vaccination = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($vaccination) {
            echo json_encode($vaccination);
        } else {
            echo json_encode(['error' => 'Vaccination record not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
    exit;
}

// AJAX endpoint: Vaccination record updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax']) && $_POST['ajax'] === 'update_vaccination') {
    header('Content-Type: application/json');
    
    try {
        $pdo = getDBConnection();
        
        $vaccination_id = (int)$_POST['vaccination_id'];
        $user_id = sanitizeInput($_POST['user_id']);
        $vaccine_type = sanitizeInput($_POST['vaccine_type']);
        $dose_number = (int)$_POST['dose_number'];
        $date_administered = sanitizeInput($_POST['date_administered']);
        $administered_by = sanitizeInput($_POST['administered_by']);
        $batch_number = sanitizeInput($_POST['batch_number']);
        $traveler_flag = isset($_POST['traveler_flag']) ? 1 : 0;
        $certification = sanitizeInput($_POST['certification']);
        $notes = sanitizeInput($_POST['notes']);
        
        $stmt = $pdo->prepare("UPDATE vaccination_records SET 
            user_id = ?, vaccine_type = ?, dose_number = ?, date_administered = ?, 
            administered_by = ?, batch_number = ?, traveler_flag = ?, certification = ?, notes = ? 
            WHERE vaccination_id = ?");
        
        $result = $stmt->execute([
            $user_id, $vaccine_type, $dose_number, $date_administered,
            $administered_by, $batch_number, $traveler_flag, $certification, $notes,
            $vaccination_id
        ]);
        
        if ($result) {
            echo json_encode(['success' => true, 'message' => 'Vaccination record updated successfully']);
            logAccess($_SESSION['user_id'], 'Updated vaccination record ID: ' . $vaccination_id, true);
        } else {
            echo json_encode(['error' => 'Failed to update vaccination record']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
    exit;
}

// Role-based vaccination management: Admin, Official, and Merchant can manage records
$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$can_manage_vaccinations = ($is_admin || $is_official || $is_merchant);

$success_message = $error_message = '';
$refresh_needed = false;

if ($can_manage_vaccinations) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_vaccination') {
        $user_id = sanitizeInput($_POST['user_id']);
        $vaccine_type = sanitizeInput($_POST['vaccine_type']);
        $dose_number = (int)$_POST['dose_number'];
        $date_administered = sanitizeInput($_POST['date_administered']);
        $administered_by = sanitizeInput($_POST['administered_by']);
        $batch_number = sanitizeInput($_POST['batch_number']);
        $traveler_flag = isset($_POST['traveler_flag']) ? 1 : 0;
        $certification = sanitizeInput($_POST['certification']);
        $notes = sanitizeInput($_POST['notes']);
        
        $errors = [];
        if (empty($user_id)) {
            $errors[] = "User ID is required";
        }
        
        if (empty($vaccine_type)) {
            $errors[] = "Vaccine type is required";
        }
        
        if ($dose_number < 1) {
            $errors[] = "Dose number must be positive";
        }
        
        if (empty($date_administered)) {
            $errors[] = "Date is required";
        }
        
        if (empty($administered_by)) {
            $errors[] = "Administrator name is required";
        }
        
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                $stmt = $pdo->prepare("INSERT INTO vaccination_records (user_id, vaccine_type, dose_number, date_administered, administered_by, batch_number, traveler_flag, certification, notes) 
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$user_id, $vaccine_type, $dose_number, $date_administered, $administered_by, $batch_number, $traveler_flag, $certification, $notes]);
                
                $success_message = "Vaccination record added successfully!";
                $refresh_needed = true;
                
                logAccess($_SESSION['user_id'], 'Added vaccination record for user ID: ' . $user_id, true);
                
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
            $stmt = $pdo->prepare("DELETE FROM vaccination_records WHERE vaccination_id = ?");
            $stmt->execute([$id]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "Vaccination record deleted successfully";
                $refresh_needed = true;
                
                logAccess($_SESSION['user_id'], 'Deleted vaccination record ID: ' . $id, true);
            } else {
                $error_message = "Vaccination record not found";
            }
        } catch (PDOException $e) {
            $error_message = "Error deleting vaccination record: " . $e->getMessage();
        }
    }
} else {
    // Security: Log unauthorized vaccination management attempts
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['action']) && $_GET['action'] === 'delete')) {
        $error_message = "You don't have permission to manage vaccination records";
        logAccess($_SESSION['user_id'], 'Unauthorized attempt to manage vaccination records', false);
    }
}

$vaccination_records = [];
try {
    $pdo = getDBConnection();
    
    // Data access control: Citizens see only their own vaccination records
    if ($is_citizen) {
        $stmt = $pdo->prepare("SELECT vr.*, u.full_name as user_name 
                               FROM vaccination_records vr 
                               LEFT JOIN users u ON vr.user_id = u.user_id 
                               WHERE vr.user_id = ? 
                               ORDER BY vr.vaccination_id DESC");
        $stmt->execute([$_SESSION['user_id']]);
    } else {
        $stmt = $pdo->query("SELECT vr.*, u.full_name as user_name 
                            FROM vaccination_records vr 
                            LEFT JOIN users u ON vr.user_id = u.user_id 
                            ORDER BY vr.vaccination_id DESC");
    }
    
    $vaccination_records = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching vaccination records: " . $e->getMessage();
}

$users = [];
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT user_id, full_name, username FROM users ORDER BY full_name");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Silently fail, we'll just have an empty dropdown
}

$vaccine_types = ["Pfizer-BioNTech", "Moderna", "Johnson & Johnson", "AstraZeneca", "Sinopharm", "Sinovac", "Covaxin", "Sputnik V"];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vaccination Records - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #343a40;
        }
        
        .top-bar {
            background: linear-gradient(90deg, #0d6efd, #0dcaf0);
            color: white;
            padding: 15px 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .dashboard-card {
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: transform 0.2s, box-shadow 0.2s;
            height: 100%;
            border: none;
            overflow: hidden;
        }
        
        .dashboard-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 10px rgba(0, 0, 0, 0.08);
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
            padding: 8px 12px;
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
                    <h4 class="mb-0 d-flex align-items-center">
                        <i class="bi bi-shield-fill-check me-2"></i>
                        COVID Resilience System
                    </h4>
                </div>
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle d-flex align-items-center" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle me-2"></i>
                            <?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?>
                            <span class="role-badge role-<?php echo strtolower($_SESSION['role']); ?>"><?php echo $_SESSION['role']; ?></span>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end shadow-sm" aria-labelledby="userDropdown">
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
                        <a class="nav-link active" href="vaccination_records.php">
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
                    <h2><i class="bi bi-clipboard2-pulse me-2"></i>Vaccination Records</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        
                        <?php if ($can_manage_vaccinations): ?>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addVaccinationModal">
                            <i class="bi bi-plus-circle me-2"></i>Add Vaccination Record
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
                
                <?php if ($is_citizen): ?>
                <div class="read-only-notice mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill text-primary me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">View-Only Access</h5>
                            <p class="mb-0">As a Citizen, you have read-only access to vaccination records. Only Officials, Merchants, and Administrators can manage vaccination records.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search vaccination records..." oninput="filterTable()">
                        </div>

                        <div class="table-responsive">
                            <table id="vaccinationRecordsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">User <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Vaccine Type <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Dose # <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">Date <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(5)">Administered By <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(6)">Traveler <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if ($can_manage_vaccinations): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($vaccination_records)): ?>
                                    <tr><td colspan="<?php echo $can_manage_vaccinations ? '8' : '7'; ?>" class="text-center">No vaccination records found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($vaccination_records as $record): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($record['vaccination_id']); ?></td>
                                        <td><?php echo htmlspecialchars($record['user_name'] ?? $record['user_id']); ?></td>
                                        <td><?php echo htmlspecialchars($record['vaccine_type']); ?></td>
                                        <td><?php echo htmlspecialchars($record['dose_number']); ?></td>
                                        <td><?php echo date('M j, Y', strtotime($record['date_administered'])); ?></td>
                                        <td><?php echo htmlspecialchars($record['administered_by']); ?></td>
                                        <td>
                                            <?php if ($record['traveler_flag'] == 1): ?>
                                            <span class="badge bg-success">Yes</span>
                                            <?php else: ?>
                                            <span class="badge bg-secondary">No</span>
                                            <?php endif; ?>
                                        </td>
                                        <?php if ($can_manage_vaccinations): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewVaccination(<?php echo $record['vaccination_id']; ?>)">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editVaccination(<?php echo $record['vaccination_id']; ?>)">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $record['vaccination_id']; ?>)">
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
                                Total: <span id="totalRecords"><?php echo count($vaccination_records); ?></span> record<?php echo count($vaccination_records) != 1 ? 's' : ''; ?>
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
    
    <?php if ($can_manage_vaccinations): ?>
    <div class="modal fade" id="addVaccinationModal" tabindex="-1" aria-labelledby="addVaccinationModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addVaccinationModalLabel"><i class="bi bi-clipboard2-plus me-2"></i>Add New Vaccination Record</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="vaccination_records.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_vaccination">
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="user_id" class="form-label">User</label>
                                <select class="form-select" id="user_id" name="user_id" required>
                                    <option value="">Select User</option>
                                    <?php foreach ($users as $user): ?>
                                    <option value="<?php echo htmlspecialchars($user['user_id']); ?>">
                                        <?php echo htmlspecialchars($user['full_name'] . ' (' . $user['username'] . ')'); ?>
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label for="vaccine_type" class="form-label">Vaccine Type</label>
                                <select class="form-select" id="vaccine_type" name="vaccine_type" required>
                                    <option value="">Select Vaccine</option>
                                    <?php foreach ($vaccine_types as $type): ?>
                                    <option value="<?php echo htmlspecialchars($type); ?>"><?php echo htmlspecialchars($type); ?></option>
                                    <?php endforeach; ?>
                                    <option value="other">Other (specify)</option>
                                </select>
                                <input type="text" id="other_vaccine" class="form-control mt-2 d-none" placeholder="Specify vaccine type">
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="dose_number" class="form-label">Dose Number</label>
                                <input type="number" class="form-control" id="dose_number" name="dose_number" min="1" max="10" value="1" required>
                            </div>
                            <div class="col-md-6">
                                <label for="date_administered" class="form-label">Date Administered</label>
                                <input type="date" class="form-control" id="date_administered" name="date_administered" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="administered_by" class="form-label">Administered By</label>
                                <input type="text" class="form-control" id="administered_by" name="administered_by" required>
                            </div>
                            <div class="col-md-6">
                                <label for="batch_number" class="form-label">Batch Number</label>
                                <input type="text" class="form-control" id="batch_number" name="batch_number">
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <div class="form-check mt-4">
                                    <input class="form-check-input" type="checkbox" id="traveler_flag" name="traveler_flag" value="1">
                                    <label class="form-check-label" for="traveler_flag">
                                        Travel Approved
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label for="certification" class="form-label">Certification</label>
                                <input type="text" class="form-control" id="certification" name="certification">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="notes" class="form-label">Notes</label>
                            <textarea class="form-control" id="notes" name="notes" rows="3"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Vaccination Record</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="viewVaccinationModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-clipboard2-pulse me-2"></i>Vaccination Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-3">
                        <i class="bi bi-clipboard2-check text-primary" style="font-size: 4rem;"></i>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <h6>Vaccination ID</h6>
                            <p id="view-id" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>User ID</h6>
                            <p id="view-user-id" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Vaccine Type</h6>
                            <p id="view-vaccine-type" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Dose Number</h6>
                            <p id="view-dose-number" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Date Administered</h6>
                            <p id="view-date" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Administered By</h6>
                            <p id="view-administered-by" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Batch Number</h6>
                            <p id="view-batch" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Traveler Status</h6>
                            <p id="view-traveler" class="text-muted"></p>
                        </div>
                        <div class="col-md-12 mb-3">
                            <h6>Certification</h6>
                            <p id="view-certification" class="text-muted"></p>
                        </div>
                        <div class="col-md-12 mb-3">
                            <h6>Notes</h6>
                            <p id="view-notes" class="text-muted"></p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="editVaccinationModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Vaccination Record</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="editVaccinationForm">
                    <div class="modal-body">
                        <input type="hidden" id="edit-id" name="vaccination_id">
                        <input type="hidden" name="ajax" value="update_vaccination">
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit-user-id" class="form-label">User</label>
                                <select class="form-select" id="edit-user-id" name="user_id" required>
                                    <option value="">Select User</option>
                                    <?php foreach ($users as $user): ?>
                                    <option value="<?php echo htmlspecialchars($user['user_id']); ?>">
                                        <?php echo htmlspecialchars($user['full_name'] . ' (' . $user['username'] . ')'); ?>
                                    </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label for="edit-vaccine-type" class="form-label">Vaccine Type</label>
                                <select class="form-select" id="edit-vaccine-type" name="vaccine_type" required>
                                    <option value="">Select Vaccine</option>
                                    <?php foreach ($vaccine_types as $type): ?>
                                    <option value="<?php echo htmlspecialchars($type); ?>"><?php echo htmlspecialchars($type); ?></option>
                                    <?php endforeach; ?>
                                    <option value="other">Other (specify)</option>
                                </select>
                                <input type="text" id="edit-other-vaccine" class="form-control mt-2 d-none" placeholder="Specify vaccine type">
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit-dose-number" class="form-label">Dose Number</label>
                                <input type="number" class="form-control" id="edit-dose-number" name="dose_number" min="1" max="10" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit-date" class="form-label">Date Administered</label>
                                <input type="date" class="form-control" id="edit-date" name="date_administered" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="edit-administered-by" class="form-label">Administered By</label>
                                <input type="text" class="form-control" id="edit-administered-by" name="administered_by" required>
                            </div>
                            <div class="col-md-6">
                                <label for="edit-batch" class="form-label">Batch Number</label>
                                <input type="text" class="form-control" id="edit-batch" name="batch_number">
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <div class="form-check mt-4">
                                    <input class="form-check-input" type="checkbox" id="edit-traveler" name="traveler_flag" value="1">
                                    <label class="form-check-label" for="edit-traveler">
                                        Travel Approved
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label for="edit-certification" class="form-label">Certification</label>
                                <input type="text" class="form-control" id="edit-certification" name="certification">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-notes" class="form-label">Notes</label>
                            <textarea class="form-control" id="edit-notes" name="notes" rows="3"></textarea>
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
    // Auto-refresh modal management after form submission
    <?php if ($refresh_needed): ?>
    document.addEventListener("DOMContentLoaded", function() {
        try {
            const activeModal = document.querySelector('.modal.show');
            if (activeModal) {
                const modalInstance = bootstrap.Modal.getInstance(activeModal);
                if (modalInstance) {
                    modalInstance.hide();
                }
            }
        } catch (e) {
            console.error("Error closing modal:", e);
        }
    });
    <?php endif; ?>
    
    const allRows = Array.from(document.querySelectorAll('#vaccinationRecordsTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        allRows.forEach(row => {
            const userId = row.cells[1]?.textContent.toLowerCase() || '';
            const vaccineType = row.cells[2]?.textContent.toLowerCase() || '';
            const adminBy = row.cells[5]?.textContent.toLowerCase() || '';
            const id = row.cells[0]?.textContent || '';
            
            if (userId.includes(filter) || 
                vaccineType.includes(filter) || 
                adminBy.includes(filter) || 
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
        document.getElementById('totalRecords').textContent = visibleRows;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('vaccinationRecordsTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            const aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            const bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Dynamic sorting with type-specific handling for IDs, doses, and dates
            if (colIndex === 0 || colIndex === 3) {
                return parseInt(aValue) - parseInt(bValue);
            }
            
            if (colIndex === 4) {
                const aDate = new Date(aValue);
                const bDate = new Date(bValue);
                return aDate - bDate;
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
    
    <?php if ($can_manage_vaccinations): ?>
    function viewVaccination(id) {
        // AJAX request: Fetch vaccination details for modal display
        fetch(`vaccination_records.php?ajax=get_vaccination_details&id=${id}`)
            .then(response => response.json())
            .then(data => {
                if (!data.error) {
                    document.getElementById('view-id').textContent = data.vaccination_id;
                    document.getElementById('view-user-id').textContent = data.user_id;
                    document.getElementById('view-vaccine-type').textContent = data.vaccine_type;
                    document.getElementById('view-dose-number').textContent = data.dose_number;
                    document.getElementById('view-date').textContent = new Date(data.date_administered).toLocaleDateString();
                    document.getElementById('view-administered-by').textContent = data.administered_by;
                    document.getElementById('view-batch').textContent = data.batch_number || 'N/A';
                    document.getElementById('view-traveler').textContent = data.traveler_flag == 1 ? 'Yes' : 'No';
                    document.getElementById('view-certification').textContent = data.certification || 'N/A';
                    document.getElementById('view-notes').textContent = data.notes || 'N/A';
                    
                    const modal = new bootstrap.Modal(document.getElementById('viewVaccinationModal'));
                    modal.show();
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error fetching vaccination details:', error);
                alert('Error loading vaccination details. Please try again.');
            });
    }
    
    function editVaccination(id) {
        // AJAX request: Fetch vaccination details for editing form
        fetch(`vaccination_records.php?ajax=get_vaccination_details&id=${id}`)
            .then(response => response.json())
            .then(data => {
                if (!data.error) {
                    document.getElementById('edit-id').value = data.vaccination_id;
                    document.getElementById('edit-user-id').value = data.user_id;
                    document.getElementById('edit-vaccine-type').value = data.vaccine_type;
                    document.getElementById('edit-dose-number').value = data.dose_number;
                    document.getElementById('edit-date').value = data.date_administered.split(' ')[0];
                    document.getElementById('edit-administered-by').value = data.administered_by;
                    document.getElementById('edit-batch').value = data.batch_number || '';
                    document.getElementById('edit-traveler').checked = data.traveler_flag == 1;
                    document.getElementById('edit-certification').value = data.certification || '';
                    document.getElementById('edit-notes').value = data.notes || '';
                    
                    const modal = new bootstrap.Modal(document.getElementById('editVaccinationModal'));
                    modal.show();
                } else {
                    alert('Error: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error fetching vaccination details for editing:', error);
                alert('Error loading vaccination details. Please try again.');
            });
    }
    
    // AJAX form submission: Handle vaccination record updates
    document.getElementById('editVaccinationForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        
        fetch('vaccination_records.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
                location.reload();
            } else {
                alert('Error: ' + (data.error || 'Unknown error occurred'));
            }
        })
        .catch(error => {
            console.error('Error updating vaccination record:', error);
            alert('Error updating vaccination record. Please try again.');
        });
    });
    
    function confirmDelete(id) {
        if (confirm(`Are you sure you want to delete vaccination record #${id}?`)) {
            window.location.href = `vaccination_records.php?action=delete&id=${id}`;
        }
    }
    <?php endif; ?>
    
    // Dynamic vaccine type selection with custom input support
    document.addEventListener('DOMContentLoaded', function() {
        const vaccineSelect = document.getElementById('vaccine_type');
        const otherVaccineInput = document.getElementById('other_vaccine');
        
        if (vaccineSelect && otherVaccineInput) {
            vaccineSelect.addEventListener('change', function() {
                if (this.value === 'other') {
                    otherVaccineInput.classList.remove('d-none');
                    otherVaccineInput.setAttribute('name', 'vaccine_type');
                    this.removeAttribute('name');
                } else {
                    otherVaccineInput.classList.add('d-none');
                    otherVaccineInput.removeAttribute('name');
                    this.setAttribute('name', 'vaccine_type');
                }
            });
        }
        
        const editVaccineSelect = document.getElementById('edit-vaccine-type');
        const editOtherVaccineInput = document.getElementById('edit-other-vaccine');
        
        if (editVaccineSelect && editOtherVaccineInput) {
            editVaccineSelect.addEventListener('change', function() {
                if (this.value === 'other') {
                    editOtherVaccineInput.classList.remove('d-none');
                    editOtherVaccineInput.setAttribute('name', 'vaccine_type');
                    this.removeAttribute('name');
                } else {
                    editOtherVaccineInput.classList.add('d-none');
                    editOtherVaccineInput.removeAttribute('name');
                    this.setAttribute('name', 'vaccine_type');
                }
            });
        }
        
        const dateInput = document.getElementById('date_administered');
        if (dateInput) {
            const today = new Date().toISOString().split('T')[0];
            dateInput.value = today;
        }
    });
    </script>
</body>
</html>