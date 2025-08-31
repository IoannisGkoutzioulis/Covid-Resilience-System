<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

// Role-based access: Admin, Official, and Merchant can manage merchants
$can_manage_merchants = ($is_admin || $is_official || $is_merchant);

// Generate unique PRS ID with "MER" prefix for merchants
function generateUniquePrsId($pdo) {
    do {
        $prs_id = 'MER' . mt_rand(1000, 9999);
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE prs_id = ?");
        $stmt->execute([$prs_id]);
        $count = $stmt->fetchColumn();
    } while ($count > 0);
    
    return $prs_id;
}

$success_message = $error_message = '';
$refresh_needed = false;

if ($can_manage_merchants) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['action']) && $_POST['action'] === 'add_merchant') {
            $merchant_name = sanitizeInput($_POST['merchant_name']);
            $contact_email = sanitizeInput($_POST['contact_email']);
            $contact_phone = sanitizeInput($_POST['contact_phone']);
            $city = sanitizeInput($_POST['city']);
            $business_license = sanitizeInput($_POST['business_license']);
            
            $user_id = null;
            if (isset($_POST['user_id']) && !empty($_POST['user_id'])) {
                $user_id = (int)$_POST['user_id'];
                if ($user_id === 0) {
                    $user_id = null;
                }
            }
            
            $errors = [];
            if (empty($merchant_name)) {
                $errors[] = "Merchant name is required";
            }
            
            if (!empty($contact_email) && !filter_var($contact_email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Valid email is required";
            }
            
            if (empty($errors)) {
                try {
                    $pdo = getDBConnection();
                    
                    // Prevent duplicate merchant names
                    $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE merchant_name = ?");
                    $checkStmt->execute([$merchant_name]);
                    $nameExists = $checkStmt->fetchColumn() > 0;
                    
                    if ($nameExists) {
                        $error_message = "Error: Merchant with this name already exists";
                    } else {
                        $prs_id = null;
                        
                        // Link to existing user or create standalone merchant
                        if ($user_id) {
                            $userStmt = $pdo->prepare("SELECT prs_id FROM users WHERE user_id = ?");
                            $userStmt->execute([$user_id]);
                            $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                            
                            if ($userData) {
                                // Ensure user's PRS ID isn't already used by another merchant
                                $prsCheckStmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE prs_id = ?");
                                $prsCheckStmt->execute([$userData['prs_id']]);
                                $prsExists = $prsCheckStmt->fetchColumn() > 0;
                                
                                if ($prsExists) {
                                    $error_message = "Error: This user is already linked to another merchant account";
                                    goto skip_merchant_insertion;
                                } else {
                                    $prs_id = $userData['prs_id'];
                                }
                            } else {
                                $user_id = null;
                                $prs_id = generateUniquePrsId($pdo);
                            }
                        } else {
                            $prs_id = generateUniquePrsId($pdo);
                        }
                        
                        $stmt = $pdo->prepare("INSERT INTO merchants (prs_id, merchant_name, contact_email, contact_phone, city, business_license, user_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Approved')");
                        $stmt->execute([$prs_id, $merchant_name, $contact_email, $contact_phone, $city, $business_license, $user_id]);
                        
                        $success_message = "Merchant added successfully! PRS ID: " . $prs_id;
                        $refresh_needed = true;
                        
                        logAccess($_SESSION['user_id'], 'Added new merchant: ' . $merchant_name, true);
                    }
                } catch (PDOException $e) {
                    $error_message = "Database error: " . $e->getMessage();
                }
            } else {
                $error_message = "Please correct the following errors: " . implode(", ", $errors);
            }
            
            skip_merchant_insertion:
        }
        else if (isset($_POST['action']) && $_POST['action'] === 'edit_merchant') {
            $merchant_id = isset($_POST['merchant_id']) ? (int)$_POST['merchant_id'] : 0;
            $prs_id = sanitizeInput($_POST['prs_id']);
            $merchant_name = sanitizeInput($_POST['merchant_name']);
            $contact_email = sanitizeInput($_POST['contact_email']);
            $contact_phone = sanitizeInput($_POST['contact_phone']);
            $city = sanitizeInput($_POST['city']);
            $business_license = sanitizeInput($_POST['business_license']);
            
            $user_id = null;
            if (isset($_POST['user_id']) && !empty($_POST['user_id'])) {
                $user_id = (int)$_POST['user_id'];
                if ($user_id === 0) {
                    $user_id = null;
                }
            }
            
            $errors = [];
            if (empty($merchant_name)) {
                $errors[] = "Merchant name is required";
            }
            
            if (!empty($contact_email) && !filter_var($contact_email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Valid email is required";
            }
            
            if (empty($merchant_id) || $merchant_id <= 0) {
                $errors[] = "Invalid merchant ID";
            }
            
            if (empty($errors)) {
                try {
                    $pdo = getDBConnection();
                    
                    // Check name uniqueness excluding current merchant
                    $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE merchant_name = ? AND merchant_id <> ?");
                    $checkStmt->execute([$merchant_name, $merchant_id]);
                    $nameExists = $checkStmt->fetchColumn() > 0;
                    
                    if ($nameExists) {
                        $error_message = "Error: Another merchant with this name already exists";
                    } else {
                        // Validate user linking if provided
                        if ($user_id) {
                            $userStmt = $pdo->prepare("SELECT prs_id FROM users WHERE user_id = ?");
                            $userStmt->execute([$user_id]);
                            $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                            
                            if ($userData) {
                                // Check PRS ID conflict with other merchants
                                $prsCheckStmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE prs_id = ? AND merchant_id <> ?");
                                $prsCheckStmt->execute([$userData['prs_id'], $merchant_id]);
                                $prsExists = $prsCheckStmt->fetchColumn() > 0;
                                
                                if ($prsExists) {
                                    $error_message = "Error: This user is already linked to another merchant account";
                                    goto skip_merchant_update;
                                } else {
                                    $prs_id = $userData['prs_id'];
                                }
                            } else {
                                $user_id = null;
                            }
                        }
                        
                        $stmt = $pdo->prepare("UPDATE merchants SET prs_id = ?, merchant_name = ?, contact_email = ?, contact_phone = ?, city = ?, business_license = ?, user_id = ? WHERE merchant_id = ?");
                        $result = $stmt->execute([$prs_id, $merchant_name, $contact_email, $contact_phone, $city, $business_license, $user_id, $merchant_id]);
                        
                        if ($result) {
                            $success_message = "Merchant updated successfully!";
                            $refresh_needed = true;
                            
                            logAccess($_SESSION['user_id'], 'Updated merchant: ' . $merchant_name, true);
                        } else {
                            $error_message = "Failed to update merchant";
                        }
                    }
                } catch (PDOException $e) {
                    $error_message = "Database error: " . $e->getMessage();
                }
            } else {
                $error_message = "Please correct the following errors: " . implode(", ", $errors);
            }
            
            skip_merchant_update:
        }
    }

    if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
        $id = (int)$_GET['id'];
        
        try {
            $pdo = getDBConnection();
            
            // Check for dependencies before deletion to maintain data integrity
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM purchases WHERE merchant_id = ?");
            $stmt->execute([$id]);
            $hasPurchases = $stmt->fetchColumn() > 0;
            
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM stock WHERE merchant_id = ?");
            $stmt->execute([$id]);
            $hasStock = $stmt->fetchColumn() > 0;
            
            if ($hasPurchases || $hasStock) {
                $error_message = "Cannot delete merchant: It has associated purchases or stock items";
            } else {
                $stmt = $pdo->prepare("DELETE FROM merchants WHERE merchant_id = ?");
                $stmt->execute([$id]);
                
                if ($stmt->rowCount() > 0) {
                    $success_message = "Merchant deleted successfully";
                    $refresh_needed = true;
                    
                    logAccess($_SESSION['user_id'], 'Deleted merchant ID: ' . $id, true);
                } else {
                    $error_message = "Merchant not found";
                }
            }
        } catch (PDOException $e) {
            $error_message = "Error deleting merchant: " . $e->getMessage();
        }
    }
    
    // Auto-link merchant users: Create merchant record for merchant role users without one
    if ($is_merchant && $_SESSION['user_id']) {
        try {
            $pdo = getDBConnection();
            
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE user_id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $hasLinkedMerchant = $stmt->fetchColumn() > 0;
            
            if (!$hasLinkedMerchant) {
                $userStmt = $pdo->prepare("SELECT full_name, prs_id FROM users WHERE user_id = ?");
                $userStmt->execute([$_SESSION['user_id']]);
                $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                
                if ($userData) {
                    // Ensure PRS ID isn't already used
                    $prsCheckStmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE prs_id = ?");
                    $prsCheckStmt->execute([$userData['prs_id']]);
                    $prsExists = $prsCheckStmt->fetchColumn() > 0;
                    
                    if (!$prsExists) {
                        $merchantName = $userData['full_name'] . "'s Business";
                        
                        $insertStmt = $pdo->prepare("INSERT INTO merchants (prs_id, merchant_name, user_id, status) VALUES (?, ?, ?, 'Approved')");
                        $insertStmt->execute([$userData['prs_id'], $merchantName, $_SESSION['user_id']]);
                        
                        $success_message = "A merchant record has been automatically created for your account.";
                        $refresh_needed = true;
                        
                        logAccess($_SESSION['user_id'], 'Auto-created merchant record for user', true);
                    } else {
                        logAccess($_SESSION['user_id'], 'Cannot auto-create merchant: PRS ID already exists', false);
                    }
                }
            }
        } catch (PDOException $e) {
            error_log("Error auto-linking merchant: " . $e->getMessage());
            logAccess($_SESSION['user_id'], 'Error auto-linking merchant: ' . $e->getMessage(), false);
        }
    }
} else {
    // Log unauthorized access attempts
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['action']) && $_GET['action'] === 'delete')) {
        $error_message = "You don't have permission to manage merchants";
        logAccess($_SESSION['user_id'], 'Unauthorized attempt to manage merchants', false);
    }
}

// Get unlinked merchant users for dropdown
$users = [];
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT u.user_id, u.full_name, u.prs_id, u.username 
                         FROM users u 
                         WHERE u.role = 'Merchant' 
                         AND u.user_id NOT IN (SELECT COALESCE(user_id, 0) FROM merchants WHERE user_id IS NOT NULL)
                         ORDER BY u.full_name");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching users: " . $e->getMessage();
}

$merchants = [];
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT m.*, u.full_name as user_name 
                         FROM merchants m 
                         LEFT JOIN users u ON m.user_id = u.user_id 
                         ORDER BY m.merchant_id DESC");
    $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching merchants: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Merchants - COVID Resilience System</title>
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
        
        .badge-prs {
            background-color: #6f42c1;
            color: white;
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
                        <a class="nav-link" href="government_officials.php">
                            <i class="bi bi-building me-2"></i>Officials
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link active" href="merchants.php">
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
                    <h2><i class="bi bi-shop me-2"></i>Merchants</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        
                        <?php if ($can_manage_merchants): ?>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addMerchantModal">
                            <i class="bi bi-plus-circle me-2"></i>Add New Merchant
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
                            <p class="mb-0">As a Citizen, you have read-only access to merchant information. Only Merchants, Officials, and Administrators can manage merchant records.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search merchants..." oninput="filterTable()">
                        </div>

                        <div class="table-responsive">
                            <table id="merchantsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th>PRS ID</th>
                                        <th onclick="sortTable(1)">Merchant Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Contact Email <i class="bi bi-arrow-down-up"></i></th>
                                        <th>City</th>
                                        <th>Linked User</th>
                                        <?php if ($can_manage_merchants): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($merchants)): ?>
                                    <tr><td colspan="<?php echo $can_manage_merchants ? '7' : '6'; ?>" class="text-center">No merchants found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($merchants as $merchant): ?>
                                    <tr 
                                        data-id="<?php echo htmlspecialchars($merchant['merchant_id']); ?>"
                                        data-prsid="<?php echo htmlspecialchars($merchant['prs_id'] ?? ''); ?>"
                                        data-name="<?php echo htmlspecialchars($merchant['merchant_name']); ?>"
                                        data-email="<?php echo htmlspecialchars($merchant['contact_email'] ?? ''); ?>"
                                        data-phone="<?php echo htmlspecialchars($merchant['contact_phone'] ?? ''); ?>"
                                        data-city="<?php echo htmlspecialchars($merchant['city'] ?? ''); ?>"
                                        data-license="<?php echo htmlspecialchars($merchant['business_license'] ?? ''); ?>"
                                        data-userid="<?php echo htmlspecialchars($merchant['user_id'] ?? ''); ?>"
                                        data-username="<?php echo htmlspecialchars($merchant['user_name'] ?? ''); ?>"
                                    >
                                        <td><?php echo htmlspecialchars($merchant['merchant_id']); ?></td>
                                        <td><span class="badge badge-prs"><?php echo htmlspecialchars($merchant['prs_id'] ?? 'N/A'); ?></span></td>
                                        <td><?php echo htmlspecialchars($merchant['merchant_name']); ?></td>
                                        <td><?php echo htmlspecialchars($merchant['contact_email'] ?? '-'); ?></td>
                                        <td><?php echo htmlspecialchars($merchant['city'] ?? '-'); ?></td>
                                        <td><?php echo htmlspecialchars($merchant['user_name'] ?? '-'); ?></td>
                                        <?php if ($can_manage_merchants): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewMerchant(this.closest('tr'))">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editMerchant(this.closest('tr'))">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $merchant['merchant_id']; ?>, '<?php echo htmlspecialchars($merchant['merchant_name']); ?>')">
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
                                Total: <span id="totalMerchants"><?php echo count($merchants); ?></span> merchant<?php echo count($merchants) != 1 ? 's' : ''; ?>
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
    
    <?php if ($can_manage_merchants): ?>
    <div class="modal fade" id="addMerchantModal" tabindex="-1" aria-labelledby="addMerchantModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addMerchantModalLabel"><i class="bi bi-shop-window me-2"></i>Add New Merchant</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="merchants.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_merchant">
                        
                        <div class="mb-3">
                            <label for="merchant_name" class="form-label">Merchant Name</label>
                            <input type="text" class="form-control" id="merchant_name" name="merchant_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="contact_email" class="form-label">Contact Email</label>
                            <input type="email" class="form-control" id="contact_email" name="contact_email">
                        </div>
                        
                        <div class="mb-3">
                            <label for="contact_phone" class="form-label">Contact Phone</label>
                            <input type="text" class="form-control" id="contact_phone" name="contact_phone">
                        </div>
                        
                        <div class="mb-3">
                            <label for="city" class="form-label">City</label>
                            <input type="text" class="form-control" id="city" name="city">
                            <small class="text-muted">Used for location-based searches</small>
                        </div>
                        
                        <div class="mb-3">
                            <label for="business_license" class="form-label">Business License</label>
                            <input type="text" class="form-control" id="business_license" name="business_license">
                        </div>
                        
                        <div class="mb-3">
                            <label for="user_id" class="form-label">Link to User (Optional)</label>
                            <select class="form-select" id="user_id" name="user_id">
                                <option value="">None (Create as standalone merchant)</option>
                                <?php foreach ($users as $user): ?>
                                <option value="<?php echo $user['user_id']; ?>">
                                    <?php echo htmlspecialchars($user['full_name']); ?> (<?php echo htmlspecialchars($user['prs_id']); ?>)
                                </option>
                                <?php endforeach; ?>
                            </select>
                            <small class="text-muted">If a user is linked, the merchant will use the same PRS ID. Only unlinked merchant users are shown.</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Merchant</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="viewMerchantModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-shop me-2"></i>Merchant Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="text-center mb-3">
                        <i class="bi bi-shop-window text-primary" style="font-size: 4rem;"></i>
                        <div class="mt-2">
                            <span class="badge badge-prs mb-2 fs-6" id="view-prsid"></span>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <h6>Merchant ID</h6>
                            <p id="view-id" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Merchant Name</h6>
                            <p id="view-name" class="text-muted"></p>
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
                            <h6>City</h6>
                            <p id="view-city" class="text-muted"></p>
                        </div>
                        <div class="col-md-6 mb-3">
                            <h6>Linked User</h6>
                            <p id="view-username" class="text-muted"></p>
                        </div>
                        <div class="col-12 mb-3">
                            <h6>Business License</h6>
                            <p id="view-license" class="text-muted"></p>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="editMerchantModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-pencil-square me-2"></i>Edit Merchant</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="editMerchantForm" action="merchants.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="edit_merchant">
                        <input type="hidden" id="edit-id" name="merchant_id">
                        
                        <div class="mb-3">
                            <label for="edit-prsid" class="form-label">PRS ID</label>
                            <input type="text" class="form-control" id="edit-prsid" name="prs_id" readonly>
                            <small class="text-muted">PRS ID cannot be changed manually</small>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-name" class="form-label">Merchant Name</label>
                            <input type="text" class="form-control" id="edit-name" name="merchant_name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-email" class="form-label">Contact Email</label>
                            <input type="email" class="form-control" id="edit-email" name="contact_email">
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-phone" class="form-label">Contact Phone</label>
                            <input type="text" class="form-control" id="edit-phone" name="contact_phone">
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-city" class="form-label">City</label>
                            <input type="text" class="form-control" id="edit-city" name="city">
                            <small class="text-muted">Used for location-based searches</small>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-license" class="form-label">Business License</label>
                            <input type="text" class="form-control" id="edit-license" name="business_license">
                        </div>
                        
                        <div class="mb-3">
                            <label for="edit-userid" class="form-label">Link to User (Optional)</label>
                            <select class="form-select" id="edit-userid" name="user_id">
                                <option value="">None (Standalone merchant)</option>
                                <?php foreach ($users as $user): ?>
                                <option value="<?php echo $user['user_id']; ?>">
                                    <?php echo htmlspecialchars($user['full_name']); ?> (<?php echo htmlspecialchars($user['prs_id']); ?>)
                                </option>
                                <?php endforeach; ?>
                            </select>
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
    
    const allRows = Array.from(document.querySelectorAll('#merchantsTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        allRows.forEach(row => {
            const name = row.cells[2]?.textContent.toLowerCase() || '';
            const email = row.cells[3]?.textContent.toLowerCase() || '';
            const prsId = row.cells[1]?.textContent.toLowerCase() || '';
            const city = row.cells[4]?.textContent.toLowerCase() || '';
            const id = row.cells[0]?.textContent || '';
            const user = row.cells[5]?.textContent.toLowerCase() || '';
            
            if (name.includes(filter) || 
                email.includes(filter) || 
                prsId.includes(filter) ||
                city.includes(filter) ||
                user.includes(filter) ||
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
        document.getElementById('totalMerchants').textContent = visibleRows;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('merchantsTable');
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
    
    <?php if ($can_manage_merchants): ?>
    // Populate modal with row data attributes
    function viewMerchant(row) {
        document.getElementById('view-id').textContent = row.dataset.id || '';
        document.getElementById('view-prsid').textContent = row.dataset.prsid || 'N/A';
        document.getElementById('view-name').textContent = row.dataset.name || '';
        document.getElementById('view-email').textContent = row.dataset.email || '-';
        document.getElementById('view-phone').textContent = row.dataset.phone || '-';
        document.getElementById('view-city').textContent = row.dataset.city || 'Not provided';
        document.getElementById('view-license').textContent = row.dataset.license || 'Not provided';
        document.getElementById('view-username').textContent = row.dataset.username || 'Not linked';
        
        const modal = new bootstrap.Modal(document.getElementById('viewMerchantModal'));
        modal.show();
    }
    
    function editMerchant(row) {
        document.getElementById('edit-id').value = row.dataset.id || '';
        document.getElementById('edit-prsid').value = row.dataset.prsid || '';
        document.getElementById('edit-name').value = row.dataset.name || '';
        document.getElementById('edit-email').value = row.dataset.email || '';
        document.getElementById('edit-phone').value = row.dataset.phone || '';
        document.getElementById('edit-city').value = row.dataset.city || '';
        document.getElementById('edit-license').value = row.dataset.license || '';
        document.getElementById('edit-userid').value = row.dataset.userid || '';
        
        const modal = new bootstrap.Modal(document.getElementById('editMerchantModal'));
        modal.show();
    }
    
    function confirmDelete(id, name) {
        if (confirm(`Are you sure you want to delete merchant "${name}"?`)) {
            window.location.href = `merchants.php?action=delete&id=${id}`;
        }
    }
    <?php endif; ?>
    </script>
</body>
</html>