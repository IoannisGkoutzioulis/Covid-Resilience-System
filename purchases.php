<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

// Role-based access control: Different permissions based on user role
$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$can_add_purchases = ($is_admin || $is_official || $is_merchant || $is_citizen);
$can_manage_purchases = ($is_admin || $is_official || $is_merchant);

$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$purchaseId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$purchaseData = null;
$users = [];
$merchants = [];
$success_message = $error_message = '';
$refresh_needed = false;
$eligibility_status = null;

// Security: Citizens cannot access view/edit/delete functions
if ($is_citizen && in_array($action, ['view', 'edit', 'delete'])) {
    logAccess($_SESSION['user_id'], 'Unauthorized attempt to ' . $action . ' purchase record', false);
    $error_message = "You don't have permission to " . $action . " purchase records";
    $action = 'list';
}

// AJAX location search requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    try {
        $pdo = getDBConnection();
        
        if ($_GET['ajax'] === 'search_by_city' && isset($_GET['city'])) {
            $city = trim($_GET['city']);
            if (!empty($city)) {
                $stmt = $pdo->prepare("
                    SELECT merchant_id, merchant_name, city, contact_phone, contact_email, status
                    FROM merchants 
                    WHERE TRIM(LOWER(city)) = TRIM(LOWER(?)) AND status = 'Approved'
                    ORDER BY merchant_name
                ");
                $stmt->execute([$city]);
                $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                if (!empty($merchants)) {
                    echo json_encode([
                        'success' => true,
                        'merchants' => $merchants,
                        'city' => $city
                    ]);
                } else {
                    // Try partial match if exact match fails
                    $stmt = $pdo->prepare("
                        SELECT merchant_id, merchant_name, city, contact_phone, contact_email, status
                        FROM merchants 
                        WHERE LOWER(city) LIKE LOWER(?) AND status = 'Approved'
                        ORDER BY merchant_name
                    ");
                    $stmt->execute(['%' . $city . '%']);
                    $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    if (!empty($merchants)) {
                        echo json_encode([
                            'success' => true,
                            'merchants' => $merchants,
                            'city' => $city
                        ]);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'No approved merchants found in: ' . $city]);
                    }
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'City name is required']);
            }
            exit;
        }
        
        if ($_GET['ajax'] === 'search_by_prs' && isset($_GET['prs_id'])) {
            $prs_id = trim($_GET['prs_id']);
            if (!empty($prs_id)) {
                $stmt = $pdo->prepare("
                    SELECT merchant_id, merchant_name, city, contact_phone, contact_email, status
                    FROM merchants 
                    WHERE prs_id = ? AND status = 'Approved'
                    ORDER BY merchant_name
                ");
                $stmt->execute([$prs_id]);
                $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                if (!empty($merchants)) {
                    echo json_encode([
                        'success' => true,
                        'merchants' => $merchants,
                        'prs_id' => $prs_id
                    ]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'No merchant found with PRS ID: ' . $prs_id]);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'PRS ID is required']);
            }
            exit;
        }
        
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        exit;
    }
}

try {
    $pdo = getDBConnection();
    
    $userStmt = $pdo->query("SELECT user_id, full_name, dob FROM users ORDER BY full_name");
    $users = $userStmt->fetchAll(PDO::FETCH_ASSOC);
    
    $merchantStmt = $pdo->query("SELECT merchant_id, merchant_name FROM merchants ORDER BY merchant_name");
    $merchants = $merchantStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Check current user's face mask purchase eligibility
    if (isset($_SESSION['user_id'])) {
        $userStmt = $pdo->prepare("SELECT dob FROM users WHERE user_id = ?");
        $userStmt->execute([$_SESSION['user_id']]);
        $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
        
        if ($userData) {
            $eligibility_status = checkPurchaseEligibility($userData['dob']);
        }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_purchase') {
        if (!$can_add_purchases) {
            $error_message = "You don't have permission to add purchase records";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to add purchase record', false);
        } else {
            $userId = (int)$_POST['user_id'];
            $merchantId = (int)$_POST['merchant_id'];
            $itemName = trim($_POST['item_name']);
            $itemQuantity = (int)$_POST['item_quantity'];
            $unitPrice = (float)$_POST['unit_price'];
            $totalPrice = (float)$_POST['total_price'];
            $purchaseDate = $_POST['purchase_date'];
            $eligiblePurchase = isset($_POST['eligible_purchase']) ? 1 : 0;
            $overrideEligibility = isset($_POST['override_eligibility']) ? true : false;
            
            $errors = [];
            
            if (empty($userId)) {
                $errors[] = "User is required";
            }
            
            if (empty($merchantId)) {
                $errors[] = "Merchant is required";
            }
            
            if (empty($itemName)) {
                $errors[] = "Item name is required";
            }
            
            if ($itemQuantity <= 0) {
                $errors[] = "Quantity must be a positive number";
            }
            
            if ($unitPrice < 0) {
                $errors[] = "Unit price cannot be negative";
            }
            
            if ($totalPrice < 0) {
                $errors[] = "Total price cannot be negative";
            }
            
            if (empty($purchaseDate)) {
                $errors[] = "Purchase date is required";
            }
            
            // Complex business logic: Face mask purchase eligibility validation
            if (empty($errors)) {
                $userStmt = $pdo->prepare("SELECT dob FROM users WHERE user_id = ?");
                $userStmt->execute([$userId]);
                $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                
                if ($userData) {
                    $purchaseEligibility = checkPurchaseEligibility($userData['dob'], $overrideEligibility);
                    
                    if (!$purchaseEligibility['eligible']) {
                        $errors[] = "Purchase not eligible: " . $purchaseEligibility['message'];
                    }
                }
            }
            
            if (empty($errors)) {
                $stmt = $pdo->prepare(
                    "INSERT INTO purchases (
                        user_id, merchant_id, item_name, item_quantity, 
                        unit_price, total_price, purchase_date, 
                        eligible_purchase
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                );
                
                $stmt->execute([
                    $userId, $merchantId, $itemName, $itemQuantity,
                    $unitPrice, $totalPrice, $purchaseDate,
                    $eligiblePurchase
                ]);
                
                $success_message = "Purchase added successfully!";
                logAccess($_SESSION['user_id'], 'Added new purchase record for item: ' . $itemName, true);
                $refresh_needed = true;
            } else {
                $error_message = implode("<br>", $errors);
            }
        }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_purchase') {
        if (!$can_manage_purchases) {
            $error_message = "You don't have permission to edit purchase records";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to edit purchase record', false);
        } else {
            $purchaseId = (int)$_POST['purchase_id'];
            $userId = (int)$_POST['user_id'];
            $merchantId = (int)$_POST['merchant_id'];
            $itemName = trim($_POST['item_name']);
            $itemQuantity = (int)$_POST['item_quantity'];
            $unitPrice = (float)$_POST['unit_price'];
            $totalPrice = (float)$_POST['total_price'];
            $purchaseDate = $_POST['purchase_date'];
            $eligiblePurchase = isset($_POST['eligible_purchase']) ? 1 : 0;
            $overrideEligibility = isset($_POST['override_eligibility']) ? true : false;
            
            $errors = [];
            
            if (empty($userId)) {
                $errors[] = "User is required";
            }
            
            if (empty($merchantId)) {
                $errors[] = "Merchant is required";
            }
            
            if (empty($itemName)) {
                $errors[] = "Item name is required";
            }
            
            if ($itemQuantity <= 0) {
                $errors[] = "Quantity must be a positive number";
            }
            
            if ($unitPrice < 0) {
                $errors[] = "Unit price cannot be negative";
            }
            
            if ($totalPrice < 0) {
                $errors[] = "Total price cannot be negative";
            }
            
            if (empty($purchaseDate)) {
                $errors[] = "Purchase date is required";
            }
            
            // Only validate eligibility for current date purchases
            if (empty($errors)) {
                $origStmt = $pdo->prepare("SELECT purchase_date FROM purchases WHERE purchase_id = ?");
                $origStmt->execute([$purchaseId]);
                $origPurchase = $origStmt->fetch(PDO::FETCH_ASSOC);
                
                $isToday = (date('Y-m-d') == date('Y-m-d', strtotime($purchaseDate)));
                
                if ($isToday) {
                    $userStmt = $pdo->prepare("SELECT dob FROM users WHERE user_id = ?");
                    $userStmt->execute([$userId]);
                    $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                    
                    if ($userData) {
                        $purchaseEligibility = checkPurchaseEligibility($userData['dob'], $overrideEligibility);
                        
                        if (!$purchaseEligibility['eligible']) {
                            $errors[] = "Purchase not eligible: " . $purchaseEligibility['message'];
                        }
                    }
                }
            }
            
            if (empty($errors)) {
                $stmt = $pdo->prepare(
                    "UPDATE purchases SET 
                     user_id = ?, 
                     merchant_id = ?, 
                     item_name = ?, 
                     item_quantity = ?, 
                     unit_price = ?, 
                     total_price = ?, 
                     purchase_date = ?, 
                     eligible_purchase = ?
                     WHERE purchase_id = ?"
                );
                
                $stmt->execute([
                    $userId,
                    $merchantId,
                    $itemName,
                    $itemQuantity,
                    $unitPrice,
                    $totalPrice,
                    $purchaseDate,
                    $eligiblePurchase,
                    $purchaseId
                ]);
                
                if ($stmt->rowCount() > 0) {
                    $success_message = "Purchase record updated successfully";
                    logAccess($_SESSION['user_id'], 'Updated purchase record ID: ' . $purchaseId, true);
                } else {
                    $error_message = "No changes were made";
                }
                
                $refresh_needed = true;
            } else {
                $error_message = implode("<br>", $errors);
            }
        }
    }
    
    if ($action === 'delete' && $purchaseId > 0) {
        if (!$can_manage_purchases) {
            $error_message = "You don't have permission to delete purchase records";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to delete purchase record', false);
        } else {
            $stmt = $pdo->prepare("DELETE FROM purchases WHERE purchase_id = ?");
            $stmt->execute([$purchaseId]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "Purchase record deleted successfully";
                logAccess($_SESSION['user_id'], 'Deleted purchase record ID: ' . $purchaseId, true);
                $refresh_needed = true;
            } else {
                $error_message = "Purchase record not found";
            }
        }
        
        $action = 'list';
    }
    
    if (($action === 'view' || $action === 'edit') && $purchaseId > 0) {
        if (!$can_manage_purchases) {
            $error_message = "You don't have permission to view or edit purchase records";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to access purchase record details', false);
            $action = 'list';
        } else {
            if ($action === 'view') {
                $stmt = $pdo->prepare(
                    "SELECT p.*, u.full_name as user_name, m.merchant_name 
                     FROM purchases p
                     JOIN users u ON p.user_id = u.user_id
                     JOIN merchants m ON p.merchant_id = m.merchant_id
                     WHERE p.purchase_id = ?"
                );
            } else {
                $stmt = $pdo->prepare("SELECT * FROM purchases WHERE purchase_id = ?");
            }
            
            $stmt->execute([$purchaseId]);
            $purchaseData = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$purchaseData) {
                $error_message = "Purchase record not found";
                $action = 'list';
            }
        }
    }
    
    if ($action === 'list') {
        $stmt = $pdo->query(
            "SELECT p.*, u.full_name as user_name, m.merchant_name 
             FROM purchases p
             JOIN users u ON p.user_id = u.user_id
             JOIN merchants m ON p.merchant_id = m.merchant_id
             ORDER BY p.purchase_id DESC"
        );
        $purchases = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    if ($action === 'search_location') {
        // Specific logic for the search page can go here
    }
} catch (PDOException $e) {
    $error_message = "Error: " . $e->getMessage();
}

if (isset($_GET['success'])) {
    $success_message = $_GET['success'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purchases - COVID Resilience System</title>
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
        
        .detail-label {
            font-weight: 600;
            color: #495057;
        }
        
        .purchase-detail {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .purchase-badge {
            font-size: 0.9rem;
            padding: 0.5rem 1rem;
            border-radius: 50px;
        }
        
        .eligibility-banner {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }
        
        .eligibility-banner.eligible {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .eligibility-banner.not-eligible {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .eligibility-icon {
            font-size: 2rem;
            margin-right: 15px;
        }
        
        .eligibility-info h5 {
            margin-bottom: 5px;
        }
        
        .eligibility-info p {
            margin-bottom: 0;
        }
        
        .search-container {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .search-header {
            margin-bottom: 15px;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 10px;
        }
        
        .search-form {
            margin-bottom: 20px;
        }
        
        .search-results {
            margin-top: 20px;
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
                        <a class="nav-link" href="vaccination_records.php">
                            <i class="bi bi-clipboard2-pulse me-2"></i>Vaccinations
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link active" href="purchases.php">
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
                <?php if (isset($eligibility_status) && !hasRole(['Official', 'Admin', 'Merchant'])): ?>
                <div class="eligibility-banner <?php echo $eligibility_status['eligible'] ? 'eligible' : 'not-eligible'; ?>">
                    <div class="eligibility-icon">
                        <?php if ($eligibility_status['eligible']): ?>
                        <i class="bi bi-check-circle-fill"></i>
                        <?php else: ?>
                        <i class="bi bi-x-circle-fill"></i>
                        <?php endif; ?>
                    </div>
                    <div class="eligibility-info">
                        <h5><?php echo $eligibility_status['eligible'] ? 'You are eligible to purchase face masks today' : 'Face mask purchase restriction in effect'; ?></h5>
                        <p><?php echo $eligibility_status['message']; ?></p>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if ($action === 'list'): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-cart me-2"></i>Purchases</h2>
                    <div>
                        <a href="purchases.php?action=search_location" class="btn btn-info me-2">
                            <i class="bi bi-geo-alt me-2"></i>Find Merchants by Location
                        </a>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        <?php if ($can_add_purchases): ?>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addPurchaseModal">
                            <i class="bi bi-plus-circle me-2"></i>Add New Purchase
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
                            <h5 class="mb-1">Limited Access</h5>
                            <p class="mb-0">As a Citizen, you can add new purchase records but cannot view, edit, or delete existing purchase records. Only Officials, Merchants, and Administrators can manage existing purchase records.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search purchases..." oninput="filterTable()">
                        </div>

                        <div class="table-responsive">
                            <table id="purchasesTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">User <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Merchant <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Item <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">Quantity <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(5)">Date <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(6)">Eligible <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if ($can_manage_purchases): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($purchases)): ?>
                                    <tr><td colspan="<?php echo $can_manage_purchases ? '8' : '7'; ?>" class="text-center">No purchases found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($purchases as $purchase): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($purchase['purchase_id']); ?></td>
                                        <td><?php echo htmlspecialchars($purchase['user_name']); ?></td>
                                        <td><?php echo htmlspecialchars($purchase['merchant_name']); ?></td>
                                        <td><?php echo htmlspecialchars($purchase['item_name']); ?></td>
                                        <td><?php echo htmlspecialchars($purchase['item_quantity']); ?></td>
                                        <td><?php echo date('M j, Y', strtotime($purchase['purchase_date'])); ?></td>
                                        <td>
                                            <?php if ($purchase['eligible_purchase'] == 1): ?>
                                            <span class="badge bg-success">Yes</span>
                                            <?php else: ?>
                                            <span class="badge bg-secondary">No</span>
                                            <?php endif; ?>
                                        </td>
                                        <?php if ($can_manage_purchases): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewPurchase(<?php echo $purchase['purchase_id']; ?>)">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editPurchase(<?php echo $purchase['purchase_id']; ?>)">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $purchase['purchase_id']; ?>, '<?php echo htmlspecialchars($purchase['item_name']); ?>')">
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
                                Total: <span id="totalPurchases"><?php echo count($purchases); ?></span> purchase<?php echo count($purchases) != 1 ? 's' : ''; ?>
                            </div>
                            <div>
                                <button type="button" class="btn btn-secondary" onclick="window.location.reload();">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'search_location'): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-geo-alt me-2"></i>Find Merchants by Location</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="purchases.php">Purchases</a></li>
                                <li class="breadcrumb-item active" aria-current="page">Location Search</li>
                            </ol>
                        </nav>
                    </div>
                    <div>
                        <a href="purchases.php" class="btn btn-secondary">
                            <i class="bi bi-arrow-left me-2"></i>Back to Purchases
                        </a>
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
                
                <div class="card mb-4">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-geo-alt me-2"></i>Search by City</h5>
                    </div>
                    <div class="card-body">
                        <div class="search-form">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="bi bi-geo-alt"></i></span>
                                        <input type="text" id="citySearch" class="form-control" placeholder="Enter city name (e.g., Athens, Thessaloniki, Patras, Larissa, Rhodes)">
                                        <button class="btn btn-primary" type="button" id="locationSearchBtn">
                                            <i class="bi bi-search me-2"></i>Search
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div id="locationSearchResults" class="search-results mt-4">
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle me-2"></i>
                                Enter a city name above to find merchants in that location. Available cities with approved merchants: Patras, Larissa, Rhodes.
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-person-badge me-2"></i>Search by PRS ID</h5>
                    </div>
                    <div class="card-body">
                        <div class="search-form">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="bi bi-person-vcard"></i></span>
                                        <input type="text" id="prsIdSearch" class="form-control" placeholder="Enter PRS ID number">
                                        <button class="btn btn-info" type="button" id="prsSearchBtn">
                                            <i class="bi bi-search me-2"></i>Search
                                        </button>
                                    </div>
                                    <small class="text-muted">This will find merchants in the same city as the user with the specified PRS ID</small>
                                </div>
                            </div>
                        </div>
                        
                        <div id="prsSearchResults" class="search-results mt-4">
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle me-2"></i>
                                Enter a PRS ID above to find merchants in the same city as that user.
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'view' && $purchaseData): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-cart me-2"></i>Purchase Details</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="purchases.php">Purchases</a></li>
                                <li class="breadcrumb-item active" aria-current="page">View Purchase</li>
                            </ol>
                        </nav>
                    </div>
                    <div>
                        <button type="button" class="btn btn-primary" onclick="editPurchase(<?php echo $purchaseId; ?>)">
                            <i class="bi bi-pencil me-2"></i>Edit Purchase
                        </button>
                        <a href="purchases.php" class="btn btn-secondary ms-2">
                            <i class="bi bi-arrow-left me-2"></i>Back to List
                        </a>
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
                
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-receipt me-2"></i>Purchase #<?php echo $purchaseData['purchase_id']; ?></h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="purchase-detail">
                                    <h5 class="border-bottom pb-2">Customer Information</h5>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Customer:</div>
                                        <div class="col-md-8">
                                            <a href="users.php?action=view&id=<?php echo $purchaseData['user_id']; ?>">
                                                <?php echo htmlspecialchars($purchaseData['user_name']); ?>
                                            </a>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">User ID:</div>
                                        <div class="col-md-8"><?php echo $purchaseData['user_id']; ?></div>
                                    </div>
                                </div>
                                
                                <div class="purchase-detail">
                                    <h5 class="border-bottom pb-2">Merchant Information</h5>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Merchant:</div>
                                        <div class="col-md-8">
                                            <a href="merchants.php?action=view&id=<?php echo $purchaseData['merchant_id']; ?>">
                                                <?php echo htmlspecialchars($purchaseData['merchant_name']); ?>
                                            </a>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Merchant ID:</div>
                                        <div class="col-md-8"><?php echo $purchaseData['merchant_id']; ?></div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="purchase-detail">
                                    <h5 class="border-bottom pb-2">Purchase Details</h5>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Item:</div>
                                        <div class="col-md-8"><?php echo htmlspecialchars($purchaseData['item_name']); ?></div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Quantity:</div>
                                        <div class="col-md-8"><?php echo $purchaseData['item_quantity']; ?></div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Unit Price:</div>
                                        <div class="col-md-8">$<?php echo number_format((float)$purchaseData['unit_price'], 2); ?></div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Total Price:</div>
                                        <div class="col-md-8">
                                            <strong>$<?php echo number_format((float)$purchaseData['total_price'], 2); ?></strong>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Purchase Date:</div>
                                        <div class="col-md-8">
                                            <?php echo date('F j, Y g:i A', strtotime($purchaseData['purchase_date'])); ?>
                                        </div>
                                    </div>
                                    
                                    <div class="row mb-3">
                                        <div class="col-md-4 detail-label">Eligible Purchase:</div>
                                        <div class="col-md-8">
                                            <?php if ((int)$purchaseData['eligible_purchase'] === 1): ?>
                                                <span class="badge bg-success purchase-badge">Yes</span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary purchase-badge">No</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="border-top pt-3 mt-3">
                            <div class="row">
                                <div class="col-md-6">
                                    <small class="text-muted">
                                        Transaction ID: <?php echo htmlspecialchars($purchaseData['purchase_id']); ?>
                                    </small>
                                </div>
                                <div class="col-md-6 text-md-end">
                                    <small class="text-muted">
                                        Record Created: <?php echo date('F j, Y', strtotime($purchaseData['purchase_date'])); ?>
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card-footer bg-light">
                        <div class="d-flex justify-content-between">
                            <a href="purchases.php" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left me-1"></i> Back to Purchases
                            </a>
                            <div>
                                <button type="button" class="btn btn-outline-primary" onclick="editPurchase(<?php echo $purchaseId; ?>)">
                                    <i class="bi bi-pencil me-1"></i> Edit
                                </button>
                                <button type="button" class="btn btn-outline-danger ms-2" 
                                        onclick="confirmDelete(<?php echo $purchaseId; ?>, '<?php echo htmlspecialchars(addslashes($purchaseData['item_name'])); ?>')">
                                    <i class="bi bi-trash me-1"></i> Delete
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'edit' && $purchaseData): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-cart me-2"></i>Edit Purchase</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="purchases.php">Purchases</a></li>
                                <li class="breadcrumb-item active" aria-current="page">Edit Purchase</li>
                            </ol>
                        </nav>
                    </div>
                    <a href="purchases.php" class="btn btn-secondary">
                        <i class="bi bi-arrow-left me-2"></i>Back to Purchases
                    </a>
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

                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-pencil-square me-2"></i>Edit Purchase #<?php echo $purchaseId; ?></h5>
                    </div>
                    <div class="card-body">
                        <form action="purchases.php?action=edit&id=<?php echo $purchaseId; ?>" method="POST">
                            <input type="hidden" name="action" value="edit_purchase">
                            <input type="hidden" name="purchase_id" value="<?php echo $purchaseId; ?>">
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="user_id" class="form-label">Customer</label>
                                        <select class="form-select" id="user_id" name="user_id" required onchange="checkUserEligibility()">
                                            <option value="">Select Customer</option>
                                            <?php foreach ($users as $user): ?>
                                            <option value="<?php echo $user['user_id']; ?>" 
                                                    data-dob="<?php echo htmlspecialchars($user['dob']); ?>"
                                                    <?php echo $user['user_id'] == $purchaseData['user_id'] ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($user['full_name']); ?>
                                            </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="merchant_id" class="form-label">Merchant</label>
                                        <select class="form-select" id="merchant_id" name="merchant_id" required>
                                            <option value="">Select Merchant</option>
                                            <?php foreach ($merchants as $merchant): ?>
                                            <option value="<?php echo $merchant['merchant_id']; ?>" 
                                                    <?php echo $merchant['merchant_id'] == $purchaseData['merchant_id'] ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($merchant['merchant_name']); ?>
                                            </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="item_name" class="form-label">Item Name</label>
                                        <input type="text" class="form-control" id="item_name" name="item_name" 
                                               value="<?php echo htmlspecialchars($purchaseData['item_name']); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="item_quantity" class="form-label">Quantity</label>
                                        <input type="number" class="form-control" id="item_quantity" name="item_quantity" 
                                               value="<?php echo (int)$purchaseData['item_quantity']; ?>" min="1" required
                                               onchange="calculateTotal()">
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="unit_price" class="form-label">Unit Price</label>
                                        <div class="input-group">
                                            <span class="input-group-text">$</span>
                                            <input type="number" class="form-control" id="unit_price" name="unit_price" 
                                                   value="<?php echo number_format((float)$purchaseData['unit_price'], 2, '.', ''); ?>" 
                                                   min="0" step="0.01" required
                                                   onchange="calculateTotal()">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="total_price" class="form-label">Total Price</label>
                                        <div class="input-group">
                                            <span class="input-group-text">$</span>
                                            <input type="number" class="form-control" id="total_price" name="total_price" 
                                                   value="<?php echo number_format((float)$purchaseData['total_price'], 2, '.', ''); ?>" 
                                                   min="0" step="0.01" required>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="purchase_date" class="form-label">Purchase Date</label>
                                        <input type="datetime-local" class="form-control" id="purchase_date" name="purchase_date" 
                                               value="<?php echo date('Y-m-d\TH:i', strtotime($purchaseData['purchase_date'])); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" id="eligible_purchase" name="eligible_purchase" 
                                                   <?php echo $purchaseData['eligible_purchase'] ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="eligible_purchase">
                                                Eligible Purchase
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <?php if (hasPermission('purchases', 'update') && hasRole(['Admin', 'Official'])): ?>
                            <div class="alert alert-info mt-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="override_eligibility" name="override_eligibility">
                                    <label class="form-check-label" for="override_eligibility">
                                        <strong>Administrative Override:</strong> Override purchase eligibility restrictions
                                    </label>
                                </div>
                            </div>
                            <?php endif; ?>
                            
                            <div id="eligibilityAlert" class="alert d-none mt-3">
                                <div id="eligibilityMessage"></div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                                <a href="purchases.php" class="btn btn-outline-secondary me-md-2">
                                    <i class="bi bi-x-circle me-2"></i>Cancel
                                </a>
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save me-2"></i>Save Changes
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <?php if ($can_add_purchases): ?>
    <div class="modal fade" id="addPurchaseModal" tabindex="-1" aria-labelledby="addPurchaseModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addPurchaseModalLabel"><i class="bi bi-cart-plus me-2"></i>Add New Purchase</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="purchases.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_purchase">
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="modal_user_id" class="form-label">Customer</label>
                                    <select class="form-select" id="modal_user_id" name="user_id" required onchange="checkModalUserEligibility()">
                                        <option value="">Select Customer</option>
                                        <?php foreach ($users as $user): ?>
                                        <option value="<?php echo $user['user_id']; ?>" data-dob="<?php echo htmlspecialchars($user['dob']); ?>"
                                            <?php echo (isset($_GET['user_id']) && $_GET['user_id'] == $user['user_id']) ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($user['full_name']); ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="modal_merchant_id" class="form-label">Merchant</label>
                                    <select class="form-select" id="modal_merchant_id" name="merchant_id" required>
                                        <option value="">Select Merchant</option>
                                        <?php foreach ($merchants as $merchant): ?>
                                        <option value="<?php echo $merchant['merchant_id']; ?>"
                                            <?php echo (isset($_GET['merchant_id']) && $_GET['merchant_id'] == $merchant['merchant_id']) ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($merchant['merchant_name']); ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="modal_item_name" class="form-label">Item Name</label>
                                    <input type="text" class="form-control" id="modal_item_name" name="item_name" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="modal_item_quantity" class="form-label">Quantity</label>
                                    <input type="number" class="form-control" id="modal_item_quantity" name="item_quantity" 
                                           min="1" value="1" required onchange="calculateModalTotal()">
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="modal_unit_price" class="form-label">Unit Price</label>
                                    <div class="input-group">
                                        <span class="input-group-text">$</span>
                                        <input type="number" class="form-control" id="modal_unit_price" name="unit_price" 
                                               min="0" step="0.01" value="0.00" required onchange="calculateModalTotal()">
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="modal_total_price" class="form-label">Total Price</label>
                                    <div class="input-group">
                                        <span class="input-group-text">$</span>
                                        <input type="number" class="form-control" id="modal_total_price" name="total_price" 
                                               min="0" step="0.01" value="0.00" required>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="modal_purchase_date" class="form-label">Purchase Date</label>
                                    <input type="datetime-local" class="form-control" id="modal_purchase_date" name="purchase_date" 
                                           value="<?php echo date('Y-m-d\TH:i'); ?>" required>
                                </div>
                                
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="modal_eligible_purchase" name="eligible_purchase">
                                        <label class="form-check-label" for="modal_eligible_purchase">
                                            Eligible Purchase
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div id="modalEligibilityAlert" class="alert d-none mt-3">
                            <div id="modalEligibilityMessage"></div>
                        </div>
                        
                        <?php if (hasPermission('purchases', 'create') && hasRole(['Admin', 'Official'])): ?>
                        <div class="alert alert-info mt-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="modal_override_eligibility" name="override_eligibility">
                                <label class="form-check-label" for="modal_override_eligibility">
                                    <strong>Administrative Override:</strong> Override purchase eligibility restrictions
                                </label>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Purchase</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const locationSearchBtn = document.getElementById('locationSearchBtn');
        if (locationSearchBtn) {
            locationSearchBtn.addEventListener('click', function() {
                const city = document.getElementById('citySearch').value.trim();
                if (!city) {
                    alert('Please enter a city name');
                    return;
                }
                searchMerchantsByCity(city);
            });
        }
        
        const prsSearchBtn = document.getElementById('prsSearchBtn');
        if (prsSearchBtn) {
            prsSearchBtn.addEventListener('click', function() {
                const prsId = document.getElementById('prsIdSearch').value.trim();
                if (!prsId) {
                    alert('Please enter a PRS ID');
                    return;
                }
                searchMerchantsByPRS(prsId);
            });
        }
        
        const citySearch = document.getElementById('citySearch');
        if (citySearch) {
            citySearch.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    locationSearchBtn.click();
                }
            });
        }
        
        const prsIdSearch = document.getElementById('prsIdSearch');
        if (prsIdSearch) {
            prsIdSearch.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    prsSearchBtn.click();
                }
            });
        }
    });

    function searchMerchantsByCity(city) {
        const resultsContainer = document.getElementById('locationSearchResults');
        resultsContainer.innerHTML = '<div class="text-center"><i class="bi bi-search"></i> Searching...</div>';
        
        fetch(`purchases.php?ajax=search_by_city&city=${encodeURIComponent(city)}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayMerchantResults(data.merchants, `Merchants in "${data.city}"`, resultsContainer);
                } else {
                    resultsContainer.innerHTML = `<div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-2"></i>${data.message}</div>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                resultsContainer.innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>An error occurred while searching.</div>';
            });
    }

    function searchMerchantsByPRS(prsId) {
        const resultsContainer = document.getElementById('prsSearchResults');
        resultsContainer.innerHTML = '<div class="text-center"><i class="bi bi-search"></i> Searching...</div>';
        
        fetch(`purchases.php?ajax=search_by_prs&prs_id=${encodeURIComponent(prsId)}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayMerchantResults(data.merchants, `Merchant with PRS ID: ${data.prs_id}`, resultsContainer);
                } else {
                    resultsContainer.innerHTML = `<div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-2"></i>${data.message}</div>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                resultsContainer.innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>An error occurred while searching.</div>';
            });
    }

    function displayMerchantResults(merchants, title, container) {
        if (merchants.length === 0) {
            container.innerHTML = `
                <div class="alert alert-info">
                    <i class="bi bi-info-circle me-2"></i>No merchants found for this search.
                </div>
            `;
            return;
        }
        
        let html = `
            <div class="alert alert-success">
                <i class="bi bi-check-circle me-2"></i>Found ${merchants.length} merchant${merchants.length !== 1 ? 's' : ''} - ${title}
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="table-dark">
                        <tr>
                            <th>Merchant Name</th>
                            <th>City</th>
                            <th>Phone</th>
                            <th>Email</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        merchants.forEach(merchant => {
            html += `
                <tr>
                    <td><strong>${escapeHTML(merchant.merchant_name)}</strong></td>
                    <td>${escapeHTML(merchant.city || 'N/A')}</td>
                    <td>${escapeHTML(merchant.contact_phone || 'N/A')}</td>
                    <td>${escapeHTML(merchant.contact_email || 'N/A')}</td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="addPurchaseForMerchant(${merchant.merchant_id}, '${escapeHTML(merchant.merchant_name)}')">
                            <i class="bi bi-plus-circle me-1"></i>Add Purchase
                        </button>
                        <a href="merchants.php?action=view&id=${merchant.merchant_id}" class="btn btn-sm btn-info ms-1" target="_blank">
                            <i class="bi bi-eye me-1"></i>View Details
                        </a>
                    </td>
                </tr>
            `;
        });
        
        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = html;
    }

    function addPurchaseForMerchant(merchantId, merchantName) {
        const merchantSelect = document.getElementById('modal_merchant_id');
        if (merchantSelect) {
            merchantSelect.value = merchantId;
            
            const addPurchaseModal = new bootstrap.Modal(document.getElementById('addPurchaseModal'));
            addPurchaseModal.show();
        } else {
            window.location.href = `purchases.php?merchant_id=${merchantId}`;
        }
    }

    function escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function filterTable() {
        const input = document.getElementById('searchInput');
        const filter = input.value.toLowerCase();
        const table = document.getElementById('purchasesTable');
        const tr = table.getElementsByTagName('tr');

        for (let i = 1; i < tr.length; i++) {
            const td = tr[i].getElementsByTagName('td');
            let txtValue = '';
            
            for (let j = 0; j < td.length - 1; j++) {
                txtValue += td[j].textContent || td[j].innerText;
            }
            
            if (txtValue.toLowerCase().indexOf(filter) > -1) {
                tr[i].style.display = '';
            } else {
                tr[i].style.display = 'none';
            }
        }
        
        const visibleRows = Array.from(tr).slice(1).filter(row => row.style.display !== 'none').length;
        const totalElement = document.getElementById('totalPurchases');
        if (totalElement) {
            totalElement.textContent = visibleRows;
        }
    }

    function sortTable(columnIndex) {
        const table = document.getElementById('purchasesTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            const aValue = a.cells[columnIndex]?.textContent.toLowerCase() || '';
            const bValue = b.cells[columnIndex]?.textContent.toLowerCase() || '';
            
            if (columnIndex === 0 || columnIndex === 4) {
                return parseInt(aValue) - parseInt(bValue);
            }
            
            if (columnIndex === 5) {
                return new Date(aValue) - new Date(bValue);
            }
            
            return aValue.localeCompare(bValue);
        });
        
        tbody.innerHTML = '';
        rows.forEach(row => tbody.appendChild(row));
    }

    function calculateTotal() {
        const quantity = parseFloat(document.getElementById('item_quantity')?.value) || 0;
        const unitPrice = parseFloat(document.getElementById('unit_price')?.value) || 0;
        const totalPrice = quantity * unitPrice;
        
        const totalField = document.getElementById('total_price');
        if (totalField) {
            totalField.value = totalPrice.toFixed(2);
        }
    }

    function calculateModalTotal() {
        const quantity = parseFloat(document.getElementById('modal_item_quantity')?.value) || 0;
        const unitPrice = parseFloat(document.getElementById('modal_unit_price')?.value) || 0;
        const totalPrice = quantity * unitPrice;
        
        const totalField = document.getElementById('modal_total_price');
        if (totalField) {
            totalField.value = totalPrice.toFixed(2);
        }
    }

    function checkUserEligibility() {
        const userSelect = document.getElementById('user_id');
        const selectedOption = userSelect.options[userSelect.selectedIndex];
        
        if (selectedOption.value && selectedOption.dataset.dob) {
            checkEligibilityForDOB(selectedOption.dataset.dob, 'eligibilityAlert', 'eligibilityMessage');
        }
    }

    function checkModalUserEligibility() {
        const userSelect = document.getElementById('modal_user_id');
        const selectedOption = userSelect.options[userSelect.selectedIndex];
        
        if (selectedOption.value && selectedOption.dataset.dob) {
            checkEligibilityForDOB(selectedOption.dataset.dob, 'modalEligibilityAlert', 'modalEligibilityMessage');
        }
    }

    function checkEligibilityForDOB(dob, alertId, messageId) {
        const birthDate = new Date(dob);
        const today = new Date();
        const age = Math.floor((today - birthDate) / (365.25 * 24 * 60 * 60 * 1000));
        
        const alertElement = document.getElementById(alertId);
        const messageElement = document.getElementById(messageId);
        
        if (age >= 18) {
            alertElement.className = 'alert alert-success';
            messageElement.innerHTML = '<i class="bi bi-check-circle me-2"></i>User is eligible for purchases (18+ years old)';
        } else {
            alertElement.className = 'alert alert-warning';
            messageElement.innerHTML = '<i class="bi bi-exclamation-triangle me-2"></i>User may have purchase restrictions (under 18 years old)';
        }
        
        alertElement.classList.remove('d-none');
    }
    </script>
    <?php if ($can_add_purchases): ?>
    <script>
    <?php if ($can_manage_purchases): ?>
    function viewPurchase(id) {
        window.location.href = `purchases.php?action=view&id=${id}`;
    }

    function editPurchase(id) {
        window.location.href = `purchases.php?action=edit&id=${id}`;
    }

    function confirmDelete(id, name) {
        if (confirm(`Are you sure you want to delete purchase record "${name}" (ID: ${id})?`)) {
            window.location.href = `purchases.php?action=delete&id=${id}`;
        }
    }
    <?php else: ?>
    function viewPurchase(id) {
        alert('Citizens do not have permission to view purchase details. Only Officials, Merchants, and Administrators can access this feature.');
    }

    function editPurchase(id) {
        alert('Citizens do not have permission to edit purchase records. Only Officials, Merchants, and Administrators can access this feature.');
    }

    function confirmDelete(id, name) {
        alert('Citizens do not have permission to delete purchase records. Only Officials, Merchants, and Administrators can access this feature.');
    }
    <?php endif; ?>
    
    // Auto-close modal after successful operations
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
    </script>
    <?php else: ?>
    <script>
    document.addEventListener("DOMContentLoaded", function() {
        console.log("No purchase management functions available for this user role");
    });
    </script>
    <?php endif; ?>
</body>
</html>