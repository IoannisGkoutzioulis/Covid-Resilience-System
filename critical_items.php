<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

// Role-based permission matrix
$can_suggest = ($is_merchant || $is_admin);
$can_approve = ($is_admin || $is_official);
$can_set_limits = ($is_admin || $is_official);

$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$item_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$success_message = $error_message = '';
$refresh_needed = false;

$stock_items = [];
$critical_items = [];

// Block unauthorized citizen access to admin functions
if ($is_citizen && in_array($action, ['review', 'edit_limits'])) {
    logAccess($_SESSION['user_id'], 'Unauthorized attempt to ' . $action . ' critical item', false);
    $_SESSION['error_message'] = "You don't have permission to " . $action . " critical items";
    header("Location: critical_items.php");
    exit();
}

// Get merchant ID for permission validation
$merchant_id = 0;
if ($is_merchant) {
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT merchant_id FROM merchants WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $merchant = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($merchant) {
            $merchant_id = $merchant['merchant_id'];
        } else {
            $_SESSION['error_message'] = "Error: Merchant profile not found";
            header("Location: dashboard.php");
            exit();
        }
    } catch (PDOException $e) {
        $error_message = "Database error: " . $e->getMessage();
    }
}

try {
    $pdo = getDBConnection();
    
    // Handle critical item suggestion (merchants/admin)
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'suggest_item' && $can_suggest) {
        $stock_id = (int)$_POST['stock_id'];
        $suggested_reason = sanitizeInput($_POST['description']);
        
        // Merchants can only suggest their own inventory items
        if ($is_merchant) {
            $stockStmt = $pdo->prepare("SELECT * FROM stock WHERE stock_id = ? AND merchant_id = ?");
            $stockStmt->execute([$stock_id, $merchant_id]);
            $stockItem = $stockStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$stockItem) {
                $error_message = "Error: Invalid stock item selected or you don't have permission to suggest this item";
            } else {
                // Prevent duplicate suggestions
                $checkStmt = $pdo->prepare("SELECT * FROM critical_items WHERE stock_id = ? AND status != 'Rejected'");
                $checkStmt->execute([$stock_id]);
                
                if ($checkStmt->rowCount() > 0) {
                    $error_message = "This item has already been suggested as critical";
                } else {
                    $stmt = $pdo->prepare("
                        INSERT INTO critical_items (stock_id, merchant_id, suggested_reason)
                        VALUES (?, ?, ?)
                    ");
                    
                    $stmt->execute([
                        $stock_id,
                        $merchant_id,
                        $suggested_reason
                    ]);
                    
                    $success_message = "Item successfully suggested as critical";
                    $refresh_needed = true;
                    
                    logAccess($_SESSION['user_id'], 'Suggested critical item: ' . $stockItem['item_name'], true);
                }
            }
        }
        // Admins can auto-approve any item
        else if ($is_admin) {
            $stockStmt = $pdo->prepare("SELECT s.*, m.merchant_id FROM stock s JOIN merchants m ON s.merchant_id = m.merchant_id WHERE s.stock_id = ?");
            $stockStmt->execute([$stock_id]);
            $stockItem = $stockStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$stockItem) {
                $error_message = "Error: Invalid stock item selected";
            } else {
                $checkStmt = $pdo->prepare("SELECT * FROM critical_items WHERE stock_id = ? AND status != 'Rejected'");
                $checkStmt->execute([$stock_id]);
                
                if ($checkStmt->rowCount() > 0) {
                    $error_message = "This item has already been suggested as critical";
                } else {
                    // Admin suggestions are auto-approved
                    $stmt = $pdo->prepare("
                        INSERT INTO critical_items (stock_id, merchant_id, suggested_reason, status, reviewed_by, reviewed_at)
                        VALUES (?, ?, ?, 'Approved', ?, NOW())
                    ");
                    
                    $stmt->execute([
                        $stock_id,
                        $stockItem['merchant_id'],
                        $suggested_reason,
                        $_SESSION['user_id']
                    ]);
                    
                    $success_message = "Item successfully added as critical";
                    $refresh_needed = true;
                    
                    logAccess($_SESSION['user_id'], 'Added critical item: ' . $stockItem['item_name'], true);
                }
            }
        }
    }
    
    // Handle item review (officials/admin only)
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'review_item' && $can_approve) {
        $item_id = (int)$_POST['item_id'];
        $status = sanitizeInput($_POST['status']);
        $review_notes = sanitizeInput($_POST['notes']);
        
        if (!in_array($status, ['Approved', 'Rejected', 'Pending'])) {
            $error_message = "Invalid status selected";
        } else {
            $stmt = $pdo->prepare("
                UPDATE critical_items 
                SET status = ?, reviewed_by = ?, reviewed_at = NOW(), review_notes = ?
                WHERE critical_item_id = ?
            ");
            
            $stmt->execute([
                $status,
                $_SESSION['user_id'],
                $review_notes,
                $item_id
            ]);
            
            $success_message = "Item review updated successfully";
            $refresh_needed = true;
            
            logAccess($_SESSION['user_id'], 'Updated critical item ID: ' . $item_id . ' to status: ' . $status, true);
        }
    }
    
    // Fetch stock items for suggestion dropdown
    if ($can_suggest) {
        if ($is_merchant) {
            $stmt = $pdo->prepare("
                SELECT * FROM stock 
                WHERE merchant_id = ? 
                ORDER BY category, item_name
            ");
            $stmt->execute([$merchant_id]);
        } else {
            // Admin can see all stock items
            $stmt = $pdo->query("
                SELECT s.*, m.merchant_name 
                FROM stock s
                JOIN merchants m ON s.merchant_id = m.merchant_id
                ORDER BY s.category, s.item_name
            ");
        }
        $stock_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    // Fetch critical items with role-based filtering
    if ($can_approve) {
        // Officials and Admin see all critical items with full details
        $stmt = $pdo->query("
            SELECT ci.critical_item_id as item_id, ci.stock_id, ci.merchant_id, 
                   ci.suggested_reason as description, ci.status, ci.reviewed_by, 
                   ci.reviewed_at, ci.review_notes as notes, ci.suggested_at,
                   s.item_name, s.category, m.merchant_name, 
                   u.full_name as reviewer_name
            FROM critical_items ci
            JOIN stock s ON ci.stock_id = s.stock_id
            JOIN merchants m ON ci.merchant_id = m.merchant_id
            LEFT JOIN users u ON ci.reviewed_by = u.user_id
            ORDER BY 
                CASE 
                    WHEN ci.status = 'Pending' THEN 1
                    WHEN ci.status = 'Approved' THEN 2
                    ELSE 3
                END,
                ci.suggested_at DESC
        ");
        $critical_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else if ($is_merchant) {
        // Merchants see all items but with ownership indication
        $stmt = $pdo->prepare("
            SELECT ci.critical_item_id as item_id, ci.stock_id, ci.merchant_id, 
                   ci.suggested_reason as description, ci.status, ci.reviewed_by, 
                   ci.reviewed_at, ci.review_notes as notes, ci.suggested_at,
                   s.item_name, s.category, m.merchant_name, 
                   u.full_name as reviewer_name,
                   CASE WHEN ci.merchant_id = ? THEN 1 ELSE 0 END as is_own_item
            FROM critical_items ci
            JOIN stock s ON ci.stock_id = s.stock_id
            JOIN merchants m ON ci.merchant_id = m.merchant_id
            LEFT JOIN users u ON ci.reviewed_by = u.user_id
            ORDER BY 
                CASE WHEN ci.merchant_id = ? THEN 0 ELSE 1 END,
                CASE 
                    WHEN ci.status = 'Pending' THEN 1
                    WHEN ci.status = 'Approved' THEN 2
                    ELSE 3
                END,
                ci.suggested_at DESC
        ");
        $stmt->execute([$merchant_id, $merchant_id]);
        $critical_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        // Citizens see only approved items
        $stmt = $pdo->query("
            SELECT ci.critical_item_id as item_id, ci.stock_id, ci.merchant_id, 
                   ci.suggested_reason as description, ci.status, ci.suggested_at,
                   s.item_name, s.category, m.merchant_name
            FROM critical_items ci
            JOIN stock s ON ci.stock_id = s.stock_id
            JOIN merchants m ON ci.merchant_id = m.merchant_id
            WHERE ci.status = 'Approved'
            ORDER BY s.category, s.item_name
        ");
        $critical_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    // Fetch item for review/editing
    $item_data = null;
    if (($action === 'review' || $action === 'edit_limits') && $item_id > 0) {
        if ($action === 'review' && !$can_approve) {
            $_SESSION['error_message'] = "You don't have permission to review critical items";
            header("Location: critical_items.php");
            exit();
        }
        
        if ($action === 'edit_limits' && !$can_set_limits) {
            $_SESSION['error_message'] = "You don't have permission to set purchase limits";
            header("Location: critical_items.php");
            exit();
        }
        
        $stmt = $pdo->prepare("
            SELECT ci.critical_item_id as item_id, ci.stock_id, ci.merchant_id,
                   ci.suggested_reason as description, ci.status, ci.reviewed_by, 
                   ci.reviewed_at, ci.review_notes as notes, ci.suggested_at,
                   s.item_name, s.category, s.description as item_description,
                   s.quantity_available, s.unit_price, m.merchant_name,
                   u.full_name as reviewer_name
            FROM critical_items ci
            JOIN stock s ON ci.stock_id = s.stock_id
            JOIN merchants m ON ci.merchant_id = m.merchant_id
            LEFT JOIN users u ON ci.reviewed_by = u.user_id
            WHERE ci.critical_item_id = ?
        ");
        $stmt->execute([$item_id]);
        $item_data = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$item_data) {
            $error_message = "Critical item not found";
            $action = 'list';
        }
    }
    
} catch (PDOException $e) {
    $error_message = "Database error: " . $e->getMessage();
    if (!isset($critical_items)) {
        $critical_items = [];
    }
    if (!isset($stock_items)) {
        $stock_items = [];
    }
}

// Handle session messages from redirects
if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

function getCategoryBadgeClass($category) {
    switch ($category) {
        case 'Medical':
            return 'bg-info text-dark';
        case 'Grocery':
            return 'bg-warning text-dark';
        case 'Essential':
            return 'bg-success text-white';
        case 'Other':
            return 'bg-secondary text-white';
        default:
            return 'bg-light text-dark';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Critical Items - COVID Resilience System</title>
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
            margin-bottom: 20px;
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
        
        .item-card {
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .item-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .tab-content {
            padding: 20px 0;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        
        .status-pending {
            background-color: #ffc107;
        }
        
        .status-approved {
            background-color: #28a745;
        }
        
        .status-rejected {
            background-color: #dc3545;
        }
        
        .limits-badge {
            position: absolute;
            top: 10px;
            right: 10px;
            font-size: 0.7rem;
        }
        
        .own-item {
            background-color: #f8f9fa;
            border-left: 4px solid #6f42c1;
        }
        
        .own-item-indicator {
            background-color: #6f42c1;
            color: white;
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 3px;
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
                        <a class="nav-link active" href="critical_items.php">
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
                <?php if ($action === 'list'): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-shield-plus me-2"></i>Critical Items</h2>
                    <?php if ($can_suggest && !$is_official): ?>
                    <div>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#suggestItemModal">
                            <i class="bi bi-plus-circle me-2"></i>Suggest New Critical Item
                        </button>
                    </div>
                    <?php endif; ?>
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
                            <h5 class="mb-1">Critical Items Information</h5>
                            <p class="mb-0">These items have been designated as critical by government officials. Purchase limits may apply to these items.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if ($is_merchant): ?>
                <div class="alert alert-info mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">Merchant Critical Items Dashboard</h5>
                            <p class="mb-0">You can see all critical items in the system and suggest items from your inventory. Items you suggested are highlighted with a purple indicator.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if ($can_approve): ?>
                <!-- Officials/Admin tabbed interface -->
                <ul class="nav nav-tabs" id="criticalItemsTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="pending-tab" data-bs-toggle="tab" data-bs-target="#pending" type="button" role="tab" aria-controls="pending" aria-selected="true">
                            <i class="bi bi-hourglass me-1"></i> Pending Review <span class="badge bg-warning text-dark" id="pending-count">0</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="approved-tab" data-bs-toggle="tab" data-bs-target="#approved" type="button" role="tab" aria-controls="approved" aria-selected="false">
                            <i class="bi bi-check-circle me-1"></i> Approved Items <span class="badge bg-success" id="approved-count">0</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="rejected-tab" data-bs-toggle="tab" data-bs-target="#rejected" type="button" role="tab" aria-controls="rejected" aria-selected="false">
                            <i class="bi bi-x-circle me-1"></i> Rejected Items <span class="badge bg-danger" id="rejected-count">0</span>
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="all-tab" data-bs-toggle="tab" data-bs-target="#all" type="button" role="tab" aria-controls="all" aria-selected="false">
                            <i class="bi bi-grid me-1"></i> All Items <span class="badge bg-secondary" id="all-count">0</span>
                        </button>
                    </li>
                </ul>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <input type="text" id="searchInput" class="form-control" placeholder="Search items..." oninput="filterTable()">
                            </div>
                            <div class="col-md-6 text-md-end">
                                <div class="btn-group" role="group">
                                    <button type="button" class="btn btn-outline-secondary" onclick="filterItems('all')">All</button>
                                    <button type="button" class="btn btn-outline-info" onclick="filterItems('Medical')">Medical</button>
                                    <button type="button" class="btn btn-outline-warning" onclick="filterItems('Grocery')">Grocery</button>
                                    <button type="button" class="btn btn-outline-success" onclick="filterItems('Essential')">Essential</button>
                                    <button type="button" class="btn btn-outline-secondary" onclick="filterItems('Other')">Other</button>
                                </div>
                            </div>
                        </div>
                        
                        <?php if ($can_approve): ?>
                        <!-- Officials/Admin tabbed content -->
                        <div class="tab-content" id="criticalItemsTabContent">
                            <div class="tab-pane fade show active" id="pending" role="tabpanel" aria-labelledby="pending-tab">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Item</th>
                                                <th>Category</th>
                                                <th>Merchant</th>
                                                <th>Date Suggested</th>
                                                <th>Status</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="pendingTableBody">
                                            <!-- Populated by JavaScript -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <div class="tab-pane fade" id="approved" role="tabpanel" aria-labelledby="approved-tab">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Item</th>
                                                <th>Category</th>
                                                <th>Merchant</th>
                                                <th>Status</th>
                                                <th>Approved By</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="approvedTableBody">
                                            <!-- Populated by JavaScript -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <div class="tab-pane fade" id="rejected" role="tabpanel" aria-labelledby="rejected-tab">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Item</th>
                                                <th>Category</th>
                                                <th>Merchant</th>
                                                <th>Date Rejected</th>
                                                <th>Rejected By</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="rejectedTableBody">
                                            <!-- Populated by JavaScript -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <div class="tab-pane fade" id="all" role="tabpanel" aria-labelledby="all-tab">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>Item</th>
                                                <th>Category</th>
                                                <th>Merchant</th>
                                                <th>Status</th>
                                                <th>Date Suggested</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="allTableBody">
                                            <!-- Populated by JavaScript -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                        <?php else: ?>
                        <!-- Merchant/Citizen view -->
                        <div class="table-responsive">
                            <table id="criticalItemsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Item</th>
                                        <th>Category</th>
                                        <th>Merchant</th>
                                        <?php if ($is_merchant): ?>
                                        <th>Date Suggested</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                        <?php elseif ($is_citizen): ?>
                                        <th>Date Approved</th>
                                        <?php else: ?>
                                        <th>Date Approved</th>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($critical_items)): ?>
                                    <tr>
                                        <td colspan="<?php echo $is_citizen ? '4' : ($is_merchant ? '6' : '5'); ?>" class="text-center">
                                            <?php if ($is_merchant): ?>
                                            No critical items found. You can suggest items using the button above.
                                            <?php else: ?>
                                            No critical items found at this time.
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php else: ?>
                                    <?php foreach ($critical_items as $item): ?>
                                    <tr data-category="<?php echo htmlspecialchars($item['category']); ?>" <?php echo (isset($item['is_own_item']) && $item['is_own_item']) ? 'class="own-item"' : ''; ?>>
                                        <td>
                                            <?php echo htmlspecialchars($item['item_name']); ?>
                                            <?php if (isset($item['is_own_item']) && $item['is_own_item']): ?>
                                            <span class="own-item-indicator ms-2">Your Item</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="badge <?php echo getCategoryBadgeClass($item['category']); ?>">
                                                <?php echo htmlspecialchars($item['category']); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($item['merchant_name'] ?? ''); ?></td>
                                        <?php if ($is_merchant): ?>
                                        <td><?php echo date('M j, Y', strtotime($item['suggested_at'])); ?></td>
                                        <td>
                                            <?php 
                                            $statusClass = 'bg-secondary';
                                            if ($item['status'] === 'Approved') $statusClass = 'bg-success';
                                            elseif ($item['status'] === 'Rejected') $statusClass = 'bg-danger';
                                            elseif ($item['status'] === 'Pending') $statusClass = 'bg-warning text-dark';
                                            ?>
                                            <span class="badge <?php echo $statusClass; ?>">
                                                <?php echo htmlspecialchars($item['status']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-info" data-bs-toggle="modal" data-bs-target="#viewDetailsModal" 
                                                    data-item-id="<?php echo $item['item_id']; ?>"
                                                    data-item-name="<?php echo htmlspecialchars($item['item_name']); ?>"
                                                    data-item-category="<?php echo htmlspecialchars($item['category']); ?>"
                                                    data-item-description="<?php echo htmlspecialchars($item['description']); ?>"
                                                    data-item-status="<?php echo htmlspecialchars($item['status']); ?>"
                                                    data-item-notes="<?php echo htmlspecialchars($item['notes'] ?? ''); ?>"
                                                    data-item-reviewer="<?php echo htmlspecialchars($item['reviewer_name'] ?? ''); ?>">
                                                <i class="bi bi-eye"></i> Details
                                            </button>
                                        </td>
                                        <?php else: ?>
                                        <td>
                                            <?php echo !empty($item['reviewed_at']) ? date('M j, Y', strtotime($item['reviewed_at'])) : 'Not yet approved'; ?>
                                        </td>
                                        <?php endif; ?>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php endif; ?>
                        
                        <div class="d-flex justify-content-between mt-3">
                            <div>
                                Total: <span id="totalItems"><?php echo count($critical_items); ?></span> item<?php echo count($critical_items) != 1 ? 's' : ''; ?>
                            </div>
                            <div>
                                <button type="button" class="btn btn-secondary" onclick="window.location.reload();">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'review' && isset($item_data) && $can_approve): ?>
                <!-- Item review interface -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-shield-plus me-2"></i>Review Critical Item</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="critical_items.php">Critical Items</a></li>
                                <li class="breadcrumb-item active" aria-current="page">Review Item</li>
                            </ol>
                        </nav>
                    </div>
                    <a href="critical_items.php" class="btn btn-secondary">
                        <i class="bi bi-arrow-left me-2"></i>Back to List
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
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Item Details</h5>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="fw-bold">Item Name:</label>
                                    <p><?php echo htmlspecialchars($item_data['item_name']); ?></p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Category:</label>
                                    <p>
                                        <span class="badge <?php echo getCategoryBadgeClass($item_data['category']); ?>">
                                            <?php echo htmlspecialchars($item_data['category']); ?>
                                        </span>
                                    </p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Merchant:</label>
                                    <p><?php echo htmlspecialchars($item_data['merchant_name']); ?></p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Description:</label>
                                    <p><?php echo nl2br(htmlspecialchars($item_data['item_description'] ?? 'No description available')); ?></p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Current Inventory:</label>
                                    <p><?php echo htmlspecialchars($item_data['quantity_available']); ?> units</p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Unit Price:</label>
                                    <p>$<?php echo number_format((float)$item_data['unit_price'], 2); ?></p>
                                </div>
                                <div class="mb-3">
                                    <label class="fw-bold">Date Suggested:</label>
                                    <p><?php echo date('F j, Y', strtotime($item_data['suggested_at'])); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Review Decision</h5>
                            </div>
                            <div class="card-body">
                                <form action="critical_items.php" method="POST">
                                    <input type="hidden" name="action" value="review_item">
                                    <input type="hidden" name="item_id" value="<?php echo $item_data['item_id']; ?>">
                                    
                                    <div class="mb-3">
                                        <label for="status" class="form-label">Status:</label>
                                        <select class="form-select" id="status" name="status" required>
                                            <option value="">Select a status</option>
                                            <option value="Pending" <?php echo $item_data['status'] === 'Pending' ? 'selected' : ''; ?>>Pending</option>
                                            <option value="Approved" <?php echo $item_data['status'] === 'Approved' ? 'selected' : ''; ?>>Approved</option>
                                            <option value="Rejected" <?php echo $item_data['status'] === 'Rejected' ? 'selected' : ''; ?>>Rejected</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="notes" class="form-label">Review Notes:</label>
                                        <textarea class="form-control" id="notes" name="notes" rows="4" placeholder="Enter your review comments here..."><?php echo htmlspecialchars($item_data['notes'] ?? ''); ?></textarea>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Current Review Information:</label>
                                        <?php if (!empty($item_data['reviewed_by'])): ?>
                                        <div class="card bg-light p-3">
                                            <p class="mb-1"><strong>Reviewed By:</strong> <?php echo htmlspecialchars($item_data['reviewer_name']); ?></p>
                                            <p class="mb-1"><strong>Reviewed On:</strong> <?php echo date('F j, Y', strtotime($item_data['reviewed_at'])); ?></p>
                                            <p class="mb-0"><strong>Status:</strong> 
                                                <?php 
                                                $statusClass = 'bg-secondary';
                                                if ($item_data['status'] === 'Approved') $statusClass = 'bg-success';
                                                elseif ($item_data['status'] === 'Rejected') $statusClass = 'bg-danger';
                                                elseif ($item_data['status'] === 'Pending') $statusClass = 'bg-warning text-dark';
                                                ?>
                                                <span class="badge <?php echo $statusClass; ?>"><?php echo htmlspecialchars($item_data['status']); ?></span>
                                            </p>
                                        </div>
                                        <?php else: ?>
                                        <p class="text-muted">This item has not been reviewed yet.</p>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Merchant's Critical Item Justification:</label>
                                        <div class="card bg-light p-3">
                                            <?php if (!empty($item_data['description'])): ?>
                                            <p class="mb-0"><?php echo nl2br(htmlspecialchars($item_data['description'])); ?></p>
                                            <?php else: ?>
                                            <p class="text-muted mb-0">No justification provided.</p>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <a href="critical_items.php" class="btn btn-outline-secondary me-md-2">Cancel</a>
                                        <button type="submit" class="btn btn-primary">Save Review</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Suggestion modal -->
    <?php if ($can_suggest): ?>
    <div class="modal fade" id="suggestItemModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-shield-plus me-2"></i>Suggest Critical Item</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="critical_items.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="suggest_item">
                        
                        <div class="mb-3">
                            <label for="stock_id" class="form-label">Select Item from Inventory:</label>
                            <select class="form-select" id="stock_id" name="stock_id" required>
                                <option value="">-- Select an item --</option>
                                <optgroup label="Medical Items">
                                <?php foreach ($stock_items as $item): ?>
                                    <?php if ($item['category'] === 'Medical'): ?>
                                    <option value="<?php echo $item['stock_id']; ?>">
                                        <?php echo htmlspecialchars($item['item_name']); ?> 
                                        <?php if (isset($item['merchant_name'])): ?>
                                        (<?php echo htmlspecialchars($item['merchant_name']); ?>)
                                        <?php endif; ?>
                                        - <?php echo $item['quantity_available']; ?> units
                                    </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                                </optgroup>
                                <optgroup label="Grocery Items">
                                <?php foreach ($stock_items as $item): ?>
                                    <?php if ($item['category'] === 'Grocery'): ?>
                                    <option value="<?php echo $item['stock_id']; ?>">
                                        <?php echo htmlspecialchars($item['item_name']); ?> 
                                        <?php if (isset($item['merchant_name'])): ?>
                                        (<?php echo htmlspecialchars($item['merchant_name']); ?>)
                                        <?php endif; ?>
                                        - <?php echo $item['quantity_available']; ?> units
                                    </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                                </optgroup>
                                <optgroup label="Essential Items">
                                <?php foreach ($stock_items as $item): ?>
                                    <?php if ($item['category'] === 'Essential'): ?>
                                    <option value="<?php echo $item['stock_id']; ?>">
                                        <?php echo htmlspecialchars($item['item_name']); ?> 
                                        <?php if (isset($item['merchant_name'])): ?>
                                        (<?php echo htmlspecialchars($item['merchant_name']); ?>)
                                        <?php endif; ?>
                                        - <?php echo $item['quantity_available']; ?> units
                                    </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                                </optgroup>
                                <optgroup label="Other Items">
                                <?php foreach ($stock_items as $item): ?>
                                    <?php if ($item['category'] === 'Other'): ?>
                                    <option value="<?php echo $item['stock_id']; ?>">
                                        <?php echo htmlspecialchars($item['item_name']); ?> 
                                        <?php if (isset($item['merchant_name'])): ?>
                                        (<?php echo htmlspecialchars($item['merchant_name']); ?>)
                                        <?php endif; ?>
                                        - <?php echo $item['quantity_available']; ?> units
                                    </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                                </optgroup>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="description" class="form-label">Why is this item critical?</label>
                            <textarea class="form-control" id="description" name="description" rows="4" 
                                placeholder="Explain why this item should be designated as critical..."></textarea>
                            <small class="text-muted">Please provide details on why this item is essential for COVID resilience.</small>
                        </div>
                        
                        <?php if ($is_merchant): ?>
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            <small>Your suggestion will be reviewed by government officials who will determine whether to approve it as a critical item.</small>
                        </div>
                        <?php endif; ?>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Submit Suggestion</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Merchant details modal -->
    <?php if ($is_merchant): ?>
    <div class="modal fade" id="viewDetailsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-info-circle me-2"></i>Item Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="fw-bold">Item Name:</label>
                        <p id="view-item-name"></p>
                    </div>
                    <div class="mb-3">
                        <label class="fw-bold">Category:</label>
                        <p id="view-item-category"></p>
                    </div>
                    <div class="mb-3">
                        <label class="fw-bold">Status:</label>
                        <p id="view-item-status"></p>
                    </div>
                    <div class="mb-3">
                        <label class="fw-bold">Your Justification:</label>
                        <p id="view-item-description"></p>
                    </div>
                    <div class="mb-3 reviewer-section">
                        <label class="fw-bold">Reviewer Comments:</label>
                        <p id="view-item-notes"></p>
                    </div>
                    <div class="mb-3 reviewer-section">
                        <label class="fw-bold">Reviewed By:</label>
                        <p id="view-item-reviewer"></p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    <?php if ($can_approve): ?>
    // JavaScript data injection for admin/official interface
    const criticalItems = <?php echo json_encode($critical_items); ?>;
    
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Critical Items Data:', criticalItems);
        
        populateTables();
        updateTabCounts();
        
        const tabs = document.querySelectorAll('[data-bs-toggle="tab"]');
        tabs.forEach(tab => {
            tab.addEventListener('shown.bs.tab', event => {
                if (typeof filterItems === 'function') {
                    filterItems('all');
                }
            });
        });
        
        <?php if ($refresh_needed): ?>
        // Auto-close modals after form submission
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
        <?php endif; ?>
    });
    
    function populateTables() {
        console.log('Populating tables with', criticalItems.length, 'items');
        
        const pendingTableBody = document.getElementById('pendingTableBody');
        const approvedTableBody = document.getElementById('approvedTableBody');
        const rejectedTableBody = document.getElementById('rejectedTableBody');
        const allTableBody = document.getElementById('allTableBody');
        
        if (!pendingTableBody || !approvedTableBody || !rejectedTableBody || !allTableBody) {
            console.error('Table bodies not found!');
            return;
        }
        
        pendingTableBody.innerHTML = '';
        approvedTableBody.innerHTML = '';
        rejectedTableBody.innerHTML = '';
        allTableBody.innerHTML = '';
        
        let pendingCount = 0;
        let approvedCount = 0;
        let rejectedCount = 0;
        
        criticalItems.forEach(item => {
            const allRow = createRow(item, 'all');
            allTableBody.appendChild(allRow);
            
            if (item.status === 'Pending') {
                const pendingRow = createRow(item, 'pending');
                pendingTableBody.appendChild(pendingRow);
                pendingCount++;
            } else if (item.status === 'Approved') {
                const approvedRow = createRow(item, 'approved');
                approvedTableBody.appendChild(approvedRow);
                approvedCount++;
            } else if (item.status === 'Rejected') {
                const rejectedRow = createRow(item, 'rejected');
                rejectedTableBody.appendChild(rejectedRow);
                rejectedCount++;
            }
        });
        
        document.getElementById('pending-count').textContent = pendingCount;
        document.getElementById('approved-count').textContent = approvedCount;
        document.getElementById('rejected-count').textContent = rejectedCount;
        document.getElementById('all-count').textContent = criticalItems.length;
        
        // Empty state handling
        if (pendingCount === 0) {
            pendingTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No pending items found</td></tr>';
        }
        
        if (approvedCount === 0) {
            approvedTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No approved items found</td></tr>';
        }
        
        if (rejectedCount === 0) {
            rejectedTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No rejected items found</td></tr>';
        }
        
        if (criticalItems.length === 0) {
            allTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No critical items found</td></tr>';
        }
        
        console.log('Tables populated. Counts:', {pending: pendingCount, approved: approvedCount, rejected: rejectedCount, total: criticalItems.length});
    }
    
    // Generate table rows with appropriate columns for each context
    function createRow(item, tableType) {
        const row = document.createElement('tr');
        row.dataset.category = item.category;
        
        if (tableType === 'pending') {
            row.innerHTML = `
                <td>${escapeHTML(item.item_name)}</td>
                <td>
                    <span class="badge ${getCategoryBadgeClass(item.category)}">
                        ${escapeHTML(item.category)}
                    </span>
                </td>
                <td>${escapeHTML(item.merchant_name || 'N/A')}</td>
                <td>${formatDate(item.suggested_at)}</td>
                <td>
                    <span class="badge ${getStatusClass(item.status)}">
                        ${escapeHTML(item.status)}
                    </span>
                </td>
                <td>
                    <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                        <i class="bi bi-check-circle"></i> Review
                    </a>
                </td>
            `;
        } else if (tableType === 'approved') {
            row.innerHTML = `
                <td>${escapeHTML(item.item_name)}</td>
                <td>
                    <span class="badge ${getCategoryBadgeClass(item.category)}">
                        ${escapeHTML(item.category)}
                    </span>
                </td>
                <td>${escapeHTML(item.merchant_name || 'N/A')}</td>
                <td>
                    <span class="badge ${getStatusClass(item.status)}">
                        ${escapeHTML(item.status)}
                    </span>
                </td>
                <td>${escapeHTML(item.reviewer_name || 'N/A')}</td>
                <td>
                    <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                        <i class="bi bi-pencil"></i> Edit
                    </a>
                </td>
            `;
        } else if (tableType === 'rejected') {
            row.innerHTML = `
                <td>${escapeHTML(item.item_name)}</td>
                <td>
                    <span class="badge ${getCategoryBadgeClass(item.category)}">
                        ${escapeHTML(item.category)}
                    </span>
                </td>
                <td>${escapeHTML(item.merchant_name || 'N/A')}</td>
                <td>${formatDate(item.reviewed_at || item.suggested_at)}</td>
                <td>${escapeHTML(item.reviewer_name || 'N/A')}</td>
                <td>
                    <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                        <i class="bi bi-arrow-repeat"></i> Re-Review
                    </a>
                </td>
            `;
        } else if (tableType === 'all') {
            row.innerHTML = `
                <td>${escapeHTML(item.item_name)}</td>
                <td>
                    <span class="badge ${getCategoryBadgeClass(item.category)}">
                        ${escapeHTML(item.category)}
                    </span>
                </td>
                <td>${escapeHTML(item.merchant_name || 'N/A')}</td>
                <td>
                    <span class="badge ${getStatusClass(item.status)}">
                        ${escapeHTML(item.status)}
                    </span>
                </td>
                <td>${formatDate(item.suggested_at)}</td>
                <td>
                    <a href="critical_items.php?action=review&id=${item.item_id}" class="btn btn-sm btn-primary">
                        <i class="bi bi-pencil"></i> Edit
                    </a>
                </td>
            `;
        }
        
        return row;
    }
    
    function getCategoryBadgeClass(category) {
        switch (category) {
            case 'Medical': return 'bg-info text-dark';
            case 'Grocery': return 'bg-warning text-dark';
            case 'Essential': return 'bg-success text-white';
            case 'Other': return 'bg-secondary text-white';
            default: return 'bg-light text-dark';
        }
    }
    
    function getStatusClass(status) {
        switch (status) {
            case 'Approved': return 'bg-success';
            case 'Rejected': return 'bg-danger';
            case 'Pending': return 'bg-warning text-dark';
            default: return 'bg-secondary';
        }
    }
    
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        return date.toLocaleDateString('en-US', options);
    }
    
    function updateTabCounts() {
        const pendingCount = criticalItems.filter(item => item.status === 'Pending').length;
        const approvedCount = criticalItems.filter(item => item.status === 'Approved').length;
        const rejectedCount = criticalItems.filter(item => item.status === 'Rejected').length;
        
        document.getElementById('pending-count').textContent = pendingCount;
        document.getElementById('approved-count').textContent = approvedCount;
        document.getElementById('rejected-count').textContent = rejectedCount;
        document.getElementById('all-count').textContent = criticalItems.length;
    }
    
    function filterItems(category) {
        console.log('Filtering by category:', category);
        
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const rows = activeTab.querySelectorAll('tbody tr[data-category]');
        
        rows.forEach(row => {
            if (category === 'all' || row.dataset.category === category) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
    
    function filterTable() {
        const searchText = document.getElementById('searchInput').value.toLowerCase();
        console.log('Filtering by search text:', searchText);
        
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const rows = activeTab.querySelectorAll('tbody tr[data-category]');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchText)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
    
    function escapeHTML(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    
    <?php else: ?>
    // Merchant/Citizen interface
    document.addEventListener('DOMContentLoaded', function() {
        <?php if ($is_merchant): ?>
        // Merchant modal initialization
        const viewDetailsModal = document.getElementById('viewDetailsModal');
        if (viewDetailsModal) {
            viewDetailsModal.addEventListener('show.bs.modal', function (event) {
                const button = event.relatedTarget;
                const itemName = button.getAttribute('data-item-name');
                const itemCategory = button.getAttribute('data-item-category');
                const itemDescription = button.getAttribute('data-item-description');
                const itemStatus = button.getAttribute('data-item-status');
                const itemNotes = button.getAttribute('data-item-notes');
                const itemReviewer = button.getAttribute('data-item-reviewer');
                
                document.getElementById('view-item-name').textContent = itemName;
                
                const categoryEl = document.getElementById('view-item-category');
                const categoryClass = getCategoryBadgeClass(itemCategory);
                categoryEl.innerHTML = `<span class="badge ${categoryClass}">${itemCategory}</span>`;
                
                const statusEl = document.getElementById('view-item-status');
                let statusClass = 'bg-secondary';
                if (itemStatus === 'Approved') statusClass = 'bg-success';
                else if (itemStatus === 'Rejected') statusClass = 'bg-danger';
                else if (itemStatus === 'Pending') statusClass = 'bg-warning text-dark';
                
                statusEl.innerHTML = `<span class="badge ${statusClass}">${itemStatus}</span>`;
                
                document.getElementById('view-item-description').textContent = itemDescription || 'No justification provided.';
                
                const notesEl = document.getElementById('view-item-notes');
                notesEl.textContent = itemNotes || 'No comments provided.';
                
                const reviewerEl = document.getElementById('view-item-reviewer');
                reviewerEl.textContent = itemReviewer || 'Not yet reviewed';
                
                // Hide reviewer sections for pending items
                const reviewerSections = document.querySelectorAll('.reviewer-section');
                reviewerSections.forEach(section => {
                    if (itemStatus === 'Pending') {
                        section.style.display = 'none';
                    } else {
                        section.style.display = 'block';
                    }
                });
            });
        }
        
        function getCategoryBadgeClass(category) {
            switch (category) {
                case 'Medical': return 'bg-info text-dark';
                case 'Grocery': return 'bg-warning text-dark';
                case 'Essential': return 'bg-success text-white';
                case 'Other': return 'bg-secondary text-white';
                default: return 'bg-light text-dark';
            }
        }
        <?php endif; ?>
        
        <?php if ($refresh_needed): ?>
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
        <?php endif; ?>
    });
    
    function filterItems(category) {
        const table = document.getElementById('criticalItemsTable');
        if (!table) return;
        
        const rows = table.querySelectorAll('tbody tr[data-category]');
        
        rows.forEach(row => {
            if (category === 'all' || row.dataset.category === category) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none').length;
        const totalItemsEl = document.getElementById('totalItems');
        if (totalItemsEl) {
            totalItemsEl.textContent = visibleRows;
        }
    }
    
    function filterTable() {
        const searchText = document.getElementById('searchInput').value.toLowerCase();
        const table = document.getElementById('criticalItemsTable');
        if (!table) return;
        
        const rows = table.querySelectorAll('tbody tr[data-category]');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchText)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none').length;
        const totalItemsEl = document.getElementById('totalItems');
        if (totalItemsEl) {
            totalItemsEl.textContent = visibleRows;
        }
    }
    <?php endif; ?>
    </script>
</body>
</html>