<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$can_manage_stock = ($is_admin || $is_official || $is_merchant);

enforcePermission('stock', 'read');

$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$stock_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$success_message = $error_message = '';
$refresh_needed = false;

// Prevent citizens from accessing privileged operations
if ($is_citizen && in_array($action, ['edit', 'delete'])) {
    logAccess($_SESSION['user_id'], 'Unauthorized attempt to ' . $action . ' stock record', false);
    $error_message = "You don't have permission to " . $action . " stock items";
    $action = 'list';
}

// Retrieve merchant profile for merchant users
$merchant_id = 0;
if (hasRole(['Merchant'])) {
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

// Process stock creation requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action']) && $_POST['action'] === 'add_stock') {
        if (!$can_manage_stock) {
            $error_message = "You don't have permission to add stock items";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to add stock item', false);
        } else {
            enforcePermission('stock', 'create');
            
            $item_name = sanitizeInput($_POST['item_name']);
            $description = sanitizeInput($_POST['description']);
            $quantity = (int)$_POST['quantity'];
            $unit_price = (float)$_POST['unit_price'];
            $category = sanitizeInput($_POST['category']);
            
            $selected_merchant_id = $merchant_id;
            
            // Allow admin/official roles to select different merchants
            if (!hasRole(['Merchant']) && isset($_POST['merchant_id'])) {
                $selected_merchant_id = (int)$_POST['merchant_id'];
            }
            
            $errors = [];
            if (empty($item_name)) {
                $errors[] = "Item name is required";
            }
            
            if ($quantity < 0) {
                $errors[] = "Quantity cannot be negative";
            }
            
            if ($unit_price < 0) {
                $errors[] = "Unit price cannot be negative";
            }
            
            if (empty($category)) {
                $errors[] = "Category is required";
            }
            
            if (empty($selected_merchant_id)) {
                $errors[] = "Merchant is required";
            }
            
            if (empty($errors)) {
                try {
                    $pdo = getDBConnection();
                    
                    $stmt = $pdo->prepare("INSERT INTO stock (merchant_id, item_name, description, quantity_available, unit_price, category) VALUES (?, ?, ?, ?, ?, ?)");
                    
                    $stmt->execute([
                        $selected_merchant_id,
                        $item_name,
                        $description,
                        $quantity,
                        $unit_price,
                        $category
                    ]);
                    
                    $success_message = "Stock item added successfully!";
                    logAccess($_SESSION['user_id'], 'Added new stock item: ' . $item_name, true);
                    $refresh_needed = true;
                    
                } catch (PDOException $e) {
                    $error_message = "Database error: " . $e->getMessage();
                }
            } else {
                $error_message = "Please correct the following errors: " . implode(", ", $errors);
            }
        }
    }
    
    // Process stock update requests
    else if (isset($_POST['action']) && $_POST['action'] === 'edit_stock') {
        if (!$can_manage_stock) {
            $error_message = "You don't have permission to edit stock items";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to edit stock item', false);
        } else {
            enforcePermission('stock', 'update');
            
            $stock_id = (int)$_POST['stock_id'];
            $item_name = sanitizeInput($_POST['item_name']);
            $description = sanitizeInput($_POST['description']);
            $quantity = (int)$_POST['quantity'];
            $unit_price = (float)$_POST['unit_price'];
            $category = sanitizeInput($_POST['category']);
            
            $selected_merchant_id = $merchant_id;
            
            // Allow admin/official roles to select different merchants
            if (!hasRole(['Merchant']) && isset($_POST['merchant_id'])) {
                $selected_merchant_id = (int)$_POST['merchant_id'];
            }
            
            $errors = [];
            if (empty($item_name)) {
                $errors[] = "Item name is required";
            }
            
            if ($quantity < 0) {
                $errors[] = "Quantity cannot be negative";
            }
            
            if ($unit_price < 0) {
                $errors[] = "Unit price cannot be negative";
            }
            
            if (empty($category)) {
                $errors[] = "Category is required";
            }
            
            if (empty($selected_merchant_id)) {
                $errors[] = "Merchant is required";
            }
            
            // Enforce merchant ownership validation
            if (hasRole(['Merchant'])) {
                try {
                    $pdo = getDBConnection();
                    $verifyStmt = $pdo->prepare("SELECT COUNT(*) FROM stock WHERE stock_id = ? AND merchant_id = ?");
                    $verifyStmt->execute([$stock_id, $merchant_id]);
                    $count = $verifyStmt->fetchColumn();
                    
                    if ($count === 0) {
                        $errors[] = "You do not have permission to edit this stock item";
                    }
                } catch (PDOException $e) {
                    $error_message = "Database error: " . $e->getMessage();
                }
            }
            
            if (empty($errors)) {
                try {
                    $pdo = getDBConnection();
                    
                    $stmt = $pdo->prepare("UPDATE stock SET merchant_id = ?, item_name = ?, description = ?, quantity_available = ?, unit_price = ?, category = ? WHERE stock_id = ?");
                    
                    $stmt->execute([
                        $selected_merchant_id,
                        $item_name,
                        $description,
                        $quantity,
                        $unit_price,
                        $category,
                        $stock_id
                    ]);
                    
                    $success_message = "Stock item updated successfully!";
                    logAccess($_SESSION['user_id'], 'Updated stock item ID: ' . $stock_id, true);
                    $refresh_needed = true;
                    
                } catch (PDOException $e) {
                    $error_message = "Database error: " . $e->getMessage();
                }
            } else {
                $error_message = "Please correct the following errors: " . implode(", ", $errors);
            }
        }
    }
}

// Process stock deletion requests
if ($action === 'delete' && $stock_id > 0) {
    if (!$can_manage_stock) {
        $error_message = "You don't have permission to delete stock items";
        logAccess($_SESSION['user_id'], 'Unauthorized attempt to delete stock item', false);
        $action = 'list';
    } else {
        enforcePermission('stock', 'delete');
        
        // Enforce merchant ownership validation
        if (hasRole(['Merchant'])) {
            try {
                $pdo = getDBConnection();
                $verifyStmt = $pdo->prepare("SELECT COUNT(*) FROM stock WHERE stock_id = ? AND merchant_id = ?");
                $verifyStmt->execute([$stock_id, $merchant_id]);
                $count = $verifyStmt->fetchColumn();
                
                if ($count === 0) {
                    $_SESSION['error_message'] = "You do not have permission to delete this stock item";
                    header("Location: stock.php");
                    exit();
                }
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
            }
        }
        
        try {
            $pdo = getDBConnection();
            
            // Prevent deletion of items referenced in purchases
            $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM purchases WHERE item_name = (SELECT item_name FROM stock WHERE stock_id = ?)");
            $checkStmt->execute([$stock_id]);
            $purchases = $checkStmt->fetchColumn();
            
            if ($purchases > 0) {
                $error_message = "Cannot delete stock item: It is associated with existing purchases";
            } else {
                $stmt = $pdo->prepare("DELETE FROM stock WHERE stock_id = ?");
                $stmt->execute([$stock_id]);
                
                if ($stmt->rowCount() > 0) {
                    $success_message = "Stock item deleted successfully";
                    logAccess($_SESSION['user_id'], 'Deleted stock item ID: ' . $stock_id, true);
                    $refresh_needed = true;
                } else {
                    $error_message = "Stock item not found";
                }
            }
        } catch (PDOException $e) {
            $error_message = "Database error: " . $e->getMessage();
        }
        
        $action = 'list';
    }
}

// Load merchant options for admin/official dropdowns
$merchants = [];
if (hasRole(['Admin', 'Official'])) {
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->query("SELECT merchant_id, merchant_name FROM merchants ORDER BY merchant_name");
        $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $error_message = "Error fetching merchants: " . $e->getMessage();
    }
}

// Load stock data for display and operations
if ($action === 'list' || $action === 'edit' || $action === 'view') {
    try {
        $pdo = getDBConnection();
        
        $stmt = $pdo->query("
            SELECT s.*, m.merchant_name 
            FROM stock s
            JOIN merchants m ON s.merchant_id = m.merchant_id
            ORDER BY s.category, s.item_name
        ");
        
        $stock_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Load specific item for edit/view operations
        if (($action === 'edit' || $action === 'view') && $stock_id > 0) {
            $itemStmt = $pdo->prepare("
                SELECT s.*, m.merchant_name 
                FROM stock s
                JOIN merchants m ON s.merchant_id = m.merchant_id
                WHERE s.stock_id = ?
            ");
            $itemStmt->execute([$stock_id]);
            $stock_item = $itemStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$stock_item) {
                $error_message = "Stock item not found";
                $action = 'list';
            } else if (hasRole(['Merchant']) && $stock_item['merchant_id'] != $merchant_id) {
                $_SESSION['error_message'] = "You do not have permission to access this stock item";
                header("Location: stock.php");
                exit();
            }
        }
    } catch (PDOException $e) {
        $error_message = "Database error: " . $e->getMessage();
    }
}

/**
 * Returns appropriate CSS class for category badges
 */
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

/**
 * Determines if user has permission to manage a specific stock item
 */
function canManageStockItem($item, $user_merchant_id, $is_admin, $is_official, $is_merchant) {
    if ($is_admin || $is_official) {
        return true;
    }
    
    if ($is_merchant && $item['merchant_id'] == $user_merchant_id) {
        return true;
    }
    
    return false;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stock Management - COVID Resilience System</title>
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
    </style>
</head>
<body>
    <!-- Top Navigation Bar -->
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
            <!-- Sidebar -->
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
                    
                    <!-- Users Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="users.php">
                            <i class="bi bi-people me-2"></i>Users
                        </a>
                    </li>
                    
                    <!-- Doctors Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="doctors.php">
                            <i class="bi bi-hospital me-2"></i>Doctors
                        </a>
                    </li>
                    
                    <!-- Officials Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="government_officials.php">
                            <i class="bi bi-building me-2"></i>Officials
                        </a>
                    </li>
                    
                    <!-- Merchants Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="merchants.php">
                            <i class="bi bi-shop me-2"></i>Merchants
                        </a>
                    </li>
                    
                    <!-- Vaccinations Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="vaccination_records.php">
                            <i class="bi bi-clipboard2-pulse me-2"></i>Vaccinations
                        </a>
                    </li>
                    
                    <!-- Purchases Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="purchases.php">
                            <i class="bi bi-cart me-2"></i>Purchases
                        </a>
                    </li>
                    
                    <!-- Stock Menu - Active -->
                    <li class="nav-item">
                        <a class="nav-link active" href="stock.php">
                            <i class="bi bi-box-seam me-2"></i>Stock
                        </a>
                    </li>
                    
                    <!-- Visualizations Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="visualization_dashboard.php">
                            <i class="bi bi-bar-chart-fill me-2"></i>Visualizations
                        </a>
                    </li>
                    
                    <!-- Access Logs Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="access_logs.php">
                            <i class="bi bi-file-earmark-text me-2"></i>Access Logs
                        </a>
                    </li>
                    
                    <!-- Documents Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="document_upload.php">
                            <i class="bi bi-file-earmark-arrow-up me-2"></i>Documents
                        </a>
                    </li>
                    
                    <!-- Critical Items Menu -->
                    <li class="nav-item">
                        <a class="nav-link" href="critical_items.php">
                            <i class="bi bi-shield-plus me-2"></i>Critical Items
                        </a>
                    </li>
                    
                    <!-- User Profile Menu -->
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
            
            <!-- Main Content -->
            <div class="col-md-10 p-4">
                <?php if ($action === 'list'): ?>
                <!-- List View -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>
                        <i class="bi bi-box-seam me-2"></i>
                        <?php echo hasRole(['Merchant']) ? 'Stock Management' : 'Stock Management'; ?>
                    </h2>
                    <?php if ($can_manage_stock): ?>
                    <div>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addStockModal">
                            <i class="bi bi-plus-circle me-2"></i>Add New Item
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
                            <h5 class="mb-1">View-Only Access</h5>
                            <p class="mb-0">As a Citizen, you have read-only access to stock items. Only Officials, Merchants, and Administrators can manage inventory.</p>
                        </div>
                    </div>
                </div>
                <?php elseif ($is_merchant): ?>
                <div class="read-only-notice mb-4" style="border-left-color: #6f42c1;">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill me-2 fs-4" style="color: #6f42c1;"></i>
                        <div>
                            <h5 class="mb-1">Merchant Stock Management</h5>
                            <p class="mb-0">You can manage your own stock items and suggest them as critical items. Use the action buttons to view, edit, delete, or suggest your items as critical.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search items..." oninput="filterTable()">
                        </div>
                        
                        <div class="mb-3 text-end">
                            <div class="btn-group" role="group">
                                <button type="button" class="btn btn-outline-secondary" onclick="filterItems('all')">All</button>
                                <button type="button" class="btn btn-outline-info" onclick="filterItems('Medical')">Medical</button>
                                <button type="button" class="btn btn-outline-warning" onclick="filterItems('Grocery')">Grocery</button>
                                <button type="button" class="btn btn-outline-success" onclick="filterItems('Essential')">Essential</button>
                                <button type="button" class="btn btn-outline-secondary" onclick="filterItems('Other')">Other</button>
                            </div>
                        </div>
                        
                        <div class="table-responsive">
                            <table id="stockTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">Item Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Category <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Quantity <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">Unit Price <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if (!hasRole(['Merchant'])): ?>
                                        <th onclick="sortTable(5)">Merchant <i class="bi bi-arrow-down-up"></i></th>
                                        <?php endif; ?>
                                        <?php if (!$is_citizen): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($stock_items)): ?>
                                    <tr><td colspan="<?php echo !$is_citizen ? (hasRole(['Merchant']) ? '6' : '7') : (hasRole(['Merchant']) ? '5' : '6'); ?>" class="text-center">No stock items found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($stock_items as $item): ?>
                                    <tr data-category="<?php echo htmlspecialchars($item['category']); ?>">
                                        <td><?php echo htmlspecialchars($item['stock_id']); ?></td>
                                        <td><?php echo htmlspecialchars($item['item_name']); ?></td>
                                        <td>
                                            <span class="badge <?php echo getCategoryBadgeClass($item['category']); ?>">
                                                <?php echo htmlspecialchars($item['category']); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($item['quantity_available']); ?></td>
                                        <td>$<?php echo number_format((float)$item['unit_price'], 2); ?></td>
                                        <?php if (!hasRole(['Merchant'])): ?>
                                        <td><?php echo htmlspecialchars($item['merchant_name']); ?></td>
                                        <?php endif; ?>
                                        <?php if (!$is_citizen): ?>
                                        <td>
                                            <?php if (canManageStockItem($item, $merchant_id, $is_admin, $is_official, $is_merchant)): ?>
                                                <button class="btn btn-sm btn-info" onclick="viewStock(<?php echo $item['stock_id']; ?>)" title="View Item">
                                                    <i class="bi bi-eye"></i>
                                                </button>
                                                <button class="btn btn-sm btn-primary" onclick="editStock(<?php echo $item['stock_id']; ?>)" title="Edit Item">
                                                    <i class="bi bi-pencil"></i>
                                                </button>
                                                <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $item['stock_id']; ?>, '<?php echo htmlspecialchars(addslashes($item['item_name'])); ?>')" title="Delete Item">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                                <?php if ($is_merchant): ?>
                                                <button class="btn btn-sm btn-success suggest-critical" 
                                                        data-bs-toggle="modal" 
                                                        data-bs-target="#suggestCriticalModal"
                                                        data-stock-id="<?php echo $item['stock_id']; ?>"
                                                        data-item-name="<?php echo htmlspecialchars($item['item_name']); ?>"
                                                        title="Suggest as Critical Item">
                                                    <i class="bi bi-shield-plus"></i>
                                                </button>
                                                <?php endif; ?>
                                            <?php else: ?>
                                                <button class="btn btn-sm btn-secondary" onclick="showPermissionMessage()" title="View Only">
                                                    <i class="bi bi-eye-slash"></i>
                                                </button>
                                            <?php endif; ?>
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
                                Total: <span id="totalItems"><?php echo count($stock_items); ?></span> item<?php echo count($stock_items) != 1 ? 's' : ''; ?>
                            </div>
                            <div>
                                <button type="button" class="btn btn-secondary" onclick="window.location.reload();">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'view' && isset($stock_item)): ?>
                <!-- View Stock Item -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-box-seam me-2"></i>View Stock Item</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="stock.php">Stock</a></li>
                                <li class="breadcrumb-item active">View Item</li>
                            </ol>
                        </nav>
                    </div>
                    <div>
                        <?php if (canManageStockItem($stock_item, $merchant_id, $is_admin, $is_official, $is_merchant)): ?>
                        <a href="stock.php?action=edit&id=<?php echo $stock_item['stock_id']; ?>" class="btn btn-primary">
                            <i class="bi bi-pencil me-2"></i>Edit Item
                        </a>
                        <?php endif; ?>
                        <a href="stock.php" class="btn btn-secondary ms-2">
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
                
                <?php if (!canManageStockItem($stock_item, $merchant_id, $is_admin, $is_official, $is_merchant)): ?>
                <div class="read-only-notice mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill text-primary me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">View-Only Access</h5>
                            <p class="mb-0">You have read-only access to this stock item. You cannot edit or delete this inventory item.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">
                            <i class="bi bi-box-seam me-2"></i><?php echo htmlspecialchars($stock_item['item_name']); ?>
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6 class="text-muted">Item Details</h6>
                                <hr>
                                <dl class="row">
                                    <dt class="col-sm-4">Item ID:</dt>
                                    <dd class="col-sm-8"><?php echo htmlspecialchars($stock_item['stock_id']); ?></dd>
                                    
                                    <dt class="col-sm-4">Name:</dt>
                                    <dd class="col-sm-8"><?php echo htmlspecialchars($stock_item['item_name']); ?></dd>
                                    
                                    <dt class="col-sm-4">Category:</dt>
                                    <dd class="col-sm-8">
                                        <span class="badge <?php echo getCategoryBadgeClass($stock_item['category']); ?>">
                                            <?php echo htmlspecialchars($stock_item['category']); ?>
                                        </span>
                                    </dd>
                                    
                                    <dt class="col-sm-4">Description:</dt>
                                    <dd class="col-sm-8">
                                        <?php echo !empty($stock_item['description']) ? nl2br(htmlspecialchars($stock_item['description'])) : '<em>No description provided</em>'; ?>
                                    </dd>
                                </dl>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-muted">Inventory Details</h6>
                                <hr>
                                <dl class="row">
                                    <dt class="col-sm-4">Quantity:</dt>
                                    <dd class="col-sm-8">
                                        <span class="fw-bold"><?php echo htmlspecialchars($stock_item['quantity_available']); ?></span> units
                                    </dd>
                                    
                                    <dt class="col-sm-4">Unit Price:</dt>
                                    <dd class="col-sm-8">
                                        $<?php echo number_format((float)$stock_item['unit_price'], 2); ?>
                                    </dd>
                                    
                                    <dt class="col-sm-4">Total Value:</dt>
                                    <dd class="col-sm-8">
                                        $<?php echo number_format((float)$stock_item['unit_price'] * (int)$stock_item['quantity_available'], 2); ?>
                                    </dd>
                                    
                                    <dt class="col-sm-4">Merchant:</dt>
                                    <dd class="col-sm-8">
                                        <?php echo htmlspecialchars($stock_item['merchant_name']); ?>
                                    </dd>
                                    
                                    <dt class="col-sm-4">Last Updated:</dt>
                                    <dd class="col-sm-8">
                                        <?php echo date('M j, Y, g:i a', strtotime($stock_item['updated_at'])); ?>
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    <div class="card-footer">
                        <div class="d-flex justify-content-between">
                            <a href="stock.php" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left me-2"></i>Back to List
                            </a>
                            <?php if (canManageStockItem($stock_item, $merchant_id, $is_admin, $is_official, $is_merchant)): ?>
                            <div>
                                <a href="stock.php?action=edit&id=<?php echo $stock_item['stock_id']; ?>" class="btn btn-outline-primary">
                                    <i class="bi bi-pencil me-2"></i>Edit Item
                                </a>
                                <button class="btn btn-outline-danger ms-2" onclick="confirmDelete(<?php echo $stock_item['stock_id']; ?>, '<?php echo htmlspecialchars(addslashes($stock_item['item_name'])); ?>')">
                                    <i class="bi bi-trash me-2"></i>Delete Item
                                </button>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'edit' && isset($stock_item)): ?>
                <!-- Edit Stock Item -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-pencil me-2"></i>Edit Stock Item</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="stock.php">Stock</a></li>
                                <li class="breadcrumb-item active">Edit Item</li>
                            </ol>
                        </nav>
                    </div>
                    <a href="stock.php" class="btn btn-secondary">
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
                <div class="alert alert-danger alert-dismissible fade show" role="role">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">
                            <i class="bi bi-pencil-square me-2"></i>Edit Stock Item
                        </h5>
                    </div>
                    <div class="card-body">
                        <form action="stock.php" method="POST">
                            <input type="hidden" name="action" value="edit_stock">
                            <input type="hidden" name="stock_id" value="<?php echo $stock_item['stock_id']; ?>">
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="item_name" class="form-label">Item Name</label>
                                        <input type="text" class="form-control" id="item_name" name="item_name" value="<?php echo htmlspecialchars($stock_item['item_name']); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="category" class="form-label">Category</label>
                                        <select class="form-select" id="category" name="category" required>
                                            <option value="">Select Category</option>
                                            <option value="Medical" <?php echo $stock_item['category'] === 'Medical' ? 'selected' : ''; ?>>Medical</option>
                                            <option value="Grocery" <?php echo $stock_item['category'] === 'Grocery' ? 'selected' : ''; ?>>Grocery</option>
                                            <option value="Essential" <?php echo $stock_item['category'] === 'Essential' ? 'selected' : ''; ?>>Essential</option>
                                            <option value="Other" <?php echo $stock_item['category'] === 'Other' ? 'selected' : ''; ?>>Other</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="description" class="form-label">Description</label>
                                        <textarea class="form-control" id="description" name="description" rows="4"><?php echo htmlspecialchars($stock_item['description'] ?? ''); ?></textarea>
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label for="quantity" class="form-label">Quantity</label>
                                        <input type="number" class="form-control" id="quantity" name="quantity" value="<?php echo htmlspecialchars($stock_item['quantity_available']); ?>" min="0" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="unit_price" class="form-label">Unit Price</label>
                                        <div class="input-group">
                                            <span class="input-group-text">$</span>
                                            <input type="number" class="form-control" id="unit_price" name="unit_price" value="<?php echo number_format((float)$stock_item['unit_price'], 2, '.', ''); ?>" min="0" step="0.01" required>
                                        </div>
                                    </div>
                                    
                                    <?php if (!hasRole(['Merchant']) && !empty($merchants)): ?>
                                    <div class="mb-3">
                                        <label for="merchant_id" class="form-label">Merchant</label>
                                        <select class="form-select" id="merchant_id" name="merchant_id" required>
                                            <option value="">Select Merchant</option>
                                            <?php foreach ($merchants as $merchant): ?>
                                            <option value="<?php echo $merchant['merchant_id']; ?>" <?php echo $stock_item['merchant_id'] == $merchant['merchant_id'] ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($merchant['merchant_name']); ?>
                                            </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <a href="stock.php" class="btn btn-outline-secondary me-md-2">Cancel</a>
                                <button type="submit" class="btn btn-primary">Save Changes</button>
                            </div>
                        </form>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Add Stock Modal -->
    <?php if ($can_manage_stock): ?>
    <div class="modal fade" id="addStockModal" tabindex="-1" aria-labelledby="addStockModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addStockModalLabel">
                        <i class="bi bi-plus-circle me-2"></i>Add New Stock Item
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="stock.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="add_stock">
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="item_name" class="form-label">Item Name</label>
                                    <input type="text" class="form-control" id="item_name" name="item_name" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="category" class="form-label">Category</label>
                                    <select class="form-select" id="category" name="category" required>
                                        <option value="">Select Category</option>
                                        <option value="Medical">Medical</option>
                                        <option value="Grocery">Grocery</option>
                                        <option value="Essential">Essential</option>
                                        <option value="Other">Other</option>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="description" class="form-label">Description</label>
                                    <textarea class="form-control" id="description" name="description" rows="4"></textarea>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="quantity" class="form-label">Quantity</label>
                                    <input type="number" class="form-control" id="quantity" name="quantity" value="0" min="0" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="unit_price" class="form-label">Unit Price</label>
                                    <div class="input-group">
                                        <span class="input-group-text">$</span>
                                        <input type="number" class="form-control" id="unit_price" name="unit_price" value="0.00" min="0" step="0.01" required>
                                    </div>
                                </div>
                                
                                <?php if (!hasRole(['Merchant']) && !empty($merchants)): ?>
                                <div class="mb-3">
                                    <label for="merchant_id" class="form-label">Merchant</label>
                                    <select class="form-select" id="merchant_id" name="merchant_id" required>
                                        <option value="">Select Merchant</option>
                                        <?php foreach ($merchants as $merchant): ?>
                                        <option value="<?php echo $merchant['merchant_id']; ?>">
                                            <?php echo htmlspecialchars($merchant['merchant_name']); ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Item</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Suggest Critical Item Modal -->
    <?php if (hasRole(['Merchant'])): ?>
    <div class="modal fade" id="suggestCriticalModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-shield-plus me-2"></i>Suggest Critical Item
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="critical_items.php" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="suggest_item">
                        <input type="hidden" name="stock_id" id="critical_stock_id">
                        
                        <div class="mb-3">
                            <p>You are suggesting the following item as critical for COVID resilience:</p>
                            <h5 id="critical_item_name" class="text-primary"></h5>
                        </div>
                        
                        <div class="mb-3">
                            <label for="critical_description" class="form-label">Why is this item critical?</label>
                            <textarea class="form-control" id="critical_description" name="description" rows="4" 
                                placeholder="Explain why this item should be designated as critical..."></textarea>
                            <small class="text-muted">Please provide details on why this item is essential for COVID resilience.</small>
                        </div>
                        
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            <small>Your suggestion will be reviewed by government officials who will determine whether to approve it as a critical item.</small>
                        </div>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
    // Table filtering and search functionality
    const allRows = Array.from(document.querySelectorAll('#stockTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        allRows.forEach(row => {
            const itemName = row.cells[1]?.textContent.toLowerCase() || '';
            const category = row.cells[2]?.textContent.toLowerCase() || '';
            const id = row.cells[0]?.textContent || '';
            
            if (itemName.includes(filter) || category.includes(filter) || id.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updateFilterCount();
    }
    
    function updateFilterCount() {
        const visibleRows = allRows.filter(row => row.style.display !== 'none').length;
        document.getElementById('totalItems').textContent = visibleRows;
    }
    
    function filterItems(category) {
        allRows.forEach(row => {
            const itemCategory = row.dataset.category || '';
            
            if (category === 'all') {
                row.style.display = '';
            } else if (itemCategory === category) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updateFilterCount();
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('stockTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            const aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            const bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Numeric sorting for ID and quantity columns
            if (colIndex === 0 || colIndex === 3) {
                return parseInt(aValue) - parseInt(bValue);
            }
            
            // Price column sorting with currency symbol handling
            if (colIndex === 4) {
                return parseFloat(aValue.replace('$', '')) - parseFloat(bValue.replace('$', ''));
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
    
    // Stock management navigation functions
    function viewStock(id) {
        window.location.href = `stock.php?action=view&id=${id}`;
    }
    
    function editStock(id) {
        window.location.href = `stock.php?action=edit&id=${id}`;
    }
    
    function confirmDelete(id, name) {
        if (confirm(`Are you sure you want to delete the stock item "${name}"?`)) {
            window.location.href = `stock.php?action=delete&id=${id}`;
        }
    }
    
    function showPermissionMessage() {
        <?php if ($is_merchant): ?>
        alert("You can only manage your own stock items. This item belongs to another merchant.");
        <?php else: ?>
        alert("You don't have permission to manage this stock item.");
        <?php endif; ?>
    }
    
    document.addEventListener('DOMContentLoaded', function() {
        // Critical item suggestion modal event binding
        const suggestCriticalModal = document.getElementById('suggestCriticalModal');
        if (suggestCriticalModal) {
            suggestCriticalModal.addEventListener('show.bs.modal', function (event) {
                const button = event.relatedTarget;
                const stockId = button.getAttribute('data-stock-id');
                const itemName = button.getAttribute('data-item-name');
                
                document.getElementById('critical_stock_id').value = stockId;
                document.getElementById('critical_item_name').textContent = itemName;
            });
        }
        
        // Auto-close modal after successful operations
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
    </script>
</body>
</html>