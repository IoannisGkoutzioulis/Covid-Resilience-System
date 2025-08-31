<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

$error_message = $success_message = '';
$section = isset($_GET['section']) ? $_GET['section'] : '';

try {
    $pdo = getDBConnection();
    
    // System-wide statistics
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $total_users = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM doctors");
    $total_doctors = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM vaccination_records");
    $total_vaccinations = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM merchants");
    $total_merchants = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM purchases");
    $total_purchases = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM government_officials");
    $total_officials = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare(
        "SELECT a.*, u.full_name, u.username
         FROM access_logs a 
         LEFT JOIN users u ON a.user_id = u.user_id 
         ORDER BY a.timestamp DESC LIMIT 10"
    );
    $stmt->execute();
    $recent_logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Low stock alert system
    $stmt = $pdo->prepare(
        "SELECT s.*, m.merchant_name 
         FROM stock s 
         JOIN merchants m ON s.merchant_id = m.merchant_id 
         WHERE s.quantity_available <= 20 
         ORDER BY s.quantity_available ASC 
         LIMIT 5"
    );
    $stmt->execute();
    $low_stock_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->prepare(
        "SELECT v.*, u.full_name 
         FROM vaccination_records v 
         JOIN users u ON v.user_id = u.user_id 
         ORDER BY v.date_administered DESC 
         LIMIT 5"
    );
    $stmt->execute();
    $recent_vaccinations = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->prepare(
        "SELECT p.*, u.full_name, m.merchant_name 
         FROM purchases p 
         JOIN users u ON p.user_id = u.user_id 
         JOIN merchants m ON p.merchant_id = m.merchant_id 
         ORDER BY p.purchase_date DESC 
         LIMIT 5"
    );
    $stmt->execute();
    $recent_purchases = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Approval workflow counts for role-based notifications
    $pending_merchants_count = 0;
    if (hasRole(['Admin', 'Official'])) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE status = 'Pending'");
        $stmt->execute();
        $pending_merchants_count = $stmt->fetchColumn();
    }
    
    $pending_officials_count = 0;
    if (hasRole('Admin')) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM government_officials WHERE status = 'Pending'");
        $stmt->execute();
        $pending_officials_count = $stmt->fetchColumn();
    }
    
    // Smart notification system based on role and pending items
    $notifications = [];
    
    if (count($low_stock_items) > 0) {
        $notifications[] = [
            'type' => 'warning',
            'icon' => 'exclamation-triangle',
            'message' => 'There are ' . count($low_stock_items) . ' items with low stock.',
            'link' => 'stock.php'
        ];
    }
    
    if ($pending_merchants_count > 0 && hasRole(['Admin', 'Official'])) {
        $notifications[] = [
            'type' => 'info',
            'icon' => 'shop',
            'message' => 'There are ' . $pending_merchants_count . ' merchants awaiting approval.',
            'link' => 'merchant_approval.php'
        ];
    }
    
    if ($pending_officials_count > 0 && hasRole('Admin')) {
        $notifications[] = [
            'type' => 'warning',
            'icon' => 'building',
            'message' => 'There are ' . $pending_officials_count . ' officials awaiting approval.',
            'link' => 'official_approval.php'
        ];
    }
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM documents WHERE is_verified = 0");
    $stmt->execute();
    $unverified_docs = $stmt->fetchColumn();
    
    if ($unverified_docs > 0 && hasRole(['Admin', 'Official'])) {
        $notifications[] = [
            'type' => 'info',
            'icon' => 'file-earmark',
            'message' => 'There are ' . $unverified_docs . ' documents awaiting verification.',
            'link' => 'document_upload.php?verified=0'
        ];
    }
    
} catch (PDOException $e) {
    $error_message = "Error fetching dashboard data: " . $e->getMessage();
}

$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_citizen = ($_SESSION['role'] === 'Citizen');
$is_admin_or_official = ($is_admin || $is_official);

// Auto-scroll to role-specific section
$scroll_to_section = '';
if ($section == 'admin' && $is_admin) {
    $scroll_to_section = 'adminDashboard';
} else if ($section == 'official' && $is_official) {
    $scroll_to_section = 'officialDashboard';
} else if ($section == 'merchant' && $is_merchant) {
    $scroll_to_section = 'merchantDashboard';
} else if ($section == 'citizen' && $is_citizen) {
    $scroll_to_section = 'citizenDashboard';
}

// Merchant-specific analytics and inventory data
$merchant_data = null;

if ($is_merchant) {
    try {
        $merchant_id = 0;
        $stmt = $pdo->prepare("SELECT merchant_id FROM merchants WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $merchant = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($merchant) {
            $merchant_id = $merchant['merchant_id'];
            
            // Inventory breakdown by category
            $stockStmt = $pdo->prepare("SELECT COUNT(*) as total, 
                SUM(CASE WHEN category = 'Medical' THEN 1 ELSE 0 END) as medical,
                SUM(CASE WHEN category = 'Grocery' THEN 1 ELSE 0 END) as grocery
                FROM stock WHERE merchant_id = ?");
            $stockStmt->execute([$merchant_id]);
            $stockCount = $stockStmt->fetch(PDO::FETCH_ASSOC);
            
            // Critical items suggestion tracking
            $criticalStmt = $pdo->prepare("SELECT COUNT(*) as total,
                SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) as rejected
                FROM critical_items WHERE merchant_id = ?");
            $criticalStmt->execute([$merchant_id]);
            $criticalCount = $criticalStmt->fetch(PDO::FETCH_ASSOC);
            
            $purchaseStmt = $pdo->prepare("SELECT COUNT(*) as total FROM purchases 
                WHERE merchant_id = ? AND purchase_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
            $purchaseStmt->execute([$merchant_id]);
            $recentPurchases = $purchaseStmt->fetch(PDO::FETCH_ASSOC);
            
            $merchant_data = [
                'merchant_id' => $merchant_id,
                'stockCount' => $stockCount,
                'criticalCount' => $criticalCount,
                'recentPurchases' => $recentPurchases
            ];
        }
    } catch (PDOException $e) {
        $error_message = "Error fetching merchant data: " . $e->getMessage();
    }
}

// Citizen-specific personal data
if ($is_citizen) {
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM vaccination_records WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user_vaccination_count = $stmt->fetchColumn();
        
        $stmt = $pdo->prepare(
            "SELECT p.*, m.merchant_name 
             FROM purchases p 
             JOIN merchants m ON p.merchant_id = m.merchant_id 
             WHERE p.user_id = ? 
             ORDER BY p.purchase_date DESC 
             LIMIT 5"
        );
        $stmt->execute([$_SESSION['user_id']]);
        $user_purchases = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $stmt = $pdo->prepare(
            "SELECT * FROM documents 
             WHERE user_id = ? 
             ORDER BY upload_date DESC 
             LIMIT 5"
        );
        $stmt->execute([$_SESSION['user_id']]);
        $user_documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        $error_message = "Error fetching user data: " . $e->getMessage();
    }
}

// Official workload tracking
if ($is_official) {
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM documents WHERE is_verified = 0");
        $stmt->execute();
        $pending_verifications = $stmt->fetchColumn();
        
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM critical_items WHERE status = 'Pending'");
        $stmt->execute();
        $pending_critical_items = $stmt->fetchColumn();
        
    } catch (PDOException $e) {
        $error_message = "Error fetching official data: " . $e->getMessage();
    }
}

// Admin system health monitoring
if ($is_admin) {
    try {
        $stmt = $pdo->query("SELECT COUNT(*) FROM access_logs WHERE success = 0");
        $failed_logins = $stmt->fetchColumn();
        
    } catch (PDOException $e) {
        $error_message = "Error fetching admin data: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #343a40;
        }
        
        .top-bar {
            background: #1a73e8;
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
        
        .card-header-minimal {
            background-color: transparent;
            border-bottom: 1px solid rgba(0,0,0,0.05);
            padding: 15px 20px;
            font-weight: 500;
        }
        
        .welcome-banner {
            background: linear-gradient(to right, #1a73e8, #34a8eb);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .status-card {
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            color: white;
            position: relative;
        }
        
        .status-card h5 {
            font-size: 1.1rem;
            margin-bottom: 15px;
        }
        
        .status-card p {
            margin-bottom: 0;
            opacity: 0.9;
        }
        
        .status-icon {
            font-size: 2.5rem;
            opacity: 0.2;
            position: absolute;
            top: 10px;
            right: 15px;
        }
        
        .stats-tab {
            border-radius: 8px;
            border: none;
            padding: 15px 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
            color: white;
        }
        
        .stats-tab:hover {
            transform: translateY(-5px);
        }
        
        .stats-tab-icon {
            font-size: 2.5rem;
            position: absolute;
            bottom: -10px;
            right: 10px;
            opacity: 0.2;
        }
        
        .stats-tab-value {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 5px;
        }
        
        .stats-tab-label {
            font-size: 1rem;
            opacity: 0.9;
        }
        
        .tab-users {
            background: linear-gradient(45deg, #3a7bd5, #00d2ff);
        }
        
        .tab-doctors {
            background: linear-gradient(45deg, #11998e, #38ef7d);
        }
        
        .tab-officials {
            background: linear-gradient(45deg, #fc4a1a, #f7b733);
        }
        
        .tab-merchants {
            background: linear-gradient(45deg, #6a3093, #a044ff);
        }
        
        .tab-vaccinations {
            background: linear-gradient(45deg, #396afc, #2948ff);
        }
        
        .tab-purchases {
            background: linear-gradient(45deg, #f857a6, #ff5858);
        }
        
        .official-card {
            background: linear-gradient(45deg, #3a6186, #89253e);
        }
        
        .admin-card {
            background: linear-gradient(45deg, #0F2027, #2C5364);
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
        
        .merchant-approval-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        
        .merchant-approval-section h4 {
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .merchant-approval-section .btn {
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .merchant-approval-section .btn:hover {
            background: rgba(255,255,255,0.3);
            border-color: rgba(255,255,255,0.5);
            color: white;
            transform: translateY(-2px);
        }
        
        .pending-count {
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            margin-left: 10px;
        }
        
        .official-approval-section {
            background: linear-gradient(135deg, #ff7b7b 0%, #d63384 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
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
                        <a class="nav-link active" href="dashboard.php">
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
                <?php if (!empty($error_message)): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <?php if (!empty($success_message)): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="bi bi-check-circle-fill me-2"></i><?php echo htmlspecialchars($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <div class="welcome-banner">
                    <div class="row align-items-center">
                        <div class="col">
                            <h4 class="mb-1">Welcome back, <?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?>!</h4>
                            <p class="mb-0 opacity-75">Here's an overview of your COVID Resilience System</p>
                        </div>
                        <div class="col-auto">
                            <div class="bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                                <i class="bi bi-calendar3 me-2"></i>
                                <?php echo date('F j, Y'); ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Admin-only approval section -->
                <?php if ($is_admin && $pending_officials_count > 0): ?>
                <div class="official-approval-section">
                    <div class="row align-items-center">
                        <div class="col">
                            <h4 class="mb-2">
                                <i class="bi bi-building me-2"></i>Official Approval Management
                                <span class="pending-count">
                                    <i class="bi bi-exclamation-circle me-1"></i>
                                    <?php echo $pending_officials_count; ?> Pending
                                </span>
                            </h4>
                            <p class="mb-0 opacity-90">
                                Review and approve government official account applications to ensure proper authorization.
                                All approvals and rejections must be handled through the dedicated approval page.
                            </p>
                        </div>
                        <div class="col-auto">
                            <a href="official_approval.php" class="btn btn-lg">
                                <i class="bi bi-eye me-2"></i>
                                Review All Officials
                                <span class="badge bg-warning text-dark ms-2"><?php echo $pending_officials_count; ?></span>
                            </a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Official-only merchant approval section -->
                <?php if ($is_official && $pending_merchants_count > 0): ?>
                <div class="merchant-approval-section">
                    <div class="row align-items-center">
                        <div class="col">
                            <h4 class="mb-2">
                                <i class="bi bi-shop-window me-2"></i>Merchant Approval Management
                                <span class="pending-count">
                                    <i class="bi bi-exclamation-circle me-1"></i>
                                    <?php echo $pending_merchants_count; ?> Pending
                                </span>
                            </h4>
                            <p class="mb-0 opacity-90">
                                Review and approve merchant account applications to ensure business compliance and system integrity.
                            </p>
                        </div>
                        <div class="col-auto">
                            <a href="merchant_approval.php" class="btn d-flex align-items-center">
                                <i class="bi bi-eye me-2"></i>
                                Review Applications
                                <span class="badge bg-warning text-dark ms-2"><?php echo $pending_merchants_count; ?></span>
                            </a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- System-wide statistics -->
                <div class="row g-3 mb-4">
                    <div class="col-md-3">
                        <div class="card stats-tab tab-users">
                            <div class="stats-tab-icon">
                                <i class="bi bi-people-fill"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_users); ?></div>
                            <div class="stats-tab-label">Registered Users</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-doctors">
                            <div class="stats-tab-icon">
                                <i class="bi bi-hospital-fill"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_doctors); ?></div>
                            <div class="stats-tab-label">Doctors</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-officials">
                            <div class="stats-tab-icon">
                                <i class="bi bi-building-fill"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_officials); ?></div>
                            <div class="stats-tab-label">Officials</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-merchants">
                            <div class="stats-tab-icon">
                                <i class="bi bi-shop"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_merchants); ?></div>
                            <div class="stats-tab-label">Merchants</div>
                        </div>
                    </div>
                </div>

                <!-- Intelligent notification system -->
                <?php if (!empty($notifications)): ?>
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header-minimal">
                                <i class="bi bi-bell me-2"></i>System Notifications
                            </div>
                            <div class="card-body">
                                <?php foreach ($notifications as $notification): ?>
                                <div class="alert alert-<?php echo htmlspecialchars($notification['type']); ?> d-flex align-items-center" role="alert">
                                    <i class="bi bi-<?php echo htmlspecialchars($notification['icon']); ?> me-2"></i>
                                    <div class="flex-grow-1">
                                        <?php echo htmlspecialchars($notification['message']); ?>
                                    </div>
                                    <a href="<?php echo htmlspecialchars($notification['link']); ?>" class="btn btn-sm btn-outline-<?php echo htmlspecialchars($notification['type']); ?>">
                                        View
                                    </a>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if ($is_merchant && $merchant_data): ?>
                <!-- Merchant analytics dashboard -->
                <div id="merchantDashboard" class="row">
                    <div class="col-md-12 mb-4">
                        <h2><i class="bi bi-speedometer2 me-2"></i>Merchant Dashboard</h2>
                        <p>Welcome to your merchant control panel. Manage your inventory and contribute to the COVID resilience program.</p>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body">
                                <h5 class="card-title">Inventory Items</h5>
                                <h2><?php echo $merchant_data['stockCount']['total'] ?? 0; ?></h2>
                                <p class="mb-0">Total items in stock</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-success text-white">
                            <div class="card-body">
                                <h5 class="card-title">Critical Items</h5>
                                <h2><?php echo $merchant_data['criticalCount']['approved'] ?? 0; ?></h2>
                                <p class="mb-0">Approved critical supplies</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-info text-white">
                            <div class="card-body">
                                <h5 class="card-title">Medical Items</h5>
                                <h2><?php echo $merchant_data['stockCount']['medical'] ?? 0; ?></h2>
                                <p class="mb-0">Medical supplies</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark">
                            <div class="card-body">
                                <h5 class="card-title">Grocery Items</h5>
                                <h2><?php echo $merchant_data['stockCount']['grocery'] ?? 0; ?></h2>
                                <p class="mb-0">Food & essential supplies</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header bg-dark text-white">
                                <h5 class="mb-0"><i class="bi bi-lightning-fill me-2"></i>Quick Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <a href="stock.php" class="btn btn-primary w-100">
                                            <i class="bi bi-box-seam me-2"></i>Manage Inventory
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="stock.php?action=add" class="btn btn-success w-100">
                                            <i class="bi bi-plus-circle me-2"></i>Add New Item
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="critical_items.php" class="btn btn-info w-100">
                                            <i class="bi bi-shield-plus me-2"></i>Suggest Critical Item
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($is_merchant && !$merchant_data): ?>
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    Your merchant profile is not set up. Please contact an administrator.
                </div>
                
                <?php elseif ($is_official): ?>
                <!-- Official workflow management dashboard -->
                
                <div id="officialDashboard" class="row mb-4">
                    <div class="col-md-12">
                        <h4>Government Official Dashboard</h4>
                        <p>Welcome to your control panel. Here you can monitor system activity, approve critical items, verify documents, and approve merchant accounts.</p>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card stats-tab tab-vaccinations">
                            <div class="stats-tab-icon">
                                <i class="bi bi-clipboard2-pulse"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_vaccinations); ?></div>
                            <div class="stats-tab-label">Total Vaccinations</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab official-card">
                            <div class="stats-tab-icon">
                                <i class="bi bi-file-earmark-check"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($pending_verifications ?? 0); ?></div>
                            <div class="stats-tab-label">Pending Verifications</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-purchases">
                            <div class="stats-tab-icon">
                                <i class="bi bi-shield-plus"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($pending_critical_items ?? 0); ?></div>
                            <div class="stats-tab-label">Pending Critical Items</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-merchants">
                            <div class="stats-tab-icon">
                                <i class="bi bi-shop"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo $pending_merchants_count; ?></div>
                            <div class="stats-tab-label">Pending Merchants</div>
                        </div>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header bg-dark text-white">
                                <h5 class="mb-0"><i class="bi bi-lightning-fill me-2"></i>Quick Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-3 mb-3">
                                        <a href="document_upload.php?verify=pending" class="btn btn-primary w-100">
                                            <i class="bi bi-file-earmark-check me-2"></i>Verify Documents
                                        </a>
                                    </div>
                                    <div class="col-md-3 mb-3">
                                        <a href="critical_items.php?status=pending" class="btn btn-success w-100">
                                            <i class="bi bi-shield-plus me-2"></i>Review Critical Items
                                        </a>
                                    </div>
                                    <div class="col-md-3 mb-3">
                                        <a href="merchant_approval.php" class="btn btn-warning w-100">
                                            <i class="bi bi-shop me-2"></i>Approve Merchants
                                            <?php if ($pending_merchants_count > 0): ?>
                                            <span class="badge bg-light text-dark ms-2"><?php echo $pending_merchants_count; ?></span>
                                            <?php endif; ?>
                                        </a>
                                    </div>
                                    <div class="col-md-3 mb-3">
                                        <a href="visualization_dashboard.php" class="btn btn-info w-100">
                                            <i class="bi bi-bar-chart-fill me-2"></i>COVID Statistics
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($is_admin): ?>
                <!-- Admin system oversight dashboard -->
                
                <div id="adminDashboard" class="row mb-4">
                    <div class="col-md-12">
                        <h4>Administrator Dashboard</h4>
                        <p>Welcome to the administrator dashboard. Here you can monitor system activity and manage all system resources.</p>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card stats-tab tab-vaccinations">
                            <div class="stats-tab-icon">
                                <i class="bi bi-clipboard2-pulse"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_vaccinations); ?></div>
                            <div class="stats-tab-label">Vaccinations</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-purchases">
                            <div class="stats-tab-icon">
                                <i class="bi bi-cart"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($total_purchases); ?></div>
                            <div class="stats-tab-label">Purchases</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab admin-card">
                            <div class="stats-tab-icon">
                                <i class="bi bi-shield-lock"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo number_format($failed_logins ?? 0); ?></div>
                            <div class="stats-tab-label">Failed Logins</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card stats-tab tab-merchants">
                            <div class="stats-tab-icon">
                                <i class="bi bi-building"></i>
                            </div>
                            <div class="stats-tab-value"><?php echo $pending_officials_count; ?></div>
                            <div class="stats-tab-label">Pending Officials</div>
                        </div>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header bg-dark text-white">
                                <h5 class="mb-0"><i class="bi bi-lightning-fill me-2"></i>Admin Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <a href="users.php" class="btn btn-primary w-100">
                                            <i class="bi bi-people me-2"></i>Manage Users
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="official_approval.php" class="btn btn-danger w-100">
                                            <i class="bi bi-building me-2"></i>Approve Officials
                                            <?php if ($pending_officials_count > 0): ?>
                                            <span class="badge bg-light text-dark ms-2"><?php echo $pending_officials_count; ?></span>
                                            <?php endif; ?>
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="merchant_approval.php" class="btn btn-warning w-100">
                                            <i class="bi bi-shop me-2"></i>Approve Merchants
                                            <?php if ($pending_merchants_count > 0): ?>
                                            <span class="badge bg-light text-dark ms-2"><?php echo $pending_merchants_count; ?></span>
                                            <?php endif; ?>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php else: ?>
                <!-- Citizen personal dashboard -->
                
                <div id="citizenDashboard" class="row mb-4">
                    <div class="col-md-12">
                        <?php if (isset($user_documents) && !empty($user_documents)): ?>
                        <div class="status-card bg-info">
                            <i class="bi bi-file-earmark-check status-icon"></i>
                            <h5>Documents</h5>
                            <p>You have <?php echo count($user_documents); ?> document(s) uploaded to the system.</p>
                            <a href="document_upload.php" class="btn btn-sm btn-light mt-3">Manage Documents</a>
                        </div>
                        <?php else: ?>
                        <div class="status-card bg-secondary">
                            <i class="bi bi-file-earmark status-icon"></i>
                            <h5>Documents</h5>
                            <p>You have not uploaded any documents yet.</p>
                            <a href="document_upload.php" class="btn btn-sm btn-light mt-3">Upload Documents</a>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card shadow-sm">
                            <div class="card-header-minimal">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div><i class="bi bi-cart me-2"></i>Your Recent Purchases</div>
                                    <a href="purchases.php" class="btn btn-sm btn-outline-primary">View All</a>
                                </div>
                            </div>
                            <div class="card-body">
                                <?php if (isset($user_purchases) && !empty($user_purchases)): ?>
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Date</th>
                                                <th>Item</th>
                                                <th>Merchant</th>
                                                <th>Amount</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($user_purchases as $purchase): ?>
                                            <tr>
                                                <td><?php echo date('M j, Y', strtotime($purchase['purchase_date'])); ?></td>
                                                <td><?php echo htmlspecialchars($purchase['item_name']); ?></td>
                                                <td><?php echo htmlspecialchars($purchase['merchant_name']); ?></td>
                                                <td><?php echo '$' . number_format($purchase['total_price'], 2); ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                                <?php else: ?>
                                <p class="text-muted">No recent purchases found</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-lightning-fill me-2"></i>Quick Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <a href="document_upload.php" class="btn btn-info w-100">
                                            <i class="bi bi-file-earmark-arrow-up me-2"></i>My Documents
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="purchases.php" class="btn btn-warning w-100">
                                            <i class="bi bi-cart me-2"></i>Make Purchase
                                        </a>
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <a href="profile.php" class="btn btn-secondary w-100">
                                            <i class="bi bi-person-gear me-2"></i>My Profile
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Document management interface -->
                <?php if (isset($user_documents) && !empty($user_documents)): ?>
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card shadow-sm">
                            <div class="card-header-minimal">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div><i class="bi bi-file-earmark me-2"></i>My Documents</div>
                                    <a href="document_upload.php" class="btn btn-sm btn-outline-primary">Manage All</a>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <?php foreach (array_slice($user_documents, 0, 4) as $doc): ?>
                                    <div class="col-md-6 mb-3">
                                        <div class="card border h-100">
                                            <div class="card-body p-3">
                                                <div class="d-flex align-items-center">
                                                    <div class="me-3">
                                                        <?php
                                                        // Document type icon mapping
                                                        $icon = 'file-earmark';
                                                        $icon_class = 'text-primary';
                                                        switch($doc['document_type']) {
                                                            case 'Vaccination Certificate':
                                                                $icon = 'file-earmark-medical';
                                                                $icon_class = 'text-success';
                                                                break;
                                                            case 'ID Document':
                                                                $icon = 'person-badge';
                                                                $icon_class = 'text-info';
                                                                break;
                                                            case 'Medical Report':
                                                                $icon = 'file-earmark-plus';
                                                                $icon_class = 'text-warning';
                                                                break;
                                                        }
                                                        ?>
                                                        <i class="bi bi-<?php echo $icon; ?> fs-2 <?php echo $icon_class; ?>"></i>
                                                    </div>
                                                    <div class="flex-grow-1">
                                                        <h6 class="mb-1"><?php echo htmlspecialchars($doc['document_name']); ?></h6>
                                                        <small class="text-muted">
                                                            <?php echo htmlspecialchars($doc['document_type']); ?> • 
                                                            <?php echo date('M j, Y', strtotime($doc['upload_date'])); ?>
                                                        </small>
                                                        <br>
                                                        <span class="badge bg-<?php echo $doc['is_verified'] ? 'success' : 'warning'; ?> mt-1">
                                                            <?php echo $doc['is_verified'] ? 'Verified' : 'Pending'; ?>
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php endif; ?>

                <!-- Low stock alerts (hidden from citizens) -->
                <?php if (!empty($low_stock_items) && !$is_citizen): ?>
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card border-warning shadow-sm">
                            <div class="card-header bg-warning text-dark">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div><i class="bi bi-exclamation-triangle me-2"></i>Low Stock Alert</div>
                                    <a href="stock.php" class="btn btn-sm btn-outline-dark">View All Stock</a>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <?php foreach ($low_stock_items as $item): ?>
                                    <div class="col-md-4 mb-3">
                                        <div class="card border-warning h-100">
                                            <div class="card-body p-3">
                                                <div class="d-flex justify-content-between align-items-start">
                                                    <div>
                                                        <h6 class="mb-1"><?php echo htmlspecialchars($item['item_name']); ?></h6>
                                                        <small class="text-muted"><?php echo htmlspecialchars($item['merchant_name']); ?></small>
                                                        <br>
                                                        <span class="badge bg-danger mt-1">
                                                            Only <?php echo $item['quantity_available']; ?> left
                                                        </span>
                                                    </div>
                                                    <div class="text-end">
                                                        <?php if (!empty($item['unit_price'])): ?>
                                                        <small class="text-muted">$<?php echo number_format($item['unit_price'], 2); ?></small>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- System summary footer -->
                <div class="row">
                    <div class="col-md-12">
                        <div class="card bg-light">
                            <div class="card-body text-center py-4">
                                <h5 class="mb-3">COVID Resilience System</h5>
                                <p class="text-muted mb-2">
                                    Your comprehensive platform for managing COVID-19 related activities, 
                                    vaccinations, purchases, and community resilience.
                                </p>
                                <div class="row text-center mt-4">
                                    <div class="col-md-3">
                                        <div class="border-end">
                                            <h6 class="text-primary"><?php echo number_format($total_users); ?></h6>
                                            <small class="text-muted">Total Users</small>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="border-end">
                                            <h6 class="text-success"><?php echo number_format($total_vaccinations); ?></h6>
                                            <small class="text-muted">Vaccinations</small>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div class="border-end">
                                            <h6 class="text-info"><?php echo number_format($total_merchants); ?></h6>
                                            <small class="text-muted">Active Merchants</small>
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <div>
                                            <h6 class="text-warning"><?php echo number_format($total_purchases); ?></h6>
                                            <small class="text-muted">Total Purchases</small>
                                        </div>
                                    </div>
                                </div>
                                <hr class="my-4">
                                <small class="text-muted">
                                    Last updated: <?php echo date('F j, Y g:i A'); ?> | 
                                    Logged in as: <strong><?php echo htmlspecialchars($_SESSION['role']); ?></strong> |
                                    User ID: <?php echo htmlspecialchars($_SESSION['prs_id']); ?>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
                
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <?php if (!empty($scroll_to_section)): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const element = document.getElementById('<?php echo $scroll_to_section; ?>');
            if (element) {
                element.scrollIntoView({ behavior: 'smooth' });
            }
        });
    </script>
    <?php endif; ?>

    <script>
        // Auto-refresh every 5 minutes to keep dashboard data current
        setTimeout(function(){
            window.location.reload();
        }, 300000);

        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth'
                    });
                }
            });
        });

        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });

        document.querySelectorAll('button[type="submit"]').forEach(button => {
            button.addEventListener('click', function() {
                this.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Processing...';
                this.disabled = true;
            });
        });

        // Progressive card loading animation
        document.addEventListener('DOMContentLoaded', function() {
            const cards = document.querySelectorAll('.card');
            cards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                
                setTimeout(() => {
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, index * 100);
            });
        });

        document.querySelectorAll('.stats-tab').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-8px) scale(1.02)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0) scale(1)';
            });
        });

        // Auto-dismiss alerts after 5 seconds
        document.querySelectorAll('.alert').forEach(alert => {
            setTimeout(function() {
                if (alert.querySelector('.btn-close')) {
                    alert.querySelector('.btn-close').click();
                }
            }, 5000);
        });
    </script>
</body>
</html>