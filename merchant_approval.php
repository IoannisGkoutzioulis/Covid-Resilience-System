<?php
require_once 'config.php';
require_once 'session_check.php';
require_once 'access_control.php';

checkLogin();
requireRole(['Admin', 'Official']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF protection for approval/rejection actions
    if (!validateCSRFToken($csrf_token)) {
        $_SESSION['error_message'] = "Security validation failed.";
    } else {
        $merchant_id = (int)$_POST['merchant_id'];
        $action = $_POST['action'];
        $rejection_reason = $_POST['rejection_reason'] ?? '';
        
        if ($action === 'approve') {
            if (updateMerchantApproval($merchant_id, 'approve', $_SESSION['user_id'])) {
                $_SESSION['success_message'] = "Merchant approved successfully!";
                
                // Send approval notification email
                try {
                    $pdo = getDBConnection();
                    $stmt = $pdo->prepare(
                        "SELECT u.email, u.full_name, m.merchant_name 
                         FROM merchants m 
                         JOIN users u ON m.user_id = u.user_id 
                         WHERE m.merchant_id = ?"
                    );
                    $stmt->execute([$merchant_id]);
                    $merchant = $stmt->fetch();
                    
                    if ($merchant && $merchant['email']) {
                        sendEmailNotification(
                            $merchant['email'],
                            "Merchant Account Approved - COVID Resilience System",
                            "Dear " . $merchant['full_name'] . ",\n\nYour merchant account for '" . $merchant['merchant_name'] . "' has been approved. You can now login to access all merchant features.\n\nBest regards,\nCOVID Resilience System"
                        );
                    }
                } catch (Exception $e) {
                    error_log("Error sending approval notification: " . $e->getMessage());
                }
                
            } else {
                $_SESSION['error_message'] = "Failed to approve merchant.";
            }
        } elseif ($action === 'reject') {
            if (!empty($rejection_reason)) {
                if (updateMerchantApproval($merchant_id, 'reject', $_SESSION['user_id'], $rejection_reason)) {
                    $_SESSION['success_message'] = "Merchant rejected.";
                    
                    // Send rejection notification email
                    try {
                        $pdo = getDBConnection();
                        $stmt = $pdo->prepare(
                            "SELECT u.email, u.full_name, m.merchant_name 
                             FROM merchants m 
                             JOIN users u ON m.user_id = u.user_id 
                             WHERE m.merchant_id = ?"
                        );
                        $stmt->execute([$merchant_id]);
                        $merchant = $stmt->fetch();
                        
                        if ($merchant && $merchant['email']) {
                            sendEmailNotification(
                                $merchant['email'],
                                "Merchant Account Update - COVID Resilience System",
                                "Dear " . $merchant['full_name'] . ",\n\nYour merchant account application for '" . $merchant['merchant_name'] . "' has been reviewed. Reason: " . $rejection_reason . "\n\nYou may re-apply by contacting an administrator.\n\nBest regards,\nCOVID Resilience System"
                            );
                        }
                    } catch (Exception $e) {
                        error_log("Error sending rejection notification: " . $e->getMessage());
                    }
                    
                } else {
                    $_SESSION['error_message'] = "Failed to reject merchant.";
                }
            } else {
                $_SESSION['error_message'] = "Rejection reason is required.";
            }
        }
    }
    
    // Prevent form resubmission on page refresh
    header("Location: merchant_approval.php");
    exit();
}

$stats = getMerchantStats();
$pending_merchants = getPendingMerchants();
$all_merchants = getAllMerchants();
$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Merchant Approval - COVID Resilience System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
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
        
        .stats-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .merchant-card {
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .status-pending {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
        }
        .status-approved {
            background-color: #d1e7dd;
            border-left: 4px solid #198754;
        }
        .status-rejected {
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
        }
        .action-buttons {
            gap: 10px;
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
                    
                    <?php
                    $is_admin_or_official = ($_SESSION['role'] === 'Admin' || $_SESSION['role'] === 'Official');
                    // Dynamic badge count for pending approvals
                    $pending_merchants_count = 0;
                    if ($is_admin_or_official) {
                        $pending_merchants_count = count($pending_merchants);
                    }
                    ?>
                    
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
                    
                    <?php if ($_SESSION['role'] === 'Admin'): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="system_settings.php">
                            <i class="bi bi-gear me-2"></i>System Settings
                        </a>
                    </li>
                    <?php endif; ?>
                    
                    <li class="nav-item mt-5">
                        <a class="nav-link text-danger" href="logout.php">
                            <i class="bi bi-box-arrow-right me-2"></i>Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="col-md-10 p-4">
                <div class="row">
                    <div class="col-12">
                        <h2><i class="bi bi-people-fill me-2"></i>Merchant Approval Management</h2>
                        <p class="text-muted">Review and approve merchant account applications</p>
                    </div>
                </div>

        <?php if (isset($_SESSION['success_message'])): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <i class="bi bi-check-circle-fill me-2"></i>
            <?php echo htmlspecialchars($_SESSION['success_message']); unset($_SESSION['success_message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error_message'])): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            <?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <h3><?php echo $stats['total']; ?></h3>
                    <p class="mb-0">Total Merchants</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <h3><?php echo $stats['pending']; ?></h3>
                    <p class="mb-0">Pending Approval</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <h3><?php echo $stats['approved']; ?></h3>
                    <p class="mb-0">Approved</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card text-center">
                    <h3><?php echo $stats['rejected']; ?></h3>
                    <p class="mb-0">Rejected</p>
                </div>
            </div>
        </div>

        <?php if (!empty($pending_merchants)): ?>
        <div class="row">
            <div class="col-12">
                <h4 class="mb-3"><i class="bi bi-clock me-2 text-warning"></i>Pending Merchant Applications</h4>
                
                <?php foreach ($pending_merchants as $merchant): ?>
                <div class="card merchant-card status-pending">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8">
                                <h5 class="card-title">
                                    <i class="bi bi-shop me-2"></i><?php echo htmlspecialchars($merchant['merchant_name']); ?>
                                    <span class="badge bg-warning text-dark ms-2">Pending</span>
                                </h5>
                                <p class="card-text">
                                    <strong>Owner:</strong> <?php echo htmlspecialchars($merchant['full_name']); ?><br>
                                    <strong>Username:</strong> <?php echo htmlspecialchars($merchant['username']); ?><br>
                                    <strong>Email:</strong> <?php echo htmlspecialchars($merchant['contact_email']); ?><br>
                                    <strong>Phone:</strong> <?php echo htmlspecialchars($merchant['contact_phone'] ?? 'Not provided'); ?><br>
                                    <strong>City:</strong> <?php echo htmlspecialchars($merchant['city'] ?? 'Not specified'); ?><br>
                                    <strong>Business License:</strong> <?php echo htmlspecialchars($merchant['business_license'] ?? 'Not provided'); ?><br>
                                    <strong>PRS ID:</strong> <?php echo htmlspecialchars($merchant['prs_id']); ?><br>
                                    <strong>Applied:</strong> <?php echo date('Y-m-d H:i', strtotime($merchant['created_at'])); ?>
                                </p>
                            </div>
                            <div class="col-md-4 text-end">
                                <div class="action-buttons d-flex flex-column">
                                    <form method="POST" class="mb-2">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                        <input type="hidden" name="merchant_id" value="<?php echo $merchant['merchant_id']; ?>">
                                        <input type="hidden" name="action" value="approve">
                                        <button type="submit" class="btn btn-success w-100" 
                                                onclick="return confirm('Are you sure you want to approve this merchant account?')">
                                            <i class="bi bi-check-circle me-1"></i>Approve
                                        </button>
                                    </form>
                                    
                                    <button type="button" class="btn btn-danger w-100" 
                                            data-bs-toggle="modal" 
                                            data-bs-target="#rejectModal<?php echo $merchant['merchant_id']; ?>">
                                        <i class="bi bi-x-circle me-1"></i>Reject
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="modal fade" id="rejectModal<?php echo $merchant['merchant_id']; ?>" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Reject Merchant Application</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="POST">
                                <div class="modal-body">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <input type="hidden" name="merchant_id" value="<?php echo $merchant['merchant_id']; ?>">
                                    <input type="hidden" name="action" value="reject">
                                    
                                    <p>Are you sure you want to reject the application for <strong><?php echo htmlspecialchars($merchant['merchant_name']); ?></strong>?</p>
                                    
                                    <div class="mb-3">
                                        <label for="rejection_reason<?php echo $merchant['merchant_id']; ?>" class="form-label">
                                            Reason for rejection: <span class="text-danger">*</span>
                                        </label>
                                        <textarea class="form-control" 
                                                id="rejection_reason<?php echo $merchant['merchant_id']; ?>" 
                                                name="rejection_reason" 
                                                rows="3" 
                                                placeholder="Please provide a reason for rejection..."
                                                required></textarea>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-danger">
                                        <i class="bi bi-x-circle me-1"></i>Reject Application
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php else: ?>
        <div class="alert alert-info">
            <i class="bi bi-info-circle me-2"></i>No pending merchant applications at this time.
        </div>
        <?php endif; ?>

        <div class="row mt-5">
            <div class="col-12">
                <h4 class="mb-3"><i class="bi bi-list me-2"></i>All Merchants</h4>
                
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead class="table-dark">
                            <tr>
                                <th>Business Name</th>
                                <th>Owner</th>
                                <th>Email</th>
                                <th>City</th>
                                <th>Status</th>
                                <th>Applied Date</th>
                                <th>Approved By</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($all_merchants as $merchant): ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($merchant['merchant_name']); ?></strong><br>
                                    <small class="text-muted"><?php echo htmlspecialchars($merchant['prs_id']); ?></small>
                                </td>
                                <td><?php echo htmlspecialchars($merchant['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($merchant['contact_email']); ?></td>
                                <td><?php echo htmlspecialchars($merchant['city'] ?? 'N/A'); ?></td>
                                <td>
                                    <?php
                                    // Dynamic status badge styling
                                    $status = $merchant['status'];
                                    $badge_class = '';
                                    switch ($status) {
                                        case 'Approved':
                                            $badge_class = 'bg-success';
                                            break;
                                        case 'Pending':
                                            $badge_class = 'bg-warning text-dark';
                                            break;
                                        case 'Rejected':
                                            $badge_class = 'bg-danger';
                                            break;
                                    }
                                    ?>
                                    <span class="badge <?php echo $badge_class; ?>"><?php echo $status; ?></span>
                                </td>
                                <td><?php echo date('Y-m-d', strtotime($merchant['created_at'])); ?></td>
                                <td>
                                    <?php if ($merchant['approved_by']): ?>
                                        <small class="text-muted">
                                            User ID: <?php echo $merchant['approved_by']; ?><br>
                                            <?php echo $merchant['approved_at'] ? date('Y-m-d', strtotime($merchant['approved_at'])) : 'N/A'; ?>
                                        </small>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($merchant['status'] === 'Rejected'): ?>
                                        <button type="button" class="btn btn-sm btn-outline-info" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#detailsModal<?php echo $merchant['merchant_id']; ?>">
                                            <i class="bi bi-eye me-1"></i>Details
                                        </button>
                                    <?php else: ?>
                                        <small class="text-muted">-</small>
                                    <?php endif; ?>
                                </td>
                            </tr>

                            <?php if ($merchant['status'] === 'Rejected'): ?>
                            <div class="modal fade" id="detailsModal<?php echo $merchant['merchant_id']; ?>" tabindex="-1">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Rejection Details</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                        </div>
                                        <div class="modal-body">
                                            <p><strong>Business:</strong> <?php echo htmlspecialchars($merchant['merchant_name']); ?></p>
                                            <p><strong>Owner:</strong> <?php echo htmlspecialchars($merchant['full_name']); ?></p>
                                            <p><strong>Rejection Reason:</strong></p>
                                            <div class="alert alert-warning">
                                                <?php echo htmlspecialchars($merchant['rejection_reason'] ?? 'No reason provided'); ?>
                                            </div>
                                            <p><strong>Rejected On:</strong> <?php echo $merchant['approved_at'] ? date('Y-m-d H:i', strtotime($merchant['approved_at'])) : 'Unknown'; ?></p>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>

                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>