<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();
requireRole('Admin', 'dashboard.php');

$success_message = $error_message = '';
$filter = $_GET['filter'] ?? 'pending';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    $official_id = (int)$_POST['official_id'];
    $rejection_reason = $_POST['rejection_reason'] ?? '';
    
    // CSRF protection for approval/rejection actions
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $error_message = "Security validation failed. Please try again.";
    } else {
        if ($action === 'approve') {
            $result = updateOfficialApproval($official_id, 'approve', $_SESSION['user_id']);
            if ($result) {
                $success_message = "Official account has been successfully approved!";
                logAccess($_SESSION['user_id'], "Approved official ID: $official_id", true);
            } else {
                $error_message = "Failed to approve official account. Please try again.";
            }
        } elseif ($action === 'reject') {
            if (empty($rejection_reason)) {
                $error_message = "Rejection reason is required when rejecting an official account.";
            } else {
                $result = updateOfficialApproval($official_id, 'reject', $_SESSION['user_id'], $rejection_reason);
                if ($result) {
                    $success_message = "Official account has been rejected with reason provided.";
                    logAccess($_SESSION['user_id'], "Rejected official ID: $official_id", true, $rejection_reason);
                } else {
                    $error_message = "Failed to reject official account. Please try again.";
                }
            }
        }
    }
}

try {
    $pdo = getDBConnection();
    
    switch ($filter) {
        case 'pending':
            $officials = getPendingOfficials(100);
            break;
        case 'approved':
            $stmt = $pdo->prepare(
                "SELECT o.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
                 FROM government_officials o 
                 JOIN users u ON o.user_id = u.user_id 
                 WHERE o.status = 'Approved' 
                 ORDER BY o.approved_at DESC 
                 LIMIT 100"
            );
            $stmt->execute();
            $officials = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
        case 'rejected':
            $stmt = $pdo->prepare(
                "SELECT o.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
                 FROM government_officials o 
                 JOIN users u ON o.user_id = u.user_id 
                 WHERE o.status = 'Rejected' 
                 ORDER BY o.approved_at DESC 
                 LIMIT 100"
            );
            $stmt->execute();
            $officials = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
        default:
            $officials = getAllOfficials(100);
            break;
    }
    
    $stats = getOfficialStats();
    
} catch (PDOException $e) {
    $error_message = "Error fetching official data: " . $e->getMessage();
    $officials = [];
    $stats = ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
}

$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Official Approval Management - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .header-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }
        .stats-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stats-card:hover {
            transform: translateY(-5px);
        }
        .pending-card {
            border-left: 4px solid #ffc107;
        }
        .approved-card {
            border-left: 4px solid #28a745;
        }
        .rejected-card {
            border-left: 4px solid #dc3545;
        }
        .total-card {
            border-left: 4px solid #007bff;
        }
        .action-buttons .btn {
            margin: 0 2px;
        }
        .filter-tabs .nav-link {
            border-radius: 20px;
            margin: 0 5px;
        }
        .filter-tabs .nav-link.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-color: transparent;
        }
        .official-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
            transition: all 0.3s;
        }
        .official-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            transform: translateX(5px);
        }
        .status-badge-pending {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        .status-badge-approved {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status-badge-rejected {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="header-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col">
                    <h1 class="mb-2">
                        <i class="bi bi-building me-3"></i>Official Approval Management
                    </h1>
                    <p class="mb-0 opacity-90">Review and approve government official account applications</p>
                </div>
                <div class="col-auto">
                    <a href="dashboard.php" class="btn btn-light">
                        <i class="bi bi-arrow-left me-2"></i>Back to Dashboard
                    </a>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <?php if (!empty($success_message)): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <i class="bi bi-check-circle-fill me-2"></i>
            <?php echo htmlspecialchars($success_message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <?php if (!empty($error_message)): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            <?php echo htmlspecialchars($error_message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stats-card total-card">
                    <div class="card-body text-center">
                        <i class="bi bi-people fs-1 text-primary mb-2"></i>
                        <h3 class="text-primary"><?php echo $stats['total']; ?></h3>
                        <p class="text-muted mb-0">Total Officials</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card pending-card">
                    <div class="card-body text-center">
                        <i class="bi bi-clock fs-1 text-warning mb-2"></i>
                        <h3 class="text-warning"><?php echo $stats['pending']; ?></h3>
                        <p class="text-muted mb-0">Pending Approval</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card approved-card">
                    <div class="card-body text-center">
                        <i class="bi bi-check-circle fs-1 text-success mb-2"></i>
                        <h3 class="text-success"><?php echo $stats['approved']; ?></h3>
                        <p class="text-muted mb-0">Approved</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stats-card rejected-card">
                    <div class="card-body text-center">
                        <i class="bi bi-x-circle fs-1 text-danger mb-2"></i>
                        <h3 class="text-danger"><?php echo $stats['rejected']; ?></h3>
                        <p class="text-muted mb-0">Rejected</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col">
                <ul class="nav nav-pills filter-tabs justify-content-center">
                    <li class="nav-item">
                        <a class="nav-link <?php echo $filter === 'pending' ? 'active' : ''; ?>" 
                           href="?filter=pending">
                            <i class="bi bi-clock me-2"></i>Pending (<?php echo $stats['pending']; ?>)
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $filter === 'approved' ? 'active' : ''; ?>" 
                           href="?filter=approved">
                            <i class="bi bi-check-circle me-2"></i>Approved (<?php echo $stats['approved']; ?>)
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $filter === 'rejected' ? 'active' : ''; ?>" 
                           href="?filter=rejected">
                            <i class="bi bi-x-circle me-2"></i>Rejected (<?php echo $stats['rejected']; ?>)
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo $filter === 'all' ? 'active' : ''; ?>" 
                           href="?filter=all">
                            <i class="bi bi-list me-2"></i>All Officials
                        </a>
                    </li>
                </ul>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <?php if (empty($officials)): ?>
                <div class="card">
                    <div class="card-body text-center py-5">
                        <i class="bi bi-inbox fs-1 text-muted mb-3"></i>
                        <h5 class="text-muted">No officials found</h5>
                        <p class="text-muted">
                            <?php
                            switch($filter) {
                                case 'pending':
                                    echo "There are currently no officials awaiting approval.";
                                    break;
                                case 'approved':
                                    echo "No officials have been approved yet.";
                                    break;
                                case 'rejected':
                                    echo "No officials have been rejected.";
                                    break;
                                default:
                                    echo "No official accounts have been registered yet.";
                            }
                            ?>
                        </p>
                    </div>
                </div>
                <?php else: ?>
                <?php foreach ($officials as $official): ?>
                <div class="card official-card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-3">
                                <div class="d-flex align-items-center">
                                    <div class="me-3">
                                        <i class="bi bi-person-badge fs-2 text-primary"></i>
                                    </div>
                                    <div>
                                        <h6 class="mb-1"><?php echo htmlspecialchars($official['full_name'] ?? $official['first_name'] . ' ' . $official['last_name']); ?></h6>
                                        <small class="text-muted">
                                            <i class="bi bi-person me-1"></i><?php echo htmlspecialchars($official['username'] ?? 'N/A'); ?>
                                        </small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div>
                                    <small class="text-muted d-block">Position</small>
                                    <strong><?php echo htmlspecialchars($official['role']); ?></strong>
                                </div>
                                <div class="mt-2">
                                    <small class="text-muted d-block">Area</small>
                                    <small><?php echo htmlspecialchars($official['authorized_area'] ?? 'N/A'); ?></small>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div>
                                    <small class="text-muted d-block">Contact</small>
                                    <small>
                                        <?php if (!empty($official['contact_email'])): ?>
                                        <i class="bi bi-envelope me-1"></i><?php echo htmlspecialchars($official['contact_email']); ?><br>
                                        <?php endif; ?>
                                        <?php if (!empty($official['contact_phone'])): ?>
                                        <i class="bi bi-telephone me-1"></i><?php echo htmlspecialchars($official['contact_phone']); ?>
                                        <?php endif; ?>
                                    </small>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="text-center">
                                    <span class="badge status-badge-<?php echo strtolower($official['status']); ?> px-3 py-2">
                                        <?php
                                        switch($official['status']) {
                                            case 'Pending':
                                                echo '<i class="bi bi-clock me-1"></i>Pending';
                                                break;
                                            case 'Approved':
                                                echo '<i class="bi bi-check-circle me-1"></i>Approved';
                                                break;
                                            case 'Rejected':
                                                echo '<i class="bi bi-x-circle me-1"></i>Rejected';
                                                break;
                                        }
                                        ?>
                                    </span>
                                    <div class="mt-2">
                                        <small class="text-muted">
                                            Registered: <?php echo date('M j, Y', strtotime($official['created_at'])); ?>
                                        </small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="action-buttons text-end">
                                    <?php if ($official['status'] === 'Pending'): ?>
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                        <input type="hidden" name="action" value="approve">
                                        <input type="hidden" name="official_id" value="<?php echo $official['official_id']; ?>">
                                        <button type="submit" class="btn btn-success btn-sm" 
                                                onclick="return confirm('Are you sure you want to approve this official account?')">
                                            <i class="bi bi-check-lg"></i> Approve
                                        </button>
                                    </form>
                                    
                                    <button class="btn btn-danger btn-sm" 
                                            data-bs-toggle="modal" 
                                            data-bs-target="#rejectModal<?php echo $official['official_id']; ?>">
                                        <i class="bi bi-x-lg"></i> Reject
                                    </button>
                                    
                                    <div class="modal fade" id="rejectModal<?php echo $official['official_id']; ?>" tabindex="-1">
                                        <div class="modal-dialog">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Reject Official Account</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                </div>
                                                <form method="POST">
                                                    <div class="modal-body">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                        <input type="hidden" name="action" value="reject">
                                                        <input type="hidden" name="official_id" value="<?php echo $official['official_id']; ?>">
                                                        
                                                        <p>Are you sure you want to reject the official account for <strong><?php echo htmlspecialchars($official['full_name'] ?? $official['first_name'] . ' ' . $official['last_name']); ?></strong>?</p>
                                                        
                                                        <div class="mb-3">
                                                            <label for="rejection_reason<?php echo $official['official_id']; ?>" class="form-label">
                                                                Rejection Reason <span class="text-danger">*</span>
                                                            </label>
                                                            <textarea class="form-control" 
                                                                      id="rejection_reason<?php echo $official['official_id']; ?>" 
                                                                      name="rejection_reason" 
                                                                      rows="3" 
                                                                      placeholder="Please provide a reason for rejection..."
                                                                      required></textarea>
                                                        </div>
                                                    </div>
                                                    <div class="modal-footer">
                                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                        <button type="submit" class="btn btn-danger">
                                                            <i class="bi bi-x-lg me-1"></i>Reject Account
                                                        </button>
                                                    </div>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <?php elseif ($official['status'] === 'Approved'): ?>
                                    <span class="badge bg-success">
                                        <i class="bi bi-check-circle me-1"></i>Approved
                                    </span>
                                    <?php if (!empty($official['approved_at'])): ?>
                                    <div class="mt-1">
                                        <small class="text-muted">
                                            <?php echo date('M j, Y', strtotime($official['approved_at'])); ?>
                                        </small>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php elseif ($official['status'] === 'Rejected'): ?>
                                    <span class="badge bg-danger">
                                        <i class="bi bi-x-circle me-1"></i>Rejected
                                    </span>
                                    <?php if (!empty($official['rejection_reason'])): ?>
                                    <div class="mt-1">
                                        <small class="text-muted" title="<?php echo htmlspecialchars($official['rejection_reason']); ?>">
                                            Reason provided
                                        </small>
                                    </div>
                                    <?php endif; ?>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        
                        <?php if ($official['status'] === 'Rejected' && !empty($official['rejection_reason'])): ?>
                        <div class="row mt-3">
                            <div class="col-12">
                                <div class="alert alert-danger mb-0">
                                    <strong>Rejection Reason:</strong> <?php echo htmlspecialchars($official['rejection_reason']); ?>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh for pending officials monitoring
        <?php if ($stats['pending'] > 0): ?>
        setTimeout(function(){
            window.location.reload();
        }, 30000);
        <?php endif; ?>
        
        document.querySelectorAll('form[method="POST"]').forEach(form => {
            if (form.querySelector('input[value="approve"]')) {
                form.addEventListener('submit', function(e) {
                    if (!confirm('Are you sure you want to approve this official account? This will grant them access to official system features.')) {
                        e.preventDefault();
                    }
                });
            }
        });
    </script>
</body>
</html>