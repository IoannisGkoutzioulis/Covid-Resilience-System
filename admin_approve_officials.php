<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

// Only Officials can approve other Official accounts
enforcePermission('government_officials', 'update');

// Handle approval action
if (isset($_GET['action']) && $_GET['action'] === 'approve' && isset($_GET['id'])) {
    $user_id = (int)$_GET['id'];
    
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("UPDATE users SET is_approved = 1 WHERE user_id = ? AND role = 'Official'");
        $stmt->execute([$user_id]);
        
        if ($stmt->rowCount() > 0) {
            $success_message = "Official account approved successfully";
            
            logAccess($_SESSION['user_id'], 'Approved Official ID: ' . $user_id);
            
            // Get user details for notification
            $stmt = $pdo->prepare("SELECT email, full_name FROM users WHERE user_id = ?");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Email notification would be sent here in production
            if ($user && !empty($user['email'])) {
                // sendApprovalEmail($user['email'], $user['full_name']);
            }
        } else {
            $error_message = "User not found or not an Official";
        }
    } catch (PDOException $e) {
        $error_message = "Error approving user: " . $e->getMessage();
    }
}

// Handle rejection action (deletes unapproved accounts)
if (isset($_GET['action']) && $_GET['action'] === 'reject' && isset($_GET['id'])) {
    $user_id = (int)$_GET['id'];
    
    try {
        $pdo = getDBConnection();
        
        // Get user info before deletion for logging purposes
        $stmt = $pdo->prepare("SELECT full_name, email FROM users WHERE user_id = ? AND role = 'Official' AND is_approved = 0");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ? AND role = 'Official' AND is_approved = 0");
            $stmt->execute([$user_id]);
            
            if ($stmt->rowCount() > 0) {
                $success_message = "Official account application rejected";
                
                logAccess($_SESSION['user_id'], 'Rejected Official: ' . $user['full_name']);
                
                // Email notification would be sent here in production
                if (!empty($user['email'])) {
                    // sendRejectionEmail($user['email'], $user['full_name']);
                }
            } else {
                $error_message = "Error rejecting the user";
            }
        } else {
            $error_message = "User not found, not an Official, or already approved";
        }
    } catch (PDOException $e) {
        $error_message = "Error rejecting user: " . $e->getMessage();
    }
}

try {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE role = 'Official' AND is_approved = 0 ORDER BY created_at DESC");
    $stmt->execute();
    $pending_officials = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role = 'Official' AND is_approved = 0");
    $stmt->execute();
    $pending_count = $stmt->fetchColumn();
} catch (PDOException $e) {
    $error_message = "Error fetching pending officials: " . $e->getMessage();
    $pending_officials = [];
    $pending_count = 0;
}

// CSRF protection for approval/rejection actions
$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Approve Official Accounts - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .badge-counter {
            position: absolute;
            transform: scale(0.7);
            transform-origin: top right;
            right: -10px;
            top: -5px;
        }
        
        .status-badge {
            font-size: 85%;
            padding: 0.25em 0.6em;
            border-radius: 30px;
        }
        
        .table-actions {
            white-space: nowrap;
        }
        
        .user-detail-row {
            border-bottom: 1px solid #f0f0f0;
            padding: 8px 0;
        }
        
        .user-detail-label {
            font-weight: 600;
            color: #495057;
        }
        
        .empty-state {
            text-align: center;
            padding: 30px 0;
        }
        
        .empty-state-icon {
            font-size: 3.5rem;
            color: #adb5bd;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <?php include 'header.php'; ?>

    <div class="container-fluid">
        <div class="row">
            <?php include 'sidebar.php'; ?>
            
            <div class="col-md-10 ms-sm-auto px-4 py-3">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h2>
                        <i class="bi bi-person-check me-2"></i>Approve Official Accounts
                        <?php if ($pending_count > 0): ?>
                        <span class="badge bg-danger ms-2"><?php echo $pending_count; ?></span>
                        <?php endif; ?>
                    </h2>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <a href="dashboard.php" class="btn btn-sm btn-outline-secondary">
                            <i class="bi bi-arrow-left me-1"></i> Back to Dashboard
                        </a>
                    </div>
                </div>
                
                <?php if (isset($success_message)): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="bi bi-check-circle-fill me-2"></i><?php echo htmlspecialchars($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <?php if (isset($error_message)): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="card-title mb-0">
                            <i class="bi bi-list-check me-2"></i>Pending Official Accounts
                            <?php if ($pending_count > 0): ?>
                            <span class="badge bg-danger ms-2"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($pending_officials)): ?>
                        <div class="empty-state">
                            <i class="bi bi-check-circle empty-state-icon"></i>
                            <h5 class="mb-1">No Pending Approvals</h5>
                            <p class="text-muted mb-3">There are no pending Official account applications at this time.</p>
                            <a href="dashboard.php" class="btn btn-outline-primary">
                                <i class="bi bi-arrow-left me-1"></i> Return to Dashboard
                            </a>
                        </div>
                        <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="table-light">
                                    <tr>
                                        <th>#</th>
                                        <th>PRS ID</th>
                                        <th>Full Name</th>
                                        <th>National ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Registration Date</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($pending_officials as $official): ?>
                                    <tr>
                                        <td><?php echo $official['user_id']; ?></td>
                                        <td>
                                            <span class="fw-bold text-primary"><?php echo htmlspecialchars($official['prs_id']); ?></span>
                                        </td>
                                        <td><?php echo htmlspecialchars($official['full_name']); ?></td>
                                        <td><?php echo htmlspecialchars($official['national_id']); ?></td>
                                        <td><?php echo htmlspecialchars($official['username']); ?></td>
                                        <td>
                                            <?php if (!empty($official['email'])): ?>
                                            <a href="mailto:<?php echo htmlspecialchars($official['email']); ?>">
                                                <?php echo htmlspecialchars($official['email']); ?>
                                            </a>
                                            <?php else: ?>
                                            <span class="text-muted">Not provided</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo date('M j, Y g:i a', strtotime($official['created_at'])); ?></td>
                                        <td class="table-actions">
                                            <button type="button" class="btn btn-sm btn-info" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#viewModal<?php echo $official['user_id']; ?>">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            
                                            <a href="admin_approve_officials.php?action=approve&id=<?php echo $official['user_id']; ?>&csrf_token=<?php echo $csrf_token; ?>" 
                                               class="btn btn-sm btn-success">
                                                <i class="bi bi-check-lg"></i> Approve
                                            </a>
                                            
                                            <a href="admin_approve_officials.php?action=reject&id=<?php echo $official['user_id']; ?>&csrf_token=<?php echo $csrf_token; ?>" 
                                               class="btn btn-sm btn-danger"
                                               onclick="return confirm('Are you sure you want to reject this Official account application? This action cannot be undone.')">
                                                <i class="bi bi-x-lg"></i> Reject
                                            </a>
                                        </td>
                                    </tr>
                                    
                                    <!-- User details modal for each official -->
                                    <div class="modal fade" id="viewModal<?php echo $official['user_id']; ?>" tabindex="-1" aria-labelledby="viewModalLabel<?php echo $official['user_id']; ?>" aria-hidden="true">
                                        <div class="modal-dialog">
                                            <div class="modal-content">
                                                <div class="modal-header bg-info text-white">
                                                    <h5 class="modal-title" id="viewModalLabel<?php echo $official['user_id']; ?>">
                                                        <i class="bi bi-person-badge me-2"></i>Official Details
                                                    </h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="user-details">
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">PRS ID:</div>
                                                            <div class="col-8"><?php echo htmlspecialchars($official['prs_id']); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Full Name:</div>
                                                            <div class="col-8"><?php echo htmlspecialchars($official['full_name']); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">National ID:</div>
                                                            <div class="col-8"><?php echo htmlspecialchars($official['national_id']); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Date of Birth:</div>
                                                            <div class="col-8"><?php echo date('F j, Y', strtotime($official['dob'])); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Username:</div>
                                                            <div class="col-8"><?php echo htmlspecialchars($official['username']); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Email:</div>
                                                            <div class="col-8">
                                                                <?php if (!empty($official['email'])): ?>
                                                                <?php echo htmlspecialchars($official['email']); ?>
                                                                <?php else: ?>
                                                                <span class="text-muted">Not provided</span>
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Registered:</div>
                                                            <div class="col-8"><?php echo date('F j, Y g:i a', strtotime($official['created_at'])); ?></div>
                                                        </div>
                                                        <div class="row user-detail-row">
                                                            <div class="col-4 user-detail-label">Status:</div>
                                                            <div class="col-8">
                                                                <span class="badge bg-warning text-dark status-badge">Pending Approval</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                    <a href="admin_approve_officials.php?action=approve&id=<?php echo $official['user_id']; ?>&csrf_token=<?php echo $csrf_token; ?>" 
                                                       class="btn btn-success">
                                                        <i class="bi bi-check-lg me-1"></i> Approve
                                                    </a>
                                                    <a href="admin_approve_officials.php?action=reject&id=<?php echo $official['user_id']; ?>&csrf_token=<?php echo $csrf_token; ?>" 
                                                       class="btn btn-danger"
                                                       onclick="return confirm('Are you sure you want to reject this Official account application? This action cannot be undone.')">
                                                        <i class="bi bi-x-lg me-1"></i> Reject
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php endif; ?>
                    </div>
                    <?php if (!empty($pending_officials)): ?>
                    <div class="card-footer bg-light text-center">
                        <small class="text-muted">
                            <i class="bi bi-info-circle me-1"></i>
                            Displaying <?php echo count($pending_officials); ?> pending Official account requests.
                        </small>
                    </div>
                    <?php endif; ?>
                </div>
                
                <div class="mt-4">
                    <h5><i class="bi bi-lightbulb me-2"></i>Approval Guidelines</h5>
                    <div class="alert alert-light">
                        <p><strong>Before approving an Official account, please verify:</strong></p>
                        <ul>
                            <li>The person is a legitimate government official</li>
                            <li>Their National ID matches official records</li>
                            <li>You have authorization to approve their access level</li>
                            <li>The position requires access to the COVID Resilience System</li>
                        </ul>
                        <p class="mb-0"><small>Officials with approved accounts will have administrative access to system data and functions.</small></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    </script>
</body>
</html>