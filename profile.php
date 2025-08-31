<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$success_message = $error_message = '';
$user_data = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_profile') {
    $full_name = sanitizeInput($_POST['full_name']);
    $email = sanitizeInput($_POST['email']);
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    $errors = [];
    if (empty($full_name)) {
        $errors[] = "Full name is required";
    }
    
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Valid email is required";
    }
    
    // Password change validation: Ensure current password provided for security
    $change_password = false;
    if (!empty($new_password) || !empty($confirm_password)) {
        if (empty($current_password)) {
            $errors[] = "Current password is required to set a new password";
        }
        
        if (empty($new_password)) {
            $errors[] = "New password is required";
        } elseif (strlen($new_password) < 8) {
            $errors[] = "New password must be at least 8 characters long";
        }
        
        if ($new_password !== $confirm_password) {
            $errors[] = "New password and confirmation do not match";
        }
        
        $change_password = true;
    }
    
    if (empty($errors)) {
        try {
            $pdo = getDBConnection();
            
            // Security: Verify current password before allowing changes
            if ($change_password) {
                $stmt = $pdo->prepare("SELECT password FROM users WHERE user_id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $stored_hash = $stmt->fetchColumn();
                
                if (!password_verify($current_password, $stored_hash)) {
                    $error_message = "Current password is incorrect";
                    goto skip_update;
                }
                
                $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
            }
            
            if ($change_password) {
                $stmt = $pdo->prepare("UPDATE users SET full_name = ?, email = ?, password = ? WHERE user_id = ?");
                $result = $stmt->execute([$full_name, $email, $new_password_hash, $_SESSION['user_id']]);
            } else {
                $stmt = $pdo->prepare("UPDATE users SET full_name = ?, email = ? WHERE user_id = ?");
                $result = $stmt->execute([$full_name, $email, $_SESSION['user_id']]);
            }
            
            if ($result) {
                // Update session to reflect profile changes
                $_SESSION['full_name'] = $full_name;
                $_SESSION['email'] = $email;
                
                $success_message = "Profile updated successfully!";
            } else {
                $error_message = "Failed to update profile";
            }
        } catch (PDOException $e) {
            $error_message = "Database error: " . $e->getMessage();
        }
    } else {
        $error_message = "Please correct the following errors: " . implode(", ", $errors);
    }
    
    skip_update:
}

try {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = "Error fetching user data: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - COVID Resilience System</title>
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
        
        .profile-header {
            background-color: #f5f5f5;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background-color: #0d6efd;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            margin-bottom: 15px;
        }
        
        .form-password-toggle {
            position: relative;
        }
        
        .password-toggle-icon {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            z-index: 10;
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
                        <a class="nav-link active" href="profile.php">
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
                    <h2><i class="bi bi-person-gear me-2"></i>My Profile</h2>
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
                    <div class="col-md-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <div class="profile-avatar mx-auto">
                                    <i class="bi bi-person"></i>
                                </div>
                                <h4 class="mb-1"><?php echo htmlspecialchars($user_data['full_name']); ?></h4>
                                <p class="text-muted mb-3"><?php echo htmlspecialchars($user_data['role']); ?></p>
                                
                                <div class="border-top pt-3 mt-3">
                                    <div class="row text-start">
                                        <div class="col-6 text-end text-muted">ID:</div>
                                        <div class="col-6 text-start"><?php echo htmlspecialchars($user_data['prs_id']); ?></div>
                                    </div>
                                    <div class="row text-start mt-2">
                                        <div class="col-6 text-end text-muted">Username:</div>
                                        <div class="col-6 text-start"><?php echo htmlspecialchars($user_data['username']); ?></div>
                                    </div>
                                    <div class="row text-start mt-2">
                                        <div class="col-6 text-end text-muted">Email:</div>
                                        <div class="col-6 text-start"><?php echo htmlspecialchars($user_data['email'] ?? 'Not set'); ?></div>
                                    </div>
                                    <div class="row text-start mt-2">
                                        <div class="col-6 text-end text-muted">National ID:</div>
                                        <div class="col-6 text-start"><?php echo htmlspecialchars($user_data['national_id']); ?></div>
                                    </div>
                                    <div class="row text-start mt-2">
                                        <div class="col-6 text-end text-muted">Date of Birth:</div>
                                        <div class="col-6 text-start"><?php echo htmlspecialchars(date('d M Y', strtotime($user_data['dob']))); ?></div>
                                    </div>
                                </div>
                                
                                <div class="mt-4">
                                    <a href="#editProfile" class="btn btn-primary" data-bs-toggle="collapse" role="button" aria-expanded="false" aria-controls="editProfile">
                                        <i class="bi bi-pencil-square me-2"></i>Edit Profile
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-8 mb-4">
                        <div class="collapse" id="editProfile">
                            <div class="card">
                                <div class="card-header bg-primary text-white">
                                    <h5 class="mb-0"><i class="bi bi-pencil-square me-2"></i>Edit Profile</h5>
                                </div>
                                <div class="card-body">
                                    <form action="profile.php" method="POST">
                                        <input type="hidden" name="action" value="update_profile">
                                        
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <label for="full_name" class="form-label">Full Name</label>
                                                <input type="text" class="form-control" id="full_name" name="full_name" value="<?php echo htmlspecialchars($user_data['full_name']); ?>" required>
                                            </div>
                                            <div class="col-md-6">
                                                <label for="email" class="form-label">Email</label>
                                                <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user_data['email'] ?? ''); ?>">
                                            </div>
                                        </div>
                                        
                                        <hr>
                                        <h5 class="mb-3">Change Password</h5>
                                        <p class="text-muted small mb-3">Leave these fields blank if you don't want to change your password</p>
                                        
                                        <div class="mb-3 form-password-toggle">
                                            <label for="current_password" class="form-label">Current Password</label>
                                            <div class="input-group">
                                                <input type="password" class="form-control" id="current_password" name="current_password">
                                                <span class="input-group-text password-toggle" data-target="current_password">
                                                    <i class="bi bi-eye"></i>
                                                </span>
                                            </div>
                                        </div>
                                        
                                        <div class="row mb-3">
                                            <div class="col-md-6 form-password-toggle">
                                                <label for="new_password" class="form-label">New Password</label>
                                                <div class="input-group">
                                                    <input type="password" class="form-control" id="new_password" name="new_password">
                                                    <span class="input-group-text password-toggle" data-target="new_password">
                                                        <i class="bi bi-eye"></i>
                                                    </span>
                                                </div>
                                                <div class="form-text">Minimum 8 characters</div>
                                            </div>
                                            <div class="col-md-6 form-password-toggle">
                                                <label for="confirm_password" class="form-label">Confirm New Password</label>
                                                <div class="input-group">
                                                    <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                                                    <span class="input-group-text password-toggle" data-target="confirm_password">
                                                        <i class="bi bi-eye"></i>
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="d-flex justify-content-end mt-4">
                                            <button type="button" class="btn btn-secondary me-2" data-bs-toggle="collapse" data-bs-target="#editProfile">
                                                Cancel
                                            </button>
                                            <button type="submit" class="btn btn-primary">
                                                <i class="bi bi-save me-2"></i>Save Changes
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card h-100">
                            <div class="card-header bg-light">
                                <h5 class="mb-0"><i class="bi bi-clock-history me-2"></i>Recent Activity</h5>
                            </div>
                            <div class="card-body">
                                <?php
                                try {
                                    $pdo = getDBConnection();
                                    $stmt = $pdo->prepare("SELECT * FROM access_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5");
                                    $stmt->execute([$_SESSION['user_id']]);
                                    $recent_logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
                                    
                                    if (count($recent_logs) > 0):
                                ?>
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Activity</th>
                                                <th>Date/Time</th>
                                                <th>IP Address</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($recent_logs as $log): ?>
                                            <tr>
                                                <td>
                                                    <?php
                                                    // Activity type icon mapping
                                                    $icon = 'bi-activity';
                                                    $activity = $log['access_type'];
                                                    
                                                    if (stripos($activity, 'login') !== false) {
                                                        $icon = 'bi-box-arrow-in-right';
                                                    } elseif (stripos($activity, 'logout') !== false) {
                                                        $icon = 'bi-box-arrow-left';
                                                    } elseif (stripos($activity, 'view') !== false) {
                                                        $icon = 'bi-eye';
                                                    } elseif (stripos($activity, 'edit') !== false || stripos($activity, 'update') !== false) {
                                                        $icon = 'bi-pencil';
                                                    } elseif (stripos($activity, 'add') !== false || stripos($activity, 'create') !== false) {
                                                        $icon = 'bi-plus-circle';
                                                    } elseif (stripos($activity, 'delete') !== false) {
                                                        $icon = 'bi-trash';
                                                    } elseif (stripos($activity, 'download') !== false) {
                                                        $icon = 'bi-download';
                                                    } elseif (stripos($activity, 'upload') !== false) {
                                                        $icon = 'bi-upload';
                                                    }
                                                    ?>
                                                    <i class="bi <?php echo $icon; ?> me-2"></i>
                                                    <?php echo htmlspecialchars($activity); ?>
                                                </td>
                                                <td><?php echo htmlspecialchars(date('d M Y H:i', strtotime($log['timestamp']))); ?></td>
                                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                                <?php else: ?>
                                <p class="text-center text-muted">No recent activity found</p>
                                <?php 
                                    endif;
                                } catch (PDOException $e) {
                                    echo '<p class="text-danger">Error fetching activity logs: ' . htmlspecialchars($e->getMessage()) . '</p>';
                                }
                                ?>
                                
                                <div class="text-center mt-3">
                                    <a href="access_logs.php" class="btn btn-outline-primary btn-sm">
                                        <i class="bi bi-list-ul me-2"></i>View All Activity
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const toggleButtons = document.querySelectorAll('.password-toggle');
        toggleButtons.forEach(button => {
            button.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const input = document.getElementById(targetId);
                const icon = this.querySelector('i');
                
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                } else {
                    input.type = 'password';
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
            });
        });
        
        // Auto-show edit profile on password errors
        <?php if (!empty($error_message) && strpos($error_message, 'password') !== false): ?>
        const editProfileSection = document.getElementById('editProfile');
        if (editProfileSection) {
            const bsCollapse = new bootstrap.Collapse(editProfileSection, {
                toggle: true
            });
        }
        <?php endif; ?>
    });
    </script>
</body>
</html>