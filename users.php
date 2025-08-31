<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

// Role-based user management: Only Admin and Official can manage all users
$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$can_manage_users = ($is_admin || $is_official);

$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$userId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$userData = null;
$success_message = $error_message = '';
$refresh_needed = false;

try {
    $pdo = getDBConnection();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_user') {
        if (!$can_manage_users && $userId != $_SESSION['user_id']) {
            $error_message = "You don't have permission to edit other users";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to edit user', false);
        } else {
            $fullName = trim($_POST['full_name']);
            $username = isset($_POST['username']) ? trim($_POST['username']) : '';
            $email = isset($_POST['email']) ? trim($_POST['email']) : '';
            $role = isset($_POST['role']) ? trim($_POST['role']) : '';
            $password = isset($_POST['password']) ? $_POST['password'] : '';
            $nationalId = isset($_POST['national_id']) ? trim($_POST['national_id']) : '';
            $prsId = isset($_POST['prs_id']) ? trim($_POST['prs_id']) : '';
            $dob = isset($_POST['dob']) ? trim($_POST['dob']) : '';
            
            $errors = [];
            
            if (empty($fullName)) {
                $errors[] = "Full name is required";
            }
            
            // Complex username uniqueness validation excluding current user
            if (!empty($username) && $userId != $_SESSION['user_id']) {
                $usernameCheck = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? AND user_id != ?");
                $usernameCheck->execute([$username, $userId]);
                
                if ($usernameCheck->fetchColumn() > 0) {
                    $errors[] = "Username already exists";
                }
            }
            
            if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Invalid email format";
            }
            
            // Role-based validation: Additional checks for privileged users
            if (hasRole(['Admin', 'Official']) && $userId != $_SESSION['user_id']) {
                $validRoles = ['Admin', 'Official', 'Doctor', 'Merchant', 'Citizen'];
                if (!empty($role) && !in_array($role, $validRoles)) {
                    $errors[] = "Invalid role";
                }
                
                if (!empty($nationalId)) {
                    $nationalIdCheck = $pdo->prepare("SELECT COUNT(*) FROM users WHERE national_id = ? AND user_id != ?");
                    $nationalIdCheck->execute([$nationalId, $userId]);
                    
                    if ($nationalIdCheck->fetchColumn() > 0) {
                        $errors[] = "National ID already exists";
                    }
                }
                
                if (!empty($prsId)) {
                    $prsIdCheck = $pdo->prepare("SELECT COUNT(*) FROM users WHERE prs_id = ? AND user_id != ?");
                    $prsIdCheck->execute([$prsId, $userId]);
                    
                    if ($prsIdCheck->fetchColumn() > 0) {
                        $errors[] = "PRS ID already exists";
                    }
                }
            }
            
            if (empty($errors)) {
                $updateData = [];
                $params = [];
                
                $updateData[] = "full_name = ?";
                $params[] = $fullName;
                
                if (!empty($email)) {
                    $updateData[] = "email = ?";
                    $params[] = $email;
                }
                
                // Role-based field editing permissions
                if (hasRole(['Admin', 'Official']) && $userId != $_SESSION['user_id']) {
                    if (!empty($role)) {
                        $updateData[] = "role = ?";
                        $params[] = $role;
                    }
                    
                    if (!empty($nationalId)) {
                        $updateData[] = "national_id = ?";
                        $params[] = $nationalId;
                    }
                    
                    if (!empty($prsId)) {
                        $updateData[] = "prs_id = ?";
                        $params[] = $prsId;
                    }
                    
                    if (!empty($dob)) {
                        $updateData[] = "dob = ?";
                        $params[] = $dob;
                    }
                    
                    if (!empty($username)) {
                        $updateData[] = "username = ?";
                        $params[] = $username;
                    }
                }
                
                if (!empty($password)) {
                    $updateData[] = "password = ?";
                    $params[] = hashPassword($password);
                }
                
                $params[] = $userId;
                
                $sql = "UPDATE users SET " . implode(", ", $updateData) . " WHERE user_id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                
                if ($stmt->rowCount() > 0) {
                    $success_message = "User updated successfully";
                    logAccess($_SESSION['user_id'], 'Updated user ID: ' . $userId, true);
                } else {
                    $error_message = "No changes were made";
                }
                
                $refresh_needed = true;
            } else {
                $error_message = implode("<br>", $errors);
                
                // Form data preservation for error handling and re-population
                $userData = [
                    'user_id' => $userId,
                    'full_name' => $fullName,
                    'username' => $username,
                    'email' => $email,
                    'role' => $role,
                    'national_id' => $nationalId,
                    'prs_id' => $prsId,
                    'dob' => $dob
                ];
            }
        }
    }
    
    if ($action === 'delete' && $userId > 0) {
        if (!$can_manage_users) {
            $error_message = "You don't have permission to delete users";
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to delete user', false);
        } else {
            // Security: Prevent users from deleting their own account
            if ($userId == $_SESSION['user_id']) {
                $error_message = "You cannot delete your own account!";
            } else {
                // Data integrity: Check foreign key constraints before user deletion
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM vaccination_records WHERE user_id = ?");
                $stmt->execute([$userId]);
                $hasVaccinations = $stmt->fetchColumn() > 0;
                
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM purchases WHERE user_id = ?");
                $stmt->execute([$userId]);
                $hasPurchases = $stmt->fetchColumn() > 0;
                
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM access_logs WHERE user_id = ?");
                $stmt->execute([$userId]);
                $hasLogs = $stmt->fetchColumn() > 0;
                
                if ($hasVaccinations || $hasPurchases || $hasLogs) {
                    $error_message = "Cannot delete user: This user has associated records (vaccinations, purchases, or access logs)";
                } else {
                    $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                    $stmt->execute([$userId]);
                    
                    if ($stmt->rowCount() > 0) {
                        $success_message = "User deleted successfully";
                        logAccess($_SESSION['user_id'], 'Deleted user ID: ' . $userId, true);
                    } else {
                        $error_message = "User not found";
                    }
                }
            }
        }
        
        $action = 'list';
    }
    
    if (($action === 'view' || $action === 'edit') && $userId > 0) {
        if (!$can_manage_users && $userId != $_SESSION['user_id']) {
            $error_message = "You don't have permission to view/edit other users";
            $action = 'list';
            logAccess($_SESSION['user_id'], 'Unauthorized attempt to view/edit user', false);
        } else {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$userId]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$userData) {
                $error_message = "User not found";
                $action = 'list';
            }
        }
    }
    
    if ($action === 'list') {
        $users = [];
        
        if ($can_manage_users) {
            $stmt = $pdo->query("SELECT * FROM users ORDER BY user_id DESC");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            // Restricted user view: Non-privileged users see only their own record
            $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
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
    <title>User Management - COVID Resilience System</title>
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
        
        .user-info-section {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .role-badge {
            font-size: 0.9rem;
            padding: 0.5rem 1rem;
            border-radius: 50px;
        }
        
        .user-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background-color: #e9ecef;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 15px;
        }
        
        .user-avatar i {
            font-size: 60px;
            color: #6c757d;
        }
        
        .read-only-notice {
            background-color: #f8f9fa;
            border-left: 4px solid #0d6efd;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .role-badge-header {
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
                            <span class="role-badge-header role-<?php echo strtolower($_SESSION['role']); ?>"><?php echo $_SESSION['role']; ?></span>
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
                        <a class="nav-link active" href="users.php">
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
                <?php if ($action === 'list'): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-people me-2"></i>User Management</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh List
                        </button>
                        <a href="register.php" class="btn btn-primary">
                            <i class="bi bi-person-plus-fill me-2"></i>Add New User
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

                <?php if (!$can_manage_users): ?>
                <div class="read-only-notice mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-info-circle-fill text-primary me-2 fs-4"></i>
                        <div>
                            <h5 class="mb-1">Restricted Access</h5>
                            <p class="mb-0">As a <?php echo $_SESSION['role']; ?>, you can only see your own user record. Only Officials and Administrators can view and manage all user accounts.</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="card">
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search by name or username..." oninput="filterTable()">
                        </div>

                        <div class="table-responsive">
                            <table id="usersTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">PRS ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Full Name <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">National ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">DOB <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(5)">Role <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(6)">Username <i class="bi bi-arrow-down-up"></i></th>
                                        <?php if ($can_manage_users): ?>
                                        <th>Actions</th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($users)): ?>
                                    <tr><td colspan="<?php echo $can_manage_users ? '8' : '7'; ?>" class="text-center">No users found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($users as $user): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($user['user_id']); ?></td>
                                        <td><?php echo htmlspecialchars($user['prs_id']); ?></td>
                                        <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                                        <td><?php echo htmlspecialchars($user['national_id']); ?></td>
                                        <td><?php echo date('M j, Y', strtotime($user['dob'])); ?></td>
                                        <td>
                                            <?php
                                            $roleBadgeClass = 'bg-secondary';
                                            if ($user['role'] === 'Admin') $roleBadgeClass = 'bg-danger';
                                            if ($user['role'] === 'Official') $roleBadgeClass = 'bg-warning';
                                            if ($user['role'] === 'Doctor') $roleBadgeClass = 'bg-info';
                                            if ($user['role'] === 'Merchant') $roleBadgeClass = 'bg-success';
                                            if ($user['role'] === 'Citizen') $roleBadgeClass = 'bg-primary';
                                            ?>
                                            <span class="badge <?php echo $roleBadgeClass; ?>"><?php echo htmlspecialchars($user['role']); ?></span>
                                        </td>
                                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                                        <?php if ($can_manage_users): ?>
                                        <td>
                                            <button class="btn btn-sm btn-info" onclick="viewUser(<?php echo $user['user_id']; ?>)">
                                                <i class="bi bi-eye"></i>
                                            </button>
                                            <button class="btn btn-sm btn-primary" onclick="editUser(<?php echo $user['user_id']; ?>)">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <?php if ($user['user_id'] != $_SESSION['user_id']): ?>
                                            <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['full_name']); ?>')">
                                                <i class="bi bi-trash"></i>
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
                                Total: <span id="totalUsers"><?php echo count($users); ?></span> user<?php echo count($users) != 1 ? 's' : ''; ?>
                            </div>
                            <div>
                                <button type="button" class="btn btn-secondary" onclick="window.location.reload();">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'view' && $userData): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-person me-2"></i>User Details</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="users.php">Users</a></li>
                                <li class="breadcrumb-item active" aria-current="page">View User</li>
                            </ol>
                        </nav>
                    </div>
                    <div>
                        <a href="users.php?action=edit&id=<?php echo $userId; ?>" class="btn btn-primary">
                            <i class="bi bi-pencil me-2"></i>Edit User
                        </a>
                        <a href="users.php" class="btn btn-secondary ms-2">
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
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3 text-center">
                                <div class="user-avatar mx-auto">
                                    <i class="bi bi-person-fill"></i>
                                </div>
                                
                                <h4><?php echo htmlspecialchars($userData['full_name']); ?></h4>
                                
                                <?php
                                $roleBadgeClass = 'bg-secondary';
                                if ($userData['role'] === 'Admin') $roleBadgeClass = 'bg-danger';
                                if ($userData['role'] === 'Official') $roleBadgeClass = 'bg-warning';
                                if ($userData['role'] === 'Doctor') $roleBadgeClass = 'bg-info';
                                if ($userData['role'] === 'Merchant') $roleBadgeClass = 'bg-success';
                                if ($userData['role'] === 'Citizen') $roleBadgeClass = 'bg-primary';
                                ?>
                                
                                <span class="badge <?php echo $roleBadgeClass; ?> role-badge">
                                    <?php echo htmlspecialchars($userData['role']); ?>
                                </span>
                            </div>
                            
                            <div class="col-md-9">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="user-info-section">
                                            <h5 class="border-bottom pb-2">Account Information</h5>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">User ID:</div>
                                                <div class="col-md-8"><?php echo htmlspecialchars($userData['user_id']); ?></div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">PRS ID:</div>
                                                <div class="col-md-8"><?php echo htmlspecialchars($userData['prs_id']); ?></div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">Username:</div>
                                                <div class="col-md-8"><?php echo htmlspecialchars($userData['username']); ?></div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">Email:</div>
                                                <div class="col-md-8">
                                                    <?php echo !empty($userData['email']) ? 
                                                        htmlspecialchars($userData['email']) : 
                                                        '<span class="text-muted">Not provided</span>'; ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="col-md-6">
                                        <div class="user-info-section">
                                            <h5 class="border-bottom pb-2">Personal Information</h5>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">Full Name:</div>
                                                <div class="col-md-8"><?php echo htmlspecialchars($userData['full_name']); ?></div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">National ID:</div>
                                                <div class="col-md-8"><?php echo htmlspecialchars($userData['national_id']); ?></div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">Date of Birth:</div>
                                                <div class="col-md-8">
                                                    <?php echo date('F j, Y', strtotime($userData['dob'])); ?>
                                                </div>
                                            </div>
                                            
                                            <div class="row mb-3">
                                                <div class="col-md-4 detail-label">Joined:</div>
                                                <div class="col-md-8">
                                                    <?php echo date('F j, Y', strtotime($userData['created_at'])); ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <?php if ($can_manage_users): ?>
                                <div class="mt-4">
                                    <h5 class="border-bottom pb-2">Related Records</h5>
                                    
                                    <div class="row mt-3">
                                        <div class="col-md-3 mb-2">
                                            <a href="vaccination_records.php?user_id=<?php echo $userData['user_id']; ?>" class="btn btn-outline-primary w-100">
                                                <i class="bi bi-clipboard2-pulse me-2"></i>Vaccination Records
                                            </a>
                                        </div>
                                        <div class="col-md-3 mb-2">
                                            <a href="purchases.php?user_id=<?php echo $userData['user_id']; ?>" class="btn btn-outline-primary w-100">
                                                <i class="bi bi-cart me-2"></i>Purchase History
                                            </a>
                                        </div>
                                        <div class="col-md-3 mb-2">
                                            <a href="view_documents.php?user_id=<?php echo $userData['user_id']; ?>" class="btn btn-outline-primary w-100">
                                                <i class="bi bi-file-earmark-text me-2"></i>Documents
                                            </a>
                                        </div>
                                        <div class="col-md-3 mb-2">
                                            <a href="access_logs.php?user_id=<?php echo $userData['user_id']; ?>" class="btn btn-outline-primary w-100">
                                                <i class="bi bi-activity me-2"></i>Activity Logs
                                            </a>
                                        </div>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card-footer bg-light">
                        <div class="d-flex justify-content-between">
                            <a href="users.php" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left me-1"></i> Back to Users
                            </a>
                            <div>
                                <a href="users.php?action=edit&id=<?php echo $userId; ?>" class="btn btn-outline-primary">
                                    <i class="bi bi-pencil me-1"></i> Edit
                                </a>
                                <?php if ($can_manage_users && $userId != $_SESSION['user_id']): ?>
                                <button type="button" class="btn btn-outline-danger ms-2" 
                                        onclick="confirmDelete(<?php echo $userId; ?>, '<?php echo htmlspecialchars(addslashes($userData['full_name'])); ?>')">
                                    <i class="bi bi-trash me-1"></i> Delete
                                </button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php elseif ($action === 'edit' && $userData): ?>
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2><i class="bi bi-person-gear me-2"></i>Edit User</h2>
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="users.php">Users</a></li>
                                <li class="breadcrumb-item active" aria-current="page">Edit User</li>
                            </ol>
                        </nav>
                    </div>
                    <a href="users.php" class="btn btn-secondary">
                        <i class="bi bi-arrow-left me-2"></i>Back to Users List
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
                        <h5 class="mb-0"><i class="bi bi-pencil-square me-2"></i>Edit User: <?php echo htmlspecialchars($userData['full_name']); ?></h5>
                    </div>
                    <div class="card-body">
                        <form action="users.php?action=edit&id=<?php echo $userId; ?>" method="POST">
                            <input type="hidden" name="action" value="edit_user">
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <h5 class="border-bottom pb-2 mb-3">Account Information</h5>
                                    
                                    <div class="mb-3">
                                        <label for="full_name" class="form-label">Full Name</label>
                                        <input type="text" class="form-control" id="full_name" name="full_name" 
                                               value="<?php echo htmlspecialchars($userData['full_name']); ?>" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="username" class="form-label">Username</label>
                                        <input type="text" class="form-control" id="username" name="username" 
                                               value="<?php echo htmlspecialchars($userData['username']); ?>"
                                               <?php echo $userId == $_SESSION['user_id'] ? 'readonly' : ''; ?>>
                                        <?php if ($userId == $_SESSION['user_id']): ?>
                                            <div class="form-text">You cannot change your own username</div>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email</label>
                                        <input type="email" class="form-control" id="email" name="email" 
                                               value="<?php echo htmlspecialchars($userData['email'] ?? ''); ?>">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="password" class="form-label">Password</label>
                                        <input type="password" class="form-control" id="password" name="password" 
                                               placeholder="Leave blank to keep current password">
                                        <div class="form-text">Only enter a new password if you want to change it</div>
                                    </div>
                                </div>
                                
                                <div class="col-md-6">
                                    <h5 class="border-bottom pb-2 mb-3">Personal Information</h5>
                                    
                                    <?php if ($can_manage_users && $userId != $_SESSION['user_id']): ?>
                                    <div class="mb-3">
                                        <label for="role" class="form-label">Role</label>
                                        <select class="form-select" id="role" name="role">
                                            <option value="">Select Role</option>
                                            <option value="Citizen" <?php echo $userData['role'] === 'Citizen' ? 'selected' : ''; ?>>Citizen</option>
                                            <option value="Merchant" <?php echo $userData['role'] === 'Merchant' ? 'selected' : ''; ?>>Merchant</option>
                                            <option value="Doctor" <?php echo $userData['role'] === 'Doctor' ? 'selected' : ''; ?>>Doctor</option>
                                            <option value="Official" <?php echo $userData['role'] === 'Official' ? 'selected' : ''; ?>>Official</option>
                                            <option value="Admin" <?php echo $userData['role'] === 'Admin' ? 'selected' : ''; ?>>Admin</option>
                                        </select>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="prs_id" class="form-label">PRS ID</label>
                                        <input type="text" class="form-control" id="prs_id" name="prs_id" 
                                               value="<?php echo htmlspecialchars($userData['prs_id']); ?>">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="national_id" class="form-label">National ID</label>
                                        <input type="text" class="form-control" id="national_id" name="national_id" 
                                               value="<?php echo htmlspecialchars($userData['national_id']); ?>">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="dob" class="form-label">Date of Birth</label>
                                        <input type="date" class="form-control" id="dob" name="dob" 
                                               value="<?php echo date('Y-m-d', strtotime($userData['dob'])); ?>">
                                    </div>
                                    <?php else: ?>
                                    <div class="mb-3">
                                        <label for="role" class="form-label">Role</label>
                                        <input type="text" class="form-control" value="<?php echo htmlspecialchars($userData['role']); ?>" readonly>
                                        <div class="form-text">Role can only be changed by administrators and officials</div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="prs_id" class="form-label">PRS ID</label>
                                        <input type="text" class="form-control" value="<?php echo htmlspecialchars($userData['prs_id']); ?>" readonly>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="national_id" class="form-label">National ID</label>
                                        <input type="text" class="form-control" value="<?php echo htmlspecialchars($userData['national_id']); ?>" readonly>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="dob" class="form-label">Date of Birth</label>
                                        <input type="date" class="form-control" value="<?php echo date('Y-m-d', strtotime($userData['dob'])); ?>" readonly>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                                <a href="users.php?action=view&id=<?php echo $userId; ?>" class="btn btn-outline-secondary me-md-2">
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
    
    const allRows = Array.from(document.querySelectorAll('#usersTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        allRows.forEach(row => {
            const name = row.cells[2]?.textContent.toLowerCase() || '';
            const username = row.cells[6]?.textContent.toLowerCase() || '';
            const prsId = row.cells[1]?.textContent.toLowerCase() || '';
            const nationalId = row.cells[3]?.textContent.toLowerCase() || '';
            
            if (name.includes(filter) || 
                username.includes(filter) || 
                prsId.includes(filter) || 
                nationalId.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
        
        updateFilterCount();
    }
    
    function updateFilterCount() {
        const visibleRows = allRows.filter(row => row.style.display !== 'none').length;
        document.getElementById('totalUsers').textContent = visibleRows;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('usersTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1) return;
        
        rows.sort((a, b) => {
            let aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            let bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Dynamic table sorting with special handling for role badges and dates
            if (colIndex === 5) {
                aValue = a.cells[colIndex]?.querySelector('.badge')?.textContent.toLowerCase() || '';
                bValue = b.cells[colIndex]?.querySelector('.badge')?.textContent.toLowerCase() || '';
            }
            
            if (colIndex === 4) {
                return new Date(aValue) - new Date(bValue);
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
    
    <?php if ($can_manage_users): ?>
    function viewUser(id) {
        window.location.href = `users.php?action=view&id=${id}`;
    }
    
    function editUser(id) {
        window.location.href = `users.php?action=edit&id=${id}`;
    }
    
    function confirmDelete(id, name) {
        const currentSession = <?php echo json_encode($_SESSION['user_id']); ?>;
        
        if (id == currentSession) {
            alert("You cannot delete your own account!");
            return;
        }
        
        if (confirm(`Are you sure you want to delete user "${name}"?`)) {
            window.location.href = `users.php?action=delete&id=${id}`;
        }
    }
    <?php endif; ?>
    </script>
</body>
</html>