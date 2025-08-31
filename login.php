<?php
require_once 'config.php';

// Auto-creates admin account on every login page visit to ensure system access
function ensureAdminAccountExists() {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return;
        }
        
        $stmt = $pdo->prepare("SELECT user_id, username, password FROM users WHERE username = 'admin' AND role = 'Admin'");
        $stmt->execute();
        $admin_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $working_hash = password_hash('admin', PASSWORD_DEFAULT);
        
        if (!$admin_user) {
            $stmt = $pdo->prepare("
                INSERT INTO users (prs_id, full_name, national_id, dob, role, username, password, email, city, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ");
            
            $stmt->execute([
                'ADM0001',
                'System Administrator',
                '0000000001',
                '1980-01-01',
                'Admin',
                'admin',
                $working_hash,
                'admin@covid-system.com',
                'System'
            ]);
            
            error_log("Admin account created automatically on login page visit");
            
        } else {
            // Verify password still works, fix if broken
            if (!password_verify('admin', $admin_user['password'])) {
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE user_id = ?");
                $stmt->execute([$working_hash, $admin_user['user_id']]);
                
                error_log("Admin password fixed automatically on login page visit");
            }
        }
        
    } catch (Exception $e) {
        error_log("Auto admin creation error: " . $e->getMessage());
    }
}

ensureAdminAccountExists();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header("Location: dashboard.php");
    exit();
}

$username = $password = '';
$login_error = '';

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = sanitizeInput($_POST["username"]);
    $password = $_POST["password"];
    
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            $login_error = "Database connection failed. Please try again later.";
        } else {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password'])) {
                
                // Merchants require approval before login
                if ($user['role'] === 'Merchant') {
                    $approval_status = getMerchantApprovalStatus($user['user_id']);
                    
                    if (!$approval_status['approved']) {
                        logAccess($user['user_id'], 'Unapproved Merchant Login Attempt', false);
                        
                        switch ($approval_status['status']) {
                            case 'Pending':
                                $login_error = "Your merchant account is pending approval. Please wait for an official to approve your account before logging in.";
                                break;
                            case 'Rejected':
                                $login_error = "Your merchant account has been rejected. Reason: " . ($approval_status['rejection_reason'] ?? 'Contact an administrator for more information.');
                                break;
                            case 'NotFound':
                                $login_error = "Your merchant profile was not found. Please contact an administrator.";
                                break;
                            default:
                                $login_error = "Your merchant account is not approved for login. Please contact an administrator.";
                        }
                    } else {
                        proceedWithLogin($user, $pdo);
                    }
                } elseif ($user['role'] === 'Official') {
                    // Officials require admin approval before login
                    $approval_status = getOfficialApprovalStatus($user['user_id']);
                    
                    if (!$approval_status['approved']) {
                        logAccess($user['user_id'], 'Unapproved Official Login Attempt', false);
                        
                        switch ($approval_status['status']) {
                            case 'Pending':
                                $login_error = "Your official account is pending approval. Please wait for an administrator to approve your account before logging in.";
                                break;
                            case 'Rejected':
                                $login_error = "Your official account has been rejected. Reason: " . ($approval_status['rejection_reason'] ?? 'Contact an administrator for more information.');
                                break;
                            case 'NotFound':
                                $login_error = "Your official profile was not found. Please contact an administrator.";
                                break;
                            default:
                                $login_error = "Your official account is not approved for login. Please contact an administrator.";
                        }
                    } else {
                        proceedWithLogin($user, $pdo);
                    }
                } else {
                    // Other roles (Citizen, Admin, Doctor) don't require approval
                    proceedWithLogin($user, $pdo);
                }
            } else {
                // Log failed attempts for security monitoring
                if ($user) {
                    logAccess($user['user_id'], 'Failed Login Attempt - Invalid Password', false);
                } else {
                    logAccess(null, 'Failed Login Attempt - Invalid Username: ' . $username, false);
                }
                
                $login_error = "Invalid username or password";
            }
        }
    } catch (PDOException $e) {
        error_log("Login error: " . $e->getMessage());
        $login_error = "System error occurred. Please try again later.";
    }
}

function proceedWithLogin($user, $pdo) {
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['prs_id'] = $user['prs_id'];
    $_SESSION['full_name'] = $user['full_name'];
    $_SESSION['logged_in'] = true;
    
    logAccess($user['user_id'], 'Login', true);
    
    // Role-based dashboard redirection
    switch ($user['role']) {
        case 'Admin':
            header("Location: dashboard.php?section=admin");
            break;
        case 'Official':
            header("Location: dashboard.php?section=official");
            break;
        case 'Merchant':
            header("Location: dashboard.php?section=merchant");
            break;
        case 'Citizen':
            header("Location: dashboard.php?section=citizen");
            break;
        case 'Doctor':
            header("Location: dashboard.php?section=doctor");
            break;
        default:
            header("Location: dashboard.php");
            break;
    }
    exit();
}

if (isset($_SESSION['error_message'])) {
    unset($_SESSION['error_message']);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login - COVID Resilience System</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
  <style>
    body {
      background: #e9f2fb;
      font-family: 'Segoe UI', sans-serif;
      padding-top: 50px;
    }
    .login-card {
      max-width: 400px;
      margin: auto;
      padding: 2rem;
      border-radius: 16px;
      background: white;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
    }
    .login-title {
      font-weight: bold;
      color: #0d6efd;
    }
    .form-control:focus {
      box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
    }
    .register-link {
      margin-top: 1rem;
      text-align: center;
    }
    .covid-icon {
      font-size: 3rem;
      color: #0d6efd;
      margin-bottom: 1rem;
    }
    
    .admin-status {
      position: fixed;
      bottom: 10px;
      right: 10px;
      background: rgba(0,0,0,0.7);
      color: white;
      padding: 5px 10px;
      border-radius: 15px;
      font-size: 12px;
      z-index: 1000;
      display: none;
    }
  </style>
</head>
<body>

  <div class="container">
    <div class="login-card">
      <div class="text-center mb-4">
        <i class="bi bi-shield-fill-check covid-icon"></i>
        <h3 class="login-title">COVID Resilience System</h3>
        <p class="text-muted">Secure access to system resources</p>
      </div>

      <?php if (!empty($login_error)): ?>
      <div class="alert alert-danger alert-dismissible fade show mt-2" role="alert">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <?php echo htmlspecialchars($login_error); ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
      <?php endif; ?>
      
      <?php if (isset($_GET['logout']) && $_GET['logout'] === 'success'): ?>
      <div class="alert alert-success alert-dismissible fade show mt-2" role="alert">
        <i class="bi bi-check-circle-fill me-2"></i>
        You have been successfully logged out.
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
      <?php endif; ?>
      
      <?php if (isset($_GET['registration']) && $_GET['registration'] === 'success'): ?>
      <div class="alert alert-success alert-dismissible fade show mt-2" role="alert">
        <i class="bi bi-check-circle-fill me-2"></i>
        Registration successful! Your PRS ID is: <strong><?php echo htmlspecialchars($_GET['prs_id'] ?? ''); ?></strong><br>
        <?php if (isset($_GET['role']) && $_GET['role'] === 'Merchant'): ?>
        <strong>Note:</strong> Your merchant account is pending approval. You will be able to login once an official approves your account.
        <?php elseif (isset($_GET['role']) && $_GET['role'] === 'Official'): ?>
        <strong>Note:</strong> Your official account is pending approval. You will be able to login once an administrator approves your account.
        <?php else: ?>
        Please login with your new credentials.
        <?php endif; ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
      <?php endif; ?>

      <?php if (isset($_GET['approved']) && $_GET['approved'] === 'success'): ?>
      <div class="alert alert-success alert-dismissible fade show mt-2" role="alert">
        <i class="bi bi-check-circle-fill me-2"></i>
        <?php if (isset($_GET['role']) && $_GET['role'] === 'merchant'): ?>
        Great news! Your merchant account has been approved. You can now login and access all merchant features.
        <?php elseif (isset($_GET['role']) && $_GET['role'] === 'official'): ?>
        Great news! Your official account has been approved. You can now login and access all official features.
        <?php else: ?>
        Your account has been approved. You can now login.
        <?php endif; ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
      <?php endif; ?>

      <form action="login.php" method="POST" id="loginForm">
        <div class="mb-3">
          <label for="username" class="form-label"><i class="bi bi-person-fill me-1"></i> Username</label>
          <input type="text" class="form-control" id="username" name="username" 
                 value="<?php echo htmlspecialchars($username); ?>"
                 placeholder="Enter your username" required>
        </div>
        <div class="mb-3">
          <label for="password" class="form-label"><i class="bi bi-lock-fill me-1"></i> Password</label>
          <input type="password" class="form-control" id="password" name="password" placeholder="Enter your password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">
          <i class="bi bi-box-arrow-in-right me-1"></i> Login
        </button>
      </form>

      <div class="register-link">
        <p class="mt-3 mb-0">Don't have an account? <a href="register.php">Register here</a></p>
      </div>
      
      <div class="text-center mt-3">
        <small class="text-muted">
          <i class="bi bi-info-circle me-1"></i>
          System administrators can use the default admin credentials
        </small>
      </div>
    </div>
  </div>

  <div class="admin-status" id="adminStatus">
    ✅ Admin account ready
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
        const adminStatus = document.getElementById('adminStatus');
        adminStatus.style.display = 'block';
        setTimeout(function() {
            adminStatus.style.display = 'none';
        }, 3000);
    });
    
    // Triple-click title to auto-fill admin credentials (testing convenience)
    document.querySelector('.login-title').addEventListener('click', function(e) {
        if (e.detail === 3) {
            document.getElementById('username').value = 'admin';
            document.getElementById('password').value = 'admin';
        }
    });
  </script>
</body>
</html>