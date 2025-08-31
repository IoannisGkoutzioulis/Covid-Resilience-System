<?php
require_once 'config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function checkLogin() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        $current_page = basename($_SERVER['PHP_SELF']);
        
        echo "
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>Access Denied - COVID Resilience System</title>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
            <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
            <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css'>
            <meta http-equiv='refresh' content='3;url=login.php'>
            <style>
                body {
                    background: #e9f2fb;
                    font-family: 'Segoe UI', sans-serif;
                }
                .login-card {
                    max-width: 400px;
                    margin: auto;
                    margin-top: 10vh;
                    padding: 2rem;
                    border-radius: 16px;
                    background: white;
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
                }
                .login-title {
                    font-weight: bold;
                    color: #0d6efd;
                }
            </style>
        </head>
        <body>
            <div class='login-card text-center'>
                <h3 class='login-title mb-4'>COVID Resilience System</h3>
                <div class='alert alert-warning' role='alert'>
                    <i class='bi bi-exclamation-triangle-fill me-2'></i>
                    You must log in to access this page. Redirecting to login...
                </div>
                <div class='text-muted small'>If you're not redirected automatically, <a href='login.php'>click here</a>.</div>
            </div>
            <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>
        </body>
        </html>";
        exit();
    }
    
    logAccess($_SESSION['user_id'], 'Page Access: ' . basename($_SERVER['PHP_SELF']));
    
    return true;
}

// Support both single role and array of roles for flexible permission checking
function hasRole($required_role) {
    if (!isset($_SESSION['role'])) {
        return false;
    }
    
    if (is_array($required_role)) {
        return in_array($_SESSION['role'], $required_role);
    }
    
    return $_SESSION['role'] === $required_role;
}

function checkLoginWithMerchantApproval() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header("Location: login.php");
        exit();
    }
    
    if (isset($_SESSION['role']) && $_SESSION['role'] === 'Merchant') {
        $approval = getMerchantApprovalStatus($_SESSION['user_id']);
        
        if (!$approval['approved']) {
            logAccess($_SESSION['user_id'], 'Unauthorized Access Attempt (Unapproved Merchant)', false);
            
            // Security: Destroy session to prevent unauthorized access attempts
            session_destroy();
            header("Location: login.php?error=merchant_not_approved&message=" . urlencode($approval['message']));
            exit();
        }
    }
    
    logAccess($_SESSION['user_id'], 'Page Access: ' . basename($_SERVER['PHP_SELF']));
    
    return true;
}

function checkLoginWithOfficialApproval() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header("Location: login.php");
        exit();
    }
    
    if (isset($_SESSION['role']) && $_SESSION['role'] === 'Official') {
        $approval = getOfficialApprovalStatus($_SESSION['user_id']);
        
        if (!$approval['approved']) {
            logAccess($_SESSION['user_id'], 'Unauthorized Access Attempt (Unapproved Official)', false);
            
            // Security: Destroy session to prevent unauthorized access attempts
            session_destroy();
            header("Location: login.php?error=official_not_approved&message=" . urlencode($approval['message']));
            exit();
        }
    }
    
    logAccess($_SESSION['user_id'], 'Page Access: ' . basename($_SERVER['PHP_SELF']));
    
    return true;
}

// Enhanced approval system: Check both merchant and official approval status
function checkLoginWithApprovalSystem() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header("Location: login.php");
        exit();
    }
    
    $user_role = $_SESSION['role'] ?? '';
    
    if ($user_role === 'Merchant') {
        $approval = getMerchantApprovalStatus($_SESSION['user_id']);
        
        if (!$approval['approved']) {
            logAccess($_SESSION['user_id'], 'Unauthorized Access Attempt (Unapproved Merchant)', false);
            session_destroy();
            header("Location: login.php?error=merchant_not_approved&message=" . urlencode($approval['message']));
            exit();
        }
    }
    
    if ($user_role === 'Official') {
        $approval = getOfficialApprovalStatus($_SESSION['user_id']);
        
        if (!$approval['approved']) {
            logAccess($_SESSION['user_id'], 'Unauthorized Access Attempt (Unapproved Official)', false);
            session_destroy();
            header("Location: login.php?error=official_not_approved&message=" . urlencode($approval['message']));
            exit();
        }
    }
    
    logAccess($_SESSION['user_id'], 'Page Access: ' . basename($_SERVER['PHP_SELF']));
    
    return true;
}

function requireLogin($redirect_url = 'login.php') {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header("Location: $redirect_url");
        exit();
    }
}

function requireRole($required_roles, $redirect_url = 'dashboard.php') {
    requireLogin();
    
    if (!hasRole($required_roles)) {
        $_SESSION['error_message'] = "Access denied. You don't have the required permissions.";
        header("Location: $redirect_url");
        exit();
    }
}

function isCurrentUserApprovedMerchant() {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Merchant') {
        return false;
    }
    
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    
    $approval = getMerchantApprovalStatus($_SESSION['user_id']);
    return $approval['approved'];
}

function isCurrentUserApprovedOfficial() {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Official') {
        return false;
    }
    
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    
    $approval = getOfficialApprovalStatus($_SESSION['user_id']);
    return $approval['approved'];
}

function getCurrentUser() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        return null;
    }
    
    return [
        'user_id' => $_SESSION['user_id'] ?? null,
        'username' => $_SESSION['username'] ?? null,
        'role' => $_SESSION['role'] ?? null,
        'prs_id' => $_SESSION['prs_id'] ?? null,
        'full_name' => $_SESSION['full_name'] ?? null
    ];
}
?>