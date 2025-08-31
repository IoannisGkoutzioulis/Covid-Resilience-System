<?php

// Database configuration - UPDATE THESE VALUES FOR YOUR SETUP
define('DB_HOST', 'localhost');
define('DB_NAME', 'PRS_System');
define('DB_USER', 'root');              // Change this to your database username
define('DB_PASS', '');                  // Change this to your database password
define('DB_CHARSET', 'utf8mb4');

// Error reporting for development (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

function getDBConnection() {
    try {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        return null;
    }
}

function sanitizeInput($data) {
    if ($data === null) return '';
    return htmlspecialchars(strip_tags(trim($data)));
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function logAccess($user_id, $access_type, $success = true, $additional_info = null) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            error_log("Cannot log access - database connection failed");
            return;
        }
        
        $stmt = $pdo->prepare(
            "INSERT INTO access_logs (user_id, access_type, ip_address, location, success, additional_info) 
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        
        $stmt->execute([
            $user_id,
            $access_type,
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'Web Application',
            $success ? 1 : 0,
            $additional_info
        ]);
        
    } catch (Exception $e) {
        error_log("Failed to log access: " . $e->getMessage());
    }
}

function getMerchantApprovalStatus($user_id) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['approved' => false, 'status' => 'Unknown', 'message' => 'Database connection failed'];
        }
        
        $stmt = $pdo->prepare("SELECT status, approved_by, approved_at, rejection_reason FROM merchants WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $merchant = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$merchant) {
            return ['approved' => false, 'status' => 'NotFound', 'message' => 'Merchant profile not found'];
        }
        
        $status = $merchant['status'];
        $approved = ($status === 'Approved');
        
        // Status message mapping
        $messages = [
            'Pending' => 'Your merchant account is pending approval. Please wait for an official to approve your account.',
            'Rejected' => 'Your merchant account has been rejected. Reason: ' . ($merchant['rejection_reason'] ?? 'No reason provided'),
            'Approved' => 'Your merchant account is approved and active.'
        ];
        
        return [
            'approved' => $approved,
            'status' => $status,
            'message' => $messages[$status] ?? 'Unknown merchant status',
            'approved_by' => $merchant['approved_by'],
            'approved_at' => $merchant['approved_at'],
            'rejection_reason' => $merchant['rejection_reason']
        ];
        
    } catch (Exception $e) {
        error_log("Error checking merchant approval: " . $e->getMessage());
        return ['approved' => false, 'status' => 'Error', 'message' => 'Error checking merchant status'];
    }
}

function getOfficialApprovalStatus($user_id) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['approved' => false, 'status' => 'Unknown', 'message' => 'Database connection failed'];
        }
        
        $stmt = $pdo->prepare("SELECT status, approved_by, approved_at, rejection_reason FROM government_officials WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $official = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$official) {
            return ['approved' => false, 'status' => 'NotFound', 'message' => 'Official profile not found'];
        }
        
        $status = $official['status'];
        $approved = ($status === 'Approved');
        
        $messages = [
            'Pending' => 'Your official account is pending approval. Please wait for an administrator to approve your account.',
            'Rejected' => 'Your official account has been rejected. Reason: ' . ($official['rejection_reason'] ?? 'No reason provided'),
            'Approved' => 'Your official account is approved and active.'
        ];
        
        return [
            'approved' => $approved,
            'status' => $status,
            'message' => $messages[$status] ?? 'Unknown official status',
            'approved_by' => $official['approved_by'],
            'approved_at' => $official['approved_at'],
            'rejection_reason' => $official['rejection_reason']
        ];
        
    } catch (Exception $e) {
        error_log("Error checking official approval: " . $e->getMessage());
        return ['approved' => false, 'status' => 'Error', 'message' => 'Error checking official status'];
    }
}

// Merchant approval workflow with transaction handling
function updateMerchantApproval($merchant_id, $action, $approved_by, $rejection_reason = null) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return false;
        }
        
        $pdo->beginTransaction();
        
        if ($action === 'approve') {
            $stmt = $pdo->prepare(
                "UPDATE merchants SET status = 'Approved', approved_by = ?, approved_at = NOW(), rejection_reason = NULL 
                 WHERE merchant_id = ?"
            );
            $result = $stmt->execute([$approved_by, $merchant_id]);
            
            if ($result) {
                logAccess($approved_by, "Approved merchant ID: $merchant_id", true);
            }
            
        } elseif ($action === 'reject') {
            $stmt = $pdo->prepare(
                "UPDATE merchants SET status = 'Rejected', approved_by = ?, approved_at = NOW(), rejection_reason = ? 
                 WHERE merchant_id = ?"
            );
            $result = $stmt->execute([$approved_by, $rejection_reason, $merchant_id]);
            
            if ($result) {
                logAccess($approved_by, "Rejected merchant ID: $merchant_id", true, $rejection_reason);
            }
        } else {
            $pdo->rollBack();
            return false;
        }
        
        if ($result && $stmt->rowCount() > 0) {
            $pdo->commit();
            return true;
        } else {
            $pdo->rollBack();
            return false;
        }
        
    } catch (Exception $e) {
        if (isset($pdo)) {
            $pdo->rollBack();
        }
        error_log("Error updating merchant approval: " . $e->getMessage());
        return false;
    }
}

// Official approval workflow with transaction handling
function updateOfficialApproval($official_id, $action, $approved_by, $rejection_reason = null) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return false;
        }
        
        $pdo->beginTransaction();
        
        if ($action === 'approve') {
            $stmt = $pdo->prepare(
                "UPDATE government_officials SET status = 'Approved', approved_by = ?, approved_at = NOW(), rejection_reason = NULL 
                 WHERE official_id = ?"
            );
            $result = $stmt->execute([$approved_by, $official_id]);
            
            if ($result) {
                logAccess($approved_by, "Approved official ID: $official_id", true);
            }
            
        } elseif ($action === 'reject') {
            $stmt = $pdo->prepare(
                "UPDATE government_officials SET status = 'Rejected', approved_by = ?, approved_at = NOW(), rejection_reason = ? 
                 WHERE official_id = ?"
            );
            $result = $stmt->execute([$approved_by, $rejection_reason, $official_id]);
            
            if ($result) {
                logAccess($approved_by, "Rejected official ID: $official_id", true, $rejection_reason);
            }
        } else {
            $pdo->rollBack();
            return false;
        }
        
        if ($result && $stmt->rowCount() > 0) {
            $pdo->commit();
            return true;
        } else {
            $pdo->rollBack();
            return false;
        }
        
    } catch (Exception $e) {
        if (isset($pdo)) {
            $pdo->rollBack();
        }
        error_log("Error updating official approval: " . $e->getMessage());
        return false;
    }
}

function getPendingMerchants($limit = 50) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return [];
        }
        
        $stmt = $pdo->prepare(
            "SELECT m.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
             FROM merchants m 
             JOIN users u ON m.user_id = u.user_id 
             WHERE m.status = 'Pending' 
             ORDER BY u.created_at DESC 
             LIMIT ?"
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (Exception $e) {
        error_log("Error getting pending merchants: " . $e->getMessage());
        return [];
    }
}

function getPendingOfficials($limit = 50) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return [];
        }
        
        $stmt = $pdo->prepare(
            "SELECT o.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
             FROM government_officials o 
             JOIN users u ON o.user_id = u.user_id 
             WHERE o.status = 'Pending' 
             ORDER BY u.created_at DESC 
             LIMIT ?"
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (Exception $e) {
        error_log("Error getting pending officials: " . $e->getMessage());
        return [];
    }
}

function getAllMerchants($limit = 100) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return [];
        }
        
        $stmt = $pdo->prepare(
            "SELECT m.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
             FROM merchants m 
             JOIN users u ON m.user_id = u.user_id 
             ORDER BY u.created_at DESC 
             LIMIT ?"
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (Exception $e) {
        error_log("Error getting all merchants: " . $e->getMessage());
        return [];
    }
}

function getAllOfficials($limit = 100) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return [];
        }
        
        $stmt = $pdo->prepare(
            "SELECT o.*, u.full_name, u.username, u.email, u.created_at, u.city as user_city
             FROM government_officials o 
             JOIN users u ON o.user_id = u.user_id 
             ORDER BY u.created_at DESC 
             LIMIT ?"
        );
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (Exception $e) {
        error_log("Error getting all officials: " . $e->getMessage());
        return [];
    }
}

function getMerchantStats() {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
        }
        
        $stmt = $pdo->query(
            "SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) as rejected
             FROM merchants"
        );
        
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
        
    } catch (Exception $e) {
        error_log("Error getting merchant stats: " . $e->getMessage());
        return ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
    }
}

function getOfficialStats() {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
        }
        
        $stmt = $pdo->query(
            "SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) as rejected
             FROM government_officials"
        );
        
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
        
    } catch (Exception $e) {
        error_log("Error getting official stats: " . $e->getMessage());
        return ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0];
    }
}

function validateUserCredentials($username, $password) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return false;
        }
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
        
        return false;
        
    } catch (Exception $e) {
        error_log("Error validating credentials: " . $e->getMessage());
        return false;
    }
}

// User creation with transaction handling
function createUser($userData) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        $pdo->beginTransaction();
        
        $stmt = $pdo->prepare(
            "INSERT INTO users (prs_id, full_name, national_id, dob, role, username, password, email, city) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        
        $result = $stmt->execute([
            $userData['prs_id'],
            $userData['full_name'],
            $userData['national_id'],
            $userData['dob'],
            $userData['role'],
            $userData['username'],
            password_hash($userData['password'], PASSWORD_DEFAULT),
            $userData['email'] ?? null,
            $userData['city'] ?? null
        ]);
        
        if ($result) {
            $user_id = $pdo->lastInsertId();
            $pdo->commit();
            return ['success' => true, 'user_id' => $user_id];
        } else {
            $pdo->rollBack();
            return ['success' => false, 'message' => 'Failed to create user'];
        }
        
    } catch (Exception $e) {
        if (isset($pdo)) {
            $pdo->rollBack();
        }
        error_log("Error creating user: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

function createMerchant($merchantData) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        $stmt = $pdo->prepare(
            "INSERT INTO merchants (prs_id, merchant_name, contact_email, contact_phone, city, business_license, user_id, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending')"
        );
        
        $result = $stmt->execute([
            $merchantData['prs_id'],
            $merchantData['merchant_name'],
            $merchantData['contact_email'],
            $merchantData['contact_phone'] ?? null,
            $merchantData['city'],
            $merchantData['business_license'] ?? null,
            $merchantData['user_id']
        ]);
        
        if ($result) {
            $merchant_id = $pdo->lastInsertId();
            return ['success' => true, 'merchant_id' => $merchant_id];
        } else {
            return ['success' => false, 'message' => 'Failed to create merchant profile'];
        }
        
    } catch (Exception $e) {
        error_log("Error creating merchant: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

function createOfficial($officialData) {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return ['success' => false, 'message' => 'Database connection failed'];
        }
        
        // Split full name for database storage
        $nameParts = explode(' ', $officialData['full_name'], 2);
        $firstName = $nameParts[0];
        $lastName = isset($nameParts[1]) ? $nameParts[1] : '';
        
        $stmt = $pdo->prepare(
            "INSERT INTO government_officials (first_name, last_name, role, contact_email, contact_phone, authorized_area, user_id, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending')"
        );
        
        $result = $stmt->execute([
            $firstName,
            $lastName,
            $officialData['official_role'] ?? 'Government Official',
            $officialData['contact_email'],
            $officialData['contact_phone'] ?? null,
            $officialData['authorized_area'] ?? $officialData['city'],
            $officialData['user_id']
        ]);
        
        if ($result) {
            $official_id = $pdo->lastInsertId();
            return ['success' => true, 'official_id' => $official_id];
        } else {
            return ['success' => false, 'message' => 'Failed to create official profile'];
        }
        
    } catch (Exception $e) {
        error_log("Error creating official: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Email notification placeholder - implement with PHPMailer in production
function sendEmailNotification($to, $subject, $message) {
    error_log("Email would be sent to $to: $subject - $message");
    return true;
}

function getSystemStats() {
    try {
        $pdo = getDBConnection();
        if (!$pdo) {
            return [];
        }
        
        $stats = [];
        
        // User counts by role
        $stmt = $pdo->query(
            "SELECT role, COUNT(*) as count FROM users GROUP BY role"
        );
        $userStats = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
        
        $merchantStats = getMerchantStats();
        $officialStats = getOfficialStats();
        
        // Recent activity in last 24 hours
        $stmt = $pdo->query(
            "SELECT COUNT(*) FROM access_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        $recentActivity = $stmt->fetchColumn();
        
        return [
            'users' => $userStats,
            'merchants' => $merchantStats,
            'officials' => $officialStats,
            'recent_activity' => $recentActivity
        ];
        
    } catch (Exception $e) {
        error_log("Error getting system stats: " . $e->getMessage());
        return [];
    }
}

date_default_timezone_set('UTC');

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>