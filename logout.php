<?php
require_once 'config.php';

session_start();

// Log logout activity for security audit trail
if (isset($_SESSION['user_id'])) {
    try {
        $pdo = getDBConnection();
        
        $ip = $_SERVER['REMOTE_ADDR'];
        $stmt = $pdo->prepare(
            "INSERT INTO access_logs (user_id, access_type, ip_address, location, success) 
             VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $_SESSION['user_id'],
            'Logout',
            $ip,
            'Web Logout',
            1
        ]);
        
    } catch (PDOException $e) {
        error_log("Failed to log logout: " . $e->getMessage());
    }
}

session_unset();
session_destroy();

header("Location: login.php?logout=success");
exit();
?>