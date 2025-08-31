<?php
require_once 'session_check.php';
require_once 'config.php';
require_once 'access_control.php';

checkLogin();

$response = [];

try {
    $pdo = getDBConnection();
    
    if (isset($_GET['city']) && !empty($_GET['city'])) {
        $city = trim($_GET['city']);
        
        $stmt = $pdo->prepare("
            SELECT merchant_id, prs_id, merchant_name, address, city, contact_phone, contact_email 
            FROM merchants 
            WHERE LOWER(city) LIKE LOWER(?) 
            ORDER BY merchant_name
        ");
        
        $stmt->execute(["%$city%"]);
        $merchants = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        header('Content-Type: application/json');
        echo json_encode($merchants);
        exit;
    }
    
    // Search by PRS ID: Handle both merchant and user IDs with different logic
    elseif (isset($_GET['prs_id']) && !empty($_GET['prs_id'])) {
        $prsId = trim($_GET['prs_id']);
        
        // Merchant PRS IDs start with "MER" prefix
        if (substr($prsId, 0, 3) === 'MER') {
            $merchantStmt = $pdo->prepare("
                SELECT city 
                FROM merchants 
                WHERE prs_id = ?
            ");
            
            $merchantStmt->execute([$prsId]);
            $merchant = $merchantStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$merchant) {
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Merchant with the specified PRS ID not found']);
                exit;
            }
            
            $cityToSearch = $merchant['city'];
        } else {
            // Regular user PRS ID - search users table
            $userStmt = $pdo->prepare("
                SELECT city 
                FROM users 
                WHERE prs_id = ?
            ");
            
            $userStmt->execute([$prsId]);
            $user = $userStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                // Fallback: Try searching by numeric user_id
                $userStmt = $pdo->prepare("
                    SELECT city 
                    FROM users 
                    WHERE user_id = ?
                ");
                
                $userStmt->execute([intval($prsId)]);
                $user = $userStmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$user) {
                    header('Content-Type: application/json');
                    echo json_encode(['error' => 'User with the specified PRS ID not found']);
                    exit;
                }
            }
            
            $cityToSearch = $user['city'];
        }
        
        if (empty($cityToSearch)) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'The user or merchant has no city specified']);
            exit;
        }
        
        $merchantStmt = $pdo->prepare("
            SELECT merchant_id, prs_id, merchant_name, address, city, contact_phone, contact_email
            FROM merchants 
            WHERE LOWER(city) = LOWER(?) 
            ORDER BY merchant_name
        ");
        
        $merchantStmt->execute([$cityToSearch]);
        $merchants = $merchantStmt->fetchAll(PDO::FETCH_ASSOC);
        
        $response = [
            'city' => $cityToSearch,
            'merchants' => $merchants
        ];
        
        header('Content-Type: application/json');
        echo json_encode($merchants);
        exit;
    }
    
    else {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Missing search parameter. Please provide either "city" or "prs_id"']);
        exit;
    }
    
} catch (PDOException $e) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    exit;
}
?>