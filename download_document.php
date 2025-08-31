<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

if (!isset($_GET['id']) || empty($_GET['id'])) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Document ID is required']);
    exit;
}

$documentId = (int)$_GET['id'];

try {
    $pdo = getDBConnection();
    
    $stmt = $pdo->prepare("SELECT * FROM documents WHERE document_id = ?");
    $stmt->execute([$documentId]);
    $document = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$document) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Document not found']);
        exit;
    }
    
    // Role-based access control: Admin/Official/Doctor can access any document, users can access their own
    $canAccess = false;
    
    if (hasRole(['Admin', 'Official', 'Doctor'])) {
        $canAccess = true;
    }
    
    if ($_SESSION['user_id'] === $document['user_id']) {
        $canAccess = true;
    }
    
    if (!$canAccess) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Permission denied']);
        exit;
    }
    
    $filePath = $document['file_path'];
    
    if (!file_exists($filePath)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found on server']);
        exit;
    }
    
    logAccess($_SESSION['user_id'], 'Document Download: ' . $document['document_name']);
    
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $document['mime_type']);
    header('Content-Disposition: attachment; filename="' . basename($document['document_name']) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . $document['file_size']);
    
    // Decrypt sensitive document types before serving
    if (!empty($document['hash_value']) && ($document['document_type'] == 'Vaccination Certificate' || $document['document_type'] == 'ID Document')) {
        $keyStmt = $pdo->prepare("SELECT key_value FROM encryption_keys WHERE is_active = 1 ORDER BY key_id DESC LIMIT 1");
        $keyStmt->execute();
        $key = $keyStmt->fetchColumn();
        
        if ($key) {
            $fileContent = file_get_contents($filePath);
            $iv = substr(hash('sha256', $document['hash_value']), 0, 16); // Use hash as IV for decryption
            $decrypted = openssl_decrypt($fileContent, 'AES-256-CBC', base64_decode($key), 0, $iv);
            
            if ($decrypted !== false) {
                echo $decrypted;
                exit;
            }
        }
    }
    
    readfile($filePath);
    exit;
    
} catch (PDOException $e) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    exit;
} catch (Exception $e) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Error: ' . $e->getMessage()]);
    exit;
}