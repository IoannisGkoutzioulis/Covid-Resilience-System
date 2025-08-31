<?php
require_once '../config.php';
require_once '../session_check.php';

// API authentication check
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$db = getDBConnection();
$method = $_SERVER['REQUEST_METHOD'];

// Handle file downloads separately (binary response)
if (isset($_GET['download']) && $_GET['download'] === 'true' && isset($_GET['id'])) {
    handleDownload($_GET['id']);
    exit;
}

header('Content-Type: application/json');

switch ($method) {
    case 'GET':
        handleGet();
        break;
        
    case 'POST':
        handlePost();
        break;
        
    case 'PUT':
        handlePut();
        break;
        
    case 'DELETE':
        handleDelete();
        break;
        
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGet() {
    global $db;
    
    if (isset($_GET['id'])) {
        $documentId = (int)$_GET['id'];
        
        $document = $db->prepare("SELECT * FROM documents WHERE document_id = ?");
        $document->execute([$documentId]);
        $documentData = $document->fetch(PDO::FETCH_ASSOC);
        
        if (!$documentData) {
            http_response_code(404);
            echo json_encode(['error' => 'Document not found']);
            return;
        }
        
        if (!canAccessDocument($documentData)) {
            http_response_code(403);
            echo json_encode(['error' => 'Permission denied']);
            return;
        }
        
        // Security: Don't expose file system paths in API response
        unset($documentData['file_path']);
        
        echo json_encode(['data' => $documentData]);
        return;
    }
    
    if (isset($_GET['user_id'])) {
        $userId = (int)$_GET['user_id'];
        
        if (!canAccessUser($userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Permission denied']);
            return;
        }
        
        $stmt = $db->prepare(
            "SELECT document_id, user_id, document_type, document_name, mime_type, 
            file_size, upload_date, is_verified, verified_by, verification_date 
            FROM documents 
            WHERE user_id = ? 
            ORDER BY upload_date DESC"
        );
        $stmt->execute([$userId]);
        $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['data' => $documents]);
        return;
    }
    
    // Privileged roles only for listing all documents
    if (!hasRole(['Admin', 'Official', 'Doctor'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    $conditions = [];
    $params = [];
    
    if (isset($_GET['document_type']) && !empty($_GET['document_type'])) {
        $conditions[] = "document_type = ?";
        $params[] = $_GET['document_type'];
    }
    
    if (isset($_GET['date_from']) && !empty($_GET['date_from'])) {
        $conditions[] = "upload_date >= ?";
        $params[] = $_GET['date_from'];
    }
    
    if (isset($_GET['date_to']) && !empty($_GET['date_to'])) {
        $conditions[] = "upload_date <= ?";
        $params[] = $_GET['date_to'];
    }
    
    if (isset($_GET['verified']) && in_array($_GET['verified'], ['0', '1'])) {
        $conditions[] = "is_verified = ?";
        $params[] = (int)$_GET['verified'];
    }
    
    $whereClause = empty($conditions) ? "" : "WHERE " . implode(" AND ", $conditions);
    
    $countStmt = $db->prepare("SELECT COUNT(*) FROM documents $whereClause");
    $countStmt->execute($params);
    $totalCount = $countStmt->fetchColumn();
    
    $stmt = $db->prepare(
        "SELECT d.document_id, d.user_id, d.document_type, d.document_name, 
        d.mime_type, d.file_size, d.upload_date, d.is_verified, 
        d.verification_date, u.full_name as user_name
        FROM documents d
        JOIN users u ON d.user_id = u.user_id
        $whereClause
        ORDER BY d.upload_date DESC
        LIMIT ? OFFSET ?"
    );
    
    $stmt->execute(array_merge($params, [$limit, $offset]));
    $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $totalPages = ceil($totalCount / $limit);
    
    echo json_encode([
        'data' => $documents,
        'pagination' => [
            'total' => $totalCount,
            'per_page' => $limit,
            'current_page' => $page,
            'total_pages' => $totalPages
        ]
    ]);
}

function handleDownload($documentId) {
    global $db;
    
    $stmt = $db->prepare("SELECT * FROM documents WHERE document_id = ?");
    $stmt->execute([(int)$documentId]);
    $document = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$document) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Document not found']);
        return;
    }
    
    if (!canAccessDocument($document)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $filePath = $document['file_path'];
    
    if (!file_exists($filePath)) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found on server']);
        return;
    }
    
    logAccess($_SESSION['user_id'], 'Document Download: ' . $document['document_name']);
    
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $document['mime_type']);
    header('Content-Disposition: attachment; filename="' . basename($document['document_name']) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . $document['file_size']);
    
    // Handle decryption for sensitive documents
    if (!empty($document['hash_value'])) {
        $keyStmt = $db->prepare("SELECT key_value FROM encryption_keys WHERE is_active = 1 ORDER BY key_id DESC LIMIT 1");
        $keyStmt->execute();
        $key = $keyStmt->fetchColumn();
        
        if ($key) {
            $fileContent = file_get_contents($filePath);
            $decrypted = openssl_decrypt($fileContent, 'AES-256-CBC', base64_decode($key), 0, substr(hash('sha256', $document['hash_value']), 0, 16));
            
            if ($decrypted !== false) {
                echo $decrypted;
                exit;
            }
        }
    }
    
    readfile($filePath);
    exit;
}

function handlePost() {
    global $db;
    
    if (empty($_FILES['document']) || $_FILES['document']['error'] !== UPLOAD_ERR_OK) {
        $error = $_FILES['document']['error'] ?? 'No file uploaded';
        http_response_code(400);
        echo json_encode(['error' => 'File upload error: ' . getUploadErrorMessage($error)]);
        return;
    }
    
    $file = $_FILES['document'];
    $fileName = $file['name'];
    $fileTmpPath = $file['tmp_name'];
    $fileSize = $file['size'];
    $fileType = $file['type'];
    
    $documentType = isset($_POST['document_type']) ? $_POST['document_type'] : 'Other';
    $userId = isset($_POST['user_id']) ? (int)$_POST['user_id'] : $_SESSION['user_id'];
    
    // Prevent unauthorized cross-user uploads
    if ($userId !== $_SESSION['user_id'] && !hasRole(['Admin', 'Official', 'Doctor'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied: Cannot upload documents for another user']);
        return;
    }
    
    $validTypes = ['Vaccination Certificate', 'ID Document', 'Medical Report', 'Other'];
    if (!in_array($documentType, $validTypes)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid document type']);
        return;
    }
    
    // Security: Restrict file types to prevent malicious uploads
    $allowedMimeTypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain'
    ];
    
    if (!in_array($fileType, $allowedMimeTypes)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid file type. Allowed types: PDF, images, and common document formats']);
        return;
    }
    
    // 10MB limit to prevent server overload
    $maxFileSize = 10 * 1024 * 1024;
    if ($fileSize > $maxFileSize) {
        http_response_code(400);
        echo json_encode(['error' => 'File too large. Maximum file size is 10MB']);
        return;
    }
    
    // Organize uploads by date for better file management
    $uploadDir = '../uploads/documents/' . date('Y/m/d') . '/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    
    $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
    $newFileName = uniqid('doc_') . '_' . time() . '.' . $fileExtension;
    $uploadPath = $uploadDir . $newFileName;
    
    try {
        $db->beginTransaction();
        
        // File integrity verification
        $fileHash = hash_file('sha256', $fileTmpPath);
        
        // Encrypt sensitive document types
        $shouldEncrypt = ($documentType === 'Vaccination Certificate' || $documentType === 'ID Document');
        
        if ($shouldEncrypt) {
            $keyStmt = $db->prepare("SELECT key_value FROM encryption_keys WHERE is_active = 1 ORDER BY key_id DESC LIMIT 1");
            $keyStmt->execute();
            $key = $keyStmt->fetchColumn();
            
            if ($key) {
                $fileContent = file_get_contents($fileTmpPath);
                $iv = substr(hash('sha256', $fileHash), 0, 16);
                $encrypted = openssl_encrypt($fileContent, 'AES-256-CBC', base64_decode($key), 0, $iv);
                
                if ($encrypted !== false) {
                    file_put_contents($uploadPath, $encrypted);
                } else {
                    move_uploaded_file($fileTmpPath, $uploadPath);
                }
            } else {
                move_uploaded_file($fileTmpPath, $uploadPath);
            }
        } else {
            move_uploaded_file($fileTmpPath, $uploadPath);
        }
        
        $stmt = $db->prepare(
            "INSERT INTO documents 
            (user_id, document_type, document_name, file_path, mime_type, file_size, hash_value) 
            VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        
        $stmt->execute([
            $userId,
            $documentType,
            $fileName,
            $uploadPath,
            $fileType,
            $fileSize,
            $fileHash
        ]);
        
        $documentId = $db->lastInsertId();
        
        logAccess($_SESSION['user_id'], 'Document Upload: ' . $fileName);
        
        $db->commit();
        
        http_response_code(201);
        echo json_encode([
            'message' => 'Document uploaded successfully',
            'document_id' => $documentId
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        
        // Clean up uploaded file on error
        if (file_exists($uploadPath)) {
            unlink($uploadPath);
        }
        
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function handlePut() {
    global $db;
    
    if (!isset($_GET['id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Document ID is required']);
        return;
    }
    
    $documentId = (int)$_GET['id'];
    
    $stmt = $db->prepare("SELECT * FROM documents WHERE document_id = ?");
    $stmt->execute([$documentId]);
    $document = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$document) {
        http_response_code(404);
        echo json_encode(['error' => 'Document not found']);
        return;
    }
    
    if (!canModifyDocument($document)) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON data']);
        return;
    }
    
    $updateData = [];
    $allowedFields = ['document_type', 'document_name'];
    
    // Additional fields for privileged roles
    if (hasRole(['Admin', 'Official', 'Doctor'])) {
        $allowedFields[] = 'is_verified';
        $allowedFields[] = 'verified_by';
    }
    
    foreach ($allowedFields as $field) {
        if (isset($input[$field])) {
            if ($field === 'document_type') {
                $validTypes = ['Vaccination Certificate', 'ID Document', 'Medical Report', 'Other'];
                if (!in_array($input[$field], $validTypes)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid document type']);
                    return;
                }
            }
            
            $updateData[$field] = $input[$field];
        }
    }
    
    // Auto-set verification metadata when document is verified
    if (isset($updateData['is_verified']) && $updateData['is_verified'] == 1) {
        $updateData['verification_date'] = date('Y-m-d H:i:s');
        if (!isset($updateData['verified_by'])) {
            $updateData['verified_by'] = $_SESSION['user_id'];
        }
    }
    
    try {
        $db->beginTransaction();
        
        $setClause = [];
        $params = [];
        
        foreach ($updateData as $field => $value) {
            $setClause[] = "$field = ?";
            $params[] = $value;
        }
        
        $params[] = $documentId;
        
        $query = "UPDATE documents SET " . implode(', ', $setClause) . " WHERE document_id = ?";
        $stmt = $db->prepare($query);
        $stmt->execute($params);
        
        logAccess($_SESSION['user_id'], 'Document Update: ' . $document['document_name']);
        
        $db->commit();
        
        echo json_encode(['message' => 'Document updated successfully']);
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function handleDelete() {
    global $db;
    
    if (!isset($_GET['id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Document ID is required']);
        return;
    }
    
    $documentId = (int)$_GET['id'];
    
    $stmt = $db->prepare("SELECT * FROM documents WHERE document_id = ?");
    $stmt->execute([$documentId]);
    $document = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$document) {
        http_response_code(404);
        echo json_encode(['error' => 'Document not found']);
        return;
    }
    
    if (!canModifyDocument($document)) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $stmt = $db->prepare("DELETE FROM documents WHERE document_id = ?");
        $stmt->execute([$documentId]);
        
        // Clean up physical file
        if (file_exists($document['file_path'])) {
            unlink($document['file_path']);
        }
        
        logAccess($_SESSION['user_id'], 'Document Delete: ' . $document['document_name']);
        
        $db->commit();
        
        echo json_encode(['message' => 'Document deleted successfully']);
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function canAccessDocument($document) {
    // Admin, Official and Doctor can access any document
    if (hasRole(['Admin', 'Official', 'Doctor'])) {
        return true;
    }
    
    // Users can access their own documents
    if ($_SESSION['user_id'] === $document['user_id']) {
        return true;
    }
    
    return false;
}

function canModifyDocument($document) {
    // Admin and Official can modify any document
    if (hasRole(['Admin', 'Official'])) {
        return true;
    }
    
    // Users can modify their own documents
    if ($_SESSION['user_id'] === $document['user_id']) {
        return true;
    }
    
    return false;
}

function getUploadErrorMessage($errorCode) {
    switch ($errorCode) {
        case UPLOAD_ERR_INI_SIZE:
            return 'The uploaded file exceeds the upload_max_filesize directive in php.ini';
        case UPLOAD_ERR_FORM_SIZE:
            return 'The uploaded file exceeds the MAX_FILE_SIZE directive in the HTML form';
        case UPLOAD_ERR_PARTIAL:
            return 'The uploaded file was only partially uploaded';
        case UPLOAD_ERR_NO_FILE:
            return 'No file was uploaded';
        case UPLOAD_ERR_NO_TMP_DIR:
            return 'Missing a temporary folder';
        case UPLOAD_ERR_CANT_WRITE:
            return 'Failed to write file to disk';
        case UPLOAD_ERR_EXTENSION:
            return 'A PHP extension stopped the file upload';
        default:
            return 'Unknown upload error';
    }
}