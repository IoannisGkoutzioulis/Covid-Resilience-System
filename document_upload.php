<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$success_message = $error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_FILES['document']) || $_FILES['document']['error'] !== UPLOAD_ERR_OK) {
        $error_code = $_FILES['document']['error'] ?? 'No file uploaded';
        $error_message = 'File upload error: ' . getUploadErrorMessage($error_code);
    } else {
        $file = $_FILES['document'];
        $fileName = $file['name'];
        $fileTmpPath = $file['tmp_name'];
        $fileSize = $file['size'];
        $fileType = $file['type'];
        
        $documentType = $_POST['document_type'];
        $userId = $_SESSION['user_id'];
        
        // Allow privileged roles to upload documents for other users
        if (isset($_POST['user_id']) && !empty($_POST['user_id']) && hasRole(['Admin', 'Official', 'Doctor'])) {
            $inputUserId = (int)$_POST['user_id'];
            
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("SELECT user_id FROM users WHERE user_id = ?");
            $stmt->execute([$inputUserId]);
            
            if ($stmt->rowCount() > 0) {
                $userId = $inputUserId;
            } else {
                $error_message = 'Error: User ID ' . $inputUserId . ' does not exist. Document will be uploaded for your account instead.';
            }
        }
        
        if (empty($error_message)) {
            $validTypes = ['Vaccination Certificate', 'ID Document', 'Medical Report', 'Other'];
            if (!in_array($documentType, $validTypes)) {
                $error_message = 'Invalid document type selected';
            } 
            else {
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
                    $error_message = 'Invalid file type. Allowed types: PDF, images, and common document formats';
                } 
                // 10MB file size limit to prevent server overload
                else if ($fileSize > 10 * 1024 * 1024) {
                    $error_message = 'File too large. Maximum file size is 10MB';
                } 
                else {
                    try {
                        // Organize uploads by date for better file management
                        $uploadDir = 'uploads/documents/' . date('Y/m/d') . '/';
                        if (!is_dir($uploadDir)) {
                            mkdir($uploadDir, 0755, true);
                        }
                        
                        $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
                        $newFileName = uniqid('doc_') . '_' . time() . '.' . $fileExtension;
                        $uploadPath = $uploadDir . $newFileName;
                        
                        $pdo = getDBConnection();
                        $pdo->beginTransaction();
                        
                        // Generate file hash for integrity verification
                        $fileHash = hash_file('sha256', $fileTmpPath);
                        
                        // Encrypt sensitive document types for security
                        $shouldEncrypt = ($documentType === 'Vaccination Certificate' || $documentType === 'ID Document');
                        
                        if ($shouldEncrypt) {
                            $keyStmt = $pdo->prepare("SELECT key_value FROM encryption_keys WHERE is_active = 1 ORDER BY key_id DESC LIMIT 1");
                            $keyStmt->execute();
                            $key = $keyStmt->fetchColumn();
                            
                            if ($key) {
                                $fileContent = file_get_contents($fileTmpPath);
                                $iv = substr(hash('sha256', $fileHash), 0, 16); // Use first 16 bytes of hash as IV
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
                        
                        // Final user validation before database insert
                        $userCheckStmt = $pdo->prepare("SELECT user_id FROM users WHERE user_id = ?");
                        $userCheckStmt->execute([$userId]);
                        if ($userCheckStmt->rowCount() === 0) {
                            throw new Exception("Cannot upload document: User ID {$userId} does not exist");
                        }
                        
                        $stmt = $pdo->prepare(
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
                        
                        $documentId = $pdo->lastInsertId();
                        
                        logAccess($_SESSION['user_id'], 'Document Upload: ' . $fileName);
                        
                        $pdo->commit();
                        
                        $success_message = 'Document uploaded successfully! Document ID: ' . $documentId;
                        
                    } catch (PDOException $e) {
                        if (isset($pdo)) {
                            $pdo->rollback();
                        }
                        
                        // Clean up uploaded file on database error
                        if (isset($uploadPath) && file_exists($uploadPath)) {
                            unlink($uploadPath);
                        }
                        
                        $error_message = 'Error uploading document: ' . $e->getMessage();
                    } catch (Exception $e) {
                        if (isset($pdo) && $pdo->inTransaction()) {
                            $pdo->rollback();
                        }
                        
                        if (isset($uploadPath) && file_exists($uploadPath)) {
                            unlink($uploadPath);
                        }
                        
                        $error_message = $e->getMessage();
                    }
                }
            }
        }
    }
}

$userDocuments = [];
try {
    $pdo = getDBConnection();
    
    $stmt = $pdo->prepare(
        "SELECT document_id, document_type, document_name, mime_type, file_size, 
         upload_date, is_verified 
         FROM documents 
         WHERE user_id = ? 
         ORDER BY upload_date DESC
         LIMIT 5"
    );
    
    $stmt->execute([$_SESSION['user_id']]);
    $userDocuments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = 'Error retrieving documents: ' . $e->getMessage();
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
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Upload - COVID Resilience System</title>
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
        
        .file-upload {
            border: 2px dashed #ddd;
            border-radius: 8px;
            padding: 30px;
            text-align: center;
            background-color: #f8f9fa;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .file-upload:hover {
            border-color: #0d6efd;
            background-color: #f1f8ff;
        }
        
        .upload-icon {
            font-size: 3rem;
            color: #6c757d;
            margin-bottom: 15px;
        }
        
        .file-upload:hover .upload-icon {
            color: #0d6efd;
        }
        
        .file-input {
            position: absolute;
            width: 0;
            height: 0;
            opacity: 0;
        }
        
        .selected-file {
            margin-top: 15px;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 8px;
            display: none;
        }
        
        .doc-list-item {
            border-bottom: 1px solid #e9ecef;
            padding: 10px 0;
        }
        
        .doc-icon {
            font-size: 1.5rem;
            margin-right: 10px;
        }
        
        .verified-badge {
            background-color: #198754;
            color: white;
            font-size: 0.7rem;
            padding: 0.25rem 0.5rem;
            border-radius: 50px;
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
                            <span class="role-badge role-<?php echo strtolower($_SESSION['role']); ?>"><?php echo $_SESSION['role']; ?></span>
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
                        <a class="nav-link active" href="document_upload.php">
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
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-file-earmark-arrow-up me-2"></i>Document Upload</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                        </button>
                        <a href="view_documents.php" class="btn btn-primary">
                            <i class="bi bi-file-earmark-text me-2"></i>View All Documents
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
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title mb-4">Upload New Document</h5>
                                
                                <form action="document_upload.php" method="POST" enctype="multipart/form-data">
                                    <div class="mb-4">
                                        <label for="document_type" class="form-label">Document Type</label>
                                        <select class="form-select" id="document_type" name="document_type" required>
                                            <option value="" selected disabled>Select document type...</option>
                                            <option value="Vaccination Certificate">Vaccination Certificate</option>
                                            <option value="ID Document">ID Document</option>
                                            <option value="Medical Report">Medical Report</option>
                                            <option value="Other">Other</option>
                                        </select>
                                    </div>
                                    
                                    <?php if (hasRole(['Admin', 'Official', 'Doctor'])): ?>
                                    <div class="mb-4">
                                        <label for="user_id" class="form-label">User ID (Admin/Official/Doctor Only)</label>
                                        <input type="number" class="form-control" id="user_id" name="user_id" 
                                               placeholder="Leave empty for your own documents">
                                        <div class="form-text">Only fill this if uploading for another user. Must be a valid User ID.</div>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <div class="mb-4">
                                        <label for="document" class="form-label">Document File</label>
                                        <div class="file-upload" id="fileUploadContainer">
                                            <i class="bi bi-cloud-arrow-up upload-icon"></i>
                                            <h5>Drag and drop file here</h5>
                                            <p class="text-muted">or click to browse</p>
                                            <input type="file" name="document" id="document" class="file-input" required>
                                        </div>
                                        <div class="selected-file" id="selectedFile">
                                            <i class="bi bi-file-earmark me-2"></i>
                                            <span id="fileName">No file selected</span>
                                            <button type="button" class="btn btn-sm btn-outline-danger float-end" id="removeFile">
                                                <i class="bi bi-x"></i>
                                            </button>
                                        </div>
                                        <div class="form-text mt-2">
                                            <i class="bi bi-info-circle me-1"></i>
                                            Allowed file types: PDF, images, MS Office documents, text files
                                        </div>
                                        <div class="form-text">
                                            <i class="bi bi-lock me-1"></i>
                                            Vaccination Certificates and ID Documents will be encrypted for security
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-2">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="bi bi-cloud-upload me-2"></i>Upload Document
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <?php if (!empty($userDocuments)): ?>
                        <div class="card mt-4">
                            <div class="card-header bg-light">
                                <h5 class="mb-0"><i class="bi bi-clock-history me-2"></i>Your Recent Documents</h5>
                            </div>
                            <div class="card-body">
                                <div class="list-group">
                                    <?php foreach ($userDocuments as $doc): ?>
                                    <div class="doc-list-item">
                                        <div class="d-flex align-items-center">
                                            <?php
                                            // Document type icon mapping
                                            $icon = 'bi-file-earmark';
                                            if (strpos($doc['mime_type'], 'pdf') !== false) {
                                                $icon = 'bi-file-earmark-pdf';
                                            } else if (strpos($doc['mime_type'], 'image') !== false) {
                                                $icon = 'bi-file-earmark-image';
                                            } else if (strpos($doc['mime_type'], 'word') !== false) {
                                                $icon = 'bi-file-earmark-word';
                                            } else if (strpos($doc['mime_type'], 'excel') !== false || strpos($doc['mime_type'], 'sheet') !== false) {
                                                $icon = 'bi-file-earmark-excel';
                                            } else if (strpos($doc['mime_type'], 'text') !== false) {
                                                $icon = 'bi-file-earmark-text';
                                            }
                                            ?>
                                            <i class="bi <?php echo $icon; ?> doc-icon"></i>
                                            <div class="flex-grow-1">
                                                <div class="d-flex justify-content-between">
                                                    <h6 class="mb-0"><?php echo htmlspecialchars($doc['document_name']); ?></h6>
                                                    <small class="text-muted">
                                                        <?php echo date('M j, Y', strtotime($doc['upload_date'])); ?>
                                                    </small>
                                                </div>
                                                <div class="d-flex justify-content-between">
                                                    <small class="text-muted">
                                                        Type: <?php echo htmlspecialchars($doc['document_type']); ?>
                                                        <?php if ($doc['is_verified']): ?>
                                                        <span class="verified-badge ms-2">
                                                            <i class="bi bi-check-circle me-1"></i>Verified
                                                        </span>
                                                        <?php endif; ?>
                                                    </small>
                                                    <small class="text-muted">
                                                        Size: <?php echo formatFileSize($doc['file_size']); ?>
                                                    </small>
                                                </div>
                                            </div>
                                            <a href="download_document.php?id=<?php echo $doc['document_id']; ?>" class="btn btn-sm btn-outline-primary ms-2" title="Download">
                                                <i class="bi bi-download"></i>
                                            </a>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                                
                                <div class="text-center mt-3">
                                    <a href="view_documents.php" class="btn btn-outline-primary">
                                        <i class="bi bi-eye me-2"></i>View All Documents
                                    </a>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card bg-light">
                            <div class="card-body">
                                <h5 class="card-title">About Document Upload</h5>
                                <hr>
                                <p>
                                    <i class="bi bi-shield-fill-check me-2 text-success"></i>
                                    <strong>Secure Storage</strong>
                                </p>
                                <p class="text-muted small">
                                    All sensitive documents such as Vaccination Certificates and ID Documents are encrypted using AES-256 encryption.
                                </p>
                                
                                <p>
                                    <i class="bi bi-fingerprint me-2 text-primary"></i>
                                    <strong>Integrity Protection</strong>
                                </p>
                                <p class="text-muted small">
                                    All uploaded documents are protected by SHA-256 hash verification to ensure they remain unmodified.
                                </p>
                                
                                <p>
                                    <i class="bi bi-file-check me-2 text-info"></i>
                                    <strong>Document Verification</strong>
                                </p>
                                <p class="text-muted small">
                                    Officials can verify your documents for authenticity, giving you added proof of validity.
                                </p>
                                
                                <p>
                                    <i class="bi bi-exclamation-triangle me-2 text-warning"></i>
                                    <strong>Size Limits</strong>
                                </p>
                                <p class="text-muted small">
                                    Maximum file size: 10MB per document
                                </p>
                            </div>
                        </div>
                        
                        <div class="card mt-4">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-info-circle me-2"></i>Document Types</h5>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <strong><i class="bi bi-shield-check me-2 text-success"></i>Vaccination Certificate</strong>
                                    <p class="text-muted small">
                                        Your official COVID-19 vaccination record, showing vaccine type, date, and provider information.
                                    </p>
                                </div>
                                
                                <div class="mb-3">
                                    <strong><i class="bi bi-person-badge me-2 text-danger"></i>ID Document</strong>
                                    <p class="text-muted small">
                                        Government-issued identification such as passport, national ID card, or driver's license.
                                    </p>
                                </div>
                                
                                <div class="mb-3">
                                    <strong><i class="bi bi-file-medical me-2 text-info"></i>Medical Report</strong>
                                    <p class="text-muted small">
                                        COVID-19 test results, recovery certificates, or related medical documentation.
                                    </p>
                                </div>
                                
                                <div>
                                    <strong><i class="bi bi-file-earmark me-2 text-secondary"></i>Other</strong>
                                    <p class="text-muted small">
                                        Any other document relevant to your COVID resilience status not covered by the categories above.
                                    </p>
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
            const fileInput = document.getElementById('document');
            const fileUploadContainer = document.getElementById('fileUploadContainer');
            const selectedFile = document.getElementById('selectedFile');
            const fileName = document.getElementById('fileName');
            const removeFile = document.getElementById('removeFile');
            
            fileUploadContainer.addEventListener('click', function() {
                fileInput.click();
            });
            
            // Drag and drop functionality
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                fileUploadContainer.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                fileUploadContainer.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                fileUploadContainer.addEventListener(eventName, unhighlight, false);
            });
            
            function highlight() {
                fileUploadContainer.classList.add('border-primary');
                fileUploadContainer.classList.add('bg-primary-subtle');
            }
            
            function unhighlight() {
                fileUploadContainer.classList.remove('border-primary');
                fileUploadContainer.classList.remove('bg-primary-subtle');
            }
            
            fileUploadContainer.addEventListener('drop', handleDrop, false);
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                
                if (files.length) {
                    fileInput.files = files;
                    updateFileInfo();
                }
            }
            
            fileInput.addEventListener('change', updateFileInfo);
            
            function updateFileInfo() {
                if (fileInput.files.length) {
                    const file = fileInput.files[0];
                    fileName.textContent = file.name;
                    selectedFile.style.display = 'block';
                    fileUploadContainer.style.display = 'none';
                } else {
                    selectedFile.style.display = 'none';
                    fileUploadContainer.style.display = 'block';
                }
            }
            
            removeFile.addEventListener('click', function() {
                fileInput.value = '';
                selectedFile.style.display = 'none';
                fileUploadContainer.style.display = 'block';
            });
        });
    </script>
</body>
</html>

<?php
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        $bytes = number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        $bytes = number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        $bytes = number_format($bytes / 1024, 2) . ' KB';
    } elseif ($bytes > 1) {
        $bytes = $bytes . ' bytes';
    } elseif ($bytes == 1) {
        $bytes = $bytes . ' byte';
    } else {
        $bytes = '0 bytes';
    }
    
    return $bytes;
}
?>