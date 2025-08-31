<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$pdo = getDBConnection();

$success_message = $error_message = '';
$documents = [];

$is_admin = hasRole(['Admin']);
$is_official = hasRole(['Official']);
$is_doctor = hasRole(['Doctor']);
$is_merchant = hasRole(['Merchant']);
$is_citizen = hasRole(['Citizen']);

if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    $documentId = (int)$_GET['id'];
    
    try {
        // Security: Verify document ownership or admin privileges before deletion
        $stmt = $pdo->prepare("SELECT * FROM documents WHERE document_id = ?");
        $stmt->execute([$documentId]);
        $document = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$document) {
            $error_message = "Document not found";
        } 
        else if ($document['user_id'] != $_SESSION['user_id'] && !hasRole(['Admin', 'Official'])) {
            $error_message = "You don't have permission to delete this document";
        } 
        else {
            $pdo->beginTransaction();
            
            $stmt = $pdo->prepare("DELETE FROM documents WHERE document_id = ?");
            $stmt->execute([$documentId]);
            
            // File system cleanup: Remove physical file after database deletion
            if (file_exists($document['file_path']) && is_file($document['file_path'])) {
                unlink($document['file_path']);
            }
            
            logAccess($_SESSION['user_id'], 'Deleted Document: ' . $document['document_name']);
            
            $pdo->commit();
            $success_message = "Document deleted successfully";
        }
    } catch (PDOException $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $error_message = "Error deleting document: " . $e->getMessage();
    }
}

// Role-based document access: Admin/Official can view all documents with filters
$isAdmin = hasRole(['Admin', 'Official']);
$filterUserId = null;

if ($isAdmin && isset($_GET['user_id']) && !empty($_GET['user_id'])) {
    $filterUserId = (int)$_GET['user_id'];
}

try {
    if ($filterUserId) {
        $stmt = $pdo->prepare(
            "SELECT d.*, u.full_name as user_name, v.full_name as verifier_name 
             FROM documents d
             JOIN users u ON d.user_id = u.user_id
             LEFT JOIN users v ON d.verified_by = v.user_id
             WHERE d.user_id = ?
             ORDER BY d.upload_date DESC"
        );
        $stmt->execute([$filterUserId]);
    } else if ($isAdmin && isset($_GET['view_all'])) {
        $stmt = $pdo->prepare(
            "SELECT d.*, u.full_name as user_name, v.full_name as verifier_name 
             FROM documents d
             JOIN users u ON d.user_id = u.user_id
             LEFT JOIN users v ON d.verified_by = v.user_id
             ORDER BY d.upload_date DESC"
        );
        $stmt->execute();
    } else {
        // Data isolation: Users see only their own documents
        $stmt = $pdo->prepare(
            "SELECT d.*, u.full_name as user_name, v.full_name as verifier_name 
             FROM documents d
             JOIN users u ON d.user_id = u.user_id
             LEFT JOIN users v ON d.verified_by = v.user_id
             WHERE d.user_id = ?
             ORDER BY d.upload_date DESC"
        );
        $stmt->execute([$_SESSION['user_id']]);
    }
    
    $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error_message = "Error retrieving documents: " . $e->getMessage();
}

// Document verification workflow: Admin/Official only
if ($isAdmin && isset($_GET['action']) && $_GET['action'] === 'verify' && isset($_GET['id'])) {
    $documentId = (int)$_GET['id'];
    
    try {
        $pdo->beginTransaction();
        
        $stmt = $pdo->prepare(
            "UPDATE documents 
             SET is_verified = 1, verified_by = ?, verification_date = NOW() 
             WHERE document_id = ?"
        );
        $stmt->execute([$_SESSION['user_id'], $documentId]);
        
        logAccess($_SESSION['user_id'], 'Verified Document ID: ' . $documentId);
        
        $pdo->commit();
        $success_message = "Document verified successfully";
        
        if ($filterUserId) {
            header("Location: view_documents.php?user_id=" . $filterUserId . "&success=" . urlencode($success_message));
        } else {
            header("Location: view_documents.php?success=" . urlencode($success_message));
        }
        exit;
        
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $error_message = "Error verifying document: " . $e->getMessage();
    }
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
    <title>Documents - COVID Resilience System</title>
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
        
        .document-card {
            transition: transform 0.2s, box-shadow 0.2s;
            margin-bottom: 20px;
        }
        
        .document-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .document-icon {
            font-size: 1.5rem;
            color: #0d6efd;
        }
        
        .document-verified {
            position: absolute;
            top: 10px;
            right: 10px;
            color: #198754;
        }
        
        .document-unverified {
            position: absolute;
            top: 10px;
            right: 10px;
            color: #adb5bd;
        }
        
        .file-type-icon {
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            background-color: rgba(13, 110, 253, 0.1);
            margin-right: 15px;
        }
        
        .document-actions {
            display: flex;
            gap: 5px;
        }
        
        .badge-document-type {
            font-size: 0.75rem;
            padding: 0.25em 0.5em;
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
                    <h2>
                        <i class="bi bi-file-earmark-text me-2"></i>
                        <?php if ($isAdmin && isset($_GET['user_id'])): ?>
                            User Documents
                        <?php elseif ($isAdmin && isset($_GET['view_all'])): ?>
                            All Documents
                        <?php else: ?>
                            My Documents
                        <?php endif; ?>
                    </h2>
                    
                    <div>
                        <?php if ($isAdmin): ?>
                        <div class="btn-group me-2">
                            <a href="view_documents.php" class="btn btn-outline-primary">
                                <i class="bi bi-person me-1"></i>My Documents
                            </a>
                            <a href="view_documents.php?view_all=1" class="btn btn-outline-primary">
                                <i class="bi bi-people me-1"></i>All Documents
                            </a>
                        </div>
                        <?php endif; ?>
                        
                        <a href="document_upload.php" class="btn btn-primary">
                            <i class="bi bi-file-earmark-plus me-2"></i>Upload New Document
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
                
                <?php if ($isAdmin && isset($_GET['user_id'])): ?>
                <?php
                $userId = (int)$_GET['user_id'];
                $userStmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
                $userStmt->execute([$userId]);
                $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
                
                if ($userData):
                ?>
                <div class="alert alert-info mb-4">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-person-badge fs-3 me-3"></i>
                        <div>
                            <h5 class="mb-1">Viewing documents for: <?php echo htmlspecialchars($userData['full_name']); ?></h5>
                            <p class="mb-0">
                                PRS ID: <?php echo htmlspecialchars($userData['prs_id']); ?> | 
                                Role: <?php echo htmlspecialchars($userData['role']); ?> | 
                                Username: <?php echo htmlspecialchars($userData['username']); ?>
                            </p>
                        </div>
                        <a href="users.php" class="btn btn-sm btn-outline-secondary ms-auto">
                            <i class="bi bi-arrow-left me-1"></i>Back to Users
                        </a>
                    </div>
                </div>
                <?php endif; ?>
                <?php endif; ?>
                
                <?php if (empty($documents)): ?>
                <div class="alert alert-info">
                    <i class="bi bi-info-circle-fill me-2"></i>
                    No documents found. 
                    <a href="document_upload.php" class="alert-link">Upload your first document</a>.
                </div>
                <?php else: ?>
                
                <div class="row">
                    <?php foreach ($documents as $document): ?>
                    <?php
                    // Dynamic file type icon and styling based on MIME type
                    $iconClass = 'bi-file-earmark';
                    $bgColor = 'bg-secondary-subtle';
                    
                    if (strpos($document['mime_type'], 'pdf') !== false) {
                        $iconClass = 'bi-file-earmark-pdf';
                        $bgColor = 'bg-danger-subtle';
                    } else if (strpos($document['mime_type'], 'image') !== false) {
                        $iconClass = 'bi-file-earmark-image';
                        $bgColor = 'bg-success-subtle';
                    } else if (strpos($document['mime_type'], 'word') !== false || strpos($document['mime_type'], 'msword') !== false) {
                        $iconClass = 'bi-file-earmark-word';
                        $bgColor = 'bg-primary-subtle';
                    } else if (strpos($document['mime_type'], 'excel') !== false || strpos($document['mime_type'], 'spreadsheet') !== false) {
                        $iconClass = 'bi-file-earmark-excel';
                        $bgColor = 'bg-success-subtle';
                    } else if (strpos($document['mime_type'], 'text') !== false) {
                        $iconClass = 'bi-file-earmark-text';
                        $bgColor = 'bg-info-subtle';
                    }
                    
                    $typeBadgeClass = 'bg-secondary';
                    switch ($document['document_type']) {
                        case 'Vaccination Certificate':
                            $typeBadgeClass = 'bg-success';
                            break;
                        case 'ID Document':
                            $typeBadgeClass = 'bg-danger';
                            break;
                        case 'Medical Report':
                            $typeBadgeClass = 'bg-info';
                            break;
                    }
                    
                    // Human-readable file size formatting
                    $fileSize = $document['file_size'];
                    if ($fileSize < 1024) {
                        $fileSizeFormatted = $fileSize . ' B';
                    } else if ($fileSize < 1024 * 1024) {
                        $fileSizeFormatted = round($fileSize / 1024, 1) . ' KB';
                    } else {
                        $fileSizeFormatted = round($fileSize / (1024 * 1024), 1) . ' MB';
                    }
                    
                    $uploadDate = new DateTime($document['upload_date']);
                    $formattedDate = $uploadDate->format('M j, Y g:i A');
                    ?>
                    
                    <div class="col-md-6 col-lg-4">
                        <div class="card document-card h-100">
                            <?php if ($document['is_verified']): ?>
                            <div class="document-verified" title="Verified document">
                                <i class="bi bi-patch-check-fill"></i>
                            </div>
                            <?php else: ?>
                            <div class="document-unverified" title="Unverified document">
                                <i class="bi bi-patch-exclamation"></i>
                            </div>
                            <?php endif; ?>
                            
                            <div class="card-body">
                                <div class="d-flex mb-3">
                                    <div class="file-type-icon <?php echo $bgColor; ?>">
                                        <i class="bi <?php echo $iconClass; ?> fs-4"></i>
                                    </div>
                                    <div>
                                        <h5 class="mb-1 text-truncate" title="<?php echo htmlspecialchars($document['document_name']); ?>">
                                            <?php echo htmlspecialchars($document['document_name']); ?>
                                        </h5>
                                        <span class="badge <?php echo $typeBadgeClass; ?> badge-document-type">
                                            <?php echo htmlspecialchars($document['document_type']); ?>
                                        </span>
                                        <span class="badge bg-secondary badge-document-type">
                                            <?php echo $fileSizeFormatted; ?>
                                        </span>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <small class="text-muted d-block">
                                        <i class="bi bi-calendar me-1"></i> Uploaded: <?php echo $formattedDate; ?>
                                    </small>
                                    
                                    <?php if ($isAdmin && isset($_GET['view_all']) || $isAdmin && isset($_GET['user_id'])): ?>
                                    <small class="text-muted d-block">
                                        <i class="bi bi-person me-1"></i> Owner: <?php echo htmlspecialchars($document['user_name']); ?>
                                    </small>
                                    <?php endif; ?>
                                    
                                    <?php if ($document['is_verified'] && !empty($document['verifier_name'])): ?>
                                    <small class="text-muted d-block">
                                        <i class="bi bi-check-circle me-1"></i> Verified by: <?php echo htmlspecialchars($document['verifier_name']); ?>
                                        <?php if (!empty($document['verification_date'])): ?>
                                        on <?php echo (new DateTime($document['verification_date']))->format('M j, Y'); ?>
                                        <?php endif; ?>
                                    </small>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="document-actions">
                                    <a href="download_document.php?id=<?php echo $document['document_id']; ?>" class="btn btn-sm btn-primary" target="_blank">
                                        <i class="bi bi-download"></i> Download
                                    </a>
                                    
                                    <?php if ($isAdmin && !$document['is_verified']): ?>
                                    <a href="view_documents.php?action=verify&id=<?php echo $document['document_id']; ?><?php echo isset($_GET['user_id']) ? '&user_id=' . $_GET['user_id'] : ''; ?>" class="btn btn-sm btn-success">
                                        <i class="bi bi-check-circle"></i> Verify
                                    </a>
                                    <?php endif; ?>
                                    
                                    <?php if ($document['user_id'] == $_SESSION['user_id'] || $isAdmin): ?>
                                    <button type="button" class="btn btn-sm btn-danger" 
                                        onclick="confirmDelete(<?php echo $document['document_id']; ?>, '<?php echo htmlspecialchars(addslashes($document['document_name'])); ?>')">
                                        <i class="bi bi-trash"></i> Delete
                                    </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Dynamic URL building for delete confirmations with proper parameter preservation
        function confirmDelete(documentId, documentName) {
            if (confirm('Are you sure you want to delete the document "' + documentName + '"? This action cannot be undone.')) {
                window.location.href = 'view_documents.php?action=delete&id=' + documentId
                <?php if (isset($_GET['user_id'])): ?>
                + '&user_id=<?php echo (int)$_GET['user_id']; ?>'
                <?php endif; ?>
                <?php if (isset($_GET['view_all'])): ?>
                + '&view_all=1'
                <?php endif; ?>;
            }
        }
    </script>
</body>
</html>