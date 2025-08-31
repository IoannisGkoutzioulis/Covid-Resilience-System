<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$success_message = $error_message = '';

// Handle clear old logs action (Officials only, 30+ days retention policy)
if (isset($_GET['action']) && $_GET['action'] === 'clear_old' && hasRole(['Official'])) {
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("DELETE FROM access_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stmt->execute();
        
        $rowsAffected = $stmt->rowCount();
        if ($rowsAffected > 0) {
            $success_message = "$rowsAffected old access logs cleared successfully";
        } else {
            $success_message = "No old logs found to clear";
        }
    } catch (PDOException $e) {
        $error_message = "Error clearing logs: " . $e->getMessage();
    }
}

$userIdFilter = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;

try {
    $pdo = getDBConnection();
    
    // Query with optional user filtering
    if ($userIdFilter > 0) {
        $query = "SELECT l.*, u.username 
                 FROM access_logs l
                 LEFT JOIN users u ON l.user_id = u.user_id
                 WHERE l.user_id = :user_id
                 ORDER BY l.timestamp DESC";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':user_id', $userIdFilter, PDO::PARAM_INT);
    } else {
        $query = "SELECT l.*, u.username 
                 FROM access_logs l
                 LEFT JOIN users u ON l.user_id = u.user_id
                 ORDER BY l.timestamp DESC
                 LIMIT 1000"; // Prevent excessive data loading
        $stmt = $pdo->prepare($query);
    }
    
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get filtered user's name for display
    $filterUserName = "";
    if ($userIdFilter > 0) {
        $userStmt = $pdo->prepare("SELECT full_name FROM users WHERE user_id = :user_id");
        $userStmt->bindParam(':user_id', $userIdFilter, PDO::PARAM_INT);
        $userStmt->execute();
        $userData = $userStmt->fetch(PDO::FETCH_ASSOC);
        if ($userData) {
            $filterUserName = $userData['full_name'];
        }
    }
} catch (PDOException $e) {
    $error_message = "Error fetching logs: " . $e->getMessage();
    $logs = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Logs - COVID Resilience System</title>
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
        
        .log-success {
            color: #198754;
        }
        
        .log-warning {
            color: #ffc107;
        }
        
        .log-danger {
            color: #dc3545;
        }
        
        .status-badge {
            font-size: 0.8rem;
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
    <!-- Top Navigation Bar -->
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
            <!-- Sidebar -->
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
                        <a class="nav-link active" href="access_logs.php">
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
            
            <!-- Main Content -->
            <div class="col-md-10 p-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>
                            <i class="bi bi-file-earmark-text me-2"></i>Access Logs
                            <?php if (!empty($filterUserName)): ?>
                            <span class="fs-5 text-muted">- Filtered for: <?php echo htmlspecialchars($filterUserName); ?></span>
                            <?php endif; ?>
                        </h2>
                    </div>
                    <div>
                        <?php if ($userIdFilter > 0): ?>
                        <a href="access_logs.php" class="btn btn-secondary me-2">
                            <i class="bi bi-x-circle me-2"></i>Clear Filter
                        </a>
                        <?php endif; ?>
                        
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh
                        </button>
                        
                        <?php if (hasRole(['Official'])): ?>
                        <button type="button" class="btn btn-danger" onclick="confirmClearOld()">
                            <i class="bi bi-trash me-2"></i>Clear Old Logs (30+ days)
                        </button>
                        <?php endif; ?>
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
                        <div class="input-group mb-3">
                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                            <input type="text" id="searchInput" class="form-control" placeholder="Search logs by user, type, IP..." oninput="filterTable()">
                        </div>
                        
                        <div class="mb-3">
                            <div class="btn-group" role="group">
                                <button type="button" class="btn btn-outline-secondary" onclick="filterAccessType('all')">All</button>
                                <button type="button" class="btn btn-outline-success" onclick="filterAccessType('login')">Login/Logout</button>
                                <button type="button" class="btn btn-outline-primary" onclick="filterAccessType('view')">View</button>
                                <button type="button" class="btn btn-outline-warning" onclick="filterAccessType('edit')">Edit</button>
                                <button type="button" class="btn btn-outline-info" onclick="filterAccessType('create')">Create</button>
                                <button type="button" class="btn btn-outline-danger" onclick="filterAccessType('delete')">Delete</button>
                                <button type="button" class="btn btn-outline-dark" onclick="filterAccessType('critical')">Critical Items</button>
                            </div>
                        </div>

                        <div class="table-responsive">
                            <table id="logsTable" class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">Log ID <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(1)">User <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(2)">Access Type <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(3)">Timestamp <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(4)">IP Address <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(5)">Location <i class="bi bi-arrow-down-up"></i></th>
                                        <th onclick="sortTable(6)">Status <i class="bi bi-arrow-down-up"></i></th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($logs)): ?>
                                    <tr><td colspan="8" class="text-center">No logs found</td></tr>
                                    <?php else: ?>
                                    <?php foreach ($logs as $log): ?>
                                    <tr data-access-type="<?php echo strtolower($log['access_type'] ?? ''); ?>">
                                        <td><?php echo htmlspecialchars($log['log_id'] ?? 'N/A'); ?></td>
                                        <td>
                                            <?php if (!empty($log['user_id'])): ?>
                                                <a href="access_logs.php?user_id=<?php echo $log['user_id']; ?>" title="Filter by this user">
                                                    <?php echo htmlspecialchars($log['username'] ?? 'Unknown'); ?> (ID: <?php echo $log['user_id']; ?>)
                                                </a>
                                            <?php else: ?>
                                                Anonymous
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php 
                                            $accessTypeIcon = '';
                                            $isCriticalItem = false;
                                            
                                            // Check for critical item operations
                                            if (strpos(strtolower($log['access_type'] ?? ''), 'critical') !== false) {
                                                $isCriticalItem = true;
                                            }
                                            
                                            // Access type icon mapping
                                            switch ($log['access_type'] ?? '') {
                                                case 'Login':
                                                    $accessTypeIcon = '<i class="bi bi-box-arrow-in-right me-1 text-success"></i>';
                                                    break;
                                                case 'Logout':
                                                    $accessTypeIcon = '<i class="bi bi-box-arrow-left me-1 text-danger"></i>';
                                                    break;
                                                case 'View':
                                                    $accessTypeIcon = '<i class="bi bi-eye me-1 text-primary"></i>';
                                                    break;
                                                case 'View Critical Item':
                                                    $accessTypeIcon = '<i class="bi bi-eye me-1 text-primary"></i>';
                                                    break;
                                                case 'Edit':
                                                    $accessTypeIcon = '<i class="bi bi-pencil me-1 text-warning"></i>';
                                                    break;
                                                case 'Edit Critical Item':
                                                    $accessTypeIcon = '<i class="bi bi-pencil me-1 text-warning"></i>';
                                                    break;
                                                case 'Delete':
                                                    $accessTypeIcon = '<i class="bi bi-trash me-1 text-danger"></i>';
                                                    break;
                                                case 'Delete Critical Item':
                                                    $accessTypeIcon = '<i class="bi bi-trash me-1 text-danger"></i>';
                                                    break;
                                                case 'Create':
                                                    $accessTypeIcon = '<i class="bi bi-plus-circle me-1 text-success"></i>';
                                                    break;
                                                case 'Create Critical Item':
                                                    $accessTypeIcon = '<i class="bi bi-plus-circle me-1 text-success"></i>';
                                                    break;
                                                case 'Sell Critical Item':
                                                    $accessTypeIcon = '<i class="bi bi-cart me-1 text-primary"></i>';
                                                    break;
                                                case 'Sell Item':
                                                    $accessTypeIcon = '<i class="bi bi-cart me-1 text-primary"></i>';
                                                    break;
                                                case 'Critical Item Request':
                                                    $accessTypeIcon = '<i class="bi bi-shield-plus me-1 text-info"></i>';
                                                    break;
                                                case 'Critical Item Approval':
                                                    $accessTypeIcon = '<i class="bi bi-check2-circle me-1 text-success"></i>';
                                                    break;
                                                case 'Critical Item Rejection':
                                                    $accessTypeIcon = '<i class="bi bi-x-circle me-1 text-danger"></i>';
                                                    break;
                                                default:
                                                    $accessTypeIcon = '<i class="bi bi-question-circle me-1"></i>';
                                            }
                                            
                                            $criticalBadge = $isCriticalItem ? 
                                                ' <span class="badge bg-dark text-light">Critical</span>' : '';
                                            
                                            echo $accessTypeIcon . htmlspecialchars($log['access_type'] ?? 'Unknown') . $criticalBadge;
                                            ?>
                                        </td>
                                        <td><?php echo isset($log['timestamp']) ? date('M j, Y g:i:s A', strtotime($log['timestamp'])) : 'N/A'; ?></td>
                                        <td><?php echo htmlspecialchars($log['ip_address'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($log['location'] ?? 'Unknown'); ?></td>
                                        
                                        <td>
                                            <?php 
                                            $success = isset($log['success']) ? (int)$log['success'] : -1;
                                            
                                            if ($success === 1) {
                                                echo '<span class="badge bg-success status-badge">Success</span>';
                                            } elseif ($success === 0) {
                                                echo '<span class="badge bg-danger status-badge">Failed</span>';
                                            } else {
                                                echo '<span class="badge bg-secondary status-badge">Unknown</span>';
                                            }
                                            ?>
                                        </td>
                                        
                                        <td>
                                            <?php if (!empty($log['details'])): ?>
                                            <button type="button" class="btn btn-sm btn-info" 
                                                    data-bs-toggle="tooltip" data-bs-placement="left" 
                                                    title="<?php echo htmlspecialchars($log['details']); ?>">
                                                <i class="bi bi-info-circle"></i>
                                            </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>

                        <div class="d-flex justify-content-between mt-3">
                            <div>
                                Total: <span id="totalLogs"><?php echo count($logs); ?></span> log<?php echo count($logs) != 1 ? 's' : ''; ?>
                                <?php if (count($logs) >= 1000 && !$userIdFilter): ?>
                                <small class="text-muted">(showing latest 1000 entries)</small>
                                <?php endif; ?>
                            </div>
                            <div>
                                <nav aria-label="Page navigation">
                                    <ul class="pagination">
                                        <li class="page-item">
                                            <a class="page-link" href="#" onclick="prevPage(); return false;" aria-label="Previous">
                                                <span aria-hidden="true">&laquo;</span>
                                            </a>
                                        </li>
                                        <li class="page-item">
                                            <span class="page-link" id="pageNumber">Page 1</span>
                                        </li>
                                        <li class="page-item">
                                            <a class="page-link" href="#" onclick="nextPage(); return false;" aria-label="Next">
                                                <span aria-hidden="true">&raquo;</span>
                                            </a>
                                        </li>
                                    </ul>
                                </nav>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="access_logs.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    });
    
    function confirmClearOld() {
        if (confirm("Are you sure you want to clear all logs older than 30 days? This action cannot be undone.")) {
            window.location.href = "access_logs.php?action=clear_old";
        }
    }
    
    // Table filtering functionality
    const allRows = Array.from(document.querySelectorAll('#logsTable tbody tr'));
    
    function filterTable() {
        const filter = document.getElementById("searchInput").value.toLowerCase();
        
        let visibleCount = 0;
        
        allRows.forEach(row => {
            if (row.cells.length <= 1) return;
            
            let userCell = row.cells[1]?.textContent.toLowerCase() || '';
            let typeCell = row.cells[2]?.textContent.toLowerCase() || '';
            let ipCell = row.cells[4]?.textContent.toLowerCase() || '';
            let locationCell = row.cells[5]?.textContent.toLowerCase() || '';
            let statusCell = row.cells[6]?.textContent.toLowerCase() || '';
            
            if (userCell.includes(filter) || 
                typeCell.includes(filter) || 
                ipCell.includes(filter) ||
                locationCell.includes(filter) ||
                statusCell.includes(filter)) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });
        
        document.getElementById('totalLogs').textContent = visibleCount;
    }
    
    function filterAccessType(type) {
        let visibleCount = 0;
        
        allRows.forEach(row => {
            if (row.cells.length <= 1) return;
            
            if (type === 'all') {
                row.style.display = '';
                visibleCount++;
                return;
            }
            
            const accessTypeCell = row.cells[2]?.textContent.toLowerCase() || '';
            
            if (type === 'login' && (accessTypeCell.includes('login') || accessTypeCell.includes('logout'))) {
                row.style.display = '';
                visibleCount++;
            } else if (type === 'view' && accessTypeCell.includes('view')) {
                row.style.display = '';
                visibleCount++;
            } else if (type === 'edit' && accessTypeCell.includes('edit')) {
                row.style.display = '';
                visibleCount++;
            } else if (type === 'create' && accessTypeCell.includes('create')) {
                row.style.display = '';
                visibleCount++;
            } else if (type === 'delete' && accessTypeCell.includes('delete')) {
                row.style.display = '';
                visibleCount++;
            } else if (type === 'critical' && accessTypeCell.includes('critical')) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });
        
        document.getElementById('totalLogs').textContent = visibleCount;
    }
    
    function sortTable(colIndex) {
        const table = document.getElementById('logsTable');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        if (rows.length <= 1 || rows[0].cells.length <= 1) return;
        
        rows.sort((a, b) => {
            if (!a.cells[colIndex] || !b.cells[colIndex]) return 0;
            
            let aValue = a.cells[colIndex]?.textContent.toLowerCase() || '';
            let bValue = b.cells[colIndex]?.textContent.toLowerCase() || '';
            
            // Special sorting for numeric log ID
            if (colIndex === 0) {
                return parseInt(aValue) - parseInt(bValue);
            }
            
            // Special sorting for timestamp
            if (colIndex === 3) {
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
    
    // Pagination functionality
    let currentPage = 1;
    const rowsPerPage = 15;
    
    function renderPage() {
        const tableBody = document.querySelector("#logsTable tbody");
        const rows = Array.from(tableBody.querySelectorAll('tr')).filter(row => row.style.display !== 'none');
        
        if (rows.length === 0 || rows[0].cells.length <= 1) return;
        
        const totalPages = Math.ceil(rows.length / rowsPerPage);
        
        if (currentPage > totalPages) {
            currentPage = totalPages;
        }
        
        const start = (currentPage - 1) * rowsPerPage;
        const end = start + rowsPerPage;
        
        rows.forEach((row, index) => {
            if (index >= start && index < end) {
                row.classList.remove('d-none');
            } else {
                row.classList.add('d-none');
            }
        });
        
        document.getElementById("pageNumber").innerText = `Page ${currentPage} of ${totalPages}`;
    }
    
    function nextPage() {
        const rows = Array.from(document.querySelectorAll('#logsTable tbody tr')).filter(row => row.style.display !== 'none');
        const totalPages = Math.ceil(rows.length / rowsPerPage);
        
        if (currentPage < totalPages) {
            currentPage++;
            renderPage();
        }
    }
    
    function prevPage() {
        if (currentPage > 1) {
            currentPage--;
            renderPage();
        }
    }
    
    document.addEventListener('DOMContentLoaded', function() {
        renderPage();
    });
    </script>
</body>
</html>