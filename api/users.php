<?php
require_once '../config.php';
require_once '../session_check.php';
require_once '../database.php';

header('Content-Type: application/json');

session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$db = getDatabase();

$method = $_SERVER['REQUEST_METHOD'];

// RESTful routing based on HTTP method
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
        $userId = (int)$_GET['id'];
        
        // Special handling for current user context
        if ($_GET['id'] === 'current') {
            $userId = (int)$_SESSION['user_id'];
        }
        
        if (!canAccessUser($userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Permission denied']);
            return;
        }
        
        $user = $db->getOne(
            "SELECT user_id, prs_id, full_name, national_id, dob, role, username, email, created_at, updated_at 
             FROM users WHERE user_id = ?",
            [$userId]
        );
        
        if (!$user) {
            http_response_code(404);
            echo json_encode(['error' => 'User not found']);
            return;
        }
        
        // Secure response: Exclude sensitive fields like password
        echo json_encode(['data' => $user]);
        return;
    }
    
    // Paginated user listing with search and filtering capabilities
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    $searchTerm = isset($_GET['search']) ? trim($_GET['search']) : '';
    $whereClause = '';
    $params = [];
    
    if (!empty($searchTerm)) {
        $whereClause = "WHERE full_name LIKE ? OR username LIKE ? OR prs_id LIKE ? OR email LIKE ?";
        $searchPattern = "%$searchTerm%";
        $params = [$searchPattern, $searchPattern, $searchPattern, $searchPattern];
    }
    
    if (isset($_GET['role']) && !empty($_GET['role'])) {
        $role = trim($_GET['role']);
        $whereClause = empty($whereClause) ? "WHERE role = ?" : "$whereClause AND role = ?";
        $params[] = $role;
    }
    
    $totalCount = $db->getValue(
        "SELECT COUNT(*) FROM users $whereClause",
        $params
    );
    
    $users = $db->getAll(
        "SELECT user_id, prs_id, full_name, national_id, dob, role, username, email, created_at, updated_at 
         FROM users $whereClause ORDER BY user_id LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $totalPages = ceil($totalCount / $limit);
    
    echo json_encode([
        'data' => $users,
        'pagination' => [
            'total' => $totalCount,
            'per_page' => $limit,
            'current_page' => $page,
            'total_pages' => $totalPages
        ]
    ]);
}

function handlePost() {
    global $db;
    
    // Role-based creation permissions
    if (!hasRole(['Admin', 'Official'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $errors = validateUserInput($input, 'create');
    
    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(['error' => 'Validation failed', 'validation_errors' => $errors]);
        return;
    }
    
    // Uniqueness validation across multiple identifier fields
    $existingUser = $db->getOne(
        "SELECT user_id FROM users WHERE username = ? OR national_id = ? OR prs_id = ?",
        [$input['username'], $input['national_id'], $input['prs_id']]
    );
    
    if ($existingUser) {
        http_response_code(409);
        echo json_encode(['error' => 'User with this username, national ID, or PRS ID already exists']);
        return;
    }
    
    $input['password'] = hashPassword($input['password']);
    
    try {
        $db->beginTransaction();
        
        $userId = $db->insert('users', [
            'prs_id' => $input['prs_id'],
            'full_name' => $input['full_name'],
            'national_id' => $input['national_id'],
            'dob' => $input['dob'],
            'role' => $input['role'],
            'username' => $input['username'],
            'password' => $input['password'],
            'email' => $input['email'] ?? null
        ]);
        
        if (!$userId) {
            throw new Exception("Failed to insert user");
        }
        
        // Audit trail: Log user creation activity
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Create User',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode(['created_user_id' => $userId])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        http_response_code(201);
        echo json_encode(['message' => 'User created successfully', 'user_id' => $userId]);
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function handlePut() {
    global $db;
    
    if (!isset($_GET['id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'User ID is required']);
        return;
    }
    
    $userId = (int)$_GET['id'];
    
    if (!canAccessUser($userId, 'update')) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $existingUser = $db->getOne("SELECT * FROM users WHERE user_id = ?", [$userId]);
    
    if (!$existingUser) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $errors = validateUserInput($input, 'update');
    
    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(['error' => 'Validation failed', 'validation_errors' => $errors]);
        return;
    }
    
    // Conditional uniqueness checks only if values have changed
    if (isset($input['username']) && $input['username'] !== $existingUser['username']) {
        $usernameExists = $db->getValue(
            "SELECT COUNT(*) FROM users WHERE username = ? AND user_id != ?",
            [$input['username'], $userId]
        );
        
        if ($usernameExists) {
            http_response_code(409);
            echo json_encode(['error' => 'Username already taken']);
            return;
        }
    }
    
    if (isset($input['national_id']) && $input['national_id'] !== $existingUser['national_id']) {
        $nationalIdExists = $db->getValue(
            "SELECT COUNT(*) FROM users WHERE national_id = ? AND user_id != ?",
            [$input['national_id'], $userId]
        );
        
        if ($nationalIdExists) {
            http_response_code(409);
            echo json_encode(['error' => 'National ID already exists']);
            return;
        }
    }
    
    $updateData = [];
    
    // Role-based field access control
    $allowedFields = ['full_name', 'dob', 'username', 'email'];
    
    if (hasRole(['Admin', 'Official'])) {
        $allowedFields = array_merge($allowedFields, ['prs_id', 'national_id', 'role']);
    }
    
    foreach ($allowedFields as $field) {
        if (isset($input[$field])) {
            $updateData[$field] = $input[$field];
        }
    }
    
    if (isset($input['password']) && !empty($input['password'])) {
        $updateData['password'] = hashPassword($input['password']);
    }
    
    try {
        $db->beginTransaction();
        
        $result = $db->update('users', $updateData, 'user_id = ?', [$userId]);
        
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Update User',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode([
                'updated_user_id' => $userId,
                'updated_fields' => array_keys($updateData)
            ])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        echo json_encode(['message' => 'User updated successfully']);
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
        echo json_encode(['error' => 'User ID is required']);
        return;
    }
    
    $userId = (int)$_GET['id'];
    
    // Security: Prevent self-deletion to avoid losing admin access
    if ($userId === $_SESSION['user_id']) {
        http_response_code(400);
        echo json_encode(['error' => 'Cannot delete your own account']);
        return;
    }
    
    if (!hasRole(['Admin', 'Official'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $userExists = $db->getValue("SELECT COUNT(*) FROM users WHERE user_id = ?", [$userId]);
    
    if (!$userExists) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        return;
    }
    
    // Data integrity: Check for foreign key dependencies before deletion
    $dependencies = [
        'vaccination_records' => $db->getValue(
            "SELECT COUNT(*) FROM vaccination_records WHERE user_id = ?", 
            [$userId]
        ),
        'purchases' => $db->getValue(
            "SELECT COUNT(*) FROM purchases WHERE user_id = ?", 
            [$userId]
        ),
        'access_logs' => $db->getValue(
            "SELECT COUNT(*) FROM access_logs WHERE user_id = ?", 
            [$userId]
        ),
        'documents' => $db->getValue(
            "SELECT COUNT(*) FROM documents WHERE user_id = ?", 
            [$userId]
        )
    ];
    
    $hasDependencies = false;
    foreach ($dependencies as $count) {
        if ($count > 0) {
            $hasDependencies = true;
            break;
        }
    }
    
    if ($hasDependencies) {
        http_response_code(409);
        echo json_encode([
            'error' => 'Cannot delete user with associated records',
            'dependencies' => $dependencies
        ]);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $result = $db->delete('users', 'user_id = ?', [$userId]);
        
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Delete User',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode(['deleted_user_id' => $userId])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        echo json_encode(['message' => 'User deleted successfully']);
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function validateUserInput($input, $action = 'create') {
    $errors = [];
    
    if ($action === 'create') {
        $requiredFields = ['prs_id', 'full_name', 'national_id', 'dob', 'role', 'username', 'password'];
        
        foreach ($requiredFields as $field) {
            if (!isset($input[$field]) || empty($input[$field])) {
                $errors[$field] = ucfirst(str_replace('_', ' ', $field)) . ' is required';
            }
        }
        
        if (isset($input['prs_id']) && (!preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $input['prs_id']))) {
            $errors['prs_id'] = 'PRS ID must be 3-50 alphanumeric characters';
        }
    }
    
    if (isset($input['full_name'])) {
        if (empty($input['full_name'])) {
            $errors['full_name'] = 'Full name is required';
        } elseif (strlen($input['full_name']) > 100) {
            $errors['full_name'] = 'Full name must be less than 100 characters';
        }
    }
    
    if (isset($input['national_id'])) {
        if (empty($input['national_id'])) {
            $errors['national_id'] = 'National ID is required';
        } elseif (strlen($input['national_id']) > 50) {
            $errors['national_id'] = 'National ID must be less than 50 characters';
        }
    }
    
    if (isset($input['dob'])) {
        if (empty($input['dob'])) {
            $errors['dob'] = 'Date of birth is required';
        } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $input['dob'])) {
            $errors['dob'] = 'Date of birth must be in YYYY-MM-DD format';
        } else {
            $date = date_create_from_format('Y-m-d', $input['dob']);
            if (!$date) {
                $errors['dob'] = 'Invalid date format';
            } else {
                // Business rule: Minimum age requirement validation
                $now = new DateTime();
                $age = $now->diff($date)->y;
                if ($age < 18) {
                    $errors['dob'] = 'User must be at least 18 years old';
                }
            }
        }
    }
    
    if (isset($input['role'])) {
        $validRoles = ['Citizen', 'Merchant', 'Official', 'Admin', 'Doctor'];
        if (empty($input['role'])) {
            $errors['role'] = 'Role is required';
        } elseif (!in_array($input['role'], $validRoles)) {
            $errors['role'] = 'Invalid role. Must be one of: ' . implode(', ', $validRoles);
        }
    }
    
    if (isset($input['username'])) {
        if (empty($input['username'])) {
            $errors['username'] = 'Username is required';
        } elseif (strlen($input['username']) < 4 || strlen($input['username']) > 50) {
            $errors['username'] = 'Username must be between 4 and 50 characters';
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $input['username'])) {
            $errors['username'] = 'Username can only contain letters, numbers, and underscores';
        }
    }
    
    if (isset($input['password'])) {
        if ($action === 'create' && empty($input['password'])) {
            $errors['password'] = 'Password is required';
        } elseif (!empty($input['password']) && strlen($input['password']) < 6) {
            $errors['password'] = 'Password must be at least 6 characters';
        }
    }
    
    if (isset($input['email']) && !empty($input['email'])) {
        if (!filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Invalid email format';
        } elseif (strlen($input['email']) > 100) {
            $errors['email'] = 'Email must be less than 100 characters';
        }
    }
    
    return $errors;
}

function canAccessUser($targetUserId, $action = 'read') {
    $currentUserId = $_SESSION['user_id'];
    $currentUserRole = $_SESSION['role'];
    
    // Hierarchical permission model
    if (in_array($currentUserRole, ['Admin', 'Official'])) {
        return true;
    }
    
    if ($currentUserId === $targetUserId) {
        return true;
    }
    
    return false;
}