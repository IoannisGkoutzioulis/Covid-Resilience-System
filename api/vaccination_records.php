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
        $recordId = (int)$_GET['id'];
        
        $record = $db->getOne(
            "SELECT vr.*, u.full_name as user_name 
             FROM vaccination_records vr
             JOIN users u ON vr.user_id = u.user_id
             WHERE vaccination_id = ?",
            [$recordId]
        );
        
        if (!$record) {
            http_response_code(404);
            echo json_encode(['error' => 'Vaccination record not found']);
            return;
        }
        
        if (!canAccessVaccinationRecord($record)) {
            http_response_code(403);
            echo json_encode(['error' => 'Permission denied']);
            return;
        }
        
        echo json_encode(['data' => $record]);
        return;
    }
    
    // User-specific vaccination record retrieval
    if (isset($_GET['user_id'])) {
        $userId = (int)$_GET['user_id'];
        
        if (!canAccessUser($userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Permission denied']);
            return;
        }
        
        $records = $db->getAll(
            "SELECT vr.*, u.full_name as user_name 
             FROM vaccination_records vr
             JOIN users u ON vr.user_id = u.user_id
             WHERE vr.user_id = ?
             ORDER BY vr.date_administered DESC",
            [$userId]
        );
        
        echo json_encode(['data' => $records]);
        return;
    }
    
    // Role-based access control for comprehensive vaccination data
    if (!hasRole(['Admin', 'Official', 'Doctor'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? min(100, max(1, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    // Advanced filtering capabilities for vaccination records
    $conditions = [];
    $params = [];
    
    if (isset($_GET['vaccine_type']) && !empty($_GET['vaccine_type'])) {
        $conditions[] = "vr.vaccine_type = ?";
        $params[] = $_GET['vaccine_type'];
    }
    
    if (isset($_GET['date_from']) && !empty($_GET['date_from'])) {
        $conditions[] = "vr.date_administered >= ?";
        $params[] = $_GET['date_from'];
    }
    
    if (isset($_GET['date_to']) && !empty($_GET['date_to'])) {
        $conditions[] = "vr.date_administered <= ?";
        $params[] = $_GET['date_to'];
    }
    
    if (isset($_GET['traveler']) && in_array($_GET['traveler'], ['0', '1'])) {
        $conditions[] = "vr.traveler_flag = ?";
        $params[] = (int)$_GET['traveler'];
    }
    
    $whereClause = empty($conditions) ? "" : "WHERE " . implode(" AND ", $conditions);
    
    $totalCount = $db->getValue(
        "SELECT COUNT(*) FROM vaccination_records vr $whereClause",
        $params
    );
    
    $records = $db->getAll(
        "SELECT vr.*, u.full_name as user_name 
         FROM vaccination_records vr
         JOIN users u ON vr.user_id = u.user_id
         $whereClause
         ORDER BY vr.date_administered DESC
         LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $totalPages = ceil($totalCount / $limit);
    
    echo json_encode([
        'data' => $records,
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
    
    // Medical professional authorization for record creation
    if (!hasRole(['Admin', 'Official', 'Doctor'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $errors = validateVaccinationInput($input);
    
    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(['error' => 'Validation failed', 'validation_errors' => $errors]);
        return;
    }
    
    $userExists = $db->getValue("SELECT COUNT(*) FROM users WHERE user_id = ?", [$input['user_id']]);
    
    if (!$userExists) {
        http_response_code(400);
        echo json_encode(['error' => 'User not found']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $recordId = $db->insert('vaccination_records', [
            'user_id' => $input['user_id'],
            'vaccine_type' => $input['vaccine_type'],
            'dose_number' => $input['dose_number'],
            'date_administered' => $input['date_administered'],
            'administered_by' => $input['administered_by'],
            'traveler_flag' => $input['traveler_flag'] ?? 0,
            'certification' => $input['certification'] ?? null
        ]);
        
        if (!$recordId) {
            throw new Exception("Failed to insert vaccination record");
        }
        
        // Medical record audit trail
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Create Vaccination Record',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode([
                'record_id' => $recordId,
                'for_user_id' => $input['user_id']
            ])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        http_response_code(201);
        echo json_encode([
            'message' => 'Vaccination record created successfully',
            'vaccination_id' => $recordId
        ]);
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
        echo json_encode(['error' => 'Vaccination record ID is required']);
        return;
    }
    
    $recordId = (int)$_GET['id'];
    
    $record = $db->getOne("SELECT * FROM vaccination_records WHERE vaccination_id = ?", [$recordId]);
    
    if (!$record) {
        http_response_code(404);
        echo json_encode(['error' => 'Vaccination record not found']);
        return;
    }
    
    if (!hasRole(['Admin', 'Official', 'Doctor'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $errors = validateVaccinationInput($input, 'update');
    
    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(['error' => 'Validation failed', 'validation_errors' => $errors]);
        return;
    }
    
    $updateData = [];
    
    $allowedFields = [
        'vaccine_type', 
        'dose_number', 
        'date_administered', 
        'administered_by', 
        'traveler_flag', 
        'certification'
    ];
    
    foreach ($allowedFields as $field) {
        if (isset($input[$field])) {
            $updateData[$field] = $input[$field];
        }
    }
    
    // Admin-only user reassignment capability
    if (isset($input['user_id']) && hasRole(['Admin'])) {
        $userExists = $db->getValue("SELECT COUNT(*) FROM users WHERE user_id = ?", [$input['user_id']]);
        
        if (!$userExists) {
            http_response_code(400);
            echo json_encode(['error' => 'User not found']);
            return;
        }
        
        $updateData['user_id'] = $input['user_id'];
    }
    
    try {
        $db->beginTransaction();
        
        $result = $db->update(
            'vaccination_records', 
            $updateData, 
            'vaccination_id = ?', 
            [$recordId]
        );
        
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Update Vaccination Record',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode([
                'record_id' => $recordId,
                'updated_fields' => array_keys($updateData)
            ])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        echo json_encode(['message' => 'Vaccination record updated successfully']);
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
        echo json_encode(['error' => 'Vaccination record ID is required']);
        return;
    }
    
    $recordId = (int)$_GET['id'];
    
    $record = $db->getOne("SELECT * FROM vaccination_records WHERE vaccination_id = ?", [$recordId]);
    
    if (!$record) {
        http_response_code(404);
        echo json_encode(['error' => 'Vaccination record not found']);
        return;
    }
    
    // Restrictive deletion permissions for data integrity
    if (!hasRole(['Admin', 'Official'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Permission denied']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $db->delete('vaccination_records', 'vaccination_id = ?', [$recordId]);
        
        $logEntry = [
            'user_id' => $_SESSION['user_id'],
            'access_type' => 'Delete Vaccination Record',
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'location' => 'API',
            'success' => 1,
            'additional_info' => json_encode([
                'record_id' => $recordId,
                'user_id' => $record['user_id']
            ])
        ];
        
        $db->insert('access_logs', $logEntry);
        
        $db->commit();
        
        echo json_encode(['message' => 'Vaccination record deleted successfully']);
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

function validateVaccinationInput($input, $action = 'create') {
    $errors = [];
    
    if ($action === 'create') {
        $requiredFields = ['user_id', 'vaccine_type', 'dose_number', 'date_administered', 'administered_by'];
        
        foreach ($requiredFields as $field) {
            if (!isset($input[$field]) || (is_string($input[$field]) && trim($input[$field]) === '') || $input[$field] === null) {
                $errors[$field] = ucfirst(str_replace('_', ' ', $field)) . ' is required';
            }
        }
    }
    
    if (isset($input['user_id'])) {
        if (!is_numeric($input['user_id']) || $input['user_id'] <= 0) {
            $errors['user_id'] = 'Invalid user ID';
        }
    }
    
    if (isset($input['vaccine_type'])) {
        if (empty($input['vaccine_type'])) {
            $errors['vaccine_type'] = 'Vaccine type is required';
        } elseif (strlen($input['vaccine_type']) > 100) {
            $errors['vaccine_type'] = 'Vaccine type must be less than 100 characters';
        }
    }
    
    if (isset($input['dose_number'])) {
        if (!is_numeric($input['dose_number']) || $input['dose_number'] <= 0) {
            $errors['dose_number'] = 'Dose number must be a positive integer';
        }
    }
    
    if (isset($input['date_administered'])) {
        if (empty($input['date_administered'])) {
            $errors['date_administered'] = 'Date administered is required';
        } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $input['date_administered'])) {
            $errors['date_administered'] = 'Date administered must be in YYYY-MM-DD format';
        } else {
            // Business rule: Vaccination date cannot be in the future
            $date = date_create_from_format('Y-m-d', $input['date_administered']);
            $today = new DateTime();
            
            if (!$date) {
                $errors['date_administered'] = 'Invalid date format';
            } elseif ($date > $today) {
                $errors['date_administered'] = 'Date administered cannot be in the future';
            }
        }
    }
    
    if (isset($input['administered_by'])) {
        if (empty($input['administered_by'])) {
            $errors['administered_by'] = 'Administrator name is required';
        } elseif (strlen($input['administered_by']) > 255) {
            $errors['administered_by'] = 'Administrator name must be less than 255 characters';
        }
    }
    
    if (isset($input['traveler_flag'])) {
        if (!is_bool($input['traveler_flag']) && !in_array($input['traveler_flag'], [0, 1, '0', '1'])) {
            $errors['traveler_flag'] = 'Traveler flag must be a boolean value';
        }
    }
    
    if (isset($input['certification']) && !empty($input['certification'])) {
        if (strlen($input['certification']) > 255) {
            $errors['certification'] = 'Certification must be less than 255 characters';
        }
    }
    
    return $errors;
}

function canAccessVaccinationRecord($record) {
    // Hierarchical access model for medical records
    if (hasRole(['Admin', 'Official', 'Doctor'])) {
        return true;
    }
    
    if ($_SESSION['user_id'] === $record['user_id']) {
        return true;
    }
    
    return false;
}

function canAccessUser($targetUserId) {
    if (hasRole(['Admin', 'Official', 'Doctor'])) {
        return true;
    }
    
    if ($_SESSION['user_id'] === $targetUserId) {
        return true;
    }
    
    return false;
}