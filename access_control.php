<?php

// Role-based permissions matrix: [role][resource][allowed_actions]
$permissionsMatrix = [
    'Citizen' => [
        'users' => ['read'],
        'doctors' => ['read'],
        'vaccination_records' => ['read'],
        'documents' => ['read', 'create'],
        'merchants' => ['read'],
        'stock' => ['read'],
        'purchases' => ['read', 'create'],
        'government_officials' => ['read'],
        'critical_items' => ['read'],
        'access_logs' => ['read']
    ],
    'Merchant' => [
        'users' => ['read'],
        'doctors' => ['read'],
        'vaccination_records' => ['read', 'create', 'update', 'delete'],
        'documents' => ['read', 'create', 'update', 'delete'],
        'merchants' => ['read', 'update'],
        'stock' => ['read', 'create', 'update', 'delete'],
        'purchases' => ['read', 'create', 'update', 'delete'],
        'government_officials' => ['read'],
        'critical_items' => ['read', 'create', 'update'],
        'access_logs' => ['read']
    ],
    'Official' => [
        'users' => ['read', 'create', 'update', 'delete'],
        'doctors' => ['read', 'create', 'update', 'delete'],
        'vaccination_records' => ['read', 'create', 'update', 'delete'],
        'documents' => ['read', 'create', 'update', 'delete'],
        'merchants' => ['read', 'create', 'update', 'delete'],
        'stock' => ['read', 'create', 'update', 'delete'],
        'purchases' => ['read', 'create', 'update', 'delete'],
        'government_officials' => ['read', 'create', 'update', 'delete'],
        'critical_items' => ['read', 'create', 'update', 'delete'],
        'access_logs' => ['read', 'create'],
        'merchant_approval' => ['read', 'update'],
        'document_verification' => ['read', 'update']
    ],
    'Admin' => [
        'users' => ['read', 'create', 'update', 'delete'],
        'doctors' => ['read', 'create', 'update', 'delete'],
        'vaccination_records' => ['read', 'create', 'update', 'delete'],
        'documents' => ['read', 'create', 'update', 'delete'],
        'merchants' => ['read', 'create', 'update', 'delete'],
        'stock' => ['read', 'create', 'update', 'delete'],
        'purchases' => ['read', 'create', 'update', 'delete'],
        'government_officials' => ['read', 'create', 'update', 'delete'],
        'critical_items' => ['read', 'create', 'update', 'delete'],
        'access_logs' => ['read', 'create', 'update', 'delete'],
        'merchant_approval' => ['read', 'create', 'update', 'delete'],
        'document_verification' => ['read', 'create', 'update', 'delete'],
        'system_settings' => ['read', 'create', 'update', 'delete']
    ]
];

/**
 * Check if current user has permission for a resource and action
 * 
 * @param string $resource The resource (e.g., 'users', 'documents')
 * @param string $action The action (e.g., 'read', 'create', 'update', 'delete')
 * @return bool True if user has permission, false otherwise
 */
function hasPermission($resource, $action) {
    global $permissionsMatrix;
    
    if (!isset($_SESSION['role'])) {
        return false;
    }
    
    $role = $_SESSION['role'];
    
    if (!isset($permissionsMatrix[$role])) {
        return false;
    }
    
    if (!isset($permissionsMatrix[$role][$resource])) {
        return false;
    }
    
    return in_array($action, $permissionsMatrix[$role][$resource]);
}

/**
 * Enforce permission check and redirect if not authorized
 * 
 * @param string $resource The resource (e.g., 'users', 'documents')
 * @param string $action The action (e.g., 'read', 'create', 'update', 'delete')
 * @param string $redirect URL to redirect to if not authorized
 */
function enforcePermission($resource, $action, $redirect = 'dashboard.php') {
    if (!hasPermission($resource, $action)) {
        $_SESSION['error_message'] = "Access denied: You don't have permission to $action $resource";
        header("Location: $redirect");
        exit();
    }
}

/**
 * Generate HTML for conditional UI elements based on permissions
 * 
 * @param string $resource The resource (e.g., 'users', 'documents')
 * @param string $action The action (e.g., 'read', 'create', 'update', 'delete')
 * @param string $html The HTML to display if allowed
 * @return string The HTML if allowed, empty string otherwise
 */
function permissionBasedHTML($resource, $action, $html) {
    if (hasPermission($resource, $action)) {
        return $html;
    }
    return '';
}

function canApproveMerchants() {
    return hasPermission('merchant_approval', 'update');
}

function isApprovedMerchant() {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Merchant') {
        return false;
    }
    
    // Double-check approval status if function exists
    if (function_exists('checkMerchantApproval')) {
        $approval = checkMerchantApproval($_SESSION['user_id']);
        return $approval['approved'];
    }
    
    return true; // Assume approved if we can't check (user already logged in)
}

/**
 * Check if user is eligible to purchase face masks based on birth year last digit
 * Business Rule: Different birth year endings can purchase on different days of the week
 * 
 * @param string $dob Date of birth in any format that strtotime can parse
 * @param bool $override Optional override for admins/officials
 * @return array Associative array with 'eligible' (bool) and 'message' (string)
 */
function checkPurchaseEligibility($dob, $override = false) {
    // Admin/Official override
    if ($override && isset($_SESSION['role']) && in_array($_SESSION['role'], ['Admin', 'Official'])) {
        return [
            'eligible' => true, 
            'message' => 'Administrative override'
        ];
    }
    
    // Merchants can always make purchases (if approved)
    if (isset($_SESSION['role']) && $_SESSION['role'] === 'Merchant') {
        if (isApprovedMerchant()) {
            return [
                'eligible' => true, 
                'message' => 'Approved merchants can always make purchases'
            ];
        } else {
            return [
                'eligible' => false, 
                'message' => 'Merchant account not approved for purchases'
            ];
        }
    }
    
    $dobTimestamp = strtotime($dob);
    if (!$dobTimestamp) {
        return [
            'eligible' => false, 
            'message' => 'Invalid date of birth'
        ];
    }
    
    $birthYear = date('Y', $dobTimestamp);
    $lastDigit = $birthYear % 10;
    
    // Convert Sunday from 7 to 0 for easier calculation
    $dayOfWeek = date('N');
    if ($dayOfWeek == 7) $dayOfWeek = 0;
    
    $eligibleDays = [];
    $eligibleDayNames = [];
    
    // Purchase eligibility rules based on birth year last digit
    if ($lastDigit == 0 || $lastDigit == 2) {
        $eligibleDays[] = 1; // Monday
        $eligibleDayNames[] = 'Monday';
    }
    
    if ($lastDigit == 1 || $lastDigit == 3) {
        $eligibleDays[] = 2; // Tuesday
        $eligibleDayNames[] = 'Tuesday';
    }
    
    if ($lastDigit == 2 || $lastDigit == 4) {
        $eligibleDays[] = 3; // Wednesday
        $eligibleDayNames[] = 'Wednesday';
    }
    
    if ($lastDigit == 3 || $lastDigit == 5) {
        $eligibleDays[] = 4; // Thursday
        $eligibleDayNames[] = 'Thursday';
    }
    
    if ($lastDigit == 4 || $lastDigit == 6) {
        $eligibleDays[] = 5; // Friday
        $eligibleDayNames[] = 'Friday';
    }
    
    if ($lastDigit == 5 || $lastDigit == 7) {
        $eligibleDays[] = 6; // Saturday
        $eligibleDayNames[] = 'Saturday';
    }
    
    if ($lastDigit == 6 || $lastDigit == 8 || $lastDigit == 9) {
        $eligibleDays[] = 0; // Sunday
        $eligibleDayNames[] = 'Sunday';
    }
    
    $isEligible = in_array($dayOfWeek, $eligibleDays);
    
    if ($isEligible) {
        return [
            'eligible' => true,
            'message' => "You are eligible to purchase face masks today (birth year ending in $lastDigit)."
        ];
    } else {
        return [
            'eligible' => false,
            'message' => "With birth year ending in $lastDigit, you can only purchase face masks on " . implode(' and ', $eligibleDayNames) . "."
        ];
    }
}

function getRoleName($role) {
    $roleNames = [
        'Admin' => 'Administrator',
        'Official' => 'Government Official',
        'Merchant' => 'Merchant',
        'Citizen' => 'Citizen',
        'Doctor' => 'Medical Professional'
    ];
    
    return $roleNames[$role] ?? $role;
}

function canAccessMerchantFeatures() {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'Merchant') {
        return false;
    }
    
    return isApprovedMerchant();
}
?>