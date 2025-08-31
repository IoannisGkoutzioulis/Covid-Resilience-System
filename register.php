<?php
require_once 'config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$firstname = $lastname = $national_id = $dob = $username = $password = $email = $role = $city = '';
$merchant_name = $contact_phone = $business_license = '';
$official_role = $authorized_area = '';
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF protection for registration security
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $errors[] = "Security validation failed. Please try again.";
    } else {
        $firstname = sanitizeInput($_POST['firstname']);
        $lastname = sanitizeInput($_POST['lastname']);
        $national_id = sanitizeInput($_POST['national_id']);
        $dob = sanitizeInput($_POST['dob']);
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];
        $email = sanitizeInput($_POST['email'] ?? '');
        $city = sanitizeInput($_POST['city'] ?? '');
        $role = sanitizeInput($_POST['role'] ?? 'Citizen');
        
        $merchant_name = sanitizeInput($_POST['merchant_name'] ?? '');
        $contact_phone = sanitizeInput($_POST['contact_phone'] ?? '');
        $business_license = sanitizeInput($_POST['business_license'] ?? '');
        
        $official_role = sanitizeInput($_POST['official_role'] ?? '');
        $authorized_area = sanitizeInput($_POST['authorized_area'] ?? '');
        
        if (empty($firstname)) {
            $errors[] = "First name is required";
        }
        
        if (empty($lastname)) {
            $errors[] = "Last name is required";
        }
        
        if (empty($national_id)) {
            $errors[] = "National ID is required";
        }
        
        if (empty($dob)) {
            $errors[] = "Date of birth is required";
        } else {
            // Business rule: Minimum age requirement for registration
            $birthDate = new DateTime($dob);
            $today = new DateTime();
            $age = $birthDate->diff($today)->y;
            
            if ($age < 18) {
                $errors[] = "You must be at least 18 years old to register";
            }
        }
        
        if (empty($username)) {
            $errors[] = "Username is required";
        } elseif (strlen($username) < 4) {
            $errors[] = "Username must be at least 4 characters long";
        }
        
        if (empty($password)) {
            $errors[] = "Password is required";
        } elseif (strlen($password) < 6) {
            $errors[] = "Password must be at least 6 characters long";
        }
        
        if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format";
        }
        
        // Security: Prevent public registration of Admin accounts
        $valid_roles = ['Citizen', 'Merchant', 'Official'];
        if (!in_array($role, $valid_roles)) {
            $errors[] = "Invalid role selected";
        }
        
        if ($role === 'Merchant') {
            if (empty($merchant_name)) {
                $errors[] = "Business name is required for merchant accounts";
            }
            
            if (empty($city)) {
                $errors[] = "City is required for merchant accounts";
            }
            
            if (empty($email)) {
                $errors[] = "Email is required for merchant accounts";
            }
        }
        
        if ($role === 'Official') {
            if (empty($official_role)) {
                $errors[] = "Official role/position is required for official accounts";
            }
            
            if (empty($city)) {
                $errors[] = "City is required for official accounts";
            }
            
            if (empty($email)) {
                $errors[] = "Email is required for official accounts";
            }
            
            if (empty($authorized_area)) {
                $errors[] = "Authorized area is required for official accounts";
            }
        }
        
        if (empty($errors)) {
            try {
                $pdo = getDBConnection();
                if (!$pdo) {
                    $errors[] = "Database connection failed. Please try again later.";
                } else {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    
                    if ($stmt->fetchColumn() > 0) {
                        $errors[] = "Username already exists";
                    } else {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE national_id = ?");
                        $stmt->execute([$national_id]);
                        
                        if ($stmt->fetchColumn() > 0) {
                            $errors[] = "National ID already registered";
                        } else {
                            // Business logic: Prevent duplicate merchant business names
                            if ($role === 'Merchant' && !empty($merchant_name)) {
                                $stmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE merchant_name = ?");
                                $stmt->execute([$merchant_name]);
                                
                                if ($stmt->fetchColumn() > 0) {
                                    $errors[] = "Business name is already registered. Please use a different business name.";
                                } else if (!empty($business_license)) {
                                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM merchants WHERE business_license = ?");
                                    $stmt->execute([$business_license]);
                                    
                                    if ($stmt->fetchColumn() > 0) {
                                        $errors[] = "Business license number is already registered. Please verify your information.";
                                    }
                                }
                            }
                            
                            if (empty($errors)) {
                                $pdo->beginTransaction();
                                
                                try {
                                    // Generate unique PRS ID with role-based prefixes
                                    $prefix = ($role === 'Merchant') ? 'MER' : (($role === 'Official') ? 'OFF' : 'PRS');
                                    $prs_id = $prefix . mt_rand(1000, 9999);
                                    
                                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE prs_id = ?");
                                    $stmt->execute([$prs_id]);
                                    while ($stmt->fetchColumn() > 0) {
                                        $prs_id = $prefix . mt_rand(1000, 9999);
                                        $stmt->execute([$prs_id]);
                                    }
                                    
                                    $full_name = $firstname . ' ' . $lastname;
                                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                                    
                                    $stmt = $pdo->prepare(
                                        "INSERT INTO users (prs_id, full_name, national_id, dob, role, username, password, email, city) 
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                                    );
                                    
                                    $result = $stmt->execute([
                                        $prs_id,
                                        $full_name,
                                        $national_id,
                                        $dob,
                                        $role,
                                        $username,
                                        $hashed_password,
                                        $email,
                                        $city
                                    ]);
                                    
                                    if ($result) {
                                        $user_id = $pdo->lastInsertId();
                                        
                                        if ($role === 'Merchant' && !empty($merchant_name)) {
                                            $merchantStmt = $pdo->prepare(
                                                "INSERT INTO merchants (prs_id, merchant_name, contact_email, contact_phone, city, business_license, user_id, status) 
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                                            );
                                            
                                            $merchantResult = $merchantStmt->execute([
                                                $prs_id,
                                                $merchant_name,
                                                $email,
                                                $contact_phone,
                                                $city,
                                                $business_license,
                                                $user_id,
                                                'Pending'
                                            ]);
                                            
                                            if (!$merchantResult) {
                                                throw new Exception("Failed to create merchant profile");
                                            }
                                        }
                                        
                                        if ($role === 'Official') {
                                            $officialStmt = $pdo->prepare(
                                                "INSERT INTO government_officials (first_name, last_name, role, contact_email, contact_phone, authorized_area, user_id, status) 
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                                            );
                                            
                                            $officialResult = $officialStmt->execute([
                                                $firstname,
                                                $lastname,
                                                $official_role,
                                                $email,
                                                $contact_phone,
                                                $authorized_area,
                                                $user_id,
                                                'Pending'
                                            ]);
                                            
                                            if (!$officialResult) {
                                                throw new Exception("Failed to create official profile");
                                            }
                                        }
                                        
                                        $pdo->commit();
                                        
                                        // Audit trail: Log successful registration
                                        logAccess($user_id, 'User Registration: ' . $username . ' (Role: ' . $role . ')', true);
                                        
                                        header("Location: login.php?registration=success&prs_id=" . urlencode($prs_id) . "&role=" . urlencode($role));
                                        exit();
                                        
                                    } else {
                                        throw new Exception("Failed to create user account");
                                    }
                                    
                                } catch (Exception $e) {
                                    $pdo->rollBack();
                                    $errors[] = "Registration failed: " . $e->getMessage();
                                    logAccess(null, 'Failed Registration: ' . $username . ' - ' . $e->getMessage(), false);
                                }
                            }
                        }
                    }
                }
            } catch (PDOException $e) {
                // Handle specific database constraint violations with user-friendly messages
                if (strpos($e->getMessage(), 'idx_merchant_name') !== false) {
                    $errors[] = "Business name is already registered. Please use a different business name.";
                } else if (strpos($e->getMessage(), 'business_license') !== false) {
                    $errors[] = "Business license number is already registered. Please verify your information.";
                } else if (strpos($e->getMessage(), 'idx_username') !== false) {
                    $errors[] = "Username is already taken. Please choose a different username.";
                } else if (strpos($e->getMessage(), 'idx_national_id') !== false) {
                    $errors[] = "National ID is already registered.";
                } else {
                    $errors[] = "Registration failed. Please try again later.";
                    error_log("Registration error: " . $e->getMessage());
                }
                
                logAccess(null, 'Registration Database Error: ' . $e->getMessage(), false);
            }
        }
    }
}

$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - COVID Resilience System</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            padding-top: 50px;
        }
        .register-card {
            max-width: 800px;
            margin: 0 auto;
            padding: 30px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .login-title {
            color: #0d6efd;
            font-weight: 600;
        }
        #merchantFields, #officialFields {
            display: none;
            padding: 15px;
            border-radius: 5px;
            background-color: #f8f9fa;
            margin-top: 15px;
            border-left: 4px solid #0d6efd;
        }
        .role-info {
            margin-top: 10px;
            padding: 10px;
            border-radius: 5px;
            background-color: #e9f2fb;
            display: none;
        }
        .approval-notice {
            background: linear-gradient(45deg, #ffc107, #fd7e14);
            color: #000;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            border: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="register-card">
            <div class="text-center mb-4">
                <i class="bi bi-shield-fill-check" style="font-size: 3rem; color: #0d6efd;"></i>
                <h3 class="login-title">COVID Resilience System</h3>
                <h5 class="mb-4">New User Registration</h5>
            </div>
            
            <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <h6><i class="bi bi-exclamation-triangle-fill me-2"></i>Please correct the following errors:</h6>
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
        
            <form action="register.php" method="POST" id="registerForm">
              <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
              
              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="firstname" class="form-label"><i class="bi bi-person me-2"></i>First Name:</label>
                  <input type="text" class="form-control" id="firstname" name="firstname" 
                         value="<?php echo htmlspecialchars($firstname); ?>" placeholder="Enter your First Name" required>
                </div>
                <div class="col-md-6 mb-3">
                  <label for="lastname" class="form-label"><i class="bi bi-person me-2"></i>Last Name:</label>
                  <input type="text" class="form-control" id="lastname" name="lastname" 
                         value="<?php echo htmlspecialchars($lastname); ?>" placeholder="Enter your Last Name" required>
                </div>
              </div>
              
              <div class="mb-3">
                <label for="national_id" class="form-label"><i class="bi bi-card-heading me-2"></i>National ID:</label>
                <input type="text" class="form-control" id="national_id" name="national_id" 
                       value="<?php echo htmlspecialchars($national_id); ?>" placeholder="Enter your National ID number" required>
              </div>
              
              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="dob" class="form-label"><i class="bi bi-calendar me-2"></i>Date of Birth:</label>
                  <input type="date" class="form-control" id="dob" name="dob" 
                         value="<?php echo htmlspecialchars($dob); ?>" required>
                  <small class="text-muted">You must be at least 18 years old to register</small>
                </div>
                <div class="col-md-6 mb-3">
                  <label for="city" class="form-label"><i class="bi bi-geo-alt me-2"></i>City:</label>
                  <input type="text" class="form-control" id="city" name="city" 
                         value="<?php echo htmlspecialchars($city); ?>" placeholder="Enter your city">
                  <small class="text-muted">Used for location-based services</small>
                </div>
              </div>
              
              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="username" class="form-label"><i class="bi bi-person-badge me-2"></i>Username:</label>
                  <input type="text" class="form-control" id="username" name="username" 
                         value="<?php echo htmlspecialchars($username); ?>" placeholder="Choose a username" required>
                  <small class="text-muted">At least 4 characters</small>
                </div>
                <div class="col-md-6 mb-3">
                  <label for="password" class="form-label"><i class="bi bi-lock me-2"></i>Password:</label>
                  <input type="password" class="form-control" id="password" name="password" placeholder="Create a password" required>
                  <small class="text-muted">At least 6 characters</small>
                </div>
              </div>
              
              <div class="mb-3">
                <label for="email" class="form-label"><i class="bi bi-envelope me-2"></i>Email:</label>
                <input type="email" class="form-control" id="email" name="email" 
                       value="<?php echo htmlspecialchars($email); ?>" placeholder="Enter your email">
                <small class="text-muted">Used for notifications and account recovery</small>
              </div>
              
              <div class="mb-3">
                <label for="role" class="form-label"><i class="bi bi-person-badge-fill me-2"></i>Role:</label>
                <select class="form-select" id="role" name="role" required onchange="toggleRoleFields()">
                  <option value="Citizen" <?php echo ($role === 'Citizen') ? 'selected' : ''; ?>>Citizen</option>
                  <option value="Merchant" <?php echo ($role === 'Merchant') ? 'selected' : ''; ?>>Merchant</option>
                  <option value="Official" <?php echo ($role === 'Official') ? 'selected' : ''; ?>>Government Official</option>
                </select>
                <small class="text-muted">Select the appropriate role for your account</small>
              </div>
              
              <div id="citizenInfo" class="role-info">
                <h6><i class="bi bi-info-circle me-2"></i>Citizen Account</h6>
                <p>As a citizen, you can:</p>
                <ul>
                  <li>Register your vaccination status</li>
                  <li>Upload and manage important documents</li>
                  <li>Make purchases from approved merchants</li>
                  <li>View COVID-19 information and statistics</li>
                </ul>
              </div>
              
              <div id="merchantInfo" class="role-info">
                <h6><i class="bi bi-info-circle me-2"></i>Merchant Account</h6>
                <p>As a merchant, you can:</p>
                <ul>
                  <li>Manage your inventory of products</li>
                  <li>Suggest critical items for approval</li>
                  <li>Process purchases from citizens</li>
                  <li>View sales reports and analytics</li>
                </ul>
                <div class="approval-notice">
                  <h6><i class="bi bi-exclamation-triangle me-2"></i><strong>Important - Merchant Approval Required</strong></h6>
                  <p class="mb-0">Merchant accounts must be approved by government officials before you can login and access merchant features. After registration, please wait for approval notification.</p>
                </div>
              </div>
              
              <div id="officialInfo" class="role-info">
                <h6><i class="bi bi-info-circle me-2"></i>Government Official Account</h6>
                <p>As a government official, you can:</p>
                <ul>
                  <li>Verify citizen documents</li>
                  <li>Approve critical items from merchants</li>
                  <li>Approve merchant accounts</li>
                  <li>Monitor vaccination statistics</li>
                  <li>Manage system resources</li>
                </ul>
                <div class="approval-notice">
                  <h6><i class="bi bi-exclamation-triangle me-2"></i><strong>Important - Official Approval Required</strong></h6>
                  <p class="mb-0">Government Official accounts must be approved by system administrators before you can login and access official features. After registration, please wait for administrator approval.</p>
                </div>
              </div>
              
              <div id="merchantFields">
                <h5 class="mb-3"><i class="bi bi-shop me-2"></i>Merchant Information</h5>
                <p class="text-muted small">These fields are required for merchant accounts. Your merchant profile will be created automatically with "Pending" status.</p>
                
                <div class="mb-3">
                  <label for="merchant_name" class="form-label">Business Name: <span class="text-danger">*</span></label>
                  <input type="text" class="form-control" id="merchant_name" name="merchant_name" 
                         value="<?php echo htmlspecialchars($merchant_name); ?>" placeholder="Enter your business name">
                </div>
                
                <div class="mb-3">
                  <label for="contact_phone" class="form-label">Business Phone:</label>
                  <input type="text" class="form-control" id="contact_phone" name="contact_phone" 
                         value="<?php echo htmlspecialchars($contact_phone); ?>" placeholder="Enter business phone number">
                </div>
                
                <div class="mb-3">
                  <label for="business_license" class="form-label">Business License Number:</label>
                  <input type="text" class="form-control" id="business_license" name="business_license" 
                         value="<?php echo htmlspecialchars($business_license); ?>" placeholder="Enter business license number (if applicable)">
                </div>

                <div class="alert alert-info">
                  <i class="bi bi-info-circle me-2"></i>
                  <small><strong>Approval Process:</strong> Your merchant account will be created with "Pending" status. A government official must approve your account before you can login and access merchant features. You will receive your PRS ID immediately, but login access will be restricted until approval.</small>
                </div>
              </div>
              
              <div id="officialFields">
                <h5 class="mb-3"><i class="bi bi-building me-2"></i>Official Information</h5>
                <p class="text-muted small">These fields are required for official accounts. Your official profile will be created automatically with "Pending" status.</p>
                
                <div class="mb-3">
                  <label for="official_role" class="form-label">Official Position/Role: <span class="text-danger">*</span></label>
                  <select class="form-select" id="official_role" name="official_role">
                    <option value="">Select your official role</option>
                    <option value="Health Officer" <?php echo ($official_role === 'Health Officer') ? 'selected' : ''; ?>>Health Officer</option>
                    <option value="Supply Control Officer" <?php echo ($official_role === 'Supply Control Officer') ? 'selected' : ''; ?>>Supply Control Officer</option>
                    <option value="Public Safety Coordinator" <?php echo ($official_role === 'Public Safety Coordinator') ? 'selected' : ''; ?>>Public Safety Coordinator</option>
                    <option value="Emergency Response Manager" <?php echo ($official_role === 'Emergency Response Manager') ? 'selected' : ''; ?>>Emergency Response Manager</option>
                    <option value="Government Administrator" <?php echo ($official_role === 'Government Administrator') ? 'selected' : ''; ?>>Government Administrator</option>
                    <option value="Other" <?php echo ($official_role === 'Other') ? 'selected' : ''; ?>>Other</option>
                  </select>
                </div>
                
                <div class="mb-3">
                  <label for="authorized_area" class="form-label">Authorized Area/Department: <span class="text-danger">*</span></label>
                  <input type="text" class="form-control" id="authorized_area" name="authorized_area" 
                         value="<?php echo htmlspecialchars($authorized_area); ?>" placeholder="Enter your department or authorized area">
                  <small class="text-muted">e.g., "Health Department", "Municipality of Athens", "Regional Emergency Response"</small>
                </div>

                <div class="alert alert-info">
                  <i class="bi bi-info-circle me-2"></i>
                  <small><strong>Approval Process:</strong> Your official account will be created with "Pending" status. A system administrator must approve your account before you can login and access official features. You will receive your PRS ID immediately, but login access will be restricted until approval.</small>
                </div>
              </div>
              
              <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="termsCheck" required>
                <label class="form-check-label" for="termsCheck">I agree to the terms and conditions</label>
              </div>
              
              <button type="submit" class="btn btn-primary w-100">
                <i class="bi bi-person-plus me-2"></i>Register
              </button>
            </form>
        
            <div class="text-center">
              <p class="mt-3 mb-0">Already have an account? <a href="login.php">Login here</a></p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Dynamic form field management based on selected role
    function toggleRoleFields() {
        const role = document.getElementById('role').value;
        const merchantFields = document.getElementById('merchantFields');
        const officialFields = document.getElementById('officialFields');
        const cityField = document.getElementById('city');
        const emailField = document.getElementById('email');
        const merchantName = document.getElementById('merchant_name');
        const officialRole = document.getElementById('official_role');
        const authorizedArea = document.getElementById('authorized_area');
        
        document.getElementById('citizenInfo').style.display = 'none';
        document.getElementById('merchantInfo').style.display = 'none';
        document.getElementById('officialInfo').style.display = 'none';
        
        if (role === 'Citizen') {
            document.getElementById('citizenInfo').style.display = 'block';
            merchantFields.style.display = 'none';
            officialFields.style.display = 'none';
            cityField.required = false;
            emailField.required = false;
            merchantName.required = false;
            officialRole.required = false;
            authorizedArea.required = false;
        } else if (role === 'Merchant') {
            document.getElementById('merchantInfo').style.display = 'block';
            merchantFields.style.display = 'block';
            officialFields.style.display = 'none';
            cityField.required = true;
            emailField.required = true;
            merchantName.required = true;
            officialRole.required = false;
            authorizedArea.required = false;
        } else if (role === 'Official') {
            document.getElementById('officialInfo').style.display = 'block';
            merchantFields.style.display = 'none';
            officialFields.style.display = 'block';
            cityField.required = true;
            emailField.required = true;
            merchantName.required = false;
            officialRole.required = true;
            authorizedArea.required = true;
        }
    }
    
    document.addEventListener('DOMContentLoaded', function() {
        toggleRoleFields();
    });
    </script>
</body>
</html>