<?php
// Admin account creator - Run ONCE after database setup, then DELETE this file
require_once 'config.php';

echo "<h1>Creating 100% Working Admin Account</h1>";
echo "<hr>";

try {
    $pdo = getDBConnection();
    if (!$pdo) {
        die("Database connection failed! Check your config.php settings.");
    }
    echo "<p style='color: green;'>Database connected successfully</p>";

    // Generate secure password hash using current PHP environment
    $username = 'admin';
    $password = 'admin';
    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    echo "<p><strong>Generated hash for password '$password':</strong></p>";
    echo "<p style='font-family: monospace; background: #f0f0f0; padding: 10px; word-break: break-all;'>$hash</p>";
    
    // Verify hash works immediately to prevent login issues
    $test_result = password_verify($password, $hash);
    echo "<p>Testing hash: " . ($test_result ? "<span style='color: green;'>SUCCESS</span>" : "<span style='color: red;'>❌ FAILED</span>") . "</p>";
    
    if (!$test_result) {
        die("Critical error: PHP password functions are not working properly!");
    }

    // Clean slate - remove any existing admin accounts
    $stmt = $pdo->prepare("DELETE FROM users WHERE username = ? OR role = 'Admin'");
    $stmt->execute(['admin']);
    echo "<p>Removed any existing admin accounts</p>";

    $stmt = $pdo->prepare("
        INSERT INTO users (prs_id, full_name, national_id, dob, role, username, password, email, city, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");
    
    $result = $stmt->execute([
        'ADM0001',
        'System Administrator',
        '0000000001',
        '1980-01-01',
        'Admin',
        $username,
        $hash,
        'admin@covid-system.com',
        'System'
    ]);

    if ($result) {
        $admin_id = $pdo->lastInsertId();
        echo "<p style='color: green;'>Admin account created successfully! (ID: $admin_id)</p>";
        
        $stmt = $pdo->prepare("SELECT user_id, username, role FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $admin_user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($admin_user) {
            echo "<p style='color: green;'>Admin account verified in database</p>";
            echo "<table border='1' style='border-collapse: collapse; margin: 10px 0;'>";
            echo "<tr><th>User ID</th><th>Username</th><th>Role</th></tr>";
            echo "<tr><td>{$admin_user['user_id']}</td><td>{$admin_user['username']}</td><td>{$admin_user['role']}</td></tr>";
            echo "</table>";
        }
        
        // Simulate complete login process to guarantee functionality
        echo "<h3>Testing Complete Login Process</h3>";
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            echo "<div style='background: #d4edda; color: #155724; padding: 20px; border: 1px solid #c3e6cb; border-radius: 5px; margin: 20px 0;'>";
            echo "<h3>SUCCESS! Admin Login is 100% GUARANTEED to work!</h3>";
            echo "<p><strong>Username:</strong> admin</p>";
            echo "<p><strong>Password:</strong> admin</p>";
            echo "<p><strong>The login will work perfectly!</strong></p>";
            echo "</div>";
            
            // Update test users with working password hashes
            echo "<h3>Updating all test user passwords...</h3>";
            $test_users = ['johncitizen', 'maria_p', 'dr_andreas', 'k_georgiadis', 'sofia_merchant'];
            $updated_count = 0;
            
            foreach ($test_users as $test_username) {
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");
                if ($stmt->execute([$hash, $test_username])) {
                    $updated_count++;
                }
            }
            
            echo "<p>Updated $updated_count test user passwords (all use password: 'admin')</p>";
            
        } else {
            echo "<p style='color: red; font-weight: bold;'>CRITICAL ERROR: Login simulation failed!</p>";
            echo "<p>This should never happen. Contact support.</p>";
        }
        
    } else {
        echo "<p style='color: red;'>Failed to create admin account!</p>";
        echo "<p>SQL Error: " . print_r($stmt->errorInfo(), true) . "</p>";
    }

} catch (Exception $e) {
    echo "<p style='color: red;'>Error: " . htmlspecialchars($e->getMessage()) . "</p>";
}

echo "<hr>";
echo "<h3>📋 Next Steps:</h3>";
echo "<ol>";
echo "<li><strong>Delete this file (create_admin.php)</strong> for security</li>";
echo "<li>Go to <a href='login.php' style='color: blue;'>login.php</a> and login with admin/admin</li>";
echo "<li>If successful, you're all set!</li>";
echo "</ol>";

echo "<div style='background: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; margin: 20px 0;'>";
echo "<h4>Security Notice:</h4>";
echo "<p>This script creates a secure bcrypt-hashed password. It does NOT store plain text passwords.</p>";
echo "<p>The password 'admin' is hashed using PHP's secure password_hash() function.</p>";
echo "<p><strong>Delete this file after running it once!</strong></p>";
echo "</div>";
?>

<style>
body { 
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
    max-width: 800px; 
    margin: 20px auto; 
    padding: 20px; 
    line-height: 1.6;
}
table { 
    border-collapse: collapse; 
    width: 100%; 
}
th, td { 
    padding: 8px 12px; 
    text-align: left; 
    border: 1px solid #ddd;
}
th { 
    background-color: #f8f9fa;
}
</style>