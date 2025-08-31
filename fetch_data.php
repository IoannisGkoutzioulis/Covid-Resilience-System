<?php
header('Content-Type: application/json');

try {
    $pdo = new PDO("mysql:host=localhost;dbname=PRS_System", "root", "", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    if (!isset($_GET["table"]) || empty($_GET["table"])) {
        echo json_encode(["error" => "Table name is required!"]);
        exit;
    }
    
    // Security: Remove non-alphanumeric characters to prevent SQL injection
    $table = preg_replace('/[^a-zA-Z0-9_]/', "", $_GET["table"]);
    
    // Verify table exists before querying
    $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
    if ($stmt->rowCount() === 0) {
        echo json_encode(["error" => "Table does not exist!"]);
        exit;
    }

    $query = "SELECT * FROM " . $table;
    $stmt = $pdo->query($query);
    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode($data);
    
} catch (PDOException $e) {
    echo json_encode(["error" => "Database connection failed: " . $e->getMessage()]);
}
?>