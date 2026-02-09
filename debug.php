<?php
// debug.php - Test database and session
session_start();
echo "<pre>";

// Test session
echo "=== SESSION STATUS ===\n";
echo "Session ID: " . session_id() . "\n";
echo "Session Status: " . session_status() . "\n";
print_r($_SESSION);

// Test database
echo "\n=== DATABASE TEST ===\n";
try {
    require_once 'includes/config.php';
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS
    );
    echo "Database connected successfully!\n";
    
    // Check user2 table
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM user2");
    $result = $stmt->fetch();
    echo "Users in user2 table: " . $result['count'] . "\n";
    
    // Show admin user
    $stmt = $pdo->query("SELECT * FROM user2 WHERE username = 'admin'");
    $admin = $stmt->fetch();
    if ($admin) {
        echo "Admin user found: " . $admin['username'] . "\n";
        echo "Password hash: " . $admin['password_hash'] . "\n";
        
        // Test password
        $testPass = 'Admin@123';
        if (password_verify($testPass, $admin['password_hash'])) {
            echo "✓ Password 'Admin@123' is correct!\n";
        } else {
            echo "✗ Password verification failed\n";
        }
    } else {
        echo "Admin user not found!\n";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage() . "\n";
}

echo "</pre>";
?>