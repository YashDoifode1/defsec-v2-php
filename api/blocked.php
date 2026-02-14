<?php
// ==============================
// CONFIGURATION
// ==============================
define('USER_ID', 1);       // Set the current user ID
define('WEBSITE_ID', 1);    // Set the current website ID

// Database configuration
$host = 'localhost';
$db   = 'mailfor';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);

    // Get client IP
    $ipAddress = $_SERVER['REMOTE_ADDR'];

    // ==============================
    // CHECK BLOCKED IPS
    // ==============================
    // This checks:
    // 1) Global blocked IPs (user_id = 0, website_id = 0)
    // 2) User-specific blocked IPs
    $stmt = $pdo->prepare("
        SELECT * FROM blocked_ips 
        WHERE ip = :ip AND 
              ((user_id = 0 AND website_id = 0) OR 
               (user_id = :uid AND website_id = :wid))
        LIMIT 1
    ");
    $stmt->execute([
        ':ip'  => $ipAddress,
        ':uid' => USER_ID,
        ':wid' => WEBSITE_ID
    ]);
    $blocked = $stmt->fetch();

    if ($blocked) {
        // Deny access
        http_response_code(403);
        echo "Access denied. Your IP has been blocked.";
        exit;
    }

    // ==============================
    // LOG VISIT
    // ==============================
    $stmt = $pdo->prepare("
        INSERT INTO logs (user_id, website_id, ip, timestamp) 
        VALUES (:uid, :wid, :ip, NOW())
    ");
    $stmt->execute([
        ':uid' => USER_ID,
        ':wid' => WEBSITE_ID,
        ':ip'  => $ipAddress
    ]);

    // ==============================
    // OPTIONAL: Return success
    // ==============================
    // echo "Access granted. Welcome!";
    
} catch (PDOException $e) {
    http_response_code(500);
    echo "Database error: " . $e->getMessage();
    exit;
}
?>
