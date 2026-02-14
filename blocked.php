<?php
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

    // Get the user's IP address
    $ipAddress = $_SERVER['REMOTE_ADDR'];

    // Query the blocked IPs table
    $stmt = $pdo->prepare("SELECT * FROM blocked_ips WHERE ip = ?");
    $stmt->execute([$ipAddress]);
    $blocked = $stmt->fetch();

    if ($blocked) {
        // Deny access
        http_response_code(403);
        echo "Access denied. Your IP has been blocked.";
        exit;
    }
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
    exit;
}
?>