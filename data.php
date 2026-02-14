<?php
// Enable error reporting for debugging (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set proper headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// Allow only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(403);
    echo json_encode(['error' => 'Direct access not allowed']);
    exit;
}

// Check if it's an AJAX request
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
    // Still allow but log it
    error_log('Warning: Non-AJAX request to data.php');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ---------------- DATABASE ----------------
$conn = new mysqli("localhost", "root", "", "mailfor");

if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $conn->connect_error]);
    exit;
}

$conn->set_charset("utf8mb4");

// ---------------- GET JSON INPUT ----------------
$input = json_decode(file_get_contents("php://input"), true);

if (!$input || json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON input: ' . json_last_error_msg()]);
    exit;
}

// ---------------- HELPERS ----------------
function sanitize_string($value) {
    return htmlspecialchars(strip_tags((string)$value), ENT_QUOTES, 'UTF-8');
}

function sanitize_int($value) {
    return filter_var($value, FILTER_VALIDATE_INT) ?: 0;
}

function sanitize_float($value) {
    return filter_var($value, FILTER_VALIDATE_FLOAT) ?: 0.0;
}

function sanitize_bool($value) {
    return filter_var($value, FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
}

function get_reverse_dns($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Invalid IP";
    return @gethostbyaddr($ip) ?: "Lookup failed";
}

// ---------------- DYNAMIC IDs ----------------
// user_id from input or generate one
$user_id = isset($input['user_id']) && preg_match('/^[a-f0-9\-]{36}$/i', $input['user_id'])
    ? sanitize_string($input['user_id'])
    : session_id();

// website_id must be numeric
$website_id = sanitize_int($input['website_id'] ?? 1);

// ---------------- IP HANDLING ----------------
$ip = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP) ?: 'Unknown';
$real_ip = filter_var($input['ip'] ?? $ip, FILTER_VALIDATE_IP) ?: $ip;

// ---------------- TRACKING DATA ----------------
$tracking = [
    'user_id' => $user_id,
    'website_id' => $website_id,
    'ip' => $ip,
    'real_ip' => $real_ip,
    'hostname' => get_reverse_dns($real_ip),
    'webrtc_ip' => sanitize_string($input['webrtcIP'] ?? 'Unknown'),
    'dns_leak_ip' => sanitize_string($input['dnsLeakIP'] ?? 'Unknown'),
    'user_agent' => sanitize_string($input['userAgent'] ?? $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
    'screen_resolution' => sanitize_string($input['screenResolution'] ?? 'Unknown'),
    'language' => sanitize_string($input['language'] ?? 'Unknown'),
    'timezone' => sanitize_string($input['timezone'] ?? 'Unknown'),
    'cookies_enabled' => sanitize_bool($input['cookiesEnabled'] ?? 0),
    'cpu_cores' => sanitize_int($input['cpuCores'] ?? 0),
    'ram' => sanitize_string($input['ram'] ?? 'Unknown'),
    'gpu' => sanitize_string($input['gpu'] ?? 'Unknown'),
    'battery' => sanitize_string($input['battery'] ?? 'Unknown'),
    'referrer' => sanitize_string($input['referrer'] ?? 'None'),
    'plugins' => sanitize_string($input['plugins'] ?? 'None'),
    'digital_dna' => sanitize_string($input['digitalDNA'] ?? 'Unknown')
];

// ---------------- INSERT INTO DATABASE ----------------
// First, check if table exists and create if not
$conn->query("
    CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(255),
        website_id INT,
        ip VARCHAR(45),
        real_ip VARCHAR(45),
        reverse_dns VARCHAR(255),
        webrtc_ip VARCHAR(45),
        dns_leak_ip VARCHAR(45),
        user_agent TEXT,
        screen_resolution VARCHAR(50),
        language VARCHAR(50),
        timezone VARCHAR(100),
        cookies_enabled TINYINT,
        cpu_cores INT,
        ram VARCHAR(50),
        gpu TEXT,
        battery VARCHAR(50),
        referrer TEXT,
        plugins TEXT,
        digital_dna VARCHAR(255),
        is_vpn TINYINT DEFAULT 0,
        is_tor TINYINT DEFAULT 0,
        is_proxy TINYINT DEFAULT 0,
        ASN VARCHAR(100),
        ISP VARCHAR(255),
        country VARCHAR(100),
        latitude DECIMAL(10,8),
        longitude DECIMAL(11,8),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");

$conn->autocommit(false);

// Prepare statement with correct number of placeholders
$stmt = $conn->prepare("
    INSERT INTO logs
    (user_id, website_id, ip, real_ip, reverse_dns, webrtc_ip, dns_leak_ip,
     user_agent, screen_resolution, language, timezone, cookies_enabled,
     cpu_cores, ram, gpu, battery, referrer, plugins, digital_dna,
     is_vpn, is_tor, is_proxy, ASN, ISP, country, latitude, longitude)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 'Unknown', 'Unknown', 'Unknown', 0, 0)
");

if (!$stmt) {
    $conn->rollback();
    http_response_code(500);
    echo json_encode(['error' => 'Prepare failed: ' . $conn->error]);
    exit;
}

// Bind parameters - make sure types match
$stmt->bind_param(
    "sisssssssssiissssss", // 19 parameters
    $tracking['user_id'],
    $tracking['website_id'],
    $tracking['ip'],
    $tracking['real_ip'],
    $tracking['hostname'],
    $tracking['webrtc_ip'],
    $tracking['dns_leak_ip'],
    $tracking['user_agent'],
    $tracking['screen_resolution'],
    $tracking['language'],
    $tracking['timezone'],
    $tracking['cookies_enabled'],
    $tracking['cpu_cores'],
    $tracking['ram'],
    $tracking['gpu'],
    $tracking['battery'],
    $tracking['referrer'],
    $tracking['plugins'],
    $tracking['digital_dna']
);

if (!$stmt->execute()) {
    $conn->rollback();
    http_response_code(500);
    echo json_encode(['error' => 'Execute failed: ' . $stmt->error]);
    exit;
}

$conn->commit();
$stmt->close();
$conn->close();

// Return success response
echo json_encode([
    'status' => 'success',
    'message' => 'Tracking data saved',
    'user_id' => $user_id
]);