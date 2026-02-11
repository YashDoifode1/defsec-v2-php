<?php
require_once 'includes/db.php'; // secure PDO connection

header("Content-Type: application/json");

// ==============================
// BASIC HARDENING
// ==============================

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';

if (!$apiKey) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing API key']);
    exit;
}

$apiHash = hash('sha256', $apiKey);

// ==============================
// VALIDATE WEBSITE
// ==============================

$stmt = $pdo->prepare("
    SELECT id, user_id, status 
    FROM websites 
    WHERE api_key_hash = ?
    LIMIT 1
");
$stmt->execute([$apiHash]);
$website = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$website || $website['status'] !== 'active') {
    http_response_code(403);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

// ==============================
// GET REQUEST DATA
// ==============================

$data = json_decode(file_get_contents("php://input"), true);

if (!$data) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid payload']);
    exit;
}

$ip        = $data['ip'] ?? '';
$uri       = $data['uri'] ?? '';
$userAgent = $data['user_agent'] ?? '';
$method    = $data['method'] ?? 'GET';

$block = false;
$severity = null;
$attackType = null;

// ==============================
// DETECTION ENGINE
// ==============================

$patterns = [
    'SQLi' => '/(union\s+select|drop\s+table|insert\s+into)/i',
    'XSS'  => '/<script|javascript:|onerror=|onload=/i',
    'RCE'  => '/(exec\(|shell_exec\(|system\()/i'
];

foreach ($patterns as $type => $pattern) {
    if (preg_match($pattern, json_encode($data))) {
        $block = true;
        $attackType = $type;
        $severity = ($type === 'SQLi' || $type === 'RCE') ? 'Critical' : 'High';
        break;
    }
}

// ==============================
// CHECK BLOCKED IP
// ==============================

$stmt = $pdo->prepare("
    SELECT id FROM blocked_ips 
    WHERE website_id = ? AND ip = ? 
    LIMIT 1
");
$stmt->execute([$website['id'], $ip]);

if ($stmt->fetch()) {
    $block = true;
    $attackType = 'BlockedIP';
    $severity = 'Critical';
}

// ==============================
// LOG IF ATTACK
// ==============================

if ($block) {

    $stmt = $pdo->prepare("
        INSERT INTO attack_logs 
        (user_id, website_id, attack_type, severity, ip_address, user_agent, request_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ");

    $stmt->execute([
        $website['user_id'],
        $website['id'],
        $attackType,
        $severity,
        $ip,
        substr($userAgent, 0, 255),
        substr($uri, 0, 500)
    ]);

    // auto block critical
    if ($severity === 'Critical') {
        $stmt = $pdo->prepare("
            INSERT IGNORE INTO blocked_ips 
            (user_id, website_id, ip, reason, created_at, expiry_time)
            VALUES (?, ?, ?, 'Auto Block', NOW(), '23:59:59')
        ");

        $stmt->execute([
            $website['user_id'],
            $website['id'],
            $ip
        ]);
    }
}

echo json_encode([
    'block' => $block,
    'delay' => 0
]);
