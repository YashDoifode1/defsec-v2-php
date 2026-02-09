<?php
// api/bulk-block.php

session_start();
header('Content-Type: application/json');

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '../../includes/db.php';

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method'
    ]);
    exit;
}

// Auth check
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Not authenticated'
    ]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_POST['website_id'] ?? $_SESSION['website_id'] ?? 0);

// Validate website ID
if ($websiteId <= 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid website ID'
    ]);
    exit;
}

// Decode IP list
$ips = json_decode($_POST['ips'] ?? '[]', true);

if (!is_array($ips) || empty($ips)) {
    echo json_encode([
        'success' => false,
        'message' => 'No IPs provided'
    ]);
    exit;
}

// Limit bulk size (prevent abuse)
$ips = array_slice($ips, 0, 500);

$reason = trim($_POST['reason'] ?? 'Bulk block');
$expiry = $_POST['expiry'] ?? '24:00:00';

// Validate expiry format HH:MM:SS
if (!preg_match('/^\d{2}:\d{2}:\d{2}$/', $expiry)) {
    $expiry = '24:00:00';
}

try {

    $successCount = 0;
    $failedCount = 0;
    $failedIps = [];

    foreach ($ips as $ip) {

        $ip = trim($ip);

        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $failedCount++;
            $failedIps[] = "$ip (invalid format)";
            continue;
        }

        // Check if already actively blocked
        $checkQuery = $pdo->prepare("
            SELECT id FROM blocked_ips
            WHERE user_id = ?
              AND website_id = ?
              AND ip_address = ?
              AND (
                    expiry_time = '00:00:00'
                    OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW()
                  )
        ");

        $checkQuery->execute([$userId, $websiteId, $ip]);

        if ($checkQuery->fetch()) {
            $successCount++;
            continue;
        }

        // Insert new block
        $insertQuery = $pdo->prepare("
            INSERT INTO blocked_ips
            (user_id, website_id, ip_address, reason, expiry_time, created_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        ");

        $insertSuccess = $insertQuery->execute([
            $userId,
            $websiteId,
            $ip,
            $reason,
            $expiry
        ]);

        if ($insertSuccess) {

            $successCount++;

            // Log action
            $logQuery = $pdo->prepare("
                INSERT INTO action_logs
                (user_id, website_id, action_type, details, ip_address, created_at)
                VALUES (?, ?, 'block_ip', ?, ?, NOW())
            ");

            $logQuery->execute([
                $userId,
                $websiteId,
                "Bulk blocked IP: $ip - Reason: $reason",
                $ip
            ]);

        } else {
            $failedCount++;
            $failedIps[] = "$ip (database error)";
        }
    }

    echo json_encode([
        'success' => true,
        'message' => "Blocked $successCount IP(s)",
        'stats' => [
            'success' => $successCount,
            'failed' => $failedCount,
            'failed_ips' => $failedIps
        ]
    ], JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {

    error_log('Bulk Block Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Server error occurred'
    ]);
}

exit;
