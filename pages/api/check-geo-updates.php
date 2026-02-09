<?php
// api/check-geo-updates.php

session_start();
header('Content-Type: application/json');

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../includes/db.php';

// Only allow POST (polling endpoint)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method',
        'has_new_data' => false
    ]);
    exit;
}

// Auth check
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Not authenticated',
        'has_new_data' => false
    ]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_POST['website_id'] ?? $_SESSION['website_id'] ?? 0);

if ($websiteId <= 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid website ID',
        'has_new_data' => false
    ]);
    exit;
}

// Validate last_check timestamp
$lastCheckInput = $_POST['last_check'] ?? null;

if ($lastCheckInput && strtotime($lastCheckInput) !== false) {
    $lastCheck = date('Y-m-d H:i:s', strtotime($lastCheckInput));
} else {
    $lastCheck = date('Y-m-d H:i:s', strtotime('-1 minute'));
}

try {

    /*
    |--------------------------------------------------------------------------
    | Check New Visitor Logs
    |--------------------------------------------------------------------------
    */

    $newLogsQuery = $pdo->prepare("
        SELECT COUNT(*) 
        FROM logs
        WHERE user_id = ?
          AND website_id = ?
          AND timestamp > ?
    ");
    $newLogsQuery->execute([$userId, $websiteId, $lastCheck]);
    $newLogs = (int) $newLogsQuery->fetchColumn();

    /*
    |--------------------------------------------------------------------------
    | Check New Attack Logs
    |--------------------------------------------------------------------------
    */

    $newAttacksQuery = $pdo->prepare("
        SELECT COUNT(*)
        FROM attack_logs
        WHERE user_id = ?
          AND website_id = ?
          AND timestamp > ?
    ");
    $newAttacksQuery->execute([$userId, $websiteId, $lastCheck]);
    $newAttacks = (int) $newAttacksQuery->fetchColumn();

    $hasNewData = ($newLogs > 0 || $newAttacks > 0);

    /*
    |--------------------------------------------------------------------------
    | Get User Settings
    |--------------------------------------------------------------------------
    */

    $settingsQuery = $pdo->prepare("
        SELECT settings
        FROM users
        WHERE id = ?
        LIMIT 1
    ");
    $settingsQuery->execute([$userId]);
    $settingsRow = $settingsQuery->fetch(PDO::FETCH_ASSOC);

    $settings = [];
    if ($settingsRow && !empty($settingsRow['settings'])) {
        $decoded = json_decode($settingsRow['settings'], true);
        if (is_array($decoded)) {
            $settings = $decoded;
        }
    }

    $autoRefreshEnabled = !empty($settings['geolocation_auto_refresh']);

    echo json_encode([
        'success' => true,
        'has_new_data' => $hasNewData,
        'new_logs' => $newLogs,
        'new_attacks' => $newAttacks,
        'auto_refresh' => ($autoRefreshEnabled && $hasNewData),
        'last_checked' => date('Y-m-d H:i:s')
    ], JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {

    error_log('Geo Update Check Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Server error occurred',
        'has_new_data' => false
    ]);
}

exit;
