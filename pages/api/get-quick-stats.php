<?php
// api/get-quick-stats.php

session_start();
header('Content-Type: application/json');
ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/
if (!$auth->isLoggedIn()) {
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Validate Website Context
|--------------------------------------------------------------------------
*/
$websiteId = $_SESSION['CONTEXT']['WEBSITE_ID'] ?? 0;

if ($websiteId <= 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid website context'
    ]);
    exit;
}

try {

    /*
    |--------------------------------------------------------------------------
    | Threats (Last 24h)
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM attack_logs 
        WHERE website_id = ?
        AND timestamp >= NOW() - INTERVAL 24 HOUR
    ");
    $stmt->execute([$websiteId]);
    $threats = (int)$stmt->fetchColumn();


    /*
    |--------------------------------------------------------------------------
    | Active Blocked IPs
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM blocked_ips 
        WHERE website_id = ?
        AND is_active = 1
    ");
    $stmt->execute([$websiteId]);
    $blockedIps = (int)$stmt->fetchColumn();


    /*
    |--------------------------------------------------------------------------
    | Online Users (Last 5 min)
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT ip_address)
        FROM user_sessions
        WHERE website_id = ?
        AND last_activity >= NOW() - INTERVAL 5 MINUTE
    ");
    $stmt->execute([$websiteId]);
    $online = (int)$stmt->fetchColumn();


    /*
    |--------------------------------------------------------------------------
    | Unresolved Attacks
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM attack_logs 
        WHERE website_id = ?
        AND resolved = 0
    ");
    $stmt->execute([$websiteId]);
    $unresolvedAttacks = (int)$stmt->fetchColumn();


    /*
    |--------------------------------------------------------------------------
    | Unread Alerts
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM alerts
        WHERE website_id = ?
        AND status = 'unread'
    ");
    $stmt->execute([$websiteId]);
    $alerts = (int)$stmt->fetchColumn();


    echo json_encode([
        'success'      => true,
        'threats'      => $threats,
        'blocked'      => $blockedIps,
        'online'       => $online,
        'attacks'      => $unresolvedAttacks,
        'blocked_ips'  => $blockedIps,
        'alerts'       => $alerts
    ]);

} catch (Exception $e) {

    error_log('Quick Stats Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Failed to load statistics'
    ]);
}

exit;
