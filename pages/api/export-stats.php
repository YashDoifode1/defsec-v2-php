<?php
// api/export-stats.php

session_start();
header('Content-Type: application/json');

// Disable error display (prevent HTML errors breaking JSON)
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Include database connection ONLY (not header.php)
require_once __DIR__ . '/../../includes/db.php';

// Check authentication
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

$user_id = $_SESSION['user_id'];
$website_id = $_SESSION['website_id'] ?? 1;

try {
    $stats = [
        'total_records' => 0,
        'log_types' => [],
        'recent_activity' => []
    ];

    /*
    |--------------------------------------------------------------------------
    | Log Counts
    |--------------------------------------------------------------------------
    */

    // Visitor logs
    $visitor_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM logs WHERE user_id = ? AND website_id = ?"
    );
    $visitor_stmt->execute([$user_id, $website_id]);
    $visitor_count = (int) $visitor_stmt->fetchColumn();
    $stats['log_types']['visitor'] = $visitor_count;
    $stats['total_records'] += $visitor_count;

    // Attack logs
    $attack_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM attack_logs WHERE user_id = ? AND website_id = ?"
    );
    $attack_stmt->execute([$user_id, $website_id]);
    $attack_count = (int) $attack_stmt->fetchColumn();
    $stats['log_types']['attack'] = $attack_count;
    $stats['total_records'] += $attack_count;

    // Blocked IPs
    $blocked_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM blocked_ips WHERE user_id = ? AND website_id = ?"
    );
    $blocked_stmt->execute([$user_id, $website_id]);
    $blocked_count = (int) $blocked_stmt->fetchColumn();
    $stats['log_types']['blocked'] = $blocked_count;
    $stats['total_records'] += $blocked_count;

    // Access logs
    $access_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM access_logs WHERE user_id = ? AND website_id = ?"
    );
    $access_stmt->execute([$user_id, $website_id]);
    $access_count = (int) $access_stmt->fetchColumn();
    $stats['log_types']['access'] = $access_count;
    $stats['total_records'] += $access_count;

    // Login logs
    $login_stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM login_logs WHERE user_id = ? AND website_id = ?"
    );
    $login_stmt->execute([$user_id, $website_id]);
    $login_count = (int) $login_stmt->fetchColumn();
    $stats['log_types']['login'] = $login_count;
    $stats['total_records'] += $login_count;

    /*
    |--------------------------------------------------------------------------
    | Recent Activity (Last 7 Days)
    |--------------------------------------------------------------------------
    */

    $recent_stmt = $pdo->prepare("
        SELECT 'visitor' as type, COUNT(*) as count, DATE(timestamp) as date
        FROM logs
        WHERE user_id = ? AND website_id = ?
          AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(timestamp)

        UNION ALL

        SELECT 'attack' as type, COUNT(*) as count, DATE(timestamp) as date
        FROM attack_logs
        WHERE user_id = ? AND website_id = ?
          AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(timestamp)

        UNION ALL

        SELECT 'blocked' as type, COUNT(*) as count, DATE(created_at) as date
        FROM blocked_ips
        WHERE user_id = ? AND website_id = ?
          AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)

        ORDER BY date DESC
        LIMIT 10
    ");

    $recent_stmt->execute([
        $user_id, $website_id,
        $user_id, $website_id,
        $user_id, $website_id
    ]);

    $stats['recent_activity'] = $recent_stmt->fetchAll(PDO::FETCH_ASSOC);

    /*
    |--------------------------------------------------------------------------
    | Success Response
    |--------------------------------------------------------------------------
    */

    echo json_encode([
        'success' => true,
        'stats' => $stats
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {

    // Log internal error
    error_log('Export Stats Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Database error occurred'
    ]);
}

exit;
