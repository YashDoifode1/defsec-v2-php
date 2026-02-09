<?php
// api/switch-website.php

session_start();
header('Content-Type: application/json');
ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/functions.php';

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Request Validation
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method'
    ]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_POST['website_id'] ?? 0);

if ($websiteId <= 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid website ID'
    ]);
    exit;
}

try {

    /*
    |--------------------------------------------------------------------------
    | Verify Website Ownership
    |--------------------------------------------------------------------------
    */
    $stmt = $pdo->prepare("
        SELECT id, site_name, domain, status
        FROM websites
        WHERE id = ? AND user_id = ?
        LIMIT 1
    ");
    $stmt->execute([$websiteId, $userId]);
    $website = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$website) {
        echo json_encode([
            'success' => false,
            'message' => 'Website not found or access denied'
        ]);
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | Update Session
    |--------------------------------------------------------------------------
    */
    $_SESSION['website_id'] = $websiteId;

    // Optional but recommended
    session_regenerate_id(true);

    /*
    |--------------------------------------------------------------------------
    | Get Website Stats
    |--------------------------------------------------------------------------
    */
    $stats = getWebsiteStatistics($pdo, $userId, $websiteId);

    echo json_encode([
        'success' => true,
        'message' => 'Website switched successfully',
        'website' => [
            'id' => (int)$website['id'],
            'name' => $website['site_name'],
            'domain' => $website['domain'],
            'status' => $website['status']
        ],
        'stats' => $stats
    ]);

} catch (Exception $e) {

    error_log('Switch Website Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Server error occurred'
    ]);
}

exit;


/*
|--------------------------------------------------------------------------
| Helper: Website Statistics
|--------------------------------------------------------------------------
*/
function getWebsiteStatistics(PDO $pdo, int $userId, int $websiteId): array
{
    try {

        $attackCount = $pdo->prepare("
            SELECT COUNT(*) 
            FROM attack_logs
            WHERE user_id = ?
              AND website_id = ?
              AND timestamp >= NOW() - INTERVAL 24 HOUR
        ");
        $attackCount->execute([$userId, $websiteId]);

        $visitorCount = $pdo->prepare("
            SELECT COUNT(DISTINCT ip)
            FROM logs
            WHERE user_id = ?
              AND website_id = ?
              AND timestamp >= NOW() - INTERVAL 24 HOUR
        ");
        $visitorCount->execute([$userId, $websiteId]);

        $blockedCount = $pdo->prepare("
            SELECT COUNT(*)
            FROM blocked_ips
            WHERE user_id = ?
              AND website_id = ?
              AND (
                  expiry_time = '00:00:00'
                  OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW()
              )
        ");
        $blockedCount->execute([$userId, $websiteId]);

        return [
            'attack_count_24h'  => (int)$attackCount->fetchColumn(),
            'visitor_count_24h' => (int)$visitorCount->fetchColumn(),
            'blocked_count'     => (int)$blockedCount->fetchColumn()
        ];

    } catch (Exception $e) {

        error_log('Stats Error: ' . $e->getMessage());

        return [
            'attack_count_24h'  => 0,
            'visitor_count_24h' => 0,
            'blocked_count'     => 0
        ];
    }
}
