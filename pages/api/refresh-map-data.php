<?php
// api/refresh-map-data.php

session_start();
header('Content-Type: application/json');

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/config.php';

// Authentication
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Not authenticated'
    ]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_POST['website_id'] ?? $_SESSION['website_id'] ?? 0);

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
    | Get Recent IPs Missing Geo (Last 24h, max 50)
    |--------------------------------------------------------------------------
    */

    $recentIps = $pdo->prepare("
        SELECT DISTINCT ip 
        FROM logs
        WHERE user_id = ?
          AND website_id = ?
          AND timestamp >= NOW() - INTERVAL 1 DAY
          AND (latitude IS NULL OR longitude IS NULL)
        LIMIT 50
    ");

    $recentIps->execute([$userId, $websiteId]);
    $ips = $recentIps->fetchAll(PDO::FETCH_COLUMN);

    if (empty($ips)) {
        echo json_encode([
            'success' => true,
            'message' => 'No IPs require geolocation update',
            'updated' => 0
        ]);
        exit;
    }

    $updatedCount = 0;

    foreach ($ips as $ip) {

        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }

        // Use HTTPS and cURL with timeout
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "https://ip-api.com/json/{$ip}?fields=status,country,lat,lon",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);

        if ($response === false) {
            curl_close($ch);
            continue;
        }

        curl_close($ch);

        $geo = json_decode($response, true);

        if (!isset($geo['status']) || $geo['status'] !== 'success') {
            continue;
        }

        $update = $pdo->prepare("
            UPDATE logs
            SET country = ?, latitude = ?, longitude = ?
            WHERE ip = ?
              AND user_id = ?
              AND website_id = ?
              AND (latitude IS NULL OR longitude IS NULL)
        ");

        $update->execute([
            $geo['country'] ?? 'Unknown',
            $geo['lat'] ?? null,
            $geo['lon'] ?? null,
            $ip,
            $userId,
            $websiteId
        ]);

        $updatedCount++;

        // Rate limit protection
        usleep(200000); // 0.2 sec
    }

    echo json_encode([
        'success' => true,
        'message' => 'Geolocation refresh completed',
        'updated' => $updatedCount
    ]);

} catch (Exception $e) {

    error_log('Geo Refresh Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'message' => 'Server error occurred'
    ]);
}

exit;
