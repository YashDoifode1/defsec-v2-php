<?php
// api/map-data.php

session_start();
header('Content-Type: application/json');

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/functions.php';

// Auth check
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized'
    ]);
    exit;
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_GET['website_id'] ?? $_SESSION['website_id'] ?? 0);

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
    | Recent Visitors (Last 24h)
    |--------------------------------------------------------------------------
    */

    $recentVisitors = $pdo->prepare("
        SELECT 
            ip, real_ip, country, latitude, longitude,
            user_agent, timestamp, is_vpn, is_proxy,
            digital_dna, ASN, ISP
        FROM logs
        WHERE user_id = ?
          AND website_id = ?
          AND latitude IS NOT NULL
          AND longitude IS NOT NULL
          AND timestamp >= NOW() - INTERVAL 24 HOUR
        ORDER BY timestamp DESC
        LIMIT 100
    ");
    $recentVisitors->execute([$userId, $websiteId]);
    $visitorGeoData = $recentVisitors->fetchAll(PDO::FETCH_ASSOC);

    /*
    |--------------------------------------------------------------------------
    | Recent Attacks (Last 24h)
    |--------------------------------------------------------------------------
    */

    $attackGeoData = $pdo->prepare("
        SELECT 
            al.ip_address AS ip,
            l.country,
            l.latitude,
            l.longitude,
            al.attack_type,
            al.severity,
            al.timestamp,
            al.request_url,
            COUNT(*) AS attack_count
        FROM attack_logs al
        LEFT JOIN logs l
            ON al.ip_address = l.ip
           AND l.user_id = al.user_id
           AND l.website_id = al.website_id
        WHERE al.user_id = ?
          AND al.website_id = ?
          AND al.timestamp >= NOW() - INTERVAL 24 HOUR
          AND l.latitude IS NOT NULL
          AND l.longitude IS NOT NULL
        GROUP BY 
            al.ip_address, l.country, l.latitude, l.longitude,
            al.attack_type, al.severity, al.timestamp, al.request_url
        ORDER BY al.timestamp DESC
        LIMIT 100
    ");
    $attackGeoData->execute([$userId, $websiteId]);
    $attackLocations = $attackGeoData->fetchAll(PDO::FETCH_ASSOC);

    /*
    |--------------------------------------------------------------------------
    | Build GeoJSON
    |--------------------------------------------------------------------------
    */

    $visitorFeatures = [];
    $attackFeatures = [];
    $countryList = [];

    foreach ($visitorGeoData as $visitor) {

        if (!$visitor['latitude'] || !$visitor['longitude']) continue;

        $country = $visitor['country'] ?: 'Unknown';
        $countryList[] = $country;

        $visitorFeatures[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [
                    (float)$visitor['longitude'],
                    (float)$visitor['latitude']
                ]
            ],
            'properties' => [
                'type' => 'visitor',
                'ip' => $visitor['ip'],
                'real_ip' => $visitor['real_ip'],
                'country' => $country,
                'timestamp' => $visitor['timestamp'],
                'vpn' => (bool)$visitor['is_vpn'],
                'proxy' => (bool)$visitor['is_proxy'],
                'asn' => $visitor['ASN'] ?? 'Unknown',
                'isp' => $visitor['ISP'] ?? 'Unknown',
                'fingerprint' => $visitor['digital_dna'] ?? 'Unknown'
            ]
        ];
    }

    foreach ($attackLocations as $attack) {

        if (!$attack['latitude'] || !$attack['longitude']) continue;

        $country = $attack['country'] ?: 'Unknown';
        $countryList[] = $country;

        $severityColor = 'gray';
        switch (strtolower($attack['severity'] ?? '')) {
            case 'critical': $severityColor = 'red'; break;
            case 'high':     $severityColor = 'orange'; break;
            case 'medium':   $severityColor = 'yellow'; break;
            case 'info':     $severityColor = 'blue'; break;
        }

        $attackFeatures[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [
                    (float)$attack['longitude'],
                    (float)$attack['latitude']
                ]
            ],
            'properties' => [
                'type' => 'attack',
                'ip' => $attack['ip'],
                'country' => $country,
                'attack_type' => $attack['attack_type'],
                'severity' => $attack['severity'],
                'count' => (int)$attack['attack_count'],
                'timestamp' => $attack['timestamp'],
                'request_url' => $attack['request_url'],
                'color' => $severityColor
            ]
        ];
    }

    $uniqueCountries = count(array_unique(array_filter($countryList)));

    $response = [
        'success' => true,
        'data' => [
            'type' => 'FeatureCollection',
            'features' => array_merge($visitorFeatures, $attackFeatures)
        ],
        'stats' => [
            'total_visitors' => count($visitorFeatures),
            'total_attacks' => count($attackFeatures),
            'unique_countries' => $uniqueCountries,
            'last_update' => date('Y-m-d H:i:s')
        ],
        'metadata' => [
            'user_id' => $userId,
            'website_id' => $websiteId,
            'generated_at' => date('c')
        ]
    ];

} catch (Exception $e) {

    error_log('Map Data Error: ' . $e->getMessage());

    $response = [
        'success' => false,
        'message' => 'Server error occurred',
        'data' => [
            'type' => 'FeatureCollection',
            'features' => []
        ],
        'stats' => [
            'total_visitors' => 0,
            'total_attacks' => 0,
            'unique_countries' => 0,
            'last_update' => date('Y-m-d H:i:s')
        ]
    ];
}

echo json_encode($response, JSON_UNESCAPED_UNICODE);
exit;
