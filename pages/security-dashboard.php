<?php
// Start session only if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once '../includes/db.php';

// Manually define APP_URL - Change this to match your installation
define('APP_URL', 'http://localhost/defsec/v2');

// CSRF token functions
function generateCSRFToken($form_name) {
    if (empty($_SESSION['csrf_tokens'][$form_name])) {
        $_SESSION['csrf_tokens'][$form_name] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_tokens'][$form_name];
}

function validateCSRFToken($form_name, $token) {
    if (empty($_SESSION['csrf_tokens'][$form_name]) || $_SESSION['csrf_tokens'][$form_name] !== $token) {
        return false;
    }
    return true;
}

// Set default timezone
date_default_timezone_set('UTC');

// Authentication check
$isLoggedIn = isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
$user_id = $_SESSION['user_id'] ?? null;
$website_id = $_SESSION['website_id'] ?? null;
$userRole = $_SESSION['role'] ?? 'user';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: " . APP_URL . "/auth/login.php");
    exit();
}

// Database connection
$db = $pdo; // Use the existing connection from db.php

// If website_id not in session, get the user's default website
if (!$website_id || $website_id == 0) {
    try {
        $defaultWebsite = $db->prepare("SELECT id FROM websites WHERE user_id = ? ORDER BY id ASC LIMIT 1");
        $defaultWebsite->execute([$user_id]);
        $website = $defaultWebsite->fetch();
        $website_id = $website['id'] ?? 1;
        $_SESSION['website_id'] = $website_id;
    } catch (Exception $e) {
        $website_id = 1;
    }
}

// Get user details
$userDetails = [];
try {
    $userQuery = $db->prepare("SELECT username, email, full_name, role FROM users WHERE id = ?");
    $userQuery->execute([$user_id]);
    $userDetails = $userQuery->fetch();
} catch (Exception $e) {
    $userDetails = ['username' => 'User', 'email' => '', 'full_name' => '', 'role' => 'viewer'];
}

// Get website details
$websiteDetails = [];
try {
    $websiteQuery = $db->prepare("SELECT site_name, domain, status FROM websites WHERE id = ? AND user_id = ?");
    $websiteQuery->execute([$website_id, $user_id]);
    $websiteDetails = $websiteQuery->fetch();
} catch (Exception $e) {
    $websiteDetails = ['site_name' => 'Default Website', 'domain' => 'unknown', 'status' => 'active'];
}

// Handle website selection
if (isset($_POST['select_website'])) {
    $_SESSION['website_id'] = $_POST['website_id'];
    $website_id = $_SESSION['website_id'];
    // Reload to update data
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Handle website switching via GET
if (isset($_GET['switch_website'])) {
    $_SESSION['website_id'] = intval($_GET['switch_website']);
    $website_id = $_SESSION['website_id'];
    // Reload to update data
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Get all statistics and map data in a single optimized query set
try {
    // Attack statistics (last 7 days)
    $attackStats = $db->prepare("
        SELECT 
            COUNT(*) as total_attacks,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'Info' THEN 1 ELSE 0 END) as info,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $attackStats->execute([$user_id, $website_id]);
    $attackData = $attackStats->fetch() ?? ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    
    // Total visitors with geo data (last 7 days)
    $visitorStats = $db->prepare("
        SELECT 
            COUNT(*) as total_visitors,
            COUNT(DISTINCT ip) as unique_visitors,
            COUNT(CASE WHEN is_vpn = 1 THEN 1 END) as vpn_users,
            COUNT(CASE WHEN is_proxy = 1 THEN 1 END) as proxy_users
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $visitorStats->execute([$user_id, $website_id]);
    $visitorData = $visitorStats->fetch() ?? ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    
    // Get recent visitors with geo data for map (last 24 hours, optimized)
    $recentVisitors = $db->prepare("
        SELECT 
            ip, 
            real_ip, 
            country, 
            latitude, 
            longitude,
            user_agent,
            timestamp,
            is_vpn,
            is_proxy,
            digital_dna,
            ASN,
            ISP
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND latitude IS NOT NULL 
        AND longitude IS NOT NULL
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY timestamp DESC 
        LIMIT 50
    ");
    $recentVisitors->execute([$user_id, $website_id]);
    $visitorGeoData = $recentVisitors->fetchAll();
    
    // Get attack IPs with geo data for map (last 24 hours, optimized)
    $attackGeoData = $db->prepare("
        SELECT 
            al.ip_address as ip,
            l.country,
            l.latitude,
            l.longitude,
            al.attack_type,
            al.severity,
            al.timestamp,
            al.request_url,
            COUNT(*) as attack_count
        FROM attack_logs al
        LEFT JOIN logs l ON al.ip_address = l.ip 
            AND l.user_id = al.user_id 
            AND l.website_id = al.website_id
        WHERE al.user_id = ? AND al.website_id = ?
        AND al.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        AND l.latitude IS NOT NULL 
        AND l.longitude IS NOT NULL
        GROUP BY al.ip_address, l.country, l.latitude, l.longitude, al.attack_type, al.severity, al.timestamp, al.request_url
        ORDER BY attack_count DESC
        LIMIT 50
    ");
    $attackGeoData->execute([$user_id, $website_id]);
    $attackLocations = $attackGeoData->fetchAll();
    
    // Blocked IPs (active)
    $blockedIps = $db->prepare("
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE user_id = ? AND website_id = ?
        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
    ");
    $blockedIps->execute([$user_id, $website_id]);
    $blockedData = $blockedIps->fetch() ?? ['count' => 0];
    
    // Recent attacks (last 10)
    $recentAttacks = $db->prepare("
        SELECT attack_type, severity, ip_address, timestamp, request_url 
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $recentAttacks->execute([$user_id, $website_id]);
    $recentData = $recentAttacks->fetchAll();
    
    // Top attacking countries
    $topCountries = $db->prepare("
        SELECT 
            l.country,
            COUNT(*) as attack_count,
            GROUP_CONCAT(DISTINCT al.attack_type) as attack_types
        FROM attack_logs al
        LEFT JOIN logs l ON al.ip_address = l.ip 
            AND l.user_id = al.user_id 
            AND l.website_id = al.website_id
        WHERE al.user_id = ? AND al.website_id = ?
        AND al.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        AND l.country IS NOT NULL 
        AND l.country != 'Unknown'
        GROUP BY l.country
        ORDER BY attack_count DESC
        LIMIT 10
    ");
    $topCountries->execute([$user_id, $website_id]);
    $countryData = $topCountries->fetchAll();
    
    // Get user's websites
    $userWebsites = $db->prepare("SELECT id, site_name, domain FROM websites WHERE user_id = ? ORDER BY site_name");
    $userWebsites->execute([$user_id]);
    $websites = $userWebsites->fetchAll();
    
} catch (PDOException $e) {
    // Initialize empty data
    $attackData = ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    $visitorData = ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    $visitorGeoData = [];
    $attackLocations = [];
    $blockedData = ['count' => 0];
    $recentData = [];
    $countryData = [];
    $websites = [];
}

// Prepare GeoJSON data for map
$visitorFeatures = [];
$attackFeatures = [];
$countryList = [];
$uniqueIPs = [];

foreach ($visitorGeoData as $visitor) {
    if (!empty($visitor['latitude']) && !empty($visitor['longitude'])) {
        $country = $visitor['country'] ?? 'Unknown';
        $countryList[] = $country;
        $uniqueIPs[$visitor['ip']] = true;
        
        $visitorFeatures[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [(float)$visitor['longitude'], (float)$visitor['latitude']]
            ],
            'properties' => [
                'type' => 'visitor',
                'ip' => $visitor['ip'],
                'real_ip' => $visitor['real_ip'] ?? $visitor['ip'],
                'country' => $country,
                'timestamp' => date('Y-m-d H:i', strtotime($visitor['timestamp'])),
                'vpn' => (bool)$visitor['is_vpn'],
                'proxy' => (bool)$visitor['is_proxy'],
                'asn' => $visitor['ASN'] ?? 'Unknown',
                'isp' => $visitor['ISP'] ?? 'Unknown',
                'fingerprint' => $visitor['digital_dna'] ?? 'Unknown',
                'title' => "Visitor from " . $country,
                'description' => "IP: " . $visitor['ip'] . 
                               "<br>Time: " . date('H:i', strtotime($visitor['timestamp'])) .
                               "<br>ISP: " . ($visitor['ISP'] ?? 'Unknown') .
                               ($visitor['is_vpn'] ? "<br>⚠️ VPN Detected" : "") .
                               ($visitor['is_proxy'] ? "<br>⚠️ Proxy Detected" : "")
            ]
        ];
    }
}

foreach ($attackLocations as $attack) {
    if (!empty($attack['latitude']) && !empty($attack['longitude'])) {
        $country = $attack['country'] ?? 'Unknown';
        $countryList[] = $country;
        $uniqueIPs[$attack['ip']] = true;
        
        $severityColor = 'gray';
        switch(strtolower($attack['severity'])) {
            case 'critical': $severityColor = 'red'; break;
            case 'high': $severityColor = 'orange'; break;
            case 'medium': $severityColor = 'yellow'; break;
            case 'info': $severityColor = 'blue'; break;
        }
        
        $attackFeatures[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [(float)$attack['longitude'], (float)$attack['latitude']]
            ],
            'properties' => [
                'type' => 'attack',
                'ip' => $attack['ip'],
                'country' => $country,
                'attack_type' => $attack['attack_type'],
                'severity' => $attack['severity'],
                'count' => (int)$attack['attack_count'],
                'timestamp' => date('Y-m-d H:i', strtotime($attack['timestamp'])),
                'request_url' => $attack['request_url'] ?? '',
                'color' => $severityColor,
                'title' => $attack['attack_type'] . " Attack",
                'description' => "IP: " . $attack['ip'] . 
                               "<br>Type: " . $attack['attack_type'] . 
                               "<br>Severity: <span class='text-" . 
                               ($attack['severity'] == 'Critical' ? 'danger' : 
                                ($attack['severity'] == 'High' ? 'warning' : 'info')) . 
                               "'>" . $attack['severity'] . "</span>" .
                               "<br>Count: " . $attack['attack_count'] .
                               "<br>Time: " . date('H:i', strtotime($attack['timestamp']))
            ]
        ];
    }
}

// Combine features
$geoJsonData = [
    'type' => 'FeatureCollection',
    'features' => array_merge($visitorFeatures, $attackFeatures),
    'stats' => [
        'total_visitors' => count($visitorFeatures),
        'total_attacks' => count($attackFeatures),
        'unique_countries' => count(array_unique(array_filter($countryList))),
        'unique_ips' => count($uniqueIPs),
        'last_update' => date('Y-m-d H:i:s')
    ]
];

$uniqueCountries = array_unique(array_filter($countryList));

// Calculate security score
$securityScore = 100;
$totalAttacks = $attackData['total_attacks'] ?? 0;
$uniqueVisitors = max(1, $visitorData['unique_visitors'] ?? 1);

if ($totalAttacks > 0) {
    $attackRatio = ($totalAttacks / $uniqueVisitors) * 100;
    $securityScore = max(0, 100 - min($attackRatio, 50));
}

// Get current page for navigation highlighting
$current_page = basename($_SERVER['PHP_SELF']);
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec - Security Dashboard</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css" />
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <!-- jQuery -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>

    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #0dcaf0;
            --dark-color: #121212;
            --light-color: #f8f9fa;
            --sidebar-width: 250px;
            --header-height: 60px;
        }
        
        body {
            background-color: var(--dark-color);
            color: #e9ecef;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Sidebar Styles */
        .sidebar {
            width: var(--sidebar-width);
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            background-color: #1e1e1e;
            border-right: 1px solid #343a40;
            z-index: 1000;
            transition: transform 0.3s ease;
        }
        
        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid #343a40;
        }
        
        .sidebar-menu {
            padding: 20px 0;
        }
        
        .nav-link {
            color: #adb5bd;
            padding: 12px 20px;
            border-left: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .nav-link:hover, .nav-link.active {
            color: #ffffff;
            background-color: rgba(255, 255, 255, 0.05);
            border-left-color: var(--primary-color);
        }
        
        .nav-link i {
            width: 24px;
            margin-right: 10px;
        }
        
        /* Main Content */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 0;
            min-height: 100vh;
            transition: margin-left 0.3s ease;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
        }
        
        /* Header */
        .main-header {
            background-color: #1e1e1e;
            border-bottom: 1px solid #343a40;
            padding: 15px 20px;
            position: sticky;
            top: 0;
            z-index: 999;
        }
        
        /* Dashboard Cards */
        .dashboard-card {
            background-color: #1e1e1e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #343a40;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        
        .card-icon {
            font-size: 2rem;
            margin-bottom: 15px;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            line-height: 1;
        }
        
        .stat-change {
            font-size: 0.9rem;
        }
        
        .positive { color: var(--success-color); }
        .negative { color: var(--danger-color); }
        
        /* Tables */
        .table-dark {
            background-color: #1e1e1e;
            color: #e9ecef;
        }
        
        .table-dark thead th {
            border-bottom: 2px solid #343a40;
            background-color: #252525;
        }
        
        .table-dark tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        /* Buttons */
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #0b5ed7;
            border-color: #0a58ca;
        }
        
        /* Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1e1e1e;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #495057;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #6c757d;
        }
        
        /* Content Area */
        .content-area {
            padding: 20px;
        }
        
        /* MAP AREA - Enhanced styling */
        #securityMap {
            height: 500px;
            width: 100%;
            border-radius: 8px;
            margin-bottom: 1rem;
            z-index: 1;
            background-color: #1a1a1a !important;
        }
        
        .map-container {
            position: relative;
            background-color: #1e1e1e;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #343a40;
        }
        
        .map-legend {
            position: absolute;
            bottom: 30px;
            right: 30px;
            background: rgba(0, 0, 0, 0.85);
            padding: 15px;
            border-radius: 8px;
            z-index: 1000;
            font-size: 12px;
            color: white;
            border: 1px solid #444;
            backdrop-filter: blur(5px);
            min-width: 180px;
        }
        
        .map-legend h6 {
            margin-bottom: 10px;
            color: #fff;
            border-bottom: 1px solid #444;
            padding-bottom: 5px;
        }
        
        .map-legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .map-legend-color {
            width: 20px;
            height: 20px;
            margin-right: 8px;
            border-radius: 50%;
            border: 2px solid rgba(255,255,255,0.3);
        }
        
        .map-legend-color.square {
            border-radius: 4px;
        }
        
        .attack-marker {
            filter: drop-shadow(0 0 5px rgba(0,0,0,0.5));
            transition: all 0.3s ease;
        }
        
        .attack-marker:hover {
            transform: scale(1.2);
            z-index: 1000;
            filter: drop-shadow(0 0 10px currentColor);
        }
        
        .map-controls {
            position: absolute;
            top: 30px;
            right: 30px;
            z-index: 1000;
            background: rgba(0, 0, 0, 0.85);
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #444;
            backdrop-filter: blur(5px);
            min-width: 150px;
        }
        
        .map-controls .form-check {
            margin-bottom: 8px;
        }
        
        .map-controls .form-check:last-child {
            margin-bottom: 0;
        }
        
        .map-tooltip {
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
        }
        
        .map-stats {
            position: absolute;
            top: 30px;
            left: 30px;
            z-index: 1000;
            background: rgba(0, 0, 0, 0.85);
            padding: 12px 15px;
            border-radius: 8px;
            font-size: 13px;
            min-width: 200px;
            border: 1px solid #444;
            backdrop-filter: blur(5px);
        }
        
        .map-stats div {
            margin-bottom: 5px;
        }
        
        .map-stats div:last-child {
            margin-bottom: 0;
        }
        
        /* Custom popup styling */
        .custom-popup .leaflet-popup-content-wrapper {
            background: rgba(30, 30, 30, 0.95);
            color: #fff;
            border-radius: 8px;
            border: 1px solid #444;
            backdrop-filter: blur(5px);
        }
        
        .custom-popup .leaflet-popup-tip {
            background: rgba(30, 30, 30, 0.95);
            border: 1px solid #444;
        }
        
        .custom-popup .leaflet-popup-content {
            margin: 15px;
            line-height: 1.5;
        }
        
        /* Cluster styling */
        .cluster-marker {
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: white;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
            transition: all 0.3s ease;
        }
        
        .cluster-marker:hover {
            transform: scale(1.1);
        }
        
        /* Marker animations */
        @keyframes pulse-attack {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.9; box-shadow: 0 0 20px currentColor; }
            100% { transform: scale(1); opacity: 1; }
        }
        
        @keyframes pulse-vpn {
            0% { box-shadow: 0 0 0 0 rgba(255, 193, 7, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(255, 193, 7, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 193, 7, 0); }
        }
        
        .vpn-marker {
            animation: pulse-vpn 2s infinite;
        }
        
        .attack-marker {
            animation: pulse-attack 2s infinite;
        }
        
        /* Modal dark mode enhancements */
        .modal-content.bg-dark {
            background-color: #1e1e1e !important;
            border: 1px solid #343a40;
        }
        
        .modal-header.border-secondary {
            border-bottom-color: #495057 !important;
        }
        
        .modal-footer.border-secondary {
            border-top-color: #495057 !important;
        }
        
        .btn-close-white {
            filter: invert(1) grayscale(100%) brightness(200%);
        }
        
        #modalMap {
            height: 300px;
            width: 100%;
            border-radius: 5px;
            margin-bottom: 15px;
            border: 1px solid #444;
        }
        
        .info-label {
            color: #adb5bd;
            font-size: 0.85rem;
            margin-bottom: 2px;
        }
        
        .info-value {
            background: #2d2d2d;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid #444;
            margin-bottom: 10px;
            font-family: monospace;
            word-break: break-all;
        }
        
        /* Dropdown dark mode */
        .dropdown-menu {
            background-color: #1e1e1e;
            border: 1px solid #343a40;
        }
        
        .dropdown-item {
            color: #adb5bd;
        }
        
        .dropdown-item:hover, .dropdown-item:focus {
            background-color: rgba(255, 255, 255, 0.05);
            color: #ffffff;
        }
        
        .dropdown-item.active {
            background-color: var(--primary-color);
            color: white;
        }
        
        /* Badges */
        .badge.bg-dark {
            background-color: #343a40 !important;
        }
        
        /* Progress bar */
        .progress {
            background-color: #2d2d2d;
            height: 6px;
        }
        
        /* Alert styling */
        .alert {
            background-color: rgba(255, 255, 255, 0.05);
            border-color: rgba(255, 255, 255, 0.1);
            color: #e9ecef;
        }
        
        .alert-warning {
            background-color: rgba(255, 193, 7, 0.1);
            border-color: rgba(255, 193, 7, 0.2);
            color: #ffc107;
        }
        
        .alert-danger {
            background-color: rgba(220, 53, 69, 0.1);
            border-color: rgba(220, 53, 69, 0.2);
            color: #dc3545;
        }
        
        .alert-info {
            background-color: rgba(13, 202, 240, 0.1);
            border-color: rgba(13, 202, 240, 0.2);
            color: #0dcaf0;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h3 class="mb-0">
                <i class="fas fa-shield-alt text-primary me-2"></i>
                <span class="fw-bold">DefSec</span>
            </h3>
            <p class="text-muted mb-0 small">Security Dashboard</p>
        </div>
        
        <div class="sidebar-menu">
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link active" href="<?php echo APP_URL; ?>/pages/summery.php">
                        <i class="fas fa-home"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/security-dashboard.php">
                        <i class="fas fa-shield-alt"></i> Security
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/web-security.php">
                        <i class="fas fa-bug"></i> Attack Logs
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/vpn-monitoring.php">
                        <i class="fas fa-shield-virus"></i> VPN Monitor
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/block-list.php">
                        <i class="fas fa-ban"></i> Block List
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/export.php">
                        <i class="fas fa-archive"></i> Export logs
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/pages/user-tracker.php">
                        <i class="fas fa-user-secret"></i> User Tracker
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="<?php echo APP_URL; ?>/auth/settings.php">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                </li>
                <li class="nav-item mt-4">
                    <a class="nav-link text-danger" href="<?php echo APP_URL; ?>/auth/logout.php">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </li>
            </ul>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <!-- Header -->
        <header class="main-header d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <button class="btn btn-outline-secondary me-3 d-lg-none" id="sidebarToggle">
                    <i class="fas fa-bars"></i>
                </button>
                <h4 class="mb-0">
                    <i class="fas fa-tachometer-alt me-2"></i>Cybersecurity Dashboard
                </h4>
            </div>
            
            <div class="d-flex align-items-center">
                <div class="dropdown">
                    <button class="btn btn-outline-light dropdown-toggle" type="button" id="userDropdown" data-bs-toggle="dropdown">
                        <i class="fas fa-user-circle me-2"></i>
                        <?php echo htmlspecialchars($userDetails['username'] ?? 'User'); ?>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="<?php echo APP_URL; ?>/auth/profile.php"><i class="fas fa-user me-2"></i> Profile</a></li>
                        <li><a class="dropdown-item" href="<?php echo APP_URL; ?>/auth/settings.php"><i class="fas fa-cog me-2"></i> Settings</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href="<?php echo APP_URL; ?>/auth/logout.php"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                    </ul>
                </div>
            </div>
        </header>

        <!-- Main Content Area -->
        <div class="content-area">
            <!-- Page Header -->
            <div class="row mb-4 fade-in">
                <div class="col-12">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <div>
                            <p class="text-muted mb-0">
                                Welcome back, <strong><?php echo htmlspecialchars($userDetails['full_name'] ?? $userDetails['username'] ?? 'User'); ?></strong>! 
                                Monitoring: <strong><?php echo htmlspecialchars($websiteDetails['site_name'] ?? 'Website'); ?></strong> 
                                (<code><?php echo htmlspecialchars($websiteDetails['domain'] ?? 'unknown'); ?></code>)
                            </p>
                        </div>
                        <div>
                            <div class="d-flex gap-2 align-items-center">
                                <span class="badge bg-primary">
                                    <i class="fas fa-calendar me-1"></i> <?php echo date('F j, Y'); ?>
                                </span>
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                        <i class="fas fa-globe me-1"></i> Site: <?php echo htmlspecialchars($websiteDetails['site_name'] ?? 'Select'); ?>
                                    </button>
                                    <ul class="dropdown-menu">
                                        <?php if (!empty($websites)): ?>
                                            <?php foreach ($websites as $website): ?>
                                                <li>
                                                    <a class="dropdown-item <?php echo ($website['id'] == $website_id) ? 'active' : ''; ?>" 
                                                       href="?switch_website=<?php echo $website['id']; ?>">
                                                        <?php echo htmlspecialchars($website['site_name']); ?> 
                                                        <small class="text-muted">(<?php echo htmlspecialchars($website['domain']); ?>)</small>
                                                    </a>
                                                </li>
                                            <?php endforeach; ?>
                                        <?php else: ?>
                                            <li><a class="dropdown-item" href="#">No websites found</a></li>
                                        <?php endif; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Map Section -->
            <div class="row mb-4 fade-in">
                <div class="col-12">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="mb-0"><i class="fas fa-map-marked-alt me-2 text-primary"></i>Global Threat Intelligence Map</h5>
                            <div>
                                <button class="btn btn-sm btn-outline-secondary" onclick="resetMapView()">
                                    <i class="fas fa-sync-alt"></i> Reset View
                                </button>
                                <button class="btn btn-sm btn-outline-info ms-1" onclick="exportMapData()">
                                    <i class="fas fa-download"></i> Export Data
                                </button>
                                <button class="btn btn-sm btn-outline-success ms-1" onclick="refreshMapData()">
                                    <i class="fas fa-redo"></i> Refresh
                                </button>
                            </div>
                        </div>
                        
                        <div class="map-container">
                            <div id="securityMap"></div>
                            
                            <div class="map-stats">
                                <h6 class="mb-2"><i class="fas fa-chart-simple me-1"></i> Live Statistics</h6>
                                <div class="d-flex justify-content-between">
                                    <small class="text-muted"><i class="fas fa-user me-1"></i> Visitors:</small>
                                    <small><span class="text-success fw-bold"><?php echo count($visitorFeatures); ?></span></small>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <small class="text-muted"><i class="fas fa-bug me-1"></i> Attacks:</small>
                                    <small><span class="text-danger fw-bold"><?php echo count($attackFeatures); ?></span></small>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <small class="text-muted"><i class="fas fa-flag me-1"></i> Countries:</small>
                                    <small><span class="text-info fw-bold"><?php echo count($uniqueCountries); ?></span></small>
                                </div>
                                <div class="d-flex justify-content-between">
                                    <small class="text-muted"><i class="fas fa-clock me-1"></i> Updated:</small>
                                    <small><?php echo date('H:i:s'); ?></small>
                                </div>
                                <hr class="my-2 opacity-25">
                                <div class="d-flex justify-content-between">
                                    <small class="text-muted"><i class="fas fa-shield me-1"></i> Protected:</small>
                                    <small><span class="text-success">Active</span></small>
                                </div>
                            </div>
                            
                            <div class="map-controls">
                                <h6 class="mb-2"><i class="fas fa-sliders me-1"></i> Layer Controls</h6>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="showVisitors" checked>
                                    <label class="form-check-label text-white" for="showVisitors">
                                        <i class="fas fa-user text-success me-1"></i> Visitors
                                    </label>
                                </div>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="showAttacks" checked>
                                    <label class="form-check-label text-white" for="showAttacks">
                                        <i class="fas fa-bug text-danger me-1"></i> Attacks
                                    </label>
                                </div>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="clusterMarkers" checked>
                                    <label class="form-check-label text-white" for="clusterMarkers">
                                        <i class="fas fa-layer-group me-1"></i> Cluster Markers
                                    </label>
                                </div>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="heatmap" disabled>
                                    <label class="form-check-label text-white text-muted" for="heatmap">
                                        <i class="fas fa-fire me-1"></i> Heatmap (Soon)
                                    </label>
                                </div>
                            </div>
                            
                            <div class="map-legend">
                                <h6><i class="fas fa-palette me-1"></i> Legend</h6>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #28a745;"></div>
                                    <span>Normal Visitor</span>
                                </div>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #6c757d; border-color: #ffc107;"></div>
                                    <span>VPN/Proxy User</span>
                                </div>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #dc3545;"></div>
                                    <span>Critical Attack</span>
                                </div>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #fd7e14;"></div>
                                    <span>High Severity</span>
                                </div>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #ffc107;"></div>
                                    <span>Medium Severity</span>
                                </div>
                                <div class="map-legend-item">
                                    <div class="map-legend-color" style="background-color: #0dcaf0;"></div>
                                    <span>Info/Low Severity</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Statistics Cards -->
            <div class="row mb-4 fade-in">
                <div class="col-xl-3 col-md-6">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <div class="card-icon text-danger">
                                    <i class="fas fa-skull-crossbones"></i>
                                </div>
                                <div class="text-muted mb-1">Total Attacks (7 days)</div>
                                <div class="stat-number text-danger"><?php echo $attackData['total_attacks'] ?? 0; ?></div>
                                <div class="stat-change">
                                    <small>
                                        <span class="text-danger"><?php echo $attackData['critical'] ?? 0; ?> Critical</span> | 
                                        <span class="text-warning"><?php echo $attackData['high'] ?? 0; ?> High</span>
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <div class="card-icon text-warning">
                                    <i class="fas fa-ban"></i>
                                </div>
                                <div class="text-muted mb-1">Blocked IPs</div>
                                <div class="stat-number text-warning"><?php echo $blockedData['count'] ?? 0; ?></div>
                                <div class="stat-change positive">
                                    <i class="fas fa-shield-alt"></i> Active protection
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <div class="card-icon text-success">
                                    <i class="fas fa-users"></i>
                                </div>
                                <div class="text-muted mb-1">Visitors (7 days)</div>
                                <div class="stat-number text-success"><?php echo $visitorData['unique_visitors'] ?? 0; ?></div>
                                <div class="stat-change">
                                    <small>
                                        <?php echo $visitorData['vpn_users'] ?? 0; ?> VPN | 
                                        <?php echo $visitorData['proxy_users'] ?? 0; ?> Proxy
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <div class="card-icon text-info">
                                    <i class="fas fa-user-shield"></i>
                                </div>
                                <div class="text-muted mb-1">Security Score</div>
                                <div class="stat-number text-info"><?php echo round($securityScore); ?>%</div>
                                <div class="stat-change <?php echo $securityScore >= 80 ? 'positive' : ($securityScore >= 60 ? '' : 'negative'); ?>">
                                    <i class="fas fa-<?php echo $securityScore >= 80 ? 'shield-alt' : 'exclamation-triangle'; ?>"></i>
                                    <?php echo $securityScore >= 80 ? 'Excellent' : ($securityScore >= 60 ? 'Good' : 'Needs attention'); ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent Attacks & Top Countries -->
            <div class="row fade-in">
                <div class="col-xl-8">
                    <div class="dashboard-card">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h5 class="mb-0"><i class="fas fa-history me-2 text-warning"></i>Recent Attacks</h5>
                            <a href="web-security.php?website_id=<?php echo $website_id; ?>" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-external-link-alt me-1"></i> View All
                            </a>
                        </div>
                        
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>Attack Type</th>
                                        <th>Severity</th>
                                        <th>IP Address</th>
                                        <th>Country</th>
                                        <th>Time</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (!empty($recentData)): ?>
                                        <?php foreach ($recentData as $attack): ?>
                                        <?php
                                        // Get country for this IP
                                        $ipCountry = 'Unknown';
                                        try {
                                            $countryQuery = $db->prepare("SELECT country FROM logs WHERE ip = ? AND user_id = ? AND website_id = ? ORDER BY timestamp DESC LIMIT 1");
                                            $countryQuery->execute([$attack['ip_address'], $user_id, $website_id]);
                                            $countryResult = $countryQuery->fetch();
                                            $ipCountry = $countryResult['country'] ?? 'Unknown';
                                        } catch (Exception $e) {
                                            $ipCountry = 'Unknown';
                                        }
                                        ?>
                                        <tr>
                                            <td>
                                                <span class="badge bg-secondary">
                                                    <?php echo htmlspecialchars($attack['attack_type'] ?? 'Unknown'); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?php
                                                $severityColor = 'secondary';
                                                $severity = strtolower($attack['severity'] ?? '');
                                                switch($severity) {
                                                    case 'critical': $severityColor = 'danger'; break;
                                                    case 'high': $severityColor = 'warning'; break;
                                                    case 'medium': $severityColor = 'info'; break;
                                                    case 'info': $severityColor = 'secondary'; break;
                                                }
                                                ?>
                                                <span class="badge bg-<?php echo $severityColor; ?>">
                                                    <?php echo htmlspecialchars($attack['severity'] ?? 'Info'); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <code><?php echo htmlspecialchars($attack['ip_address'] ?? 'Unknown'); ?></code>
                                            </td>
                                            <td>
                                                <span class="badge bg-dark">
                                                    <?php echo htmlspecialchars($ipCountry); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?php 
                                                $time = $attack['timestamp'] ?? '';
                                                if ($time) {
                                                    echo date('H:i', strtotime($time));
                                                } else {
                                                    echo 'N/A';
                                                }
                                                ?>
                                            </td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <button type="button" class="btn btn-outline-info" 
                                                            onclick="focusOnIP('<?php echo htmlspecialchars($attack['ip_address'] ?? ''); ?>')"
                                                            title="Locate on Map">
                                                        <i class="fas fa-map-marker-alt"></i>
                                                    </button>
                                                    <a href="block-list.php?ip=<?php echo urlencode($attack['ip_address'] ?? ''); ?>&website_id=<?php echo $website_id; ?>" 
                                                       class="btn btn-outline-danger" title="Block IP">
                                                        <i class="fas fa-ban"></i>
                                                    </a>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <tr>
                                            <td colspan="6" class="text-center py-4">
                                                <div class="text-muted">
                                                    <i class="fas fa-check-circle fa-2x mb-3 text-success"></i>
                                                    <div>No recent attacks detected</div>
                                                    <small class="mt-2 d-block">Your security is looking good!</small>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="col-xl-4">
                    <div class="dashboard-card">
                        <h5 class="mb-4"><i class="fas fa-flag me-2 text-danger"></i>Top Attacking Countries</h5>
                        
                        <?php if (!empty($countryData)): ?>
                            <div class="mb-4">
                                <?php foreach ($countryData as $country): ?>
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <div>
                                            <span class="badge bg-dark"><?php echo htmlspecialchars($country['country']); ?></span>
                                            <small class="text-muted ms-2"><?php echo $country['attack_types']; ?></small>
                                        </div>
                                        <div>
                                            <span class="badge bg-danger"><?php echo $country['attack_count']; ?> attacks</span>
                                        </div>
                                    </div>
                                    <div class="progress mb-3" style="height: 6px;">
                                        <div class="progress-bar bg-danger" 
                                             style="width: <?php echo min(100, ($country['attack_count'] / max(1, $attackData['total_attacks'])) * 100); ?>%"></div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <div class="text-center text-muted py-3">
                                <i class="fas fa-globe fa-lg mb-2"></i>
                                <div>No country data available</div>
                            </div>
                        <?php endif; ?>
                        
                        <div class="mt-4 pt-3 border-top border-secondary">
                            <h6 class="mb-3"><i class="fas fa-bolt me-2 text-warning"></i>Quick Actions</h6>
                            <div class="d-grid gap-2">
                                <a href="geolocation.php?website_id=<?php echo $website_id; ?>" class="btn btn-outline-primary text-start">
                                    <i class="fas fa-map me-2"></i> Detailed Geolocation
                                </a>
                                <a href="web-security.php?website_id=<?php echo $website_id; ?>" class="btn btn-outline-primary text-start">
                                    <i class="fas fa-bug me-2"></i> Attack Analytics
                                </a>
                                <a href="block-list.php?website_id=<?php echo $website_id; ?>" class="btn btn-outline-primary text-start">
                                    <i class="fas fa-ban me-2"></i> IP Management
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Attack Details Modal -->
    <div class="modal fade" id="attackDetailsModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark">
                <div class="modal-header border-secondary">
                    <h5 class="modal-title">
                        <i class="fas fa-map-pin me-2 text-info"></i>
                        IP Location Details
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="modalMap" style="height: 300px; width: 100%; border-radius: 5px; margin-bottom: 15px;"></div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="info-label"><i class="fas fa-ip me-1"></i> IP Address</div>
                            <div class="info-value" id="modalIp"></div>
                            
                            <div class="info-label"><i class="fas fa-flag me-1"></i> Country</div>
                            <div class="info-value" id="modalCountry"></div>
                            
                            <div class="info-label"><i class="fas fa-map-marker-alt me-1"></i> Coordinates</div>
                            <div class="info-value" id="modalCoords"></div>
                        </div>
                        <div class="col-md-6">
                            <div class="info-label"><i class="fas fa-clock me-1"></i> Last Seen</div>
                            <div class="info-value" id="modalLastSeen"></div>
                            
                            <div class="info-label"><i class="fas fa-network-wired me-1"></i> ISP / ASN</div>
                            <div class="info-value" id="modalISP"></div>
                            
                            <div class="info-label"><i class="fas fa-fingerprint me-1"></i> Fingerprint</div>
                            <div class="info-value" id="modalFingerprint"></div>
                        </div>
                    </div>
                    <div id="modalAttackDetails" class="mt-3"></div>
                </div>
                <div class="modal-footer border-secondary">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <a href="#" class="btn btn-danger" id="modalBlockBtn" target="_blank">
                        <i class="fas fa-ban me-1"></i> Block IP
                    </a>
                    <a href="#" class="btn btn-info" id="modalWhoisBtn" target="_blank">
                        <i class="fas fa-search me-1"></i> WHOIS
                    </a>
                    <a href="#" class="btn btn-warning" id="modalIPDetailsBtn" target="_blank">
                        <i class="fas fa-info-circle me-1"></i> IP Details
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Leaflet JS -->
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

    <script>
    // Map variables
    let map;
    let markers = L.featureGroup();
    let visitorLayer;
    let attackLayer;
    let markerCluster;
    let modalMap = null;

    // GeoJSON data from PHP
    const geoJsonData = <?php echo json_encode($geoJsonData, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT); ?>;

    // Initialize map
    function initMap() {
        // Create map centered on world with dark theme
        map = L.map('securityMap', {
            center: [20, 0],
            zoom: 2,
            zoomControl: true,
            fadeAnimation: true,
            markerZoomAnimation: true
        });
        
        // Add CartoDB dark theme tiles for better contrast
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>, &copy; CartoDB',
            maxZoom: 18,
            subdomains: 'abcd'
        }).addTo(map);
        
        // Add zoom control to bottom right
        map.zoomControl.setPosition('bottomright');
        
        // Create marker cluster group with custom styling
        markerCluster = L.markerClusterGroup({
            chunkedLoading: true,
            showCoverageOnHover: false,
            maxClusterRadius: 60,
            spiderfyOnMaxZoom: true,
            disableClusteringAtZoom: 10,
            iconCreateFunction: function(cluster) {
                const markers = cluster.getAllChildMarkers();
                const attackCount = markers.filter(m => 
                    m.getPopup()?.getContent()?.toLowerCase().includes('attack')
                ).length;
                
                const totalCount = cluster.getChildCount();
                const color = attackCount > totalCount / 2 ? '#dc3545' : 
                             (attackCount > 0 ? '#fd7e14' : '#28a745');
                
                return L.divIcon({
                    html: `<div style="background-color: ${color}; width: 45px; height: 45px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; border: 3px solid white; box-shadow: 0 0 15px rgba(0,0,0,0.7); background: radial-gradient(circle at 30% 30%, ${color}dd, ${color});">${totalCount}</div>`,
                    className: 'cluster-marker',
                    iconSize: [45, 45]
                });
            }
        });
        
        // Create separate layers
        visitorLayer = L.layerGroup();
        attackLayer = L.layerGroup();
        
        // Add markers from GeoJSON
        addMarkersToLayers();
        
        // Add cluster to map
        map.addLayer(markerCluster);
        
        // Add scale
        L.control.scale({
            imperial: false,
            metric: true,
            position: 'bottomleft'
        }).addTo(map);
        
        // Force a map resize after initialization
        setTimeout(() => {
            map.invalidateSize();
        }, 200);
    }

    // Function to add markers to layers
    function addMarkersToLayers() {
        // Clear existing markers
        visitorLayer.clearLayers();
        attackLayer.clearLayers();
        markerCluster.clearLayers();
        
        geoJsonData.features.forEach(function(feature) {
            const coords = feature.geometry.coordinates;
            const props = feature.properties;
            
            let markerColor, markerIcon, markerSize;
            
            if (props.type === 'visitor') {
                // Visitor marker - color based on VPN/Proxy status
                if (props.vpn || props.proxy) {
                    markerColor = '#6c757d'; // Gray for VPN/Proxy
                    markerIcon = L.divIcon({
                        className: 'visitor-marker vpn-marker',
                        html: `<div style="background-color: ${markerColor}; width: 18px; height: 18px; border-radius: 50%; border: 3px solid #ffc107; box-shadow: 0 0 15px rgba(255,193,7,0.7);"></div>`,
                        iconSize: [24, 24],
                        iconAnchor: [12, 12]
                    });
                } else {
                    markerColor = '#28a745'; // Green for normal visitors
                    markerIcon = L.divIcon({
                        className: 'visitor-marker',
                        html: `<div style="background-color: ${markerColor}; width: 16px; height: 16px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 10px ${markerColor};"></div>`,
                        iconSize: [20, 20],
                        iconAnchor: [10, 10]
                    });
                }
            } else {
                // Attack marker - color based on severity with size based on count
                switch(props.severity?.toLowerCase()) {
                    case 'critical':
                        markerColor = '#dc3545'; // Red
                        break;
                    case 'high':
                        markerColor = '#fd7e14'; // Orange
                        break;
                    case 'medium':
                        markerColor = '#ffc107'; // Yellow
                        break;
                    case 'info':
                    default:
                        markerColor = '#0dcaf0'; // Blue
                        break;
                }
                
                // Size based on attack count (min 18px, max 40px)
                markerSize = Math.min(40, Math.max(18, 12 + (props.count || 1) * 3));
                
                markerIcon = L.divIcon({
                    className: 'attack-marker',
                    html: `<div style="background-color: ${markerColor}; width: ${markerSize}px; height: ${markerSize}px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 20px ${markerColor}; background: radial-gradient(circle at 30% 30%, ${markerColor}dd, ${markerColor});"></div>`,
                    iconSize: [markerSize + 6, markerSize + 6],
                    iconAnchor: [(markerSize + 6) / 2, (markerSize + 6) / 2]
                });
            }
            
            const marker = L.marker([coords[1], coords[0]], { icon: markerIcon });
            
            // Enhanced popup content
            const popupContent = `
                <div class="map-tooltip" style="max-width: 320px; padding: 5px;">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-${props.type === 'attack' ? 'skull-crossbones' : 'user'} me-2" style="color: ${markerColor}; font-size: 1.2rem;"></i>
                        <strong style="color: ${markerColor}; font-size: 1.1rem;">${props.title}</strong>
                    </div>
                    <hr style="margin: 8px 0; border-color: #444;">
                    <div class="mt-2" style="line-height: 1.6;">
                        <div><i class="fas fa-ip me-2" style="width: 20px;"></i> <strong>IP:</strong> ${props.ip}</div>
                        <div><i class="fas fa-map-marker-alt me-2" style="width: 20px;"></i> <strong>Country:</strong> ${props.country || 'Unknown'}</div>
                        <div><i class="fas fa-clock me-2" style="width: 20px;"></i> <strong>Time:</strong> ${props.timestamp || 'Unknown'}</div>
                        ${props.type === 'attack' ? 
                            `<div><i class="fas fa-bug me-2" style="width: 20px;"></i> <strong>Type:</strong> ${props.attack_type || 'Unknown'}</div>
                             <div><i class="fas fa-exclamation-triangle me-2" style="width: 20px;"></i> <strong>Severity:</strong> <span class="badge bg-${props.severity === 'Critical' ? 'danger' : (props.severity === 'High' ? 'warning' : 'info')}">${props.severity}</span></div>
                             <div><i class="fas fa-hashtag me-2" style="width: 20px;"></i> <strong>Count:</strong> ${props.count || 1}</div>` : 
                            `<div><i class="fas fa-network-wired me-2" style="width: 20px;"></i> <strong>ISP:</strong> ${props.isp || 'Unknown'}</div>
                             <div><i class="fas fa-building me-2" style="width: 20px;"></i> <strong>ASN:</strong> ${props.asn || 'Unknown'}</div>
                             ${props.vpn ? '<div class="text-warning"><i class="fas fa-shield-alt me-2" style="width: 20px;"></i> ⚠️ VPN Detected</div>' : ''}
                             ${props.proxy ? '<div class="text-warning"><i class="fas fa-user-secret me-2" style="width: 20px;"></i> ⚠️ Proxy Detected</div>' : ''}`
                        }
                    </div>
                    <hr style="margin: 8px 0; border-color: #444;">
                    <small class="text-muted d-block text-center">Click for detailed information</small>
                </div>
            `;
            
            marker.bindPopup(popupContent, { 
                maxWidth: 350,
                className: 'custom-popup'
            });
            
            marker.on('click', function() {
                showIPDetails(props, [coords[1], coords[0]]);
            });
            
            // Store feature data in marker for later reference
            marker.feature = feature;
            
            // Add to appropriate layer
            if (props.type === 'visitor') {
                visitorLayer.addLayer(marker);
            } else {
                attackLayer.addLayer(marker);
            }
            
            markers.addLayer(marker);
        });
        
        // Add layers to cluster
        markerCluster.addLayer(visitorLayer);
        markerCluster.addLayer(attackLayer);
        
        // Update map stats
        updateMapStats();
    }

    // Update map statistics display
    function updateMapStats() {
        const visitorCount = visitorLayer.getLayers().length;
        const attackCount = attackLayer.getLayers().length;
        
        $('.map-stats').html(`
            <h6 class="mb-2"><i class="fas fa-chart-simple me-1"></i> Live Statistics</h6>
            <div class="d-flex justify-content-between">
                <small class="text-muted"><i class="fas fa-user me-1"></i> Visitors:</small>
                <small><span class="text-success fw-bold">${visitorCount}</span></small>
            </div>
            <div class="d-flex justify-content-between">
                <small class="text-muted"><i class="fas fa-bug me-1"></i> Attacks:</small>
                <small><span class="text-danger fw-bold">${attackCount}</span></small>
            </div>
            <div class="d-flex justify-content-between">
                <small class="text-muted"><i class="fas fa-flag me-1"></i> Countries:</small>
                <small><span class="text-info fw-bold">${geoJsonData.stats.unique_countries}</span></small>
            </div>
            <div class="d-flex justify-content-between">
                <small class="text-muted"><i class="fas fa-clock me-1"></i> Updated:</small>
                <small>${new Date().toLocaleTimeString()}</small>
            </div>
            <hr class="my-2 opacity-25">
            <div class="d-flex justify-content-between">
                <small class="text-muted"><i class="fas fa-shield me-1"></i> Protected:</small>
                <small><span class="text-success">Active</span></small>
            </div>
        `);
    }

    // Show IP details modal
    function showIPDetails(props, coordinates) {
        $('#modalIp').text(props.ip);
        $('#modalCountry').text(props.country || 'Unknown');
        $('#modalCoords').text(coordinates ? coordinates.reverse().join(', ') : 'Not available');
        $('#modalLastSeen').text(props.timestamp || 'Unknown');
        $('#modalISP').text(props.isp || props.asn ? `${props.isp || 'Unknown'} (${props.asn || 'Unknown'})` : 'Unknown');
        $('#modalFingerprint').text(props.fingerprint || 'Not available');
        $('#modalBlockBtn').attr('href', 'block-list.php?ip=' + encodeURIComponent(props.ip) + '&website_id=<?php echo $website_id; ?>');
        $('#modalWhoisBtn').attr('href', 'https://whois.domaintools.com/' + props.ip);
        $('#modalIPDetailsBtn').attr('href', 'https://ipinfo.io/' + props.ip);
        
        // Initialize modal map if not exists
        if (!modalMap) {
            modalMap = L.map('modalMap').setView(coordinates || [0, 0], coordinates ? 10 : 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; OpenStreetMap, CartoDB'
            }).addTo(modalMap);
        } else {
            modalMap.setView(coordinates || [0, 0], coordinates ? 10 : 2);
            modalMap.eachLayer(layer => {
                if (layer instanceof L.Marker) {
                    modalMap.removeLayer(layer);
                }
            });
        }
        
        if (coordinates) {
            let markerColor = props.type === 'attack' ? 
                (props.severity === 'Critical' ? '#dc3545' : 
                 props.severity === 'High' ? '#fd7e14' : 
                 props.severity === 'Medium' ? '#ffc107' : '#0dcaf0') : 
                (props.vpn || props.proxy ? '#6c757d' : '#28a745');
                
            L.marker(coordinates, {
                icon: L.divIcon({
                    html: `<div style="background-color: ${markerColor}; width: 20px; height: 20px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 15px ${markerColor};"></div>`,
                    iconSize: [26, 26],
                    iconAnchor: [13, 13]
                })
            }).addTo(modalMap)
                .bindPopup(`<strong>${props.ip}</strong><br>${props.country}<br>${props.type === 'attack' ? props.attack_type : 'Visitor'}`)
                .openPopup();
        }
        
        // Show attack details if available
        if (props.type === 'attack') {
            $('#modalAttackDetails').html(`
                <div class="alert alert-${props.severity === 'Critical' ? 'danger' : (props.severity === 'High' ? 'warning' : 'info')}">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-skull-crossbones me-2 fs-5"></i>
                        <strong>Attack Details</strong>
                    </div>
                    <div class="row">
                        <div class="col-6">
                            <small>Type: ${props.attack_type}</small>
                        </div>
                        <div class="col-6">
                            <small>Severity: <span class="badge bg-${props.severity === 'Critical' ? 'danger' : 
                                props.severity === 'High' ? 'warning' : 
                                props.severity === 'Medium' ? 'info' : 'secondary'}">${props.severity}</span></small>
                        </div>
                        <div class="col-6">
                            <small>Attack Count: ${props.count}</small>
                        </div>
                        <div class="col-12 mt-2">
                            <small>Request URL: <code class="text-light">${props.request_url || 'N/A'}</code></small>
                        </div>
                    </div>
                </div>
            `);
        } else {
            $('#modalAttackDetails').html(`
                <div class="alert alert-info">
                    <div class="d-flex align-items-center mb-2">
                        <i class="fas fa-user me-2 fs-5"></i>
                        <strong>Visitor Information</strong>
                    </div>
                    <div class="row">
                        <div class="col-6">
                            <small>Type: ${props.vpn ? 'VPN User' : props.proxy ? 'Proxy User' : 'Normal Visitor'}</small>
                        </div>
                        <div class="col-6">
                            <small>Fingerprint: <code>${props.fingerprint || 'Unknown'}</code></small>
                        </div>
                    </div>
                    ${props.vpn ? '<div class="mt-2 text-warning"><i class="fas fa-shield-alt me-1"></i> ⚠️ VPN Detected</div>' : ''}
                    ${props.proxy ? '<div class="mt-2 text-warning"><i class="fas fa-user-secret me-1"></i> ⚠️ Proxy Detected</div>' : ''}
                </div>
            `);
        }
        
        new bootstrap.Modal(document.getElementById('attackDetailsModal')).show();
    }

    // Focus map on specific IP
    function focusOnIP(ip) {
        let found = false;
        
        markers.eachLayer(function(marker) {
            const latLng = marker.getLatLng();
            const popup = marker.getPopup();
            const content = popup ? popup.getContent() : '';
            
            // Check if marker's popup contains this IP
            if (content && content.includes(ip)) {
                map.setView(latLng, 12);
                marker.openPopup();
                
                // Highlight marker with temporary animation
                const originalIcon = marker.options.icon;
                const highlightIcon = L.divIcon({
                    className: 'attack-marker',
                    html: `<div style="background-color: #ff00ff; width: 30px; height: 30px; border-radius: 50%; border: 4px solid white; box-shadow: 0 0 30px #ff00ff; animation: pulse 1s infinite;"></div>`,
                    iconSize: [38, 38],
                    iconAnchor: [19, 19]
                });
                
                marker.setIcon(highlightIcon);
                found = true;
                
                // Reset after 3 seconds
                setTimeout(() => {
                    marker.setIcon(originalIcon);
                }, 3000);
            }
        });
        
        if (!found) {
            alert('IP not found on map');
        }
    }

    // Reset map view
    function resetMapView() {
        map.setView([20, 0], 2);
    }

    // Export map data
    function exportMapData() {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(geoJsonData, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `security-map-data-${new Date().toISOString().split('T')[0]}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    }

    // Refresh map data by reloading page
    function refreshMapData() {
        const btn = event.target;
        const originalHTML = btn.innerHTML;
        
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        btn.disabled = true;
        
        setTimeout(() => {
            window.location.reload();
        }, 500);
    }

    // Main initialization
    $(document).ready(function() {
        // Initialize map
        initMap();
        
        // Layer toggle controls
        $('#showVisitors').change(function() {
            if ($(this).is(':checked')) {
                markerCluster.addLayer(visitorLayer);
            } else {
                markerCluster.removeLayer(visitorLayer);
            }
            updateMapStats();
        });
        
        $('#showAttacks').change(function() {
            if ($(this).is(':checked')) {
                markerCluster.addLayer(attackLayer);
            } else {
                markerCluster.removeLayer(attackLayer);
            }
            updateMapStats();
        });
        
        $('#clusterMarkers').change(function() {
            if ($(this).is(':checked')) {
                map.removeLayer(markers);
                map.addLayer(markerCluster);
                markerCluster.addLayer(visitorLayer);
                markerCluster.addLayer(attackLayer);
            } else {
                map.removeLayer(markerCluster);
                markers.addLayer(visitorLayer);
                markers.addLayer(attackLayer);
                map.addLayer(markers);
            }
        });
        
        // Sidebar toggle for mobile
        $('#sidebarToggle').click(function() {
            $('#sidebar').toggleClass('active');
        });
        
        // Cleanup modal map on close
        $('#attackDetailsModal').on('hidden.bs.modal', function() {
            if (modalMap) {
                modalMap.remove();
                modalMap = null;
            }
        });
        
        // Auto-refresh every 60 seconds (optional - can be disabled)
        // setTimeout(function(){
        //     location.reload();
        // }, 60000);
        
        // Add window resize handler to fix map display
        $(window).on('resize', function() {
            if (map) {
                map.invalidateSize();
            }
        });
    });

    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.7; }
            100% { transform: scale(1); opacity: 1; }
        }
        
        .visitor-marker, .attack-marker {
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .visitor-marker:hover, .attack-marker:hover {
            transform: scale(1.2);
            z-index: 1000;
            filter: drop-shadow(0 0 10px currentColor);
        }
        
        .leaflet-popup-content {
            margin: 15px !important;
        }
        
        .leaflet-control-attribution {
            background: rgba(0,0,0,0.5) !important;
            color: #999 !important;
            font-size: 9px !important;
            padding: 2px 5px !important;
            border-radius: 3px !important;
        }
        
        .leaflet-control-attribution a {
            color: #ccc !important;
        }
        
        .leaflet-control-zoom {
            border: none !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3) !important;
        }
        
        .leaflet-control-zoom a {
            background-color: #1e1e1e !important;
            color: #fff !important;
            border: 1px solid #444 !important;
        }
        
        .leaflet-control-zoom a:hover {
            background-color: #2d2d2d !important;
        }
        
        .leaflet-control-scale-line {
            background: rgba(30,30,30,0.8) !important;
            border: 1px solid #444 !important;
            color: #ccc !important;
        }
    `;
    document.head.appendChild(style);
    </script>
</body>
</html>