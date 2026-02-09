<?php
// summery.php - Dashboard with OpenStreetMap
require_once '../includes/header.php';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: login.php");
    exit();
}

// Get current user and website IDs from session or database
$userId = $_SESSION['user_id'] ?? 0;
$websiteId = $_SESSION['website_id'] ?? 1;

// If website_id not in session, get the user's default website
if (!$websiteId || $websiteId == 0) {
    try {
        $defaultWebsite = $pdo->prepare("SELECT id FROM websites WHERE user_id = ? ORDER BY id ASC LIMIT 1");
        $defaultWebsite->execute([$userId]);
        $website = $defaultWebsite->fetch();
        $websiteId = $website['id'] ?? 1;
        $_SESSION['website_id'] = $websiteId;
    } catch (Exception $e) {
        $websiteId = 1;
    }
}

// Get user details
$userDetails = [];
try {
    $userQuery = $pdo->prepare("SELECT username, email, full_name, role FROM users WHERE id = ?");
    $userQuery->execute([$userId]);
    $userDetails = $userQuery->fetch();
} catch (Exception $e) {
    $userDetails = ['username' => 'User', 'email' => '', 'full_name' => '', 'role' => 'viewer'];
}

// Get website details
$websiteDetails = [];
try {
    $websiteQuery = $pdo->prepare("SELECT site_name, domain, status FROM websites WHERE id = ? AND user_id = ?");
    $websiteQuery->execute([$websiteId, $userId]);
    $websiteDetails = $websiteQuery->fetch();
} catch (Exception $e) {
    $websiteDetails = ['site_name' => 'Default Website', 'domain' => 'unknown', 'status' => 'active'];
}

// Get statistics
try {
    // Attack statistics (last 7 days)
    $attackStats = $pdo->prepare("
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
    $attackStats->execute([$userId, $websiteId]);
    $attackData = $attackStats->fetch() ?? ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    
    // Total visitors with geo data (last 7 days)
    $visitorStats = $pdo->prepare("
        SELECT 
            COUNT(*) as total_visitors,
            COUNT(DISTINCT ip) as unique_visitors,
            COUNT(CASE WHEN is_vpn = 1 THEN 1 END) as vpn_users,
            COUNT(CASE WHEN is_proxy = 1 THEN 1 END) as proxy_users
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $visitorStats->execute([$userId, $websiteId]);
    $visitorData = $visitorStats->fetch() ?? ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    
    // Get recent visitors with geo data for map
    $recentVisitors = $pdo->prepare("
        SELECT 
            ip, 
            real_ip, 
            country, 
            latitude, 
            longitude,
            user_agent,
            timestamp,
            is_vpn,
            is_proxy
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND latitude IS NOT NULL 
        AND longitude IS NOT NULL
        ORDER BY timestamp DESC 
        LIMIT 50
    ");
    $recentVisitors->execute([$userId, $websiteId]);
    $visitorGeoData = $recentVisitors->fetchAll();
    
    // Get attack IPs with geo data for map
    $attackGeoData = $pdo->prepare("
        SELECT 
            al.ip_address as ip,
            l.country,
            l.latitude,
            l.longitude,
            al.attack_type,
            al.severity,
            COUNT(*) as attack_count
        FROM attack_logs al
        LEFT JOIN logs l ON al.ip_address = l.ip 
            AND l.user_id = al.user_id 
            AND l.website_id = al.website_id
        WHERE al.user_id = ? AND al.website_id = ?
        AND al.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        AND l.latitude IS NOT NULL 
        AND l.longitude IS NOT NULL
        GROUP BY al.ip_address, l.country, l.latitude, l.longitude, al.attack_type, al.severity
        ORDER BY attack_count DESC
        LIMIT 50
    ");
    $attackGeoData->execute([$userId, $websiteId]);
    $attackLocations = $attackGeoData->fetchAll();
    
    // Blocked IPs (active)
    $blockedIps = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE user_id = ? AND website_id = ?
        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
    ");
    $blockedIps->execute([$userId, $websiteId]);
    $blockedData = $blockedIps->fetch() ?? ['count' => 0];
    
    // Recent attacks (last 10)
    $recentAttacks = $pdo->prepare("
        SELECT attack_type, severity, ip_address, timestamp, request_url 
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $recentAttacks->execute([$userId, $websiteId]);
    $recentData = $recentAttacks->fetchAll();
    
    // Top attacking countries
    $topCountries = $pdo->prepare("
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
    $topCountries->execute([$userId, $websiteId]);
    $countryData = $topCountries->fetchAll();
    
} catch (PDOException $e) {
    // Initialize empty data
    $attackData = ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    $visitorData = ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    $visitorGeoData = [];
    $attackLocations = [];
    $blockedData = ['count' => 0];
    $recentData = [];
    $countryData = [];
}

// Prepare GeoJSON data for map
$visitorFeatures = [];
$attackFeatures = [];

foreach ($visitorGeoData as $visitor) {
    if (!empty($visitor['latitude']) && !empty($visitor['longitude'])) {
        $visitorFeatures[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [(float)$visitor['longitude'], (float)$visitor['latitude']]
            ],
            'properties' => [
                'type' => 'visitor',
                'ip' => $visitor['ip'],
                'country' => $visitor['country'] ?? 'Unknown',
                'timestamp' => date('Y-m-d H:i', strtotime($visitor['timestamp'])),
                'vpn' => (bool)$visitor['is_vpn'],
                'proxy' => (bool)$visitor['is_proxy'],
                'title' => "Visitor from " . ($visitor['country'] ?? 'Unknown'),
                'description' => "IP: " . $visitor['ip'] . "<br>Time: " . date('H:i', strtotime($visitor['timestamp']))
            ]
        ];
    }
}

foreach ($attackLocations as $attack) {
    if (!empty($attack['latitude']) && !empty($attack['longitude'])) {
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
                'country' => $attack['country'] ?? 'Unknown',
                'attack_type' => $attack['attack_type'],
                'severity' => $attack['severity'],
                'count' => $attack['attack_count'],
                'color' => $severityColor,
                'title' => $attack['attack_type'] . " Attack",
                'description' => "IP: " . $attack['ip'] . "<br>Type: " . $attack['attack_type'] . 
                               "<br>Severity: " . $attack['severity'] . "<br>Count: " . $attack['attack_count']
            ]
        ];
    }
}

// Combine features
$geoJsonData = [
    'type' => 'FeatureCollection',
    'features' => array_merge($visitorFeatures, $attackFeatures)
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Security Monitoring</title>
    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <!-- Leaflet MarkerCluster CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css" />
    <style>
        #securityMap {
            height: 400px;
            width: 100%;
            border-radius: 8px;
            margin-bottom: 1rem;
            z-index: 1;
        }
        .map-container {
            position: relative;
        }
        .map-legend {
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 5px;
            z-index: 1000;
            font-size: 12px;
        }
        .map-legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }
        .map-legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 50%;
        }
        .attack-marker {
            filter: drop-shadow(0 0 2px rgba(0,0,0,0.5));
        }
        .map-controls {
            position: absolute;
            top: 10px;
            right: 10px;
            z-index: 1000;
            background: rgba(0, 0, 0, 0.8);
            padding: 8px;
            border-radius: 5px;
        }
        .map-tooltip {
            font-family: monospace;
            font-size: 12px;
        }
        .country-flag {
            width: 16px;
            height: 12px;
            display: inline-block;
            margin-right: 5px;
            background-size: cover;
        }
    </style>
</head>
<body>
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-tachometer-alt me-2"></i>Security Dashboard</h2>
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
                            <?php
                            try {
                                $userWebsites = $pdo->prepare("SELECT id, site_name, domain FROM websites WHERE user_id = ? ORDER BY site_name");
                                $userWebsites->execute([$userId]);
                                $websites = $userWebsites->fetchAll();
                                
                                foreach ($websites as $website) {
                                    $active = ($website['id'] == $websiteId) ? 'active' : '';
                                    echo "<li>
                                            <a class='dropdown-item $active' href='?switch_website={$website['id']}'>
                                                {$website['site_name']} <small class='text-muted'>({$website['domain']})</small>
                                            </a>
                                          </li>";
                                }
                            } catch (Exception $e) {
                                echo "<li><a class='dropdown-item' href='#'>No websites found</a></li>";
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Security Map Section -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-map-marked-alt me-2"></i>Security Threat Map</h5>
                <div>
                    <button class="btn btn-sm btn-outline-secondary" onclick="resetMapView()">
                        <i class="fas fa-sync-alt"></i> Reset View
                    </button>
                    <button class="btn btn-sm btn-outline-info ms-1" onclick="exportMapData()">
                        <i class="fas fa-download"></i> Export Data
                    </button>
                </div>
            </div>
            
            <div class="map-container">
                <div id="securityMap"></div>
                
                <div class="map-controls">
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="showVisitors" checked>
                        <label class="form-check-label" for="showVisitors">Visitors</label>
                    </div>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="showAttacks" checked>
                        <label class="form-check-label" for="showAttacks">Attacks</label>
                    </div>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="clusterMarkers" checked>
                        <label class="form-check-label" for="clusterMarkers">Cluster</label>
                    </div>
                </div>
                
                <div class="map-legend">
                    <div class="map-legend-item">
                        <div class="map-legend-color" style="background-color: #28a745;"></div>
                        <span>Normal Visitors</span>
                    </div>
                    <div class="map-legend-item">
                        <div class="map-legend-color" style="background-color: #dc3545;"></div>
                        <span>Critical Attacks</span>
                    </div>
                    <div class="map-legend-item">
                        <div class="map-legend-color" style="background-color: #fd7e14;"></div>
                        <span>High Severity</span>
                    </div>
                    <div class="map-legend-item">
                        <div class="map-legend-color" style="background-color: #ffc107;"></div>
                        <span>Medium Severity</span>
                    </div>
                </div>
            </div>
            
            <div class="row mt-3">
                <div class="col-md-6">
                    <div class="card bg-dark border-secondary">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Total Locations Mapped:</small>
                                <small><strong><?php echo count($visitorFeatures) + count($attackFeatures); ?></strong></small>
                            </div>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Visitor Locations:</small>
                                <small><span class="text-success"><?php echo count($visitorFeatures); ?></span></small>
                            </div>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Attack Locations:</small>
                                <small><span class="text-danger"><?php echo count($attackFeatures); ?></span></small>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card bg-dark border-secondary">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Map Coverage:</small>
                                <small>
                                    <?php 
                                    $uniqueCountries = array_unique(array_merge(
                                        array_column($visitorGeoData, 'country'),
                                        array_column($attackLocations, 'country')
                                    ));
                                    echo count(array_filter($uniqueCountries, function($c) { return $c && $c != 'Unknown'; }));
                                    ?> countries
                                </small>
                            </div>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">Last Update:</small>
                                <small><?php echo date('H:i:s'); ?></small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Statistics Cards -->
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
                    <div class="stat-number text-info">
                        <?php
                        $securityScore = 100;
                        $totalAttacks = $attackData['total_attacks'] ?? 0;
                        $uniqueVisitors = max(1, $visitorData['unique_visitors'] ?? 1);
                        
                        if ($totalAttacks > 0) {
                            $attackRatio = ($totalAttacks / $uniqueVisitors) * 100;
                            $securityScore = max(0, 100 - min($attackRatio, 50));
                        }
                        echo round($securityScore);
                        ?>%
                    </div>
                    <div class="stat-change <?php echo $securityScore >= 80 ? 'positive' : ($securityScore >= 60 ? '' : 'negative'); ?>">
                        <i class="fas fa-<?php echo $securityScore >= 80 ? 'shield-alt' : 'exclamation-triangle'; ?>"></i>
                        <?php echo $securityScore >= 80 ? 'Excellent' : ($securityScore >= 60 ? 'Good' : 'Needs attention'); ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Attacks & Top Countries -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Attacks</h5>
                <a href="web-security.php?website_id=<?php echo $websiteId; ?>" class="btn btn-sm btn-outline-primary">
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
                                $countryQuery = $pdo->prepare("SELECT country FROM logs WHERE ip = ? AND user_id = ? AND website_id = ? ORDER BY timestamp DESC LIMIT 1");
                                $countryQuery->execute([$attack['ip_address'], $userId, $websiteId]);
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
                                        <a href="block-list.php?ip=<?php echo urlencode($attack['ip_address'] ?? ''); ?>&website_id=<?php echo $websiteId; ?>" 
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

    <!-- Top Attacking Countries & Quick Actions -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-flag me-2"></i>Top Attacking Countries</h5>
            
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
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-bolt me-2"></i>Quick Actions</h6>
                <div class="d-grid gap-2">
                    <a href="geolocation.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                        <i class="fas fa-map me-2"></i> Detailed Geolocation
                    </a>
                    <a href="web-security.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                        <i class="fas fa-bug me-2"></i> Attack Analytics
                    </a>
                    <a href="block-list.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                        <i class="fas fa-ban me-2"></i> IP Management
                    </a>
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
                <h5 class="modal-title">IP Location Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="modalMap" style="height: 300px; width: 100%; border-radius: 5px; margin-bottom: 15px;"></div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">IP Address</label>
                            <div class="form-control bg-dark text-light" id="modalIp"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Country</label>
                            <div class="form-control bg-dark text-light" id="modalCountry"></div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">Coordinates</label>
                            <div class="form-control bg-dark text-light" id="modalCoords"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Last Seen</label>
                            <div class="form-control bg-dark text-light" id="modalLastSeen"></div>
                        </div>
                    </div>
                </div>
                <div id="modalAttackDetails"></div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" class="btn btn-danger" id="modalBlockBtn">
                    <i class="fas fa-ban me-1"></i> Block This IP
                </a>
                <a href="#" class="btn btn-info" id="modalWhoisBtn" target="_blank">
                    <i class="fas fa-search me-1"></i> WHOIS Lookup
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Leaflet JS -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>

<script>
// Map variables
let map;
let markers = L.featureGroup();
let visitorLayer;
let attackLayer;
let markerCluster;

// GeoJSON data from PHP
const geoJsonData = <?php echo json_encode($geoJsonData); ?>;

// Initialize map
function initMap() {
    // Create map centered on world
    map = L.map('securityMap').setView([20, 0], 2);
    
    // Add OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 18
    }).addTo(map);
    
    // Create marker cluster group
    markerCluster = L.markerClusterGroup({
        chunkedLoading: true,
        showCoverageOnHover: false,
        maxClusterRadius: 40
    });
    
    // Create separate layers
    visitorLayer = L.layerGroup();
    attackLayer = L.layerGroup();
    
    // Add markers from GeoJSON
    geoJsonData.features.forEach(function(feature) {
        const coords = feature.geometry.coordinates;
        const props = feature.properties;
        
        let markerColor, markerIcon, markerSize;
        
        if (props.type === 'visitor') {
            markerColor = props.vpn ? '#6c757d' : '#28a745'; // Gray for VPN, green for normal
            markerIcon = L.divIcon({
                className: 'attack-marker',
                html: `<div style="background-color: ${markerColor}; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 5px rgba(0,0,0,0.5);"></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8]
            });
        } else {
            // Attack marker
            markerColor = props.color;
            markerSize = Math.min(20, Math.max(10, 10 + (props.count || 1)));
            markerIcon = L.divIcon({
                className: 'attack-marker',
                html: `<div style="background-color: ${markerColor}; width: ${markerSize}px; height: ${markerSize}px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 10px ${markerColor};"></div>`,
                iconSize: [markerSize + 4, markerSize + 4],
                iconAnchor: [(markerSize + 4) / 2, (markerSize + 4) / 2]
            });
        }
        
        const marker = L.marker([coords[1], coords[0]], { icon: markerIcon });
        
        // Popup content
        const popupContent = `
            <div class="map-tooltip">
                <strong>${props.title}</strong><br>
                <hr style="margin: 5px 0;">
                ${props.description}<br>
                <small class="text-muted">Click for details</small>
            </div>
        `;
        
        marker.bindPopup(popupContent);
        marker.on('click', function() {
            showIPDetails(props);
        });
        
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
    
    // Add cluster to map
    map.addLayer(markerCluster);
    
    // Layer control
    const baseLayers = {
        "OpenStreetMap": L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap'
        })
    };
    
    const overlayLayers = {
        "Visitors": visitorLayer,
        "Attacks": attackLayer,
        "Clustered View": markerCluster
    };
    
    L.control.layers(baseLayers, overlayLayers, { collapsed: false }).addTo(map);
    
    // Add scale
    L.control.scale().addTo(map);
}

// Show IP details modal
function showIPDetails(props) {
    $('#modalIp').text(props.ip);
    $('#modalCountry').text(props.country || 'Unknown');
    $('#modalCoords').text(props.coordinates ? props.coordinates.join(', ') : 'Not available');
    $('#modalLastSeen').text(props.timestamp || 'Unknown');
    $('#modalBlockBtn').attr('href', 'block-list.php?ip=' + encodeURIComponent(props.ip) + '&website_id=<?php echo $websiteId; ?>');
    $('#modalWhoisBtn').attr('href', 'https://whois.domaintools.com/' + props.ip);
    
    // Initialize modal map
    const modalMap = L.map('modalMap').setView([props.coordinates ? props.coordinates[1] : 0, props.coordinates ? props.coordinates[0] : 0], 10);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap'
    }).addTo(modalMap);
    
    if (props.coordinates) {
        L.marker([props.coordinates[1], props.coordinates[0]]).addTo(modalMap)
            .bindPopup(`<strong>${props.ip}</strong><br>${props.country}`)
            .openPopup();
    }
    
    // Show attack details if available
    if (props.type === 'attack') {
        $('#modalAttackDetails').html(`
            <div class="alert alert-${props.severity === 'critical' ? 'danger' : 'warning'}">
                <strong>Attack Details:</strong><br>
                Type: ${props.attack_type}<br>
                Severity: <span class="badge bg-${props.severity === 'critical' ? 'danger' : 'warning'}">${props.severity}</span><br>
                Attack Count: ${props.count}
            </div>
        `);
    } else {
        $('#modalAttackDetails').html('');
    }
    
    new bootstrap.Modal(document.getElementById('attackDetailsModal')).show();
    
    // Cleanup modal map on close
    $('#attackDetailsModal').on('hidden.bs.modal', function() {
        if (modalMap) {
            modalMap.remove();
        }
    });
}

// Focus map on specific IP
function focusOnIP(ip) {
    // Find marker with this IP
    markers.eachLayer(function(marker) {
        const props = marker.feature ? marker.feature.properties : null;
        if (props && props.ip === ip) {
            map.setView(marker.getLatLng(), 10);
            marker.openPopup();
            
            // Highlight marker
            marker.setIcon(L.divIcon({
                className: 'attack-marker',
                html: `<div style="background-color: #ff00ff; width: 20px; height: 20px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 15px #ff00ff; animation: pulse 1s infinite;"></div>`,
                iconSize: [24, 24],
                iconAnchor: [12, 12]
            }));
            
            // Reset after 3 seconds
            setTimeout(() => {
                const originalColor = props.type === 'attack' ? props.color : (props.vpn ? '#6c757d' : '#28a745');
                marker.setIcon(L.divIcon({
                    className: 'attack-marker',
                    html: `<div style="background-color: ${originalColor}; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white;"></div>`,
                    iconSize: [16, 16],
                    iconAnchor: [8, 8]
                }));
            }, 3000);
        }
    });
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
    downloadAnchor.setAttribute("download", "security-map-data-<?php echo date('Y-m-d'); ?>.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
}

// Layer toggles
$(document).ready(function() {
    // Initialize map
    initMap();
    
    // Layer toggle controls
    $('#showVisitors').change(function() {
        if ($(this).is(':checked')) {
            map.addLayer(visitorLayer);
        } else {
            map.removeLayer(visitorLayer);
        }
    });
    
    $('#showAttacks').change(function() {
        if ($(this).is(':checked')) {
            map.addLayer(attackLayer);
        } else {
            map.removeLayer(attackLayer);
        }
    });
    
    $('#clusterMarkers').change(function() {
        if ($(this).is(':checked')) {
            map.removeLayer(markers);
            map.addLayer(markerCluster);
        } else {
            map.removeLayer(markerCluster);
            map.addLayer(markers);
        }
    });
    
    // Auto-refresh map data every 60 seconds
    setInterval(function() {
        $.ajax({
            url: 'api/map-data.php?website_id=<?php echo $websiteId; ?>',
            method: 'GET',
            success: function(data) {
                if (data.success && data.features) {
                    console.log('Map data refreshed');
                    // You could update markers here if needed
                }
            },
            error: function() {
                console.log('Failed to refresh map data');
            }
        });
    }, 60000);
    
    // Handle website switching
    <?php if (isset($_GET['switch_website'])): ?>
        $.ajax({
            url: 'api/switch-website.php',
            method: 'POST',
            data: { website_id: <?php echo intval($_GET['switch_website']); ?> },
            success: function(response) {
                window.location.reload();
            },
            error: function() {
                alert('Failed to switch website');
                window.location.href = window.location.pathname;
            }
        });
    <?php endif; ?>
});

// Add CSS for pulsing animation
const style = document.createElement('style');
style.textContent = `
    @keyframes pulse {
        0% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.2); opacity: 0.7; }
        100% { transform: scale(1); opacity: 1; }
    }
    .leaflet-popup-content {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
`;
document.head.appendChild(style);
</script>

<?php
require_once '../includes/footer.php';
?>