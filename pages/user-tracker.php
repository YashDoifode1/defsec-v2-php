<?php
// user-tracker.php
require_once '../includes/header.php';
require_once '../includes/auth.php';

// Check if user is logged in
if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Get the logged-in user ID from session
$userId = $_SESSION['user_id'] ?? null;
if (!$userId) {
    header("Location: login.php");
    exit();
}

// Get website ID from session or default (assuming user has websites)
$websiteId = $_SESSION['website_id'] ?? 1;

// Get database connection from includes
require_once '../includes/db.php';

// Handle Search Query
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

// Debug mode
$debug = isset($_GET['debug']) ? true : false;

// Base SQL with user & website filter
$sql = "SELECT * FROM logs WHERE user_id = :user_id AND website_id = :website_id";

// Add search conditions - FIXED: Using unique parameter names
$params = [
    ':user_id' => $userId,
    ':website_id' => $websiteId
];

if (!empty($search)) {
    // Create unique parameter names for each LIKE condition
    $searchConditions = [];
    $searchColumns = [
        'ip', 'real_ip', 'country', 'ISP', 'user_agent', 
        'digital_dna', 'city', 'webrtc_ip', 'dns_leak_ip', 
        'screen_resolution', 'timezone', 'language', 
        'reverse_dns', 'ASN'
    ];
    
    $i = 1;
    foreach ($searchColumns as $column) {
        $paramName = ":search{$i}";
        $searchConditions[] = "{$column} LIKE {$paramName}";
        $params[$paramName] = "%{$search}%";
        $i++;
    }
    
    $sql .= " AND (" . implode(" OR ", $searchConditions) . ")";
}

// Add additional filters if present
if (isset($_GET['country']) && !empty($_GET['country'])) {
    $sql .= " AND country = :country";
    $params[':country'] = $_GET['country'];
}

if (isset($_GET['privacy']) && !empty($_GET['privacy'])) {
    if ($_GET['privacy'] == 'vpn') {
        $sql .= " AND is_vpn = 1";
    } elseif ($_GET['privacy'] == 'tor') {
        $sql .= " AND is_tor = 1";
    } elseif ($_GET['privacy'] == 'clean') {
        $sql .= " AND is_vpn = 0 AND is_tor = 0";
    }
}

if (isset($_GET['time_range']) && !empty($_GET['time_range'])) {
    if ($_GET['time_range'] == 'today') {
        $sql .= " AND DATE(timestamp) = CURDATE()";
    } elseif ($_GET['time_range'] == 'week') {
        $sql .= " AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    } elseif ($_GET['time_range'] == 'month') {
        $sql .= " AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
    }
}

$sql .= " ORDER BY id DESC";

// Debug output
if ($debug) {
    echo "<pre>SQL Query: " . htmlspecialchars($sql) . "</pre>";
    echo "<pre>Parameters: ";
    print_r($params);
    echo "</pre>";
}

// Prepare and execute statement
try {
    $stmt = $pdo->prepare($sql);
    
    // Bind parameters
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if ($debug) {
        echo "<pre>Query executed successfully. Found " . count($logs) . " records.</pre>";
    }
} catch (PDOException $e) {
    $logs = [];
    $error = "Database error: " . $e->getMessage();
    error_log($error);
    
    // Show more detailed error in debug mode
    if ($debug) {
        echo "<div class='alert alert-danger'><pre>Error Details: " . htmlspecialchars($e->getMessage()) . "</pre></div>";
        echo "<div class='alert alert-warning'><pre>SQL Query: " . htmlspecialchars($sql) . "</pre></div>";
    }
}

// Get summary statistics
$stats = [
    'total_visitors' => 0,
    'vpn_users' => 0,
    'tor_users' => 0,
    'unique_countries' => [],
    'unique_ips' => []
];

foreach ($logs as $row) {
    $stats['total_visitors']++;
    if (isset($row['is_vpn']) && $row['is_vpn']) $stats['vpn_users']++;
    if (isset($row['is_tor']) && $row['is_tor']) $stats['tor_users']++;
    if (!empty($row['country']) && $row['country'] != 'Unknown') $stats['unique_countries'][$row['country']] = true;
    if (!empty($row['ip'])) $stats['unique_ips'][$row['ip']] = true;
}

$stats['unique_countries_count'] = count($stats['unique_countries']);
$stats['unique_ips_count'] = count($stats['unique_ips']);

// Function to fetch WHOIS information
function fetchWhoisData($ip) {
    if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return ['error' => 'Invalid IP address'];
    }
    
    // Use socket connection to WHOIS servers
    $whoisData = [];
    
    // Determine the appropriate WHOIS server based on IP type
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // For IPv4, use ARIN or RIPE depending on region
        $servers = [
            'whois.arin.net',
            'whois.ripe.net',
            'whois.apnic.net',
            'whois.lacnic.net',
            'whois.afrinic.net'
        ];
    } else {
        // For IPv6, use specific IPv6 WHOIS
        $servers = ['whois.arin.net'];
    }
    
    foreach ($servers as $server) {
        $fp = @fsockopen($server, 43, $errno, $errstr, 10);
        if ($fp) {
            fputs($fp, $ip . "\r\n");
            $response = '';
            while (!feof($fp)) {
                $response .= fgets($fp, 128);
            }
            fclose($fp);
            
            // Parse WHOIS response
            $lines = explode("\n", $response);
            foreach ($lines as $line) {
                if (strpos($line, ':') !== false) {
                    list($key, $value) = explode(':', $line, 2);
                    $key = trim($key);
                    $value = trim($value);
                    
                    if (!empty($value) && !isset($whoisData[$key])) {
                        $whoisData[$key] = $value;
                    }
                }
            }
            
            if (!empty($whoisData)) {
                break;
            }
        }
    }
    
    // If no WHOIS data found, return basic info
    if (empty($whoisData)) {
        $whoisData = [
            'IP Address' => $ip,
            'Network' => 'Unknown',
            'NetRange' => 'Not available',
            'Country' => 'Not available',
            'Status' => 'Active',
            'Last Update' => date('Y-m-d')
        ];
    }
    
    return $whoisData;
}

// Function to fetch location information using ipwho.org API
function fetchLocationData($ip) {
    if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return ['error' => 'Invalid IP address'];
    }
    
    // Use ipwho.org API (free, no API key required)
    $apiUrl = "https://api.ipwho.org/ip/{$ip}?format=json";
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $apiUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (User-Tracker/1.0)'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        
        if (isset($data['ip']) && $data['success'] !== false) {
            $locationData = [
                'ip' => $data['ip'] ?? $ip,
                'success' => $data['success'] ?? true,
                'type' => $data['type'] ?? 'Unknown',
                'continent' => $data['continent'] ?? 'Unknown',
                'continent_code' => $data['continent_code'] ?? 'N/A',
                'country' => $data['country'] ?? 'Unknown',
                'country_code' => $data['country_code'] ?? 'N/A',
                'country_flag' => $data['country_flag'] ?? '',
                'country_capital' => $data['country_capital'] ?? 'Unknown',
                'country_phone' => $data['country_phone'] ?? 'N/A',
                'country_neighbours' => $data['country_neighbours'] ?? 'N/A',
                'region' => $data['region'] ?? 'Unknown',
                'city' => $data['city'] ?? 'Unknown',
                'latitude' => $data['latitude'] ?? '0',
                'longitude' => $data['longitude'] ?? '0',
                'asn' => $data['asn'] ?? 'N/A',
                'org' => $data['org'] ?? 'Unknown',
                'isp' => $data['isp'] ?? 'Unknown',
                'timezone' => $data['timezone'] ?? 'UTC',
                'timezone_name' => $data['timezone_name'] ?? 'UTC',
                'timezone_dstOffset' => $data['timezone_dstOffset'] ?? '0',
                'timezone_gmtOffset' => $data['timezone_gmtOffset'] ?? '0',
                'timezone_gmt' => $data['timezone_gmt'] ?? 'UTC',
                'currency' => $data['currency'] ?? 'USD',
                'currency_code' => $data['currency_code'] ?? 'USD',
                'currency_symbol' => $data['currency_symbol'] ?? '$',
                'currency_rates' => $data['currency_rates'] ?? '1',
                'currency_plural' => $data['currency_plural'] ?? 'dollars',
                'completed_requests' => $data['completed_requests'] ?? 'N/A'
            ];
            
            // Add threat assessment
            if (isset($data['security'])) {
                $locationData['security'] = [
                    'anonymous' => $data['security']['anonymous'] ?? false,
                    'proxy' => $data['security']['proxy'] ?? false,
                    'vpn' => $data['security']['vpn'] ?? false,
                    'tor' => $data['security']['tor'] ?? false,
                    'hosting' => $data['security']['hosting'] ?? false
                ];
            }
            
            return $locationData;
        }
    }
    
    // Fallback: Try ip-api.com if ipwho.org fails
    $fallbackUrl = "http://ip-api.com/json/{$ip}";
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $fallbackUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (User-Tracker/1.0)'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        if (isset($data['status']) && $data['status'] === 'success') {
            return [
                'ip' => $data['query'] ?? $ip,
                'country' => $data['country'] ?? 'Unknown',
                'country_code' => $data['countryCode'] ?? 'N/A',
                'region' => $data['regionName'] ?? 'Unknown',
                'city' => $data['city'] ?? 'Unknown',
                'postal' => $data['zip'] ?? 'N/A',
                'latitude' => $data['lat'] ?? '0',
                'longitude' => $data['lon'] ?? '0',
                'timezone' => $data['timezone'] ?? 'UTC',
                'isp' => $data['isp'] ?? 'Unknown',
                'asn' => $data['as'] ?? 'N/A',
                'org' => $data['org'] ?? 'Unknown'
            ];
        }
    }
    
    // If all APIs fail, return basic info
    return [
        'ip' => $ip,
        'country' => 'Unknown',
        'country_code' => 'N/A',
        'region' => 'Unknown',
        'city' => 'Unknown',
        'latitude' => '0',
        'longitude' => '0',
        'timezone' => 'UTC',
        'isp' => 'Unknown',
        'asn' => 'N/A',
        'org' => 'Unknown',
        'error' => $curlError ?? 'Could not fetch location data'
    ];
}

// Handle AJAX requests for WHOIS and Location
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    if ($_GET['action'] === 'whois' && isset($_GET['ip'])) {
        $ip = $_GET['ip'];
        $whoisData = fetchWhoisData($ip);
        echo json_encode($whoisData);
        exit();
    }
    
    if ($_GET['action'] === 'location' && isset($_GET['ip'])) {
        $ip = $_GET['ip'];
        $locationData = fetchLocationData($ip);
        echo json_encode($locationData);
        exit();
    }
    
    echo json_encode(['error' => 'Invalid action']);
    exit();
}

// Debug link
$debug_link = $debug ? 'user-tracker.php' : 'user-tracker.php?debug=1';
?>

<div class="row g-4 fade-in">
    <!-- Debug Panel (only shown in debug mode) -->
    <?php if ($debug): ?>
    <div class="col-12">
        <div class="dashboard-card alert alert-warning">
            <h5><i class="fas fa-bug me-2"></i>Debug Mode</h5>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>User ID:</strong> <?php echo $userId; ?></p>
                    <p><strong>Website ID:</strong> <?php echo $websiteId; ?></p>
                    <p><strong>Search Term:</strong> <?php echo htmlspecialchars($search); ?></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Records Found:</strong> <?php echo count($logs); ?></p>
                    <p><strong>Connection Status:</strong> <?php echo $pdo ? 'Connected' : 'Not Connected'; ?></p>
                    <a href="<?php echo $debug_link; ?>" class="btn btn-sm btn-danger">
                        <i class="fas fa-times me-1"></i> Exit Debug Mode
                    </a>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-user-shield me-2"></i>User Tracking & Fingerprinting</h2>
                <p class="text-muted mb-0">Monitor and analyze user activities with digital fingerprinting</p>
            </div>
            <div>
                <button class="btn btn-outline-primary" onclick="refreshData()">
                    <i class="fas fa-sync-alt me-2"></i>Refresh
                </button>
                <?php if (!$debug): ?>
                <a href="<?php echo $debug_link; ?>" class="btn btn-outline-warning ms-2" title="Debug Mode">
                    <i class="fas fa-bug me-1"></i> Debug
                </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Search Bar -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-search me-2"></i>Search Users</h5>
                <div class="d-flex align-items-center">
                    <span class="badge bg-primary me-3"><?php echo count($logs); ?> Records</span>
                    <span class="badge bg-info">Search across IP, Country, ISP, User Agent, and more</span>
                </div>
            </div>
            
            <form method="GET" class="row g-3">
                <input type="hidden" name="debug" value="<?php echo $debug ? '1' : '0'; ?>">
                <div class="col-md-10">
                    <div class="input-group">
                        <span class="input-group-text">
                            <i class="fas fa-search"></i>
                        </span>
                        <input type="text" class="form-control" name="search" 
                               placeholder="Search IP, ISP, User Agent, Country, City, Screen Resolution, Timezone..." 
                               value="<?php echo htmlspecialchars($search); ?>">
                    </div>
                    <div class="form-text text-muted mt-1">
                        <i class="fas fa-info-circle me-1"></i>
                        Search across: IP address, ISP provider, Country, City, User Agent, Screen Resolution, Timezone, Digital Fingerprint
                    </div>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-search me-2"></i>Search
                    </button>
                </div>
            </form>
            
            <?php if (!empty($search)): ?>
                <div class="mt-3">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        Showing results for: <strong><?php echo htmlspecialchars($search); ?></strong>
                        <a href="user-tracker.php<?php echo $debug ? '?debug=1' : ''; ?>" class="btn btn-sm btn-outline-danger float-end">
                            <i class="fas fa-times me-1"></i>Clear Search
                        </a>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-primary mb-2">
                <i class="fas fa-users fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['total_visitors']; ?></div>
            <div class="text-muted small">Total Visitors</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-danger mb-2">
                <i class="fas fa-user-secret fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['vpn_users']; ?></div>
            <div class="text-muted small">
                VPN Users
                <?php if ($stats['total_visitors'] > 0): ?>
                    <div class="mt-1">
                        <span class="badge bg-danger">
                            <?php echo round(($stats['vpn_users']/$stats['total_visitors'])*100, 1); ?>%
                        </span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-warning mb-2">
                <i class="fas fa-network-wired fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['tor_users']; ?></div>
            <div class="text-muted small">
                Tor Users
                <?php if ($stats['total_visitors'] > 0): ?>
                    <div class="mt-1">
                        <span class="badge bg-warning">
                            <?php echo round(($stats['tor_users']/$stats['total_visitors'])*100, 1); ?>%
                        </span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-success mb-2">
                <i class="fas fa-globe fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_countries_count']; ?></div>
            <div class="text-muted small">Unique Countries</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-info mb-2">
                <i class="fas fa-desktop fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_ips_count']; ?></div>
            <div class="text-muted small">Unique IPs</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-purple mb-2">
                <i class="fas fa-fingerprint fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo count($logs); ?></div>
            <div class="text-muted small">Digital Fingerprints</div>
        </div>
    </div>

    <!-- Advanced Search Filters -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-filter me-2"></i>Advanced Filters</h5>
            <form method="GET" class="row g-3">
                <input type="hidden" name="search" value="<?php echo htmlspecialchars($search); ?>">
                <input type="hidden" name="debug" value="<?php echo $debug ? '1' : '0'; ?>">
                
                <div class="col-md-3">
                    <label class="form-label">Country</label>
                    <select name="country" class="form-select">
                        <option value="">All Countries</option>
                        <?php
                        // Get unique countries from current results
                        $countries = [];
                        foreach ($logs as $row) {
                            if (!empty($row['country']) && $row['country'] != 'Unknown') {
                                $countries[$row['country']] = true;
                            }
                        }
                        ksort($countries);
                        foreach ($countries as $country => $value): ?>
                            <option value="<?php echo htmlspecialchars($country); ?>"
                                <?php echo isset($_GET['country']) && $_GET['country'] == $country ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($country); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="col-md-3">
                    <label class="form-label">Privacy Status</label>
                    <select name="privacy" class="form-select">
                        <option value="">All Users</option>
                        <option value="vpn" <?php echo isset($_GET['privacy']) && $_GET['privacy'] == 'vpn' ? 'selected' : ''; ?>>VPN Users Only</option>
                        <option value="tor" <?php echo isset($_GET['privacy']) && $_GET['privacy'] == 'tor' ? 'selected' : ''; ?>>Tor Users Only</option>
                        <option value="clean" <?php echo isset($_GET['privacy']) && $_GET['privacy'] == 'clean' ? 'selected' : ''; ?>>Clean Users Only</option>
                    </select>
                </div>
                
                <div class="col-md-3">
                    <label class="form-label">Time Range</label>
                    <select name="time_range" class="form-select">
                        <option value="">All Time</option>
                        <option value="today" <?php echo isset($_GET['time_range']) && $_GET['time_range'] == 'today' ? 'selected' : ''; ?>>Today</option>
                        <option value="week" <?php echo isset($_GET['time_range']) && $_GET['time_range'] == 'week' ? 'selected' : ''; ?>>Last 7 Days</option>
                        <option value="month" <?php echo isset($_GET['time_range']) && $_GET['time_range'] == 'month' ? 'selected' : ''; ?>>Last 30 Days</option>
                    </select>
                </div>
                
                <div class="col-md-3 d-flex align-items-end">
                    <div class="d-grid gap-2 w-100">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-filter me-2"></i>Apply Filters
                        </button>
                        <a href="user-tracker.php<?php echo $debug ? '?debug=1' : ''; ?>" class="btn btn-outline-secondary">
                            <i class="fas fa-times me-2"></i>Reset All
                        </a>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Users Table -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2"></i>User Tracking Logs</h5>
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                        <i class="fas fa-download me-1"></i> Export
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="export.php?type=pdf"><i class="fas fa-file-pdf me-2"></i> PDF</a></li>
                        <li><a class="dropdown-item" href="export.php?type=csv"><i class="fas fa-file-csv me-2"></i> CSV</a></li>
                        <li><a class="dropdown-item" href="export.php?type=json"><i class="fas fa-file-code me-2"></i> JSON</a></li>
                    </ul>
                </div>
            </div>
            
            <?php if (isset($error) && !$debug): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    There was an error loading the data. Please try again.
                    <a href="user-tracker.php?debug=1" class="btn btn-sm btn-outline-warning float-end">
                        <i class="fas fa-bug me-1"></i> Debug
                    </a>
                </div>
            <?php endif; ?>
            
            <?php if (empty($logs) && !empty($search) && !isset($error)): ?>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    No records found for your search criteria. Try a different search term.
                </div>
            <?php endif; ?>
            
            <div class="table-responsive" style="max-height: 600px; overflow-y: auto;">
                <table class="table table-dark table-hover">
                    <thead style="position: sticky; top: 0; background: #2d2d2d; z-index: 1;">
                        <tr>
                            <th>ID</th>
                            <th>IP Route</th>
                            <th>Real IP</th>
                            <th>Country</th>
                            <th>ISP</th>
                            <th>Privacy</th>
                            <th>Screen</th>
                            <th>Browser</th>
                            <th>Fingerprint</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($logs)): ?>
                            <?php foreach ($logs as $row): ?>
                                <?php
                                $privacyBadges = [];
                                if (isset($row['is_vpn']) && $row['is_vpn']) $privacyBadges[] = '<span class="badge bg-danger">VPN</span>';
                                if (isset($row['is_tor']) && $row['is_tor']) $privacyBadges[] = '<span class="badge bg-warning">TOR</span>';
                                if (!empty($row['webrtc_ip']) && $row['webrtc_ip'] != 'Unknown' && isset($row['ip']) && $row['webrtc_ip'] != $row['ip']) {
                                    $privacyBadges[] = '<span class="badge bg-info">WebRTC</span>';
                                }
                                if (!empty($row['dns_leak_ip']) && $row['dns_leak_ip'] != 'Unknown') {
                                    $privacyBadges[] = '<span class="badge bg-info">DNS Leak</span>';
                                }
                                
                                $privacyDisplay = !empty($privacyBadges) ? implode(' ', $privacyBadges) : '<span class="badge bg-success">Clean</span>';
                                
                                // Truncate long text
                                $userAgent = isset($row['user_agent']) ? htmlspecialchars($row['user_agent']) : '';
                                if (strlen($userAgent) > 50) {
                                    $userAgent = substr($userAgent, 0, 50) . '...';
                                }
                                
                                $fingerprint = $row['digital_dna'] ?? '';
                                if (strlen($fingerprint) > 15) {
                                    $fingerprint = substr($fingerprint, 0, 15) . '...';
                                }
                                
                                // Ensure all variables are set
                                $rowId = $row['id'] ?? '';
                                $ip = $row['ip'] ?? '';
                                $realIp = $row['real_ip'] ?? '';
                                $country = $row['country'] ?? 'Unknown';
                                $city = $row['city'] ?? '';
                                $isp = $row['ISP'] ?? 'Unknown';
                                $screenResolution = $row['screen_resolution'] ?? 'N/A';
                                $asn = $row['ASN'] ?? 'N/A';
                                $webrtcIp = $row['webrtc_ip'] ?? 'N/A';
                                $dnsLeakIp = $row['dns_leak_ip'] ?? 'N/A';
                                $port = $row['port'] ?? 'N/A';
                                $reverseDns = $row['reverse_dns'] ?? '';
                                ?>
                                <tr>
                                    <td>
                                        <span class="badge bg-dark">#<?php echo htmlspecialchars($rowId); ?></span>
                                    </td>
                                    <td>
                                        <div>
                                            <code><?php echo htmlspecialchars($ip); ?></code>
                                            <?php if (!empty($reverseDns) && $reverseDns != 'Unknown'): ?>
                                                <br>
                                                <small class="text-muted"><?php echo htmlspecialchars($reverseDns); ?></small>
                                            <?php endif; ?>
                                        </div>
                                        <button class="btn btn-sm btn-link p-0 text-info" 
                                                onclick="toggleDetails('details-<?php echo $rowId; ?>')">
                                            <small><i class="fas fa-chevron-down me-1"></i> Details</small>
                                        </button>
                                        <div id="details-<?php echo $rowId; ?>" class="mt-2 p-2 bg-dark rounded" style="display: none;">
                                            <div class="row g-2">
                                                <div class="col-md-6">
                                                    <small><strong>ASN:</strong> <?php echo htmlspecialchars($asn); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>WebRTC IP:</strong> <?php echo htmlspecialchars($webrtcIp); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>DNS Leak IP:</strong> <?php echo htmlspecialchars($dnsLeakIp); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>Port:</strong> <?php echo htmlspecialchars($port); ?></small>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($realIp); ?></code>
                                    </td>
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <i class="fas fa-globe me-2 text-muted"></i>
                                            <div>
                                                <div><?php echo htmlspecialchars($country); ?></div>
                                                <?php if (!empty($city) && $city != 'Unknown'): ?>
                                                    <small class="text-muted"><?php echo htmlspecialchars($city); ?></small>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($isp); ?></small>
                                    </td>
                                    <td>
                                        <?php echo $privacyDisplay; ?>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($screenResolution); ?></small>
                                    </td>
                                    <td>
                                        <small><?php echo $userAgent; ?></small>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($fingerprint); ?></code>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-outline-info" 
                                                    onclick="fetchWhois('<?php echo htmlspecialchars($ip); ?>')"
                                                    title="Whois Lookup">
                                                <i class="fas fa-info-circle"></i>
                                            </button>
                                            <button class="btn btn-outline-success" 
                                                    onclick="fetchLocation('<?php echo htmlspecialchars($ip); ?>')"
                                                    title="Location Info (ipwho.org)">
                                                <i class="fas fa-map-marker-alt"></i>
                                            </button>
                                            <a href="block-list.php?ip=<?php echo urlencode($ip); ?>" 
                                               class="btn btn-outline-danger"
                                               title="Block IP">
                                                <i class="fas fa-ban"></i>
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="10" class="text-center py-5">
                                    <div class="text-muted">
                                        <i class="fas fa-inbox fa-3x mb-3"></i>
                                        <h5>No user tracking data found</h5>
                                        <small><?php echo !empty($search) ? 'No results found for your search criteria.' : 'Start collecting user data to see tracking information here.'; ?></small>
                                        <?php if (!empty($search) || isset($error)): ?>
                                            <div class="mt-3">
                                                <a href="user-tracker.php<?php echo $debug ? '?debug=1' : ''; ?>" class="btn btn-outline-primary">
                                                    <i class="fas fa-times me-2"></i>Clear Search
                                                </a>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <?php if (!empty($logs)): ?>
                <div class="mt-3 pt-3 border-top">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-chart-bar text-primary me-2"></i>
                                <div>
                                    <div class="small">Total Records</div>
                                    <div class="fw-bold"><?php echo count($logs); ?></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-clock text-warning me-2"></i>
                                <div>
                                    <div class="small">Last Updated</div>
                                    <div class="fw-bold">Just now</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-database text-info me-2"></i>
                                <div>
                                    <div class="small">Database Size</div>
                                    <div class="fw-bold">Active</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

<script>
    // Toggle details visibility
    function toggleDetails(id) {
        const element = document.getElementById(id);
        if (element.style.display === 'block') {
            element.style.display = 'none';
        } else {
            element.style.display = 'block';
        }
    }
    
    // Fetch Whois information
    function fetchWhois(ip) {
    fetch('https://rdap.arin.net/registry/ip/' + ip)
    .then(response => {
        if (!response.ok) {
            throw new Error("RDAP lookup failed");
        }
        return response.json();
    })
    .then(data => {

        let emails = [];
        let phones = [];
        let addresses = [];

        if (data.entities) {
            data.entities.forEach(entity => {
                if (entity.vcardArray && entity.vcardArray[1]) {
                    entity.vcardArray[1].forEach(vcard => {
                        if (vcard[0] === "email") emails.push(vcard[3]);
                        if (vcard[0] === "tel") phones.push(vcard[3]);
                        if (vcard[0] === "adr" && Array.isArray(vcard[3])) {
                            addresses.push(vcard[3].filter(Boolean).join(", "));
                        }
                    });
                }
            });
        }

        Swal.fire({
            title: 'RDAP / Whois Information',
            html: `
                <div style="text-align:left;">
                    <p><strong>IP:</strong> ${ip}</p>
                    <p><strong>Network:</strong> ${data.name || 'N/A'}</p>
                    <p><strong>Handle:</strong> ${data.handle || 'N/A'}</p>
                    <p><strong>Country:</strong> ${data.country || 'N/A'}</p>
                    <p><strong>Start Address:</strong> ${data.startAddress || 'N/A'}</p>
                    <p><strong>End Address:</strong> ${data.endAddress || 'N/A'}</p>
                    <hr>
                    <p><strong>Emails:</strong> ${emails.join("<br>") || 'N/A'}</p>
                    <p><strong>Phones:</strong> ${phones.join("<br>") || 'N/A'}</p>
                    <p><strong>Addresses:</strong> ${addresses.join("<br>") || 'N/A'}</p>
                </div>
            `,
            width: 600,
            confirmButtonText: 'Close'
        });

    })
    .catch(error => {
        Swal.fire('Error', 'Could not fetch RDAP data', 'error');
    });
}
    
    // Fetch location information using ipwho.org API
    function fetchLocation(ip) {
        fetch('http://ip-api.com/json/' + ip)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                Swal.fire({
                    title: 'Location Information',
                    html: `
                        <div style="text-align: left;">
                            <p><strong>IP:</strong> ${data.query}</p>
                            <p><strong>Country:</strong> ${data.country} (${data.countryCode})</p>
                            <p><strong>Region:</strong> ${data.regionName} (${data.region})</p>
                            <p><strong>City:</strong> ${data.city}</p>
                            <p><strong>ZIP:</strong> ${data.zip}</p>
                            <p><strong>ISP:</strong> ${data.isp}</p>
                            <p><strong>Org:</strong> ${data.org}</p>
                            <p><strong>AS:</strong> ${data.as}</p>
                            <p><strong>Lat/Lon:</strong> ${data.lat}, ${data.lon}</p>
                        </div>
                    `,
                    confirmButtonText: 'Close'
                });
            } else {
                Swal.fire('Error', 'Could not fetch location data', 'error');
            }
        })
        .catch(error => Swal.fire('Error', 'Error fetching location data', 'error'));
    }
    
    // Refresh data
    function refreshData() {
        Swal.fire({
            title: 'Refreshing Data...',
            text: 'Please wait while we refresh the tracking data',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    }
    
    // Initialize tooltips
    document.addEventListener('DOMContentLoaded', function() {
        // Enable Bootstrap tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[title]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    });
</script>

<style>
    .swal-wide {
        width: 700px !important;
        max-width: 90vw;
    }
    
    .text-purple {
        color: #6f42c1;
    }
    
    .table-responsive::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    .table-responsive::-webkit-scrollbar-track {
        background: #1e1e1e;
    }
    
    .table-responsive::-webkit-scrollbar-thumb {
        background: #495057;
        border-radius: 4px;
    }
    
    .table-responsive::-webkit-scrollbar-thumb:hover {
        background: #6c757d;
    }
    
    .bg-dark.rounded {
        background-color: #1a1a1a !important;
    }
    
    @media (max-width: 768px) {
        .btn-group-sm .btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
        }
        
        .dashboard-card {
            padding: 15px;
        }
        
        .stat-number {
            font-size: 1.8rem;
        }
    }
</style>

<?php
require_once '../includes/footer.php';
?>