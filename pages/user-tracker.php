<?php
// user-tracker.php
require_once '../includes/header.php';
require_once '../includes/auth.php';
require_once '../includes/db.php';

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

// Get website ID from session or default
$websiteId = $_SESSION['website_id'] ?? 1;

// Make sure $pdo is available
global $pdo;

// Handle Search Query
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

// Debug mode
$debug = isset($_GET['debug']) ? true : false;

// Base SQL with user & website filter
$sql = "SELECT * FROM logs WHERE user_id = :user_id AND website_id = :website_id";

// Add search conditions
$params = [
    ':user_id' => $userId,
    ':website_id' => $websiteId
];

if (!empty($search)) {
    $searchConditions = [];
    // Using your actual column names from the database
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
    } elseif ($_GET['privacy'] == 'proxy') {
        $sql .= " AND is_proxy = 1";
    } elseif ($_GET['privacy'] == 'clean') {
        $sql .= " AND is_vpn = 0 AND is_tor = 0 AND is_proxy = 0";
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
        if (count($logs) > 0) {
            echo "<pre>First record columns: " . print_r(array_keys($logs[0]), true) . "</pre>";
        }
    }
} catch (PDOException $e) {
    $logs = [];
    $error = "Database error: " . $e->getMessage();
    error_log($error);
    
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
    'proxy_users' => 0,
    'unique_countries' => [],
    'unique_cities' => [],
    'unique_ips' => []
];

foreach ($logs as $row) {
    $stats['total_visitors']++;
    if (isset($row['is_vpn']) && $row['is_vpn']) $stats['vpn_users']++;
    if (isset($row['is_tor']) && $row['is_tor']) $stats['tor_users']++;
    if (isset($row['is_proxy']) && $row['is_proxy']) $stats['proxy_users']++;
    if (!empty($row['country']) && $row['country'] != 'Unknown') $stats['unique_countries'][$row['country']] = true;
    if (!empty($row['city']) && $row['city'] != 'Unknown') $stats['unique_cities'][$row['city']] = true;
    if (!empty($row['ip'])) $stats['unique_ips'][$row['ip']] = true;
}

$stats['unique_countries_count'] = count($stats['unique_countries']);
$stats['unique_cities_count'] = count($stats['unique_cities']);
$stats['unique_ips_count'] = count($stats['unique_ips']);

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
                    <p><strong>Connection Status:</strong> <?php echo isset($pdo) ? 'Connected' : 'Not Connected'; ?></p>
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
            <div class="text-info mb-2">
                <i class="fas fa-globe fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_countries_count']; ?></div>
            <div class="text-muted small">Unique Countries</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-success mb-2">
                <i class="fas fa-building fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_cities_count']; ?></div>
            <div class="text-muted small">Unique Cities</div>
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
                        <option value="proxy" <?php echo isset($_GET['privacy']) && $_GET['privacy'] == 'proxy' ? 'selected' : ''; ?>>Proxy Users Only</option>
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
                        <li><a class="dropdown-item" href="#" onclick="exportData('pdf')"><i class="fas fa-file-pdf me-2"></i> PDF</a></li>
                        <li><a class="dropdown-item" href="#" onclick="exportData('csv')"><i class="fas fa-file-csv me-2"></i> CSV</a></li>
                        <li><a class="dropdown-item" href="#" onclick="exportData('json')"><i class="fas fa-file-code me-2"></i> JSON</a></li>
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
                            <th>Location</th>
                            <th>ISP/ASN</th>
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
                                if (isset($row['is_proxy']) && $row['is_proxy']) $privacyBadges[] = '<span class="badge bg-info">Proxy</span>';
                                if (!empty($row['webrtc_ip']) && $row['webrtc_ip'] != 'Unknown' && $row['webrtc_ip'] != $row['ip']) {
                                    $privacyBadges[] = '<span class="badge bg-info">WebRTC Leak</span>';
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
                                
                                // Use correct column names based on your database
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
                                $reverseDns = $row['reverse_dns'] ?? '';
                                $latitude = $row['latitude'] ?? '0';
                                $longitude = $row['longitude'] ?? '0';
                                $timezone = $row['timezone'] ?? 'UTC';
                                $timestamp = $row['timestamp'] ?? '';
                                $userAgentFull = $row['user_agent'] ?? '';
                                $language = $row['language'] ?? 'Unknown';
                                $cookiesEnabled = $row['cookies_enabled'] ?? 'Unknown';
                                $cpuCores = $row['cpu_cores'] ?? 'Unknown';
                                $ram = $row['ram'] ?? 'Unknown';
                                $gpu = $row['gpu'] ?? 'Unknown';
                                $battery = $row['battery'] ?? 'Unknown';
                                $referrer = $row['referrer'] ?? 'Direct';
                                $plugins = $row['plugins'] ?? 'None';
                                ?>
                                <tr>
                                    <td>
                                        <span class="badge bg-dark">#<?php echo htmlspecialchars($rowId); ?></span>
                                        <br>
                                        <small class="text-muted"><?php echo date('H:i', strtotime($timestamp)); ?></small>
                                    </td>
                                    <td>
                                        <div>
                                            <code><?php echo htmlspecialchars($ip); ?></code>
                                            <?php if (!empty($reverseDns) && $reverseDns != 'Unknown' && $reverseDns != 'Lookup failed'): ?>
                                                <br>
                                                <small class="text-muted" title="Reverse DNS"><?php echo htmlspecialchars($reverseDns); ?></small>
                                            <?php endif; ?>
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
                                        <div>
                                            <small><?php echo htmlspecialchars($isp); ?></small>
                                        </div>
                                        <?php if (!empty($asn) && $asn != 'N/A'): ?>
                                            <small class="text-muted"><?php echo htmlspecialchars($asn); ?></small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php echo $privacyDisplay; ?>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($screenResolution); ?></small>
                                    </td>
                                    <td>
                                        <small title="<?php echo htmlspecialchars($userAgentFull); ?>"><?php echo $userAgent; ?></small>
                                    </td>
                                    <td>
                                        <code title="<?php echo htmlspecialchars($row['digital_dna'] ?? ''); ?>"><?php echo htmlspecialchars($fingerprint); ?></code>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-outline-primary" 
                                                    onclick='showLogDetails(<?php echo json_encode([
                                                        'id' => $rowId,
                                                        'timestamp' => $timestamp,
                                                        'ip' => $ip,
                                                        'real_ip' => $realIp,
                                                        'country' => $country,
                                                        'city' => $city,
                                                        'isp' => $isp,
                                                        'asn' => $asn,
                                                        'reverse_dns' => $reverseDns,
                                                        'webrtc_ip' => $webrtcIp,
                                                        'dns_leak_ip' => $dnsLeakIp,
                                                        'user_agent' => $userAgentFull,
                                                        'screen_resolution' => $screenResolution,
                                                        'language' => $language,
                                                        'timezone' => $timezone,
                                                        'cookies_enabled' => $cookiesEnabled,
                                                        'cpu_cores' => $cpuCores,
                                                        'ram' => $ram,
                                                        'gpu' => $gpu,
                                                        'battery' => $battery,
                                                        'referrer' => $referrer,
                                                        'plugins' => $plugins,
                                                        'digital_dna' => $row['digital_dna'] ?? '',
                                                        'is_vpn' => $row['is_vpn'] ?? 0,
                                                        'is_tor' => $row['is_tor'] ?? 0,
                                                        'is_proxy' => $row['is_proxy'] ?? 0,
                                                        'latitude' => $latitude,
                                                        'longitude' => $longitude
                                                    ]); ?>)'
                                                    title="View Full Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="btn btn-outline-info" 
                                                    onclick="fetchWhois('<?php echo htmlspecialchars($ip); ?>')"
                                                    title="RDAP/Whois Lookup">
                                                <i class="fas fa-info-circle"></i>
                                            </button>
                                            <button class="btn btn-outline-success" 
                                                    onclick="fetchLocation('<?php echo htmlspecialchars($ip); ?>')"
                                                    title="Location Info">
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
                                    <div class="fw-bold"><?php echo date('Y-m-d H:i:s'); ?></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-database text-info me-2"></i>
                                <div>
                                    <div class="small">Unique Visitors</div>
                                    <div class="fw-bold"><?php echo $stats['unique_ips_count']; ?></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Log Details Modal -->
<div class="modal fade" id="logDetailsModal" tabindex="-1" aria-labelledby="logDetailsModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title" id="logDetailsModalLabel">
                    <i class="fas fa-user-shield me-2 text-primary"></i>
                    Complete User Tracking Details
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body" id="logDetailsContent">
                <!-- Content will be populated by JavaScript -->
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-3 text-muted">Loading details...</p>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i class="fas fa-times me-2"></i>Close
                </button>
                <button type="button" class="btn btn-danger" id="modalBlockIpBtn">
                    <i class="fas fa-ban me-2"></i>Block IP
                </button>
            </div>
        </div>
    </div>
</div>

<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

<script>
    // Show log details in modal
    function showLogDetails(data) {
        const modal = new bootstrap.Modal(document.getElementById('logDetailsModal'));
        
        // Format privacy badges
        let privacyBadges = '';
        if (data.is_vpn) privacyBadges += '<span class="badge bg-danger me-1">VPN</span>';
        if (data.is_tor) privacyBadges += '<span class="badge bg-warning me-1">TOR</span>';
        if (data.is_proxy) privacyBadges += '<span class="badge bg-info me-1">Proxy</span>';
        if (!privacyBadges) privacyBadges = '<span class="badge bg-success">Clean</span>';
        
        // Format coordinates
        const hasCoordinates = data.latitude && data.longitude && data.latitude != '0' && data.longitude != '0';
        
        // Build modal content
        const content = `
            <div class="row g-4">
                <!-- Basic Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-primary mb-3"><i class="fas fa-info-circle me-2"></i>Basic Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <th style="width: 120px;">Log ID:</th>
                                <td><span class="badge bg-primary">#${data.id}</span></td>
                            </tr>
                            <tr>
                                <th>Timestamp:</th>
                                <td>${data.timestamp}</td>
                            </tr>
                            <tr>
                                <th>Privacy Status:</th>
                                <td>${privacyBadges}</td>
                            </tr>
                            <tr>
                                <th>Digital DNA:</th>
                                <td><code class="text-info" style="word-break: break-all;">${data.digital_dna}</code></td>
                            </tr>
                            <tr>
                                <th>Referrer:</th>
                                <td><small class="text-muted">${data.referrer}</small></td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- IP & Network Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-info mb-3"><i class="fas fa-network-wired me-2"></i>IP & Network Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <th style="width: 120px;">IP Address:</th>
                                <td><code>${data.ip}</code></td>
                            </tr>
                            <tr>
                                <th>Real IP:</th>
                                <td><code>${data.real_ip}</code></td>
                            </tr>
                            <tr>
                                <th>Reverse DNS:</th>
                                <td><small>${data.reverse_dns}</small></td>
                            </tr>
                            <tr>
                                <th>WebRTC IP:</th>
                                <td><code class="${data.webrtc_ip != 'N/A' && data.webrtc_ip != data.ip ? 'text-warning' : ''}">${data.webrtc_ip}</code></td>
                            </tr>
                            <tr>
                                <th>DNS Leak IP:</th>
                                <td><code class="${data.dns_leak_ip != 'N/A' ? 'text-warning' : ''}">${data.dns_leak_ip}</code></td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- Location Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-success mb-3"><i class="fas fa-map-marker-alt me-2"></i>Location Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <th style="width: 120px;">Country:</th>
                                <td>${data.country} ${data.country ? `<span class="flag-icon flag-icon-${data.country.toLowerCase()}"></span>` : ''}</td>
                            </tr>
                            <tr>
                                <th>City:</th>
                                <td>${data.city}</td>
                            </tr>
                            <tr>
                                <th>Timezone:</th>
                                <td>${data.timezone}</td>
                            </tr>
                            <tr>
                                <th>Coordinates:</th>
                                <td>
                                    ${hasCoordinates ? `
                                        ${data.latitude}, ${data.longitude}
                                        <a href="https://www.google.com/maps?q=${data.latitude},${data.longitude}" 
                                           target="_blank" class="btn btn-sm btn-link">
                                            <i class="fas fa-external-link-alt"></i>
                                        </a>
                                    ` : 'Not available'}
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- ISP & ASN Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-warning mb-3"><i class="fas fa-building me-2"></i>ISP & ASN Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <th style="width: 120px;">ISP:</th>
                                <td>${data.isp}</td>
                            </tr>
                            <tr>
                                <th>ASN:</th>
                                <td>${data.asn}</td>
                            </tr>
                            <tr>
                                <th>Language:</th>
                                <td>${data.language}</td>
                            </tr>
                            <tr>
                                <th>Cookies Enabled:</th>
                                <td><span class="badge bg-${data.cookies_enabled == 'Yes' ? 'success' : 'danger'}">${data.cookies_enabled}</span></td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- Device Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-purple mb-3"><i class="fas fa-laptop me-2"></i>Device Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <th style="width: 120px;">Screen Resolution:</th>
                                <td>${data.screen_resolution}</td>
                            </tr>
                            <tr>
                                <th>CPU Cores:</th>
                                <td>${data.cpu_cores}</td>
                            </tr>
                            <tr>
                                <th>RAM:</th>
                                <td>${data.ram}</td>
                            </tr>
                            <tr>
                                <th>GPU:</th>
                                <td><small>${data.gpu}</small></td>
                            </tr>
                            <tr>
                                <th>Battery:</th>
                                <td>${data.battery}</td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- Browser Information -->
                <div class="col-md-6">
                    <div class="bg-dark rounded p-3 border border-secondary">
                        <h6 class="text-danger mb-3"><i class="fas fa-globe me-2"></i>Browser Information</h6>
                        <div class="mb-3">
                            <label class="text-muted small">User Agent:</label>
                            <div class="bg-black p-2 rounded small border border-dark">
                                ${data.user_agent}
                            </div>
                        </div>
                        <div>
                            <label class="text-muted small">Plugins:</label>
                            <div class="bg-black p-2 rounded small border border-dark" style="max-height: 100px; overflow-y: auto;">
                                ${data.plugins}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.getElementById('logDetailsContent').innerHTML = content;
        document.getElementById('modalBlockIpBtn').onclick = function() {
            window.location.href = 'block-list.php?ip=' + encodeURIComponent(data.ip);
        };
        
        modal.show();
    }
    
    // Toggle details visibility (keep for backward compatibility)
    function toggleDetails(id) {
        const element = document.getElementById(id);
        if (element.style.display === 'block') {
            element.style.display = 'none';
        } else {
            element.style.display = 'block';
        }
    }
    
    // Fetch RDAP/Whois information
    function fetchWhois(ip) {
        Swal.fire({
            title: 'Fetching RDAP Data...',
            text: 'Please wait while we retrieve network information',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
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
                    <div style="text-align:left; max-height: 400px; overflow-y: auto;">
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
            Swal.fire('Error', 'Could not fetch RDAP data: ' + error.message, 'error');
        });
    }
    
    // Fetch location information using ip-api.com
    function fetchLocation(ip) {
        Swal.fire({
            title: 'Fetching Location Data...',
            text: 'Please wait while we retrieve location information',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        fetch('http://ip-api.com/json/' + ip + '?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query')
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
                            <p><strong>Timezone:</strong> ${data.timezone}</p>
                            <hr>
                            <p><strong>ISP:</strong> ${data.isp}</p>
                            <p><strong>Organization:</strong> ${data.org}</p>
                            <p><strong>AS:</strong> ${data.as}</p>
                            <p><strong>AS Name:</strong> ${data.asname}</p>
                            <hr>
                            <p><strong>Lat/Lon:</strong> ${data.lat}, ${data.lon}</p>
                        </div>
                    `,
                    width: 600,
                    confirmButtonText: 'Close'
                });
            } else {
                Swal.fire('Error', 'Could not fetch location data: ' + (data.message || 'Unknown error'), 'error');
            }
        })
        .catch(error => Swal.fire('Error', 'Error fetching location data: ' + error.message, 'error'));
    }
    
    // Export data function
    function exportData(type) {
        Swal.fire({
            title: 'Export Data',
            text: 'This feature is under development',
            icon: 'info',
            confirmButtonText: 'OK'
        });
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
    
    .modal-xl {
        max-width: 90vw;
    }
    
    .modal-content {
        border: 1px solid #495057;
    }
    
    .modal-header {
        border-bottom: 1px solid #495057;
    }
    
    .modal-footer {
        border-top: 1px solid #495057;
    }
    
    .table-dark.table-sm td, 
    .table-dark.table-sm th {
        padding: 0.5rem;
        border-color: #495057;
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
        
        .modal-xl {
            max-width: 100%;
            margin: 0.5rem;
        }
    }
</style>

<?php
require_once '../includes/footer.php';
?>