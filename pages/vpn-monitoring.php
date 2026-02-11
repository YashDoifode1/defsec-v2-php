<?php
// vpn-monitoring.php

// Start output buffering to prevent header errors
ob_start();

// Require header after starting output buffer
require_once '../includes/header.php';

// Check if user is logged in
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Set default values for userId and websiteId
$userId = $_SESSION['user_id'] ?? 1;
$websiteId = $_SESSION['website_id'] ?? 1;

date_default_timezone_set('UTC');

// Set Cache-Control headers
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');

/* -------------------------------------------------
   LOAD SETTINGS (SCOPED)
------------------------------------------------- */
$settings = [
    'block_vpn'   => '0',
    'strict_mode' => '0',
    'geo_blocking' => '0'
];

try {
    $stmt = $pdo->prepare("
        SELECT setting_name, setting_value
        FROM settings
        WHERE user_id = ? AND website_id = ?
    ");
    $stmt->execute([$userId, $websiteId]);
    
    while ($row = $stmt->fetch()) {
        $settings[$row['setting_name']] = $row['setting_value'];
    }
    $stmt->closeCursor();
} catch (PDOException $e) {
    // Settings table might not exist or have different structure
    // Try global settings without website_id
    try {
        $stmt = $pdo->prepare("
            SELECT setting_name, setting_value
            FROM settings
            WHERE user_id = ?
        ");
        $stmt->execute([$userId]);
        
        while ($row = $stmt->fetch()) {
            $settings[$row['setting_name']] = $row['setting_value'];
        }
        $stmt->closeCursor();
    } catch (PDOException $e2) {
        // Use defaults
    }
}

/* -------------------------------------------------
   HANDLE POST ACTIONS
------------------------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Generate CSRF token if not exists
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $csrf_token = $_POST['csrf_token'] ?? '';
    $stored_token = $_SESSION['csrf_tokens']['vpn_settings'] ?? '';
    
    if ($csrf_token !== $stored_token || empty($csrf_token)) {
        die('Invalid CSRF token');
    }

    // Toggle country allow/block
    if (isset($_POST['toggle_country'])) {
        $countryCode = strtoupper(trim($_POST['country_code'] ?? ''));

        if ($countryCode !== '') {
            try {
                $stmt = $pdo->prepare("
                    UPDATE allowed_countries
                    SET is_allowed = NOT is_allowed
                    WHERE country_code = ?
                      AND user_id = ?
                      AND website_id = ?
                ");
                $stmt->execute([$countryCode, $userId, $websiteId]);
                $stmt->closeCursor();
                
                // Log the action
                logAction($pdo, $userId, $websiteId, 'TOGGLE_COUNTRY', 
                    "Toggled country status: {$countryCode}");
            } catch (PDOException $e) {
                error_log("Toggle country error: " . $e->getMessage());
            }
        }
    }

    // VPN block toggle
    if (isset($_POST['toggle_vpn_block'])) {
        $value = isset($_POST['block_vpn']) ? '1' : '0';

        try {
            // Check if setting exists
            $checkStmt = $pdo->prepare("
                SELECT id FROM settings 
                WHERE user_id = ? AND website_id = ? AND setting_name = 'block_vpn'
            ");
            $checkStmt->execute([$userId, $websiteId]);
            
            if ($checkStmt->fetch()) {
                // Update existing
                $stmt = $pdo->prepare("
                    UPDATE settings 
                    SET setting_value = ?
                    WHERE user_id = ? AND website_id = ? AND setting_name = 'block_vpn'
                ");
                $stmt->execute([$value, $userId, $websiteId]);
            } else {
                // Insert new
                $stmt = $pdo->prepare("
                    INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                    VALUES (?, ?, 'block_vpn', ?)
                ");
                $stmt->execute([$userId, $websiteId, $value]);
            }
            
            $settings['block_vpn'] = $value;
            $checkStmt->closeCursor();
            $stmt->closeCursor();
            
            logAction($pdo, $userId, $websiteId, 'VPN_SETTING', 
                "VPN blocking set to: {$value}");
        } catch (PDOException $e) {
            error_log("VPN block toggle error: " . $e->getMessage());
        }
    }

    // Strict mode toggle
    if (isset($_POST['toggle_strict_mode'])) {
        $value = isset($_POST['strict_mode']) ? '1' : '0';

        try {
            $checkStmt = $pdo->prepare("
                SELECT id FROM settings 
                WHERE user_id = ? AND website_id = ? AND setting_name = 'strict_mode'
            ");
            $checkStmt->execute([$userId, $websiteId]);
            
            if ($checkStmt->fetch()) {
                $stmt = $pdo->prepare("
                    UPDATE settings 
                    SET setting_value = ?
                    WHERE user_id = ? AND website_id = ? AND setting_name = 'strict_mode'
                ");
                $stmt->execute([$value, $userId, $websiteId]);
            } else {
                $stmt = $pdo->prepare("
                    INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                    VALUES (?, ?, 'strict_mode', ?)
                ");
                $stmt->execute([$userId, $websiteId, $value]);
            }
            
            $settings['strict_mode'] = $value;
            $checkStmt->closeCursor();
            $stmt->closeCursor();
            
            logAction($pdo, $userId, $websiteId, 'STRICT_MODE', 
                "Strict mode set to: {$value}");
        } catch (PDOException $e) {
            error_log("Strict mode toggle error: " . $e->getMessage());
        }
    }

    // Geo-blocking toggle
    if (isset($_POST['toggle_geo_block'])) {
        $value = isset($_POST['geo_blocking']) ? '1' : '0';

        try {
            $checkStmt = $pdo->prepare("
                SELECT id FROM settings 
                WHERE user_id = ? AND website_id = ? AND setting_name = 'geo_blocking'
            ");
            $checkStmt->execute([$userId, $websiteId]);
            
            if ($checkStmt->fetch()) {
                $stmt = $pdo->prepare("
                    UPDATE settings 
                    SET setting_value = ?
                    WHERE user_id = ? AND website_id = ? AND setting_name = 'geo_blocking'
                ");
                $stmt->execute([$value, $userId, $websiteId]);
            } else {
                $stmt = $pdo->prepare("
                    INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                    VALUES (?, ?, 'geo_blocking', ?)
                ");
                $stmt->execute([$userId, $websiteId, $value]);
            }
            
            $settings['geo_blocking'] = $value;
            $checkStmt->closeCursor();
            $stmt->closeCursor();
            
            logAction($pdo, $userId, $websiteId, 'GEO_BLOCKING', 
                "Geo-blocking set to: {$value}");
        } catch (PDOException $e) {
            error_log("Geo-blocking toggle error: " . $e->getMessage());
        }
    }

    // Add or update country
    if (isset($_POST['add_country'])) {
        $code = strtoupper(trim($_POST['new_country_code'] ?? ''));
        $name = trim($_POST['new_country_name'] ?? '');
        $allowed = isset($_POST['new_country_allowed']) ? 1 : 0;

        if ($code && $name) {
            try {
                $checkStmt = $pdo->prepare("
                    SELECT id FROM allowed_countries
                    WHERE user_id = ? AND website_id = ? AND country_code = ?
                ");
                $checkStmt->execute([$userId, $websiteId, $code]);
                
                if ($checkStmt->fetch()) {
                    $stmt = $pdo->prepare("
                        UPDATE allowed_countries
                        SET country_name = ?, is_allowed = ?
                        WHERE user_id = ? AND website_id = ? AND country_code = ?
                    ");
                    $stmt->execute([$name, $allowed, $userId, $websiteId, $code]);
                    $action = "updated";
                } else {
                    $stmt = $pdo->prepare("
                        INSERT INTO allowed_countries
                        (user_id, website_id, country_code, country_name, is_allowed)
                        VALUES (?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([$userId, $websiteId, $code, $name, $allowed]);
                    $action = "added";
                }
                
                $checkStmt->closeCursor();
                $stmt->closeCursor();
                
                logAction($pdo, $userId, $websiteId, 'COUNTRY_ADDED', 
                    "Country {$action}: {$name} ({$code}) - " . ($allowed ? "Allowed" : "Blocked"));
            } catch (PDOException $e) {
                error_log("Add country error: " . $e->getMessage());
            }
        }
    }
    
    // Delete country
    if (isset($_POST['delete_country'])) {
        $countryCode = strtoupper(trim($_POST['country_code'] ?? ''));
        
        if ($countryCode !== '') {
            try {
                $stmt = $pdo->prepare("
                    DELETE FROM allowed_countries
                    WHERE country_code = ?
                      AND user_id = ?
                      AND website_id = ?
                ");
                $stmt->execute([$countryCode, $userId, $websiteId]);
                $stmt->closeCursor();
                
                logAction($pdo, $userId, $websiteId, 'COUNTRY_DELETED', 
                    "Country deleted: {$countryCode}");
            } catch (PDOException $e) {
                error_log("Delete country error: " . $e->getMessage());
            }
        }
    }
    
    // Clear CSRF token after use
    unset($_SESSION['csrf_tokens']['vpn_settings']);
    
    // Redirect to avoid form resubmission
    header("Location: vpn-monitoring.php");
    exit();
}

/* -------------------------------------------------
   FILTER / SORT / PAGINATION
------------------------------------------------- */
$search_country = trim($_GET['search_country'] ?? '');
$status_filter = isset($_GET['status']) ? (array)$_GET['status'] : [];
$sort_column = $_GET['sort'] ?? 'country_name';
$sort_order = strtoupper($_GET['order'] ?? 'ASC');
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 10;

$valid_columns = ['country_code', 'country_name', 'is_allowed'];
if (!in_array($sort_column, $valid_columns)) $sort_column = 'country_name';
if (!in_array($sort_order, ['ASC', 'DESC'])) $sort_order = 'ASC';

/* -------------------------------------------------
   GET STATISTICS FROM DATABASE
------------------------------------------------- */
try {
    // Get countries
    $countryQuery = $pdo->prepare("
        SELECT country_code, country_name, is_allowed
        FROM allowed_countries
        WHERE user_id = ? AND website_id = ?
        ORDER BY country_name
    ");
    $countryQuery->execute([$userId, $websiteId]);
    $countries = $countryQuery->fetchAll();
    $countryQuery->closeCursor();
    
    $total_countries = count($countries);
    $allowed_countries = array_filter($countries, function($c) { return $c['is_allowed']; });
    $blocked_countries = array_filter($countries, function($c) { return !$c['is_allowed']; });
    
    // Get VPN detection stats from logs - FIXED to use correct table name
    $vpnStatsQuery = $pdo->prepare("
        SELECT 
            COUNT(*) as total_blocked,
            COUNT(CASE WHEN DATE(timestamp) = CURDATE() THEN 1 END) as today_blocked
        FROM access_logs 
        WHERE user_id = ? AND website_id = ?
        AND (is_vpn = 1 OR is_proxy = 1)
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $vpnStatsQuery->execute([$userId, $websiteId]);
    $vpn_stats_raw = $vpnStatsQuery->fetch();
    $vpnStatsQuery->closeCursor();
    
    // Get top VPN countries - FIXED to use correct table name
    $topCountriesQuery = $pdo->prepare("
        SELECT country, COUNT(*) as count
        FROM access_logs 
        WHERE user_id = ? AND website_id = ?
        AND (is_vpn = 1 OR is_proxy = 1)
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        AND country IS NOT NULL AND country != 'Unknown'
        GROUP BY country
        ORDER BY count DESC
        LIMIT 5
    ");
    $topCountriesQuery->execute([$userId, $websiteId]);
    $top_countries = $topCountriesQuery->fetchAll();
    $topCountriesQuery->closeCursor();
    
    $vpn_stats = [
        'total_blocked' => $vpn_stats_raw['total_blocked'] ?? 0,
        'today_blocked' => $vpn_stats_raw['today_blocked'] ?? 0,
        'top_countries' => array_column($top_countries, 'country')
    ];
    
} catch (PDOException $e) {
    error_log("Statistics error: " . $e->getMessage());
    $countries = [];
    $total_countries = 0;
    $allowed_countries = [];
    $blocked_countries = [];
    $vpn_stats = [
        'total_blocked' => 0,
        'today_blocked' => 0,
        'top_countries' => []
    ];
}

/* -------------------------------------------------
   GET FILTERED COUNTRIES FOR TABLE
------------------------------------------------- */
try {
    // Build base query
    $sql = "SELECT *
            FROM allowed_countries
            WHERE user_id = ? AND website_id = ?";
    $params = [$userId, $websiteId];
    
    if ($search_country !== '') {
        $sql .= " AND (country_name LIKE ? OR country_code LIKE ?)";
        $params[] = "%$search_country%";
        $params[] = "%$search_country%";
    }
    
    if (!empty($status_filter)) {
        $allowed_conditions = [];
        if (in_array('allowed', $status_filter)) {
            $allowed_conditions[] = "is_allowed = 1";
        }
        if (in_array('blocked', $status_filter)) {
            $allowed_conditions[] = "is_allowed = 0";
        }
        if (!empty($allowed_conditions)) {
            $sql .= " AND (" . implode(' OR ', $allowed_conditions) . ")";
        }
    }
    
    // Add sorting
    $sql .= " ORDER BY $sort_column $sort_order";
    
    // Get total count
    $countStmt = $pdo->prepare(str_replace('*', 'COUNT(*)', $sql));
    $countStmt->execute($params);
    $total_countries_filtered = $countStmt->fetchColumn();
    $countStmt->closeCursor();
    
    // Add pagination
    $sql .= " LIMIT ? OFFSET ?";
    $params[] = $per_page;
    $params[] = ($page - 1) * $per_page;
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $filtered_countries = $stmt->fetchAll();
    $stmt->closeCursor();
    
    $total_pages = ceil($total_countries_filtered / $per_page);
    
} catch (PDOException $e) {
    error_log("Filtered countries error: " . $e->getMessage());
    $filtered_countries = [];
    $total_countries_filtered = 0;
    $total_pages = 1;
}

/* -------------------------------------------------
   HELPER FUNCTIONS
------------------------------------------------- */
function logAction($pdo, $userId, $websiteId, $actionType, $details) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO action_logs (user_id, action_type, details, ip_address, user_agent, website_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $userId,
            $actionType,
            $details,
            $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            $websiteId
        ]);
        $stmt->closeCursor();
    } catch (Exception $e) {
        // Silently fail on logging errors
        error_log("Log action error: " . $e->getMessage());
    }
}

// Generate CSRF token
if (!isset($_SESSION['csrf_tokens'])) {
    $_SESSION['csrf_tokens'] = [];
}
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_tokens']['vpn_settings'] = $csrf_token;
?>

<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-shield-virus me-2 text-primary"></i>VPN & Geo-Restrictions</h2>
                <p class="text-muted mb-0">Manage VPN blocking and country-based access controls</p>
                <small class="text-muted">User ID: <?php echo htmlspecialchars($userId); ?> | Website ID: <?php echo htmlspecialchars($websiteId); ?></small>
            </div>
            <div>
                <div class="d-flex gap-2 align-items-center">
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-chart-line me-1"></i> Quick Stats
                        </button>
                        <ul class="dropdown-menu dropdown-menu-dark">
                            <li><h6 class="dropdown-header">VPN Statistics</h6></li>
                            <li><a class="dropdown-item" href="#">
                                <i class="fas fa-shield-alt text-warning me-2"></i>
                                Blocked Today: <span class="badge bg-warning float-end"><?php echo $vpn_stats['today_blocked']; ?></span>
                            </a></li>
                            <li><a class="dropdown-item" href="#">
                                <i class="fas fa-ban text-danger me-2"></i>
                                Total Blocked: <span class="badge bg-danger float-end"><?php echo $vpn_stats['total_blocked']; ?></span>
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><h6 class="dropdown-header">Country Stats</h6></li>
                            <li><a class="dropdown-item" href="#">
                                <i class="fas fa-check-circle text-success me-2"></i>
                                Allowed: <span class="badge bg-success float-end"><?php echo count($allowed_countries); ?></span>
                            </a></li>
                            <li><a class="dropdown-item" href="#">
                                <i class="fas fa-times-circle text-danger me-2"></i>
                                Blocked: <span class="badge bg-danger float-end"><?php echo count($blocked_countries); ?></span>
                            </a></li>
                        </ul>
                    </div>
                    <a href="geolocation.php" class="btn btn-sm btn-outline-info">
                        <i class="fas fa-map-marker-alt me-1"></i> View Geolocation
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-danger">
                        <i class="fas fa-user-shield"></i>
                    </div>
                    <div class="text-muted mb-1">VPN/Proxy Blocked</div>
                    <div class="stat-number text-danger"><?php echo $vpn_stats['total_blocked']; ?></div>
                    <div class="stat-change <?php echo $vpn_stats['today_blocked'] > 0 ? 'negative' : 'positive'; ?>">
                        <i class="fas fa-<?php echo $vpn_stats['today_blocked'] > 0 ? 'arrow-up' : 'arrow-down'; ?> me-1"></i>
                        <?php echo $vpn_stats['today_blocked']; ?> today
                    </div>
                </div>
                <div class="dropdown">
                    <button class="btn btn-sm btn-link text-muted p-0" data-bs-toggle="dropdown">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-dark">
                        <li><a class="dropdown-item" href="#" onclick="showVPNDetails()">
                            <i class="fas fa-info-circle me-2"></i>View Details
                        </a></li>
                        <li><a class="dropdown-item" href="logs.php?filter=vpn">
                            <i class="fas fa-history me-2"></i>View Logs
                        </a></li>
                    </ul>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted d-block">Top VPN Countries:</small>
                <div class="mt-2">
                    <?php if (!empty($vpn_stats['top_countries'])): ?>
                        <?php foreach ($vpn_stats['top_countries'] as $country): ?>
                            <span class="badge bg-dark me-1 mb-1"><?php echo htmlspecialchars($country); ?></span>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <span class="text-muted small">No recent VPN traffic</span>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-success">
                        <i class="fas fa-globe-americas"></i>
                    </div>
                    <div class="text-muted mb-1">Allowed Countries</div>
                    <div class="stat-number text-success"><?php echo count($allowed_countries); ?></div>
                    <div class="stat-change positive">
                        <i class="fas fa-check-circle me-1"></i>
                        Active whitelist
                    </div>
                </div>
                <span class="badge bg-<?php echo $settings['strict_mode'] == '1' ? 'success' : 'secondary'; ?>">
                    <?php echo $settings['strict_mode'] == '1' ? 'Strict' : 'Normal'; ?>
                </span>
            </div>
            <div class="mt-3">
                <div class="progress" style="height: 6px;">
                    <?php if ($total_countries > 0): ?>
                        <div class="progress-bar bg-success" 
                             style="width: <?php echo (count($allowed_countries) / $total_countries) * 100; ?>%"></div>
                    <?php else: ?>
                        <div class="progress-bar bg-secondary" style="width: 0%"></div>
                    <?php endif; ?>
                </div>
                <small class="text-muted">
                    <?php echo count($allowed_countries); ?> of <?php echo $total_countries; ?> countries allowed
                </small>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-warning">
                        <i class="fas fa-ban"></i>
                    </div>
                    <div class="text-muted mb-1">Blocked Countries</div>
                    <div class="stat-number text-warning"><?php echo count($blocked_countries); ?></div>
                    <div class="stat-change">
                        <i class="fas fa-shield-alt me-1"></i>
                        Active blacklist
                    </div>
                </div>
                <span class="badge bg-<?php echo $settings['geo_blocking'] == '1' ? 'danger' : 'secondary'; ?>">
                    <?php echo $settings['geo_blocking'] == '1' ? 'Active' : 'Inactive'; ?>
                </span>
            </div>
            <div class="mt-3">
                <div class="progress" style="height: 6px;">
                    <?php if ($total_countries > 0): ?>
                        <div class="progress-bar bg-danger" 
                             style="width: <?php echo (count($blocked_countries) / $total_countries) * 100; ?>%"></div>
                    <?php else: ?>
                        <div class="progress-bar bg-secondary" style="width: 0%"></div>
                    <?php endif; ?>
                </div>
                <small class="text-muted">
                    <?php echo count($blocked_countries); ?> of <?php echo $total_countries; ?> countries blocked
                </small>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-info">
                        <i class="fas fa-lock"></i>
                    </div>
                    <div class="text-muted mb-1">Security Level</div>
                    <div class="stat-number text-info">
                        <?php 
                        $security_score = 0;
                        if ($settings['block_vpn'] == '1') $security_score += 30;
                        if ($settings['strict_mode'] == '1') $security_score += 40;
                        if ($settings['geo_blocking'] == '1') $security_score += 30;
                        echo $security_score; 
                        ?>%
                    </div>
                    <div class="stat-change <?php echo $security_score >= 70 ? 'positive' : ($security_score >= 40 ? '' : 'negative'); ?>">
                        <i class="fas fa-<?php echo $security_score >= 70 ? 'shield-alt' : ($security_score >= 40 ? 'shield' : 'exclamation-triangle'); ?> me-1"></i>
                        <?php echo $security_score >= 70 ? 'High' : ($security_score >= 40 ? 'Medium' : 'Low'); ?>
                    </div>
                </div>
                <button class="btn btn-sm btn-link text-info p-0" onclick="showSecurityInfo()">
                    <i class="fas fa-info-circle"></i>
                </button>
            </div>
            <div class="mt-3">
                <div class="d-flex justify-content-between small mb-1">
                    <span>VPN Block</span>
                    <span class="<?php echo $settings['block_vpn'] == '1' ? 'text-success' : 'text-muted'; ?>">
                        <i class="fas fa-<?php echo $settings['block_vpn'] == '1' ? 'check' : 'times'; ?>"></i>
                    </span>
                </div>
                <div class="d-flex justify-content-between small mb-1">
                    <span>Strict Mode</span>
                    <span class="<?php echo $settings['strict_mode'] == '1' ? 'text-warning' : 'text-muted'; ?>">
                        <i class="fas fa-<?php echo $settings['strict_mode'] == '1' ? 'check' : 'times'; ?>"></i>
                    </span>
                </div>
                <div class="d-flex justify-content-between small">
                    <span>Geo-Blocking</span>
                    <span class="<?php echo $settings['geo_blocking'] == '1' ? 'text-danger' : 'text-muted'; ?>">
                        <i class="fas fa-<?php echo $settings['geo_blocking'] == '1' ? 'check' : 'times'; ?>"></i>
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- Security Settings Cards -->
    <div class="col-xl-4">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-network-wired me-2 text-primary"></i>VPN/Proxy Blocking</h5>
                <span class="badge bg-<?php echo $settings['block_vpn'] == '1' ? 'success' : 'secondary'; ?>">
                    <?php echo $settings['block_vpn'] == '1' ? 'Active' : 'Inactive'; ?>
                </span>
            </div>
            <form method="POST" id="vpnForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <div class="form-check form-switch mb-3">
                    <input class="form-check-input" type="checkbox" id="vpnBlockToggle" 
                        name="block_vpn" value="1" <?= ($settings['block_vpn'] ?? '0') == '1' ? 'checked' : '' ?>
                        onchange="document.getElementById('vpnForm').submit();">
                    <label class="form-check-label" for="vpnBlockToggle">
                        <strong>Block VPN/Proxy Connections</strong>
                        <div class="text-muted small mt-1">
                            Prevent access from known VPN and proxy services
                        </div>
                    </label>
                </div>
                <input type="hidden" name="toggle_vpn_block" value="1">
            </form>
            
            <div class="mt-3 pt-3 border-top">
                <h6 class="mb-2"><i class="fas fa-info-circle me-2 text-info"></i>How it works</h6>
                <ul class="small text-muted mb-0 ps-3">
                    <li>Blocks connections from known VPN IP ranges</li>
                    <li>Detects proxy servers and TOR nodes</li>
                    <li>Real-time updates to VPN databases</li>
                    <li>Customizable exceptions available</li>
                </ul>
            </div>
        </div>
    </div>

    <div class="col-xl-4">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-lock me-2 text-warning"></i>Strict Mode</h5>
                <span class="badge bg-<?php echo $settings['strict_mode'] == '1' ? 'warning' : 'secondary'; ?>">
                    <?php echo $settings['strict_mode'] == '1' ? 'Enabled' : 'Disabled'; ?>
                </span>
            </div>
            <form method="POST" id="strictForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <div class="form-check form-switch mb-3">
                    <input class="form-check-input" type="checkbox" id="strictModeToggle" 
                        name="strict_mode" value="1" <?= ($settings['strict_mode'] ?? '0') == '1' ? 'checked' : '' ?>
                        onchange="document.getElementById('strictForm').submit();">
                    <label class="form-check-label" for="strictModeToggle">
                        <strong>Block countries not in allowed list</strong>
                        <div class="text-muted small mt-1">
                            Only allow traffic from explicitly permitted countries
                        </div>
                    </label>
                </div>
                <input type="hidden" name="toggle_strict_mode" value="1">
            </form>
            
            <div class="mt-3 pt-3 border-top">
                <div class="alert alert-<?php echo ($settings['strict_mode'] ?? '0') == '1' ? 'warning' : 'info'; ?> small">
                    <i class="fas fa-<?php echo ($settings['strict_mode'] ?? '0') == '1' ? 'exclamation-triangle' : 'info-circle'; ?> me-2"></i>
                    <?php echo ($settings['strict_mode'] ?? '0') == '1' ? 
                        '<strong>Warning:</strong> Strict mode enabled. All non-whitelisted countries will be blocked automatically.' : 
                        '<strong>Info:</strong> Strict mode disabled. All countries are allowed unless explicitly blocked.'; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-4">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-globe me-2 text-danger"></i>Geo-Blocking</h5>
                <span class="badge bg-<?php echo $settings['geo_blocking'] == '1' ? 'danger' : 'secondary'; ?>">
                    <?php echo $settings['geo_blocking'] == '1' ? 'Active' : 'Inactive'; ?>
                </span>
            </div>
            <form method="POST" id="geoForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <div class="form-check form-switch mb-3">
                    <input class="form-check-input" type="checkbox" id="geoBlockToggle" 
                        name="geo_blocking" value="1" <?= ($settings['geo_blocking'] ?? '0') == '1' ? 'checked' : '' ?>
                        onchange="document.getElementById('geoForm').submit();">
                    <label class="form-check-label" for="geoBlockToggle">
                        <strong>Enable Geo-Blocking</strong>
                        <div class="text-muted small mt-1">
                            Block traffic based on geographic location
                        </div>
                    </label>
                </div>
                <input type="hidden" name="toggle_geo_block" value="1">
            </form>
            
            <div class="mt-3 pt-3 border-top">
                <h6 class="mb-2"><i class="fas fa-map-marker-alt me-2 text-success"></i>Coverage</h6>
                <div class="row g-2">
                    <div class="col-6">
                        <div class="bg-dark rounded p-2 text-center">
                            <div class="small text-muted">Configured</div>
                            <div class="h4 mb-0"><?php echo $total_countries; ?></div>
                            <div class="small text-muted">Countries</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-dark rounded p-2 text-center">
                            <div class="small text-muted">Rules</div>
                            <div class="h4 mb-0"><?php echo $total_countries; ?></div>
                            <div class="small text-muted">Active</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Country Form -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-plus-circle me-2 text-success"></i>Add New Country</h5>
                <button class="btn btn-sm btn-outline-info" onclick="showCountrySuggestions()">
                    <i class="fas fa-lightbulb me-1"></i> Suggestions
                </button>
            </div>
            <form method="POST" class="row g-3">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <div class="col-md-3">
                    <label for="newCountryCode" class="form-label">Country Code</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-flag"></i></span>
                        <input type="text" class="form-control" id="newCountryCode" name="new_country_code" 
                               maxlength="2" required pattern="[A-Za-z]{2}" placeholder="US"
                               oninput="this.value = this.value.toUpperCase()">
                    </div>
                    <div class="form-text">ISO 2-letter code (e.g., US, GB)</div>
                </div>
                <div class="col-md-5">
                    <label for="newCountryName" class="form-label">Country Name</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-globe"></i></span>
                        <input type="text" class="form-control" id="newCountryName" name="new_country_name" 
                               required placeholder="United States">
                    </div>
                </div>
                <div class="col-md-2">
                    <label class="form-label">Status</label>
                    <div class="d-flex align-items-center h-100">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="newCountryAllowed" 
                                   name="new_country_allowed" checked>
                            <label class="form-check-label" for="newCountryAllowed">
                                <span class="text-success">Allowed</span>
                            </label>
                        </div>
                    </div>
                </div>
                <div class="col-md-2">
                    <label class="form-label">&nbsp;</label>
                    <button type="submit" name="add_country" class="btn btn-success w-100">
                        <i class="fas fa-plus me-2"></i>Add Country
                    </button>
                </div>
            </form>
            
            <div class="mt-3 pt-3 border-top">
                <div class="row g-2">
                    <div class="col-auto">
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="setCountry('US', 'United States')">
                            <i class="fas fa-flag-usa me-1"></i> USA
                        </button>
                    </div>
                    <div class="col-auto">
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="setCountry('GB', 'United Kingdom')">
                            <i class="fas fa-flag-uk me-1"></i> UK
                        </button>
                    </div>
                    <div class="col-auto">
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="setCountry('DE', 'Germany')">
                            <i class="fas fa-flag me-1"></i> Germany
                        </button>
                    </div>
                    <div class="col-auto">
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="setCountry('JP', 'Japan')">
                            <i class="fas fa-flag me-1"></i> Japan
                        </button>
                    </div>
                    <div class="col-auto">
                        <button type="button" class="btn btn-sm btn-outline-secondary" onclick="setCountry('IN', 'India')">
                            <i class="fas fa-flag me-1"></i> India
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Countries Table -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2 text-info"></i>Configured Countries</h5>
                <div>
                    <span class="badge bg-dark me-2"><?php echo count($filtered_countries); ?> of <?php echo $total_countries_filtered; ?></span>
                    <button class="btn btn-sm btn-outline-secondary me-2" onclick="toggleAllDetails()">
                        <i class="fas fa-arrows-expand me-1"></i> Toggle Details
                    </button>
                    <a href="?export=countries" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-download me-1"></i> Export
                    </a>
                </div>
            </div>
            
            <!-- Search and Filter -->
            <form method="GET" class="row g-3 mb-4">
                <div class="col-md-6">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" name="search_country" 
                               value="<?php echo htmlspecialchars($search_country); ?>" 
                               placeholder="Search by country name or code...">
                        <button class="btn btn-outline-primary" type="submit">
                            Search
                        </button>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-filter"></i></span>
                        <select class="form-control" name="status[]" multiple onchange="this.form.submit()">
                            <option value="allowed" <?php echo in_array('allowed', $status_filter) ? 'selected' : ''; ?>>Allowed</option>
                            <option value="blocked" <?php echo in_array('blocked', $status_filter) ? 'selected' : ''; ?>>Blocked</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-2">
                    <a href="?" class="btn btn-outline-secondary w-100">
                        <i class="fas fa-times me-1"></i> Clear
                    </a>
                </div>
            </form>
            
            <?php if (!empty($filtered_countries)): ?>
            <div class="table-responsive">
                <table class="table table-dark table-hover table-striped">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('country_code')">
                                Code 
                                <?php if ($sort_column == 'country_code'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th class="sortable" onclick="sortTable('country_name')">
                                Country Name 
                                <?php if ($sort_column == 'country_name'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th class="sortable" onclick="sortTable('is_allowed')">
                                Status 
                                <?php if ($sort_column == 'is_allowed'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($filtered_countries as $country): ?>
                        <tr>
                            <td>
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-flag text-muted me-2"></i>
                                    <code class="badge bg-dark"><?php echo htmlspecialchars($country['country_code']); ?></code>
                                </div>
                            </td>
                            <td>
                                <strong><?php echo htmlspecialchars($country['country_name']); ?></strong>
                            </td>
                            <td>
                                <span class="badge bg-<?php echo $country['is_allowed'] ? 'success' : 'danger'; ?>">
                                    <i class="fas fa-<?php echo $country['is_allowed'] ? 'check' : 'ban'; ?> me-1"></i>
                                    <?php echo $country['is_allowed'] ? 'Allowed' : 'Blocked'; ?>
                                </span>
                            </td>
                            <td>
                                <div class="btn-group btn-group-sm">
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                        <input type="hidden" name="country_code" value="<?php echo htmlspecialchars($country['country_code']); ?>">
                                        <button type="submit" name="toggle_country" class="btn btn-<?php echo $country['is_allowed'] ? 'warning' : 'success'; ?>"
                                                title="<?php echo $country['is_allowed'] ? 'Block Country' : 'Allow Country'; ?>">
                                            <?php echo $country['is_allowed'] ? '<i class="fas fa-ban"></i>' : '<i class="fas fa-check"></i>'; ?>
                                        </button>
                                    </form>
                                    <button class="btn btn-outline-info" onclick="toggleCountryDetails('<?php echo htmlspecialchars($country['country_code']); ?>')"
                                            title="View Details">
                                        <i class="fas fa-info-circle"></i>
                                    </button>
                                    <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this country?')">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                        <input type="hidden" name="country_code" value="<?php echo htmlspecialchars($country['country_code']); ?>">
                                        <button type="submit" name="delete_country" class="btn btn-outline-danger" title="Delete">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        <tr id="details-<?php echo htmlspecialchars($country['country_code']); ?>" class="d-none">
                            <td colspan="4">
                                <div class="bg-dark rounded p-3 mt-2 border border-secondary">
                                    <div class="row g-3">
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-info-circle me-2 text-info"></i>Country Details</h6>
                                            <div class="bg-black rounded p-3">
                                                <div class="row">
                                                    <div class="col-6">
                                                        <small class="text-muted">Code:</small><br>
                                                        <strong><?php echo htmlspecialchars($country['country_code']); ?></strong>
                                                    </div>
                                                    <div class="col-6">
                                                        <small class="text-muted">Name:</small><br>
                                                        <strong><?php echo htmlspecialchars($country['country_name']); ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-shield-alt me-2 text-warning"></i>Security Info</h6>
                                            <div class="bg-black rounded p-3">
                                                <div class="row">
                                                    <div class="col-6">
                                                        <small class="text-muted">Status:</small><br>
                                                        <span class="badge bg-<?php echo $country['is_allowed'] ? 'success' : 'danger'; ?>">
                                                            <?php echo $country['is_allowed'] ? 'Allowed' : 'Blocked'; ?>
                                                        </span>
                                                    </div>
                                                    <div class="col-6">
                                                        <small class="text-muted">Type:</small><br>
                                                        <strong><?php echo $country['is_allowed'] ? 'Whitelisted' : 'Blacklisted'; ?></strong>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
            <div class="mt-4">
                <nav aria-label="Countries pagination">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $page - 1; ?>&search_country=<?php echo urlencode($search_country); ?>&sort=<?php echo $sort_column; ?>&order=<?php echo $sort_order; ?>"
                                   aria-label="Previous">
                                    <span aria-hidden="true">&laquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php 
                        $start = max(1, $page - 2);
                        $end = min($total_pages, $start + 4);
                        if ($end - $start < 4) {
                            $start = max(1, $end - 4);
                        }
                        
                        for ($i = $start; $i <= $end; $i++): ?>
                            <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo $i; ?>&search_country=<?php echo urlencode($search_country); ?>&sort=<?php echo $sort_column; ?>&order=<?php echo $sort_order; ?>">
                                    <?php echo $i; ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $page + 1; ?>&search_country=<?php echo urlencode($search_country); ?>&sort=<?php echo $sort_column; ?>&order=<?php echo $sort_order; ?>"
                                   aria-label="Next">
                                    <span aria-hidden="true">&raquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            </div>
            <?php endif; ?>
            
            <?php else: ?>
            <div class="text-center py-5">
                <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                <h5>No countries found</h5>
                <p class="text-muted"><?php echo $search_country || !empty($status_filter) ? 'Try adjusting your filters' : 'Add your first country using the form above'; ?></p>
                <?php if ($search_country || !empty($status_filter)): ?>
                    <a href="?" class="btn btn-outline-secondary mt-2">
                        <i class="fas fa-times me-2"></i>Clear Filters
                    </a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Quick Stats -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-chart-pie me-2 text-primary"></i>Country Distribution</h5>
            <div class="row">
                <div class="col-md-6">
                    <div class="text-center">
                        <div class="display-4 text-success"><?php echo count($allowed_countries); ?></div>
                        <div class="text-muted">Allowed Countries</div>
                        <div class="mt-2">
                            <span class="badge bg-success"><?php echo $total_countries > 0 ? round((count($allowed_countries) / $total_countries) * 100) : 0; ?>%</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="text-center">
                        <div class="display-4 text-danger"><?php echo count($blocked_countries); ?></div>
                        <div class="text-muted">Blocked Countries</div>
                        <div class="mt-2">
                            <span class="badge bg-danger"><?php echo $total_countries > 0 ? round((count($blocked_countries) / $total_countries) * 100) : 0; ?>%</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="mt-4">
                <div class="progress" style="height: 10px;">
                    <div class="progress-bar bg-success" style="width: <?php echo $total_countries > 0 ? (count($allowed_countries) / $total_countries) * 100 : 0; ?>%"></div>
                    <div class="progress-bar bg-danger" style="width: <?php echo $total_countries > 0 ? (count($blocked_countries) / $total_countries) * 100 : 0; ?>%"></div>
                </div>
                <div class="d-flex justify-content-between mt-2 small text-muted">
                    <span>Allowed (<?php echo count($allowed_countries); ?>)</span>
                    <span>Blocked (<?php echo count($blocked_countries); ?>)</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-history me-2 text-warning"></i>Recent VPN Activity</h5>
                <small class="text-muted">Last 7 days</small>
            </div>
            <div class="timeline">
                <?php if ($vpn_stats['today_blocked'] > 0): ?>
                    <div class="timeline-item mb-3">
                        <div class="d-flex">
                            <div class="timeline-marker bg-danger"></div>
                            <div class="timeline-content ms-3">
                                <div class="d-flex justify-content-between">
                                    <strong><?php echo $vpn_stats['today_blocked']; ?> VPNs blocked today</strong>
                                    <small class="text-muted">Today</small>
                                </div>
                                <div class="small text-muted">
                                    Total of <?php echo $vpn_stats['total_blocked']; ?> VPN/proxy connections blocked
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <?php if (!empty($vpn_stats['top_countries'])): ?>
                    <div class="timeline-item mb-3">
                        <div class="d-flex">
                            <div class="timeline-marker bg-warning"></div>
                            <div class="timeline-content ms-3">
                                <div class="d-flex justify-content-between">
                                    <strong>Top VPN Countries</strong>
                                    <small class="text-muted">Last 30 days</small>
                                </div>
                                <div class="small text-muted">
                                    <?php echo implode(', ', $vpn_stats['top_countries']); ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <div class="timeline-item">
                    <div class="d-flex">
                        <div class="timeline-marker bg-info"></div>
                        <div class="timeline-content ms-3">
                            <div class="d-flex justify-content-between">
                                <strong>Security Status</strong>
                                <small class="text-muted">Current</small>
                            </div>
                            <div class="small text-muted">
                                VPN Blocking: <span class="badge bg-<?php echo $settings['block_vpn'] == '1' ? 'success' : 'secondary'; ?>"><?php echo $settings['block_vpn'] == '1' ? 'Active' : 'Inactive'; ?></span>
                                | Strict Mode: <span class="badge bg-<?php echo $settings['strict_mode'] == '1' ? 'warning' : 'secondary'; ?>"><?php echo $settings['strict_mode'] == '1' ? 'Enabled' : 'Disabled'; ?></span>
                                | Geo-Blocking: <span class="badge bg-<?php echo $settings['geo_blocking'] == '1' ? 'danger' : 'secondary'; ?>"><?php echo $settings['geo_blocking'] == '1' ? 'Active' : 'Inactive'; ?></span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- VPN Details Modal -->
<div class="modal fade" id="vpnDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-shield-virus me-2"></i>VPN Blocking Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card bg-dark border-secondary mb-3">
                            <div class="card-body">
                                <h6><i class="fas fa-chart-line me-2 text-primary"></i>Statistics</h6>
                                <div class="row mt-3">
                                    <div class="col-6">
                                        <div class="text-center">
                                            <div class="h3 text-danger"><?php echo $vpn_stats['total_blocked']; ?></div>
                                            <small class="text-muted">Total Blocked</small>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="text-center">
                                            <div class="h3 text-warning"><?php echo $vpn_stats['today_blocked']; ?></div>
                                            <small class="text-muted">Today</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card bg-dark border-secondary mb-3">
                            <div class="card-body">
                                <h6><i class="fas fa-globe me-2 text-info"></i>Top Countries</h6>
                                <div class="mt-3">
                                    <?php if (!empty($vpn_stats['top_countries'])): ?>
                                        <?php foreach ($vpn_stats['top_countries'] as $country): ?>
                                            <span class="badge bg-dark me-1 mb-1"><?php echo htmlspecialchars($country); ?></span>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <p class="text-muted mb-0">No recent VPN traffic</p>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="alert alert-info">
                    <h6><i class="fas fa-info-circle me-2"></i>How VPN Blocking Works</h6>
                    <p class="mb-0 small">The system detects VPN and proxy connections using real-time IP intelligence databases and fingerprinting techniques. When enabled, all traffic from known VPN/proxy servers is automatically blocked.</p>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="logs.php?filter=vpn" class="btn btn-primary">
                    <i class="fas fa-history me-1"></i> View Logs
                </a>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // Auto-fill country name based on code
    const countryMap = {
        'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany', 
        'FR': 'France', 'JP': 'Japan', 'CA': 'Canada', 'AU': 'Australia',
        'IN': 'India', 'CN': 'China', 'BR': 'Brazil', 'RU': 'Russia',
        'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands', 'SE': 'Sweden'
    };
    
    $('#newCountryCode').on('blur', function() {
        if (this.value.length === 2 && !$('#newCountryName').val()) {
            const countryName = countryMap[this.value.toUpperCase()];
            if (countryName) {
                $('#newCountryName').val(countryName);
            }
        }
    });

    // Set country from quick buttons
    window.setCountry = function(code, name) {
        $('#newCountryCode').val(code);
        $('#newCountryName').val(name);
        $('#newCountryCode').focus();
    }

    // Show country suggestions
    window.showCountrySuggestions = function() {
        const suggestions = [
            {code: 'US', name: 'United States', desc: 'Most traffic'},
            {code: 'GB', name: 'United Kingdom', desc: 'European traffic'},
            {code: 'DE', name: 'Germany', desc: 'EU traffic'},
            {code: 'JP', name: 'Japan', desc: 'Asian traffic'},
            {code: 'IN', name: 'India', desc: 'Growing market'}
        ];
        
        let html = '<div class="row g-2">';
        suggestions.forEach(s => {
            html += `
                <div class="col-md-6">
                    <div class="card bg-dark border-secondary">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${s.name}</strong><br>
                                    <small class="text-muted">${s.desc}</small>
                                </div>
                                <button type="button" class="btn btn-sm btn-outline-primary" 
                                        onclick="setCountry('${s.code}', '${s.name}')">
                                    Use
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        // Show in modal or alert
        alertify.alert('Country Suggestions', html);
    }

    // Toggle country details
    window.toggleCountryDetails = function(countryCode) {
        const detailsRow = document.getElementById(`details-${countryCode}`);
        detailsRow.classList.toggle('d-none');
    }

    // Toggle all details
    window.toggleAllDetails = function() {
        const allDetails = document.querySelectorAll('[id^="details-"]');
        if (allDetails.length === 0) return;
        
        const shouldShow = allDetails[0].classList.contains('d-none');
        
        allDetails.forEach((details) => {
            if (shouldShow) {
                details.classList.remove('d-none');
            } else {
                details.classList.add('d-none');
            }
        });
    }

    // Show VPN details modal
    window.showVPNDetails = function() {
        new bootstrap.Modal(document.getElementById('vpnDetailsModal')).show();
    }

    // Show security info
    window.showSecurityInfo = function() {
        alertify.alert('Security Level Info', `
            <div class="alert alert-info">
                <h6><i class="fas fa-info-circle me-2"></i>Security Score Calculation</h6>
                <p>The security score is calculated based on:</p>
                <ul>
                    <li><strong>VPN Blocking (30%):</strong> Blocks known VPN/proxy servers</li>
                    <li><strong>Strict Mode (40%):</strong> Only allows whitelisted countries</li>
                    <li><strong>Geo-Blocking (30%):</strong> Active country-based filtering</li>
                </ul>
                <p class="mb-0">Each enabled feature adds to your security score. Higher scores indicate better protection.</p>
            </div>
        `);
    }

    // Sort table
    window.sortTable = function(column) {
        const urlParams = new URLSearchParams(window.location.search);
        let order = 'ASC';
        
        if (urlParams.get('sort') === column && urlParams.get('order') === 'ASC') {
            order = 'DESC';
        }
        
        let queryString = `?sort=${column}&order=${order}`;
        
        const searchCountry = urlParams.get('search_country');
        if (searchCountry) {
            queryString += `&search_country=${encodeURIComponent(searchCountry)}`;
        }
        
        const statuses = urlParams.getAll('status[]');
        statuses.forEach(status => {
            queryString += `&status[]=${encodeURIComponent(status)}`;
        });
        
        window.location.href = queryString;
    }

    // Auto-refresh stats every 60 seconds
    setInterval(function() {
        $.ajax({
            url: 'api/get-vpn-stats.php',
            method: 'GET',
            data: { website_id: <?php echo $websiteId; ?>, user_id: <?php echo $userId; ?> },
            success: function(response) {
                if (response.success && response.stats) {
                    // Update counters
                    if (response.stats.today_blocked != <?php echo $vpn_stats['today_blocked']; ?>) {
                        // Show notification if there are new blocks
                        if (response.stats.today_blocked > <?php echo $vpn_stats['today_blocked']; ?>) {
                            showNotification('New VPN connections blocked', 'warning');
                        }
                        // Reload page to show updated stats
                        setTimeout(() => location.reload(), 5000);
                    }
                }
            }
        });
    }, 60000);
});

// Show notification
function showNotification(message, type = 'info') {
    const alertClass = {
        'info': 'alert-info',
        'success': 'alert-success',
        'warning': 'alert-warning',
        'danger': 'alert-danger'
    }[type] || 'alert-info';
    
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert" 
             style="position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 300px;">
            <i class="fas fa-bell me-2"></i>
            ${message}
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('body').append(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alert.alert('close');
    }, 5000);
}
</script>

<style>
/* Custom styles for VPN page */
.dashboard-card {
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    background: linear-gradient(145deg, #1a1a1a, #222222);
    border: 1px solid #2a2a2a;
}

.dashboard-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
}

.card-icon {
    font-size: 2.5rem;
    margin-bottom: 15px;
    opacity: 0.8;
}

.stat-number {
    font-size: 2.8rem;
    font-weight: 700;
    line-height: 1;
}

.stat-change {
    font-size: 0.85rem;
    font-weight: 500;
}

.sortable {
    cursor: pointer;
    position: relative;
    padding-right: 25px !important;
}

.sortable:hover {
    background-color: rgba(0, 123, 255, 0.1);
}

.bg-black {
    background-color: #111 !important;
}

.timeline {
    position: relative;
    padding-left: 30px;
}

.timeline:before {
    content: '';
    position: absolute;
    left: 15px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, #495057, transparent);
}

.timeline-item {
    position: relative;
    margin-bottom: 25px;
}

.timeline-marker {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    position: absolute;
    left: -32px;
    top: 5px;
    border: 3px solid #121212;
    box-shadow: 0 0 0 2px #495057;
    z-index: 2;
}

.timeline-content {
    padding-left: 20px;
}

.progress {
    background-color: #2a2a2a;
    border-radius: 10px;
}

.progress-bar {
    border-radius: 10px;
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .stat-number {
        font-size: 2.2rem;
    }
    
    .card-icon {
        font-size: 2rem;
    }
    
    .btn-group-sm {
        flex-wrap: wrap;
    }
    
    .timeline:before {
        left: 10px;
    }
    
    .timeline-marker {
        left: -22px;
        width: 12px;
        height: 12px;
    }
}

/* Animation for new blocks */
@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.05); }
    100% { transform: scale(1); }
}

.new-block {
    animation: pulse 0.5s ease-in-out;
}

/* Form styling */
.input-group-text {
    background-color: #2a2a2a;
    border-color: #444;
    color: #8a8a8a;
}

.form-control, .form-select {
    background-color: #2a2a2a;
    border-color: #444;
    color: #e9ecef;
}

.form-control:focus, .form-select:focus {
    background-color: #2a2a2a;
    border-color: #0d6efd;
    color: #e9ecef;
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
}

/* Badge enhancements */
.badge {
    font-weight: 600;
    padding: 0.35em 0.65em;
}

/* Table enhancements */
.table-dark.table-striped > tbody > tr:nth-of-type(odd) {
    background-color: rgba(255, 255, 255, 0.02);
}

.table-dark.table-hover > tbody > tr:hover {
    background-color: rgba(0, 123, 255, 0.1);
}

/* Modal styling */
.modal-content {
    background: linear-gradient(145deg, #1a1a1a, #222222);
    border: 1px solid #2a2a2a;
}

.modal-header {
    border-bottom-color: #444;
}

.modal-footer {
    border-top-color: #444;
}

/* Alert styling */
.alert {
    border: none;
    border-radius: 8px;
}

.alert-info {
    background-color: rgba(23, 162, 184, 0.15);
    border-left: 4px solid #17a2b8;
}

.alert-warning {
    background-color: rgba(255, 193, 7, 0.15);
    border-left: 4px solid #ffc107;
}

.alert-success {
    background-color: rgba(40, 167, 69, 0.15);
    border-left: 4px solid #28a745;
}

.alert-danger {
    background-color: rgba(220, 53, 69, 0.15);
    border-left: 4px solid #dc3545;
}
</style>

<?php
// End output buffering and send output
ob_end_flush();
require_once '../includes/footer.php';
?>