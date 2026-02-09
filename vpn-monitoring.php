<?php
// vpn-monitor.php
require_once 'includes/header.php';
require_once 'includes/auth.php';

// Check if user is logged in
if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Set default values for userId and websiteId
$userId = $userId ?? 1;
$websiteId = $websiteId ?? 1;

date_default_timezone_set('UTC');

/**
 * -------------------------------------------------
 * LOAD SETTINGS (SCOPED)
 * -------------------------------------------------
 */
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
} catch (PDOException $e) {
    // Settings table might not exist
}

/**
 * -------------------------------------------------
 * HANDLE POST ACTIONS (WITHOUT AUTO-REDIRECT)
 * -------------------------------------------------
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    if (!validateCSRFToken('vpn_settings', $csrf_token)) {
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
            } catch (PDOException $e) {
                // Log error but don't crash
                error_log("Toggle country error: " . $e->getMessage());
            }
        }
    }

    // VPN block toggle
    if (isset($_POST['toggle_vpn_block'])) {
        $value = isset($_POST['block_vpn']) ? '1' : '0';

        try {
            $stmt = $pdo->prepare("
                INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                VALUES (?, ?, 'block_vpn', ?)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            ");
            $stmt->execute([$userId, $websiteId, $value]);
            $settings['block_vpn'] = $value;
        } catch (PDOException $e) {
            error_log("VPN block toggle error: " . $e->getMessage());
        }
    }

    // Strict mode toggle
    if (isset($_POST['toggle_strict_mode'])) {
        $value = isset($_POST['strict_mode']) ? '1' : '0';

        try {
            $stmt = $pdo->prepare("
                INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                VALUES (?, ?, 'strict_mode', ?)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            ");
            $stmt->execute([$userId, $websiteId, $value]);
            $settings['strict_mode'] = $value;
        } catch (PDOException $e) {
            error_log("Strict mode toggle error: " . $e->getMessage());
        }
    }

    // Geo-blocking toggle
    if (isset($_POST['toggle_geo_block'])) {
        $value = isset($_POST['geo_blocking']) ? '1' : '0';

        try {
            $stmt = $pdo->prepare("
                INSERT INTO settings (user_id, website_id, setting_name, setting_value)
                VALUES (?, ?, 'geo_blocking', ?)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            ");
            $stmt->execute([$userId, $websiteId, $value]);
            $settings['geo_blocking'] = $value;
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
                $stmt = $pdo->prepare("
                    INSERT INTO allowed_countries
                    (user_id, website_id, country_code, country_name, is_allowed)
                    VALUES (?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                        country_name = VALUES(country_name),
                        is_allowed = VALUES(is_allowed)
                ");
                $stmt->execute([$userId, $websiteId, $code, $name, $allowed]);
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
            } catch (PDOException $e) {
                error_log("Delete country error: " . $e->getMessage());
            }
        }
    }
    
    // REMOVED AUTO-REDIRECT to prevent infinite loop
    // Refresh page without POST data instead
    // Use JavaScript to reload the page after form submission
}

/**
 * -------------------------------------------------
 * FILTER / SORT / PAGINATION
 * -------------------------------------------------
 */
$search_country = trim($_GET['search_country'] ?? '');
$status_filter = $_GET['status'] ?? [];
$sort_column = $_GET['sort'] ?? 'country_name';
$sort_order = strtoupper($_GET['order'] ?? 'ASC');
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 10;

$valid_columns = ['country_code', 'country_name', 'is_allowed'];
if (!in_array($sort_column, $valid_columns)) $sort_column = 'country_name';
if (!in_array($sort_order, ['ASC', 'DESC'])) $sort_order = 'ASC';

/**
 * -------------------------------------------------
 * LOAD COUNTRIES WITH FILTERING (SIMPLIFIED)
 * -------------------------------------------------
 */
function getFilteredCountriesCount($pdo, $search_country, $status_filter, $userId, $websiteId) {
    $sql = "SELECT COUNT(*) AS total
            FROM allowed_countries
            WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $userId,
        ':website_id' => $websiteId
    ];

    if ($search_country !== '') {
        $sql .= " AND (country_name LIKE :search OR country_code LIKE :search)";
        $params[':search'] = "%$search_country%";
    }

    if (!empty($status_filter)) {
        $conditions = [];
        foreach ($status_filter as $status) {
            if ($status === 'allowed') {
                $conditions[] = "is_allowed = 1";
            } elseif ($status === 'blocked') {
                $conditions[] = "is_allowed = 0";
            }
        }
        if (!empty($conditions)) {
            $sql .= " AND (" . implode(' OR ', $conditions) . ")";
        }
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

function getFilteredCountries($pdo, $search_country, $status_filter, $sort_column, $sort_order, $page, $per_page, $userId, $websiteId) {
    $offset = ($page - 1) * $per_page;

    // SIMPLIFIED QUERY
    $sql = "SELECT *
            FROM allowed_countries
            WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $userId,
        ':website_id' => $websiteId
    ];

    if ($search_country !== '') {
        $sql .= " AND (country_name LIKE :search OR country_code LIKE :search)";
        $params[':search'] = "%$search_country%";
    }

    if (!empty($status_filter)) {
        $conditions = [];
        foreach ($status_filter as $status) {
            if ($status === 'allowed') {
                $conditions[] = "is_allowed = 1";
            } elseif ($status === 'blocked') {
                $conditions[] = "is_allowed = 0";
            }
        }
        if (!empty($conditions)) {
            $sql .= " AND (" . implode(' OR ', $conditions) . ")";
        }
    }

    $sql .= " ORDER BY $sort_column $sort_order LIMIT :limit OFFSET :offset";

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':user_id', $userId, PDO::PARAM_INT);
    $stmt->bindValue(':website_id', $websiteId, PDO::PARAM_INT);
    if ($search_country !== '') {
        $stmt->bindValue(':search', "%$search_country%", PDO::PARAM_STR);
    }
    $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    
    return $stmt->fetchAll();
}

/**
 * -------------------------------------------------
 * GET STATISTICS
 * -------------------------------------------------
 */
$countries = getFilteredCountries($pdo, $search_country, $status_filter, $sort_column, $sort_order, 1, 1000, $userId, $websiteId);
$total_countries = count($countries);
$allowed_countries = array_filter($countries, function($c) { return $c['is_allowed']; });
$blocked_countries = array_filter($countries, function($c) { return !$c['is_allowed']; });

// Get VPN detection stats (example - would come from actual logs)
$vpn_stats = [
    'total_blocked' => 42,
    'today_blocked' => 3,
    'top_countries' => ['US', 'GB', 'DE', 'RU', 'CN']
];

// Generate CSRF token
$csrf_token = generateCSRFToken('vpn_settings');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN & Geo-Restrictions</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #121212;
            color: #e9ecef;
        }
        .dashboard-card {
            background-color: #1e1e1e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #343a40;
        }
        .card-icon {
            font-size: 2rem;
            margin-bottom: 15px;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
        }
        .stat-change {
            font-size: 0.9rem;
        }
        .positive { color: #28a745; }
        .negative { color: #dc3545; }
        .sortable { cursor: pointer; }
        .sortable:hover { background-color: rgba(255,255,255,0.05); }
        .bg-black { background-color: #121212; }
        .timeline { position: relative; }
        .timeline-item { position: relative; }
        .timeline-marker {
            width: 12px; height: 12px;
            border-radius: 50%;
            position: absolute;
            top: 5px;
        }
        .timeline-content { padding-left: 20px; }
    </style>
</head>
<body>
    <div class="container-fluid py-4">
        <!-- VPN Monitoring Content -->
        <div class="row g-4 fade-in">
            <!-- Page Header -->
            <div class="col-12">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2 class="mb-1"><i class="fas fa-shield-virus me-2"></i>VPN & Geo-Restrictions</h2>
                        <p class="text-muted mb-0">Manage VPN blocking and country-based restrictions</p>
                    </div>
                    <div>
                        <span class="badge bg-light text-dark me-3">
                            <i class="fas fa-users me-1"></i> <?php echo $total_countries; ?> Countries
                        </span>
                    </div>
                </div>
            </div>

            <!-- Summary Cards -->
            <div class="col-xl-3 col-md-6">
                <div class="dashboard-card">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div class="card-icon text-danger">
                                <i class="fas fa-ban"></i>
                            </div>
                            <div class="text-muted mb-1">VPNs Blocked</div>
                            <div class="stat-number text-danger"><?php echo $vpn_stats['total_blocked']; ?></div>
                            <div class="stat-change negative">
                                <i class="fas fa-arrow-up"></i> <?php echo $vpn_stats['today_blocked']; ?> today
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
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <div class="text-muted mb-1">Allowed Countries</div>
                            <div class="stat-number text-success"><?php echo count($allowed_countries); ?></div>
                            <div class="stat-change positive">
                                <i class="fas fa-globe"></i> Whitelisted
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
                                <i class="fas fa-globe"></i>
                            </div>
                            <div class="text-muted mb-1">Blocked Countries</div>
                            <div class="stat-number text-warning"><?php echo count($blocked_countries); ?></div>
                            <div class="stat-change">
                                <i class="fas fa-shield-alt"></i> Blacklisted
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
                            <div class="stat-change">
                                <i class="fas fa-<?php echo $security_score >= 70 ? 'shield-alt' : 'exclamation-triangle'; ?>"></i>
                                <?php echo $security_score >= 70 ? 'High' : ($security_score >= 40 ? 'Medium' : 'Low'); ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Settings Cards -->
            <div class="col-xl-4">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-network-wired me-2"></i>VPN/Proxy Blocking</h5>
                    <form method="POST" onsubmit="handleFormSubmit(event)">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="vpnBlockToggle" 
                                name="block_vpn" value="1" <?= ($settings['block_vpn'] ?? '0') == '1' ? 'checked' : '' ?>>
                            <label class="form-check-label" for="vpnBlockToggle">
                                <strong>Block VPN/Proxy Connections</strong>
                                <div class="text-muted small mt-1">
                                    Prevent access from known VPN and proxy services
                                </div>
                            </label>
                        </div>
                        <button type="submit" name="toggle_vpn_block" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Save Settings
                        </button>
                    </form>
                    
                    <div class="mt-4 pt-3 border-top">
                        <h6 class="mb-3"><i class="fas fa-info-circle me-2"></i>Current Status</h6>
                        <div class="alert alert-<?php echo ($settings['block_vpn'] ?? '0') == '1' ? 'success' : 'secondary'; ?>">
                            <i class="fas fa-<?php echo ($settings['block_vpn'] ?? '0') == '1' ? 'shield-check' : 'shield'; ?> me-2"></i>
                            VPN blocking is <strong><?php echo ($settings['block_vpn'] ?? '0') == '1' ? 'active' : 'inactive'; ?></strong>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-xl-4">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-lock me-2"></i>Strict Mode</h5>
                    <form method="POST" onsubmit="handleFormSubmit(event)">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="strictModeToggle" 
                                name="strict_mode" value="1" <?= ($settings['strict_mode'] ?? '0') == '1' ? 'checked' : '' ?>>
                            <label class="form-check-label" for="strictModeToggle">
                                <strong>Block countries not in allowed list</strong>
                                <div class="text-muted small mt-1">
                                    Only allow traffic from explicitly permitted countries
                                </div>
                            </label>
                        </div>
                        <button type="submit" name="toggle_strict_mode" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Save Settings
                        </button>
                    </form>
                    
                    <div class="mt-4 pt-3 border-top">
                        <h6 class="mb-3"><i class="fas fa-exclamation-triangle me-2"></i>Warning</h6>
                        <div class="alert alert-<?php echo ($settings['strict_mode'] ?? '0') == '1' ? 'warning' : 'info'; ?>">
                            <i class="fas fa-<?php echo ($settings['strict_mode'] ?? '0') == '1' ? 'exclamation-triangle' : 'info-circle'; ?> me-2"></i>
                            <?php echo ($settings['strict_mode'] ?? '0') == '1' ? 
                                'Strict mode enabled - only allowed countries can access.' : 
                                'Strict mode disabled - all countries are allowed.'; ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-xl-4">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-globe me-2"></i>Geo-Blocking</h5>
                    <form method="POST" onsubmit="handleFormSubmit(event)">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="geoBlockToggle" 
                                name="geo_blocking" value="1" <?= ($settings['geo_blocking'] ?? '0') == '1' ? 'checked' : '' ?>>
                            <label class="form-check-label" for="geoBlockToggle">
                                <strong>Enable Geo-Blocking</strong>
                                <div class="text-muted small mt-1">
                                    Block traffic based on geographic location
                                </div>
                            </label>
                        </div>
                        <button type="submit" name="toggle_geo_block" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Save Settings
                        </button>
                    </form>
                    
                    <div class="mt-4 pt-3 border-top">
                        <h6 class="mb-3"><i class="fas fa-map-marker-alt me-2"></i>Coverage</h6>
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span>Countries configured</span>
                            <span class="badge bg-primary"><?php echo $total_countries; ?></span>
                        </div>
                        <div class="d-flex justify-content-between align-items-center">
                            <span>Active rules</span>
                            <span class="badge bg-<?php echo ($settings['geo_blocking'] ?? '0') == '1' ? 'success' : 'secondary'; ?>">
                                <?php echo ($settings['geo_blocking'] ?? '0') == '1' ? 'Active' : 'Inactive'; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Add Country Form -->
            <div class="col-12">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-globe-americas me-2"></i>Add New Country</h5>
                    <form method="POST" class="row g-3" onsubmit="handleFormSubmit(event)">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="col-md-3">
                            <label for="newCountryCode" class="form-label">Country Code</label>
                            <input type="text" class="form-control" id="newCountryCode" name="new_country_code" 
                                   maxlength="2" required pattern="[A-Za-z]{2}" placeholder="US">
                            <div class="form-text">ISO 2-letter code (e.g., US, GB)</div>
                        </div>
                        <div class="col-md-5">
                            <label for="newCountryName" class="form-label">Country Name</label>
                            <input type="text" class="form-control" id="newCountryName" name="new_country_name" required placeholder="United States">
                        </div>
                        <div class="col-md-2 d-flex align-items-end">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="newCountryAllowed" 
                                       name="new_country_allowed" checked>
                                <label class="form-check-label" for="newCountryAllowed">
                                    Allowed
                                </label>
                            </div>
                        </div>
                        <div class="col-md-2 d-flex align-items-end">
                            <button type="submit" name="add_country" class="btn btn-success w-100">
                                <i class="fas fa-plus me-2"></i>Add Country
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Countries Table -->
            <div class="col-12">
                <div class="dashboard-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h5 class="mb-0"><i class="fas fa-list me-2"></i>Configured Countries</h5>
                        <div>
                            <button class="btn btn-sm btn-outline-secondary me-2" onclick="toggleAllDetails()">
                                <i class="fas fa-arrows-expand me-1"></i> Toggle Details
                            </button>
                            <span class="badge bg-dark"><?php echo count($countries); ?> Countries</span>
                        </div>
                    </div>
                    
                    <div class="table-responsive">
                        <table class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th class="sortable" onclick="sortTable('country_code')">
                                        Code 
                                        <?php if ($sort_column == 'country_code') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                                    </th>
                                    <th class="sortable" onclick="sortTable('country_name')">
                                        Country Name 
                                        <?php if ($sort_column == 'country_name') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                                    </th>
                                    <th class="sortable" onclick="sortTable('is_allowed')">
                                        Status 
                                        <?php if ($sort_column == 'is_allowed') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                                    </th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($countries)): ?>
                                    <?php foreach ($countries as $country): ?>
                                    <tr>
                                        <td>
                                            <code class="badge bg-dark"><?php echo htmlspecialchars($country['country_code']); ?></code>
                                        </td>
                                        <td>
                                            <div class="d-flex align-items-center">
                                                <i class="fas fa-flag me-3 text-muted"></i>
                                                <div>
                                                    <strong><?php echo htmlspecialchars($country['country_name']); ?></strong>
                                                    <div class="small text-muted">ISO: <?php echo htmlspecialchars($country['country_code']); ?></div>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="badge bg-<?php echo $country['is_allowed'] ? 'success' : 'danger'; ?>">
                                                <i class="fas fa-<?php echo $country['is_allowed'] ? 'check' : 'ban'; ?> me-1"></i>
                                                <?php echo $country['is_allowed'] ? 'Allowed' : 'Blocked'; ?>
                                            </span>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <form method="POST" class="d-inline" onsubmit="return handleFormSubmit(event)">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <input type="hidden" name="country_code" value="<?php echo $country['country_code']; ?>">
                                                    <button type="submit" name="toggle_country" class="btn btn-<?php echo $country['is_allowed'] ? 'danger' : 'success'; ?>">
                                                        <?php echo $country['is_allowed'] ? '<i class="fas fa-ban"></i>' : '<i class="fas fa-check"></i>'; ?>
                                                    </button>
                                                </form>
                                                <form method="POST" class="d-inline" onsubmit="return confirmDelete(event)">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <input type="hidden" name="country_code" value="<?php echo $country['country_code']; ?>">
                                                    <button type="submit" name="delete_country" class="btn btn-outline-danger">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </form>
                                                <button class="btn btn-outline-info" onclick="toggleCountryDetails('<?php echo $country['country_code']; ?>')">
                                                    <i class="fas fa-info"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr id="details-<?php echo $country['country_code']; ?>" class="d-none">
                                        <td colspan="4">
                                            <div class="bg-dark rounded p-3 mt-2">
                                                <div class="row g-3">
                                                    <div class="col-md-6">
                                                        <h6><i class="fas fa-info-circle me-2"></i>Country Details</h6>
                                                        <div class="bg-black rounded p-2 small">
                                                            <strong>Code:</strong> <?php echo htmlspecialchars($country['country_code']); ?><br>
                                                            <strong>Name:</strong> <?php echo htmlspecialchars($country['country_name']); ?><br>
                                                            <strong>Status:</strong> 
                                                            <span class="badge bg-<?php echo $country['is_allowed'] ? 'success' : 'danger'; ?>">
                                                                <?php echo $country['is_allowed'] ? 'Allowed' : 'Blocked'; ?>
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <div class="col-md-6">
                                                        <h6><i class="fas fa-shield-alt me-2"></i>Security</h6>
                                                        <div class="bg-black rounded p-2 small">
                                                            <strong>Type:</strong> <?php echo $country['is_allowed'] ? 'Whitelisted' : 'Blacklisted'; ?><br>
                                                            <strong>Active:</strong> Yes<br>
                                                            <strong>Added:</strong> Recently
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="4" class="text-center py-4">
                                            <div class="text-muted">
                                                <i class="fas fa-inbox fa-2x mb-3"></i>
                                                <div>No countries configured yet.</div>
                                                <small class="mt-2 d-block">Add your first country using the form above.</small>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function() {
            // Convert country code to uppercase
            $('#newCountryCode').on('input', function() {
                this.value = this.value.toUpperCase();
            });
            
            // Auto-fill country name based on code
            $('#newCountryCode').on('blur', function() {
                if (this.value.length === 2 && !$('#newCountryName').val()) {
                    const countryMap = {
                        'US': 'United States',
                        'GB': 'United Kingdom',
                        'DE': 'Germany',
                        'FR': 'France',
                        'JP': 'Japan',
                        'CA': 'Canada',
                        'AU': 'Australia',
                        'IN': 'India',
                        'CN': 'China',
                        'BR': 'Brazil'
                    };
                    
                    if (countryMap[this.value]) {
                        $('#newCountryName').val(countryMap[this.value]);
                    }
                }
            });

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

            // Handle form submission with AJAX
            window.handleFormSubmit = function(event) {
                event.preventDefault();
                const form = event.target;
                const formData = new FormData(form);
                
                fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (response.ok) {
                        // Reload page to show updated data
                        window.location.reload();
                    } else {
                        alert('Error saving changes');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error saving changes');
                });
                
                return false;
            }

            // Confirm delete
            window.confirmDelete = function(event) {
                if (!confirm('Are you sure you want to delete this country?')) {
                    return false;
                }
                return handleFormSubmit(event);
            }
        });
    </script>
</body>
</html>
