<?php
// block-list.php
require_once '../includes/header.php';
require_once '../includes/auth.php';
require_once '../includes/db.php';

// Start output buffering to prevent header issues
ob_start();

// Check if user is logged in
if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    ob_end_flush();
    exit();
}

// Get logged-in user ID from session
$userId = $_SESSION['user_id'] ?? null;
if (!$userId) {
    header("Location: login.php");
    ob_end_flush();
    exit();
}

// Get website ID (you might want to make this selectable)
$websiteId = $_SESSION['website_id'] ?? 1;

/* --------------------------------
   HANDLE BLOCK ACTION FROM USER TRACKER
--------------------------------- */
if (isset($_GET['ip'])) {
    $ip_to_block = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
    
    // Generate CSRF token if not exists
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $csrf_block_token = bin2hex(random_bytes(32));
    $_SESSION['csrf_tokens']['block_ip'] = $csrf_block_token;
    
    if ($ip_to_block) {
        // Check if IP is already blocked
        $checkStmt = $pdo->prepare("
            SELECT id FROM blocked_ips 
            WHERE ip = ? AND user_id = ? AND website_id = ?
            AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
        ");
        $checkStmt->execute([$ip_to_block, $userId, $websiteId]);
        
        if (!$checkStmt->fetch()) {
            // Insert new block
            $stmt = $pdo->prepare("
                INSERT INTO blocked_ips (user_id, ip, website_id, reason, created_at, expiry_time)
                VALUES (?, ?, ?, 'Manual block from user tracker', NOW(), '24:00:00')
            ");
            
            $stmt->execute([$userId, $ip_to_block, $websiteId]);
            
            // Also log to attack_logs for tracking
            $logStmt = $pdo->prepare("
                INSERT INTO attack_logs (user_id, website_id, timestamp, attack_type, severity, ip_address, user_agent, attack_payload, request_url)
                VALUES (?, ?, NOW(), 'MANUAL_BLOCK', 'Medium', ?, ?, 'Manual IP Block', 'User Tracker')
            ");
            $logStmt->execute([$userId, $websiteId, $ip_to_block, $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown']);
            
            $block_message = "IP $ip_to_block has been blocked successfully.";
            $message_type = "success";
        } else {
            $block_message = "IP $ip_to_block is already blocked.";
            $message_type = "warning";
        }
    }
    
    // Store flash message and redirect
    $_SESSION['flash_message'] = $block_message;
    $_SESSION['flash_type'] = $message_type;
    
    // Clear output buffer and redirect
    ob_end_clean();
    header("Location: user-tracker.php");
    exit();
}

// Check for other redirect conditions before any output
if (isset($_GET['action']) && $_GET['action'] === 'redirect') {
    ob_end_clean();
    header("Location: user-tracker.php");
    exit();
}

/* --------------------------------
   GET WEBSITE DETAILS FOR DISPLAY
--------------------------------- */
$websiteDetails = [];
try {
    $websiteQuery = $pdo->prepare("SELECT site_name, domain FROM websites WHERE id = ? AND user_id = ?");
    $websiteQuery->execute([$websiteId, $userId]);
    $websiteDetails = $websiteQuery->fetch();
} catch (Exception $e) {
    $websiteDetails = ['site_name' => 'Unknown Website', 'domain' => 'unknown'];
}

/* --------------------------------
   HANDLE BLOCK ACTION (FROM FORM)
--------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['block_ip'])) {
    // Generate CSRF token if not exists
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $csrf_token = $_POST['csrf_token'] ?? '';
    $stored_token = $_SESSION['csrf_tokens']['block_ip'] ?? '';
    
    if ($csrf_token !== $stored_token || empty($csrf_token)) {
        die('Invalid CSRF token');
    }

    $ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
    $reason = trim($_POST['reason'] ?? 'Manual block by admin');
    $expiry_hours = intval($_POST['expiry_hours'] ?? 24);
    
    // Convert hours to TIME format (HH:MM:SS)
    $expiry_time = sprintf('%02d:00:00', min(720, max(1, $expiry_hours))); // Limit 1-720 hours (30 days)

    if ($ip) {
        try {
            // Check if IP is already blocked for this user/website
            $checkStmt = $pdo->prepare("
                SELECT id FROM blocked_ips 
                WHERE ip = ? AND user_id = ? AND website_id = ?
                AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
            ");
            $checkStmt->execute([$ip, $userId, $websiteId]);
            
            if ($checkStmt->fetch()) {
                // Already blocked
                $block_message = "IP $ip is already blocked for this website.";
                $message_type = "warning";
            } else {
                // Insert new block
                $stmt = $pdo->prepare("
                    INSERT INTO blocked_ips (user_id, ip, website_id, reason, created_at, expiry_time)
                    VALUES (?, ?, ?, ?, NOW(), ?)
                ");
                
                $stmt->execute([$userId, $ip, $websiteId, $reason, $expiry_time]);
                
                // Also log to attack_logs for tracking
                $logStmt = $pdo->prepare("
                    INSERT INTO attack_logs (user_id, website_id, timestamp, attack_type, severity, ip_address, user_agent, attack_payload, request_url)
                    VALUES (?, ?, NOW(), 'MANUAL_BLOCK', 'Medium', ?, ?, ?, 'Block List')
                ");
                $logStmt->execute([$userId, $websiteId, $ip, $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', $reason]);
                
                $block_message = "IP $ip has been blocked successfully.";
                $message_type = "success";
            }
        } catch (PDOException $e) {
            $block_message = "Error blocking IP: " . $e->getMessage();
            $message_type = "danger";
        }
    }
    
    // Clear CSRF token after use
    unset($_SESSION['csrf_tokens']['block_ip']);
}

/* --------------------------------
   HANDLE UNBLOCK
--------------------------------- */
if (isset($_GET['unblock'])) {
    $ip = filter_var($_GET['unblock'], FILTER_VALIDATE_IP);
    
    // Generate CSRF token if not exists
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $csrf_token = $_GET['csrf_token'] ?? '';
    $stored_token = $_SESSION['csrf_tokens']['unblock_ip'] ?? '';
    
    if ($csrf_token !== $stored_token || empty($csrf_token)) {
        die('Invalid CSRF token');
    }

    if ($ip) {
        try {
            $stmt = $pdo->prepare("
                DELETE FROM blocked_ips
                WHERE ip = ? AND user_id = ? AND website_id = ?
            ");
            
            $stmt->execute([$ip, $userId, $websiteId]);
            
            $unblock_message = "IP $ip has been unblocked successfully.";
            $message_type = "success";
            
        } catch (PDOException $e) {
            $unblock_message = "Error unblocking IP: " . $e->getMessage();
            $message_type = "danger";
        }
    }
    
    // Clear CSRF token after use
    unset($_SESSION['csrf_tokens']['unblock_ip']);
}

/* --------------------------------
   HANDLE BULK ACTIONS
--------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['bulk_action'])) {
    // Generate CSRF token if not exists
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $csrf_token = $_POST['csrf_token'] ?? '';
    $stored_token = $_SESSION['csrf_tokens']['bulk_ips'] ?? '';
    
    if ($csrf_token !== $stored_token || empty($csrf_token)) {
        die('Invalid CSRF token');
    }

    $selected_ips = $_POST['selected_ips'] ?? [];
    $bulk_action = $_POST['bulk_action'];
    
    if (!empty($selected_ips) && is_array($selected_ips)) {
        $success_count = 0;
        $error_count = 0;
        
        foreach ($selected_ips as $ip) {
            $ip = filter_var($ip, FILTER_VALIDATE_IP);
            if (!$ip) continue;
            
            try {
                if ($bulk_action === 'unblock') {
                    $stmt = $pdo->prepare("
                        DELETE FROM blocked_ips
                        WHERE ip = ? AND user_id = ? AND website_id = ?
                    ");
                    $stmt->execute([$ip, $userId, $websiteId]);
                } elseif ($bulk_action === 'block') {
                    // Check if already blocked
                    $checkStmt = $pdo->prepare("
                        SELECT id FROM blocked_ips 
                        WHERE ip = ? AND user_id = ? AND website_id = ?
                        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
                    ");
                    $checkStmt->execute([$ip, $userId, $websiteId]);
                    
                    if (!$checkStmt->fetch()) {
                        $stmt = $pdo->prepare("
                            INSERT INTO blocked_ips (user_id, ip, website_id, reason, created_at, expiry_time)
                            VALUES (?, ?, ?, 'Bulk block from list', NOW(), '24:00:00')
                        ");
                        $stmt->execute([$userId, $ip, $websiteId]);
                    } else {
                        continue; // Already blocked
                    }
                }
                
                $success_count++;
                
            } catch (PDOException $e) {
                $error_count++;
            }
        }
        
        $bulk_message = "$success_count IP(s) " . ($bulk_action === 'unblock' ? 'unblocked' : 'blocked') . " successfully.";
        if ($error_count > 0) {
            $bulk_message .= " Failed to process $error_count IP(s).";
        }
        $message_type = $success_count > 0 ? "success" : "warning";
    }
    
    // Clear CSRF token after use
    unset($_SESSION['csrf_tokens']['bulk_ips']);
}

/* --------------------------------
   SEARCH AND FILTERS
--------------------------------- */
$search = trim($_GET['search'] ?? '');
$status_filter = $_GET['status'] ?? 'active'; // active, expired, all
$sort_column = $_GET['sort'] ?? 'created_at';
$sort_order = strtoupper($_GET['order'] ?? 'DESC');

// Valid sort columns
$valid_columns = ['ip', 'reason', 'created_at', 'expiry_time'];
if (!in_array($sort_column, $valid_columns)) $sort_column = 'created_at';
if (!in_array($sort_order, ['ASC', 'DESC'])) $sort_order = 'DESC';

// Build WHERE clause
$where = "WHERE user_id = ? AND website_id = ?";
$params = [$userId, $websiteId];

if ($search !== '') {
    $where .= " AND (ip LIKE ? OR reason LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}

// Add status filter
if ($status_filter === 'active') {
    $where .= " AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())";
} elseif ($status_filter === 'expired') {
    $where .= " AND expiry_time != '00:00:00' AND DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) <= NOW()";
}
// 'all' shows everything

/* --------------------------------
   PAGINATION
--------------------------------- */
$per_page = 20;
$page = max(1, intval($_GET['page'] ?? 1));
$offset = ($page - 1) * $per_page;

/* --------------------------------
   FETCH BLOCKED IPs WITH STATS
--------------------------------- */
try {
    // Get total count for pagination
    $count_query = "SELECT COUNT(*) FROM blocked_ips $where";
    $count_stmt = $pdo->prepare($count_query);
    $count_stmt->execute($params);
    $total = $count_stmt->fetchColumn();
    
    // Get filtered data
    $query = "
        SELECT *,
            CASE 
                WHEN expiry_time = '00:00:00' THEN 'permanent'
                WHEN DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW() THEN 'active'
                ELSE 'expired'
            END as status,
            TIME_TO_SEC(expiry_time) / 3600 as expiry_hours
        FROM blocked_ips
        $where
        ORDER BY $sort_column $sort_order
        LIMIT ? OFFSET ?
    ";
    
    $params_with_limit = array_merge($params, [$per_page, $offset]);
    $stmt = $pdo->prepare($query);
    $stmt->execute($params_with_limit);
    $blocked_ips = $stmt->fetchAll();
    
    $total_pages = ceil($total / $per_page);
    
    // Get statistics
    $stats_query = "
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN expiry_time = '00:00:00' THEN 1 END) as permanent,
            COUNT(CASE WHEN expiry_time != '00:00:00' AND DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW() THEN 1 END) as active_temporary,
            COUNT(CASE WHEN expiry_time != '00:00:00' AND DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) <= NOW() THEN 1 END) as expired
        FROM blocked_ips
        WHERE user_id = ? AND website_id = ?
    ";
    
    $stats_stmt = $pdo->prepare($stats_query);
    $stats_stmt->execute([$userId, $websiteId]);
    $stats = $stats_stmt->fetch();
    
} catch (PDOException $e) {
    $blocked_ips = [];
    $total = 0;
    $total_pages = 1;
    $stats = ['total' => 0, 'permanent' => 0, 'active_temporary' => 0, 'expired' => 0];
    error_log("Database error: " . $e->getMessage());
}

/* --------------------------------
   CSRF TOKENS
--------------------------------- */
if (!isset($_SESSION['csrf_tokens'])) {
    $_SESSION['csrf_tokens'] = [];
}

$csrf_block_token = bin2hex(random_bytes(32));
$_SESSION['csrf_tokens']['block_ip'] = $csrf_block_token;

$csrf_bulk_token = bin2hex(random_bytes(32));
$_SESSION['csrf_tokens']['bulk_ips'] = $csrf_bulk_token;

$csrf_unblock_token = bin2hex(random_bytes(32));
$_SESSION['csrf_tokens']['unblock_ip'] = $csrf_unblock_token;
?>

<!-- Block List Content -->
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-ban me-2 text-danger"></i>Blocked IPs Management</h2>
                <p class="text-muted mb-0">
                    Managing blocked IP addresses for 
                    <strong><?php echo htmlspecialchars($websiteDetails['site_name']); ?></strong>
                    (<code><?php echo htmlspecialchars($websiteDetails['domain']); ?></code>)
                </p>
            </div>
            <div>
                <div class="d-flex gap-2 align-items-center">
                    <a href="user-tracker.php" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-arrow-left me-1"></i> Back to Tracker
                    </a>
                    <a href="web-security.php" class="btn btn-sm btn-outline-info">
                        <i class="fas fa-bug me-1"></i> View Attacks
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-danger">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="text-muted mb-1">Total Blocked</div>
                    <div class="stat-number text-danger"><?php echo $stats['total']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-globe me-1"></i> All time
                    </div>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted d-block">Active Protection</small>
                <div class="progress mt-1" style="height: 5px;">
                    <div class="progress-bar bg-success" style="width: <?php echo $stats['total'] > 0 ? (($stats['permanent'] + $stats['active_temporary']) / $stats['total']) * 100 : 0; ?>%"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-warning">
                        <i class="fas fa-infinity"></i>
                    </div>
                    <div class="text-muted mb-1">Permanent Blocks</div>
                    <div class="stat-number text-warning"><?php echo $stats['permanent']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-lock me-1"></i> No expiry
                    </div>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted d-block">Never expire</small>
                <div class="progress mt-1" style="height: 5px;">
                    <div class="progress-bar bg-warning" style="width: <?php echo $stats['total'] > 0 ? ($stats['permanent'] / $stats['total']) * 100 : 0; ?>%"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-info">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="text-muted mb-1">Temporary</div>
                    <div class="stat-number text-info"><?php echo $stats['active_temporary']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-hourglass-half me-1"></i> Time-limited
                    </div>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted d-block">Will expire</small>
                <div class="progress mt-1" style="height: 5px;">
                    <div class="progress-bar bg-info" style="width: <?php echo $stats['total'] > 0 ? ($stats['active_temporary'] / $stats['total']) * 100 : 0; ?>%"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-secondary">
                        <i class="fas fa-hourglass-end"></i>
                    </div>
                    <div class="text-muted mb-1">Expired</div>
                    <div class="stat-number text-secondary"><?php echo $stats['expired']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-history me-1"></i> Auto-removed
                    </div>
                </div>
            </div>
            <div class="mt-3">
                <small class="text-muted d-block">Auto cleanup</small>
                <div class="progress mt-1" style="height: 5px;">
                    <div class="progress-bar bg-secondary" style="width: <?php echo $stats['total'] > 0 ? ($stats['expired'] / $stats['total']) * 100 : 0; ?>%"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Block New IP Form -->
    <div class="col-xl-4">
        <div class="dashboard-card h-100">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-plus-circle me-2 text-success"></i>Block New IP</h5>
            </div>
            
            <?php if (isset($block_message)): ?>
                <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show">
                    <i class="fas fa-<?php echo $message_type == 'success' ? 'check-circle' : ($message_type == 'warning' ? 'exclamation-triangle' : 'times-circle'); ?> me-2"></i>
                    <?php echo htmlspecialchars($block_message); ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if (isset($_SESSION['flash_message'])): ?>
                <div class="alert alert-<?php echo $_SESSION['flash_type']; ?> alert-dismissible fade show">
                    <i class="fas fa-<?php echo $_SESSION['flash_type'] == 'success' ? 'check-circle' : ($_SESSION['flash_type'] == 'warning' ? 'exclamation-triangle' : 'times-circle'); ?> me-2"></i>
                    <?php echo htmlspecialchars($_SESSION['flash_message']); ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
                <?php unset($_SESSION['flash_message'], $_SESSION['flash_type']); ?>
            <?php endif; ?>
            
            <?php if (isset($unblock_message)): ?>
                <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show">
                    <i class="fas fa-<?php echo $message_type == 'success' ? 'check-circle' : 'times-circle'; ?> me-2"></i>
                    <?php echo htmlspecialchars($unblock_message); ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if (isset($bulk_message)): ?>
                <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show">
                    <i class="fas fa-<?php echo $message_type == 'success' ? 'check-circle' : 'exclamation-triangle'; ?> me-2"></i>
                    <?php echo htmlspecialchars($bulk_message); ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <form method="POST" id="blockForm">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_block_token; ?>">
                
                <div class="mb-3">
                    <label for="ip" class="form-label">IP Address</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-network-wired"></i></span>
                        <input type="text" class="form-control" id="ip" name="ip" 
                               placeholder="e.g., 192.168.1.1" required
                               value="<?php echo isset($_GET['suggest_ip']) ? htmlspecialchars($_GET['suggest_ip']) : ''; ?>">
                    </div>
                    <div class="form-text">Enter a valid IPv4 address</div>
                </div>
                
                <div class="mb-3">
                    <label for="expiry_hours" class="form-label">Block Duration</label>
                    <select class="form-control" id="expiry_hours" name="expiry_hours">
                        <option value="1">1 Hour</option>
                        <option value="6">6 Hours</option>
                        <option value="24" selected>24 Hours</option>
                        <option value="168">7 Days</option>
                        <option value="720">30 Days</option>
                        <option value="0">Permanent</option>
                    </select>
                </div>
                
                <div class="mb-3">
                    <label for="reason" class="form-label">Reason</label>
                    <textarea class="form-control" id="reason" name="reason" 
                              rows="3" placeholder="Reason for blocking this IP..."><?php 
                        echo isset($_GET['suggest_reason']) ? htmlspecialchars($_GET['suggest_reason']) : ''; 
                    ?></textarea>
                </div>
                
                <div class="d-grid gap-2">
                    <button type="submit" name="block_ip" class="btn btn-danger">
                        <i class="fas fa-ban me-2"></i>Block IP Address
                    </button>
                    <button type="button" class="btn btn-outline-secondary" onclick="document.getElementById('blockForm').reset()">
                        <i class="fas fa-times me-2"></i>Clear Form
                    </button>
                </div>
            </form>
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-info-circle me-2 text-info"></i>Quick Actions</h6>
                <div class="d-grid gap-2">
                    <button type="button" class="btn btn-outline-info" onclick="suggestRecentAttacker()">
                        <i class="fas fa-bolt me-2"></i> Suggest Recent Attacker
                    </button>
                    <button type="button" class="btn btn-outline-warning" onclick="suggestVPNUser()">
                        <i class="fas fa-user-secret me-2"></i> Suggest VPN User
                    </button>
                    <a href="user-tracker.php" class="btn btn-outline-primary">
                        <i class="fas fa-search me-2"></i> Browse User Tracker
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Blocked IPs List -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2 text-primary"></i>Blocked IP Addresses</h5>
                
                <div class="d-flex gap-2">
                    <form method="GET" class="d-flex">
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-search"></i></span>
                            <input type="text" class="form-control" name="search" 
                                   placeholder="Search IPs or reasons..." 
                                   value="<?= htmlspecialchars($search) ?>"
                                   style="width: 250px;">
                            <select class="form-control" name="status" onchange="this.form.submit()" style="width: auto;">
                                <option value="active" <?= $status_filter === 'active' ? 'selected' : ''; ?>>Active</option>
                                <option value="expired" <?= $status_filter === 'expired' ? 'selected' : ''; ?>>Expired</option>
                                <option value="all" <?= $status_filter === 'all' ? 'selected' : ''; ?>>All</option>
                            </select>
                            <?php if (!empty($search) || $status_filter !== 'active'): ?>
                                <a href="block-list.php" class="btn btn-outline-danger">
                                    <i class="fas fa-times"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Bulk Actions Bar -->
            <div class="mb-3" id="bulkActions" style="display: none;">
                <div class="bg-dark rounded p-3 border border-secondary">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <strong id="selectedCount">0</strong> IP(s) selected
                        </div>
                        <div class="btn-group">
                            <form method="POST" class="d-inline">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_bulk_token; ?>">
                                <input type="hidden" name="bulk_action" value="unblock">
                                <div id="bulkSelectedIps"></div>
                                <button type="submit" class="btn btn-sm btn-success" onclick="return confirm('Unblock selected IPs?')">
                                    <i class="fas fa-unlock me-1"></i> Unblock Selected
                                </button>
                            </form>
                            <button class="btn btn-sm btn-outline-secondary" onclick="clearSelection()">
                                <i class="fas fa-times me-1"></i> Clear
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <?php if (!empty($blocked_ips)): ?>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th width="50">
                                <input type="checkbox" id="selectAll" onchange="toggleSelectAll(this)">
                            </th>
                            <th class="sortable" onclick="sortTable('ip')">
                                IP Address 
                                <?php if ($sort_column == 'ip'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th>Reason</th>
                            <th class="sortable" onclick="sortTable('created_at')">
                                Date Blocked 
                                <?php if ($sort_column == 'created_at'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th class="sortable" onclick="sortTable('expiry_time')">
                                Status 
                                <?php if ($sort_column == 'expiry_time'): ?>
                                    <i class="fas fa-arrow-<?php echo $sort_order == 'ASC' ? 'up' : 'down'; ?> ms-1"></i>
                                <?php endif; ?>
                            </th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocked_ips as $row): 
                            $status = $row['status'] ?? 'active';
                            $status_class = $status === 'permanent' ? 'warning' : ($status === 'active' ? 'success' : 'secondary');
                            $status_text = $status === 'permanent' ? 'Permanent' : ($status === 'active' ? 'Active' : 'Expired');
                        ?>
                        <tr>
                            <td>
                                <input type="checkbox" class="ip-checkbox" value="<?= htmlspecialchars($row['ip']) ?>" 
                                       onchange="updateBulkActions()">
                            </td>
                            <td>
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-network-wired text-muted me-2"></i>
                                    <code class="badge bg-dark"><?= htmlspecialchars($row['ip']) ?></code>
                                </div>
                            </td>
                            <td>
                                <span class="text-truncate d-inline-block" style="max-width: 200px;" 
                                      title="<?= htmlspecialchars($row['reason']) ?>">
                                    <?= htmlspecialchars($row['reason']) ?>
                                </span>
                            </td>
                            <td>
                                <div>
                                    <small><?= date('M d, Y', strtotime($row['created_at'])) ?></small><br>
                                    <small class="text-muted"><?= date('H:i', strtotime($row['created_at'])) ?></small>
                                </div>
                            </td>
                            <td>
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-<?= $status_class ?> me-2">
                                        <i class="fas fa-<?= $status === 'permanent' ? 'infinity' : ($status === 'active' ? 'clock' : 'hourglass-end'); ?> me-1"></i>
                                        <?= $status_text ?>
                                    </span>
                                    <?php if ($status === 'active' && $row['expiry_hours'] > 0): ?>
                                        <small class="text-muted">
                                            <?= round($row['expiry_hours']) ?>h left
                                        </small>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td>
                                <div class="btn-group btn-group-sm">
                                    <button class="btn btn-outline-info" 
                                            onclick="viewIPDetails('<?= htmlspecialchars($row['ip']) ?>')"
                                            title="View Details">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <a href="block-list.php?unblock=<?= urlencode($row['ip']) ?>&csrf_token=<?= $csrf_unblock_token ?>" 
                                       class="btn btn-outline-success"
                                       onclick="return confirm('Are you sure you want to unblock this IP?')"
                                       title="Unblock">
                                        <i class="fas fa-unlock"></i>
                                    </a>
                                    <a href="user-tracker.php?search=<?= urlencode($row['ip']) ?>" 
                                       class="btn btn-outline-primary"
                                       title="Search in Tracker">
                                        <i class="fas fa-search"></i>
                                    </a>
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
    <nav aria-label="Blocked IPs pagination">
        <ul class="pagination justify-content-center">
            <?php if ($page > 1): ?>
                <li class="page-item">
                    <a class="page-link" href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status_filter ?>&sort=<?= $sort_column ?>&order=<?= $sort_order ?>" 
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
                <li class="page-item <?= $i == $page ? 'active' : '' ?>">
                    <a class="page-link" href="?page=<?= $i ?>&search=<?= urlencode($search) ?>&status=<?= $status_filter ?>&sort=<?= $sort_column ?>&order=<?= $sort_order ?>">
                        <?= $i ?>
                    </a>
                </li>
            <?php endfor; ?>
            
            <?php if ($page < $total_pages): ?>
                <li class="page-item">
                    <a class="page-link" href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status_filter ?>&sort=<?= $sort_column ?>&order=<?= $sort_order ?>" 
                       aria-label="Next">
                        <span aria-hidden="true">&raquo;</span>
                    </a>
                </li>
            <?php endif; ?>
        </ul>
    </nav>
</div>
<?php endif; ?>
            
            <!-- Export and Tools -->
            <div class="mt-4 pt-3 border-top">
                <div class="d-flex justify-content-between align-items-center">
                    <div class="text-muted small">
                        Showing <?= count($blocked_ips) ?> of <?= $total ?> blocked IPs
                        <?php if ($status_filter !== 'all'): ?>
                            (filtered by status: <?= $status_filter ?>)
                        <?php endif; ?>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-warning" onclick="cleanExpiredIPs()">
                            <i class="fas fa-broom me-1"></i> Clean Expired
                        </button>
                    </div>
                </div>
            </div>
            
            <?php else: ?>
            <div class="text-center py-5">
                <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                <h5>No blocked IPs found</h5>
                <p class="text-muted">
                    <?php if ($search || $status_filter !== 'active'): ?>
                        Try adjusting your filters
                    <?php else: ?>
                        Start by blocking your first IP address
                    <?php endif; ?>
                </p>
                <?php if ($search || $status_filter !== 'active'): ?>
                    <a href="block-list.php" class="btn btn-outline-secondary mt-2">
                        <i class="fas fa-times me-2"></i>Clear Filters
                    </a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-info-circle me-2"></i>IP Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="ipDetailsContent">
                Loading IP details...
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-danger" onclick="blockIPFromModal()">
                    <i class="fas fa-ban me-1"></i> Block This IP
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
$(document).ready(function() {
    // Toggle select all checkboxes
    window.toggleSelectAll = function(source) {
        const checkboxes = document.getElementsByClassName('ip-checkbox');
        for (let i = 0; i < checkboxes.length; i++) {
            checkboxes[i].checked = source.checked;
        }
        updateBulkActions();
    }

    // Update bulk actions bar
    window.updateBulkActions = function() {
        const checkboxes = document.getElementsByClassName('ip-checkbox');
        let selectedCount = 0;
        let selectedIps = [];
        
        for (let i = 0; i < checkboxes.length; i++) {
            if (checkboxes[i].checked) {
                selectedCount++;
                selectedIps.push(checkboxes[i].value);
            }
        }
        
        document.getElementById('selectedCount').textContent = selectedCount;
        document.getElementById('bulkActions').style.display = selectedCount > 0 ? 'block' : 'none';
        
        // Update hidden input for bulk form
        const bulkDiv = document.getElementById('bulkSelectedIps');
        bulkDiv.innerHTML = '';
        selectedIps.forEach(ip => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'selected_ips[]';
            input.value = ip;
            bulkDiv.appendChild(input);
        });
        
        // Update select all checkbox
        document.getElementById('selectAll').checked = selectedCount === checkboxes.length;
    }

    // Clear selection
    window.clearSelection = function() {
        const checkboxes = document.getElementsByClassName('ip-checkbox');
        for (let i = 0; i < checkboxes.length; i++) {
            checkboxes[i].checked = false;
        }
        document.getElementById('selectAll').checked = false;
        updateBulkActions();
    }

    // View IP details
    window.viewIPDetails = function(ip) {
        $('#ipDetailsContent').html(`
            <div class="text-center py-4">
                <div class="spinner-border" role="status"></div>
                <p class="mt-2">Loading IP information...</p>
            </div>
        `);
        
        const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
        modal.show();
        
        // Store IP for blocking
        window.currentIP = ip;
        
        // Fetch IP details using AJAX
        $.ajax({
            url: '../api/get-ip-info.php',
            method: 'GET',
            data: { ip: ip },
            success: function(response) {
                if (response.success) {
                    const data = response.data;
                    let detailsHtml = `
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card bg-dark border-secondary mb-3">
                                    <div class="card-body">
                                        <h6><i class="fas fa-network-wired me-2"></i>IP Information</h6>
                                        <table class="table table-sm table-dark mb-0">
                                            <tr><td><strong>IP Address:</strong></td><td><code>${data.ip}</code></td></tr>
                                            <tr><td><strong>Country:</strong></td><td>${data.country || 'Unknown'}</td></tr>
                                            <tr><td><strong>ISP:</strong></td><td>${data.isp || 'Unknown'}</td></tr>
                                            <tr><td><strong>ASN:</strong></td><td>${data.asn || 'Unknown'}</td></tr>
                                            <tr><td><strong>Block Status:</strong></td>
                                                <td>
                                                    ${data.is_blocked ? 
                                                        '<span class="badge bg-danger">Currently Blocked</span>' : 
                                                        '<span class="badge bg-success">Not Blocked</span>'}
                                                </td>
                                            </tr>
                                        </table>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card bg-dark border-secondary mb-3">
                                    <div class="card-body">
                                        <h6><i class="fas fa-history me-2"></i>Recent Activity</h6>
                                        <table class="table table-sm table-dark mb-0">
                                            <tr><td><strong>Last Seen:</strong></td><td>${data.last_seen || 'Never'}</td></tr>
                                            <tr><td><strong>Total Visits:</strong></td><td><span class="badge bg-info">${data.visit_count || 0}</span></td></tr>
                                            <tr><td><strong>Attack Count:</strong></td><td><span class="badge bg-danger">${data.attack_count || 0}</span></td></tr>
                                            <tr><td><strong>VPN/Proxy:</strong></td>
                                                <td>
                                                    ${data.is_vpn ? '<span class="badge bg-warning">VPN</span>' : 
                                                      data.is_proxy ? '<span class="badge bg-danger">Proxy</span>' : 
                                                      '<span class="badge bg-success">Direct</span>'}
                                                </td>
                                            </tr>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    $('#ipDetailsContent').html(detailsHtml);
                } else {
                    $('#ipDetailsContent').html(`
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ${response.message || 'Failed to load IP details.'}
                        </div>
                    `);
                }
            },
            error: function() {
                $('#ipDetailsContent').html(`
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Failed to load IP details. Please try again.
                    </div>
                `);
            }
        });
    }

    // Block IP from modal
    window.blockIPFromModal = function() {
        const ip = window.currentIP;
        if (ip) {
            window.location.href = `block-list.php?ip=${encodeURIComponent(ip)}`;
        }
    }

    // Suggest recent attacker
    window.suggestRecentAttacker = function() {
        Swal.fire({
            title: 'Finding recent attacker...',
            text: 'Please wait',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        $.ajax({
            url: '../api/get-recent-attacker.php',
            method: 'GET',
            success: function(response) {
                Swal.close();
                if (response.success && response.ip) {
                    $('#ip').val(response.ip);
                    $('#reason').val('Recent attacker - ' + response.reason);
                    Swal.fire({
                        title: 'IP Suggestion',
                        text: `Suggested IP: ${response.ip} - ${response.reason}`,
                        icon: 'info',
                        confirmButtonText: 'Block This IP'
                    });
                } else {
                    Swal.fire({
                        title: 'No Suggestions',
                        text: 'No recent attackers found to suggest.',
                        icon: 'info'
                    });
                }
            },
            error: function() {
                Swal.fire({
                    title: 'Error',
                    text: 'Failed to fetch suggestions.',
                    icon: 'error'
                });
            }
        });
    }

    // Suggest VPN user
    window.suggestVPNUser = function() {
        Swal.fire({
            title: 'Finding VPN users...',
            text: 'Please wait',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        $.ajax({
            url: '../api/get-vpn-user.php',
            method: 'GET',
            success: function(response) {
                Swal.close();
                if (response.success && response.ip) {
                    $('#ip').val(response.ip);
                    $('#reason').val('VPN/Proxy user detected');
                    Swal.fire({
                        title: 'VPN User Found',
                        html: `Suggested IP: ${response.ip}<br>Country: ${response.country}<br>ISP: ${response.isp}`,
                        icon: 'warning',
                        confirmButtonText: 'Block This VPN User'
                    });
                } else {
                    Swal.fire({
                        title: 'No VPN Users',
                        text: 'No VPN users found to suggest.',
                        icon: 'info'
                    });
                }
            },
            error: function() {
                Swal.fire({
                    title: 'Error',
                    text: 'Failed to fetch VPN users.',
                    icon: 'error'
                });
            }
        });
    }

    // Clean expired IPs
    window.cleanExpiredIPs = function() {
        Swal.fire({
            title: 'Clean Expired IPs?',
            text: 'This will permanently remove all expired IP blocks. This action cannot be undone.',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, clean them',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                window.location.href = 'block-list.php?clean_expired=true';
            }
        });
    }

    // Sort table
    window.sortTable = function(column) {
        const urlParams = new URLSearchParams(window.location.search);
        let order = 'DESC';
        
        if (urlParams.get('sort') === column && urlParams.get('order') === 'DESC') {
            order = 'ASC';
        }
        
        let queryString = `?sort=${column}&order=${order}`;
        
        const search = urlParams.get('search');
        if (search) {
            queryString += `&search=${encodeURIComponent(search)}`;
        }
        
        const status = urlParams.get('status') || 'active';
        queryString += `&status=${status}`;
        
        const page = urlParams.get('page') || '1';
        queryString += `&page=${page}`;
        
        window.location.href = queryString;
    }
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

.sortable {
    cursor: pointer;
    position: relative;
    padding-right: 25px !important;
}

.sortable:hover {
    background-color: rgba(0, 123, 255, 0.1);
}

.table-hover > tbody > tr:hover {
    background-color: rgba(0, 123, 255, 0.1);
}

.progress {
    background-color: #2a2a2a;
    border-radius: 10px;
}

.progress-bar {
    border-radius: 10px;
}

code {
    background: #111;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 0.9em;
    color: #4ea1ff;
}

.badge {
    font-weight: 600;
    padding: 0.35em 0.65em;
}

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

#bulkActions {
    animation: slideDown 0.3s ease;
}

@keyframes slideDown {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@media (max-width: 768px) {
    .stat-number {
        font-size: 2.2rem;
    }
    
    .card-icon {
        font-size: 2rem;
    }
}
</style>

<?php
// End output buffering and flush
ob_end_flush();
require_once '../includes/footer.php';
?>