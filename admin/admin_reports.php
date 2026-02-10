<?php
// admin_reports.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

// Initialize variables
$report_type = $_GET['type'] ?? 'overview';
$date_from = $_GET['date_from'] ?? date('Y-m-01'); // First day of current month
$date_to = $_GET['date_to'] ?? date('Y-m-d');
$website_id = $_GET['website_id'] ?? '';
$user_id = $_GET['user_id'] ?? '';

// Handle report generation
$action = $_GET['action'] ?? '';
$success_msg = '';
$error_msg = '';

if ($action === 'generate') {
    // Validate dates
    if (strtotime($date_from) > strtotime($date_to)) {
        $error_msg = "Start date cannot be after end date.";
    } else {
        // Generate report data based on type
        $report_data = generateReportData($pdo, $report_type, $date_from, $date_to, $website_id, $user_id);
        $success_msg = "Report generated successfully for " . date('F j, Y', strtotime($date_from)) . 
                      " to " . date('F j, Y', strtotime($date_to));
    }
}

// Get websites for filter
$websites = [];
try {
    $stmt = $pdo->query("SELECT id, domain, site_name FROM websites WHERE status = 'active' ORDER BY domain");
    $websites = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Error fetching websites: " . $e->getMessage());
}

// Get users for filter
$users = [];
try {
    $stmt = $pdo->query("SELECT id, username, email FROM users WHERE status = 'active' ORDER BY username");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Error fetching users: " . $e->getMessage());
}

// Generate report data
$report_data = generateReportData($pdo, $report_type, $date_from, $date_to, $website_id, $user_id);

// Helper function to generate report data
function generateReportData($pdo, $type, $date_from, $date_to, $website_id = '', $user_id = '') {
    $data = [];
    $conditions = [];
    $params = [];
    
    // Common date conditions
    $conditions[] = "DATE(timestamp) BETWEEN ? AND ?";
    $params[] = $date_from;
    $params[] = $date_to;
    
    if (!empty($website_id)) {
        $conditions[] = "website_id = ?";
        $params[] = $website_id;
    }
    
    if (!empty($user_id)) {
        $conditions[] = "user_id = ?";
        $params[] = $user_id;
    }
    
    $where_clause = !empty($conditions) ? "WHERE " . implode(" AND ", $conditions) : "";
    
    switch ($type) {
        case 'overview':
            $data = generateOverviewReport($pdo, $where_clause, $params);
            break;
            
        case 'security':
            $data = generateSecurityReport($pdo, $where_clause, $params);
            break;
            
        case 'traffic':
            $data = generateTrafficReport($pdo, $where_clause, $params);
            break;
            
        case 'users':
            $data = generateUsersReport($pdo, $where_clause, $params);
            break;
            
        case 'system':
            $data = generateSystemReport($pdo, $where_clause, $params);
            break;
            
        default:
            $data = generateOverviewReport($pdo, $where_clause, $params);
    }
    
    return $data;
}

function generateOverviewReport($pdo, $where_clause, $params) {
    $data = [];
    
    try {
        // Total visits
        $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM logs $where_clause");
        $stmt->execute($params);
        $data['total_visits'] = $stmt->fetch()['total'];
        
        // Unique visitors
        $stmt = $pdo->prepare("SELECT COUNT(DISTINCT ip) as total FROM logs $where_clause");
        $stmt->execute($params);
        $data['unique_visitors'] = $stmt->fetch()['total'];
        
        // Attack attempts
        $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM attack_logs $where_clause");
        $stmt->execute($params);
        $data['attack_attempts'] = $stmt->fetch()['total'];
        
        // Blocked IPs
        $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM blocked_ips $where_clause");
        $stmt->execute($params);
        $data['blocked_ips'] = $stmt->fetch()['total'];
        
        // Active users
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT user_id) as total 
            FROM logs 
            WHERE DATE(timestamp) BETWEEN ? AND ?
        ");
        $stmt->execute([$params[0], $params[1]]);
        $data['active_users'] = $stmt->fetch()['total'];
        
        // Daily traffic
        $stmt = $pdo->prepare("
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as visits,
                COUNT(DISTINCT ip) as unique_visitors
            FROM logs 
            $where_clause
            GROUP BY DATE(timestamp)
            ORDER BY date
        ");
        $stmt->execute($params);
        $data['daily_traffic'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error generating overview report: " . $e->getMessage());
    }
    
    return $data;
}

function generateSecurityReport($pdo, $where_clause, $params) {
    $data = [];
    
    try {
        // Attack types distribution
        $stmt = $pdo->prepare("
            SELECT 
                attack_type,
                COUNT(*) as count,
                severity
            FROM attack_logs 
            $where_clause
            GROUP BY attack_type, severity
            ORDER BY count DESC
        ");
        $stmt->execute($params);
        $data['attack_types'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Top attacking IPs
        $stmt = $pdo->prepare("
            SELECT 
                ip_address,
                COUNT(*) as attack_count,
                GROUP_CONCAT(DISTINCT attack_type) as attack_types
            FROM attack_logs 
            $where_clause
            GROUP BY ip_address
            ORDER BY attack_count DESC
            LIMIT 10
        ");
        $stmt->execute($params);
        $data['top_attackers'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Severity breakdown
        $stmt = $pdo->prepare("
            SELECT 
                severity,
                COUNT(*) as count
            FROM attack_logs 
            $where_clause
            GROUP BY severity
            ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Info')
        ");
        $stmt->execute($params);
        $data['severity_breakdown'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Blocked IPs analysis
        $stmt = $pdo->prepare("
            SELECT 
                reason,
                COUNT(*) as count,
                COUNT(DISTINCT ip) as unique_ips
            FROM blocked_ips 
            $where_clause
            GROUP BY reason
            ORDER BY count DESC
        ");
        $stmt->execute($params);
        $data['block_reasons'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error generating security report: " . $e->getMessage());
    }
    
    return $data;
}

function generateTrafficReport($pdo, $where_clause, $params) {
    $data = [];
    
    try {
        // Hourly traffic pattern
        $stmt = $pdo->prepare("
            SELECT 
                HOUR(timestamp) as hour,
                COUNT(*) as visits
            FROM logs 
            $where_clause
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        ");
        $stmt->execute($params);
        $data['hourly_traffic'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Top countries
        $stmt = $pdo->prepare("
            SELECT 
                country,
                COUNT(*) as visits,
                COUNT(DISTINCT ip) as unique_visitors
            FROM logs 
            WHERE country != 'Unknown' $where_clause
            GROUP BY country
            ORDER BY visits DESC
            LIMIT 10
        ");
        $stmt->execute(array_slice($params, 2)); // Remove date params already in where_clause
        $data['top_countries'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Browser distribution
        $stmt = $pdo->prepare("
            SELECT 
                CASE 
                    WHEN user_agent LIKE '%Chrome%' THEN 'Chrome'
                    WHEN user_agent LIKE '%Firefox%' THEN 'Firefox'
                    WHEN user_agent LIKE '%Safari%' AND user_agent NOT LIKE '%Chrome%' THEN 'Safari'
                    WHEN user_agent LIKE '%Edge%' THEN 'Edge'
                    WHEN user_agent LIKE '%Opera%' THEN 'Opera'
                    ELSE 'Other'
                END as browser,
                COUNT(*) as count
            FROM logs 
            WHERE user_agent IS NOT NULL $where_clause
            GROUP BY browser
            ORDER BY count DESC
        ");
        $stmt->execute(array_slice($params, 2));
        $data['browser_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Device types
        $stmt = $pdo->prepare("
            SELECT 
                CASE 
                    WHEN screen_resolution LIKE '%768%' THEN 'Mobile'
                    WHEN screen_resolution LIKE '%1024%' THEN 'Tablet'
                    ELSE 'Desktop'
                END as device_type,
                COUNT(*) as count
            FROM logs 
            WHERE screen_resolution != 'Unknown' $where_clause
            GROUP BY device_type
            ORDER BY count DESC
        ");
        $stmt->execute(array_slice($params, 2));
        $data['device_types'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error generating traffic report: " . $e->getMessage());
    }
    
    return $data;
}

function generateUsersReport($pdo, $where_clause, $params) {
    $data = [];
    
    try {
        // User activity
        $stmt = $pdo->prepare("
            SELECT 
                u.username,
                u.email,
                u.role,
                COUNT(DISTINCT l.id) as logins,
                COUNT(DISTINCT w.id) as websites,
                MAX(l.timestamp) as last_activity
            FROM users u
            LEFT JOIN logs l ON u.id = l.user_id AND DATE(l.timestamp) BETWEEN ? AND ?
            LEFT JOIN websites w ON u.id = w.user_id
            WHERE u.role IN ('viewer', 'analyst', 'admin')
            GROUP BY u.id
            ORDER BY logins DESC
        ");
        $stmt->execute([$params[0], $params[1]]);
        $data['user_activity'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // New users
        $stmt = $pdo->prepare("
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as new_users,
                GROUP_CONCAT(username SEPARATOR ', ') as users
            FROM users 
            WHERE DATE(created_at) BETWEEN ? AND ?
            AND role IN ('viewer', 'analyst', 'admin')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        ");
        $stmt->execute([$params[0], $params[1]]);
        $data['new_users'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error generating users report: " . $e->getMessage());
    }
    
    return $data;
}

function generateSystemReport($pdo, $where_clause, $params) {
    $data = [];
    
    try {
        // System performance
        $data['total_records'] = [
            'logs' => getTableCount($pdo, 'logs', $where_clause, $params),
            'attack_logs' => getTableCount($pdo, 'attack_logs', $where_clause, $params),
            'blocked_ips' => getTableCount($pdo, 'blocked_ips', $where_clause, $params),
            'users' => getTableCount($pdo, 'users', '', []),
            'websites' => getTableCount($pdo, 'websites', '', [])
        ];
        
        // Database size (estimate)
        $stmt = $pdo->query("
            SELECT 
                table_name,
                ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
            FROM information_schema.TABLES 
            WHERE table_schema = DATABASE()
            ORDER BY size_mb DESC
        ");
        $data['database_size'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Peak usage times
        $stmt = $pdo->prepare("
            SELECT 
                DATE(timestamp) as date,
                HOUR(timestamp) as hour,
                COUNT(*) as requests
            FROM logs 
            $where_clause
            GROUP BY DATE(timestamp), HOUR(timestamp)
            ORDER BY requests DESC
            LIMIT 10
        ");
        $stmt->execute($params);
        $data['peak_usage'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error generating system report: " . $e->getMessage());
    }
    
    return $data;
}

function getTableCount($pdo, $table, $where_clause, $params) {
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM $table $where_clause");
        $stmt->execute($params);
        return $stmt->fetch()['count'];
    } catch (PDOException $e) {
        return 0;
    }
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Reports</title>
    <!-- Include same CSS as admin_dashboard.php -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <!-- Include Navbar and Sidebar -->
    <?php include 'includes/admin_navbar.php'; ?>
    <?php include 'includes/admin_sidebar.php'; ?>
    
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1"><i class="bi bi-bar-chart me-2"></i>Reports & Analytics</h2>
                <p class="text-muted mb-0">Generate insights and analytics from your security data</p>
            </div>
            <div>
                <button type="button" class="btn btn-admin btn-admin-primary" onclick="exportReport()">
                    <i class="bi bi-download me-1"></i>Export Report
                </button>
            </div>
        </div>
        
        <!-- Alerts -->
        <?php if ($success_msg): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill me-2"></i>
                <?= htmlspecialchars($success_msg) ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error_msg): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <?= htmlspecialchars($error_msg) ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <!-- Report Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3" id="reportForm">
                <div class="col-md-3">
                    <label class="form-label">Report Type</label>
                    <select class="form-select" name="type" id="reportType">
                        <option value="overview" <?= $report_type === 'overview' ? 'selected' : '' ?>>Overview</option>
                        <option value="security" <?= $report_type === 'security' ? 'selected' : '' ?>>Security Analysis</option>
                        <option value="traffic" <?= $report_type === 'traffic' ? 'selected' : '' ?>>Traffic Analysis</option>
                        <option value="users" <?= $report_type === 'users' ? 'selected' : '' ?>>User Activity</option>
                        <option value="system" <?= $report_type === 'system' ? 'selected' : '' ?>>System Performance</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">From Date</label>
                    <input type="date" class="form-control" name="date_from" 
                           value="<?= htmlspecialchars($date_from) ?>" 
                           max="<?= date('Y-m-d') ?>">
                </div>
                <div class="col-md-2">
                    <label class="form-label">To Date</label>
                    <input type="date" class="form-control" name="date_to" 
                           value="<?= htmlspecialchars($date_to) ?>"
                           max="<?= date('Y-m-d') ?>">
                </div>
                <div class="col-md-2">
                    <label class="form-label">Website</label>
                    <select class="form-select" name="website_id">
                        <option value="">All Websites</option>
                        <?php foreach ($websites as $website): ?>
                            <option value="<?= $website['id'] ?>" <?= $website_id == $website['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($website['domain']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label">User</label>
                    <select class="form-select" name="user_id">
                        <option value="">All Users</option>
                        <?php foreach ($users as $user): ?>
                            <option value="<?= $user['id'] ?>" <?= $user_id == $user['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($user['username']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-1">
                    <label class="form-label">&nbsp;</label>
                    <button type="submit" name="action" value="generate" class="btn btn-primary w-100">
                        <i class="bi bi-play-fill"></i>
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Report Content -->
        <div id="reportContent">
            <?php if ($report_type === 'overview'): ?>
                <!-- Overview Report -->
                <div class="row g-4 mb-4">
                    <!-- Key Metrics -->
                    <div class="col-md-3">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-primary">
                                <i class="bi bi-eye"></i>
                            </div>
                            <div class="stat-value"><?= number_format($report_data['total_visits'] ?? 0) ?></div>
                            <div class="stat-label">Total Visits</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-success">
                                <i class="bi bi-people"></i>
                            </div>
                            <div class="stat-value"><?= number_format($report_data['unique_visitors'] ?? 0) ?></div>
                            <div class="stat-label">Unique Visitors</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-danger">
                                <i class="bi bi-shield-exclamation"></i>
                            </div>
                            <div class="stat-value"><?= number_format($report_data['attack_attempts'] ?? 0) ?></div>
                            <div class="stat-label">Attack Attempts</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-warning">
                                <i class="bi bi-ban"></i>
                            </div>
                            <div class="stat-value"><?= number_format($report_data['blocked_ips'] ?? 0) ?></div>
                            <div class="stat-label">Blocked IPs</div>
                        </div>
                    </div>
                </div>
                
                <!-- Traffic Chart -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-graph-up me-2"></i>Daily Traffic Overview</h5>
                    <div class="chart-container" style="height: 300px;">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
                
                <!-- Recent Activity -->
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-calendar-week me-2"></i>Daily Breakdown</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Visits</th>
                                    <th>Unique Visitors</th>
                                    <th>Avg. Per Visitor</th>
                                    <th>Trend</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($report_data['daily_traffic'] ?? [] as $day): ?>
                                    <tr>
                                        <td><?= date('M j, Y', strtotime($day['date'])) ?></td>
                                        <td><?= number_format($day['visits']) ?></td>
                                        <td><?= number_format($day['unique_visitors']) ?></td>
                                        <td><?= $day['unique_visitors'] > 0 ? round($day['visits'] / $day['unique_visitors'], 1) : 0 ?></td>
                                        <td>
                                            <?php 
                                            $ratio = $day['unique_visitors'] > 0 ? $day['visits'] / $day['unique_visitors'] : 0;
                                            if ($ratio > 3): ?>
                                                <span class="badge bg-success">High Engagement</span>
                                            <?php elseif ($ratio > 1): ?>
                                                <span class="badge bg-info">Normal</span>
                                            <?php else: ?>
                                                <span class="badge bg-warning">Low</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['daily_traffic'])): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-3 text-muted">
                                            No traffic data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
            <?php elseif ($report_type === 'security'): ?>
                <!-- Security Report -->
                <div class="row g-4 mb-4">
                    <!-- Attack Types Distribution -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-pie-chart me-2"></i>Attack Types Distribution</h5>
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="attackTypesChart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Severity Breakdown -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-shield-exclamation me-2"></i>Severity Breakdown</h5>
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Top Attackers -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-list-ol me-2"></i>Top Attacking IPs</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Attack Count</th>
                                    <th>Attack Types</th>
                                    <th>Threat Level</th>
                                    <th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($report_data['top_attackers'] ?? [] as $attacker): ?>
                                    <tr>
                                        <td><code><?= htmlspecialchars($attacker['ip_address']) ?></code></td>
                                        <td><span class="badge bg-danger"><?= $attacker['attack_count'] ?></span></td>
                                        <td><small><?= htmlspecialchars($attacker['attack_types']) ?></small></td>
                                        <td>
                                            <?php if ($attacker['attack_count'] > 10): ?>
                                                <span class="badge bg-danger">Critical</span>
                                            <?php elseif ($attacker['attack_count'] > 5): ?>
                                                <span class="badge bg-warning">High</span>
                                            <?php else: ?>
                                                <span class="badge bg-info">Medium</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?= date('Y-m-d H:i') ?></td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['top_attackers'])): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-3 text-muted">
                                            No attack data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Block Reasons -->
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-ban me-2"></i>Block Reasons Analysis</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>Reason</th>
                                    <th>Block Count</th>
                                    <th>Unique IPs</th>
                                    <th>Percentage</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $total_blocks = array_sum(array_column($report_data['block_reasons'] ?? [], 'count'));
                                foreach ($report_data['block_reasons'] ?? [] as $reason): 
                                    $percentage = $total_blocks > 0 ? round(($reason['count'] / $total_blocks) * 100, 1) : 0;
                                ?>
                                    <tr>
                                        <td><?= htmlspecialchars($reason['reason']) ?></td>
                                        <td><?= number_format($reason['count']) ?></td>
                                        <td><?= number_format($reason['unique_ips']) ?></td>
                                        <td>
                                            <div class="progress" style="height: 20px;">
                                                <div class="progress-bar bg-<?= $percentage > 50 ? 'danger' : ($percentage > 20 ? 'warning' : 'info') ?>" 
                                                     style="width: <?= $percentage ?>%">
                                                    <?= $percentage ?>%
                                                </div>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['block_reasons'])): ?>
                                    <tr>
                                        <td colspan="4" class="text-center py-3 text-muted">
                                            No block data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
            <?php elseif ($report_type === 'traffic'): ?>
                <!-- Traffic Analysis Report -->
                <div class="row g-4 mb-4">
                    <!-- Hourly Traffic Pattern -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-clock-history me-2"></i>Hourly Traffic Pattern</h5>
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="hourlyTrafficChart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Browser Distribution -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-browser-chrome me-2"></i>Browser Distribution</h5>
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="browserChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Top Countries -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-globe me-2"></i>Top Countries by Traffic</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>Country</th>
                                    <th>Visits</th>
                                    <th>Unique Visitors</th>
                                    <th>Visits per Visitor</th>
                                    <th>Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $total_country_visits = array_sum(array_column($report_data['top_countries'] ?? [], 'visits'));
                                foreach ($report_data['top_countries'] ?? [] as $country): 
                                    $percentage = $total_country_visits > 0 ? round(($country['visits'] / $total_country_visits) * 100, 1) : 0;
                                    $visits_per_visitor = $country['unique_visitors'] > 0 ? round($country['visits'] / $country['unique_visitors'], 1) : 0;
                                ?>
                                    <tr>
                                        <td>
                                            <i class="bi bi-flag me-2"></i>
                                            <?= htmlspecialchars($country['country']) ?>
                                        </td>
                                        <td><?= number_format($country['visits']) ?></td>
                                        <td><?= number_format($country['unique_visitors']) ?></td>
                                        <td><?= $visits_per_visitor ?></td>
                                        <td>
                                            <div class="progress" style="height: 20px;">
                                                <div class="progress-bar bg-<?= $percentage > 30 ? 'success' : ($percentage > 10 ? 'info' : 'secondary') ?>" 
                                                     style="width: <?= $percentage ?>%">
                                                    <?= $percentage ?>%
                                                </div>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['top_countries'])): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-3 text-muted">
                                            No country data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Device Types -->
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-phone me-2"></i>Device Type Distribution</h5>
                    <div class="row">
                        <?php 
                        $total_devices = array_sum(array_column($report_data['device_types'] ?? [], 'count'));
                        foreach ($report_data['device_types'] ?? [] as $device): 
                            $percentage = $total_devices > 0 ? round(($device['count'] / $total_devices) * 100, 1) : 0;
                        ?>
                            <div class="col-md-4">
                                <div class="dashboard-card text-center">
                                    <div class="mb-2" style="font-size: 2rem;">
                                        <?php if ($device['device_type'] === 'Mobile'): ?>
                                            <i class="bi bi-phone text-primary"></i>
                                        <?php elseif ($device['device_type'] === 'Tablet'): ?>
                                            <i class="bi bi-tablet text-info"></i>
                                        <?php else: ?>
                                            <i class="bi bi-laptop text-success"></i>
                                        <?php endif; ?>
                                    </div>
                                    <h4><?= $percentage ?>%</h4>
                                    <p class="text-muted mb-0"><?= $device['device_type'] ?></p>
                                    <small><?= number_format($device['count']) ?> visits</small>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        <?php if (empty($report_data['device_types'])): ?>
                            <div class="col-12 text-center py-4 text-muted">
                                <i class="bi bi-devices mb-2" style="font-size: 2rem;"></i>
                                <p class="mb-0">No device data available</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
            <?php elseif ($report_type === 'users'): ?>
                <!-- Users Activity Report -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-people me-2"></i>User Activity Overview</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Websites</th>
                                    <th>Activity Count</th>
                                    <th>Last Activity</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($report_data['user_activity'] ?? [] as $user): ?>
                                    <tr>
                                        <td>
                                            <div class="fw-bold"><?= htmlspecialchars($user['username']) ?></div>
                                        </td>
                                        <td><?= htmlspecialchars($user['email']) ?></td>
                                        <td>
                                            <span class="badge bg-<?= getRoleBadge($user['role']) ?>">
                                                <?= ucfirst($user['role']) ?>
                                            </span>
                                        </td>
                                        <td><?= $user['websites'] ?></td>
                                        <td>
                                            <span class="badge bg-<?= $user['logins'] > 50 ? 'success' : ($user['logins'] > 10 ? 'info' : 'secondary') ?>">
                                                <?= $user['logins'] ?>
                                            </span>
                                        </td>
                                        <td><?= $user['last_activity'] ? formatDate($user['last_activity'], 'Y-m-d') : 'Never' ?></td>
                                        <td>
                                            <?php if ($user['last_activity'] && strtotime($user['last_activity']) > strtotime('-7 days')): ?>
                                                <span class="badge bg-success">Active</span>
                                            <?php elseif ($user['last_activity'] && strtotime($user['last_activity']) > strtotime('-30 days')): ?>
                                                <span class="badge bg-warning">Inactive</span>
                                            <?php else: ?>
                                                <span class="badge bg-danger">Dormant</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['user_activity'])): ?>
                                    <tr>
                                        <td colspan="7" class="text-center py-3 text-muted">
                                            No user activity data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- New Users -->
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-person-plus me-2"></i>New User Registrations</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>New Users</th>
                                    <th>Users</th>
                                    <th>Cumulative</th>
                                    <th>Growth</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $cumulative = 0;
                                $previous_day = 0;
                                foreach ($report_data['new_users'] ?? [] as $day): 
                                    $cumulative += $day['new_users'];
                                    $growth = $previous_day > 0 ? round((($day['new_users'] - $previous_day) / $previous_day) * 100, 1) : 0;
                                    $previous_day = $day['new_users'];
                                ?>
                                    <tr>
                                        <td><?= date('M j, Y', strtotime($day['date'])) ?></td>
                                        <td><span class="badge bg-success"><?= $day['new_users'] ?></span></td>
                                        <td><small><?= htmlspecialchars(truncateText($day['users'], 50)) ?></small></td>
                                        <td><?= $cumulative ?></td>
                                        <td>
                                            <?php if ($growth > 0): ?>
                                                <span class="text-success">+<?= $growth ?>%</span>
                                            <?php elseif ($growth < 0): ?>
                                                <span class="text-danger"><?= $growth ?>%</span>
                                            <?php else: ?>
                                                <span class="text-muted">0%</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['new_users'])): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-3 text-muted">
                                            No new user data available for the selected period
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
            <?php elseif ($report_type === 'system'): ?>
                <!-- System Performance Report -->
                <div class="row g-4 mb-4">
                    <!-- Database Records -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-database me-2"></i>Database Records</h5>
                            <div class="chart-container" style="height: 300px;">
                                <canvas id="recordsChart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Database Size -->
                    <div class="col-lg-6">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-hdd me-2"></i>Database Size by Table</h5>
                            <div class="table-responsive">
                                <table class="table table-dark table-sm">
                                    <thead>
                                        <tr>
                                            <th>Table</th>
                                            <th>Size (MB)</th>
                                            <th>Percentage</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php 
                                        $total_size = array_sum(array_column($report_data['database_size'] ?? [], 'size_mb'));
                                        foreach ($report_data['database_size'] ?? [] as $table): 
                                            $percentage = $total_size > 0 ? round(($table['size_mb'] / $total_size) * 100, 1) : 0;
                                        ?>
                                            <tr>
                                                <td><?= htmlspecialchars($table['table_name']) ?></td>
                                                <td><?= number_format($table['size_mb'], 2) ?> MB</td>
                                                <td>
                                                    <div class="progress" style="height: 15px;">
                                                        <div class="progress-bar bg-<?= $percentage > 50 ? 'danger' : ($percentage > 20 ? 'warning' : 'info') ?>" 
                                                             style="width: <?= $percentage ?>%">
                                                            <?= $percentage ?>%
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($report_data['database_size'])): ?>
                                            <tr>
                                                <td colspan="3" class="text-center py-3 text-muted">
                                                    No database size data available
                                                </td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Peak Usage Times -->
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-speedometer me-2"></i>Peak Usage Times</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Hour</th>
                                    <th>Requests</th>
                                    <th>Load</th>
                                    <th>Recommendation</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($report_data['peak_usage'] ?? [] as $peak): ?>
                                    <tr>
                                        <td><?= date('M j, Y', strtotime($peak['date'])) ?></td>
                                        <td><?= sprintf('%02d:00', $peak['hour']) ?></td>
                                        <td><?= number_format($peak['requests']) ?></td>
                                        <td>
                                            <?php if ($peak['requests'] > 1000): ?>
                                                <span class="badge bg-danger">Very High</span>
                                            <?php elseif ($peak['requests'] > 500): ?>
                                                <span class="badge bg-warning">High</span>
                                            <?php elseif ($peak['requests'] > 100): ?>
                                                <span class="badge bg-info">Moderate</span>
                                            <?php else: ?>
                                                <span class="badge bg-success">Normal</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($peak['requests'] > 1000): ?>
                                                <small class="text-danger">Consider scaling</small>
                                            <?php elseif ($peak['requests'] > 500): ?>
                                                <small class="text-warning">Monitor closely</small>
                                            <?php else: ?>
                                                <small class="text-success">Normal operation</small>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($report_data['peak_usage'])): ?>
                                    <tr>
                                        <td colspan="5" class="text-center py-3 text-muted">
                                            No peak usage data available
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Summary Statistics -->
                <div class="dashboard-card mt-4">
                    <h5 class="mb-3"><i class="bi bi-clipboard-data me-2"></i>Summary Statistics</h5>
                    <div class="row text-center">
                        <div class="col-md-4 mb-3">
                            <div class="h2 text-primary mb-1"><?= number_format($report_data['total_records']['logs'] ?? 0) ?></div>
                            <div class="text-muted">Total Log Records</div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="h2 text-danger mb-1"><?= number_format($report_data['total_records']['attack_logs'] ?? 0) ?></div>
                            <div class="text-muted">Security Events</div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="h2 text-success mb-1"><?= number_format($report_data['total_records']['users'] ?? 0) ?></div>
                            <div class="text-muted">Active Users</div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    
    <script>
        function exportReport() {
            const params = new URLSearchParams(window.location.search);
            window.open(`ajax/export_report.php?${params.toString()}`, '_blank');
        }
        
        // Update report when type changes
        document.getElementById('reportType').addEventListener('change', function() {
            document.getElementById('reportForm').submit();
        });
        
        // Initialize charts based on report type
        $(document).ready(function() {
            const reportType = '<?= $report_type ?>';
            
            switch(reportType) {
                case 'overview':
                    initializeOverviewCharts();
                    break;
                case 'security':
                    initializeSecurityCharts();
                    break;
                case 'traffic':
                    initializeTrafficCharts();
                    break;
                case 'system':
                    initializeSystemCharts();
                    break;
            }
        });
        
        function initializeOverviewCharts() {
            // Traffic Chart
            const trafficData = <?= json_encode($report_data['daily_traffic'] ?? []) ?>;
            const trafficLabels = trafficData.map(item => item.date.substring(5)); // MM-DD
            const trafficVisits = trafficData.map(item => item.visits);
            const trafficUnique = trafficData.map(item => item.unique_visitors);
            
            const trafficCtx = document.getElementById('trafficChart').getContext('2d');
            new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: trafficLabels,
                    datasets: [
                        {
                            label: 'Visits',
                            data: trafficVisits,
                            borderColor: '#0d6efd',
                            backgroundColor: 'rgba(13, 110, 253, 0.1)',
                            fill: true
                        },
                        {
                            label: 'Unique Visitors',
                            data: trafficUnique,
                            borderColor: '#198754',
                            backgroundColor: 'rgba(25, 135, 84, 0.1)',
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        function initializeSecurityCharts() {
            // Attack Types Chart
            const attackTypesData = <?= json_encode($report_data['attack_types'] ?? []) ?>;
            const attackLabels = attackTypesData.map(item => item.attack_type);
            const attackCounts = attackTypesData.map(item => item.count);
            
            const attackCtx = document.getElementById('attackTypesChart').getContext('2d');
            new Chart(attackCtx, {
                type: 'doughnut',
                data: {
                    labels: attackLabels,
                    datasets: [{
                        data: attackCounts,
                        backgroundColor: [
                            '#dc3545', '#fd7e14', '#ffc107', '#0dcaf0', '#6c757d',
                            '#20c997', '#6610f2', '#e83e8c', '#fd7e14', '#6f42c1'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
            
            // Severity Chart
            const severityData = <?= json_encode($report_data['severity_breakdown'] ?? []) ?>;
            const severityLabels = severityData.map(item => item.severity);
            const severityCounts = severityData.map(item => item.count);
            
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: severityLabels,
                    datasets: [{
                        label: 'Attack Count',
                        data: severityCounts,
                        backgroundColor: severityLabels.map(label => 
                            label === 'Critical' ? '#dc3545' :
                            label === 'High' ? '#fd7e14' :
                            label === 'Medium' ? '#ffc107' : '#0dcaf0'
                        )
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        function initializeTrafficCharts() {
            // Hourly Traffic Chart
            const hourlyData = <?= json_encode($report_data['hourly_traffic'] ?? []) ?>;
            const hourlyLabels = Array.from({length: 24}, (_, i) => i);
            const hourlyVisits = hourlyLabels.map(hour => {
                const data = hourlyData.find(item => item.hour == hour);
                return data ? data.visits : 0;
            });
            
            const hourlyCtx = document.getElementById('hourlyTrafficChart').getContext('2d');
            new Chart(hourlyCtx, {
                type: 'bar',
                data: {
                    labels: hourlyLabels.map(h => h + ':00'),
                    datasets: [{
                        label: 'Visits',
                        data: hourlyVisits,
                        backgroundColor: 'rgba(13, 110, 253, 0.7)'
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
            
            // Browser Chart
            const browserData = <?= json_encode($report_data['browser_distribution'] ?? []) ?>;
            const browserLabels = browserData.map(item => item.browser);
            const browserCounts = browserData.map(item => item.count);
            
            const browserCtx = document.getElementById('browserChart').getContext('2d');
            new Chart(browserCtx, {
                type: 'pie',
                data: {
                    labels: browserLabels,
                    datasets: [{
                        data: browserCounts,
                        backgroundColor: [
                            '#4285F4', // Chrome
                            '#FF6B35', // Firefox
                            '#43A047', // Safari
                            '#0078D7', // Edge
                            '#FF1B1C', // Opera
                            '#6C757D'  // Other
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
        
        function initializeSystemCharts() {
            // Records Chart
            const recordsData = <?= json_encode($report_data['total_records'] ?? []) ?>;
            const recordsLabels = Object.keys(recordsData);
            const recordsValues = Object.values(recordsData);
            
            const recordsCtx = document.getElementById('recordsChart').getContext('2d');
            new Chart(recordsCtx, {
                type: 'bar',
                data: {
                    labels: recordsLabels.map(label => 
                        label.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())
                    ),
                    datasets: [{
                        label: 'Record Count',
                        data: recordsValues,
                        backgroundColor: [
                            '#0d6efd',
                            '#dc3545',
                            '#ffc107',
                            '#198754',
                            '#6c757d'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    if (value >= 1000000) {
                                        return (value / 1000000).toFixed(1) + 'M';
                                    }
                                    if (value >= 1000) {
                                        return (value / 1000).toFixed(1) + 'K';
                                    }
                                    return value;
                                }
                            }
                        }
                    }
                }
            });
        }
    </script>
</body>
</html>