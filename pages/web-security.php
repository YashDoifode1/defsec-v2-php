<?php
// web-security.php
require_once '../includes/header.php';

// Check if user is logged in - now using session directly since auth object not available
if (!isset($_SESSION['user_id']) || empty($_SESSION['website_id'])) {
    header("Location: login.php");
    exit();
}

// Set default values for userId and websiteId
$userId = $_SESSION['user_id'] ?? 1;
$websiteId = $_SESSION['website_id'] ?? 1;

date_default_timezone_set('UTC');

/* -------------------------------
   FILTER / SORT / PAGINATION
-------------------------------- */
$search_ip = trim($_GET['search_ip'] ?? '');
$severity_filter = isset($_GET['severity']) ? (array)$_GET['severity'] : [];
$sort_column = $_GET['sort'] ?? 'timestamp';
$sort_order = strtoupper($_GET['order'] ?? 'DESC');
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 10;

$valid_columns = ['id','timestamp','attack_type','severity','ip_address','user_agent','attack_payload','request_url'];
if (!in_array($sort_column, $valid_columns)) $sort_column = 'timestamp';
if (!in_array($sort_order, ['ASC','DESC'])) $sort_order = 'DESC';

/* -------------------------------
   DATA FETCH FUNCTIONS
-------------------------------- */
function getFilteredLogsCount($pdo, $search_ip, $severity_filter, $userId, $websiteId) {
    $sql = "SELECT COUNT(*) AS total
            FROM attack_logs
            WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $userId,
        ':website_id' => $websiteId
    ];

    if ($search_ip !== '') {
        $sql .= " AND ip_address LIKE :search_ip";
        $params[':search_ip'] = "%$search_ip%";
    }

    if (!empty($severity_filter)) {
        $placeholders = implode(',', array_fill(0, count($severity_filter), '?'));
        $sql .= " AND severity IN ($placeholders)";
    }

    $stmt = $pdo->prepare($sql);
    
    // Debug: Check query and parameters
    error_log("SQL: " . $sql);
    error_log("Params: " . print_r($params, true));
    
    // Handle different binding approaches
    if (!empty($severity_filter)) {
        // Merge params and severity filter
        $values = array_values($params);
        foreach ($severity_filter as $severity) {
            $values[] = $severity;
        }
        
        // Bind all values
        for ($i = 1; $i <= count($values); $i++) {
            $stmt->bindValue($i, $values[$i-1], is_int($values[$i-1]) ? PDO::PARAM_INT : PDO::PARAM_STR);
        }
        $stmt->execute();
    } else {
        // Use named parameters
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value, PDO::PARAM_STR);
        }
        $stmt->execute();
    }

    return $stmt->fetchColumn();
}

function getFilteredLogs($pdo, $search_ip, $severity_filter, $sort_column, $sort_order, $page, $per_page, $userId, $websiteId) {
    $offset = ($page - 1) * $per_page;

    $sql = "SELECT *
            FROM attack_logs
            WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $userId,
        ':website_id' => $websiteId
    ];

    if ($search_ip !== '') {
        $sql .= " AND ip_address LIKE :search_ip";
        $params[':search_ip'] = "%$search_ip%";
    }

    if (!empty($severity_filter)) {
        $placeholders = implode(',', array_fill(0, count($severity_filter), '?'));
        $sql .= " AND severity IN ($placeholders)";
    }

    $sql .= " ORDER BY $sort_column $sort_order LIMIT :limit OFFSET :offset";

    error_log("Filtered Logs SQL: " . $sql);
    
    $stmt = $pdo->prepare($sql);
    
    if (!empty($severity_filter)) {
        // Use positional parameters
        $values = array_values($params);
        foreach ($severity_filter as $severity) {
            $values[] = $severity;
        }
        $values[] = $per_page;
        $values[] = $offset;
        
        for ($i = 1; $i <= count($values); $i++) {
            $paramType = is_int($values[$i-1]) ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt->bindValue($i, $values[$i-1], $paramType);
        }
    } else {
        // Use named parameters with proper binding
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value, PDO::PARAM_STR);
        }
        $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    }

    $stmt->execute();
    return $stmt->fetchAll();
}

/* -------------------------------
   GET SEVERITY DISTRIBUTION DATA
-------------------------------- */
function getSeverityDistribution($pdo, $userId, $websiteId, $timeRange = '7d') {
    $timeCondition = '';
    
    switch($timeRange) {
        case '24h':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
            break;
        case '7d':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
            break;
        case '30d':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
            break;
        default:
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    }
    
    $sql = "SELECT 
                severity,
                COUNT(*) as count
            FROM attack_logs 
            WHERE user_id = ? AND website_id = ?
            $timeCondition
            GROUP BY severity
            ORDER BY 
                CASE severity 
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    WHEN 'Info' THEN 5
                    ELSE 6
                END";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$userId, $websiteId]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Initialize all severity levels
    $distribution = [
        'Critical' => 0,
        'High' => 0,
        'Medium' => 0,
        'Low' => 0,
        'Info' => 0
    ];
    
    // Fill with actual data
    foreach ($results as $row) {
        $severity = ucfirst(strtolower($row['severity']));
        if (isset($distribution[$severity])) {
            $distribution[$severity] = (int)$row['count'];
        }
    }
    
    return $distribution;
}

/* -------------------------------
   GET ATTACK TYPE DISTRIBUTION
-------------------------------- */
function getAttackTypeDistribution($pdo, $userId, $websiteId, $timeRange = '7d') {
    $timeCondition = '';
    
    switch($timeRange) {
        case '24h':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
            break;
        case '7d':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
            break;
        case '30d':
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
            break;
        default:
            $timeCondition = "AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    }
    
    $sql = "SELECT 
                attack_type,
                COUNT(*) as count
            FROM attack_logs 
            WHERE user_id = ? AND website_id = ?
            $timeCondition
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$userId, $websiteId]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $types = [];
    $counts = [];
    
    foreach ($results as $row) {
        $types[] = $row['attack_type'];
        $counts[] = (int)$row['count'];
    }
    
    return ['types' => $types, 'counts' => $counts];
}

/* -------------------------------
   EXPORT HANDLER
-------------------------------- */
if (isset($_GET['export'])) {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="attack_logs_export_' . date('Y-m-d') . '.csv"');

    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID','Timestamp','Attack Type','Severity','IP','User Agent','Payload','URL']);

    $sql = "SELECT *
            FROM attack_logs
            WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $userId,
        ':website_id' => $websiteId
    ];

    if ($search_ip !== '') {
        $sql .= " AND ip_address LIKE :search_ip";
        $params[':search_ip'] = "%$search_ip%";
    }

    if (!empty($severity_filter)) {
        $placeholders = implode(',', array_fill(0, count($severity_filter), '?'));
        $sql .= " AND severity IN ($placeholders)";
    }

    $sql .= " ORDER BY $sort_column $sort_order";

    $stmt = $pdo->prepare($sql);
    
    if (!empty($severity_filter)) {
        $values = array_values($params);
        foreach ($severity_filter as $severity) {
            $values[] = $severity;
        }
        $stmt->execute($values);
    } else {
        $stmt->execute($params);
    }

    $logs = $stmt->fetchAll();
    foreach ($logs as $row) {
        fputcsv($out, [
            $row['id'],
            $row['timestamp'],
            $row['attack_type'],
            $row['severity'],
            $row['ip_address'],
            $row['user_agent'],
            $row['attack_payload'],
            $row['request_url']
        ]);
    }

    fclose($out);
    exit;
}

/* -------------------------------
   FETCH DATA
-------------------------------- */
try {
    $total_logs = getFilteredLogsCount($pdo, $search_ip, $severity_filter, $userId, $websiteId);
    $total_pages = ceil($total_logs / $per_page);
    
    error_log("Total logs: " . $total_logs . ", Page: " . $page . ", Per page: " . $per_page);
    
    $logs = getFilteredLogs($pdo, $search_ip, $severity_filter, $sort_column, $sort_order, $page, $per_page, $userId, $websiteId);
    
    error_log("Logs fetched: " . count($logs));
    
    // Get severity distribution for charts
    $severityDistribution = getSeverityDistribution($pdo, $userId, $websiteId, '7d');
    $attackTypeDistribution = getAttackTypeDistribution($pdo, $userId, $websiteId, '7d');
    
} catch (Exception $e) {
    error_log("Error fetching logs: " . $e->getMessage());
    $total_logs = 0;
    $total_pages = 1;
    $logs = [];
    $severityDistribution = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0];
    $attackTypeDistribution = ['types' => [], 'counts' => []];
}

/* -------------------------------
   HELPER FUNCTIONS
-------------------------------- */
function getSeverityBadge($severity) {
    $severity = strtolower($severity);
    switch ($severity) {
        case 'critical': return 'danger';
        case 'high': return 'warning';
        case 'medium': return 'info';
        case 'low': return 'success';
        case 'info': return 'secondary';
        default: return 'secondary';
    }
}

function getSeverityIcon($severity) {
    $severity = strtolower($severity);
    switch ($severity) {
        case 'critical': return 'fa-fire';
        case 'high': return 'fa-exclamation-triangle';
        case 'medium': return 'fa-exclamation-circle';
        case 'low': return 'fa-info-circle';
        case 'info': return 'fa-info';
        default: return 'fa-info-circle';
    }
}

function calculateSecurityScore($logs) {
    if (!$logs || count($logs) === 0) return 100;

    $score = 0;
    foreach ($logs as $l) {
        $severity = strtolower($l['severity']);
        switch ($severity) {
            case 'critical': $score += 3; break;
            case 'high': $score += 2; break;
            case 'medium': $score += 1; break;
            default: break;
        }
    }
    return max(0, 100 - round(($score / (count($logs) * 3)) * 100));
}

function buildQueryString($page, $search_ip, $severity_filter, $sort_column, $sort_order) {
    $params = [
        'page' => $page,
        'search_ip' => $search_ip,
        'sort' => $sort_column,
        'order' => $sort_order
    ];
    
    foreach ($severity_filter as $severity) {
        $params['severity[]'] = $severity;
    }
    
    return http_build_query($params);
}

// Get severity counts for summary cards
$severityCounts = [
    'critical' => 0,
    'high' => 0,
    'medium' => 0,
    'low' => 0,
    'info' => 0
];

foreach ($logs as $log) {
    $severity = strtolower($log['severity']);
    if (isset($severityCounts[$severity])) {
        $severityCounts[$severity]++;
    }
}
?>

<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-bug me-2"></i>Attack Logs</h2>
                <p class="text-muted mb-0">Monitor and analyze security attack logs</p>
            </div>
            <div>
                <a href="?export=1&search_ip=<?php echo urlencode($search_ip); ?>&<?php echo http_build_query(['severity' => $severity_filter]); ?>" 
                   class="btn btn-primary">
                    <i class="fas fa-download me-2"></i>Export Data
                </a>
            </div>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-danger">
                        <i class="fas fa-skull-crossbones"></i>
                    </div>
                    <div class="text-muted mb-1">Total Attacks</div>
                    <div class="stat-number text-danger"><?php echo $total_logs; ?></div>
                    <div class="stat-change negative">
                        <i class="fas fa-arrow-up"></i> All time
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
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="text-muted mb-1">Critical</div>
                    <div class="stat-number text-warning"><?php echo $severityDistribution['Critical']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-fire"></i> High priority
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
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="text-muted mb-1">High</div>
                    <div class="stat-number text-info"><?php echo $severityDistribution['High']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-shield-alt"></i> Monitored
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-secondary">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="text-muted mb-1">Medium</div>
                    <div class="stat-number text-secondary"><?php echo $severityDistribution['Medium']; ?></div>
                    <div class="stat-change">
                        <i class="fas fa-eye"></i> Low risk
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters and Search -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-filter me-2"></i>Filters</h5>
            <form method="get" action="">
                <div class="row g-3">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="search_ip" class="form-label">Search by IP Address</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-search"></i></span>
                                <input type="text" class="form-control" id="search_ip" name="search_ip" 
                                       value="<?php echo htmlspecialchars($search_ip); ?>" 
                                       placeholder="Enter IP address...">
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label">Filter by Severity</label>
                            <div class="d-flex flex-wrap gap-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="severity-critical" 
                                           name="severity[]" value="Critical" 
                                           <?php echo in_array('Critical', $severity_filter) ? 'checked' : ''; ?>>
                                    <label class="form-check-label badge bg-danger" for="severity-critical">
                                        Critical
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="severity-high" 
                                           name="severity[]" value="High" 
                                           <?php echo in_array('High', $severity_filter) ? 'checked' : ''; ?>>
                                    <label class="form-check-label badge bg-warning" for="severity-high">
                                        High
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="severity-medium" 
                                           name="severity[]" value="Medium" 
                                           <?php echo in_array('Medium', $severity_filter) ? 'checked' : ''; ?>>
                                    <label class="form-check-label badge bg-info" for="severity-medium">
                                        Medium
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="severity-low" 
                                           name="severity[]" value="Low" 
                                           <?php echo in_array('Low', $severity_filter) ? 'checked' : ''; ?>>
                                    <label class="form-check-label badge bg-success" for="severity-low">
                                        Low
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="d-flex justify-content-between">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-filter me-2"></i>Apply Filters
                    </button>
                    <a href="?" class="btn btn-outline-secondary">
                        <i class="fas fa-times me-2"></i>Reset Filters
                    </a>
                </div>
            </form>
        </div>
    </div>

    <!-- Security Score -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Security Score</h5>
            <div class="text-center">
                <div class="position-relative d-inline-block mb-3">
                    <div id="securityScoreChart" style="width: 200px; height: 200px;"></div>
                    <div class="position-absolute top-50 start-50 translate-middle text-center">
                        <div class="display-4 fw-bold"><?php echo calculateSecurityScore($logs); ?></div>
                        <div class="text-muted">/ 100</div>
                    </div>
                </div>
                <div class="mt-3">
                    <div class="progress" style="height: 10px;">
                        <div class="progress-bar bg-success" 
                             style="width: <?php echo calculateSecurityScore($logs); ?>%"></div>
                    </div>
                    <small class="text-muted">Score based on severity and frequency of attacks (100% = no issues)</small>
                </div>
            </div>
        </div>
    </div>

    <!-- Severity Distribution -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Severity Distribution (Last 7 Days)</h5>
                <select class="form-select form-select-sm w-auto" id="distributionTimeRange" onchange="updateCharts()">
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>
            </div>
            <div id="severityChart" style="height: 300px;"></div>
        </div>
    </div>

    <!-- Logs Table -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0">
                    <i class="fas fa-list me-2"></i>Attack Logs 
                    <span class="badge bg-dark ms-2"><?php echo count($logs); ?> of <?php echo $total_logs; ?></span>
                </h5>
                <?php if (count($logs) > 0): ?>
                <button class="btn btn-sm btn-outline-secondary" onclick="toggleAllDetails()">
                    <i class="fas fa-arrows-expand me-1"></i> Toggle Details
                </button>
                <?php endif; ?>
            </div>
            
            <?php if (count($logs) > 0): ?>
            <div class="table-responsive">
                <table class="table table-dark table-hover" id="logsTable">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('id')">
                                ID 
                                <?php if ($sort_column == 'id') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                            </th>
                            <th class="sortable" onclick="sortTable('timestamp')">
                                Timestamp 
                                <?php if ($sort_column == 'timestamp') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                            </th>
                            <th>Attack Type</th>
                            <th class="sortable" onclick="sortTable('severity')">
                                Severity 
                                <?php if ($sort_column == 'severity') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                            </th>
                            <th class="sortable" onclick="sortTable('ip_address')">
                                IP Address 
                                <?php if ($sort_column == 'ip_address') echo $sort_order == 'ASC' ? '<i class="fas fa-arrow-up ms-1"></i>' : '<i class="fas fa-arrow-down ms-1"></i>'; ?>
                            </th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <tr>
                            <td>
                                <span class="badge bg-dark">#<?php echo htmlspecialchars($log['id']); ?></span>
                            </td>
                            <td>
                                <small><?php echo date('H:i', strtotime($log['timestamp'])); ?></small><br>
                                <small class="text-muted"><?php echo date('M d, Y', strtotime($log['timestamp'])); ?></small>
                            </td>
                            <td>
                                <span class="badge bg-secondary border">
                                    <?php echo htmlspecialchars($log['attack_type']); ?>
                                </span>
                            </td>
                            <td>
                                <?php 
                                $severityColor = getSeverityBadge($log['severity']);
                                $severityIcon = getSeverityIcon($log['severity']);
                                ?>
                                <span class="badge bg-<?php echo $severityColor; ?>">
                                    <i class="fas <?php echo $severityIcon; ?> me-1"></i>
                                    <?php echo htmlspecialchars($log['severity']); ?>
                                </span>
                            </td>
                            <td>
                                <code><?php echo htmlspecialchars($log['ip_address']); ?></code>
                                <button class="btn btn-sm btn-outline-info ms-1" onclick="showIPDetails('<?php echo htmlspecialchars($log['ip_address']); ?>')">
                                    <i class="fas fa-map-marker-alt"></i>
                                </button>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary" onclick="toggleDetails(<?php echo $log['id']; ?>)">
                                    <i class="fas fa-eye me-1"></i> Details
                                </button>
                                <a href="block-list.php?ip=<?php echo urlencode($log['ip_address']); ?>" 
                                   class="btn btn-sm btn-outline-danger ms-1">
                                    <i class="fas fa-ban me-1"></i> Block
                                </a>
                            </td>
                        </tr>
                        <tr id="details-<?php echo $log['id']; ?>" class="d-none details-row">
                            <td colspan="6">
                                <div class="bg-dark rounded p-3 mt-2 border border-secondary">
                                    <div class="row g-3">
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-desktop me-2"></i>User Agent</h6>
                                            <div class="bg-black rounded p-2 small border border-dark">
                                                <?php echo htmlspecialchars($log['user_agent']); ?>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-link me-2"></i>Request URL</h6>
                                            <div class="bg-black rounded p-2 small border border-dark">
                                                <?php echo htmlspecialchars($log['request_url']); ?>
                                            </div>
                                        </div>
                                        <div class="col-12">
                                            <h6><i class="fas fa-code me-2"></i>Attack Payload</h6>
                                            <div class="bg-black rounded p-2 small border border-dark">
                                                <pre class="mb-0 text-light"><?php echo htmlspecialchars($log['attack_payload']); ?></pre>
                                            </div>
                                        </div>
                                        <div class="col-12">
                                            <div class="d-flex justify-content-between align-items-center mt-2">
                                                <small class="text-muted">Attack ID: #<?php echo $log['id']; ?></small>
                                                <small class="text-muted">Detected: <?php echo date('Y-m-d H:i:s', strtotime($log['timestamp'])); ?></small>
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
                <nav aria-label="Logs pagination">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?<?php echo buildQueryString($page - 1, $search_ip, $severity_filter, $sort_column, $sort_order); ?>" aria-label="Previous">
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
                                <a class="page-link" href="?<?php echo buildQueryString($i, $search_ip, $severity_filter, $sort_column, $sort_order); ?>">
                                    <?php echo $i; ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?<?php echo buildQueryString($page + 1, $search_ip, $severity_filter, $sort_column, $sort_order); ?>" aria-label="Next">
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
                <h5>No attack logs found</h5>
                <p class="text-muted"><?php echo $search_ip || !empty($severity_filter) ? 'Try adjusting your filters' : 'No security attacks detected yet'; ?></p>
                <?php if ($search_ip || !empty($severity_filter)): ?>
                    <a href="?" class="btn btn-outline-secondary mt-2">
                        <i class="fas fa-times me-2"></i>Clear Filters
                    </a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Attack Types Analysis -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-chart-bar me-2"></i>Attack Types Analysis (Last 7 Days)</h5>
            <div id="attackTypesChart" style="height: 300px;"></div>
        </div>
    </div>

    <!-- Recent Activity Timeline -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-history me-2"></i>Recent Activity Timeline</h5>
            <div class="timeline">
                <?php
                $recentLogs = array_slice($logs, 0, 5);
                if (count($recentLogs) > 0):
                foreach ($recentLogs as $log):
                    $severityColor = getSeverityBadge($log['severity']);
                ?>
                <div class="timeline-item mb-3">
                    <div class="d-flex">
                        <div class="timeline-marker bg-<?php echo $severityColor; ?>"></div>
                        <div class="timeline-content ms-3">
                            <div class="d-flex justify-content-between">
                                <strong><?php echo htmlspecialchars($log['attack_type']); ?></strong>
                                <small class="text-muted"><?php echo date('H:i', strtotime($log['timestamp'])); ?></small>
                            </div>
                            <div class="small text-muted">
                                <code><?php echo htmlspecialchars($log['ip_address']); ?></code>
                                <span class="badge bg-<?php echo $severityColor; ?> ms-2">
                                    <?php echo htmlspecialchars($log['severity']); ?>
                                </span>
                            </div>
                            <small class="text-truncate d-block mt-1" title="<?php echo htmlspecialchars($log['request_url']); ?>">
                                <i class="fas fa-link me-1"></i><?php echo htmlspecialchars(substr($log['request_url'], 0, 50)); ?>...
                            </small>
                        </div>
                    </div>
                </div>
                <?php endforeach;
                else: ?>
                <div class="text-center py-4">
                    <p class="text-muted">No recent activity to display</p>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title">IP Address Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="ipDetailsContent">
                    Loading IP details...
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" id="blockIpBtn" class="btn btn-danger">
                    <i class="fas fa-ban me-1"></i> Block IP
                </a>
                <a href="#" id="viewGeolocationBtn" class="btn btn-info" target="_blank">
                    <i class="fas fa-map-marker-alt me-1"></i> View on Map
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Include ApexCharts -->
<script src="https://cdn.jsdelivr.net/npm/apexcharts@3.35.0/dist/apexcharts.min.js"></script>
<script>
    // Initialize variables for chart updates
    let severityChart;
    let attackTypesChart;
    let securityScoreChart;

    $(document).ready(function() {
        // Initialize security score chart
        var securityScore = <?php echo calculateSecurityScore($logs); ?>;
        securityScoreChart = new ApexCharts(document.querySelector("#securityScoreChart"), {
            series: [securityScore],
            chart: {
                type: 'radialBar',
                height: 200,
                background: 'transparent',
                foreColor: '#e9ecef'
            },
            plotOptions: {
                radialBar: {
                    hollow: {
                        size: '70%',
                    },
                    dataLabels: {
                        show: true,
                        name: {
                            show: false
                        },
                        value: {
                            show: false
                        }
                    }
                }
            },
            colors: [securityScore >= 80 ? '#28a745' : securityScore >= 60 ? '#ffc107' : '#dc3545'],
            stroke: {
                lineCap: 'round'
            },
            labels: ['Security Score']
        });

        securityScoreChart.render();

        // Initialize severity distribution chart with actual data
        var severityData = [
            <?php echo $severityDistribution['Critical']; ?>,
            <?php echo $severityDistribution['High']; ?>,
            <?php echo $severityDistribution['Medium']; ?>,
            <?php echo $severityDistribution['Low']; ?>,
            <?php echo $severityDistribution['Info']; ?>
        ];

        severityChart = new ApexCharts(document.querySelector("#severityChart"), {
            series: severityData,
            chart: {
                type: 'donut',
                height: 300,
                background: 'transparent',
                foreColor: '#e9ecef'
            },
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            colors: ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d'],
            dataLabels: {
                enabled: true,
                formatter: function(val, opts) {
                    return opts.w.config.series[opts.seriesIndex] + ' (' + val.toFixed(1) + '%)';
                },
                style: {
                    colors: ['#fff']
                }
            },
            legend: {
                position: 'bottom',
                labels: {
                    colors: '#e9ecef'
                }
            },
            responsive: [{
                breakpoint: 480,
                options: {
                    chart: {
                        width: 200
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }],
            tooltip: {
                y: {
                    formatter: function(value) {
                        return value + ' attacks';
                    }
                }
            }
        });

        severityChart.render();

        // Initialize attack types chart with actual data
        var attackTypesData = <?php echo json_encode($attackTypeDistribution['counts']); ?>;
        var attackTypeLabels = <?php echo json_encode($attackTypeDistribution['types']); ?>;
        
        // If no data, create empty chart
        if (attackTypesData.length === 0) {
            attackTypesData = [0, 0, 0, 0, 0];
            attackTypeLabels = ['No attacks', 'in the', 'selected', 'time', 'period'];
        }

        attackTypesChart = new ApexCharts(document.querySelector("#attackTypesChart"), {
            series: [{
                name: 'Attack Count',
                data: attackTypesData
            }],
            chart: {
                type: 'bar',
                height: 300,
                background: 'transparent',
                foreColor: '#e9ecef',
                toolbar: {
                    show: false
                }
            },
            colors: ['#4e54c8'],
            plotOptions: {
                bar: {
                    horizontal: true,
                    columnWidth: '60%',
                    borderRadius: 4,
                    distributed: false
                },
            },
            dataLabels: {
                enabled: true,
                formatter: function(val) {
                    return val;
                },
                style: {
                    colors: ['#fff']
                }
            },
            xaxis: {
                categories: attackTypeLabels,
                labels: {
                    style: {
                        colors: '#6c757d',
                        fontSize: '12px'
                    }
                },
                title: {
                    text: 'Number of Attacks',
                    style: {
                        color: '#e9ecef'
                    }
                }
            },
            yaxis: {
                labels: {
                    style: {
                        colors: '#6c757d',
                        fontSize: '12px'
                    }
                }
            },
            grid: {
                borderColor: '#495057'
            },
            tooltip: {
                y: {
                    formatter: function(value) {
                        return value + ' attacks';
                    }
                }
            }
        });

        attackTypesChart.render();

        // Toggle details for a specific log
        window.toggleDetails = function(logId) {
            const detailsRow = document.getElementById(`details-${logId}`);
            const button = event.target.closest('button');
            
            detailsRow.classList.toggle('d-none');
            
            if (detailsRow.classList.contains('d-none')) {
                button.innerHTML = '<i class="fas fa-eye me-1"></i> Details';
                button.classList.remove('btn-primary');
                button.classList.add('btn-outline-primary');
            } else {
                button.innerHTML = '<i class="fas fa-eye-slash me-1"></i> Hide';
                button.classList.remove('btn-outline-primary');
                button.classList.add('btn-primary');
            }
        }

        // Toggle all details
        window.toggleAllDetails = function() {
            const allDetails = document.querySelectorAll('.details-row');
            if (allDetails.length === 0) return;
            
            const shouldShow = allDetails[0].classList.contains('d-none');
            const buttons = document.querySelectorAll('button[onclick^="toggleDetails"]');
            
            allDetails.forEach((details, index) => {
                if (shouldShow) {
                    details.classList.remove('d-none');
                    if (buttons[index]) {
                        buttons[index].innerHTML = '<i class="fas fa-eye-slash me-1"></i> Hide';
                        buttons[index].classList.remove('btn-outline-primary');
                        buttons[index].classList.add('btn-primary');
                    }
                } else {
                    details.classList.add('d-none');
                    if (buttons[index]) {
                        buttons[index].innerHTML = '<i class="fas fa-eye me-1"></i> Details';
                        buttons[index].classList.remove('btn-primary');
                        buttons[index].classList.add('btn-outline-primary');
                    }
                }
            });
        }

        // Show IP details modal
        window.showIPDetails = function(ip) {
            $('#ipDetailsContent').html(`
                <div class="text-center py-3">
                    <div class="spinner-border" role="status"></div>
                    <p class="mt-2">Loading IP information...</p>
                </div>
            `);
            
            const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
            modal.show();
            
            // Fetch IP details via AJAX
            $.ajax({
                url: 'api/get-ip-details.php',
                method: 'GET',
                data: { ip: ip },
                success: function(response) {
                    if (response.success) {
                        $('#ipDetailsContent').html(`
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label text-muted">IP Address</label>
                                        <div class="form-control bg-dark text-light">
                                            ${response.data.ip}
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-muted">Country</label>
                                        <div class="form-control bg-dark text-light">
                                            ${response.data.country || 'Unknown'}
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label text-muted">ISP</label>
                                        <div class="form-control bg-dark text-light">
                                            ${response.data.isp || 'Unknown'}
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-muted">Threat Level</label>
                                        <div class="form-control bg-dark text-light">
                                            <span class="badge bg-${response.data.threat_level === 'high' ? 'danger' : response.data.threat_level === 'medium' ? 'warning' : 'success'}">
                                                ${response.data.threat_level || 'low'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-info mt-3">
                                <strong>Total Attacks from this IP:</strong> ${response.data.attack_count || 0}
                            </div>
                        `);
                    } else {
                        $('#ipDetailsContent').html(`
                            <div class="alert alert-danger">
                                Failed to load IP details: ${response.message}
                            </div>
                        `);
                    }
                },
                error: function() {
                    $('#ipDetailsContent').html(`
                        <div class="alert alert-danger">
                            Failed to load IP details. Please try again.
                        </div>
                    `);
                }
            });
            
            // Set up button links
            $('#blockIpBtn').attr('href', 'block-list.php?ip=' + encodeURIComponent(ip));
            $('#viewGeolocationBtn').attr('href', 'geolocation.php?ip=' + encodeURIComponent(ip));
        }

        // Update charts based on time range
        window.updateCharts = function() {
            const timeRange = $('#distributionTimeRange').val();
            
            // Show loading state
            $('#severityChart').html('<div class="text-center py-5"><div class="spinner-border"></div><p class="mt-2">Loading...</p></div>');
            $('#attackTypesChart').html('<div class="text-center py-5"><div class="spinner-border"></div><p class="mt-2">Loading...</p></div>');
            
            $.ajax({
                url: 'api/get-chart-data.php',
                method: 'GET',
                data: {
                    timeRange: timeRange,
                    website_id: <?php echo $websiteId; ?>
                },
                success: function(response) {
                    if (response.success) {
                        // Update severity chart
                        severityChart.updateSeries(response.severityData);
                        severityChart.updateOptions({
                            labels: ['Critical', 'High', 'Medium', 'Low', 'Info']
                        });
                        
                        // Update attack types chart
                        attackTypesChart.updateSeries([{
                            data: response.attackTypeData
                        }]);
                        attackTypesChart.updateOptions({
                            xaxis: {
                                categories: response.attackTypeLabels
                            }
                        });
                        
                        // Update summary cards
                        $('#criticalCount').text(response.severityCounts.critical);
                        $('#highCount').text(response.severityCounts.high);
                        $('#mediumCount').text(response.severityCounts.medium);
                    }
                },
                error: function() {
                    // Restore original charts if error
                    severityChart.render();
                    attackTypesChart.render();
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
            
            // Keep existing filters in the URL
            let queryString = `?sort=${column}&order=${order}`;
            
            const searchIp = urlParams.get('search_ip');
            if (searchIp) {
                queryString += `&search_ip=${encodeURIComponent(searchIp)}`;
            }
            
            const severities = urlParams.getAll('severity[]');
            severities.forEach(severity => {
                queryString += `&severity[]=${encodeURIComponent(severity)}`;
            });
            
            window.location.href = queryString;
        }

        // Auto-refresh every 30 seconds
        setInterval(function() {
            // Check for new attacks
            $.ajax({
                url: 'api/check-new-attacks.php',
                method: 'GET',
                data: {
                    website_id: <?php echo $websiteId; ?>,
                    last_check: new Date().toISOString()
                },
                success: function(response) {
                    if (response.has_new_attacks) {
                        // Show notification
                        showNotification('New attacks detected', 'warning');
                        
                        // Optionally refresh the page
                        if (response.auto_refresh) {
                            window.location.reload();
                        }
                    }
                }
            });
        }, 30000);
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
    /* Timeline styling */
    .timeline {
        position: relative;
        padding-left: 20px;
    }
    
    .timeline:before {
        content: '';
        position: absolute;
        left: 6px;
        top: 0;
        bottom: 0;
        width: 2px;
        background: #495057;
    }
    
    .timeline-item {
        position: relative;
        margin-bottom: 20px;
    }
    
    .timeline-marker {
        width: 14px;
        height: 14px;
        border-radius: 50%;
        position: absolute;
        left: -24px;
        top: 5px;
        border: 2px solid #212529;
        z-index: 2;
    }
    
    .timeline-content {
        padding-left: 15px;
    }
    
    /* Progress bar customization */
    .progress {
        background-color: #495057;
    }
    
    /* Sortable headers */
    .sortable {
        cursor: pointer;
        user-select: none;
        position: relative;
        padding-right: 25px !important;
    }
    
    .sortable:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    /* Table row details */
    .bg-black {
        background-color: #121212 !important;
    }
    
    pre {
        color: #e9ecef;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.85rem;
        line-height: 1.4;
        white-space: pre-wrap;
        word-wrap: break-word;
        overflow-x: auto;
        background: #1a1a1a;
        padding: 10px;
        border-radius: 4px;
        border: 1px solid #333;
    }
    
    /* Details row animation */
    .details-row {
        transition: all 0.3s ease;
    }
    
    /* Card hover effects */
    .dashboard-card:hover {
        transform: translateY(-2px);
        transition: transform 0.2s ease;
    }
    
    /* Modal styling */
    .modal-content {
        border: 1px solid #495057;
    }
    
    /* Chart container */
    .apexcharts-tooltip {
        background: #212529 !important;
        border: 1px solid #495057 !important;
        color: #e9ecef !important;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .stat-number {
            font-size: 1.8rem;
        }
        
        .dashboard-card {
            padding: 15px;
        }
        
        #securityScoreChart {
            width: 150px;
            height: 150px;
        }
        
        .timeline:before {
            left: 0;
        }
        
        .timeline-marker {
            left: -18px;
        }
        
        .sortable {
            font-size: 0.9rem;
        }
        
        .btn-group {
            flex-wrap: wrap;
            gap: 5px;
        }
        
        .btn {
            margin-bottom: 5px;
        }
    }
    
    @media (max-width: 576px) {
        .display-4 {
            font-size: 2rem;
        }
        
        .stat-number {
            font-size: 1.5rem;
        }
        
        #severityChart, #attackTypesChart {
            height: 250px;
        }
    }
</style>

<?php
require_once '../includes/footer.php';
?>