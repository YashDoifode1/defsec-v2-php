<?php
// web-security.php
require_once 'includes/header.php';

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
$severity_filter = $_GET['severity'] ?? [];
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
} catch (Exception $e) {
    error_log("Error fetching logs: " . $e->getMessage());
    $total_logs = 0;
    $total_pages = 1;
    $logs = [];
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
        default: return 'secondary';
    }
}

function getSeverityIcon($severity) {
    $severity = strtolower($severity);
    switch ($severity) {
        case 'critical': return 'fa-fire';
        case 'high': return 'fa-exclamation-triangle';
        case 'medium': return 'fa-exclamation-circle';
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

// Get severity counts for chart
$severityCounts = [
    'critical' => 0,
    'high' => 0,
    'medium' => 0
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
                    <div class="stat-number text-warning"><?php echo $severityCounts['critical']; ?></div>
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
                    <div class="stat-number text-info"><?php echo $severityCounts['high']; ?></div>
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
                    <div class="stat-number text-secondary"><?php echo $severityCounts['medium']; ?></div>
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
                <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Severity Distribution</h5>
                <select class="form-select form-select-sm w-auto" id="distributionTimeRange">
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
                        <tr id="details-<?php echo $log['id']; ?>" class="d-none">
                            <td colspan="6">
                                <div class="bg-dark rounded p-3 mt-2">
                                    <div class="row g-3">
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-desktop me-2"></i>User Agent</h6>
                                            <div class="bg-black rounded p-2 small">
                                                <?php echo htmlspecialchars($log['user_agent']); ?>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <h6><i class="fas fa-link me-2"></i>Request URL</h6>
                                            <div class="bg-black rounded p-2 small">
                                                <?php echo htmlspecialchars($log['request_url']); ?>
                                            </div>
                                        </div>
                                        <div class="col-12">
                                            <h6><i class="fas fa-code me-2"></i>Attack Payload</h6>
                                            <div class="bg-black rounded p-2 small">
                                                <pre class="mb-0"><?php echo htmlspecialchars($log['attack_payload']); ?></pre>
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
            <h5 class="mb-4"><i class="fas fa-chart-bar me-2"></i>Attack Types Analysis</h5>
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

<!-- Include ApexCharts -->
<script src="https://cdn.jsdelivr.net/npm/apexcharts@3.35.0/dist/apexcharts.min.js"></script>
<script>
    $(document).ready(function() {
        // Initialize security score chart
        var securityScore = <?php echo calculateSecurityScore($logs); ?>;
        var securityScoreChart = new ApexCharts(document.querySelector("#securityScoreChart"), {
            series: [securityScore],
            chart: {
                type: 'radialBar',
                height: 200,
                background: 'transparent'
            },
            plotOptions: {
                radialBar: {
                    hollow: {
                        size: '70%',
                    },
                    dataLabels: {
                        show: false
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

        // Initialize severity distribution chart
        var severityChart = new ApexCharts(document.querySelector("#severityChart"), {
            series: [<?php echo $severityCounts['critical']; ?>, <?php echo $severityCounts['high']; ?>, <?php echo $severityCounts['medium']; ?>],
            chart: {
                type: 'donut',
                height: 300,
                background: 'transparent',
                foreColor: '#e9ecef'
            },
            labels: ['Critical', 'High', 'Medium'],
            colors: ['#dc3545', '#ffc107', '#17a2b8'],
            dataLabels: {
                enabled: true,
                formatter: function(val, opts) {
                    return opts.w.config.series[opts.seriesIndex]
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
            }]
        });

        severityChart.render();

        // Initialize attack types chart with actual data
        <?php
        // Calculate attack type counts
        $attackTypeCounts = [];
        foreach ($logs as $log) {
            $type = $log['attack_type'];
            if (!isset($attackTypeCounts[$type])) {
                $attackTypeCounts[$type] = 0;
            }
            $attackTypeCounts[$type]++;
        }
        arsort($attackTypeCounts); // Sort by count descending
        $topAttackTypes = array_slice($attackTypeCounts, 0, 7); // Get top 7
        ?>
        
        var attackTypesData = [
            <?php 
            foreach ($topAttackTypes as $type => $count) {
                echo $count . ',';
            }
            if (count($topAttackTypes) < 7) {
                // Fill remaining with zeros
                for ($i = count($topAttackTypes); $i < 7; $i++) {
                    echo '0,';
                }
            }
            ?>
        ];
        
        var attackTypeLabels = [
            <?php 
            foreach ($topAttackTypes as $type => $count) {
                echo "'" . addslashes($type) . "',";
            }
            if (count($topAttackTypes) < 7) {
                // Fill remaining with placeholders
                $placeholders = ['SQL Injection', 'XSS', 'Brute Force', 'DDoS', 'Malware', 'Phishing', 'CSRF'];
                for ($i = count($topAttackTypes); $i < 7; $i++) {
                    echo "'" . $placeholders[$i] . "',";
                }
            }
            ?>
        ];

        var attackTypesChart = new ApexCharts(document.querySelector("#attackTypesChart"), {
            series: [{
                name: 'Attacks',
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
                },
            },
            dataLabels: {
                enabled: false
            },
            xaxis: {
                categories: attackTypeLabels,
                labels: {
                    style: {
                        colors: '#6c757d'
                    }
                }
            },
            yaxis: {
                labels: {
                    style: {
                        colors: '#6c757d'
                    }
                }
            },
            grid: {
                borderColor: '#495057'
            }
        });

        attackTypesChart.render();

        // Toggle details for a specific log
        window.toggleDetails = function(logId) {
            const detailsRow = document.getElementById(`details-${logId}`);
            detailsRow.classList.toggle('d-none');
            
            const button = event.target.closest('button');
            if (detailsRow.classList.contains('d-none')) {
                button.innerHTML = '<i class="fas fa-eye me-1"></i> Details';
            } else {
                button.innerHTML = '<i class="fas fa-eye-slash me-1"></i> Hide';
            }
        }

        // Toggle all details
        window.toggleAllDetails = function() {
            const allDetails = document.querySelectorAll('[id^="details-"]');
            if (allDetails.length === 0) return;
            
            const shouldShow = allDetails[0].classList.contains('d-none');
            const buttons = document.querySelectorAll('button[onclick^="toggleDetails"]');
            
            allDetails.forEach((details, index) => {
                if (shouldShow) {
                    details.classList.remove('d-none');
                    if (buttons[index]) {
                        buttons[index].innerHTML = '<i class="fas fa-eye-slash me-1"></i> Hide';
                    }
                } else {
                    details.classList.add('d-none');
                    if (buttons[index]) {
                        buttons[index].innerHTML = '<i class="fas fa-eye me-1"></i> Details';
                    }
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

        // Time range selector
        $('#distributionTimeRange').change(function() {
            // You can implement AJAX to update chart data based on selected range
            console.log('Time range changed to:', $(this).val());
            // Example: fetchData($(this).val());
        });

        // Auto-refresh every 30 seconds
        setInterval(function() {
            // You can implement AJAX refresh here
            console.log('Auto-refresh triggered');
        }, 30000);
    });
</script>

<style>
    /* Timeline styling */
    .timeline {
        position: relative;
    }
    
    .timeline-item {
        position: relative;
    }
    
    .timeline-marker {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        position: absolute;
        top: 5px;
    }
    
    .timeline-content {
        padding-left: 20px;
    }
    
    /* Progress bar customization */
    .progress {
        background-color: #495057;
    }
    
    /* Sortable headers */
    .sortable {
        cursor: pointer;
        user-select: none;
    }
    
    .sortable:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    /* Table row details */
    .bg-black {
        background-color: #121212;
    }
    
    pre {
        color: #e9ecef;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.85rem;
        line-height: 1.4;
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
    }
</style>

<?php
require_once 'includes/footer.php';
?>