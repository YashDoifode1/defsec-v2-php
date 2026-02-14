<?php
// web-security.php
require_once '../includes/header.php';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: " . APP_URL . "/auth/login.php");
    exit();
}

$userId = $_SESSION['user_id'] ?? 1;
$websiteId = $_SESSION['website_id'] ?? 1;

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
   BUILD WHERE CLAUSE
-------------------------------- */
$where_clause = "WHERE user_id = :user_id AND website_id = :website_id";
$params = [
    ':user_id' => $userId,
    ':website_id' => $websiteId
];

if ($search_ip !== '') {
    $where_clause .= " AND ip_address LIKE :search_ip";
    $params[':search_ip'] = "%$search_ip%";
}

if (!empty($severity_filter)) {
    $severity_placeholders = [];
    $i = 1;
    foreach ($severity_filter as $severity) {
        $param_name = ':severity' . $i;
        $severity_placeholders[] = $param_name;
        $params[$param_name] = $severity;
        $i++;
    }
    $where_clause .= " AND severity IN (" . implode(', ', $severity_placeholders) . ")";
}

/* -------------------------------
   GET TOTAL COUNT
-------------------------------- */
try {
    $count_sql = "SELECT COUNT(*) as total FROM attack_logs $where_clause";
    $count_stmt = $pdo->prepare($count_sql);
    
    foreach ($params as $key => $value) {
        $count_stmt->bindValue($key, $value);
    }
    
    $count_stmt->execute();
    $total_logs = $count_stmt->fetchColumn();
    $total_pages = ceil($total_logs / $per_page);
} catch (Exception $e) {
    error_log("Count error: " . $e->getMessage());
    $total_logs = 0;
    $total_pages = 1;
}

/* -------------------------------
   GET LOGS WITH PAGINATION
-------------------------------- */
$logs = [];
try {
    $offset = ($page - 1) * $per_page;
    $sql = "SELECT * FROM attack_logs $where_clause 
            ORDER BY $sort_column $sort_order 
            LIMIT :limit OFFSET :offset";
    
    $stmt = $pdo->prepare($sql);
    
    // Bind all parameters
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    // Bind pagination parameters
    $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    $stmt->execute();
    $logs = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Fetch error: " . $e->getMessage());
    $logs = [];
}

/* -------------------------------
   GET STATISTICS FOR CHARTS
-------------------------------- */
$severityDistribution = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0];
$attackTypeDistribution = ['types' => [], 'counts' => []];

try {
    // Get severity distribution (last 7 days)
    $severity_sql = "SELECT severity, COUNT(*) as count 
                     FROM attack_logs 
                     WHERE user_id = ? AND website_id = ? 
                     AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                     GROUP BY severity";
    
    $severity_stmt = $pdo->prepare($severity_sql);
    $severity_stmt->execute([$userId, $websiteId]);
    $severity_results = $severity_stmt->fetchAll();
    
    foreach ($severity_results as $row) {
        $severity = ucfirst(strtolower($row['severity']));
        if (isset($severityDistribution[$severity])) {
            $severityDistribution[$severity] = (int)$row['count'];
        }
    }
    
    // Get attack type distribution (last 7 days)
    $type_sql = "SELECT attack_type, COUNT(*) as count 
                 FROM attack_logs 
                 WHERE user_id = ? AND website_id = ? 
                 AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                 GROUP BY attack_type 
                 ORDER BY count DESC 
                 LIMIT 10";
    
    $type_stmt = $pdo->prepare($type_sql);
    $type_stmt->execute([$userId, $websiteId]);
    $type_results = $type_stmt->fetchAll();
    
    $attackTypes = [];
    $attackCounts = [];
    foreach ($type_results as $row) {
        $attackTypes[] = $row['attack_type'];
        $attackCounts[] = (int)$row['count'];
    }
    
    $attackTypeDistribution = ['types' => $attackTypes, 'counts' => $attackCounts];
} catch (Exception $e) {
    error_log("Stats error: " . $e->getMessage());
}

/* -------------------------------
   EXPORT HANDLER
-------------------------------- */
if (isset($_GET['export'])) {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="attack_logs_' . date('Y-m-d') . '.csv"');
    
    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID', 'Timestamp', 'Attack Type', 'Severity', 'IP Address', 'User Agent', 'Payload', 'URL']);
    
    try {
        $export_sql = "SELECT * FROM attack_logs $where_clause ORDER BY $sort_column $sort_order";
        $export_stmt = $pdo->prepare($export_sql);
        
        foreach ($params as $key => $value) {
            $export_stmt->bindValue($key, $value);
        }
        
        $export_stmt->execute();
        $export_logs = $export_stmt->fetchAll();
        
        foreach ($export_logs as $row) {
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
    } catch (Exception $e) {
        fputcsv($out, ['Error: ' . $e->getMessage()]);
    }
    
    fclose($out);
    exit;
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
    $max_score = count($logs) * 3; // Worst case: all critical
    
    foreach ($logs as $log) {
        $severity = strtolower($log['severity']);
        switch ($severity) {
            case 'critical': $score += 3; break;
            case 'high': $score += 2; break;
            case 'medium': $score += 1; break;
            default: break;
        }
    }
    
    if ($max_score === 0) return 100;
    
    $percentage = ($score / $max_score) * 100;
    return max(0, 100 - round($percentage));
}

// Build query string for pagination
$query_parts = [];
if ($search_ip) $query_parts[] = 'search_ip=' . urlencode($search_ip);
foreach ($severity_filter as $severity) {
    $query_parts[] = 'severity[]=' . urlencode($severity);
}
$query_parts[] = 'sort=' . $sort_column;
$query_parts[] = 'order=' . $sort_order;
$query_string = implode('&', $query_parts);
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
                <a href="?export=1&<?php echo $query_string; ?>" class="btn btn-primary">
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
                    <div class="stat-change">
                        <i class="fas fa-history"></i> All time
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
                    <div class="stat-change text-danger">
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
                    <div class="stat-change text-warning">
                        <i class="fas fa-shield-alt"></i> Monitor
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
                            <div class="d-flex flex-wrap gap-2">
                                <?php 
                                $severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
                                $badge_colors = [
                                    'Critical' => 'danger',
                                    'High' => 'warning',
                                    'Medium' => 'info',
                                    'Low' => 'success',
                                    'Info' => 'secondary'
                                ];
                                
                                foreach ($severities as $severity): 
                                ?>
                                <div class="form-check form-check-inline">
                                    <input class="form-check-input" type="checkbox" 
                                           id="severity-<?php echo strtolower($severity); ?>" 
                                           name="severity[]" value="<?php echo $severity; ?>" 
                                           <?php echo in_array($severity, $severity_filter) ? 'checked' : ''; ?>>
                                    <label class="form-check-label badge bg-<?php echo $badge_colors[$severity]; ?>" 
                                           for="severity-<?php echo strtolower($severity); ?>">
                                        <?php echo $severity; ?>
                                    </label>
                                </div>
                                <?php endforeach; ?>
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

    <!-- Charts Section -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Security Score</h5>
            <div class="text-center">
                <div class="position-relative d-inline-block mb-3">
                    <div id="securityScoreChart" style="width: 200px; height: 200px;"></div>
                    <div class="position-absolute top-50 start-50 translate-middle text-center">
                        <div class="display-4 fw-bold" id="securityScoreValue">
                            <?php echo calculateSecurityScore($logs); ?>
                        </div>
                        <div class="text-muted">/ 100</div>
                    </div>
                </div>
                <div class="mt-3">
                    <div class="progress" style="height: 10px;">
                        <div class="progress-bar bg-success" 
                             style="width: <?php echo calculateSecurityScore($logs); ?>%"></div>
                    </div>
                    <small class="text-muted">Based on severity and frequency of attacks</small>
                </div>
            </div>
        </div>
    </div>

    <!-- Severity Distribution -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Severity Distribution</h5>
                <select class="form-select form-select-sm w-auto" id="chartTimeRange" onchange="updateCharts()">
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
            </div>
            
            <?php if (count($logs) > 0): ?>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>
                                <a href="?<?php echo $query_string; ?>&sort=id&order=<?php echo ($sort_column == 'id' && $sort_order == 'ASC') ? 'DESC' : 'ASC'; ?>" class="text-decoration-none text-white">
                                    ID <?php echo $sort_column == 'id' ? ($sort_order == 'ASC' ? '↑' : '↓') : ''; ?>
                                </a>
                            </th>
                            <th>
                                <a href="?<?php echo $query_string; ?>&sort=timestamp&order=<?php echo ($sort_column == 'timestamp' && $sort_order == 'ASC') ? 'DESC' : 'ASC'; ?>" class="text-decoration-none text-white">
                                    Timestamp <?php echo $sort_column == 'timestamp' ? ($sort_order == 'ASC' ? '↑' : '↓') : ''; ?>
                                </a>
                            </th>
                            <th>Attack Type</th>
                            <th>
                                <a href="?<?php echo $query_string; ?>&sort=severity&order=<?php echo ($sort_column == 'severity' && $sort_order == 'ASC') ? 'DESC' : 'ASC'; ?>" class="text-decoration-none text-white">
                                    Severity <?php echo $sort_column == 'severity' ? ($sort_order == 'ASC' ? '↑' : '↓') : ''; ?>
                                </a>
                            </th>
                            <th>
                                <a href="?<?php echo $query_string; ?>&sort=ip_address&order=<?php echo ($sort_column == 'ip_address' && $sort_order == 'ASC') ? 'DESC' : 'ASC'; ?>" class="text-decoration-none text-white">
                                    IP Address <?php echo $sort_column == 'ip_address' ? ($sort_order == 'ASC' ? '↑' : '↓') : ''; ?>
                                </a>
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
                                <button class="btn btn-sm btn-outline-info ms-1 ip-details-btn" 
                                        data-ip="<?php echo htmlspecialchars($log['ip_address']); ?>" 
                                        title="View IP Details">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary view-details-btn" 
                                        data-log-id="<?php echo $log['id']; ?>"
                                        data-attack-type="<?php echo htmlspecialchars($log['attack_type']); ?>"
                                        data-severity="<?php echo htmlspecialchars($log['severity']); ?>"
                                        data-ip="<?php echo htmlspecialchars($log['ip_address']); ?>"
                                        data-user-agent="<?php echo htmlspecialchars($log['user_agent']); ?>"
                                        data-payload="<?php echo htmlspecialchars($log['attack_payload']); ?>"
                                        data-url="<?php echo htmlspecialchars($log['request_url']); ?>"
                                        data-timestamp="<?php echo htmlspecialchars($log['timestamp']); ?>">
                                    <i class="fas fa-eye me-1"></i> View Details
                                </button>
                                <a href="block-list.php?ip=<?php echo urlencode($log['ip_address']); ?>&website_id=<?php echo $websiteId; ?>" 
                                   class="btn btn-sm btn-outline-danger ms-1 block-ip-btn" title="Block IP">
                                    <i class="fas fa-ban me-1"></i>
                                </a>
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
                                <a class="page-link" href="?page=<?php echo $page - 1; ?>&<?php echo $query_string; ?>" aria-label="Previous">
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
                                <a class="page-link" href="?page=<?php echo $i; ?>&<?php echo $query_string; ?>">
                                    <?php echo $i; ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo $page + 1; ?>&<?php echo $query_string; ?>" aria-label="Next">
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

    <!-- Attack Types Chart -->
    <div class="col-xl-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>Attack Types Distribution</h5>
                <small class="text-muted">Top 10 attack types in selected period</small>
            </div>
            <div id="attackTypesChart" style="height: 350px;"></div>
        </div>
    </div>
</div>

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-info-circle me-2"></i>IP Address Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="ipDetailsContent">
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Loading IP information...</p>
                    </div>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" id="blockIpBtn" class="btn btn-danger">
                    <i class="fas fa-ban me-1"></i> Block IP
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Attack Details Modal -->
<div class="modal fade" id="attackDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-bug me-2"></i>Attack Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">Attack ID</label>
                            <div class="form-control bg-dark text-light" id="detail-id"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Timestamp</label>
                            <div class="form-control bg-dark text-light" id="detail-timestamp"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Attack Type</label>
                            <div class="form-control bg-dark text-light" id="detail-attack-type"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Severity</label>
                            <div class="form-control bg-dark text-light" id="detail-severity"></div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">IP Address</label>
                            <div class="form-control bg-dark text-light" id="detail-ip"></div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">User Agent</label>
                            <div class="form-control bg-dark text-light" style="min-height: 100px;" id="detail-user-agent"></div>
                        </div>
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="mb-3">
                            <label class="form-label text-muted">Request URL</label>
                            <div class="form-control bg-dark text-light" style="min-height: 60px;" id="detail-url"></div>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="mb-3">
                            <label class="form-label text-muted">Attack Payload</label>
                            <div class="form-control bg-dark text-light" style="min-height: 150px;">
                                <pre class="mb-0 text-light small" id="detail-payload" style="white-space: pre-wrap; word-wrap: break-word;"></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" id="blockFromDetailsBtn" class="btn btn-danger">
                    <i class="fas fa-ban me-1"></i> Block IP
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Include ApexCharts -->
<script src="https://cdn.jsdelivr.net/npm/apexcharts@3.35.0/dist/apexcharts.min.js"></script>
<script>
    // Global chart instances
    let severityChart = null;
    let attackTypesChart = null;
    let securityScoreChart = null;

    // Initialize security score chart (simple progress circle)
    function initSecurityScoreChart() {
        const score = <?php echo calculateSecurityScore($logs); ?>;
        const color = score >= 80 ? '#28a745' : score >= 60 ? '#ffc107' : '#dc3545';
        
        securityScoreChart = new ApexCharts(document.querySelector("#securityScoreChart"), {
            series: [score],
            chart: {
                type: 'radialBar',
                height: 200,
                background: 'transparent'
            },
            plotOptions: {
                radialBar: {
                    hollow: {
                        size: '70%'
                    },
                    dataLabels: {
                        show: false
                    }
                }
            },
            colors: [color],
            stroke: {
                lineCap: 'round'
            }
        });
        
        securityScoreChart.render();
    }

    // Initialize severity distribution chart
    function initSeverityChart() {
        const severityData = [
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
                background: 'transparent'
            },
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            colors: ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d'],
            legend: {
                position: 'bottom',
                labels: {
                    colors: '#adb5bd'
                }
            },
            dataLabels: {
                enabled: true,
                formatter: function(val, opts) {
                    return opts.w.globals.series[opts.seriesIndex] + ' (' + val.toFixed(1) + '%)';
                },
                style: {
                    colors: ['#fff']
                }
            },
            responsive: [{
                breakpoint: 480,
                options: {
                    chart: {
                        width: 200
                    }
                }
            }]
        });
        
        severityChart.render();
    }

    // Initialize attack types chart
    function initAttackTypesChart() {
        const attackTypes = <?php echo json_encode($attackTypeDistribution['types']); ?>;
        const attackCounts = <?php echo json_encode($attackTypeDistribution['counts']); ?>;
        
        // If no data, show empty chart
        if (attackTypes.length === 0) {
            attackTypesChart = new ApexCharts(document.querySelector("#attackTypesChart"), {
                series: [{
                    name: 'No data',
                    data: [0]
                }],
                chart: {
                    type: 'bar',
                    height: 350,
                    background: 'transparent'
                },
                xaxis: {
                    categories: ['No attack data']
                },
                noData: {
                    text: 'No attack data available',
                    align: 'center',
                    verticalAlign: 'middle',
                    style: {
                        color: '#adb5bd',
                        fontSize: '14px'
                    }
                }
            });
        } else {
            attackTypesChart = new ApexCharts(document.querySelector("#attackTypesChart"), {
                series: [{
                    name: 'Attack Count',
                    data: attackCounts
                }],
                chart: {
                    type: 'bar',
                    height: 350,
                    background: 'transparent',
                    toolbar: {
                        show: true,
                        tools: {
                            download: true,
                            selection: true,
                            zoom: true,
                            zoomin: true,
                            zoomout: true,
                            pan: true,
                            reset: true
                        }
                    }
                },
                plotOptions: {
                    bar: {
                        borderRadius: 4,
                        horizontal: true,
                    }
                },
                dataLabels: {
                    enabled: true
                },
                xaxis: {
                    categories: attackTypes,
                    labels: {
                        style: {
                            colors: '#adb5bd'
                        }
                    }
                },
                yaxis: {
                    labels: {
                        style: {
                            colors: '#adb5bd'
                        }
                    }
                },
                colors: ['#4e54c8'],
                tooltip: {
                    y: {
                        formatter: function(val) {
                            return val + ' attacks';
                        }
                    }
                }
            });
        }
        
        attackTypesChart.render();
    }

    // Show attack details in modal
    function showAttackDetails(button) {
        // Get data from button attributes
        const logId = button.getAttribute('data-log-id');
        const attackType = button.getAttribute('data-attack-type');
        const severity = button.getAttribute('data-severity');
        const ip = button.getAttribute('data-ip');
        const userAgent = button.getAttribute('data-user-agent');
        const payload = button.getAttribute('data-payload');
        const url = button.getAttribute('data-url');
        const timestamp = button.getAttribute('data-timestamp');
        
        // Fill modal with data
        document.getElementById('detail-id').textContent = '#' + logId;
        document.getElementById('detail-timestamp').textContent = timestamp;
        document.getElementById('detail-attack-type').textContent = attackType;
        document.getElementById('detail-severity').innerHTML = getSeverityBadgeHTML(severity);
        document.getElementById('detail-ip').textContent = ip;
        document.getElementById('detail-user-agent').textContent = userAgent || 'N/A';
        document.getElementById('detail-url').textContent = url || 'N/A';
        document.getElementById('detail-payload').textContent = payload || 'N/A';
        
        // Update block button link
        document.getElementById('blockFromDetailsBtn').href = `block-list.php?ip=${encodeURIComponent(ip)}&website_id=<?php echo $websiteId; ?>`;
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('attackDetailsModal'));
        modal.show();
    }
    
    // Helper function to get severity badge HTML
    function getSeverityBadgeHTML(severity) {
        const severityLower = severity.toLowerCase();
        let color = 'secondary';
        let icon = 'fa-info-circle';
        
        switch(severityLower) {
            case 'critical':
                color = 'danger';
                icon = 'fa-fire';
                break;
            case 'high':
                color = 'warning';
                icon = 'fa-exclamation-triangle';
                break;
            case 'medium':
                color = 'info';
                icon = 'fa-exclamation-circle';
                break;
            case 'low':
                color = 'success';
                icon = 'fa-info-circle';
                break;
            case 'info':
                color = 'secondary';
                icon = 'fa-info';
                break;
        }
        
        return `<span class="badge bg-${color}"><i class="fas ${icon} me-1"></i>${severity}</span>`;
    }

    // Fetch IP details from ipinfo.io (free service)
    async function fetchIPDetails(ip) {
        try {
            const response = await fetch(`https://ipinfo.io/${ip}/json`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error fetching IP details:', error);
            return null;
        }
    }

    // Show IP details modal
    async function showIPDetails(ip) {
        const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
        
        // Show loading state
        document.getElementById('ipDetailsContent').innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2">Fetching IP information...</p>
            </div>
        `;
        
        modal.show();
        
        // Fetch IP details
        const ipData = await fetchIPDetails(ip);
        
        if (!ipData) {
            // Fallback to static data if API fails
            document.getElementById('ipDetailsContent').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">IP Address</label>
                            <div class="form-control bg-dark text-light">
                                ${ip}
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">IP Type</label>
                            <div class="form-control bg-dark text-light">
                                ${ip.includes(':') ? 'IPv6' : 'IPv4'}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">Threat Level</label>
                            <div class="form-control bg-dark text-light">
                                <span class="badge bg-warning">Unknown</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="alert alert-warning mt-3">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Could not fetch detailed IP information.
                </div>
            `;
        } else {
            // Display fetched IP data
            const { city, region, country, loc, org } = ipData;
            const [latitude, longitude] = loc ? loc.split(',') : ['', ''];
            
            let threatLevel = 'Low';
            let threatColor = 'success';
            
            // Basic threat assessment
            if (org && (org.toLowerCase().includes('tor') || org.toLowerCase().includes('vpn'))) {
                threatLevel = 'Medium';
                threatColor = 'warning';
            }
            
            if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1') {
                threatLevel = 'Local Network';
                threatColor = 'info';
            }
            
            document.getElementById('ipDetailsContent').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">IP Address</label>
                            <div class="form-control bg-dark text-light">
                                <i class="fas fa-network-wired me-2"></i>${ip}
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Location</label>
                            <div class="form-control bg-dark text-light">
                                <i class="fas fa-map-marker-alt me-2"></i>
                                ${city || 'Unknown'}, ${region || 'Unknown'}, ${country || 'Unknown'}
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Coordinates</label>
                            <div class="form-control bg-dark text-light">
                                <i class="fas fa-globe me-2"></i>
                                ${latitude ? `${latitude}, ${longitude}` : 'Not available'}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label text-muted">ISP / Organization</label>
                            <div class="form-control bg-dark text-light">
                                <i class="fas fa-building me-2"></i>
                                ${org || 'Unknown'}
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted">Threat Level</label>
                            <div class="form-control bg-dark text-light">
                                <span class="badge bg-${threatColor}"><i class="fas fa-shield-alt me-1"></i>${threatLevel}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="alert alert-info mt-3">
                    <i class="fas fa-info-circle me-2"></i>
                    IP information provided by <a href="https://ipinfo.io" target="_blank" class="alert-link">ipinfo.io</a>
                </div>
            `;
        }
        
        // Update block button link
        document.getElementById('blockIpBtn').href = `block-list.php?ip=${encodeURIComponent(ip)}&website_id=<?php echo $websiteId; ?>`;
    }

    // Update charts based on time range
    function updateCharts() {
        const timeRange = document.getElementById('chartTimeRange').value;
        
        // Show loading state
        document.getElementById('severityChart').innerHTML = '<div class="text-center py-5"><div class="spinner-border text-light"></div><p class="mt-2 text-light">Loading...</p></div>';
        document.getElementById('attackTypesChart').innerHTML = '<div class="text-center py-5"><div class="spinner-border text-light"></div><p class="mt-2 text-light">Loading...</p></div>';
        
        // Reload page with new time range parameter
        const url = new URL(window.location.href);
        url.searchParams.set('time_range', timeRange);
        window.location.href = url.toString();
    }

    // Initialize everything when page loads
    document.addEventListener('DOMContentLoaded', function() {
        console.log('DOM loaded - initializing...');
        
        // Initialize charts
        initSecurityScoreChart();
        initSeverityChart();
        initAttackTypesChart();
        
        // Add event listeners for view details buttons
        document.querySelectorAll('.view-details-btn').forEach(button => {
            button.addEventListener('click', function() {
                showAttackDetails(this);
            });
        });
        
        // Add event listeners for IP details buttons
        document.querySelectorAll('.ip-details-btn').forEach(button => {
            button.addEventListener('click', function() {
                const ip = this.getAttribute('data-ip');
                showIPDetails(ip);
            });
        });
        
        // Add confirmation for export
        document.querySelectorAll('a[href*="export"]').forEach(link => {
            link.addEventListener('click', function(e) {
                if (!confirm('Export attack logs to CSV?')) {
                    e.preventDefault();
                }
            });
        });
        
        // Add confirmation for IP blocking
        document.querySelectorAll('.block-ip-btn').forEach(link => {
            link.addEventListener('click', function(e) {
                if (!confirm('Block this IP address?')) {
                    e.preventDefault();
                }
            });
        });
        
        console.log('DOM loaded - initialized...');
    });
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
    }
    
    /* Modal styling */
    .modal-content {
        border: 1px solid #495057;
    }
    
    .modal-header {
        border-bottom: 1px solid #495057;
    }
    
    .modal-footer {
        border-top: 1px solid #495057;
    }
    
    .form-control[readonly] {
        background-color: #2d2d2d;
        cursor: text;
    }
    
    /* IP details modal styling */
    #ipDetailsModal .form-control {
        border: 1px solid #495057;
    }
    
    /* ApexCharts tooltip dark theme */
    .apexcharts-tooltip {
        background: #212529 !important;
        border: 1px solid #495057 !important;
        color: #e9ecef !important;
    }
    
    .apexcharts-tooltip-title {
        background: #343a40 !important;
        border-bottom: 1px solid #495057 !important;
    }
    
    /* Chart legend text color */
    .apexcharts-legend-text {
        color: #adb5bd !important;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .stat-number {
            font-size: 1.8rem;
        }
        
        #securityScoreChart {
            width: 150px;
            height: 150px;
        }
        
        .btn-group {
            flex-wrap: wrap;
            gap: 5px;
        }
        
        #ipDetailsModal .modal-dialog {
            margin: 0.5rem;
        }
    }
    
    /* IP details button hover effect */
    .ip-details-btn:hover {
        transform: scale(1.1);
        transition: transform 0.2s;
    }
    
    /* Loading animation for IP details */
    @keyframes pulse {
        0% { opacity: 0.6; }
        50% { opacity: 1; }
        100% { opacity: 0.6; }
    }
    
    .loading-pulse {
        animation: pulse 1.5s infinite;
    }
</style>

<?php
require_once '../includes/footer.php';
?>