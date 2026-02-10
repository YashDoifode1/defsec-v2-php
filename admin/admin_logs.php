<?php
// admin_logs.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

// Initialize variables
$search = $_GET['search'] ?? '';
$website_id = $_GET['website_id'] ?? '';
$user_id = $_GET['user_id'] ?? '';
$ip = $_GET['ip'] ?? '';
$date = $_GET['date'] ?? date('Y-m-d');
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 30;
$offset = ($page - 1) * $limit;

// Handle actions
$action = $_GET['action'] ?? '';
$log_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

if ($action === 'delete' && $log_id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM logs WHERE id = ?");
        $stmt->execute([$log_id]);
        $success_msg = "Log entry deleted successfully.";
        
        // Log admin action
        logAdminAction($pdo, $admin_auth->getAdminId(), 'delete_log', "Log ID: $log_id");
    } catch (PDOException $e) {
        $error_msg = "Error deleting log: " . $e->getMessage();
    }
} elseif ($action === 'cleanup_old_logs') {
    try {
        // Delete logs older than 30 days
        $stmt = $pdo->prepare("DELETE FROM logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stmt->execute();
        $deleted = $stmt->rowCount();
        $success_msg = "Cleaned up $deleted old log entries.";
        
        // Log admin action
        logAdminAction($pdo, $admin_auth->getAdminId(), 'cleanup_logs', "Deleted: $deleted logs");
    } catch (PDOException $e) {
        $error_msg = "Error cleaning up logs: " . $e->getMessage();
    }
}

// Build query for logs
$query = "
    SELECT 
        l.*,
        w.domain,
        w.site_name,
        u.username,
        u.email as user_email,
        COUNT(*) OVER() as total_count
    FROM logs l
    LEFT JOIN websites w ON l.website_id = w.id
    LEFT JOIN users u ON l.user_id = u.id
";

$count_query = "SELECT COUNT(*) as total FROM logs l";
$conditions = [];
$params = [];

if (!empty($search)) {
    $conditions[] = "(l.ip LIKE ? OR l.real_ip LIKE ? OR l.user_agent LIKE ? OR w.domain LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

if (!empty($website_id) && is_numeric($website_id)) {
    $conditions[] = "l.website_id = ?";
    $params[] = $website_id;
}

if (!empty($user_id) && is_numeric($user_id)) {
    $conditions[] = "l.user_id = ?";
    $params[] = $user_id;
}

if (!empty($ip)) {
    $conditions[] = "(l.ip LIKE ? OR l.real_ip LIKE ?)";
    $ip_param = "%$ip%";
    $params[] = $ip_param;
    $params[] = $ip_param;
}

if (!empty($date)) {
    $conditions[] = "DATE(l.timestamp) = ?";
    $params[] = $date;
}

// Apply conditions
if (!empty($conditions)) {
    $query .= " WHERE " . implode(" AND ", $conditions);
    $count_query .= " WHERE " . implode(" AND ", $conditions);
}

// Add ordering
$query .= " ORDER BY l.timestamp DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;

// Get logs
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total count
$stmt = $pdo->prepare($count_query);
array_pop($params); // Remove limit and offset params
array_pop($params);
$total_logs = $stmt->rowCount() ? $stmt->fetch()['total'] : 0;
$total_pages = ceil($total_logs / $limit);

// Get statistics
$stats = [];
try {
    // Today's logs
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM logs WHERE DATE(timestamp) = CURDATE()");
    $stats['today_logs'] = $stmt->fetch()['count'];
    
    // Unique visitors today
    $stmt = $pdo->query("SELECT COUNT(DISTINCT ip) as count FROM logs WHERE DATE(timestamp) = CURDATE()");
    $stats['unique_visitors'] = $stmt->fetch()['count'];
    
    // VPN/Proxy/Tor detection
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM logs WHERE is_vpn = 1 OR is_proxy = 1 OR is_tor = 1");
    $stats['suspicious_connections'] = $stmt->fetch()['count'];
    
    // Top countries
    $stmt = $pdo->query("
        SELECT country, COUNT(*) as count 
        FROM logs 
        WHERE country != 'Unknown'
        GROUP BY country 
        ORDER BY count DESC 
        LIMIT 5
    ");
    $stats['top_countries'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Browser distribution
    $stmt = $pdo->query("
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
        WHERE user_agent IS NOT NULL
        GROUP BY browser
        ORDER BY count DESC
    ");
    $stats['browser_distribution'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    error_log("Error fetching log stats: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Access Logs</title>
    <!-- Include same CSS as admin_dashboard.php -->
</head>
<body>
    <!-- Include Navbar and Sidebar -->
    <?php include 'includes/admin_navbar.php'; ?>
    <?php include 'includes/admin_sidebar.php'; ?>
    
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1"><i class="bi bi-list-check me-2"></i>Access Logs</h2>
                <p class="text-muted mb-0">Monitor visitor access and fingerprinting data</p>
            </div>
            <div>
                <button type="button" class="btn btn-admin btn-admin-danger me-2" 
                        onclick="cleanupOldLogs()">
                    <i class="bi bi-trash me-1"></i>Cleanup Old Logs
                </button>
                <button type="button" class="btn btn-admin btn-admin-primary" onclick="exportLogs()">
                    <i class="bi bi-download me-1"></i>Export
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
        
        <!-- Stats Cards -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-primary me-3">
                            <i class="bi bi-eye"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($total_logs) ?></div>
                            <div class="stat-label small">Total Logs</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-success me-3">
                            <i class="bi bi-people"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['unique_visitors'] ?? 0) ?></div>
                            <div class="stat-label small">Unique Visitors</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-warning me-3">
                            <i class="bi bi-shield-exclamation"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['suspicious_connections'] ?? 0) ?></div>
                            <div class="stat-label small">Suspicious</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-info me-3">
                            <i class="bi bi-clock-history"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['today_logs'] ?? 0) ?></div>
                            <div class="stat-label small">Today's Logs</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3">
                <div class="col-md-3">
                    <input type="text" class="form-control" name="search" placeholder="Search IP, User Agent, Domain..." 
                           value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="website_id" placeholder="Website ID" 
                           value="<?= htmlspecialchars($website_id) ?>">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="user_id" placeholder="User ID" 
                           value="<?= htmlspecialchars($user_id) ?>">
                </div>
                <div class="col-md-2">
                    <input type="text" class="form-control" name="ip" placeholder="IP Address" 
                           value="<?= htmlspecialchars($ip) ?>">
                </div>
                <div class="col-md-2">
                    <input type="date" class="form-control" name="date" 
                           value="<?= htmlspecialchars($date) ?>" 
                           max="<?= date('Y-m-d') ?>">
                </div>
                <div class="col-md-1">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-search"></i>
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Logs Table -->
        <div class="dashboard-card table-card">
            <div class="table-responsive">
                <table class="table table-dark table-hover" id="logsTable">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Country</th>
                            <th>Browser</th>
                            <th>Device</th>
                            <th>Website</th>
                            <th>User</th>
                            <th>Threat</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                            <tr class="<?= ($log['is_vpn'] || $log['is_proxy'] || $log['is_tor']) ? 'table-warning' : '' ?>">
                                <td class="text-nowrap">
                                    <?= formatDate($log['timestamp'], 'H:i:s') ?>
                                    <br>
                                    <small class="text-muted"><?= formatDate($log['timestamp'], 'm-d') ?></small>
                                </td>
                                <td>
                                    <div>
                                        <code><?= htmlspecialchars($log['ip']) ?></code>
                                        <?php if ($log['real_ip'] !== $log['ip']): ?>
                                            <br>
                                            <small class="text-muted">Real: <?= htmlspecialchars($log['real_ip']) ?></small>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td>
                                    <?php if ($log['country'] !== 'Unknown'): ?>
                                        <span class="badge bg-secondary">
                                            <?= htmlspecialchars($log['country']) ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="badge bg-dark">Unknown</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php
                                    $user_agent = $log['user_agent'] ?? '';
                                    $browser = 'Unknown';
                                    if (stripos($user_agent, 'Chrome') !== false) $browser = 'Chrome';
                                    elseif (stripos($user_agent, 'Firefox') !== false) $browser = 'Firefox';
                                    elseif (stripos($user_agent, 'Safari') !== false && stripos($user_agent, 'Chrome') === false) $browser = 'Safari';
                                    elseif (stripos($user_agent, 'Edge') !== false) $browser = 'Edge';
                                    elseif (stripos($user_agent, 'Opera') !== false) $browser = 'Opera';
                                    ?>
                                    <span class="badge bg-info"><?= $browser ?></span>
                                </td>
                                <td>
                                    <?php
                                    $screen = $log['screen_resolution'] ?? 'Unknown';
                                    $device = 'Desktop';
                                    if (strpos($screen, 'x')) {
                                        list($width, $height) = explode('x', $screen);
                                        if ($width <= 768) $device = 'Mobile';
                                        elseif ($width <= 1024) $device = 'Tablet';
                                    }
                                    ?>
                                    <small><?= $device ?></small>
                                    <br>
                                    <small class="text-muted"><?= $screen ?></small>
                                </td>
                                <td>
                                    <?php if ($log['domain']): ?>
                                        <div class="small"><?= htmlspecialchars($log['site_name']) ?></div>
                                        <div class="x-small text-muted"><?= htmlspecialchars($log['domain']) ?></div>
                                    <?php else: ?>
                                        <span class="text-muted">N/A</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($log['username']): ?>
                                        <div><?= htmlspecialchars($log['username']) ?></div>
                                        <div class="x-small text-muted">ID: <?= $log['user_id'] ?></div>
                                    <?php else: ?>
                                        <span class="text-muted">N/A</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div class="d-flex gap-1">
                                        <?php if ($log['is_vpn']): ?>
                                            <span class="badge bg-danger" data-bs-toggle="tooltip" title="VPN Detected">VPN</span>
                                        <?php endif; ?>
                                        <?php if ($log['is_proxy']): ?>
                                            <span class="badge bg-warning" data-bs-toggle="tooltip" title="Proxy Detected">Proxy</span>
                                        <?php endif; ?>
                                        <?php if ($log['is_tor']): ?>
                                            <span class="badge bg-dark" data-bs-toggle="tooltip" title="Tor Network">Tor</span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <button type="button" class="btn btn-outline-info" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#logDetailsModal<?= $log['id'] ?>">
                                            <i class="bi bi-info-circle"></i>
                                        </button>
                                        <a href="admin_logs.php?action=delete&id=<?= $log['id'] ?>" 
                                           class="btn btn-outline-secondary" 
                                           onclick="return confirm('Delete this log entry?')">
                                            <i class="bi bi-trash"></i>
                                        </a>
                                    </div>
                                    
                                    <!-- Log Details Modal -->
                                    <div class="modal fade" id="logDetailsModal<?= $log['id'] ?>" tabindex="-1" aria-hidden="true">
                                        <div class="modal-dialog modal-lg">
                                            <div class="modal-content bg-dark">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Log Details #<?= $log['id'] ?></h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="row">
                                                        <div class="col-md-6">
                                                            <h6>Connection Information</h6>
                                                            <table class="table table-sm table-borderless">
                                                                <tr>
                                                                    <th>IP Address:</th>
                                                                    <td><code><?= htmlspecialchars($log['ip']) ?></code></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Real IP:</th>
                                                                    <td><code><?= htmlspecialchars($log['real_ip']) ?></code></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Country:</th>
                                                                    <td><?= htmlspecialchars($log['country']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>ISP:</th>
                                                                    <td><?= htmlspecialchars($log['ISP']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>ASN:</th>
                                                                    <td><?= htmlspecialchars($log['ASN']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Threat Level:</th>
                                                                    <td>
                                                                        <?php if ($log['is_vpn'] || $log['is_proxy'] || $log['is_tor']): ?>
                                                                            <span class="badge bg-danger">High</span>
                                                                        <?php else: ?>
                                                                            <span class="badge bg-success">Low</span>
                                                                        <?php endif; ?>
                                                                    </td>
                                                                </tr>
                                                            </table>
                                                        </div>
                                                        <div class="col-md-6">
                                                            <h6>Device Information</h6>
                                                            <table class="table table-sm table-borderless">
                                                                <tr>
                                                                    <th>User Agent:</th>
                                                                    <td><small><?= htmlspecialchars($log['user_agent'] ?? 'N/A') ?></small></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Screen:</th>
                                                                    <td><?= htmlspecialchars($log['screen_resolution']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Language:</th>
                                                                    <td><?= htmlspecialchars($log['language']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>Timezone:</th>
                                                                    <td><?= htmlspecialchars($log['timezone']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>CPU Cores:</th>
                                                                    <td><?= htmlspecialchars($log['cpu_cores']) ?></td>
                                                                </tr>
                                                                <tr>
                                                                    <th>RAM:</th>
                                                                    <td><?= htmlspecialchars($log['ram']) ?></td>
                                                                </tr>
                                                            </table>
                                                        </div>
                                                    </div>
                                                    <div class="mt-3">
                                                        <h6>Additional Information</h6>
                                                        <table class="table table-sm table-borderless">
                                                            <tr>
                                                                <th>Digital DNA:</th>
                                                                <td><code><?= htmlspecialchars($log['digital_dna']) ?></code></td>
                                                            </tr>
                                                            <tr>
                                                                <th>Referrer:</th>
                                                                <td><?= htmlspecialchars($log['referrer'] ?? 'Direct') ?></td>
                                                            </tr>
                                                            <tr>
                                                                <th>Cookies Enabled:</th>
                                                                <td><?= $log['cookies_enabled'] === 'true' ? 'Yes' : 'No' ?></td>
                                                            </tr>
                                                            <tr>
                                                                <th>Plugins:</th>
                                                                <td><small><?= htmlspecialchars($log['plugins'] ?? 'None') ?></small></td>
                                                            </tr>
                                                        </table>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($logs)): ?>
                            <tr>
                                <td colspan="9" class="text-center py-4 text-muted">
                                    <i class="bi bi-journal-x mb-2" style="font-size: 2rem;"></i>
                                    <p class="mb-0">No log entries found</p>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <nav class="mt-3">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page - 1 ?>&<?= http_build_query($_GET) ?>">
                                    Previous
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>&<?= http_build_query($_GET) ?>">
                                    <?= $i ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page + 1 ?>&<?= http_build_query($_GET) ?>">
                                    Next
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
        </div>
        
        <!-- Statistics Section -->
        <div class="row g-4 mt-2">
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-globe me-2"></i>Top Countries</h5>
                    <div class="list-group">
                        <?php foreach ($stats['top_countries'] ?? [] as $country): ?>
                            <div class="list-group-item d-flex justify-content-between align-items-center bg-transparent border-secondary">
                                <div>
                                    <i class="bi bi-flag me-2"></i>
                                    <?= htmlspecialchars($country['country']) ?>
                                </div>
                                <span class="badge bg-primary"><?= $country['count'] ?></span>
                            </div>
                        <?php endforeach; ?>
                        <?php if (empty($stats['top_countries'])): ?>
                            <div class="text-center py-3 text-muted">
                                <i class="bi bi-globe mb-2"></i>
                                <p class="mb-0">No country data available</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-browser-chrome me-2"></i>Browser Distribution</h5>
                    <div class="chart-container">
                        <canvas id="browserChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        function cleanupOldLogs() {
            if (confirm('Delete all logs older than 30 days?\n\nThis action cannot be undone.')) {
                window.location.href = 'admin_logs.php?action=cleanup_old_logs';
            }
        }
        
        function exportLogs() {
            const params = new URLSearchParams(window.location.search);
            window.open(`ajax/export_logs.php?${params.toString()}`, '_blank');
        }
        
        $(document).ready(function() {
            // Initialize DataTable
            $('#logsTable').DataTable({
                pageLength: 30,
                order: [[0, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search logs...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ logs",
                    infoEmpty: "No logs found",
                    infoFiltered: "(filtered from _MAX_ total logs)"
                }
            });
            
            // Initialize tooltips
            $('[data-bs-toggle="tooltip"]').tooltip();
            
            // Initialize browser chart
            initializeBrowserChart();
        });
        
        function initializeBrowserChart() {
            const ctx = document.getElementById('browserChart').getContext('2d');
            const browserData = <?= json_encode($stats['browser_distribution'] ?? []) ?>;
            
            const labels = browserData.map(item => item.browser);
            const data = browserData.map(item => item.count);
            const colors = ['#4285F4', '#FF6B35', '#43A047', '#0078D7', '#FF1B1C', '#6C757D'];
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors.slice(0, labels.length)
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
    </script>
</body>
</html>