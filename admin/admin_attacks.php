<?php
// admin_attacks.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

// Initialize variables
$search = $_GET['search'] ?? '';
$severity = $_GET['severity'] ?? '';
$attack_type = $_GET['attack_type'] ?? '';
$website_id = $_GET['website_id'] ?? '';
$user_id = $_GET['user_id'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 25;
$offset = ($page - 1) * $limit;

// Handle actions
$action = $_GET['action'] ?? '';
$attack_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

if ($action === 'delete' && $attack_id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM attack_logs WHERE id = ?");
        $stmt->execute([$attack_id]);
        $success_msg = "Attack log deleted successfully.";
        
        // Log admin action
        logAdminAction($pdo, $admin_auth->getAdminId(), 'delete_attack_log', "Attack ID: $attack_id");
    } catch (PDOException $e) {
        $error_msg = "Error deleting attack log: " . $e->getMessage();
    }
} elseif ($action === 'block_ip' && $attack_id) {
    try {
        // Get attack details
        $stmt = $pdo->prepare("SELECT ip_address, website_id FROM attack_logs WHERE id = ?");
        $stmt->execute([$attack_id]);
        $attack = $stmt->fetch();
        
        if ($attack) {
            // Block IP for 24 hours
            $stmt = $pdo->prepare("
                INSERT INTO blocked_ips (user_id, ip, website_id, reason, created_at, expiry_time)
                VALUES (?, ?, ?, ?, NOW(), DATE_ADD(CURTIME(), INTERVAL 24 HOUR))
            ");
            $stmt->execute([
                $admin_auth->getAdminId(),
                $attack['ip_address'],
                $attack['website_id'],
                'Blocked due to attack'
            ]);
            $success_msg = "IP address blocked successfully.";
            
            // Log admin action
            logAdminAction($pdo, $admin_auth->getAdminId(), 'block_ip_from_attack', 
                         "IP: {$attack['ip_address']}, Website ID: {$attack['website_id']}");
        }
    } catch (PDOException $e) {
        $error_msg = "Error blocking IP: " . $e->getMessage();
    }
}

// Build query for attack logs
$query = "
    SELECT 
        al.*,
        w.domain,
        w.site_name,
        u.username,
        u.email as user_email,
        COUNT(*) OVER() as total_count
    FROM attack_logs al
    JOIN websites w ON al.website_id = w.id
    JOIN users u ON al.user_id = u.id
";

$count_query = "SELECT COUNT(*) as total FROM attack_logs al";
$conditions = [];
$params = [];

if (!empty($search)) {
    $conditions[] = "(al.ip_address LIKE ? OR al.attack_type LIKE ? OR w.domain LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

if (!empty($severity) && in_array($severity, ['Critical', 'High', 'Medium', 'Info'])) {
    $conditions[] = "al.severity = ?";
    $params[] = $severity;
}

if (!empty($attack_type)) {
    $conditions[] = "al.attack_type = ?";
    $params[] = $attack_type;
}

if (!empty($website_id) && is_numeric($website_id)) {
    $conditions[] = "al.website_id = ?";
    $params[] = $website_id;
}

if (!empty($user_id) && is_numeric($user_id)) {
    $conditions[] = "al.user_id = ?";
    $params[] = $user_id;
}

if (!empty($date_from)) {
    $conditions[] = "DATE(al.timestamp) >= ?";
    $params[] = $date_from;
}

if (!empty($date_to)) {
    $conditions[] = "DATE(al.timestamp) <= ?";
    $params[] = $date_to;
}

// Apply conditions
if (!empty($conditions)) {
    $query .= " WHERE " . implode(" AND ", $conditions);
    $count_query .= " WHERE " . implode(" AND ", $conditions);
}

// Add ordering
$query .= " ORDER BY al.timestamp DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;

// Get attack logs
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$attacks = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total count
$stmt = $pdo->prepare($count_query);
array_pop($params); // Remove limit and offset params
array_pop($params);
$total_attacks = $stmt->rowCount() ? $stmt->fetch()['total'] : 0;
$total_pages = ceil($total_attacks / $limit);

// Get statistics
$stats = [];
try {
    // Severity distribution
    $stmt = $pdo->query("
        SELECT severity, COUNT(*) as count 
        FROM attack_logs 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY severity
    ");
    $severity_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($severity_stats as $stat) {
        $stats['severity_' . strtolower($stat['severity'])] = $stat['count'];
    }
    
    // Today's attacks
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM attack_logs WHERE DATE(timestamp) = CURDATE()");
    $stats['today_attacks'] = $stmt->fetch()['count'];
    
    // This week's attacks
    $stmt = $pdo->query("
        SELECT COUNT(*) as count 
        FROM attack_logs 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $stats['week_attacks'] = $stmt->fetch()['count'];
    
    // Top attack types
    $stmt = $pdo->query("
        SELECT attack_type, COUNT(*) as count 
        FROM attack_logs 
        GROUP BY attack_type 
        ORDER BY count DESC 
        LIMIT 5
    ");
    $stats['top_attack_types'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    error_log("Error fetching attack stats: " . $e->getMessage());
}

// Get unique attack types for filter
$attack_types = [];
try {
    $stmt = $pdo->query("SELECT DISTINCT attack_type FROM attack_logs WHERE attack_type IS NOT NULL ORDER BY attack_type");
    $attack_types = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
} catch (PDOException $e) {
    error_log("Error fetching attack types: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Attack Logs</title>
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
                <h2 class="h3 mb-1"><i class="bi bi-shield-exclamation me-2"></i>Attack Logs</h2>
                <p class="text-muted mb-0">Monitor and analyze security attacks</p>
            </div>
            <div>
                <button type="button" class="btn btn-admin btn-admin-primary" onclick="exportAttackLogs()">
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
                        <div class="stat-icon text-danger me-3">
                            <i class="bi bi-fire"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['severity_critical'] ?? 0 ?></div>
                            <div class="stat-label small">Critical</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-warning me-3">
                            <i class="bi bi-exclamation-triangle"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['severity_high'] ?? 0 ?></div>
                            <div class="stat-label small">High</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-info me-3">
                            <i class="bi bi-info-circle"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['severity_medium'] ?? 0 ?></div>
                            <div class="stat-label small">Medium</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-secondary me-3">
                            <i class="bi bi-shield"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['today_attacks'] ?? 0 ?></div>
                            <div class="stat-label small">Today</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Advanced Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3" id="filterForm">
                <div class="col-md-3">
                    <input type="text" class="form-control" name="search" placeholder="Search IP, type, domain..." 
                           value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="severity">
                        <option value="">All Severity</option>
                        <option value="Critical" <?= $severity === 'Critical' ? 'selected' : '' ?>>Critical</option>
                        <option value="High" <?= $severity === 'High' ? 'selected' : '' ?>>High</option>
                        <option value="Medium" <?= $severity === 'Medium' ? 'selected' : '' ?>>Medium</option>
                        <option value="Info" <?= $severity === 'Info' ? 'selected' : '' ?>>Info</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="attack_type">
                        <option value="">All Types</option>
                        <?php foreach ($attack_types as $type): ?>
                            <option value="<?= htmlspecialchars($type) ?>" <?= $attack_type === $type ? 'selected' : '' ?>>
                                <?= htmlspecialchars($type) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="website_id" placeholder="Website ID" 
                           value="<?= htmlspecialchars($website_id) ?>">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="user_id" placeholder="User ID" 
                           value="<?= htmlspecialchars($user_id) ?>">
                </div>
                <div class="col-md-3">
                    <input type="date" class="form-control" name="date_from" 
                           value="<?= htmlspecialchars($date_from) ?>" 
                           max="<?= date('Y-m-d') ?>">
                </div>
                <div class="col-md-3">
                    <input type="date" class="form-control" name="date_to" 
                           value="<?= htmlspecialchars($date_to) ?>"
                           max="<?= date('Y-m-d') ?>">
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
                <div class="col-md-2">
                    <button type="button" class="btn btn-outline-secondary w-100" onclick="resetFilters()">
                        <i class="bi bi-arrow-clockwise me-1"></i>Reset
                    </button>
                </div>
                <div class="col-md-2">
                    <button type="button" class="btn btn-outline-info w-100" data-bs-toggle="collapse" 
                            data-bs-target="#advancedFilters">
                        <i class="bi bi-funnel me-1"></i>Advanced
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Attacks Table -->
        <div class="dashboard-card table-card">
            <div class="table-responsive">
                <table class="table table-dark table-hover" id="attacksTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Time</th>
                            <th>Attack Type</th>
                            <th>Severity</th>
                            <th>IP Address</th>
                            <th>Website</th>
                            <th>User</th>
                            <th>Payload</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($attacks as $attack): ?>
                            <tr class="<?= $attack['severity'] === 'Critical' ? 'table-danger' : '' ?>">
                                <td>#<?= $attack['id'] ?></td>
                                <td class="text-nowrap">
                                    <?= formatDate($attack['timestamp'], 'Y-m-d H:i') ?>
                                </td>
                                <td>
                                    <span class="badge bg-dark"><?= htmlspecialchars($attack['attack_type']) ?></span>
                                </td>
                                <td>
                                    <span class="badge bg-<?= getSeverityBadge($attack['severity']) ?>">
                                        <?= $attack['severity'] ?>
                                    </span>
                                </td>
                                <td>
                                    <code><?= htmlspecialchars($attack['ip_address']) ?></code>
                                    <button type="button" class="btn btn-sm btn-outline-info ms-1" 
                                            onclick="showIPDetails('<?= htmlspecialchars($attack['ip_address']) ?>')">
                                        <i class="bi bi-info-circle"></i>
                                    </button>
                                </td>
                                <td>
                                    <div>
                                        <div class="small"><?= htmlspecialchars($attack['site_name']) ?></div>
                                        <div class="x-small text-muted"><?= htmlspecialchars($attack['domain']) ?></div>
                                    </div>
                                </td>
                                <td>
                                    <div>
                                        <div><?= htmlspecialchars($attack['username']) ?></div>
                                        <div class="x-small text-muted"><?= htmlspecialchars($attack['user_email']) ?></div>
                                    </div>
                                </td>
                                <td>
                                    <button type="button" class="btn btn-sm btn-outline-warning" 
                                            data-bs-toggle="modal" 
                                            data-bs-target="#payloadModal<?= $attack['id'] ?>">
                                        <i class="bi bi-code"></i> View
                                    </button>
                                    
                                    <!-- Payload Modal -->
                                    <div class="modal fade" id="payloadModal<?= $attack['id'] ?>" tabindex="-1" aria-hidden="true">
                                        <div class="modal-dialog modal-lg">
                                            <div class="modal-content bg-dark">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Attack Payload Details</h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <div class="mb-3">
                                                        <strong>Attack Type:</strong> <?= htmlspecialchars($attack['attack_type']) ?><br>
                                                        <strong>Severity:</strong> <?= $attack['severity'] ?><br>
                                                        <strong>IP Address:</strong> <?= htmlspecialchars($attack['ip_address']) ?><br>
                                                        <strong>Time:</strong> <?= formatDate($attack['timestamp']) ?>
                                                    </div>
                                                    <div class="mb-3">
                                                        <label class="form-label">Payload:</label>
                                                        <pre class="bg-dark border rounded p-3" style="max-height: 300px; overflow: auto;">
<?= htmlspecialchars($attack['attack_payload'] ?? 'No payload available') ?></pre>
                                                    </div>
                                                    <div>
                                                        <label class="form-label">Request URL:</label>
                                                        <code class="d-block bg-dark border rounded p-2">
                                                            <?= htmlspecialchars($attack['request_url'] ?? 'N/A') ?>
                                                        </code>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="admin_attacks.php?action=block_ip&id=<?= $attack['id'] ?>" 
                                           class="btn btn-outline-danger" data-bs-toggle="tooltip" title="Block IP">
                                            <i class="bi bi-ban"></i>
                                        </a>
                                        <button type="button" class="btn btn-outline-warning" 
                                                onclick="investigateAttack(<?= $attack['id'] ?>)" 
                                                data-bs-toggle="tooltip" title="Investigate">
                                            <i class="bi bi-search"></i>
                                        </button>
                                        <a href="admin_attacks.php?action=delete&id=<?= $attack['id'] ?>" 
                                           class="btn btn-outline-secondary" 
                                           onclick="return confirm('Delete this attack log?')"
                                           data-bs-toggle="tooltip" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($attacks)): ?>
                            <tr>
                                <td colspan="9" class="text-center py-4 text-muted">
                                    <i class="bi bi-shield-check mb-2" style="font-size: 2rem;"></i>
                                    <p class="mb-0">No attack logs found</p>
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
        
        <!-- Analysis Section -->
        <div class="row g-4 mt-2">
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-pie-chart me-2"></i>Attack Type Distribution</h5>
                    <div class="chart-container">
                        <canvas id="attackTypeChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-clock-history me-2"></i>Recent Activity Timeline</h5>
                    <div class="chart-container">
                        <canvas id="attackTimelineChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <!-- IP Details Modal -->
    <div class="modal fade" id="ipDetailsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">IP Address Details</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="ipDetailsContent">
                    <!-- Content will be loaded via AJAX -->
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        function resetFilters() {
            window.location.href = 'admin_attacks.php';
        }
        
        function showIPDetails(ip) {
            const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
            const content = document.getElementById('ipDetailsContent');
            
            // Load IP details via AJAX
            fetch(`ajax/ip_details.php?ip=${encodeURIComponent(ip)}`)
                .then(response => response.text())
                .then(html => {
                    content.innerHTML = html;
                    modal.show();
                })
                .catch(error => {
                    console.error('Error loading IP details:', error);
                    content.innerHTML = '<div class="alert alert-danger">Error loading IP details</div>';
                    modal.show();
                });
        }
        
        function investigateAttack(attackId) {
            // Implement attack investigation
            window.open(`attack_investigation.php?id=${attackId}`, '_blank');
        }
        
        function exportAttackLogs() {
            const params = new URLSearchParams(window.location.search);
            window.open(`ajax/export_attacks.php?${params.toString()}`, '_blank');
        }
        
        $(document).ready(function() {
            // Initialize DataTable
            $('#attacksTable').DataTable({
                pageLength: 25,
                order: [[1, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search attacks...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ attacks",
                    infoEmpty: "No attacks found",
                    infoFiltered: "(filtered from _MAX_ total attacks)"
                }
            });
            
            // Initialize tooltips
            $('[data-bs-toggle="tooltip"]').tooltip();
            
            // Initialize charts
            initializeCharts();
        });
        
        function initializeCharts() {
            // Attack Type Distribution Chart
            const typeCtx = document.getElementById('attackTypeChart').getContext('2d');
            new Chart(typeCtx, {
                type: 'pie',
                data: {
                    labels: <?= json_encode(array_column($stats['top_attack_types'] ?? [], 'attack_type')) ?>,
                    datasets: [{
                        data: <?= json_encode(array_column($stats['top_attack_types'] ?? [], 'count')) ?>,
                        backgroundColor: [
                            '#dc3545', '#fd7e14', '#ffc107', '#0dcaf0', '#6c757d'
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
            
            // Attack Timeline Chart (dummy data for now)
            const timelineCtx = document.getElementById('attackTimelineChart').getContext('2d');
            new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: ['6h ago', '5h ago', '4h ago', '3h ago', '2h ago', '1h ago', 'Now'],
                    datasets: [{
                        label: 'Attacks',
                        data: [12, 19, 8, 15, 22, 17, 14],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        fill: true
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
    </script>
</body>
</html>