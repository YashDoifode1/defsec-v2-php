<?php
// admin_website_view.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

$website_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

// Get website details
$website = null;
$user = null;
$stats = [];
$recent_activities = [];
$top_attack_types = [];
$top_blocked_ips = [];

if ($website_id) {
    try {
        // Get website info
        $stmt = $pdo->prepare("
            SELECT w.*, u.username, u.email, u.full_name, u.role as user_role
            FROM websites w
            JOIN users u ON w.user_id = u.id
            WHERE w.id = ?
        ");
        $stmt->execute([$website_id]);
        $website = $stmt->fetch();
        
        if (!$website) {
            header("Location: admin_websites.php");
            exit();
        }
        
        // Get statistics
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(DISTINCT al.id) as total_access,
                COUNT(DISTINCT atl.id) as total_attacks,
                COUNT(DISTINCT bi.id) as active_blocks,
                COUNT(DISTINCT l.id) as total_logs
            FROM websites w
            LEFT JOIN access_logs al ON w.id = al.website_id
            LEFT JOIN attack_logs atl ON w.id = atl.website_id
            LEFT JOIN blocked_ips bi ON w.id = bi.website_id AND bi.expiry_time > CURTIME()
            LEFT JOIN logs l ON w.id = l.website_id
            WHERE w.id = ?
        ");
        $stmt->execute([$website_id]);
        $stats = $stmt->fetch();
        
        // Get today's stats
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(DISTINCT al.id) as today_access,
                COUNT(DISTINCT atl.id) as today_attacks
            FROM websites w
            LEFT JOIN access_logs al ON w.id = al.website_id AND DATE(al.timestamp) = CURDATE()
            LEFT JOIN attack_logs atl ON w.id = atl.website_id AND DATE(atl.timestamp) = CURDATE()
            WHERE w.id = ?
        ");
        $stmt->execute([$website_id]);
        $today_stats = $stmt->fetch();
        $stats = array_merge($stats, $today_stats);
        
        // Get recent attacks
        $stmt = $pdo->prepare("
            SELECT 
                atl.*,
                u.username as attack_username
            FROM attack_logs atl
            LEFT JOIN users u ON atl.user_id = u.id
            WHERE atl.website_id = ?
            ORDER BY atl.timestamp DESC
            LIMIT 10
        ");
        $stmt->execute([$website_id]);
        $recent_activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get top attack types
        $stmt = $pdo->prepare("
            SELECT 
                attack_type,
                COUNT(*) as count,
                MAX(timestamp) as last_occurrence
            FROM attack_logs
            WHERE website_id = ?
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
        ");
        $stmt->execute([$website_id]);
        $top_attack_types = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get top blocked IPs
        $stmt = $pdo->prepare("
            SELECT 
                ip,
                COUNT(*) as block_count,
                MAX(created_at) as last_blocked,
                GROUP_CONCAT(DISTINCT reason SEPARATOR ', ') as reasons
            FROM blocked_ips
            WHERE website_id = ?
            GROUP BY ip
            ORDER BY block_count DESC
            LIMIT 5
        ");
        $stmt->execute([$website_id]);
        $top_blocked_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get allowed countries
        $stmt = $pdo->prepare("
            SELECT country_code, country_name, is_allowed
            FROM allowed_countries
            WHERE website_id = ?
            ORDER BY country_name
        ");
        $stmt->execute([$website_id]);
        $allowed_countries = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        $error_msg = "Error fetching website data: " . $e->getMessage();
    }
} else {
    header("Location: admin_websites.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Website Details</title>
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
                <h2 class="h3 mb-1">
                    <i class="bi bi-globe me-2"></i>
                    <?= htmlspecialchars($website['site_name']) ?>
                    <small class="text-muted">(ID: #<?= $website['id'] ?>)</small>
                </h2>
                <p class="text-muted mb-0">
                    <code><?= htmlspecialchars($website['domain']) ?></code>
                    • Owned by <?= htmlspecialchars($website['username']) ?>
                </p>
            </div>
            <div>
                <a href="admin_websites.php" class="btn btn-outline-secondary me-2">
                    <i class="bi bi-arrow-left me-1"></i>Back
                </a>
                <a href="admin_website_edit.php?id=<?= $website['id'] ?>" class="btn btn-primary">
                    <i class="bi bi-pencil me-1"></i>Edit
                </a>
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
        
        <div class="row g-4">
            <!-- Left Column - Info & Stats -->
            <div class="col-lg-4">
                <!-- Website Info Card -->
                <div class="dashboard-card">
                    <div class="text-center mb-4">
                        <div class="mb-3" style="font-size: 3rem;">
                            <i class="bi bi-globe text-primary"></i>
                        </div>
                        <h4><?= htmlspecialchars($website['site_name']) ?></h4>
                        <p class="text-muted">
                            <code><?= htmlspecialchars($website['domain']) ?></code>
                        </p>
                        
                        <div class="mb-3">
                            <span class="badge bg-<?= getStatusBadge($website['status']) ?>">
                                <?= ucfirst($website['status']) ?>
                            </span>
                            <span class="badge bg-secondary ms-1">
                                Since <?= formatDate($website['created_at'], 'M Y') ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="list-group list-group-flush">
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-person me-2"></i>Owner</span>
                            <span>
                                <?= htmlspecialchars($website['username']) ?>
                                <span class="badge bg-<?= getRoleBadge($website['user_role']) ?> ms-1">
                                    <?= ucfirst($website['user_role']) ?>
                                </span>
                            </span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-envelope me-2"></i>Email</span>
                            <span><?= htmlspecialchars($website['email']) ?></span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-calendar me-2"></i>Created</span>
                            <span><?= formatDate($website['created_at']) ?></span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-shield me-2"></i>Protection</span>
                            <span>
                                <span class="badge bg-<?= $stats['active_blocks'] > 0 ? 'success' : 'secondary' ?>">
                                    Active
                                </span>
                            </span>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <a href="admin_websites.php?action=toggle_status&id=<?= $website['id'] ?>" 
                           class="btn btn-outline-<?= $website['status'] === 'active' ? 'warning' : 'success' ?> w-100 mb-2">
                            <i class="bi bi-<?= $website['status'] === 'active' ? 'pause' : 'play' ?> me-1"></i>
                            <?= $website['status'] === 'active' ? 'Pause Protection' : 'Activate Protection' ?>
                        </a>
                        <a href="../logs.php?website_id=<?= $website['id'] ?>" target="_blank" 
                           class="btn btn-outline-info w-100">
                            <i class="bi bi-bar-chart me-1"></i>View Live Logs
                        </a>
                    </div>
                </div>
                
                <!-- Quick Stats -->
                <div class="dashboard-card mt-4">
                    <h6 class="mb-3"><i class="bi bi-bar-chart me-2"></i>Quick Statistics</h6>
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <div class="h4 mb-1 text-primary"><?= number_format($stats['total_access'] ?? 0) ?></div>
                            <div class="small text-muted">Total Access</div>
                            <div class="x-small text-success">+<?= number_format($stats['today_access'] ?? 0) ?> today</div>
                        </div>
                        <div class="col-6 mb-3">
                            <div class="h4 mb-1 text-danger"><?= number_format($stats['total_attacks'] ?? 0) ?></div>
                            <div class="small text-muted">Attack Attempts</div>
                            <div class="x-small text-danger">+<?= number_format($stats['today_attacks'] ?? 0) ?> today</div>
                        </div>
                        <div class="col-6">
                            <div class="h4 mb-1 text-warning"><?= number_format($stats['active_blocks'] ?? 0) ?></div>
                            <div class="small text-muted">Blocked IPs</div>
                        </div>
                        <div class="col-6">
                            <div class="h4 mb-1 text-info"><?= number_format($stats['total_logs'] ?? 0) ?></div>
                            <div class="small text-muted">Total Logs</div>
                        </div>
                    </div>
                </div>
                
                <!-- Top Attack Types -->
                <div class="dashboard-card mt-4">
                    <h6 class="mb-3"><i class="bi bi-shield-exclamation me-2"></i>Top Attack Types</h6>
                    <?php if (!empty($top_attack_types)): ?>
                        <div class="list-group">
                            <?php foreach ($top_attack_types as $attack): ?>
                                <div class="list-group-item d-flex justify-content-between align-items-center bg-transparent border-secondary">
                                    <div>
                                        <div class="fw-bold"><?= htmlspecialchars($attack['attack_type'] ?? 'Unknown') ?></div>
                                        <div class="small text-muted">
                                            Last: <?= formatDate($attack['last_occurrence'], 'M j') ?>
                                        </div>
                                    </div>
                                    <span class="badge bg-danger"><?= $attack['count'] ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-3 text-muted">
                            <i class="bi bi-check-circle mb-2"></i>
                            <p class="mb-0">No attack data</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Right Column - Activities & Details -->
            <div class="col-lg-8">
                <!-- Recent Security Activities -->
                <div class="dashboard-card mb-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="mb-0"><i class="bi bi-activity me-2"></i>Recent Security Activities</h5>
                        <a href="admin_attacks.php?website_id=<?= $website['id'] ?>" class="btn btn-sm btn-outline-primary">
                            View All
                        </a>
                    </div>
                    
                    <?php if (!empty($recent_activities)): ?>
                        <div class="table-responsive">
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Type</th>
                                        <th>Severity</th>
                                        <th>IP Address</th>
                                        <th>User</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recent_activities as $activity): ?>
                                        <tr>
                                            <td class="text-nowrap">
                                                <?= formatDate($activity['timestamp'], 'H:i') ?>
                                            </td>
                                            <td><?= htmlspecialchars($activity['attack_type']) ?></td>
                                            <td>
                                                <span class="badge bg-<?= getSeverityBadge($activity['severity']) ?>">
                                                    <?= $activity['severity'] ?>
                                                </span>
                                            </td>
                                            <td>
                                                <code><?= htmlspecialchars($activity['ip_address']) ?></code>
                                            </td>
                                            <td><?= htmlspecialchars($activity['attack_username'] ?? 'Unknown') ?></td>
                                            <td>
                                                <button type="button" class="btn btn-sm btn-outline-info" 
                                                        data-bs-toggle="popover" 
                                                        title="Attack Details"
                                                        data-bs-content="<?= htmlspecialchars($activity['attack_payload'] ?? 'No details available') ?>">
                                                    <i class="bi bi-info-circle"></i>
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-4 text-muted">
                            <i class="bi bi-shield-check mb-3" style="font-size: 2rem;"></i>
                            <p class="mb-0">No recent security activities</p>
                        </div>
                    <?php endif; ?>
                </div>
                
                <!-- Top Blocked IPs -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-ban me-2"></i>Top Blocked IPs</h5>
                    
                    <?php if (!empty($top_blocked_ips)): ?>
                        <div class="table-responsive">
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Block Count</th>
                                        <th>Last Blocked</th>
                                        <th>Reasons</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($top_blocked_ips as $ip): ?>
                                        <tr>
                                            <td>
                                                <code><?= htmlspecialchars($ip['ip']) ?></code>
                                                <?php
                                                $ip_info = getIPInfo($ip['ip']);
                                                if ($ip_info['country'] !== 'Unknown'): ?>
                                                    <span class="badge bg-secondary ms-1">
                                                        <?= $ip_info['country'] ?>
                                                    </span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="badge bg-danger"><?= $ip['block_count'] ?></span>
                                            </td>
                                            <td><?= formatDate($ip['last_blocked'], 'M j, H:i') ?></td>
                                            <td>
                                                <small><?= htmlspecialchars(truncateText($ip['reasons'], 50)) ?></small>
                                            </td>
                                            <td>
                                                <button type="button" class="btn btn-sm btn-outline-danger" 
                                                        onclick="permanentBlock('<?= htmlspecialchars($ip['ip']) ?>', <?= $website['id'] ?>)">
                                                    <i class="bi bi-ban"></i>
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-3 text-muted">
                            <i class="bi bi-check-circle mb-2"></i>
                            <p class="mb-0">No blocked IPs</p>
                        </div>
                    <?php endif; ?>
                </div>
                
                <!-- Allowed Countries -->
                <div class="dashboard-card">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="mb-0"><i class="bi bi-flag me-2"></i>Allowed Countries</h5>
                        <button type="button" class="btn btn-sm btn-outline-primary" onclick="manageCountries(<?= $website['id'] ?>)">
                            <i class="bi bi-plus-circle me-1"></i>Manage
                        </button>
                    </div>
                    
                    <?php if (!empty($allowed_countries)): ?>
                        <div class="row g-2">
                            <?php foreach ($allowed_countries as $country): ?>
                                <div class="col-6 col-md-4 col-lg-3">
                                    <div class="d-flex align-items-center p-2 border rounded">
                                        <div class="me-2">
                                            <?php if ($country['is_allowed']): ?>
                                                <i class="bi bi-check-circle text-success"></i>
                                            <?php else: ?>
                                                <i class="bi bi-x-circle text-danger"></i>
                                            <?php endif; ?>
                                        </div>
                                        <div>
                                            <div class="small fw-bold"><?= htmlspecialchars($country['country_name']) ?></div>
                                            <div class="x-small text-muted"><?= htmlspecialchars($country['country_code']) ?></div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-3 text-muted">
                            <i class="bi bi-globe mb-2"></i>
                            <p class="mb-0">No country restrictions configured</p>
                            <small>All countries are allowed by default</small>
                        </div>
                    <?php endif; ?>
                </div>
                
                <!-- Quick Actions -->
                <div class="dashboard-card mt-4">
                    <h6 class="mb-3"><i class="bi bi-lightning me-2"></i>Quick Actions</h6>
                    <div class="row g-2">
                        <div class="col-md-4">
                            <a href="admin_logs.php?website_id=<?= $website['id'] ?>" class="btn btn-outline-info w-100">
                                <i class="bi bi-list-check me-1"></i>Access Logs
                            </a>
                        </div>
                        <div class="col-md-4">
                            <a href="admin_attacks.php?website_id=<?= $website['id'] ?>" class="btn btn-outline-danger w-100">
                                <i class="bi bi-shield-exclamation me-1"></i>Attack Logs
                            </a>
                        </div>
                        <div class="col-md-4">
                            <a href="admin_blocked.php?website_id=<?= $website['id'] ?>" class="btn btn-outline-warning w-100">
                                <i class="bi bi-ban me-1"></i>Blocked IPs
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        function permanentBlock(ip, websiteId) {
            if (confirm(`Permanently block IP ${ip}?\n\nThis will block all access from this IP address.`)) {
                // Implement AJAX call to block IP
                fetch('ajax/block_ip.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ip: ip,
                        website_id: websiteId,
                        reason: 'Manual block from admin',
                        permanent: true
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('IP blocked successfully');
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                });
            }
        }
        
        function manageCountries(websiteId) {
            // Implement country management modal
            alert('Country management feature would open here for website ID: ' + websiteId);
        }
        
        $(document).ready(function() {
            // Initialize popovers
            var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
            var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
                return new bootstrap.Popover(popoverTriggerEl);
            });
            
            // Auto-refresh page every 30 seconds
            setInterval(function() {
                $.ajax({
                    url: 'ajax/refresh_website_stats.php?id=<?= $website['id'] ?>',
                    method: 'GET',
                    success: function(data) {
                        // Update stats if needed
                        console.log('Stats refreshed');
                    }
                });
            }, 30000);
        });
    </script>
</body>
</html>