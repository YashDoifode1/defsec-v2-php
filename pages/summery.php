<?php
// summery.php - Dashboard
require_once '../includes/header.php';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: login.php");
    exit();
}

// Get current user and website IDs from session or database
$userId = $_SESSION['user_id'] ?? 0;
$websiteId = $_SESSION['website_id'] ?? 1; // Default to website ID 1 if not set

// If website_id not in session, get the user's default website
if (!$websiteId || $websiteId == 0) {
    try {
        $defaultWebsite = $pdo->prepare("SELECT id FROM websites WHERE user_id = ? ORDER BY id ASC LIMIT 1");
        $defaultWebsite->execute([$userId]);
        $website = $defaultWebsite->fetch();
        $websiteId = $website['id'] ?? 1;
        $_SESSION['website_id'] = $websiteId;
    } catch (Exception $e) {
        $websiteId = 1;
    }
}

// Get user details
$userDetails = [];
try {
    $userQuery = $pdo->prepare("SELECT username, email, full_name, role FROM users WHERE id = ?");
    $userQuery->execute([$userId]);
    $userDetails = $userQuery->fetch();
} catch (Exception $e) {
    $userDetails = ['username' => 'User', 'email' => '', 'full_name' => '', 'role' => 'viewer'];
}

// Get website details
$websiteDetails = [];
try {
    $websiteQuery = $pdo->prepare("SELECT site_name, domain, status FROM websites WHERE id = ? AND user_id = ?");
    $websiteQuery->execute([$websiteId, $userId]);
    $websiteDetails = $websiteQuery->fetch();
} catch (Exception $e) {
    $websiteDetails = ['site_name' => 'Default Website', 'domain' => 'unknown', 'status' => 'active'];
}

// Get statistics
try {
    // Attack statistics (last 7 days)
    $attackStats = $pdo->prepare("
        SELECT 
            COUNT(*) as total_attacks,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'Info' THEN 1 ELSE 0 END) as info,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $attackStats->execute([$userId, $websiteId]);
    $attackData = $attackStats->fetch() ?? ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    
    // Total visitors (last 7 days)
    $visitorStats = $pdo->prepare("
        SELECT 
            COUNT(*) as total_visitors,
            COUNT(DISTINCT ip) as unique_visitors,
            COUNT(CASE WHEN is_vpn = 1 THEN 1 END) as vpn_users,
            COUNT(CASE WHEN is_proxy = 1 THEN 1 END) as proxy_users
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $visitorStats->execute([$userId, $websiteId]);
    $visitorData = $visitorStats->fetch() ?? ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    
    // Blocked IPs (active)
    $blockedIps = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE user_id = ? AND website_id = ?
        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
    ");
    $blockedIps->execute([$userId, $websiteId]);
    $blockedData = $blockedIps->fetch() ?? ['count' => 0];
    
    // Allowed countries
    $allowedCountries = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM allowed_countries 
        WHERE (user_id = ? OR user_id = 0) 
        AND (website_id = ? OR website_id = 0)
        AND is_allowed = 1
    ");
    $allowedCountries->execute([$userId, $websiteId]);
    $allowedData = $allowedCountries->fetch() ?? ['count' => 0];
    
    // Access logs (last 24 hours)
    $accessLogs = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM access_logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $accessLogs->execute([$userId, $websiteId]);
    $accessData = $accessLogs->fetch() ?? ['count' => 0];
    
    // Recent attacks (last 10)
    $recentAttacks = $pdo->prepare("
        SELECT attack_type, severity, ip_address, timestamp, request_url 
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $recentAttacks->execute([$userId, $websiteId]);
    $recentData = $recentAttacks->fetchAll();
    
    // Attack distribution by type
    $attackTypes = $pdo->prepare("
        SELECT attack_type, COUNT(*) as count 
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY attack_type
        ORDER BY count DESC
        LIMIT 5
    ");
    $attackTypes->execute([$userId, $websiteId]);
    $attackTypeData = $attackTypes->fetchAll();
    
} catch (PDOException $e) {
    // Initialize empty data if tables don't exist
    $attackData = ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'unique_ips' => 0];
    $visitorData = ['total_visitors' => 0, 'unique_visitors' => 0, 'vpn_users' => 0, 'proxy_users' => 0];
    $blockedData = ['count' => 0];
    $allowedData = ['count' => 0];
    $accessData = ['count' => 0];
    $recentData = [];
    $attackTypeData = [];
}
?>
<style>
.text-muted {
    --bs-text-opacity: 1;
    /* color: var(--bs-secondary-color) !important; */
}

.mb-1 {
    margin-bottom: .25rem !important;
    color: white;
}

</style>
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
                <p class="text-muted mb-0">
                    Welcome back, <strong><?php echo htmlspecialchars($userDetails['full_name'] ?? $userDetails['username'] ?? 'User'); ?></strong>! 
                    Monitoring: <strong><?php echo htmlspecialchars($websiteDetails['site_name'] ?? 'Website'); ?></strong> 
                    (<code><?php echo htmlspecialchars($websiteDetails['domain'] ?? 'unknown'); ?></code>)
                </p>
            </div>
            <div>
                <div class="d-flex gap-2 align-items-center">
                    <span class="badge bg-primary">
                        <i class="fas fa-calendar me-1"></i> <?php echo date('F j, Y'); ?>
                    </span>
                    <div class="dropdown">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-globe me-1"></i> Site: <?php echo htmlspecialchars($websiteDetails['site_name'] ?? 'Select'); ?>
                        </button>
                        <ul class="dropdown-menu">
                            <?php
                            try {
                                $userWebsites = $pdo->prepare("SELECT id, site_name, domain FROM websites WHERE user_id = ? ORDER BY site_name");
                                $userWebsites->execute([$userId]);
                                $websites = $userWebsites->fetchAll();
                                
                                foreach ($websites as $website) {
                                    $active = ($website['id'] == $websiteId) ? 'active' : '';
                                    echo "<li>
                                            <a class='dropdown-item $active' href='?switch_website={$website['id']}'>
                                                {$website['site_name']} <small class='text-muted'>({$website['domain']})</small>
                                            </a>
                                          </li>";
                                }
                            } catch (Exception $e) {
                                echo "<li><a class='dropdown-item' href='#'>No websites found</a></li>";
                            }
                            ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="card-icon text-danger">
                        <i class="fas fa-skull-crossbones"></i>
                    </div>
                    <div class="text-muted mb-1">Total Attacks (7 days)</div>
                    <div class="stat-number text-danger"><?php echo $attackData['total_attacks'] ?? 0; ?></div>
                    <div class="stat-change">
                        <small>
                            <span class="text-danger"><?php echo $attackData['critical'] ?? 0; ?> Critical</span> | 
                            <span class="text-warning"><?php echo $attackData['high'] ?? 0; ?> High</span> | 
                            <span class="text-info"><?php echo $attackData['medium'] ?? 0; ?> Medium</span>
                        </small>
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
                        <i class="fas fa-ban"></i>
                    </div>
                    <div class="text-muted mb-1">Blocked IPs</div>
                    <div class="stat-number text-warning"><?php echo $blockedData['count'] ?? 0; ?></div>
                    <div class="stat-change positive">
                        <i class="fas fa-shield-alt"></i> Active protection
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
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="text-muted mb-1">Visitors (7 days)</div>
                    <div class="stat-number text-success"><?php echo $visitorData['unique_visitors'] ?? 0; ?></div>
                    <div class="stat-change">
                        <small>
                            <?php echo $visitorData['vpn_users'] ?? 0; ?> VPN | 
                            <?php echo $visitorData['proxy_users'] ?? 0; ?> Proxy
                        </small>
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
                        <i class="fas fa-user-shield"></i>
                    </div>
                    <div class="text-muted mb-1">Security Score</div>
                    <div class="stat-number text-info">
                        <?php
                        $securityScore = 100;
                        $totalAttacks = $attackData['total_attacks'] ?? 0;
                        $uniqueVisitors = max(1, $visitorData['unique_visitors'] ?? 1);
                        
                        if ($totalAttacks > 0) {
                            $attackRatio = ($totalAttacks / $uniqueVisitors) * 100;
                            $securityScore = max(0, 100 - min($attackRatio, 50));
                        }
                        echo round($securityScore);
                        ?>%
                    </div>
                    <div class="stat-change <?php echo $securityScore >= 80 ? 'positive' : ($securityScore >= 60 ? '' : 'negative'); ?>">
                        <i class="fas fa-<?php echo $securityScore >= 80 ? 'shield-alt' : 'exclamation-triangle'; ?>"></i>
                        <?php echo $securityScore >= 80 ? 'Excellent' : ($securityScore >= 60 ? 'Good' : 'Needs attention'); ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Attacks -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Attacks</h5>
                <a href="web-security.php?website_id=<?php echo $websiteId; ?>" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-external-link-alt me-1"></i> View All
                </a>
            </div>
            
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Attack Type</th>
                            <th>Severity</th>
                            <th>IP Address</th>
                            <th>Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($recentData)): ?>
                            <?php foreach ($recentData as $attack): ?>
                            <tr>
                                <td>
                                    <span class="badge bg-secondary">
                                        <?php echo htmlspecialchars($attack['attack_type'] ?? 'Unknown'); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php
                                    $severityColor = 'secondary';
                                    $severity = strtolower($attack['severity'] ?? '');
                                    switch($severity) {
                                        case 'critical': $severityColor = 'danger'; break;
                                        case 'high': $severityColor = 'warning'; break;
                                        case 'medium': $severityColor = 'info'; break;
                                        case 'info': $severityColor = 'secondary'; break;
                                    }
                                    ?>
                                    <span class="badge bg-<?php echo $severityColor; ?>">
                                        <?php echo htmlspecialchars($attack['severity'] ?? 'Info'); ?>
                                    </span>
                                </td>
                                <td>
                                    <code><?php echo htmlspecialchars($attack['ip_address'] ?? 'Unknown'); ?></code>
                                </td>
                                <td>
                                    <?php 
                                    $time = $attack['timestamp'] ?? '';
                                    if ($time) {
                                        echo date('H:i', strtotime($time));
                                    } else {
                                        echo 'N/A';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="block-list.php?ip=<?php echo urlencode($attack['ip_address'] ?? ''); ?>&website_id=<?php echo $websiteId; ?>" 
                                           class="btn btn-outline-danger" title="Block IP">
                                            <i class="fas fa-ban"></i>
                                        </a>
                                        <button type="button" class="btn btn-outline-info" 
                                                onclick="showAttackDetails('<?php echo htmlspecialchars($attack['attack_type'] ?? ''); ?>', 
                                                                          '<?php echo htmlspecialchars($attack['ip_address'] ?? ''); ?>',
                                                                          '<?php echo htmlspecialchars($attack['request_url'] ?? ''); ?>')"
                                                title="View Details">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" class="text-center py-4">
                                    <div class="text-muted">
                                        <i class="fas fa-check-circle fa-2x mb-3 text-success"></i>
                                        <div>No recent attacks detected</div>
                                        <small class="mt-2 d-block">Your security is looking good!</small>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Quick Actions & Stats -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
            <div class="d-grid gap-3">
                <a href="web-security.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                    <i class="fas fa-bug me-2"></i> View Attack Logs
                </a>
                <a href="vpn-monitoring.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                    <i class="fas fa-shield-virus me-2"></i> Manage VPN Settings
                </a>
                <a href="block-list.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                    <i class="fas fa-ban me-2"></i> Manage Block List
                </a>
                <a href="logs.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-primary text-start">
                    <i class="fas fa-file-alt me-2"></i> View Visitor Logs
                </a>
            </div>
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-chart-pie me-2"></i>Attack Distribution</h6>
                <?php if (!empty($attackTypeData)): ?>
                    <div class="mb-3">
                        <?php foreach ($attackTypeData as $type): ?>
                            <div class="d-flex justify-content-between mb-1">
                                <small><?php echo htmlspecialchars($type['attack_type']); ?></small>
                                <small class="text-muted"><?php echo $type['count']; ?></small>
                            </div>
                            <div class="progress mb-2" style="height: 5px;">
                                <div class="progress-bar bg-warning" 
                                     style="width: <?php echo min(100, ($type['count'] / max(1, $attackData['total_attacks'])) * 100); ?>%"></div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="text-center text-muted py-3">
                        <i class="fas fa-chart-bar fa-lg mb-2"></i>
                        <div>No attack data available</div>
                    </div>
                <?php endif; ?>
                
                <div class="d-flex justify-content-between small">
                    <span>Total requests (24h)</span>
                    <span><?php echo $accessData['count']; ?></span>
                </div>
                <div class="d-flex justify-content-between small">
                    <span>Blocked countries</span>
                    <span><?php 
                        try {
                            $blockedCountries = $pdo->prepare("SELECT COUNT(*) as count FROM allowed_countries WHERE (user_id = ? OR user_id = 0) AND (website_id = ? OR website_id = 0) AND is_allowed = 0");
                            $blockedCountries->execute([$userId, $websiteId]);
                            $bcData = $blockedCountries->fetch();
                            echo $bcData['count'] ?? 0;
                        } catch (Exception $e) {
                            echo '0';
                        }
                    ?></span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Attack Details Modal -->
<div class="modal fade" id="attackDetailsModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title">Attack Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label text-muted">Attack Type</label>
                    <div class="form-control bg-dark text-light" id="modalAttackType"></div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">IP Address</label>
                    <div class="form-control bg-dark text-light" id="modalIpAddress"></div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Request URL</label>
                    <div class="form-control bg-dark text-light" style="height: auto; min-height: 80px; font-family: monospace; font-size: 12px;" 
                         id="modalRequestUrl"></div>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" class="btn btn-danger" id="modalBlockBtn">
                    <i class="fas fa-ban me-1"></i> Block This IP
                </a>
            </div>
        </div>
    </div>
</div>

<script>
    // Function to show attack details
    function showAttackDetails(type, ip, url) {
        $('#modalAttackType').text(type);
        $('#modalIpAddress').text(ip);
        $('#modalRequestUrl').text(url);
        $('#modalBlockBtn').attr('href', 'block-list.php?ip=' + encodeURIComponent(ip) + '&website_id=<?php echo $websiteId; ?>');
        new bootstrap.Modal(document.getElementById('attackDetailsModal')).show();
    }
    
    // Handle website switching
    <?php if (isset($_GET['switch_website'])): ?>
        $.ajax({
            url: 'api/switch-website.php',
            method: 'POST',
            data: { website_id: <?php echo intval($_GET['switch_website']); ?> },
            success: function(response) {
                window.location.reload();
            },
            error: function() {
                alert('Failed to switch website');
                window.location.href = window.location.pathname;
            }
        });
    <?php endif; ?>
    
    // Auto-refresh every 30 seconds
    $(document).ready(function() {
        console.log('Dashboard loaded for website ID: <?php echo $websiteId; ?>');
        
        setInterval(function() {
            $.ajax({
                url: 'api/dashboard-stats.php?website_id=<?php echo $websiteId; ?>',
                method: 'GET',
                success: function(data) {
                    if (data.success) {
                        // Update stats if needed
                        console.log('Dashboard stats refreshed');
                    }
                },
                error: function() {
                    console.log('Failed to refresh dashboard stats');
                }
            });
        }, 30000);
    });
</script>

<?php
require_once '../includes/footer.php';
?>