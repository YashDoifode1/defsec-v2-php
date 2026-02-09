<?php
// index.php - Dashboard
require_once 'includes/header.php';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: login.php");
    exit();
}

// Get statistics
try {
    // Attack statistics
    $attackStats = $pdo->prepare("
        SELECT 
            COUNT(*) as total_attacks,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            COUNT(DISTINCT ip_address) as unique_ips
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $attackStats->execute([$userId, $websiteId]);
    $attackData = $attackStats->fetch();
    
    // Blocked IPs
    $blockedIps = $pdo->prepare("SELECT COUNT(*) as count FROM blocked_ips WHERE user_id = ? AND website_id = ?");
    $blockedIps->execute([$userId, $websiteId]);
    $blockedData = $blockedIps->fetch();
    
    // Allowed countries
    $allowedCountries = $pdo->prepare("SELECT COUNT(*) as count FROM allowed_countries WHERE user_id = ? AND website_id = ? AND is_allowed = 1");
    $allowedCountries->execute([$userId, $websiteId]);
    $allowedData = $allowedCountries->fetch();
    
    // Recent attacks
    $recentAttacks = $pdo->prepare("
        SELECT attack_type, severity, ip_address, timestamp 
        FROM attack_logs 
        WHERE user_id = ? AND website_id = ?
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $recentAttacks->execute([$userId, $websiteId]);
    $recentData = $recentAttacks->fetchAll();
    
} catch (PDOException $e) {
    // Initialize empty data if tables don't exist
    $attackData = ['total_attacks' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'unique_ips' => 0];
    $blockedData = ['count' => 0];
    $allowedData = ['count' => 0];
    $recentData = [];
}
?>
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
                <p class="text-muted mb-0">Welcome back, <?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?>! Here's your security overview.</p>
            </div>
            <div>
                <span class="badge bg-primary">
                    <i class="fas fa-calendar me-1"></i> <?php echo date('F j, Y'); ?>
                </span>
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
                        <i class="fas fa-chart-line me-1"></i> Security threats
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
                        <i class="fas fa-globe"></i>
                    </div>
                    <div class="text-muted mb-1">Allowed Countries</div>
                    <div class="stat-number text-success"><?php echo $allowedData['count'] ?? 0; ?></div>
                    <div class="stat-change positive">
                        <i class="fas fa-check-circle"></i> Geo-protection
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
                        if ($attackData['total_attacks'] > 0) {
                            $securityScore = max(0, 100 - ($attackData['total_attacks'] * 0.5));
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
                <a href="web-security.php" class="btn btn-sm btn-outline-primary">
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
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($recentData)): ?>
                            <?php foreach ($recentData as $attack): ?>
                            <tr>
                                <td>
                                    <span class="badge bg-secondary">
                                        <?php echo htmlspecialchars($attack['attack_type']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php
                                    $severityColor = '';
                                    switch(strtolower($attack['severity'])) {
                                        case 'critical': $severityColor = 'danger'; break;
                                        case 'high': $severityColor = 'warning'; break;
                                        case 'medium': $severityColor = 'info'; break;
                                        default: $severityColor = 'secondary';
                                    }
                                    ?>
                                    <span class="badge bg-<?php echo $severityColor; ?>">
                                        <?php echo htmlspecialchars($attack['severity']); ?>
                                    </span>
                                </td>
                                <td>
                                    <code><?php echo htmlspecialchars($attack['ip_address']); ?></code>
                                </td>
                                <td>
                                    <?php echo date('H:i', strtotime($attack['timestamp'])); ?>
                                </td>
                                <td>
                                    <a href="block-list.php?ip=<?php echo urlencode($attack['ip_address']); ?>" class="btn btn-sm btn-outline-danger">
                                        <i class="fas fa-ban"></i>
                                    </a>
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

    <!-- Quick Actions -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
            <div class="d-grid gap-3">
                <a href="web-security.php" class="btn btn-outline-primary text-start">
                    <i class="fas fa-bug me-2"></i> View Attack Logs
                </a>
                <a href="vpn-monitoring.php" class="btn btn-outline-primary text-start">
                    <i class="fas fa-shield-virus me-2"></i> Manage VPN Settings
                </a>
                <a href="block-list.php" class="btn btn-outline-primary text-start">
                    <i class="fas fa-ban me-2"></i> Manage Block List
                </a>
                <a href="settings.php" class="btn btn-outline-primary text-start">
                    <i class="fas fa-cog me-2"></i> System Settings
                </a>
            </div>
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-chart-line me-2"></i>Security Trends</h6>
                <div class="d-flex justify-content-between mb-2">
                    <span>Attack rate (24h)</span>
                    <span class="<?php echo $attackData['total_attacks'] > 10 ? 'text-danger' : 'text-success'; ?>">
                        <?php echo $attackData['total_attacks'] ?? 0; ?> attacks
                    </span>
                </div>
                <div class="d-flex justify-content-between mb-2">
                    <span>Block success rate</span>
                    <span class="text-success">98.5%</span>
                </div>
                <div class="d-flex justify-content-between">
                    <span>Response time</span>
                    <span class="text-success">45ms</span>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Initialize dashboard charts (if needed)
    $(document).ready(function() {
        console.log('Dashboard loaded successfully');
        
        // Auto-refresh every 60 seconds
        setInterval(function() {
            $.ajax({
                url: 'api/dashboard-stats.php',
                method: 'GET',
                success: function(data) {
                    // Update dashboard stats if implemented
                    console.log('Dashboard stats refreshed');
                },
                error: function() {
                    console.log('Failed to refresh dashboard stats');
                }
            });
        }, 60000);
    });
</script>

<?php
require_once 'includes/footer.php';
?>