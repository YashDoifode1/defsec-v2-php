<?php include 'includes/admin_navbar.php';?>
            
            <!-- Main Content -->
            <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
                <!-- Page Header -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2 class="h3 mb-1"><i class="bi bi-speedometer2 me-2"></i>Admin Dashboard</h2>
                        <p class="text-muted mb-0">Welcome back, <?= htmlspecialchars($_SESSION['admin_name'] ?? 'Admin') ?>!</p>
                    </div>
                    <div>
                        <button class="btn btn-admin btn-admin-primary" onclick="refreshDashboard()">
                            <i class="bi bi-arrow-clockwise me-1"></i>Refresh
                        </button>
                    </div>
                </div>
                
                <!-- Stats Cards -->
                <div class="row g-4 mb-4">
                    <div class="col-xl-3 col-md-6">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-primary">
                                <i class="bi bi-people-fill"></i>
                            </div>
                            <div class="stat-value"><?= number_format($stats['total_users'] ?? 0) ?></div>
                            <div class="stat-label">Total Users</div>
                            <div class="small text-muted mt-2">
                                <?= number_format($stats['new_users_month'] ?? 0) ?> new this month
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-3 col-md-6">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-success">
                                <i class="bi bi-globe"></i>
                            </div>
                            <div class="stat-value"><?= number_format($stats['total_websites'] ?? 0) ?></div>
                            <div class="stat-label">Protected Websites</div>
                            <div class="small text-muted mt-2">
                                <?= number_format($stats['active_users'] ?? 0) ?> active today
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-3 col-md-6">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-danger">
                                <i class="bi bi-shield-exclamation"></i>
                            </div>
                            <div class="stat-value"><?= number_format($stats['total_attacks'] ?? 0) ?></div>
                            <div class="stat-label">Total Attacks</div>
                            <div class="small text-muted mt-2">
                                <?= number_format($stats['recent_attacks'] ?? 0) ?> in last 24h
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-3 col-md-6">
                        <div class="dashboard-card stat-card">
                            <div class="stat-icon text-warning">
                                <i class="bi bi-ban"></i>
                            </div>
                            <div class="stat-value"><?= number_format($stats['blocked_ips'] ?? 0) ?></div>
                            <div class="stat-label">Blocked IPs</div>
                            <div class="small text-muted mt-2">
                                <?= number_format($stats['suspended_users'] ?? 0) ?> suspended users
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Activities & System Status -->
                <div class="row g-4">
                    <!-- Recent Activities -->
                    <div class="col-lg-8">
                        <div class="dashboard-card table-card">
                            <h5 class="mb-3"><i class="bi bi-activity me-2"></i>Recent Security Activities</h5>
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>Attack Type</th>
                                            <th>Severity</th>
                                            <th>IP Address</th>
                                            <th>Website</th>
                                            <th>User</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_activities as $activity): ?>
                                            <tr>
                                                <td class="text-nowrap">
                                                    <?= date('H:i', strtotime($activity['timestamp'])) ?>
                                                </td>
                                                <td><?= htmlspecialchars($activity['attack_type'] ?? 'Unknown') ?></td>
                                                <td>
                                                    <?php
                                                    $severity = $activity['severity'] ?? 'Info';
                                                    $badge_class = 'badge-info';
                                                    if ($severity === 'Critical') $badge_class = 'badge-critical';
                                                    elseif ($severity === 'High') $badge_class = 'badge-high';
                                                    elseif ($severity === 'Medium') $badge_class = 'badge-medium';
                                                    ?>
                                                    <span class="badge badge-severity <?= $badge_class ?>">
                                                        <?= $severity ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <code><?= htmlspecialchars($activity['ip_address'] ?? 'Unknown') ?></code>
                                                </td>
                                                <td><?= htmlspecialchars($activity['domain'] ?? 'Unknown') ?></td>
                                                <td><?= htmlspecialchars($activity['username'] ?? 'Unknown') ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($recent_activities)): ?>
                                            <tr>
                                                <td colspan="6" class="text-center text-muted py-4">
                                                    <i class="bi bi-check-circle-fill me-2"></i>
                                                    No recent security activities
                                                </td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <!-- System Status -->
                    <div class="col-lg-4">
                        <div class="dashboard-card">
                            <h5 class="mb-3"><i class="bi bi-server me-2"></i>System Status</h5>
                            
                            <div class="list-group">
                                <?php foreach ($system_status as $component => $status): ?>
                                    <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center bg-transparent border-secondary text-light">
                                        <div>
                                            <i class="bi bi-<?= $status === 'active' ? 'check-circle-fill text-success' : 'exclamation-circle-fill text-warning' ?> me-2"></i>
                                            <?= ucfirst($component) ?>
                                        </div>
                                        <span class="badge bg-<?= $status === 'active' ? 'success' : 'warning' ?>">
                                            <?= ucfirst($status) ?>
                                        </span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            
                            <div class="mt-4 pt-3 border-top border-secondary">
                                <h6 class="mb-2">Quick Actions</h6>
                                <div class="d-grid gap-2">
                                    <a href="admin_users.php?action=add" class="btn btn-admin btn-admin-primary">
                                        <i class="bi bi-person-plus me-1"></i>Add New User
                                    </a>
                                    <a href="admin_reports.php" class="btn btn-outline-primary">
                                        <i class="bi bi-file-earmark-text me-1"></i>Generate Report
                                    </a>
                                    <a href="system_settings.php" class="btn btn-outline-secondary">
                                        <i class="bi bi-sliders me-1"></i>System Settings
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Quick Stats -->
                <div class="row g-4 mt-2">
                    <div class="col-md-6">
                        <div class="dashboard-card">
                            <h6 class="mb-3"><i class="bi bi-calendar-week me-2"></i>Today's Overview</h6>
                            <div class="row text-center">
                                <div class="col-4">
                                    <div class="h4 mb-1"><?= number_format($stats['active_users'] ?? 0) ?></div>
                                    <div class="small text-muted">Active Users</div>
                                </div>
                                <div class="col-4">
                                    <div class="h4 mb-1"><?= number_format($stats['recent_attacks'] ?? 0) ?></div>
                                    <div class="small text-muted">Attacks</div>
                                </div>
                                <div class="col-4">
                                    <?php
                                    try {
                                        $stmt = $pdo->query("SELECT COUNT(DISTINCT ip) as unique_visitors FROM logs WHERE DATE(timestamp) = CURDATE()");
                                        $unique_visitors = $stmt->fetch()['unique_visitors'];
                                    } catch (PDOException $e) {
                                        $unique_visitors = 0;
                                    }
                                    ?>
                                    <div class="h4 mb-1"><?= number_format($unique_visitors) ?></div>
                                    <div class="small text-muted">Unique Visitors</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="dashboard-card">
                            <h6 class="mb-3"><i class="bi bi-exclamation-triangle me-2"></i>Security Alerts</h6>
                            <div class="alert alert-warning alert-admin mb-0">
                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                <strong>System is operational.</strong> All services are running normally.
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        function refreshDashboard() {
            location.reload();
        }
        
        // Initialize DataTable
        $(document).ready(function() {
            $('table').DataTable({
                pageLength: 10,
                order: [[0, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ entries",
                    infoEmpty: "No entries found",
                    infoFiltered: "(filtered from _MAX_ total entries)"
                }
            });
        });
        
        // Auto-refresh dashboard every 60 seconds
        setInterval(function() {
            $.ajax({
                url: 'ajax/refresh_stats.php',
                method: 'GET',
                success: function(data) {
                    // Update stats if needed
                    console.log('Dashboard auto-refreshed');
                }
            });
        }, 60000);
    </script>
</body>
</html>