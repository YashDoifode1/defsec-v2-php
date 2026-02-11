
<?php
// admin_dashboard.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

// Get admin info
$admin_id = $admin_auth->getAdminId();
$is_superadmin = $admin_auth->isSuperAdmin();

// Get statistics
$stats = [];
try {
    // Total users
    $stmt = $pdo->query("SELECT COUNT(*) as total_users FROM users WHERE role IN ('analyst', 'viewer')");
    $stats['total_users'] = $stmt->fetch()['total_users'];
    
    // Total websites
    $stmt = $pdo->query("SELECT COUNT(*) as total_websites FROM websites");
    $stats['total_websites'] = $stmt->fetch()['total_websites'];
    
    // Active users today
    $stmt = $pdo->query("SELECT COUNT(DISTINCT user_id) as active_users FROM logs WHERE DATE(timestamp) = CURDATE()");
    $stats['active_users'] = $stmt->fetch()['active_users'];
    
    // Blocked IPs
    $stmt = $pdo->query("SELECT COUNT(*) as blocked_ips FROM blocked_ips WHERE expiry_time > CURTIME()");
    $stats['blocked_ips'] = $stmt->fetch()['blocked_ips'];
    
    // Recent attacks
    $stmt = $pdo->query("SELECT COUNT(*) as recent_attacks FROM attack_logs WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $stats['recent_attacks'] = $stmt->fetch()['recent_attacks'];
    
    // Total attacks
    $stmt = $pdo->query("SELECT COUNT(*) as total_attacks FROM attack_logs");
    $stats['total_attacks'] = $stmt->fetch()['total_attacks'];
    
    // New users this month
    $stmt = $pdo->query("SELECT COUNT(*) as new_users_month FROM users WHERE role IN ('analyst', 'viewer') AND MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())");
    $stats['new_users_month'] = $stmt->fetch()['new_users_month'];
    
    // Suspended accounts
    $stmt = $pdo->query("SELECT COUNT(*) as suspended_users FROM users WHERE status = 'suspended'");
    $stats['suspended_users'] = $stmt->fetch()['suspended_users'];
    
} catch (PDOException $e) {
    error_log("Error fetching stats: " . $e->getMessage());
}

// Get recent activities
$recent_activities = [];
try {
    $stmt = $pdo->query("
        SELECT 
            al.timestamp,
            al.attack_type,
            al.severity,
            al.ip_address,
            w.domain,
            u.username
        FROM attack_logs al
        JOIN websites w ON al.website_id = w.id
        JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
        LIMIT 10
    ");
    $recent_activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Error fetching recent activities: " . $e->getMessage());
}

// Get system status
$system_status = [];
try {
    // Check if any tables are empty
    $tables = ['users', 'websites', 'logs', 'attack_logs'];
    foreach ($tables as $table) {
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM $table");
        $system_status[$table] = $stmt->fetch()['count'] > 0 ? 'active' : 'empty';
    }
} catch (PDOException $e) {
    error_log("Error checking system status: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #0dcaf0;
            --dark-bg: #121212;
            --darker-bg: #0a0a0a;
            --card-bg: #1e1e1e;
            --border-color: #2d2d2d;
            --text-light: #e0e0e0;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--text-light);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        }
        
        .navbar-admin {
            background: linear-gradient(135deg, var(--darker-bg) 0%, #1a1a1a 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 0;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }
        
        .sidebar {
            background: var(--darker-bg);
            border-right: 1px solid var(--border-color);
            min-height: calc(100vh - 56px);
            position: sticky;
            top: 56px;
            z-index: 1000;
        }
        
        .sidebar .nav-link {
            color: var(--text-light);
            padding: 0.75rem 1.5rem;
            margin: 0.25rem 0.75rem;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .sidebar .nav-link:hover,
        .sidebar .nav-link.active {
            background: var(--card-bg);
            color: var(--primary-color);
            transform: translateX(5px);
        }
        
        .sidebar .nav-link i {
            width: 20px;
            margin-right: 10px;
        }
        
        .dashboard-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: transform 0.3s, box-shadow 0.3s;
            height: 100%;
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        
        .stat-card {
            text-align: center;
            padding: 1.5rem;
        }
        
        .stat-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            opacity: 0.8;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--secondary-color);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .table-card {
            overflow-x: auto;
        }
        
        .table-dark {
            --bs-table-bg: transparent;
            --bs-table-striped-bg: rgba(255, 255, 255, 0.05);
            --bs-table-hover-bg: rgba(255, 255, 255, 0.1);
        }
        
        .badge-severity {
            padding: 0.35em 0.65em;
            font-size: 0.75em;
        }
        
        .badge-critical { background: linear-gradient(135deg, #dc3545, #c82333); }
        .badge-high { background: linear-gradient(135deg, #fd7e14, #e8590c); }
        .badge-medium { background: linear-gradient(135deg, #ffc107, #e0a800); }
        .badge-info { background: linear-gradient(135deg, #0dcaf0, #0baccc); }
        
        .btn-admin {
            padding: 0.5rem 1rem;
            font-weight: 500;
            border-radius: 6px;
            transition: all 0.3s;
        }
        
        .btn-admin-primary {
            background: linear-gradient(135deg, var(--primary-color) 0%, #0b5ed7 100%);
            border: none;
            color: white;
        }
        
        .btn-admin-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(13, 110, 253, 0.4);
        }
        
        .alert-admin {
            border: none;
            border-radius: 8px;
            padding: 1rem 1.25rem;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--info-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .notification-badge {
            position: absolute;
            top: -5px;
            right: -5px;
            background: var(--danger-color);
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .dropdown-menu {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
        }
        
        .dropdown-item {
            color: var(--text-light);
        }
        
        .dropdown-item:hover {
            background: rgba(13, 110, 253, 0.1);
            color: var(--primary-color);
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-admin">
        <div class="container-fluid">
            <a class="navbar-brand d-flex align-items-center" href="#">
                <i class="bi bi-shield-lock-fill me-2" style="color: var(--primary-color);"></i>
                <span class="fw-bold">DefSec</span>
                <span class="ms-2 badge bg-danger">Admin</span>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarAdmin">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarAdmin">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center" href="#" role="button" 
                           data-bs-toggle="dropdown">
                            <div class="user-avatar me-2">
                                <?= strtoupper(substr($_SESSION['admin_name'] ?? 'A', 0, 1)) ?>
                            </div>
                            <div class="d-none d-md-block">
                                <div class="fw-bold small"><?= htmlspecialchars($_SESSION['admin_name'] ?? 'Admin') ?></div>
                                <div class="text-muted x-small"><?= ucfirst($_SESSION['admin_role'] ?? 'admin') ?></div>
                            </div>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="admin_profile.php"><i class="bi bi-person me-2"></i>Profile</a></li>
                            <li><a class="dropdown-item" href="admin_settings.php"><i class="bi bi-gear me-2"></i>Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <?php if ($is_superadmin): ?>
                                <li><a class="dropdown-item" href="system_settings.php"><i class="bi bi-terminal me-2"></i>System Settings</a></li>
                            <?php endif; ?>
                            <li><a class="dropdown-item text-danger" href="admin_logout.php"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-lg-2 col-md-3 d-none d-md-block sidebar">
                <div class="sticky-top pt-3">
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="admin_dashboard.php">
                                <i class="bi bi-speedometer2"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_users.php">
                                <i class="bi bi-people"></i>Users
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_websites.php">
                                <i class="bi bi-globe"></i>Websites
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_logs.php">
                                <i class="bi bi-list-check"></i>Access Logs
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_attacks.php">
                                <i class="bi bi-shield-exclamation"></i>Attack Logs
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_blocked.php">
                                <i class="bi bi-ban"></i>Blocked IPs
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="admin_reports.php">
                                <i class="bi bi-bar-chart"></i>Reports
                            </a>
                        </li>
                        <?php if ($is_superadmin): ?>
                            <li class="nav-item mt-4 pt-3 border-top border-secondary">
                                <span class="nav-link disabled text-muted small">SUPER ADMIN</span>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="admin_management.php">
                                    <i class="bi bi-person-badge"></i>Admin Management
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="system_settings.php">
                                    <i class="bi bi-sliders"></i>System Settings
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="database_backup.php">
                                    <i class="bi bi-database"></i>Backup & Restore
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>