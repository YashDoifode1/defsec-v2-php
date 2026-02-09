<?php

// includes/header.php

// Start session only if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'db.php';

// Manually define APP_URL - Change this to match your installation
define('APP_URL', 'http://localhost/defsec/v2');

// CSRF token functions
function generateCSRFToken($form_name) {
    if (empty($_SESSION['csrf_tokens'][$form_name])) {
        $_SESSION['csrf_tokens'][$form_name] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_tokens'][$form_name];
}

function validateCSRFToken($form_name, $token) {
    if (empty($_SESSION['csrf_tokens'][$form_name]) || $_SESSION['csrf_tokens'][$form_name] !== $token) {
        return false;
    }
    return true;
}

// Set default timezone
date_default_timezone_set('UTC');

// Authentication check
$isLoggedIn = isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
$userId = $_SESSION['user_id'] ?? null;
$websiteId = $_SESSION['website_id'] ?? 1;
$userRole = $_SESSION['role'] ?? 'user';

// Get user info if logged in
if ($isLoggedIn && $userId) {
    try {
        $stmt = $pdo->prepare("SELECT username, email, role FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $userData = $stmt->fetch();
        
        if ($userData) {
            $_SESSION['username'] = $userData['username'];
            $_SESSION['email'] = $userData['email'] ?? '';
            $_SESSION['role'] = $userData['role'] ?? 'user';
        }
    } catch (PDOException $e) {
        // If table doesn't have email column, use fallback
        $stmt = $pdo->prepare("SELECT username, role FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $userData = $stmt->fetch();
        
        if ($userData) {
            $_SESSION['username'] = $userData['username'];
            $_SESSION['email'] = $userData['username'] . '@defsec.local';
            $_SESSION['role'] = $userData['role'] ?? 'user';
        }
    }
}

// Get current page
$current_page = basename($_SERVER['PHP_SELF']);

// Define page titles
$page_titles = [
    'summery.php' => 'Dashboard',
    'security-dashboard.php' => 'Security',
    'web-security.php' => 'Attack Logs',
    'vpn-monitoring.php' => 'VPN Monitoring',
    'block-list.php' => 'Block List',
    'settings.php' => 'Settings',
    'login.php' => 'Login',
    'profile.php' => 'Profile',
    'export.php ' => 'Export Logs'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec - <?php echo htmlspecialchars($page_titles[$current_page] ?? 'Security Dashboard'); ?></title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Custom CSS -->
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #0dcaf0;
            --dark-color: #121212;
            --light-color: #f8f9fa;
            --sidebar-width: 250px;
            --header-height: 60px;
        }
        
        body {
            background-color: var(--dark-color);
            color: #e9ecef;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Sidebar Styles */
        .sidebar {
            width: var(--sidebar-width);
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            background-color: #1e1e1e;
            border-right: 1px solid #343a40;
            z-index: 1000;
            transition: transform 0.3s ease;
        }
        
        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid #343a40;
        }
        
        .sidebar-menu {
            padding: 20px 0;
        }
        
        .nav-link {
            color: #adb5bd;
            padding: 12px 20px;
            border-left: 3px solid transparent;
            transition: all 0.3s;
        }
        
        .nav-link:hover, .nav-link.active {
            color: #ffffff;
            background-color: rgba(255, 255, 255, 0.05);
            border-left-color: var(--primary-color);
        }
        
        .nav-link i {
            width: 24px;
            margin-right: 10px;
        }
        
        /* Main Content */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 0;
            min-height: 100vh;
            transition: margin-left 0.3s ease;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
        }
        
        /* Header */
        .main-header {
            background-color: #1e1e1e;
            border-bottom: 1px solid #343a40;
            padding: 15px 20px;
            position: sticky;
            top: 0;
            z-index: 999;
        }
        
        /* Dashboard Cards */
        .dashboard-card {
            background-color: #1e1e1e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #343a40;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        
        .card-icon {
            font-size: 2rem;
            margin-bottom: 15px;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            line-height: 1;
        }
        
        .stat-change {
            font-size: 0.9rem;
        }
        
        .positive { color: var(--success-color); }
        .negative { color: var(--danger-color); }
        
        /* Tables */
        .table-dark {
            background-color: #1e1e1e;
            color: #e9ecef;
        }
        
        .table-dark thead th {
            border-bottom: 2px solid #343a40;
            background-color: #252525;
        }
        
        .table-dark tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        /* Buttons */
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #0b5ed7;
            border-color: #0a58ca;
        }
        
        /* Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1e1e1e;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #495057;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #6c757d;
        }
        
        /* Content Area */
        .content-area {
            padding: 20px;
        }
    </style>
    <style>/* Geolocation specific styles */
.table-active {
    background-color: rgba(13, 110, 253, 0.1) !important;
}

.country-flag {
    width: 20px;
    height: 15px;
    display: inline-block;
    margin-right: 8px;
    vertical-align: middle;
    background-size: cover;
    border: 1px solid #444;
}

.map-popup {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 12px;
    line-height: 1.4;
}

.stat-card {
    transition: transform 0.2s;
}

.stat-card:hover {
    transform: translateY(-2px);
}

.bulk-actions-bar {
    position: sticky;
    bottom: 0;
    background: rgba(0, 0, 0, 0.9);
    padding: 10px;
    border-top: 1px solid #444;
    z-index: 100;
}

/* Chart containers */
.chart-container {
    position: relative;
    height: 300px;
    width: 100%;
}

/* Filter panel */
.filter-card {
    transition: all 0.3s ease;
}

.filter-card.collapsed {
    max-height: 60px;
    overflow: hidden;
}

/* Loading spinner */
.geo-loading {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 200px;
}

/* Responsive table adjustments */
@media (max-width: 768px) {
    .table-responsive {
        font-size: 0.9rem;
    }
    
    .btn-group-sm {
        flex-wrap: wrap;
    }
    
    .chart-container {
        height: 250px;
    }
}</style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h3 class="mb-0">
                <i class="fas fa-shield-alt text-primary me-2"></i>
                <span class="fw-bold">DefSec</span>
            </h3>
            <p class="text-muted mb-0 small">Security Dashboard</p>
        </div>
        
        <div class="sidebar-menu">
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'summery.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/summery.php">
                        <i class="fas fa-home"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'security-dashboard.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/security-dashboard.php">
                        <i class="fas fa-shield-alt"></i> Security
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'web-security.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/web-security.php">
                        <i class="fas fa-bug"></i> Attack Logs
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'vpn-monitoring.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/vpn-monitoring.php">
                        <i class="fas fa-shield-virus"></i> VPN Monitor
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'block-list.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/block-list.php">
                        <i class="fas fa-ban"></i> Block List
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'export.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/pages/export.php">
                        <i class="fas fa-archive"></i> Export logs
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo $current_page == 'settings.php' ? 'active' : ''; ?>" href="<?php echo APP_URL; ?>/auth/settings.php">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                </li>
                <?php if ($isLoggedIn): ?>
                <li class="nav-item mt-4">
                    <a class="nav-link text-danger" href="<?php echo APP_URL; ?>/logout.php">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <!-- Header -->
        <header class="main-header d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <button class="btn btn-outline-secondary me-3 d-lg-none" id="sidebarToggle">
                    <i class="fas fa-bars"></i>
                </button>
                <h4 class="mb-0">
                    <?php echo htmlspecialchars($page_titles[$current_page] ?? 'Dashboard'); ?>
                </h4>
            </div>
            
            <?php if ($isLoggedIn): ?>
            <div class="d-flex align-items-center">
                <div class="dropdown">
                    <button class="btn btn-outline-light dropdown-toggle" type="button" id="userDropdown" data-bs-toggle="dropdown">
                        <i class="fas fa-user-circle me-2"></i>
                        <?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="<?php echo APP_URL; ?>/auth/profile.php"><i class="fas fa-user me-2"></i> Profile</a></li>
                        <li><a class="dropdown-item" href="<?php echo APP_URL; ?>/auth/settings.php"><i class="fas fa-cog me-2"></i> Settings</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href="<?php echo APP_URL; ?>/auth/logout.php"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                    </ul>
                </div>
            </div>
            <?php endif; ?>
        </header>

        <!-- Main Content Area -->
        <div class="content-area">