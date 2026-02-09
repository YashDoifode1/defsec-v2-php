<?php

// includes/header.php

// Start session only if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'db.php';

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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec - Security Dashboard</title>
    
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
            padding: 20px;
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
    </style>
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
                    <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'index.php' ? 'active' : ''; ?>" href="index.php">
                        <i class="fas fa-home"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'web-security.php' ? 'active' : ''; ?>" href="web-security.php">
                        <i class="fas fa-bug"></i> Attack Logs
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'vpn-monitoring.php' ? 'active' : ''; ?>" href="vpn-monitoring.php">
                        <i class="fas fa-shield-virus"></i> VPN Monitor
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'block-list.php' ? 'active' : ''; ?>" href="block-list.php">
                        <i class="fas fa-ban"></i> Block List
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'settings.php' ? 'active' : ''; ?>" href="settings.php">
                        <i class="fas fa-cog"></i> Settings
                    </a>
                </li>
                <?php if ($isLoggedIn): ?>
                <li class="nav-item mt-4">
                    <a class="nav-link text-danger" href="logout.php">
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
                    <?php
                    $page_titles = [
                        'index.php' => 'Dashboard',
                        'web-security.php' => 'Attack Logs',
                        'vpn-monitoring.php' => 'VPN Monitoring',
                        'block-list.php' => 'Block List',
                        'settings.php' => 'Settings',
                        'login.php' => 'Login'
                    ];
                    $current_page = basename($_SERVER['PHP_SELF']);
                    echo $page_titles[$current_page] ?? 'Dashboard';
                    ?>
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
                        <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i> Profile</a></li>
                        <li><a class="dropdown-item" href="settings.php"><i class="fas fa-cog me-2"></i> Settings</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                    </ul>
                </div>
            </div>
            <?php endif; ?>
        </header>

        <!-- Main Content Area -->
        <div class="container-fluid py-4">