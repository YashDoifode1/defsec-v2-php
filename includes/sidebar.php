<?php
// includes/sidebar.php
?>
<!-- Sidebar -->
<aside class="sidebar">
    <div class="sidebar-header">
        <div class="logo">
            <i class="fas fa-shield-alt"></i>
            <span class="logo-text">Defsec</span>
            <span class="version">v<?= APP_VERSION ?></span>
        </div>
        <button class="sidebar-toggle" id="sidebarToggle">
            <i class="fas fa-bars"></i>
        </button>
    </div>
    
    <div class="sidebar-user">
        <div class="user-avatar">
            <img src="assets/images/profile.jpeg" alt="<?= htmlspecialchars($_SESSION['full_name'] ?? 'User') ?>">
            <span class="user-status online"></span>
        </div>
        <div class="user-info">
            <h6 class="user-name"><?= htmlspecialchars($_SESSION['full_name'] ?? 'User') ?></h6>
            <span class="user-role"><?= htmlspecialchars(ucfirst($_SESSION['role'] ?? 'User')) ?></span>
        </div>
    </div>
    
    <nav class="sidebar-nav">
        <ul class="nav-links">
            <li class="nav-item">
                <a href="security-dashboard.php" class="nav-link <?= $currentPage === 'security-dashboard.php' ? 'active' : '' ?>">
                    <i class="fas fa-tachometer-alt"></i>
                    <span class="link-text">Dashboard</span>
                </a>
            </li>
            
            <li class="nav-section">
                <span class="section-label">MONITORING</span>
            </li>
            
            <li class="nav-item">
                <a href="web-security.php" class="nav-link <?= $currentPage === 'web-security.php' ? 'active' : '' ?>">
                    <i class="fas fa-bug"></i>
                    <span class="link-text">Attack Logs</span>
                    <span class="badge bg-danger" id="attackCount">0</span>
                </a>
            </li>

            <li class="nav-item">
                <a href="web-security.php" class="nav-link <?= $currentPage === 'security-dashboard.php' ? 'active' : '' ?>">
                    <i class="fas fa-bug"></i>
                    <span class="link-text">Security Logs</span>
                    <span class="badge bg-danger" id="attackCount">0</span>
                </a>
            </li>
            
            <li class="nav-item">
                <a href="user-tracker.php" class="nav-link <?= $currentPage === 'user-tracker.php' ? 'active' : '' ?>">
                    <i class="fas fa-user-secret"></i>
                    <span class="link-text">User Tracking</span>
                </a>
            </li>
            
            <li class="nav-section">
                <span class="section-label">SECURITY</span>
            </li>
            
            <li class="nav-item">
                <a href="block-list.php" class="nav-link <?= $currentPage === 'block-list.php' ? 'active' : '' ?>">
                    <i class="fas fa-ban"></i>
                    <span class="link-text">Blocked IPs</span>
                    <span class="badge bg-warning" id="blockedCount">0</span>
                </a>
            </li>
            
            <li class="nav-item">
                <a href="vpn-monitoring.php" class="nav-link <?= $currentPage === 'vpn-monitoring.php' ? 'active' : '' ?>">
                    <i class="fas fa-shield-virus"></i>
                    <span class="link-text">VPN Security</span>
                </a>
            </li>
            
            <li class="nav-section">
                <span class="section-label">ADMINISTRATION</span>
            </li>
            
            <li class="nav-item">
                <a href="profile.php" class="nav-link <?= $currentPage === 'profile.php' ? 'active' : '' ?>">
                    <i class="fas fa-user-cog"></i>
                    <span class="link-text">Profile</span>
                </a>
            </li>
            
            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
            <li class="nav-item">
                <a href="users.php" class="nav-link <?= $currentPage === 'users.php' ? 'active' : '' ?>">
                    <i class="fas fa-users"></i>
                    <span class="link-text">User Management</span>
                </a>
            </li>
            <?php endif; ?>
        </ul>
    </nav>
    
    <div class="sidebar-footer">
        <div class="system-status">
            <div class="status-indicator">
                <span class="status-dot active"></span>
                <span class="status-text">System Active</span>
            </div>
            <small class="text-muted">Last updated: <span id="lastUpdate">Just now</span></small>
        </div>
        <a href="http://localhost/defsec/v2/logout.php" class="logout-btn">
            <i class="fas fa-sign-out-alt"></i>
            <span>Logout</span>
        </a>
    </div>
</aside>

<style>
    /* Sidebar Styles */
    .sidebar {
        width: 250px;
        background: var(--sidebar-bg);
        position: fixed;
        top: 0;
        left: 0;
        height: 100vh;
        z-index: 1000;
        transition: width 0.3s ease;
        display: flex;
        flex-direction: column;
        border-right: 1px solid var(--border-color);
    }

    .sidebar.collapsed {
        width: 70px;
    }

    .sidebar.collapsed .logo-text,
    .sidebar.collapsed .version,
    .sidebar.collapsed .link-text,
    .sidebar.collapsed .user-name,
    .sidebar.collapsed .user-role,
    .sidebar.collapsed .status-text,
    .sidebar.collapsed .section-label,
    .sidebar.collapsed .logout-btn span,
    .sidebar.collapsed .user-info {
        display: none !important;
    }

    .sidebar.collapsed .nav-link {
        justify-content: center;
    }

    .sidebar.collapsed .nav-link i {
        margin-right: 0;
        font-size: 1.2rem;
    }

    .sidebar.collapsed .badge {
        position: absolute;
        top: 5px;
        right: 5px;
        font-size: 0.6rem;
        padding: 2px 5px;
    }

    .sidebar-header {
        padding: 20px;
        border-bottom: 1px solid var(--border-color);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .logo {
        display: flex;
        align-items: center;
        color: var(--text-color);
        font-weight: bold;
        font-size: 1.5rem;
    }

    .logo i {
        color: var(--primary-color);
        margin-right: 10px;
        font-size: 2rem;
    }

    .version {
        font-size: 0.7rem;
        color: var(--muted-color);
        margin-left: 5px;
        margin-top: 5px;
    }

    .sidebar-toggle {
        background: none;
        border: none;
        color: var(--text-color);
        cursor: pointer;
        font-size: 1.2rem;
    }

    .sidebar-user {
        padding: 20px;
        border-bottom: 1px solid var(--border-color);
        display: flex;
        align-items: center;
    }

    .user-avatar {
        position: relative;
        margin-right: 15px;
    }

    .user-avatar img {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        border: 2px solid var(--primary-color);
    }

    .user-status {
        position: absolute;
        bottom: 0;
        right: 0;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        border: 2px solid var(--sidebar-bg);
    }

    .user-status.online {
        background: var(--success-color);
    }

    .user-status.away {
        background: var(--warning-color);
    }

    .user-status.offline {
        background: var(--danger-color);
    }

    .user-info {
        flex: 1;
    }

    .user-name {
        margin: 0;
        font-size: 0.9rem;
        color: var(--text-color);
    }

    .user-role {
        font-size: 0.8rem;
        color: var(--muted-color);
    }

    .sidebar-nav {
        flex: 1;
        overflow-y: auto;
        padding: 20px 0;
    }

    .nav-links {
        list-style: none;
        padding: 0;
        margin: 0;
    }

    .nav-section {
        padding: 10px 20px;
    }

    .section-label {
        font-size: 0.7rem;
        color: var(--muted-color);
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: bold;
    }

    .nav-item {
        margin: 5px 0;
    }

    .nav-link {
        display: flex;
        align-items: center;
        padding: 12px 20px;
        color: var(--text-color);
        text-decoration: none;
        transition: all 0.3s;
        border-left: 3px solid transparent;
    }

    .nav-link:hover {
        background: rgba(255, 255, 255, 0.05);
        border-left-color: var(--primary-color);
        color: var(--text-color);
    }

    .nav-link.active {
        background: rgba(78, 84, 200, 0.1);
        border-left-color: var(--primary-color);
        color: var(--primary-color);
    }

    .nav-link i {
        margin-right: 10px;
        font-size: 1.1rem;
        width: 20px;
        text-align: center;
    }

    .link-text {
        flex: 1;
    }

    .badge {
        font-size: 0.7rem;
        padding: 3px 6px;
    }

    .sidebar-footer {
        padding: 20px;
        border-top: 1px solid var(--border-color);
    }

    .system-status {
        margin-bottom: 15px;
    }

    .status-indicator {
        display: flex;
        align-items: center;
        margin-bottom: 5px;
    }

    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 8px;
    }

    .status-dot.active {
        background: var(--success-color);
        animation: pulse 2s infinite;
    }

    .status-dot.inactive {
        background: var(--danger-color);
    }

    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }

    .logout-btn {
        display: flex;
        align-items: center;
        padding: 10px;
        background: rgba(220, 53, 69, 0.1);
        color: var(--danger-color);
        text-decoration: none;
        border-radius: 5px;
        transition: all 0.3s;
    }

    .logout-btn:hover {
        background: rgba(220, 53, 69, 0.2);
        color: var(--danger-color);
    }

    .logout-btn i {
        margin-right: 10px;
    }
</style>