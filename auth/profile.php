<?php
// profile.php
require_once '../includes/header.php';
require_once '../includes/auth.php';

// Check if user is logged in
if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    exit();
}

$userId = $auth->getUserId();
$success_msg = '';
$error_msg = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // Validate CSRF token
    if (!validateCSRFToken('profile_form', $csrf_token)) {
        $error_msg = "Invalid security token. Please try again.";
    } else {
        // Update profile information
        $full_name = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $bio = trim($_POST['bio'] ?? '');
        
        if (empty($email)) {
            $error_msg = "Email is required.";
        } else {
            try {
                // Check if email already exists for another user
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $userId]);
                if ($stmt->fetch()) {
                    $error_msg = "Email already exists.";
                } else {
                    // Update user profile
                    $stmt = $pdo->prepare("UPDATE users SET full_name = ?, email = ?, phone = ?, bio = ?, updated_at = NOW() WHERE id = ?");
                    if ($stmt->execute([$full_name, $email, $phone, $bio, $userId])) {
                        // Update session
                        $_SESSION['email'] = $email;
                        $_SESSION['full_name'] = $full_name;
                        $success_msg = "Profile updated successfully.";
                    }
                }
            } catch (PDOException $e) {
                $error_msg = "Error updating profile: " . $e->getMessage();
            }
        }
    }
}

// Get current user data with associated website details
try {
    // Get user basic info
    $stmt = $pdo->prepare("
        SELECT 
            u.*,
            COUNT(DISTINCT w.id) as website_count,
            GROUP_CONCAT(DISTINCT w.site_name ORDER BY w.site_name SEPARATOR ', ') as website_names,
            GROUP_CONCAT(DISTINCT w.domain ORDER BY w.domain SEPARATOR ', ') as website_domains
        FROM users u
        LEFT JOIN websites w ON u.id = w.user_id
        WHERE u.id = ?
        GROUP BY u.id
    ");
    $stmt->execute([$userId]);
    $userData = $stmt->fetch();
    
    // Get threat statistics
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(DISTINCT al.id) as total_threats,
            SUM(CASE WHEN al.severity = 'Critical' THEN 1 ELSE 0 END) as critical_threats,
            SUM(CASE WHEN al.severity = 'High' THEN 1 ELSE 0 END) as high_threats
        FROM attack_logs al
        WHERE al.user_id = ?
    ");
    $stmt->execute([$userId]);
    $threatStats = $stmt->fetch();
    
    // Get request statistics
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(DISTINCT al.id) as total_requests,
            COUNT(DISTINCT al.ip_address) as unique_ips
        FROM access_logs al
        WHERE al.user_id = ?
    ");
    $stmt->execute([$userId]);
    $requestStats = $stmt->fetch();
    
    // Get blocked IP statistics
    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT id) as blocked_ips_count
        FROM blocked_ips 
        WHERE user_id = ?
        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
    ");
    $stmt->execute([$userId]);
    $blockedStats = $stmt->fetch();
    
    // Get website details (first website for display)
    $stmt = $pdo->prepare("
        SELECT id, site_name, domain, status, created_at
        FROM websites 
        WHERE user_id = ?
        ORDER BY created_at DESC 
        LIMIT 1
    ");
    $stmt->execute([$userId]);
    $primaryWebsite = $stmt->fetch();
    
    // Get recent activity (combine login logs and access logs)
    $stmt = $pdo->prepare("
        (SELECT 
            'login' as activity_type,
            created_at as timestamp,
            ip_address,
            user_agent,
            NULL as request_uri
        FROM login_logs 
        WHERE user_id = ?
        ORDER BY created_at DESC 
        LIMIT 5)
        
        UNION ALL
        
        (SELECT 
            'access' as activity_type,
            timestamp,
            ip_address,
            user_agent,
            request_uri
        FROM access_logs 
        WHERE user_id = ?
        ORDER BY timestamp DESC 
        LIMIT 5)
        
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $stmt->execute([$userId, $userId]);
    $recentActivity = $stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Profile data error: " . $e->getMessage());
    $error_msg = "Error loading profile data: " . $e->getMessage();
    $userData = [];
    $threatStats = ['total_threats' => 0, 'critical_threats' => 0, 'high_threats' => 0];
    $requestStats = ['total_requests' => 0, 'unique_ips' => 0];
    $blockedStats = ['blocked_ips_count' => 0];
    $primaryWebsite = [];
    $recentActivity = [];
}

// Generate CSRF token
$csrf_token = generateCSRFToken('profile_form');
?>

<div class="row g-4">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-user-circle me-2"></i>My Profile</h2>
                <p class="text-muted mb-0">Manage your personal information and activity</p>
            </div>
            <div>
                <span class="badge bg-<?= ($userData['status'] ?? 'active') === 'active' ? 'success' : 'danger' ?>">
                    <i class="fas fa-user me-1"></i> 
                    <?= htmlspecialchars(ucfirst($userData['role'] ?? 'user')) ?> Account
                </span>
                <?php if ($userData['status'] === 'suspended'): ?>
                    <span class="badge bg-danger ms-2">
                        <i class="fas fa-ban me-1"></i> Suspended
                    </span>
                <?php endif; ?>
            </div>
        </div>
        
        <?php if ($success_msg): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="fas fa-check-circle me-2"></i> <?= htmlspecialchars($success_msg) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error_msg): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-circle me-2"></i> <?= htmlspecialchars($error_msg) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
    </div>

    <!-- Profile Header Card -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="row align-items-center">
                <div class="col-auto">
                    <div class="avatar-lg">
                        <div class="rounded-circle bg-primary d-flex align-items-center justify-content-center" 
                             style="width: 100px; height: 100px; font-size: 2.5rem; color: white;">
                            <?= strtoupper(substr($userData['username'] ?? 'U', 0, 1)) ?>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <h3 class="mb-2"><?= htmlspecialchars($userData['full_name'] ?? $userData['username'] ?? 'User') ?></h3>
                    <p class="text-muted mb-1">
                        <i class="fas fa-envelope me-2"></i><?= htmlspecialchars($userData['email'] ?? 'No email') ?>
                    </p>
                    <p class="text-muted mb-0">
                        <i class="fas fa-globe me-2"></i>
                        <?php if (!empty($userData['website_count']) && $userData['website_count'] > 0): ?>
                            Protecting <?= $userData['website_count'] ?> website(s)
                        <?php else: ?>
                            No websites assigned
                        <?php endif; ?>
                    </p>
                </div>
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-cog me-1"></i> Account Actions
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="changeAvatar()">
                                <i class="fas fa-camera me-2"></i> Change Avatar
                            </a></li>
                            <?php if (!empty($userData['api_key'])): ?>
                                <li><a class="dropdown-item" href="#" onclick="showAPIKey()">
                                    <i class="fas fa-key me-2"></i> View API Key
                                </a></li>
                            <?php endif; ?>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="change-password.php">
                                <i class="fas fa-lock me-2"></i> Change Password
                            </a></li>
                            <li><a class="dropdown-item text-warning" href="#" onclick="regenerateAPIKey()">
                                <i class="fas fa-redo me-2"></i> Regenerate API Key
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Account Status Info -->
            <?php if ($userData['login_attempts'] > 2): ?>
                <div class="alert alert-warning mt-3 mb-0">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Multiple failed login attempts detected (<?= $userData['login_attempts'] ?>). 
                    <?php if ($userData['is_locked']): ?>
                        <strong>Account is currently locked.</strong>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-danger bg-opacity-10 p-3">
                        <i class="fas fa-shield-alt fa-2x text-danger"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($threatStats['total_threats'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Threats Blocked</p>
                    <?php if (($threatStats['critical_threats'] ?? 0) > 0): ?>
                        <small class="text-danger">
                            <i class="fas fa-exclamation-circle me-1"></i>
                            <?= $threatStats['critical_threats'] ?> critical
                        </small>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-primary bg-opacity-10 p-3">
                        <i class="fas fa-chart-line fa-2x text-primary"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($requestStats['total_requests'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Requests Monitored</p>
                    <?php if (($requestStats['unique_ips'] ?? 0) > 0): ?>
                        <small class="text-primary">
                            <i class="fas fa-users me-1"></i>
                            <?= $requestStats['unique_ips'] ?> unique IPs
                        </small>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-success bg-opacity-10 p-3">
                        <i class="fas fa-ban fa-2x text-success"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($blockedStats['blocked_ips_count'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Active Blocks</p>
                    <small class="text-success">
                        <i class="fas fa-clock me-1"></i> Real-time protection
                    </small>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-warning bg-opacity-10 p-3">
                        <i class="fas fa-globe fa-2x text-warning"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($userData['website_count'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Protected Websites</p>
                    <?php if (!empty($primaryWebsite['domain'])): ?>
                        <small class="text-warning" title="<?= htmlspecialchars($primaryWebsite['domain']) ?>">
                            <i class="fas fa-link me-1"></i>
                            <?= htmlspecialchars(substr($primaryWebsite['domain'], 0, 20)) ?>...
                        </small>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Profile Form -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-user-edit me-2"></i>Edit Profile Information</h5>
            
            <form method="POST" class="row g-3">
                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                
                <div class="col-md-6">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control bg-dark text-light" id="username" 
                           value="<?= htmlspecialchars($userData['username'] ?? '') ?>" readonly>
                    <div class="form-text">Username cannot be changed</div>
                </div>
                
                <div class="col-md-6">
                    <label for="email" class="form-label">Email Address *</label>
                    <input type="email" class="form-control bg-dark text-light" id="email" name="email" 
                           value="<?= htmlspecialchars($userData['email'] ?? '') ?>" required>
                </div>
                
                <div class="col-md-6">
                    <label for="full_name" class="form-label">Full Name</label>
                    <input type="text" class="form-control bg-dark text-light" id="full_name" name="full_name"
                           value="<?= htmlspecialchars($userData['full_name'] ?? '') ?>"
                           placeholder="Enter your full name">
                </div>
                
                <div class="col-md-6">
                    <label for="phone" class="form-label">Phone Number</label>
                    <input type="tel" class="form-control bg-dark text-light" id="phone" name="phone"
                           value="<?= htmlspecialchars($userData['phone'] ?? '') ?>"
                           placeholder="+1 (555) 123-4567">
                </div>
                
                <div class="col-12">
                    <label for="bio" class="form-label">Bio / About Me</label>
                    <textarea class="form-control bg-dark text-light" id="bio" name="bio" rows="4"
                              placeholder="Tell us about yourself..."><?= htmlspecialchars($userData['bio'] ?? '') ?></textarea>
                    <div class="form-text">Maximum 500 characters</div>
                </div>
                
                <div class="col-md-6">
                    <label class="form-label">Account Role</label>
                    <input type="text" class="form-control bg-dark text-light" 
                           value="<?= htmlspecialchars(ucfirst($userData['role'] ?? 'user')) ?>" readonly>
                </div>
                
                <div class="col-md-6">
                    <label class="form-label">Account Status</label>
                    <input type="text" class="form-control bg-dark text-light" 
                           value="<?= htmlspecialchars(ucfirst($userData['status'] ?? 'active')) ?>" readonly>
                </div>
                
                <div class="col-12">
                    <label class="form-label">Protected Websites</label>
                    <?php if (!empty($userData['website_names'])): ?>
                        <div class="form-control bg-dark text-light" style="min-height: 80px;">
                            <?php 
                            $websites = explode(', ', $userData['website_names']);
                            $domains = explode(', ', $userData['website_domains']);
                            foreach ($websites as $index => $website): 
                                $domain = $domains[$index] ?? '';
                            ?>
                                <div class="mb-1">
                                    <i class="fas fa-globe me-2 text-info"></i>
                                    <strong><?= htmlspecialchars($website) ?></strong>
                                    <small class="text-muted ms-2">(<?= htmlspecialchars($domain) ?>)</small>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="form-control bg-dark text-light text-center py-2">
                            <i class="fas fa-exclamation-circle me-2 text-warning"></i>
                            No websites assigned. <a href="websites.php" class="text-primary">Add a website</a>
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="col-12 mt-4">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save me-2"></i> Update Profile
                    </button>
                    <button type="reset" class="btn btn-outline-secondary ms-2">
                        <i class="fas fa-undo me-2"></i> Reset Changes
                    </button>
                    <a href="websites.php" class="btn btn-outline-info ms-2">
                        <i class="fas fa-cog me-2"></i> Manage Websites
                    </a>
                </div>
            </form>
        </div>
        
        <!-- API Key Section -->
        <?php if (!empty($userData['api_key'])): ?>
        <div class="dashboard-card mt-4">
            <h5 class="mb-4"><i class="fas fa-key me-2"></i>API Access</h5>
            <div class="alert alert-dark">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <strong>API Key:</strong>
                        <code id="apiKeyDisplay" class="ms-2"><?= substr($userData['api_key'], 0, 10) ?>**********</code>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="toggleAPIKey()">
                            <i class="fas fa-eye me-1"></i> Show Key
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="copyAPIKey()">
                            <i class="fas fa-copy me-1"></i> Copy
                        </button>
                    </div>
                </div>
                <small class="text-muted mt-2 d-block">
                    <i class="fas fa-info-circle me-1"></i>
                    Use this key for API authentication. Keep it secure and never share it publicly.
                </small>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- Account Information Sidebar -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-info-circle me-2"></i>Account Information</h5>
            
            <div class="list-group list-group-flush">
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-user-tag me-2"></i> Account Status</span>
                        <span class="badge bg-<?= ($userData['status'] ?? 'active') === 'active' ? 'success' : 'danger' ?>">
                            <?= htmlspecialchars(ucfirst($userData['status'] ?? 'active')) ?>
                        </span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-calendar-plus me-2"></i> Member Since</span>
                        <span><?= date('M j, Y', strtotime($userData['created_at'] ?? 'now')) ?></span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-clock me-2"></i> Last Login</span>
                        <span><?= $userData['last_login'] ? date('M j, H:i', strtotime($userData['last_login'])) : 'Never' ?></span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-key me-2"></i> Login Attempts</span>
                        <span class="<?= ($userData['login_attempts'] ?? 0) > 2 ? 'text-warning' : '' ?>">
                            <?= $userData['login_attempts'] ?? 0 ?>
                        </span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-lock me-2"></i> Account Lock</span>
                        <span class="<?= $userData['is_locked'] ? 'text-danger' : 'text-success' ?>">
                            <?= $userData['is_locked'] ? 'Locked' : 'Unlocked' ?>
                        </span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-id-badge me-2"></i> User ID</span>
                        <code><?= htmlspecialchars($userId) ?></code>
                    </div>
                </div>
                
                <?php if (!empty($primaryWebsite)): ?>
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between align-items-start">
                        <span><i class="fas fa-globe me-2"></i> Primary Website</span>
                        <div class="text-end">
                            <div><strong><?= htmlspecialchars($primaryWebsite['site_name']) ?></strong></div>
                            <small class="text-muted"><?= htmlspecialchars($primaryWebsite['domain']) ?></small>
                            <div>
                                <span class="badge bg-<?= $primaryWebsite['status'] === 'active' ? 'success' : 'secondary' ?>">
                                    <?= htmlspecialchars($primaryWebsite['status']) ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            
            <div class="mt-4">
                <h6 class="border-bottom pb-2 mb-3">Quick Actions</h6>
                <div class="d-grid gap-2">
                    <a href="dashboard.php" class="btn btn-outline-success">
                        <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                    </a>
                    <a href="web-security.php" class="btn btn-outline-warning">
                        <i class="fas fa-bug me-2"></i> Security Logs
                    </a>
                    <a href="websites.php" class="btn btn-outline-info">
                        <i class="fas fa-cog me-2"></i> Manage Websites
                    </a>
                    <a href="activity-logs.php" class="btn btn-outline-secondary">
                        <i class="fas fa-history me-2"></i> Activity Logs
                    </a>
                </div>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="dashboard-card mt-4">
            <h5 class="mb-4"><i class="fas fa-history me-2"></i>Recent Activity</h5>
            
            <div class="activity-timeline">
                <?php if (empty($recentActivity)): ?>
                    <div class="text-center py-4">
                        <i class="fas fa-inbox fa-2x text-muted mb-3"></i>
                        <p class="text-muted">No recent activity</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($recentActivity as $activity): ?>
                        <div class="activity-item mb-3">
                            <div class="d-flex">
                                <div class="flex-shrink-0">
                                    <div class="activity-icon bg-<?= $activity['activity_type'] === 'login' ? 'primary' : 'info' ?>">
                                        <i class="fas fa-<?= $activity['activity_type'] === 'login' ? 'sign-in-alt' : 'external-link-alt' ?> text-white"></i>
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6 class="mb-1">
                                        <?= $activity['activity_type'] === 'login' ? 'Login' : 'Access' ?> from 
                                        <?= htmlspecialchars($activity['ip_address'] ?? 'Unknown IP') ?>
                                    </h6>
                                    <p class="text-muted mb-0 small">
                                        <i class="far fa-clock me-1"></i>
                                        <?= date('M j, H:i', strtotime($activity['timestamp'])) ?>
                                        <?php if (!empty($activity['request_uri'])): ?>
                                            <br><small class="text-muted">
                                                <i class="fas fa-link me-1"></i>
                                                <?= htmlspecialchars(substr($activity['request_uri'], 0, 40)) ?>...
                                            </small>
                                        <?php endif; ?>
                                    </p>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <div class="text-center mt-3">
                <a href="activity-logs.php" class="btn btn-outline-primary btn-sm">
                    View All Activity <i class="fas fa-arrow-right ms-1"></i>
                </a>
            </div>
        </div>
    </div>
</div>

<style>
    .avatar-lg {
        position: relative;
    }
    
    .avatar-lg .rounded-circle {
        width: 100px;
        height: 100px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .avatar-lg .rounded-circle:hover {
        transform: scale(1.05);
    }
    
    .activity-timeline .activity-item {
        position: relative;
        padding-left: 10px;
    }
    
    .activity-timeline .activity-item:before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 2px;
        background-color: var(--primary-color);
        opacity: 0.3;
    }
    
    .activity-timeline .activity-item:last-child:before {
        bottom: 50%;
    }
    
    .activity-timeline .activity-icon {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .activity-icon.bg-primary {
        background-color: rgba(13, 110, 253, 0.2);
    }
    
    .activity-icon.bg-info {
        background-color: rgba(23, 162, 184, 0.2);
    }
</style>

<script>
    // Character counter for bio
    document.getElementById('bio').addEventListener('input', function() {
        const maxLength = 500;
        const currentLength = this.value.length;
        const counter = document.getElementById('bioCounter') || (() => {
            const div = document.createElement('div');
            div.id = 'bioCounter';
            div.className = 'form-text text-end';
            this.parentNode.appendChild(div);
            return div;
        })();
        
        counter.textContent = `${currentLength}/${maxLength} characters`;
        
        if (currentLength > maxLength) {
            counter.classList.add('text-danger');
            this.classList.add('is-invalid');
        } else {
            counter.classList.remove('text-danger');
            this.classList.remove('is-invalid');
        }
    });
    
    // Initialize bio counter on page load
    document.addEventListener('DOMContentLoaded', function() {
        const bio = document.getElementById('bio');
        if (bio) {
            bio.dispatchEvent(new Event('input'));
        }
    });
    
    // API Key Management
    let apiKeyVisible = false;
    const fullAPIKey = '<?= $userData['api_key'] ?? '' ?>';
    
    function toggleAPIKey() {
        const display = document.getElementById('apiKeyDisplay');
        if (display) {
            if (apiKeyVisible) {
                display.textContent = fullAPIKey.substring(0, 10) + '**********';
                event.target.innerHTML = '<i class="fas fa-eye me-1"></i> Show Key';
                event.target.classList.remove('btn-danger');
                event.target.classList.add('btn-outline-primary');
            } else {
                display.textContent = fullAPIKey;
                event.target.innerHTML = '<i class="fas fa-eye-slash me-1"></i> Hide Key';
                event.target.classList.remove('btn-outline-primary');
                event.target.classList.add('btn-danger');
            }
            apiKeyVisible = !apiKeyVisible;
        }
    }
    
    function copyAPIKey() {
        if (!fullAPIKey) return;
        
        navigator.clipboard.writeText(fullAPIKey).then(() => {
            const originalText = event.target.innerHTML;
            event.target.innerHTML = '<i class="fas fa-check me-1"></i> Copied!';
            event.target.classList.remove('btn-outline-warning');
            event.target.classList.add('btn-success');
            
            setTimeout(() => {
                event.target.innerHTML = originalText;
                event.target.classList.remove('btn-success');
                event.target.classList.add('btn-outline-warning');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            alert('Failed to copy API key to clipboard');
        });
    }
    
    function regenerateAPIKey() {
        if (confirm('Are you sure you want to regenerate your API key?\n\nThis will invalidate your current key and require updating all applications using it.')) {
            fetch('api/regenerate-api-key.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    csrf_token: '<?= $csrf_token ?>'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('API key regenerated successfully!');
                    location.reload();
                } else {
                    alert('Error: ' + (data.message || 'Failed to regenerate API key'));
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to regenerate API key');
            });
        }
    }
    
    function showAPIKey() {
        const modalContent = `
            <div class="modal fade" id="apiKeyModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content bg-dark">
                        <div class="modal-header border-secondary">
                            <h5 class="modal-title"><i class="fas fa-key me-2"></i>Your API Key</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                Keep this key secure! Never share it publicly.
                            </div>
                            <div class="input-group mb-3">
                                <input type="text" class="form-control bg-dark text-light" id="modalAPIKey" 
                                       value="${fullAPIKey}" readonly>
                                <button class="btn btn-outline-primary" type="button" onclick="copyToClipboard('modalAPIKey')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <small class="text-muted">
                                Use this key in the Authorization header: 
                                <code>Authorization: Bearer ${fullAPIKey}</code>
                            </small>
                        </div>
                        <div class="modal-footer border-secondary">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal if any
        const existingModal = document.getElementById('apiKeyModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Add new modal
        document.body.insertAdjacentHTML('beforeend', modalContent);
        const modal = new bootstrap.Modal(document.getElementById('apiKeyModal'));
        modal.show();
    }
    
    function copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        element.select();
        document.execCommand('copy');
        
        const button = event.target.closest('button');
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>';
        button.classList.remove('btn-outline-primary');
        button.classList.add('btn-success');
        
        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-primary');
        }, 2000);
    }
    
    // Form validation
    document.querySelector('form').addEventListener('submit', function(e) {
        const email = document.getElementById('email').value.trim();
        const bio = document.getElementById('bio').value.trim();
        
        if (!email) {
            e.preventDefault();
            showAlert('Email address is required.', 'danger');
            return;
        }
        
        if (bio.length > 500) {
            e.preventDefault();
            showAlert('Bio must be 500 characters or less.', 'danger');
            return;
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            e.preventDefault();
            showAlert('Please enter a valid email address.', 'danger');
            return;
        }
    });
    
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            <i class="fas fa-exclamation-circle me-2"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.querySelector('.col-12').insertBefore(alertDiv, document.querySelector('.col-12').firstChild);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    // Avatar functions
    function changeAvatar() {
        alert('Avatar upload functionality would be implemented with a proper file upload system.');
        // In production, implement file upload with validation
    }
</script>

<?php
require_once '../includes/footer.php';
?>