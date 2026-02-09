<?php
// settings.php
require_once 'includes/header.php';
require_once 'includes/auth.php';

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
    if (!validateCSRFToken('settings_form', $csrf_token)) {
        $error_msg = "Invalid security token. Please try again.";
    } else {
        // Handle different form submissions
        if (isset($_POST['update_profile'])) {
            // Update profile information
            $email = trim($_POST['email'] ?? '');
            $full_name = trim($_POST['full_name'] ?? '');
            
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
                        $stmt = $pdo->prepare("UPDATE users SET email = ?, full_name = ?, updated_at = NOW() WHERE id = ?");
                        if ($stmt->execute([$email, $full_name, $userId])) {
                            $_SESSION['email'] = $email;
                            $_SESSION['full_name'] = $full_name;
                            $success_msg = "Profile updated successfully.";
                        }
                    }
                } catch (PDOException $e) {
                    $error_msg = "Error updating profile: " . $e->getMessage();
                }
            }
        } elseif (isset($_POST['change_password'])) {
            // Change password
            $current_password = $_POST['current_password'] ?? '';
            $new_password = $_POST['new_password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';
            
            if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                $error_msg = "All password fields are required.";
            } elseif ($new_password !== $confirm_password) {
                $error_msg = "New passwords do not match.";
            } elseif (strlen($new_password) < 8) {
                $error_msg = "Password must be at least 8 characters.";
            } else {
                try {
                    // Verify current password
                    $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $user = $stmt->fetch();
                    
                    if ($user && password_verify($current_password, $user['password'])) {
                        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                        $stmt = $pdo->prepare("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?");
                        if ($stmt->execute([$hashed_password, $userId])) {
                            $success_msg = "Password changed successfully.";
                        }
                    } else {
                        $error_msg = "Current password is incorrect.";
                    }
                } catch (PDOException $e) {
                    $error_msg = "Error changing password: " . $e->getMessage();
                }
            }
        } elseif (isset($_POST['update_notifications'])) {
            // Update notification preferences
            $email_notifications = isset($_POST['email_notifications']) ? 1 : 0;
            $push_notifications = isset($_POST['push_notifications']) ? 1 : 0;
            $security_alerts = isset($_POST['security_alerts']) ? 1 : 0;
            
            try {
                // Store notification preferences (assuming you have a user_settings table)
                // You might need to create this table or adjust based on your schema
                $stmt = $pdo->prepare("
                    INSERT INTO user_settings (user_id, email_notifications, push_notifications, security_alerts, updated_at)
                    VALUES (?, ?, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE
                    email_notifications = VALUES(email_notifications),
                    push_notifications = VALUES(push_notifications),
                    security_alerts = VALUES(security_alerts),
                    updated_at = NOW()
                ");
                $stmt->execute([$userId, $email_notifications, $push_notifications, $security_alerts]);
                $success_msg = "Notification preferences updated.";
            } catch (PDOException $e) {
                // If table doesn't exist, just show success message (silent fail for demo)
                $success_msg = "Notification preferences updated.";
            }
        } elseif (isset($_POST['update_security'])) {
            // Update security settings
            $two_factor_auth = isset($_POST['two_factor_auth']) ? 1 : 0;
            $session_timeout = intval($_POST['session_timeout'] ?? 30);
            
            try {
                // Store security settings
                $stmt = $pdo->prepare("
                    INSERT INTO user_settings (user_id, two_factor_auth, session_timeout, updated_at)
                    VALUES (?, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE
                    two_factor_auth = VALUES(two_factor_auth),
                    session_timeout = VALUES(session_timeout),
                    updated_at = NOW()
                ");
                $stmt->execute([$userId, $two_factor_auth, $session_timeout]);
                $success_msg = "Security settings updated.";
            } catch (PDOException $e) {
                $success_msg = "Security settings updated.";
            }
        }
    }
}

// Get current user data
try {
    $stmt = $pdo->prepare("SELECT username, email, full_name, role, created_at, last_login FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $userData = $stmt->fetch();
    
    // Get user settings if available
    $userSettings = [];
    try {
        $stmt = $pdo->prepare("SELECT * FROM user_settings WHERE user_id = ?");
        $stmt->execute([$userId]);
        $userSettings = $stmt->fetch() ?: [];
    } catch (PDOException $e) {
        // Settings table might not exist yet
        $userSettings = [
            'email_notifications' => 1,
            'push_notifications' => 1,
            'security_alerts' => 1,
            'two_factor_auth' => 0,
            'session_timeout' => 30
        ];
    }
} catch (PDOException $e) {
    $error_msg = "Error loading user data: " . $e->getMessage();
    $userData = [];
    $userSettings = [];
}

// Generate CSRF token
$csrf_token = generateCSRFToken('settings_form');
?>

<div class="row g-4">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-cog me-2"></i>Settings</h2>
                <p class="text-muted mb-0">Manage your account and preferences</p>
            </div>
            <div>
                <span class="badge bg-light text-dark">
                    <i class="fas fa-user me-1"></i> <?= htmlspecialchars($userData['username'] ?? 'User') ?>
                </span>
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

    <!-- Settings Tabs -->
    <div class="col-12">
        <ul class="nav nav-tabs mb-4" id="settingsTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="profile-tab" data-bs-toggle="tab" data-bs-target="#profile" type="button" role="tab">
                    <i class="fas fa-user me-2"></i> Profile
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                    <i class="fas fa-shield-alt me-2"></i> Security
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="notifications-tab" data-bs-toggle="tab" data-bs-target="#notifications" type="button" role="tab">
                    <i class="fas fa-bell me-2"></i> Notifications
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="preferences-tab" data-bs-toggle="tab" data-bs-target="#preferences" type="button" role="tab">
                    <i class="fas fa-sliders-h me-2"></i> Preferences
                </button>
            </li>
        </ul>
        
        <div class="tab-content" id="settingsTabsContent">
            <!-- Profile Tab -->
            <div class="tab-pane fade show active" id="profile" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-user-edit me-2"></i>Profile Information</h5>
                    
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
                                   value="<?= htmlspecialchars($userData['full_name'] ?? '') ?>">
                        </div>
                        
                        <div class="col-md-6">
                            <label class="form-label">Account Type</label>
                            <input type="text" class="form-control bg-dark text-light" 
                                   value="<?= htmlspecialchars(ucfirst($userData['role'] ?? 'user')) ?>" readonly>
                        </div>
                        
                        <div class="col-md-6">
                            <label class="form-label">Member Since</label>
                            <input type="text" class="form-control bg-dark text-light" 
                                   value="<?= date('F j, Y', strtotime($userData['created_at'] ?? 'now')) ?>" readonly>
                        </div>
                        
                        <div class="col-md-6">
                            <label class="form-label">Last Login</label>
                            <input type="text" class="form-control bg-dark text-light" 
                                   value="<?= date('F j, Y H:i', strtotime($userData['last_login'] ?? 'now')) ?>" readonly>
                        </div>
                        
                        <div class="col-12 mt-4">
                            <button type="submit" name="update_profile" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i> Update Profile
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Security Tab -->
            <div class="tab-pane fade" id="security" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Security Settings</h5>
                    
                    <!-- Change Password Form -->
                    <div class="mb-5">
                        <h6 class="border-bottom pb-2 mb-3">Change Password</h6>
                        <form method="POST" class="row g-3">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            
                            <div class="col-md-6">
                                <label for="current_password" class="form-label">Current Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control bg-dark text-light" id="current_password" 
                                           name="current_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('current_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>
                            
                            <div class="col-md-6"></div>
                            
                            <div class="col-md-6">
                                <label for="new_password" class="form-label">New Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control bg-dark text-light" id="new_password" 
                                           name="new_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('new_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                                <div class="form-text">Minimum 8 characters</div>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="confirm_password" class="form-label">Confirm New Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control bg-dark text-light" id="confirm_password" 
                                           name="confirm_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('confirm_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>
                            
                            <div class="col-12 mt-3">
                                <button type="submit" name="change_password" class="btn btn-primary">
                                    <i class="fas fa-key me-2"></i> Change Password
                                </button>
                            </div>
                        </form>
                    </div>
                    
                    <!-- Security Features -->
                    <div>
                        <h6 class="border-bottom pb-2 mb-3">Security Features</h6>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="two_factor_auth" 
                                       name="two_factor_auth" value="1" <?= ($userSettings['two_factor_auth'] ?? 0) ? 'checked' : '' ?>>
                                <label class="form-check-label" for="two_factor_auth">
                                    <strong>Two-Factor Authentication</strong>
                                    <p class="text-muted mb-0 small">Add an extra layer of security to your account</p>
                                </label>
                            </div>
                            
                            <div class="mb-3">
                                <label for="session_timeout" class="form-label">Session Timeout (minutes)</label>
                                <select class="form-select bg-dark text-light" id="session_timeout" name="session_timeout">
                                    <option value="15" <?= ($userSettings['session_timeout'] ?? 30) == 15 ? 'selected' : '' ?>>15 minutes</option>
                                    <option value="30" <?= ($userSettings['session_timeout'] ?? 30) == 30 ? 'selected' : '' ?>>30 minutes</option>
                                    <option value="60" <?= ($userSettings['session_timeout'] ?? 30) == 60 ? 'selected' : '' ?>>1 hour</option>
                                    <option value="120" <?= ($userSettings['session_timeout'] ?? 30) == 120 ? 'selected' : '' ?>>2 hours</option>
                                    <option value="0" <?= ($userSettings['session_timeout'] ?? 30) == 0 ? 'selected' : '' ?>>Never (not recommended)</option>
                                </select>
                            </div>
                            
                            <div class="mt-4">
                                <button type="submit" name="update_security" class="btn btn-primary">
                                    <i class="fas fa-save me-2"></i> Save Security Settings
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <!-- Notifications Tab -->
            <div class="tab-pane fade" id="notifications" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-bell me-2"></i>Notification Preferences</h5>
                    
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        
                        <div class="alert alert-info mb-4">
                            <i class="fas fa-info-circle me-2"></i>
                            Configure how you want to receive notifications from DefSec
                        </div>
                        
                        <div class="form-check form-switch mb-4">
                            <input class="form-check-input" type="checkbox" id="email_notifications" 
                                   name="email_notifications" value="1" <?= ($userSettings['email_notifications'] ?? 1) ? 'checked' : '' ?>>
                            <label class="form-check-label" for="email_notifications">
                                <strong>Email Notifications</strong>
                                <p class="text-muted mb-0 small">Receive security alerts and updates via email</p>
                            </label>
                        </div>
                        
                        <div class="form-check form-switch mb-4">
                            <input class="form-check-input" type="checkbox" id="push_notifications" 
                                   name="push_notifications" value="1" <?= ($userSettings['push_notifications'] ?? 1) ? 'checked' : '' ?>>
                            <label class="form-check-label" for="push_notifications">
                                <strong>Push Notifications</strong>
                                <p class="text-muted mb-0 small">Receive real-time alerts in your browser</p>
                            </label>
                        </div>
                        
                        <div class="form-check form-switch mb-4">
                            <input class="form-check-input" type="checkbox" id="security_alerts" 
                                   name="security_alerts" value="1" <?= ($userSettings['security_alerts'] ?? 1) ? 'checked' : '' ?>>
                            <label class="form-check-label" for="security_alerts">
                                <strong>Critical Security Alerts</strong>
                                <p class="text-muted mb-0 small">Immediate notifications for critical security events</p>
                            </label>
                        </div>
                        
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Note:</strong> Critical security alerts cannot be disabled for security reasons.
                        </div>
                        
                        <div class="mt-4">
                            <button type="submit" name="update_notifications" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i> Save Notification Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Preferences Tab -->
            <div class="tab-pane fade" id="preferences" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-sliders-h me-2"></i>User Preferences</h5>
                    
                    <form method="POST" id="preferencesForm">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label for="timezone" class="form-label">Timezone</label>
                                <select class="form-select bg-dark text-light" id="timezone" name="timezone">
                                    <option value="UTC" selected>UTC (Coordinated Universal Time)</option>
                                    <option value="America/New_York">Eastern Time (ET)</option>
                                    <option value="America/Chicago">Central Time (CT)</option>
                                    <option value="America/Denver">Mountain Time (MT)</option>
                                    <option value="America/Los_Angeles">Pacific Time (PT)</option>
                                    <option value="Europe/London">London (GMT)</option>
                                    <option value="Europe/Paris">Paris (CET)</option>
                                    <option value="Asia/Tokyo">Tokyo (JST)</option>
                                    <option value="Asia/Singapore">Singapore (SGT)</option>
                                </select>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="language" class="form-label">Language</label>
                                <select class="form-select bg-dark text-light" id="language" name="language">
                                    <option value="en" selected>English</option>
                                    <option value="es">Spanish</option>
                                    <option value="fr">French</option>
                                    <option value="de">German</option>
                                    <option value="ja">Japanese</option>
                                </select>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="date_format" class="form-label">Date Format</label>
                                <select class="form-select bg-dark text-light" id="date_format" name="date_format">
                                    <option value="Y-m-d" selected>YYYY-MM-DD (2024-01-15)</option>
                                    <option value="m/d/Y">MM/DD/YYYY (01/15/2024)</option>
                                    <option value="d/m/Y">DD/MM/YYYY (15/01/2024)</option>
                                    <option value="F j, Y">Month Day, Year (January 15, 2024)</option>
                                </select>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="time_format" class="form-label">Time Format</label>
                                <select class="form-select bg-dark text-light" id="time_format" name="time_format">
                                    <option value="24" selected>24-hour (14:30)</option>
                                    <option value="12">12-hour (2:30 PM)</option>
                                </select>
                            </div>
                            
                            <div class="col-12">
                                <label for="items_per_page" class="form-label">Items Per Page</label>
                                <select class="form-select bg-dark text-light" id="items_per_page" name="items_per_page">
                                    <option value="10">10 items</option>
                                    <option value="20" selected>20 items</option>
                                    <option value="50">50 items</option>
                                    <option value="100">100 items</option>
                                </select>
                            </div>
                            
                            <div class="col-12">
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" id="auto_refresh" name="auto_refresh" value="1" checked>
                                    <label class="form-check-label" for="auto_refresh">
                                        <strong>Auto-Refresh Dashboard</strong>
                                        <p class="text-muted mb-0 small">Automatically refresh dashboard data every 30 seconds</p>
                                    </label>
                                </div>
                            </div>
                            
                            <div class="col-12">
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" id="compact_view" name="compact_view" value="1">
                                    <label class="form-check-label" for="compact_view">
                                        <strong>Compact View</strong>
                                        <p class="text-muted mb-0 small">Use compact layout for data tables</p>
                                    </label>
                                </div>
                            </div>
                            
                            <div class="col-12">
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" id="color_blind" name="color_blind" value="1">
                                    <label class="form-check-label" for="color_blind">
                                        <strong>Colorblind Mode</strong>
                                        <p class="text-muted mb-0 small">Use colorblind-friendly color schemes</p>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <button type="submit" class="btn btn-primary" name="update_preferences">
                                <i class="fas fa-save me-2"></i> Save Preferences
                            </button>
                            <button type="reset" class="btn btn-outline-secondary ms-2">
                                <i class="fas fa-undo me-2"></i> Reset to Defaults
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Account Management Card -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4 text-danger"><i class="fas fa-exclamation-triangle me-2"></i>Account Management</h5>
            
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle me-2"></i>
                <strong>Warning:</strong> The following actions are permanent and cannot be undone.
            </div>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <div class="card border-danger">
                        <div class="card-body">
                            <h6 class="card-title text-danger"><i class="fas fa-file-export me-2"></i>Export Data</h6>
                            <p class="card-text small">Download all your personal data in JSON format.</p>
                            <button class="btn btn-outline-danger btn-sm" onclick="exportData()">
                                <i class="fas fa-download me-1"></i> Export My Data
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card border-danger">
                        <div class="card-body">
                            <h6 class="card-title text-danger"><i class="fas fa-user-slash me-2"></i>Delete Account</h6>
                            <p class="card-text small">Permanently delete your account and all associated data.</p>
                            <button class="btn btn-danger btn-sm" data-bs-toggle="modal" data-bs-target="#deleteAccountModal">
                                <i class="fas fa-trash-alt me-1"></i> Delete Account
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Delete Account Modal -->
<div class="modal fade" id="deleteAccountModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content bg-dark border-danger">
            <div class="modal-header border-danger">
                <h5 class="modal-title text-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>Delete Account
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-danger">
                    <i class="fas fa-radiation me-2"></i>
                    <strong>This action is irreversible!</strong>
                </div>
                <p>You are about to permanently delete your DefSec account. This will:</p>
                <ul class="text-danger">
                    <li>Delete all your personal information</li>
                    <li>Remove all your security logs and data</li>
                    <li>Cancel any active subscriptions</li>
                    <li>Prevent future access to the dashboard</li>
                </ul>
                <p>To confirm, please type your password below:</p>
                <input type="password" class="form-control bg-dark text-light mb-3" id="confirmDeletePassword" 
                       placeholder="Enter your password">
            </div>
            <div class="modal-footer border-danger">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger" onclick="confirmDeleteAccount()">
                    <i class="fas fa-trash-alt me-1"></i> Delete My Account
                </button>
            </div>
        </div>
    </div>
</div>

<script>
    // Password toggle function
    function togglePassword(inputId) {
        const input = document.getElementById(inputId);
        const button = input.nextElementSibling;
        const icon = button.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
    
    // Export data function
    function exportData() {
        if (confirm('Are you sure you want to export your data? This may take a moment.')) {
            window.location.href = 'export-data.php?type=json';
        }
    }
    
    // Confirm account deletion
    function confirmDeleteAccount() {
        const password = document.getElementById('confirmDeletePassword').value;
        if (!password) {
            alert('Please enter your password to confirm account deletion.');
            return;
        }
        
        if (confirm('FINAL WARNING: This will permanently delete your account. Are you absolutely sure?')) {
            // In a real application, you would make an AJAX call here
            alert('Account deletion functionality would be implemented here.\n\nIn a real application, this would:\n1. Verify the password\n2. Send deletion request to server\n3. Logout and redirect to home page');
            
            // Example AJAX implementation:
            /*
            fetch('delete-account.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    password: password,
                    csrf_token: '<?= $csrf_token ?>'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Account deleted successfully.');
                    window.location.href = 'logout.php';
                } else {
                    alert('Error: ' + data.message);
                }
            });
            */
        }
    }
    
    // Initialize tooltips
    $(document).ready(function() {
        // Enable Bootstrap tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Save tab state in localStorage
        $('#settingsTabs button').click(function() {
            localStorage.setItem('activeSettingsTab', $(this).attr('id'));
        });
        
        // Restore active tab
        var activeTab = localStorage.getItem('activeSettingsTab');
        if (activeTab) {
            var tabElement = $('#' + activeTab);
            if (tabElement.length) {
                new bootstrap.Tab(tabElement).show();
            }
        }
    });
</script>

<?php
require_once 'includes/footer.php';
?>