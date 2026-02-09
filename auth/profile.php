<?php
// profile.php
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

// Get current user data
try {
    $stmt = $pdo->prepare("
        SELECT u.*, 
               (SELECT COUNT(*) FROM attack_logs WHERE user_id = u.id) as total_threats,
               (SELECT COUNT(*) FROM access_logs WHERE user_id = u.id) as total_requests,
               (SELECT website_url FROM websites WHERE user_id = u.id LIMIT 1) as website_url
        FROM users u 
        WHERE u.id = ?
    ");
    $stmt->execute([$userId]);
    $userData = $stmt->fetch();
    
    // Get recent activity
    $stmt = $pdo->prepare("
        SELECT * FROM access_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $stmt->execute([$userId]);
    $recentActivity = $stmt->fetchAll();
} catch (PDOException $e) {
    $error_msg = "Error loading profile data: " . $e->getMessage();
    $userData = [];
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
                <span class="badge bg-primary">
                    <i class="fas fa-shield-alt me-1"></i> 
                    <?= htmlspecialchars(ucfirst($userData['role'] ?? 'user')) ?> Account
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
                        <i class="fas fa-calendar-alt me-2"></i>
                        Member since <?= date('F j, Y', strtotime($userData['created_at'] ?? 'now')) ?>
                    </p>
                </div>
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-camera me-1"></i> Change Avatar
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="changeAvatar()">Upload Photo</a></li>
                            <li><a class="dropdown-item" href="#" onclick="generateAvatar()">Generate Avatar</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="#" onclick="removeAvatar()">Remove Avatar</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-danger bg-opacity-10 p-3">
                        <i class="fas fa-skull-crossbones fa-2x text-danger"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($userData['total_threats'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Threats Blocked</p>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-primary bg-opacity-10 p-3">
                        <i class="fas fa-shield-alt fa-2x text-primary"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0"><?= number_format($userData['total_requests'] ?? 0) ?></h4>
                    <p class="text-muted mb-0">Requests Monitored</p>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <div class="rounded-circle bg-success bg-opacity-10 p-3">
                        <i class="fas fa-clock fa-2x text-success"></i>
                    </div>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="mb-0">24/7</h4>
                    <p class="text-muted mb-0">Active Protection</p>
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
                    <h4 class="mb-0"><?= $userData['domain'] ? '1' : '0' ?></h4>
                    <p class="text-muted mb-0">Protected Websites</p>
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
                    <label class="form-label">Last Login</label>
                    <input type="text" class="form-control bg-dark text-light" 
                           value="<?= date('F j, Y H:i', strtotime($userData['last_login'] ?? 'now')) ?>" readonly>
                </div>
                
                <div class="col-12">
                    <label class="form-label">Protected Website</label>
                    <div class="input-group">
                        <input type="text" class="form-control bg-dark text-light" 
                               value="<?= htmlspecialchars($userData['domain'] ?? 'No website assigned') ?>" readonly>
                        <button class="btn btn-outline-secondary" type="button" onclick="manageWebsite()">
                            <i class="fas fa-external-link-alt"></i>
                        </button>
                    </div>
                </div>
                
                <div class="col-12 mt-4">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save me-2"></i> Update Profile
                    </button>
                    <button type="reset" class="btn btn-outline-secondary ms-2">
                        <i class="fas fa-undo me-2"></i> Reset Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Account Information Sidebar -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-info-circle me-2"></i>Account Information</h5>
            
            <div class="list-group list-group-flush">
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-user-tag me-2"></i> Account Status</span>
                        <span class="badge bg-success">Active</span>
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
                        <span><i class="fas fa-clock me-2"></i> Last Active</span>
                        <span><?= date('H:i', strtotime($userData['last_login'] ?? 'now')) ?></span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-globe me-2"></i> Timezone</span>
                        <span>UTC</span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-language me-2"></i> Language</span>
                        <span>English</span>
                    </div>
                </div>
                
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex justify-content-between">
                        <span><i class="fas fa-id-badge me-2"></i> User ID</span>
                        <code><?= htmlspecialchars($userId) ?></code>
                    </div>
                </div>
            </div>
            
            <div class="mt-4">
                <h6 class="border-bottom pb-2 mb-3">Quick Actions</h6>
                <div class="d-grid gap-2">
                    <a href="settings.php" class="btn btn-outline-primary">
                        <i class="fas fa-cog me-2"></i> Settings
                    </a>
                    <a href="security-dashboard.php" class="btn btn-outline-success">
                        <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                    </a>
                    <a href="web-security.php" class="btn btn-outline-warning">
                        <i class="fas fa-bug me-2"></i> Security Logs
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
                                    <div class="activity-icon">
                                        <i class="fas fa-user-check text-primary"></i>
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6 class="mb-1">Access from <?= htmlspecialchars($activity['ip_address'] ?? 'Unknown IP') ?></h6>
                                    <p class="text-muted mb-0 small">
                                        <?= date('M j, H:i', strtotime($activity['timestamp'] ?? 'now')) ?>
                                        <?php if ($activity['user_agent']): ?>
                                            <br><small class="text-muted"><?= htmlspecialchars(substr($activity['user_agent'], 0, 50)) ?>...</small>
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
        background-color: rgba(13, 110, 253, 0.1);
        display: flex;
        align-items: center;
        justify-content: center;
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
        } else {
            counter.classList.remove('text-danger');
        }
    });
    
    // Initialize bio counter on page load
    document.addEventListener('DOMContentLoaded', function() {
        const bio = document.getElementById('bio');
        if (bio) {
            bio.dispatchEvent(new Event('input'));
        }
    });
    
    // Avatar management functions
    function changeAvatar() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.onchange = function(e) {
            const file = e.target.files[0];
            if (file) {
                if (file.size > 5 * 1024 * 1024) {
                    alert('File size must be less than 5MB');
                    return;
                }
                
                // In a real application, you would upload the file here
                alert('Avatar upload functionality would be implemented here.\n\nSelected file: ' + file.name);
                
                // Example AJAX upload:
                /*
                const formData = new FormData();
                formData.append('avatar', file);
                formData.append('csrf_token', '<?= $csrf_token ?>');
                
                fetch('upload-avatar.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                });
                */
            }
        };
        input.click();
    }
    
    function generateAvatar() {
        // Generate a random color for the avatar
        const colors = ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6f42c1', '#20c997'];
        const randomColor = colors[Math.floor(Math.random() * colors.length)];
        
        const avatarDiv = document.querySelector('.avatar-lg .rounded-circle');
        if (avatarDiv) {
            avatarDiv.style.backgroundColor = randomColor;
            alert('Avatar color changed to ' + randomColor);
            
            // In a real app, save this preference
            /*
            fetch('update-avatar-color.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    color: randomColor,
                    csrf_token: '<?= $csrf_token ?>'
                })
            });
            */
        }
    }
    
    function removeAvatar() {
        if (confirm('Remove custom avatar and use default?')) {
            const avatarDiv = document.querySelector('.avatar-lg .rounded-circle');
            if (avatarDiv) {
                avatarDiv.style.backgroundColor = '';
            }
            
            // In a real app, remove avatar from server
            /*
            fetch('remove-avatar.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    csrf_token: '<?= $csrf_token ?>'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                }
            });
            */
        }
    }
    
    function manageWebsite() {
        alert('Website management would open in a new window or modal.\n\nCurrent website: <?= htmlspecialchars($userData['website_url'] ?? "No website") ?>');
        
        // In a real app, you might:
        // 1. Open a modal to edit website settings
        // 2. Redirect to website management page
        // 3. Show website statistics
    }
    
    // Form validation
    document.querySelector('form').addEventListener('submit', function(e) {
        const email = document.getElementById('email').value.trim();
        const bio = document.getElementById('bio').value.trim();
        
        if (!email) {
            e.preventDefault();
            alert('Email address is required.');
            return;
        }
        
        if (bio.length > 500) {
            e.preventDefault();
            alert('Bio must be 500 characters or less.');
            return;
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            e.preventDefault();
            alert('Please enter a valid email address.');
            return;
        }
    });
</script>

<?php
require_once 'includes/footer.php';
?>