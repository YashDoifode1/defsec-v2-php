<?php
// admin_user_view.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

$user_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

// Get user details
$user = null;
$websites = [];
$stats = [];

if ($user_id) {
    try {
        // Get user info
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        
        if (!$user) {
            header("Location: admin_users.php");
            exit();
        }
        
        // Get user's websites
        $stmt = $pdo->prepare("SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC");
        $stmt->execute([$user_id]);
        $websites = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get user statistics
        $stmt = $pdo->prepare("SELECT COUNT(*) as total_logs FROM logs WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $stats['total_logs'] = $stmt->fetch()['total_logs'];
        
        $stmt = $pdo->prepare("SELECT COUNT(*) as total_attacks FROM attack_logs WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $stats['total_attacks'] = $stmt->fetch()['total_attacks'];
        
        $stmt = $pdo->prepare("SELECT COUNT(*) as blocked_ips FROM blocked_ips WHERE user_id = ? AND expiry_time > CURTIME()");
        $stmt->execute([$user_id]);
        $stats['blocked_ips'] = $stmt->fetch()['blocked_ips'];
        
        // Get last login
        $stmt = $pdo->prepare("SELECT MAX(created_at) as last_login FROM login_logs WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $stats['last_login'] = $stmt->fetch()['last_login'];
        
        // Get recent activities
        $stmt = $pdo->prepare("
            SELECT attack_type, severity, timestamp, ip_address 
            FROM attack_logs 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 5
        ");
        $stmt->execute([$user_id]);
        $recent_activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        $error_msg = "Error fetching user data: " . $e->getMessage();
    }
} else {
    header("Location: admin_users.php");
    exit();
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // Validate CSRF token (implement your own validation)
    if (true) { // Replace with actual CSRF validation
        $email = trim($_POST['email'] ?? '');
        $full_name = trim($_POST['full_name'] ?? '');
        $role = $_POST['role'] ?? 'viewer';
        $status = $_POST['status'] ?? 'active';
        
        if (empty($email)) {
            $error_msg = "Email is required.";
        } else {
            try {
                // Check if email exists for another user
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$email, $user_id]);
                if ($stmt->fetch()) {
                    $error_msg = "Email already exists for another user.";
                } else {
                    $stmt = $pdo->prepare("
                        UPDATE users 
                        SET email = ?, full_name = ?, role = ?, status = ?, updated_at = NOW()
                        WHERE id = ?
                    ");
                    $stmt->execute([$email, $full_name, $role, $status, $user_id]);
                    $success_msg = "User updated successfully.";
                    
                    // Refresh user data
                    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                    $stmt->execute([$user_id]);
                    $user = $stmt->fetch();
                }
            } catch (PDOException $e) {
                $error_msg = "Error updating user: " . $e->getMessage();
            }
        }
    } else {
        $error_msg = "Invalid security token.";
    }
}

// Generate CSRF token (implement your own CSRF token generation)
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | User Details</title>
    <!-- Include same CSS as dashboard.php -->
</head>
<body>
    <!-- Include navbar and sidebar -->
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1">
                    <i class="bi bi-person me-2"></i>
                    <?= htmlspecialchars($user['username']) ?> 
                    <small class="text-muted">(ID: #<?= $user['id'] ?>)</small>
                </h2>
                <p class="text-muted mb-0">User profile and management</p>
            </div>
            <div>
                <a href="admin_users.php" class="btn btn-outline-secondary">
                    <i class="bi bi-arrow-left me-1"></i>Back to Users
                </a>
            </div>
        </div>
        
        <?php if ($success_msg): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle-fill me-2"></i>
                <?= htmlspecialchars($success_msg) ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <?php if ($error_msg): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <?= htmlspecialchars($error_msg) ?>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        
        <div class="row g-4">
            <!-- User Info Card -->
            <div class="col-lg-4">
                <div class="dashboard-card">
                    <div class="text-center mb-4">
                        <div class="user-avatar mx-auto" style="width: 80px; height: 80px; font-size: 2rem;">
                            <?= strtoupper(substr($user['username'] ?? 'U', 0, 1)) ?>
                        </div>
                        <h4 class="mt-3 mb-0"><?= htmlspecialchars($user['full_name'] ?: $user['username']) ?></h4>
                        <p class="text-muted">@<?= htmlspecialchars($user['username']) ?></p>
                        
                        <div class="d-flex justify-content-center gap-2 mb-3">
                            <span class="badge bg-<?= $user['role'] === 'admin' ? 'info' : ($user['role'] === 'analyst' ? 'success' : 'secondary') ?>">
                                <?= ucfirst($user['role']) ?>
                            </span>
                            <span class="badge bg-<?= $user['status'] === 'active' ? 'success' : 'danger' ?>">
                                <?= ucfirst($user['status']) ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="list-group list-group-flush">
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-envelope me-2"></i>Email</span>
                            <span><?= htmlspecialchars($user['email']) ?></span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-calendar me-2"></i>Member Since</span>
                            <span><?= date('F j, Y', strtotime($user['created_at'])) ?></span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-clock-history me-2"></i>Last Login</span>
                            <span><?= $stats['last_login'] ? date('M j, H:i', strtotime($stats['last_login'])) : 'Never' ?></span>
                        </div>
                        <div class="list-group-item d-flex justify-content-between bg-transparent border-secondary">
                            <span><i class="bi bi-key me-2"></i>API Key</span>
                            <span>
                                <?php if ($user['api_key']): ?>
                                    <span class="badge bg-success">Active</span>
                                    <button class="btn btn-sm btn-outline-warning ms-1" 
                                            onclick="copyApiKey('<?= $user['api_key'] ?>')">
                                        <i class="bi bi-copy"></i>
                                    </button>
                                <?php else: ?>
                                    <span class="badge bg-danger">Inactive</span>
                                <?php endif; ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <a href="admin_users.php?action=regenerate_api&id=<?= $user['id'] ?>" 
                           class="btn btn-outline-info w-100 mb-2">
                            <i class="bi bi-key me-1"></i>Regenerate API Key
                        </a>
                        <a href="admin_users.php?action=toggle_status&id=<?= $user['id'] ?>" 
                           class="btn btn-outline-<?= $user['status'] === 'active' ? 'warning' : 'success' ?> w-100">
                            <i class="bi bi-<?= $user['status'] === 'active' ? 'person-x' : 'person-check' ?> me-1"></i>
                            <?= $user['status'] === 'active' ? 'Suspend User' : 'Activate User' ?>
                        </a>
                    </div>
                </div>
                
                <!-- Quick Stats -->
                <div class="dashboard-card mt-4">
                    <h6 class="mb-3"><i class="bi bi-bar-chart me-2"></i>User Statistics</h6>
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <div class="h4 mb-1 text-primary"><?= count($websites) ?></div>
                            <div class="small text-muted">Websites</div>
                        </div>
                        <div class="col-6 mb-3">
                            <div class="h4 mb-1 text-info"><?= number_format($stats['total_logs'] ?? 0) ?></div>
                            <div class="small text-muted">Total Logs</div>
                        </div>
                        <div class="col-6">
                            <div class="h4 mb-1 text-warning"><?= number_format($stats['total_attacks'] ?? 0) ?></div>
                            <div class="small text-muted">Attack Logs</div>
                        </div>
                        <div class="col-6">
                            <div class="h4 mb-1 text-danger"><?= number_format($stats['blocked_ips'] ?? 0) ?></div>
                            <div class="small text-muted">Blocked IPs</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Edit Form & Websites -->
            <div class="col-lg-8">
                <!-- Edit User Form -->
                <div class="dashboard-card mb-4">
                    <h5 class="mb-3"><i class="bi bi-pencil-square me-2"></i>Edit User Information</h5>
                    
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" 
                                       value="<?= htmlspecialchars($user['username']) ?>" readonly>
                                <div class="form-text">Username cannot be changed</div>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="email" class="form-label">Email Address *</label>
                                <input type="email" class="form-control" id="email" name="email" 
                                       value="<?= htmlspecialchars($user['email']) ?>" required>
                            </div>
                            
                            <div class="col-md-6">
                                <label for="full_name" class="form-label">Full Name</label>
                                <input type="text" class="form-control" id="full_name" name="full_name"
                                       value="<?= htmlspecialchars($user['full_name'] ?? '') ?>">
                            </div>
                            
                            <div class="col-md-3">
                                <label for="role" class="form-label">Role</label>
                                <select class="form-select" id="role" name="role">
                                    <option value="viewer" <?= $user['role'] === 'viewer' ? 'selected' : '' ?>>Viewer</option>
                                    <option value="analyst" <?= $user['role'] === 'analyst' ? 'selected' : '' ?>>Analyst</option>
                                    <?php if ($admin_auth->isSuperAdmin()): ?>
                                        <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                    <?php endif; ?>
                                </select>
                            </div>
                            
                            <div class="col-md-3">
                                <label for="status" class="form-label">Status</label>
                                <select class="form-select" id="status" name="status">
                                    <option value="active" <?= $user['status'] === 'active' ? 'selected' : '' ?>>Active</option>
                                    <option value="suspended" <?= $user['status'] === 'suspended' ? 'selected' : '' ?>>Suspended</option>
                                </select>
                            </div>
                            
                            <div class="col-12 mt-3">
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save me-2"></i>Save Changes
                                </button>
                                <button type="reset" class="btn btn-outline-secondary">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Reset
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
                
                <!-- User's Websites -->
                <div class="dashboard-card">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="mb-0"><i class="bi bi-globe me-2"></i>User's Websites</h5>
                        <a href="admin_websites.php?user_id=<?= $user['id'] ?>" class="btn btn-sm btn-outline-primary">
                            View All
                        </a>
                    </div>
                    
                    <?php if (!empty($websites)): ?>
                        <div class="table-responsive">
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Name</th>
                                        <th>Status</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($websites as $website): ?>
                                        <tr>
                                            <td>
                                                <code><?= htmlspecialchars($website['domain']) ?></code>
                                            </td>
                                            <td><?= htmlspecialchars($website['site_name']) ?></td>
                                            <td>
                                                <span class="badge bg-<?= $website['status'] === 'active' ? 'success' : 'warning' ?>">
                                                    <?= ucfirst($website['status']) ?>
                                                </span>
                                            </td>
                                            <td><?= date('Y-m-d', strtotime($website['created_at'])) ?></td>
                                            <td>
                                                <a href="admin_website_view.php?id=<?= $website['id'] ?>" 
                                                   class="btn btn-sm btn-outline-info">
                                                    <i class="bi bi-eye"></i>
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-4 text-muted">
                            <i class="bi bi-globe mb-3" style="font-size: 2rem;"></i>
                            <p class="mb-0">No websites registered</p>
                        </div>
                    <?php endif; ?>
                </div>
                
                <!-- Recent Activities -->
                <div class="dashboard-card mt-4">
                    <h5 class="mb-3"><i class="bi bi-activity me-2"></i>Recent Security Activities</h5>
                    
                    <?php if (!empty($recent_activities)): ?>
                        <div class="list-group">
                            <?php foreach ($recent_activities as $activity): ?>
                                <div class="list-group-item d-flex justify-content-between align-items-center bg-transparent border-secondary">
                                    <div>
                                        <div class="fw-bold"><?= htmlspecialchars($activity['attack_type']) ?></div>
                                        <div class="small text-muted">
                                            <?= date('M j, H:i', strtotime($activity['timestamp'])) ?>
                                            • IP: <?= htmlspecialchars($activity['ip_address']) ?>
                                        </div>
                                    </div>
                                    <span class="badge bg-<?= 
                                        $activity['severity'] === 'Critical' ? 'danger' : 
                                        ($activity['severity'] === 'High' ? 'warning' : 
                                        ($activity['severity'] === 'Medium' ? 'info' : 'secondary')) 
                                    ?>">
                                        <?= $activity['severity'] ?>
                                    </span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-3 text-muted">
                            <i class="bi bi-shield-check mb-2" style="font-size: 2rem;"></i>
                            <p class="mb-0">No recent security activities</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        function copyApiKey(apiKey) {
            navigator.clipboard.writeText(apiKey).then(function() {
                alert('API key copied to clipboard!');
            }, function(err) {
                console.error('Could not copy text: ', err);
            });
        }
    </script>
</body>
</html>