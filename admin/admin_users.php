<?php
// admin_users.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();

// Initialize variables
$search = $_GET['search'] ?? '';
$status = $_GET['status'] ?? '';
$role = $_GET['role'] ?? '';
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// Handle actions
$action = $_GET['action'] ?? '';
$user_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

if ($action === 'toggle_status' && $user_id) {
    // Toggle user status
    try {
        $stmt = $pdo->prepare("UPDATE users SET status = IF(status = 'active', 'suspended', 'active') WHERE id = ? AND role NOT IN ('superadmin', 'admin')");
        $stmt->execute([$user_id]);
        $success_msg = "User status updated successfully.";
    } catch (PDOException $e) {
        $error_msg = "Error updating user status: " . $e->getMessage();
    }
} elseif ($action === 'delete' && $user_id) {
    // Delete user (soft delete or move to archive)
    try {
        // First, delete user's websites and related data
        $stmt = $pdo->prepare("DELETE FROM websites WHERE user_id = ?");
        $stmt->execute([$user_id]);
        
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND role NOT IN ('superadmin', 'admin')");
        $stmt->execute([$user_id]);
        $success_msg = "User deleted successfully.";
    } catch (PDOException $e) {
        $error_msg = "Error deleting user: " . $e->getMessage();
    }
} elseif ($action === 'regenerate_api' && $user_id) {
    // Regenerate API key
    try {
        $new_api_key = bin2hex(random_bytes(32));
        $stmt = $pdo->prepare("UPDATE users SET api_key = ? WHERE id = ?");
        $stmt->execute([$new_api_key, $user_id]);
        $success_msg = "API key regenerated successfully.";
    } catch (PDOException $e) {
        $error_msg = "Error regenerating API key: " . $e->getMessage();
    }
}

// Build query for users
$query = "SELECT u.*, COUNT(w.id) as website_count FROM users u LEFT JOIN websites w ON u.id = w.user_id";
$count_query = "SELECT COUNT(*) as total FROM users u";
$conditions = [];
$params = [];

if (!empty($search)) {
    $conditions[] = "(u.username LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

if (!empty($status) && in_array($status, ['active', 'suspended'])) {
    $conditions[] = "u.status = ?";
    $params[] = $status;
}

if (!empty($role) && in_array($role, ['viewer', 'analyst', 'admin'])) {
    $conditions[] = "u.role = ?";
    $params[] = $role;
}

// Exclude superadmin from regular user management
$conditions[] = "u.role != 'superadmin'";

// Apply conditions
if (!empty($conditions)) {
    $query .= " WHERE " . implode(" AND ", $conditions);
    $count_query .= " WHERE " . implode(" AND ", $conditions);
}

// Add grouping
$query .= " GROUP BY u.id ORDER BY u.created_at DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;

// Get users
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total count
$stmt = $pdo->prepare($count_query);
array_pop($params); // Remove limit and offset params
array_pop($params);
$stmt->execute($params);
$total_users = $stmt->fetch()['total'];
$total_pages = ceil($total_users / $limit);

// Get statistics
$stats = [];
try {
    $roles = ['viewer', 'analyst', 'admin'];
    foreach ($roles as $role_type) {
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE role = ? AND status = 'active'");
        $stmt->execute([$role_type]);
        $stats[$role_type] = $stmt->fetch()['count'];
    }
    
    $stmt = $pdo->query("SELECT COUNT(*) as suspended FROM users WHERE status = 'suspended'");
    $stats['suspended'] = $stmt->fetch()['suspended'];
} catch (PDOException $e) {
    error_log("Error fetching stats: " . $e->getMessage());
}
?>

<!-- HTML Structure similar to dashboard.php -->
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | User Management</title>
    <!-- Include same CSS as dashboard.php -->
     
</head>
<body>
       <?php include 'includes/admin_navbar.php'; ?>
    <?php include 'includes/admin_sidebar.php'; ?>
    <!-- Include navbar and sidebar from dashboard.php -->
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1"><i class="bi bi-people me-2"></i>User Management</h2>
                <p class="text-muted mb-0">Manage all system users and their permissions</p>
            </div>
            <div>
                <a href="admin_users.php?action=add" class="btn btn-admin btn-admin-primary">
                    <i class="bi bi-person-plus me-1"></i>Add New User
                </a>
            </div>
        </div>
        
        <!-- Stats Cards -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-primary me-3">
                            <i class="bi bi-eye"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['viewer'] ?? 0 ?></div>
                            <div class="stat-label small">Viewers</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-success me-3">
                            <i class="bi bi-graph-up"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['analyst'] ?? 0 ?></div>
                            <div class="stat-label small">Analysts</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-info me-3">
                            <i class="bi bi-shield-check"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['admin'] ?? 0 ?></div>
                            <div class="stat-label small">Admins</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-danger me-3">
                            <i class="bi bi-person-x"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['suspended'] ?? 0 ?></div>
                            <div class="stat-label small">Suspended</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Search and Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3">
                <div class="col-md-4">
                    <input type="text" class="form-control" name="search" placeholder="Search by name, email..." 
                           value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="status">
                        <option value="">All Status</option>
                        <option value="active" <?= $status === 'active' ? 'selected' : '' ?>>Active</option>
                        <option value="suspended" <?= $status === 'suspended' ? 'selected' : '' ?>>Suspended</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="role">
                        <option value="">All Roles</option>
                        <option value="viewer" <?= $role === 'viewer' ? 'selected' : '' ?>>Viewer</option>
                        <option value="analyst" <?= $role === 'analyst' ? 'selected' : '' ?>>Analyst</option>
                        <option value="admin" <?= $role === 'admin' ? 'selected' : '' ?>>Admin</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
                <div class="col-md-2">
                    <a href="admin_users.php" class="btn btn-outline-secondary w-100">
                        <i class="bi bi-arrow-clockwise me-1"></i>Reset
                    </a>
                </div>
            </form>
        </div>
        
        <!-- Users Table -->
        <div class="dashboard-card table-card">
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>User</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Websites</th>
                            <th>API Key</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td>#<?= $user['id'] ?></td>
                                <td>
                                    <div class="d-flex align-items-center">
                                        <div class="user-avatar me-2">
                                            <?= strtoupper(substr($user['username'] ?? 'U', 0, 1)) ?>
                                        </div>
                                        <div>
                                            <div class="fw-bold"><?= htmlspecialchars($user['username']) ?></div>
                                            <div class="small text-muted"><?= htmlspecialchars($user['full_name'] ?? 'N/A') ?></div>
                                        </div>
                                    </div>
                                </td>
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                <td>
                                    <span class="badge bg-<?= $user['role'] === 'admin' ? 'info' : ($user['role'] === 'analyst' ? 'success' : 'secondary') ?>">
                                        <?= ucfirst($user['role']) ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-<?= $user['status'] === 'active' ? 'success' : 'danger' ?>">
                                        <?= ucfirst($user['status']) ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-dark"><?= $user['website_count'] ?></span>
                                    <?php if ($user['website_count'] > 0): ?>
                                        <a href="admin_websites.php?user_id=<?= $user['id'] ?>" class="ms-1 text-decoration-none">
                                            <i class="bi bi-eye"></i>
                                        </a>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['api_key']): ?>
                                        <span class="badge bg-success">Active</span>
                                        <button class="btn btn-sm btn-outline-warning ms-1" 
                                                onclick="copyApiKey('<?= $user['api_key'] ?>')"
                                                data-bs-toggle="tooltip" title="Copy API Key">
                                            <i class="bi bi-copy"></i>
                                        </button>
                                    <?php else: ?>
                                        <span class="badge bg-danger">Inactive</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= date('Y-m-d', strtotime($user['created_at'])) ?></td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="admin_user_view.php?id=<?= $user['id'] ?>" 
                                           class="btn btn-outline-primary" data-bs-toggle="tooltip" title="View">
                                            <i class="bi bi-eye"></i>
                                        </a>
                                        <a href="admin_users.php?action=toggle_status&id=<?= $user['id'] ?>" 
                                           class="btn btn-outline-<?= $user['status'] === 'active' ? 'warning' : 'success' ?>"
                                           data-bs-toggle="tooltip" title="<?= $user['status'] === 'active' ? 'Suspend' : 'Activate' ?>">
                                            <i class="bi bi-<?= $user['status'] === 'active' ? 'person-x' : 'person-check' ?>"></i>
                                        </a>
                                        <a href="admin_users.php?action=regenerate_api&id=<?= $user['id'] ?>" 
                                           class="btn btn-outline-info" data-bs-toggle="tooltip" title="Regenerate API Key">
                                            <i class="bi bi-key"></i>
                                        </a>
                                        <button type="button" class="btn btn-outline-danger" 
                                                onclick="confirmDelete(<?= $user['id'] ?>)" 
                                                data-bs-toggle="tooltip" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <nav class="mt-3">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&role=<?= $role ?>">
                                    Previous
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php for ($i = 1; $i <= min($total_pages, 5); $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&role=<?= $role ?>">
                                    <?= $i ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&role=<?= $role ?>">
                                    Next
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
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
        
        function confirmDelete(userId) {
            if (confirm('Are you sure you want to delete this user? This will also delete all their websites and data.')) {
                window.location.href = 'admin_users.php?action=delete&id=' + userId;
            }
        }
        
        $(document).ready(function() {
            // Initialize tooltips
            $('[data-bs-toggle="tooltip"]').tooltip();
            
            // Initialize DataTable
            $('table').DataTable({
                pageLength: 20,
                order: [[0, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search users...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ users",
                    infoEmpty: "No users found",
                    infoFiltered: "(filtered from _MAX_ total users)"
                }
            });
        });
    </script>
</body>
</html>