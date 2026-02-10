
<?php
// admin_websites.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();
$admin_id = $admin_auth->getAdminId();

// Initialize variables
$search = $_GET['search'] ?? '';
$status = $_GET['status'] ?? '';
$user_id = $_GET['user_id'] ?? '';
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// Handle actions
$action = $_GET['action'] ?? '';
$website_id = $_GET['id'] ?? 0;
$success_msg = '';
$error_msg = '';

if ($action === 'toggle_status' && $website_id) {
    try {
        $stmt = $pdo->prepare("UPDATE websites SET status = IF(status = 'active', 'paused', 'active') WHERE id = ?");
        $stmt->execute([$website_id]);
        $success_msg = "Website status updated successfully.";
        
        // Log action
        logAdminAction($pdo, $admin_id, 'website_toggle_status', "Website ID: $website_id");
    } catch (PDOException $e) {
        $error_msg = "Error updating website status: " . $e->getMessage();
    }
} elseif ($action === 'delete' && $website_id) {
    try {
        // Delete related data first
        $tables = ['access_logs', 'attack_logs', 'blocked_ips', 'allowed_countries', 'logs'];
        foreach ($tables as $table) {
            try {
                $stmt = $pdo->prepare("DELETE FROM $table WHERE website_id = ?");
                $stmt->execute([$website_id]);
            } catch (PDOException $e) {
                // Table might not exist, continue
            }
        }
        
        // Delete website
        $stmt = $pdo->prepare("DELETE FROM websites WHERE id = ?");
        $stmt->execute([$website_id]);
        $success_msg = "Website deleted successfully.";
        
        // Log action
        logAdminAction($pdo, $admin_id, 'website_delete', "Website ID: $website_id");
    } catch (PDOException $e) {
        $error_msg = "Error deleting website: " . $e->getMessage();
    }
}

// Build query for websites
$query = "
    SELECT 
        w.*,
        u.username,
        u.email,
        u.full_name,
        COUNT(DISTINCT al.id) as access_count,
        COUNT(DISTINCT atl.id) as attack_count,
        COUNT(DISTINCT bi.id) as blocked_count
    FROM websites w
    LEFT JOIN users u ON w.user_id = u.id
    LEFT JOIN access_logs al ON w.id = al.website_id
    LEFT JOIN attack_logs atl ON w.id = atl.website_id
    LEFT JOIN blocked_ips bi ON w.id = bi.website_id AND bi.expiry_time > CURTIME()
";

$count_query = "SELECT COUNT(*) as total FROM websites w";
$conditions = [];
$params = [];

if (!empty($search)) {
    $conditions[] = "(w.domain LIKE ? OR w.site_name LIKE ? OR u.username LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

if (!empty($status) && in_array($status, ['active', 'paused'])) {
    $conditions[] = "w.status = ?";
    $params[] = $status;
}

if (!empty($user_id) && is_numeric($user_id)) {
    $conditions[] = "w.user_id = ?";
    $params[] = $user_id;
}

// Apply conditions
if (!empty($conditions)) {
    $query .= " WHERE " . implode(" AND ", $conditions);
    $count_query .= " WHERE " . implode(" AND ", $conditions);
}

// Add grouping and ordering
$query .= " GROUP BY w.id ORDER BY w.created_at DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;

// Get websites
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$websites = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total count
$stmt = $pdo->prepare($count_query);
array_pop($params); // Remove limit and offset params
array_pop($params);
$stmt->execute($params);
$total_websites = $stmt->fetch()['total'];
$total_pages = ceil($total_websites / $limit);

// Get statistics
$stats = [];
try {
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM websites WHERE status = 'active'");
    $stats['active'] = $stmt->fetch()['count'];
    
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM websites WHERE status = 'paused'");
    $stats['paused'] = $stmt->fetch()['count'];
    
    $stmt = $pdo->query("SELECT COUNT(DISTINCT user_id) as total FROM websites");
    $stats['users_with_websites'] = $stmt->fetch()['count'];
    
    // Get recent attacks
    $stmt = $pdo->query("
        SELECT COUNT(*) as attacks_today 
        FROM attack_logs 
        WHERE DATE(timestamp) = CURDATE()
    ");
    $stats['attacks_today'] = $stmt->fetch()['count'];
} catch (PDOException $e) {
    error_log("Error fetching stats: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Website Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
    <style>
        /* Use the same styles as admin_dashboard.php */
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
    </style>
</head>
<body>
    <!-- Include Navbar and Sidebar from admin_dashboard.php -->
    <?php include 'includes/admin_navbar.php'; ?>
    <?php include 'includes/admin_sidebar.php'; ?>
    
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1"><i class="bi bi-globe me-2"></i>Website Management</h2>
                <p class="text-muted mb-0">Monitor and manage all protected websites</p>
            </div>
            <div>
                <a href="admin_websites.php?action=add" class="btn btn-admin btn-admin-primary">
                    <i class="bi bi-plus-circle me-1"></i>Add Website
                </a>
            </div>
        </div>
        
        <!-- Alerts -->
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
        
        <!-- Stats Cards -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-success me-3">
                            <i class="bi bi-check-circle"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['active'] ?? 0 ?></div>
                            <div class="stat-label small">Active Websites</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-warning me-3">
                            <i class="bi bi-pause-circle"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['paused'] ?? 0 ?></div>
                            <div class="stat-label small">Paused Websites</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-primary me-3">
                            <i class="bi bi-people"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['users_with_websites'] ?? 0 ?></div>
                            <div class="stat-label small">Active Users</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-danger me-3">
                            <i class="bi bi-shield-exclamation"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= $stats['attacks_today'] ?? 0 ?></div>
                            <div class="stat-label small">Attacks Today</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Search and Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3">
                <div class="col-md-4">
                    <input type="text" class="form-control" name="search" placeholder="Search by domain, name, or username..." 
                           value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="status">
                        <option value="">All Status</option>
                        <option value="active" <?= $status === 'active' ? 'selected' : '' ?>>Active</option>
                        <option value="paused" <?= $status === 'paused' ? 'selected' : '' ?>>Paused</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="user_id" placeholder="User ID" 
                           value="<?= htmlspecialchars($user_id) ?>">
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
                <div class="col-md-2">
                    <a href="admin_websites.php" class="btn btn-outline-secondary w-100">
                        <i class="bi bi-arrow-clockwise me-1"></i>Reset
                    </a>
                </div>
            </form>
        </div>
        
        <!-- Websites Table -->
        <div class="dashboard-card table-card">
            <div class="table-responsive">
                <table class="table table-dark table-hover" id="websitesTable">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Website</th>
                            <th>Owner</th>
                            <th>Status</th>
                            <th>Statistics</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($websites as $website): ?>
                            <tr>
                                <td>#<?= $website['id'] ?></td>
                                <td>
                                    <div>
                                        <div class="fw-bold"><?= htmlspecialchars($website['site_name']) ?></div>
                                        <div class="small text-muted">
                                            <code><?= htmlspecialchars($website['domain']) ?></code>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <div>
                                        <div><?= htmlspecialchars($website['username']) ?></div>
                                        <div class="small text-muted"><?= htmlspecialchars($website['email']) ?></div>
                                    </div>
                                </td>
                                <td>
                                    <span class="badge bg-<?= getStatusBadge($website['status']) ?>">
                                        <?= ucfirst($website['status']) ?>
                                    </span>
                                </td>
                                <td>
                                    <div class="d-flex gap-2">
                                        <span class="badge bg-info" data-bs-toggle="tooltip" title="Access Logs">
                                            <i class="bi bi-eye me-1"></i><?= $website['access_count'] ?>
                                        </span>
                                        <span class="badge bg-danger" data-bs-toggle="tooltip" title="Attack Logs">
                                            <i class="bi bi-shield-exclamation me-1"></i><?= $website['attack_count'] ?>
                                        </span>
                                        <span class="badge bg-warning" data-bs-toggle="tooltip" title="Blocked IPs">
                                            <i class="bi bi-ban me-1"></i><?= $website['blocked_count'] ?>
                                        </span>
                                    </div>
                                </td>
                                <td><?= formatDate($website['created_at'], 'Y-m-d') ?></td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="admin_website_view.php?id=<?= $website['id'] ?>" 
                                           class="btn btn-outline-primary" data-bs-toggle="tooltip" title="View Details">
                                            <i class="bi bi-eye"></i>
                                        </a>
                                        <a href="admin_websites.php?action=toggle_status&id=<?= $website['id'] ?>" 
                                           class="btn btn-outline-<?= $website['status'] === 'active' ? 'warning' : 'success' ?>"
                                           data-bs-toggle="tooltip" title="<?= $website['status'] === 'active' ? 'Pause' : 'Activate' ?>">
                                            <i class="bi bi-<?= $website['status'] === 'active' ? 'pause' : 'play' ?>"></i>
                                        </a>
                                        <a href="admin_website_edit.php?id=<?= $website['id'] ?>" 
                                           class="btn btn-outline-info" data-bs-toggle="tooltip" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <button type="button" class="btn btn-outline-danger" 
                                                onclick="confirmDelete(<?= $website['id'] ?>, '<?= htmlspecialchars(addslashes($website['site_name'])) ?>')" 
                                                data-bs-toggle="tooltip" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($websites)): ?>
                            <tr>
                                <td colspan="7" class="text-center py-4 text-muted">
                                    <i class="bi bi-globe mb-2" style="font-size: 2rem;"></i>
                                    <p class="mb-0">No websites found</p>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <nav class="mt-3">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&user_id=<?= $user_id ?>">
                                    Previous
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&user_id=<?= $user_id ?>">
                                    <?= $i ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>&status=<?= $status ?>&user_id=<?= $user_id ?>">
                                    Next
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
        </div>
    </main>
    
    <!-- Modal for Add/Edit Website -->
    <div class="modal fade" id="websiteModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">Add New Website</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <!-- Form will be loaded via AJAX -->
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    
    <script>
        function confirmDelete(websiteId, websiteName) {
            if (confirm(`Are you sure you want to delete "${websiteName}"?\n\nThis will also delete all related logs and data.`)) {
                window.location.href = 'admin_websites.php?action=delete&id=' + websiteId;
            }
        }
        
        function loadWebsiteForm(websiteId = null) {
            const modal = new bootstrap.Modal(document.getElementById('websiteModal'));
            const modalBody = document.querySelector('#websiteModal .modal-body');
            
            let url = 'ajax/website_form.php';
            if (websiteId) {
                url += '?id=' + websiteId;
                document.querySelector('#websiteModal .modal-title').textContent = 'Edit Website';
            } else {
                document.querySelector('#websiteModal .modal-title').textContent = 'Add New Website';
            }
            
            // Load form via AJAX
            fetch(url)
                .then(response => response.text())
                .then(html => {
                    modalBody.innerHTML = html;
                    modal.show();
                })
                .catch(error => {
                    console.error('Error loading form:', error);
                    modalBody.innerHTML = '<div class="alert alert-danger">Error loading form. Please try again.</div>';
                    modal.show();
                });
        }
        
        $(document).ready(function() {
            // Initialize DataTable
            $('#websitesTable').DataTable({
                pageLength: 20,
                order: [[0, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search websites...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ websites",
                    infoEmpty: "No websites found",
                    infoFiltered: "(filtered from _MAX_ total websites)"
                }
            });
            
            // Initialize tooltips
            $('[data-bs-toggle="tooltip"]').tooltip();
        });
    </script>
</body>
</html>