<?php
// admin_blocked.php
require_once 'includes/config.php';
require_once 'includes/admin_auth.php';
require_once 'includes/functions.php';

// Check admin authentication
// $admin_auth->requireAdminLogin();
$admin_id = $admin_auth->getAdminId();

// Initialize variables
$search = $_GET['search'] ?? '';
$website_id = $_GET['website_id'] ?? '';
$status = $_GET['status'] ?? 'active'; // active, expired, all
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 25;
$offset = ($page - 1) * $limit;

// Handle actions
$action = $_GET['action'] ?? '';
$block_id = $_GET['id'] ?? 0;
$ip = $_GET['ip'] ?? '';
$success_msg = '';
$error_msg = '';

if ($action === 'unblock' && $block_id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM blocked_ips WHERE id = ?");
        $stmt->execute([$block_id]);
        $success_msg = "IP address unblocked successfully.";
        
        // Log admin action
        logAdminAction($pdo, $admin_id, 'unblock_ip', "Block ID: $block_id");
    } catch (PDOException $e) {
        $error_msg = "Error unblocking IP: " . $e->getMessage();
    }
} elseif ($action === 'block' && $ip) {
    $website_id = $_POST['website_id'] ?? 0;
    $reason = $_POST['reason'] ?? 'Manual block by admin';
    $duration = $_POST['duration'] ?? 24; // hours
    
    if ($website_id) {
        try {
            // Check if IP is already blocked
            $stmt = $pdo->prepare("
                SELECT id FROM blocked_ips 
                WHERE ip = ? AND website_id = ? AND expiry_time > CURTIME()
            ");
            $stmt->execute([$ip, $website_id]);
            
            if ($stmt->fetch()) {
                $error_msg = "This IP is already blocked for this website.";
            } else {
                // Block the IP
                $stmt = $pdo->prepare("
                    INSERT INTO blocked_ips (user_id, ip, website_id, reason, created_at, expiry_time)
                    VALUES (?, ?, ?, ?, NOW(), DATE_ADD(CURTIME(), INTERVAL ? HOUR))
                ");
                $stmt->execute([$admin_id, $ip, $website_id, $reason, $duration]);
                $success_msg = "IP address blocked successfully for $duration hours.";
                
                // Log admin action
                logAdminAction($pdo, $admin_id, 'block_ip_manual', 
                             "IP: $ip, Website ID: $website_id, Duration: {$duration}h");
            }
        } catch (PDOException $e) {
            $error_msg = "Error blocking IP: " . $e->getMessage();
        }
    } else {
        $error_msg = "Please select a website.";
    }
} elseif ($action === 'extend' && $block_id) {
    $duration = $_POST['duration'] ?? 24;
    
    try {
        $stmt = $pdo->prepare("
            UPDATE blocked_ips 
            SET expiry_time = DATE_ADD(expiry_time, INTERVAL ? HOUR)
            WHERE id = ?
        ");
        $stmt->execute([$duration, $block_id]);
        $success_msg = "Block extended by $duration hours.";
        
        // Log admin action
        logAdminAction($pdo, $admin_id, 'extend_block', "Block ID: $block_id, Duration: {$duration}h");
    } catch (PDOException $e) {
        $error_msg = "Error extending block: " . $e->getMessage();
    }
}

// Build query for blocked IPs
$query = "
    SELECT 
        bi.*,
        w.domain,
        w.site_name,
        u.username,
        u.email as user_email,
        CASE 
            WHEN bi.expiry_time > CURTIME() THEN 'active'
            ELSE 'expired'
        END as block_status,
        TIMESTAMPDIFF(HOUR, NOW(), CONCAT(CURDATE(), ' ', bi.expiry_time)) as hours_remaining
    FROM blocked_ips bi
    JOIN websites w ON bi.website_id = w.id
    JOIN users u ON bi.user_id = u.id
";

$count_query = "SELECT COUNT(*) as total FROM blocked_ips bi";
$conditions = [];
$params = [];

if (!empty($search)) {
    $conditions[] = "(bi.ip LIKE ? OR bi.reason LIKE ? OR w.domain LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

if (!empty($website_id) && is_numeric($website_id)) {
    $conditions[] = "bi.website_id = ?";
    $params[] = $website_id;
}

if ($status === 'active') {
    $conditions[] = "bi.expiry_time > CURTIME()";
} elseif ($status === 'expired') {
    $conditions[] = "bi.expiry_time <= CURTIME()";
}

// Apply conditions
if (!empty($conditions)) {
    $query .= " WHERE " . implode(" AND ", $conditions);
    $count_query .= " WHERE " . implode(" AND ", $conditions);
}

// Add ordering
$query .= " ORDER BY bi.created_at DESC LIMIT ? OFFSET ?";
$params[] = $limit;
$params[] = $offset;

// Get blocked IPs
$stmt = $pdo->prepare($query);
$stmt->execute($params);
$blocked_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total count
$stmt = $pdo->prepare($count_query);
array_pop($params); // Remove limit and offset params
array_pop($params);
$total_blocks = $stmt->rowCount() ? $stmt->fetch()['total'] : 0;
$total_pages = ceil($total_blocks / $limit);

// Get statistics
$stats = [];
try {
    // Active blocks
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM blocked_ips WHERE expiry_time > CURTIME()");
    $stats['active_blocks'] = $stmt->fetch()['count'];
    
    // Expired blocks
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM blocked_ips WHERE expiry_time <= CURTIME()");
    $stats['expired_blocks'] = $stmt->fetch()['count'];
    
    // Blocks today
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM blocked_ips WHERE DATE(created_at) = CURDATE()");
    $stats['today_blocks'] = $stmt->fetch()['count'];
    
    // Top blocked IPs
    $stmt = $pdo->query("
        SELECT ip, COUNT(*) as block_count
        FROM blocked_ips
        WHERE expiry_time > CURTIME()
        GROUP BY ip
        ORDER BY block_count DESC
        LIMIT 5
    ");
    $stats['top_blocked_ips'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Common reasons
    $stmt = $pdo->query("
        SELECT reason, COUNT(*) as count
        FROM blocked_ips
        WHERE expiry_time > CURTIME()
        GROUP BY reason
        ORDER BY count DESC
        LIMIT 5
    ");
    $stats['common_reasons'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    error_log("Error fetching block stats: " . $e->getMessage());
}

// Get websites for dropdown
$websites = [];
try {
    $stmt = $pdo->query("SELECT id, domain, site_name FROM websites WHERE status = 'active' ORDER BY domain");
    $websites = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Error fetching websites: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Blocked IPs</title>
    <!-- Include same CSS as admin_dashboard.php -->
</head>
<body>
    <!-- Include Navbar and Sidebar -->
    <?php include 'includes/admin_navbar.php'; ?>
    <?php include 'includes/admin_sidebar.php'; ?>
    
    <main class="col-lg-10 col-md-9 ms-sm-auto px-md-4 py-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="h3 mb-1"><i class="bi bi-ban me-2"></i>Blocked IPs</h2>
                <p class="text-muted mb-0">Manage blocked IP addresses and their expiration</p>
            </div>
            <div>
                <button type="button" class="btn btn-admin btn-admin-primary" data-bs-toggle="modal" data-bs-target="#blockIPModal">
                    <i class="bi bi-plus-circle me-1"></i>Block IP
                </button>
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
                        <div class="stat-icon text-danger me-3">
                            <i class="bi bi-ban"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['active_blocks'] ?? 0) ?></div>
                            <div class="stat-label small">Active Blocks</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-secondary me-3">
                            <i class="bi bi-clock-history"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['expired_blocks'] ?? 0) ?></div>
                            <div class="stat-label small">Expired Blocks</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-warning me-3">
                            <i class="bi bi-calendar-day"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format($stats['today_blocks'] ?? 0) ?></div>
                            <div class="stat-label small">Today</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="dashboard-card stat-card p-3">
                    <div class="d-flex align-items-center">
                        <div class="stat-icon text-info me-3">
                            <i class="bi bi-globe"></i>
                        </div>
                        <div>
                            <div class="stat-value h4 mb-0"><?= number_format(count($stats['top_blocked_ips'] ?? [])) ?></div>
                            <div class="stat-label small">Unique IPs</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="dashboard-card mb-4">
            <form method="GET" class="row g-3">
                <div class="col-md-4">
                    <input type="text" class="form-control" name="search" placeholder="Search IP, reason, domain..." 
                           value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-2">
                    <input type="number" class="form-control" name="website_id" placeholder="Website ID" 
                           value="<?= htmlspecialchars($website_id) ?>">
                </div>
                <div class="col-md-2">
                    <select class="form-select" name="status">
                        <option value="active" <?= $status === 'active' ? 'selected' : '' ?>>Active Only</option>
                        <option value="expired" <?= $status === 'expired' ? 'selected' : '' ?>>Expired Only</option>
                        <option value="all" <?= $status === 'all' ? 'selected' : '' ?>>All</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
                <div class="col-md-2">
                    <a href="admin_blocked.php" class="btn btn-outline-secondary w-100">
                        <i class="bi bi-arrow-clockwise me-1"></i>Reset
                    </a>
                </div>
            </form>
        </div>
        
        <!-- Blocked IPs Table -->
        <div class="dashboard-card table-card">
            <div class="table-responsive">
                <table class="table table-dark table-hover" id="blocksTable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Website</th>
                            <th>Blocked By</th>
                            <th>Reason</th>
                            <th>Created</th>
                            <th>Expires</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocked_ips as $block): ?>
                            <tr class="<?= $block['block_status'] === 'active' ? 'table-danger' : 'table-secondary' ?>">
                                <td>
                                    <code><?= htmlspecialchars($block['ip']) ?></code>
                                    <button type="button" class="btn btn-sm btn-outline-info ms-1" 
                                            onclick="showIPDetails('<?= htmlspecialchars($block['ip']) ?>')">
                                        <i class="bi bi-info-circle"></i>
                                    </button>
                                </td>
                                <td>
                                    <div class="small"><?= htmlspecialchars($block['site_name']) ?></div>
                                    <div class="x-small text-muted"><?= htmlspecialchars($block['domain']) ?></div>
                                </td>
                                <td>
                                    <div><?= htmlspecialchars($block['username']) ?></div>
                                    <div class="x-small text-muted">ID: <?= $block['user_id'] ?></div>
                                </td>
                                <td>
                                    <span class="badge bg-dark" data-bs-toggle="tooltip" title="<?= htmlspecialchars($block['reason']) ?>">
                                        <?= htmlspecialchars(truncateText($block['reason'], 30)) ?>
                                    </span>
                                </td>
                                <td class="text-nowrap">
                                    <?= formatDate($block['created_at'], 'Y-m-d H:i') ?>
                                </td>
                                <td class="text-nowrap">
                                    <?php if ($block['block_status'] === 'active'): ?>
                                        <div class="text-danger">
                                            <?= date('H:i', strtotime($block['expiry_time'])) ?>
                                            <br>
                                            <small class="text-muted">
                                                (<?= abs($block['hours_remaining']) ?>h remaining)
                                            </small>
                                        </div>
                                    <?php else: ?>
                                        <div class="text-muted">
                                            <?= date('Y-m-d H:i', strtotime($block['expiry_time'])) ?>
                                            <br>
                                            <small>Expired</small>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($block['block_status'] === 'active'): ?>
                                        <span class="badge bg-danger">Active</span>
                                    <?php else: ?>
                                        <span class="badge bg-secondary">Expired</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <?php if ($block['block_status'] === 'active'): ?>
                                            <button type="button" class="btn btn-outline-warning" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#extendBlockModal<?= $block['id'] ?>">
                                                <i class="bi bi-clock"></i>
                                            </button>
                                            <a href="admin_blocked.php?action=unblock&id=<?= $block['id'] ?>" 
                                               class="btn btn-outline-success"
                                               onclick="return confirm('Unblock this IP address?')">
                                                <i class="bi bi-unlock"></i>
                                            </a>
                                        <?php endif; ?>
                                        <a href="admin_blocked.php?action=delete&id=<?= $block['id'] ?>" 
                                           class="btn btn-outline-secondary"
                                           onclick="return confirm('Delete this block record?')">
                                            <i class="bi bi-trash"></i>
                                        </a>
                                    </div>
                                    
                                    <!-- Extend Block Modal -->
                                    <div class="modal fade" id="extendBlockModal<?= $block['id'] ?>" tabindex="-1" aria-hidden="true">
                                        <div class="modal-dialog">
                                            <div class="modal-content bg-dark">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Extend Block Duration</h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                </div>
                                                <form method="POST" action="?action=extend&id=<?= $block['id'] ?>">
                                                    <div class="modal-body">
                                                        <div class="mb-3">
                                                            <label class="form-label">Extend by (hours)</label>
                                                            <select class="form-select" name="duration">
                                                                <option value="1">1 hour</option>
                                                                <option value="6">6 hours</option>
                                                                <option value="12">12 hours</option>
                                                                <option value="24" selected>24 hours</option>
                                                                <option value="72">3 days</option>
                                                                <option value="168">7 days</option>
                                                                <option value="720">30 days</option>
                                                            </select>
                                                        </div>
                                                        <div class="alert alert-info">
                                                            <i class="bi bi-info-circle me-2"></i>
                                                            Current expiry: <?= date('Y-m-d H:i', strtotime($block['expiry_time'])) ?>
                                                        </div>
                                                    </div>
                                                    <div class="modal-footer">
                                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                        <button type="submit" class="btn btn-warning">Extend Block</button>
                                                    </div>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($blocked_ips)): ?>
                            <tr>
                                <td colspan="8" class="text-center py-4 text-muted">
                                    <i class="bi bi-shield-check mb-2" style="font-size: 2rem;"></i>
                                    <p class="mb-0">No blocked IPs found</p>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <!-- Pagination -->
<?php if ($total_pages > 1): ?>

<?php
// Preserve existing filters but remove page parameter
$queryParams = $_GET;
unset($queryParams['page']);
$queryString = http_build_query($queryParams);
$queryString = $queryString ? '&' . $queryString : '';
?>

<nav class="mt-3">
    <ul class="pagination justify-content-center">

        <!-- Previous -->
        <?php if ($page > 1): ?>
            <li class="page-item">
                <a class="page-link" href="?page=<?= $page - 1 ?><?= $queryString ?>">
                    Previous
                </a>
            </li>
        <?php endif; ?>

        <!-- Page Numbers -->
        <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
            <li class="page-item <?= ($i == $page) ? 'active' : '' ?>">
                <a class="page-link" href="?page=<?= $i ?><?= $queryString ?>">
                    <?= $i ?>
                </a>
            </li>
        <?php endfor; ?>

        <!-- Next -->
        <?php if ($page < $total_pages): ?>
            <li class="page-item">
                <a class="page-link" href="?page=<?= $page + 1 ?><?= $queryString ?>">
                    Next
                </a>
            </li>
        <?php endif; ?>

    </ul>
</nav>

<?php endif; ?>

        </div>
        
        <!-- Statistics Section -->
        <div class="row g-4 mt-2">
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-list-ol me-2"></i>Top Blocked IPs</h5>
                    <div class="list-group">
                        <?php foreach ($stats['top_blocked_ips'] ?? [] as $ip): ?>
                            <div class="list-group-item d-flex justify-content-between align-items-center bg-transparent border-secondary">
                                <div>
                                    <code><?= htmlspecialchars($ip['ip']) ?></code>
                                </div>
                                <span class="badge bg-danger"><?= $ip['block_count'] ?> blocks</span>
                            </div>
                        <?php endforeach; ?>
                        <?php if (empty($stats['top_blocked_ips'])): ?>
                            <div class="text-center py-3 text-muted">
                                <i class="bi bi-check-circle mb-2"></i>
                                <p class="mb-0">No blocked IP data</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="dashboard-card">
                    <h5 class="mb-3"><i class="bi bi-exclamation-circle me-2"></i>Common Block Reasons</h5>
                    <div class="list-group">
                        <?php foreach ($stats['common_reasons'] ?? [] as $reason): ?>
                            <div class="list-group-item d-flex justify-content-between align-items-center bg-transparent border-secondary">
                                <div class="small"><?= htmlspecialchars($reason['reason']) ?></div>
                                <span class="badge bg-warning"><?= $reason['count'] ?></span>
                            </div>
                        <?php endforeach; ?>
                        <?php if (empty($stats['common_reasons'])): ?>
                            <div class="text-center py-3 text-muted">
                                <i class="bi bi-check-circle mb-2"></i>
                                <p class="mb-0">No reason data</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <!-- Block IP Modal -->
    <div class="modal fade" id="blockIPModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">Block IP Address</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="?action=block">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="block_ip" class="form-label">IP Address *</label>
                            <input type="text" class="form-control" id="block_ip" name="ip" 
                                   placeholder="e.g., 192.168.1.1 or 2001:db8::1" required>
                        </div>
                        <div class="mb-3">
                            <label for="block_website" class="form-label">Website *</label>
                            <select class="form-select" id="block_website" name="website_id" required>
                                <option value="">Select a website</option>
                                <?php foreach ($websites as $website): ?>
                                    <option value="<?= $website['id'] ?>">
                                        <?= htmlspecialchars($website['domain']) ?> (<?= htmlspecialchars($website['site_name']) ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="block_reason" class="form-label">Reason</label>
                            <textarea class="form-control" id="block_reason" name="reason" rows="2" 
                                      placeholder="Why are you blocking this IP?"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="block_duration" class="form-label">Duration</label>
                            <select class="form-select" id="block_duration" name="duration">
                                <option value="1">1 hour</option>
                                <option value="6">6 hours</option>
                                <option value="12">12 hours</option>
                                <option value="24" selected>24 hours</option>
                                <option value="72">3 days</option>
                                <option value="168">7 days</option>
                                <option value="720">30 days</option>
                                <option value="8760">1 year</option>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-danger">Block IP</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- IP Details Modal -->
    <div class="modal fade" id="ipDetailsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content bg-dark">
                <div class="modal-header">
                    <h5 class="modal-title">IP Address Details</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="ipDetailsContent">
                    <!-- Content will be loaded via AJAX -->
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    
    <script>
        function showIPDetails(ip) {
            const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
            const content = document.getElementById('ipDetailsContent');
            
            // Load IP details via AJAX
            fetch(`ajax/ip_details.php?ip=${encodeURIComponent(ip)}`)
                .then(response => response.text())
                .then(html => {
                    content.innerHTML = html;
                    modal.show();
                })
                .catch(error => {
                    console.error('Error loading IP details:', error);
                    content.innerHTML = '<div class="alert alert-danger">Error loading IP details</div>';
                    modal.show();
                });
        }
        
        // Auto-focus on IP field when modal opens
        document.getElementById('blockIPModal').addEventListener('shown.bs.modal', function () {
            document.getElementById('block_ip').focus();
        });
        
        $(document).ready(function() {
            // Initialize DataTable
            $('#blocksTable').DataTable({
                pageLength: 25,
                order: [[4, 'desc']],
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search blocked IPs...",
                    lengthMenu: "_MENU_ records per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ blocks",
                    infoEmpty: "No blocks found",
                    infoFiltered: "(filtered from _MAX_ total blocks)"
                }
            });
            
            // Initialize tooltips
            $('[data-bs-toggle="tooltip"]').tooltip();
        });
    </script>
</body>
</html>