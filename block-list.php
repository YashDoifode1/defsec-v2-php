<?php
require_once 'includes/header.php';

/* --------------------------------
   AUTH CHECK
--------------------------------- */
$websiteId = $_SESSION['website_id'] ?? null;

if (!$websiteId) {
    die("Unauthorized access. Website session missing.");
}

/* --------------------------------
   HANDLE BLOCK ACTION
--------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['block_ip'])) {

    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!validateCSRFToken('block_ip', $csrf_token)) {
        die('Invalid CSRF token');
    }

    $ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
    $reason = trim($_POST['reason'] ?? 'Manual block by admin');

    if ($ip) {

        $stmt = $pdo->prepare("
            INSERT INTO blocked_ips (ip, reason, website_id)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                reason = VALUES(reason)
        ");

        $stmt->execute([$ip, $reason, $websiteId]);

        header("Location: block-list.php");
        exit();
    }
}

/* --------------------------------
   HANDLE UNBLOCK
--------------------------------- */
if (isset($_GET['unblock'])) {

    $ip = filter_var($_GET['unblock'], FILTER_VALIDATE_IP);

    if ($ip) {
        $stmt = $pdo->prepare("
            DELETE FROM blocked_ips
            WHERE ip = ? AND website_id = ?
        ");

        $stmt->execute([$ip, $websiteId]);

        header("Location: block-list.php?unblocked=1");
        exit();
    }
}

/* --------------------------------
   SEARCH
--------------------------------- */
$search = trim($_GET['search'] ?? '');
$where  = "WHERE website_id = ?";
$params = [$websiteId];

if ($search !== '') {
    $where .= " AND (ip LIKE ? OR reason LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}

/* --------------------------------
   PAGINATION
--------------------------------- */
$per_page = 20;
$page = max(1, intval($_GET['page'] ?? 1));
$offset = ($page - 1) * $per_page;

/* --------------------------------
   FETCH BLOCKED IPs
--------------------------------- */
$query = "
    SELECT *
    FROM blocked_ips
    $where
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
";

$params_with_limit = $params;
$params_with_limit[] = $per_page;
$params_with_limit[] = $offset;

$stmt = $pdo->prepare($query);
$stmt->execute($params_with_limit);
$blocked_ips = $stmt->fetchAll();

/* --------------------------------
   COUNT FOR PAGINATION
--------------------------------- */
$count_query = "SELECT COUNT(*) FROM blocked_ips $where";
$count_stmt = $pdo->prepare($count_query);
$count_stmt->execute($params);
$total = $count_stmt->fetchColumn();
$total_pages = ceil($total / $per_page);

/* --------------------------------
   CSRF
--------------------------------- */
$csrf_token = generateCSRFToken('block_ip');
?>


<!-- Block List Content -->
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-ban me-2"></i>Blocked IPs Management</h2>
                <p class="text-muted mb-0">Manage blocked IP addresses and security rules</p>
            </div>
            <div>
                <span class="badge bg-danger me-3"><?php echo $total; ?> IPs Blocked</span>
            </div>
        </div>
    </div>

    <!-- Block New IP Form -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-plus-circle me-2"></i>Block New IP</h5>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="mb-3">
                    <label for="ip" class="form-label">IP Address</label>
                    <input type="text" class="form-control" id="ip" name="ip" 
                           placeholder="e.g., 192.168.1.1" required
                           pattern="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$">
                    <div class="form-text">Enter a valid IPv4 address</div>
                </div>
                
                <div class="mb-3">
                    <label for="reason" class="form-label">Reason</label>
                    <textarea class="form-control" id="reason" name="reason" 
                              rows="3" placeholder="Reason for blocking this IP..."></textarea>
                </div>
                
                <button type="submit" name="block_ip" class="btn btn-danger w-100">
                    <i class="fas fa-ban me-2"></i>Block IP Address
                </button>
            </form>
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-info-circle me-2"></i>Information</h6>
                <div class="alert alert-info">
                    <i class="fas fa-lightbulb me-2"></i>
                    <strong>Tip:</strong> Block suspicious IPs to prevent unauthorized access. 
                    You can also block IP ranges by using CIDR notation.
                </div>
            </div>
        </div>
    </div>

    <!-- Blocked IPs List -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2"></i>Blocked IP Addresses</h5>
                
                <form method="GET" class="d-flex">
                    <div class="input-group">
                        <input type="text" class="form-control" name="search" 
                               placeholder="Search IPs or reasons..." 
                               value="<?= htmlspecialchars($search) ?>">
                        <button class="btn btn-outline-secondary" type="submit">
                            <i class="fas fa-search"></i>
                        </button>
                        <?php if (!empty($search)): ?>
                            <a href="block-list.php" class="btn btn-outline-danger">
                                <i class="fas fa-times"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
            
            <?php if (isset($_GET['unblocked'])): ?>
                <div class="alert alert-success alert-dismissible fade show">
                    <i class="fas fa-check-circle me-2"></i>
                    IP address has been unblocked successfully.
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Date Blocked</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($blocked_ips)): ?>
                            <?php foreach ($blocked_ips as $row): ?>
                            <tr>
                                <td>
                                    <code><?= htmlspecialchars($row['ip']) ?></code>
                                    <?php if (strpos($row['ip'], '/') !== false): ?>
                                        <span class="badge bg-warning ms-1">CIDR</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="text-truncate" style="max-width: 200px;" 
                                          title="<?= htmlspecialchars($row['reason']) ?>">
                                        <?= htmlspecialchars($row['reason']) ?>
                                    </span>
                                </td>
                                <td>
                                    <small><?= date('M d, Y', strtotime($row['created_at'])) ?></small><br>
                                    <small class="text-muted"><?= date('H:i', strtotime($row['created_at'])) ?></small>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm" role="group">
                                        <a href="blocked-ip.php?id=<?= urlencode($row['ip']) ?>" 
                                           class="btn btn-outline-info">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                        <a href="block-list.php?unblock=<?= urlencode($row['ip']) ?>" 
                                           class="btn btn-outline-success"
                                           onclick="return confirm('Are you sure you want to unblock this IP?')">
                                            <i class="fas fa-unlock"></i>
                                        </a>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="4" class="text-center py-4">
                                    <div class="text-muted">
                                        <i class="fas fa-inbox fa-2x mb-3"></i>
                                        <div>No blocked IPs found.</div>
                                        <small>Start by blocking your first IP address.</small>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
            <div class="mt-4">
                <nav aria-label="Blocked IPs pagination">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page - 1 ?>&search=<?= urlencode($search) ?>" 
                                   aria-label="Previous">
                                    <span aria-hidden="true">&laquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>
                        
                        <?php 
                        $start = max(1, $page - 2);
                        $end = min($total_pages, $start + 4);
                        if ($end - $start < 4) {
                            $start = max(1, $end - 4);
                        }
                        
                        for ($i = $start; $i <= $end; $i++): ?>
                            <li class="page-item <?= $i == $page ? 'active' : '' ?>">
                                <a class="page-link" href="?page=<?= $i ?>&search=<?= urlencode($search) ?>">
                                    <?= $i ?>
                                </a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($page < $total_pages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?= $page + 1 ?>&search=<?= urlencode($search) ?>" 
                                   aria-label="Next">
                                    <span aria-hidden="true">&raquo;</span>
                                </a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            </div>
            <?php endif; ?>
            
            <!-- Statistics -->
            <div class="mt-4 pt-3 border-top">
                <div class="row">
                    <div class="col-md-4">
                        <div class="text-center">
                            <div class="fw-bold fs-4"><?= $total ?></div>
                            <div class="text-muted small">Total Blocked</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="text-center">
                            <div class="fw-bold fs-4"><?= date('M d') ?></div>
                            <div class="text-muted small">Last Updated</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="text-center">
                            <div class="fw-bold fs-4"><?= count($blocked_ips) ?></div>
                            <div class="text-muted small">On This Page</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    $(document).ready(function() {
        // Validate IP address format
        $('#ip').on('blur', function() {
            const ip = $(this).val();
            if (ip && !isValidIP(ip)) {
                $(this).addClass('is-invalid');
                $(this).next('.form-text').html('<span class="text-danger">Please enter a valid IP address</span>');
            } else {
                $(this).removeClass('is-invalid');
                $(this).next('.form-text').text('Enter a valid IPv4 address');
            }
        });
        
        function isValidIP(ip) {
            // Simple IPv4 validation
            const pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return pattern.test(ip);
        }
    });
</script>

<?php
// require_once 'includes/footer.php';
?>