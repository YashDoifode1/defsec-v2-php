<?php
// block-list.php

require_once 'includes/config.php';
require_once 'includes/db.php';

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

    $ip     = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
    $reason = trim($_POST['reason'] ?? 'Manual block by admin');

    if ($ip) {

        $stmt = $pdo->prepare("
            INSERT INTO blocked_ips (ip, reason, website_id)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE reason = VALUES(reason)
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
$page     = max(1, intval($_GET['page'] ?? 1));
$offset   = ($page - 1) * $per_page;

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

$params_with_limit = array_merge($params, [$per_page, $offset]);

$stmt = $pdo->prepare($query);
$stmt->execute($params_with_limit);
$blocked_ips = $stmt->fetchAll();

/* --------------------------------
   COUNT FOR PAGINATION
--------------------------------- */
$count_query = "SELECT COUNT(*) FROM blocked_ips $where";
$count_stmt  = $pdo->prepare($count_query);
$count_stmt->execute($params);
$total = $count_stmt->fetchColumn();
$total_pages = ceil($total / $per_page);

/* --------------------------------
   CSRF
--------------------------------- */
$csrf_token = generateCSRFToken('block_ip');

/* --------------------------------
   NOW LOAD HEADER (AFTER LOGIC)
--------------------------------- */
require_once 'includes/header.php';
?>

<!-- ============================= -->
<!-- ====== UI STARTS HERE ======= -->
<!-- ============================= -->

<div class="row g-4 fade-in">
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

    <!-- Block Form -->
    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-plus-circle me-2"></i>Block New IP</h5>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="mb-3">
                    <label class="form-label">IP Address</label>
                    <input type="text" class="form-control" name="ip"
                           placeholder="192.168.1.1" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Reason</label>
                    <textarea class="form-control" name="reason" rows="3"></textarea>
                </div>

                <button type="submit" name="block_ip" class="btn btn-danger w-100">
                    <i class="fas fa-ban me-2"></i>Block IP Address
                </button>
            </form>
        </div>
    </div>

    <!-- Blocked IP Table -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-list me-2"></i>Blocked IP Addresses</h5>

            <?php if (isset($_GET['unblocked'])): ?>
                <div class="alert alert-success">
                    IP address has been unblocked successfully.
                </div>
            <?php endif; ?>

            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Reason</th>
                            <th>Date</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($blocked_ips)): ?>
                            <?php foreach ($blocked_ips as $row): ?>
                                <tr>
                                    <td><code><?= htmlspecialchars($row['ip']) ?></code></td>
                                    <td><?= htmlspecialchars($row['reason']) ?></td>
                                    <td><?= date('M d, Y H:i', strtotime($row['created_at'])) ?></td>
                                    <td>
                                        <a href="block-list.php?unblock=<?= urlencode($row['ip']) ?>"
                                           class="btn btn-sm btn-outline-success"
                                           onclick="return confirm('Unblock this IP?')">
                                           <i class="fas fa-unlock"></i>
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="4" class="text-center text-muted py-4">
                                    No blocked IPs found.
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
            <nav>
                <ul class="pagination justify-content-center">
                    <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                        <li class="page-item <?= $i == $page ? 'active' : '' ?>">
                            <a class="page-link" href="?page=<?= $i ?>&search=<?= urlencode($search) ?>">
                                <?= $i ?>
                            </a>
                        </li>
                    <?php endfor; ?>
                </ul>
            </nav>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
