<?php
// geolocation.php - Detailed Geolocation Reports
require_once '../includes/header.php';

// Check if user is logged in
if (!$isLoggedIn) {
    header("Location: login.php");
    exit();
}

$userId = $_SESSION['user_id'];
$websiteId = isset($_GET['website_id']) ? intval($_GET['website_id']) : ($_SESSION['website_id'] ?? 1);

// Get website details
try {
    $websiteQuery = $pdo->prepare("SELECT site_name, domain FROM websites WHERE id = ? AND user_id = ?");
    $websiteQuery->execute([$websiteId, $userId]);
    $websiteDetails = $websiteQuery->fetch();
} catch (Exception $e) {
    $websiteDetails = ['site_name' => 'Unknown Website', 'domain' => 'unknown'];
}

// Get filter parameters
$startDate = $_GET['start_date'] ?? date('Y-m-d', strtotime('-7 days'));
$endDate = $_GET['end_date'] ?? date('Y-m-d');
$country = $_GET['country'] ?? '';
$ipSearch = $_GET['ip'] ?? '';

// Build query conditions
$conditions = ["user_id = ?", "website_id = ?"];
$params = [$userId, $websiteId];

if (!empty($startDate)) {
    $conditions[] = "DATE(timestamp) >= ?";
    $params[] = $startDate;
}

if (!empty($endDate)) {
    $conditions[] = "DATE(timestamp) <= ?";
    $params[] = $endDate;
}

if (!empty($country) && $country !== 'all') {
    $conditions[] = "country = ?";
    $params[] = $country;
}

if (!empty($ipSearch)) {
    $conditions[] = "(ip LIKE ? OR real_ip LIKE ?)";
    $params[] = "%$ipSearch%";
    $params[] = "%$ipSearch%";
}

$whereClause = implode(' AND ', $conditions);

try {
    // Get visitor statistics by country
    $countryStats = $pdo->prepare("
        SELECT 
            country,
            COUNT(*) as total_visits,
            COUNT(DISTINCT ip) as unique_ips,
            COUNT(CASE WHEN is_vpn = 1 THEN 1 END) as vpn_count,
            COUNT(CASE WHEN is_proxy = 1 THEN 1 END) as proxy_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM logs 
        WHERE $whereClause
        AND country IS NOT NULL 
        AND country != 'Unknown'
        GROUP BY country
        ORDER BY total_visits DESC
    ");
    $countryStats->execute($params);
    $countryData = $countryStats->fetchAll();

    // Get attack statistics by country
    $attackCountryStats = $pdo->prepare("
        SELECT 
            l.country,
            COUNT(*) as total_attacks,
            COUNT(DISTINCT al.ip_address) as unique_attackers,
            GROUP_CONCAT(DISTINCT al.attack_type) as attack_types,
            SUM(CASE WHEN al.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN al.severity = 'High' THEN 1 ELSE 0 END) as high_count,
            MIN(al.timestamp) as first_attack,
            MAX(al.timestamp) as last_attack
        FROM attack_logs al
        LEFT JOIN logs l ON al.ip_address = l.ip 
            AND l.user_id = al.user_id 
            AND l.website_id = al.website_id
        WHERE al.user_id = ? AND al.website_id = ?
        AND DATE(al.timestamp) BETWEEN ? AND ?
        AND l.country IS NOT NULL 
        AND l.country != 'Unknown'
        GROUP BY l.country
        ORDER BY total_attacks DESC
    ");
    $attackCountryStats->execute([$userId, $websiteId, $startDate, $endDate]);
    $attackCountryData = $attackCountryStats->fetchAll();

    // Get unique countries for filter dropdown
    $uniqueCountries = $pdo->prepare("
        SELECT DISTINCT country 
        FROM logs 
        WHERE user_id = ? AND website_id = ?
        AND country IS NOT NULL 
        AND country != 'Unknown'
        ORDER BY country
    ");
    $uniqueCountries->execute([$userId, $websiteId]);
    $countries = $uniqueCountries->fetchAll();

    // Get recent geolocated visitors
    $recentVisitors = $pdo->prepare("
        SELECT 
            ip,
            real_ip,
            country,
            latitude,
            longitude,
            user_agent,
            timestamp,
            is_vpn,
            is_proxy,
            ASN,
            ISP,
            screen_resolution,
            language,
            timezone,
            digital_dna
        FROM logs 
        WHERE $whereClause
        AND latitude IS NOT NULL 
        AND longitude IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 50
    ");
    $recentVisitors->execute($params);
    $visitorData = $recentVisitors->fetchAll();

    // Get total statistics
    $totalStats = $pdo->prepare("
        SELECT 
            COUNT(*) as total_logs,
            COUNT(DISTINCT ip) as unique_ips,
            COUNT(DISTINCT country) as unique_countries,
            COUNT(CASE WHEN is_vpn = 1 THEN 1 END) as total_vpn,
            COUNT(CASE WHEN is_proxy = 1 THEN 1 END) as total_proxy
        FROM logs 
        WHERE $whereClause
    ");
    $totalStats->execute($params);
    $statsData = $totalStats->fetch();

} catch (PDOException $e) {
    $countryData = [];
    $attackCountryData = [];
    $countries = [];
    $visitorData = [];
    $statsData = ['total_logs' => 0, 'unique_ips' => 0, 'unique_countries' => 0, 'total_vpn' => 0, 'total_proxy' => 0];
}
?>
<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-globe-americas me-2"></i>Geolocation Analytics</h2>
                <p class="text-muted mb-0">
                    Tracking visitors from around the world for 
                    <strong><?php echo htmlspecialchars($websiteDetails['site_name']); ?></strong>
                </p>
            </div>
            <div>
                <a href="summery.php" class="btn btn-outline-secondary">
                    <i class="fas fa-arrow-left me-1"></i> Back to Dashboard
                </a>
            </div>
        </div>
    </div>

    <!-- Filter Card -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-3"><i class="fas fa-filter me-2"></i>Filter Data</h5>
            <form method="GET" class="row g-3">
                <input type="hidden" name="website_id" value="<?php echo $websiteId; ?>">
                
                <div class="col-md-3">
                    <label class="form-label">Start Date</label>
                    <input type="date" class="form-control" name="start_date" value="<?php echo $startDate; ?>">
                </div>
                
                <div class="col-md-3">
                    <label class="form-label">End Date</label>
                    <input type="date" class="form-control" name="end_date" value="<?php echo $endDate; ?>">
                </div>
                
                <div class="col-md-3">
                    <label class="form-label">Country</label>
                    <select class="form-control" name="country">
                        <option value="all">All Countries</option>
                        <?php foreach ($countries as $c): ?>
                            <option value="<?php echo htmlspecialchars($c['country']); ?>" 
                                <?php echo ($country === $c['country']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($c['country']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="col-md-3">
                    <label class="form-label">IP Address</label>
                    <input type="text" class="form-control" name="ip" value="<?php echo htmlspecialchars($ipSearch); ?>" 
                           placeholder="Search by IP...">
                </div>
                
                <div class="col-12">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search me-1"></i> Apply Filters
                            </button>
                            <a href="geolocation.php?website_id=<?php echo $websiteId; ?>" class="btn btn-outline-secondary ms-2">
                                <i class="fas fa-redo me-1"></i> Reset
                            </a>
                        </div>
                        <div class="text-end">
                            <small class="text-muted">
                                Showing data from <?php echo date('M j, Y', strtotime($startDate)); ?> 
                                to <?php echo date('M j, Y', strtotime($endDate)); ?>
                            </small>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Summary Statistics -->
    <div class="col-md-6">
        <div class="dashboard-card">
            <h5 class="mb-3"><i class="fas fa-chart-bar me-2"></i>Visitor Statistics</h5>
            <div class="row">
                <div class="col-6 mb-3">
                    <div class="text-center">
                        <div class="display-4 text-primary"><?php echo $statsData['unique_ips']; ?></div>
                        <div class="text-muted">Unique IPs</div>
                    </div>
                </div>
                <div class="col-6 mb-3">
                    <div class="text-center">
                        <div class="display-4 text-info"><?php echo $statsData['unique_countries']; ?></div>
                        <div class="text-muted">Countries</div>
                    </div>
                </div>
                <div class="col-6">
                    <div class="text-center">
                        <div class="display-4 text-warning"><?php echo $statsData['total_vpn']; ?></div>
                        <div class="text-muted">VPN Users</div>
                    </div>
                </div>
                <div class="col-6">
                    <div class="text-center">
                        <div class="display-4 text-danger"><?php echo $statsData['total_proxy']; ?></div>
                        <div class="text-muted">Proxy Users</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="dashboard-card">
            <h5 class="mb-3"><i class="fas fa-shield-alt me-2"></i>Attack Statistics</h5>
            <div class="row">
                <?php
                $totalAttacks = 0;
                $criticalAttacks = 0;
                $uniqueAttackers = 0;
                
                foreach ($attackCountryData as $attack) {
                    $totalAttacks += $attack['total_attacks'];
                    $criticalAttacks += $attack['critical_count'];
                    $uniqueAttackers += $attack['unique_attackers'];
                }
                ?>
                <div class="col-6 mb-3">
                    <div class="text-center">
                        <div class="display-4 text-danger"><?php echo $totalAttacks; ?></div>
                        <div class="text-muted">Total Attacks</div>
                    </div>
                </div>
                <div class="col-6 mb-3">
                    <div class="text-center">
                        <div class="display-4 text-danger"><?php echo $criticalAttacks; ?></div>
                        <div class="text-muted">Critical Attacks</div>
                    </div>
                </div>
                <div class="col-6">
                    <div class="text-center">
                        <div class="display-4 text-warning"><?php echo $uniqueAttackers; ?></div>
                        <div class="text-muted">Unique Attackers</div>
                    </div>
                </div>
                <div class="col-6">
                    <div class="text-center">
                        <div class="display-4 text-info"><?php echo count($attackCountryData); ?></div>
                        <div class="text-muted">Countries with Attacks</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Country Statistics Tables -->
    <div class="col-lg-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-users me-2"></i>Visitors by Country</h5>
                <span class="badge bg-primary"><?php echo count($countryData); ?> countries</span>
            </div>
            
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Country</th>
                            <th>Visits</th>
                            <th>Unique IPs</th>
                            <th>VPN</th>
                            <th>Proxy</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($countryData)): ?>
                            <?php foreach ($countryData as $country): ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($country['country']); ?></strong>
                                </td>
                                <td>
                                    <span class="badge bg-primary"><?php echo $country['total_visits']; ?></span>
                                </td>
                                <td>
                                    <span class="badge bg-info"><?php echo $country['unique_ips']; ?></span>
                                </td>
                                <td>
                                    <?php if ($country['vpn_count'] > 0): ?>
                                        <span class="badge bg-warning"><?php echo $country['vpn_count']; ?></span>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($country['proxy_count'] > 0): ?>
                                        <span class="badge bg-danger"><?php echo $country['proxy_count']; ?></span>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <small><?php echo date('M j, H:i', strtotime($country['last_seen'])); ?></small>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" class="text-center py-4">
                                    <div class="text-muted">
                                        <i class="fas fa-globe fa-lg mb-2"></i>
                                        <div>No country data available</div>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-skull-crossbones me-2"></i>Attacks by Country</h5>
                <span class="badge bg-danger"><?php echo count($attackCountryData); ?> countries</span>
            </div>
            
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Country</th>
                            <th>Attacks</th>
                            <th>Critical</th>
                            <th>Attackers</th>
                            <th>Attack Types</th>
                            <th>Last Attack</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($attackCountryData)): ?>
                            <?php foreach ($attackCountryData as $attack): ?>
                            <tr>
                                <td>
                                    <strong><?php echo htmlspecialchars($attack['country']); ?></strong>
                                </td>
                                <td>
                                    <span class="badge bg-danger"><?php echo $attack['total_attacks']; ?></span>
                                </td>
                                <td>
                                    <?php if ($attack['critical_count'] > 0): ?>
                                        <span class="badge bg-danger"><?php echo $attack['critical_count']; ?></span>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge bg-warning"><?php echo $attack['unique_attackers']; ?></span>
                                </td>
                                <td>
                                    <small><?php echo htmlspecialchars(substr($attack['attack_types'], 0, 30)); ?>...</small>
                                </td>
                                <td>
                                    <small><?php echo date('M j, H:i', strtotime($attack['last_attack'])); ?></small>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" class="text-center py-4">
                                    <div class="text-muted">
                                        <i class="fas fa-shield-alt fa-lg mb-2"></i>
                                        <div>No attack data by country</div>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Recent Geolocated Visitors -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-map-marker-alt me-2"></i>Recent Geolocated Visitors</h5>
                <span class="badge bg-info"><?php echo count($visitorData); ?> records</span>
            </div>
            
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Country</th>
                            <th>Coordinates</th>
                            <th>ISP / ASN</th>
                            <th>VPN/Proxy</th>
                            <th>Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($visitorData)): ?>
                            <?php foreach ($visitorData as $visitor): ?>
                            <tr>
                                <td>
                                    <code><?php echo htmlspecialchars($visitor['ip']); ?></code>
                                    <?php if ($visitor['real_ip'] && $visitor['real_ip'] !== $visitor['ip']): ?>
                                        <br><small class="text-muted">Real: <?php echo htmlspecialchars($visitor['real_ip']); ?></small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge bg-dark"><?php echo htmlspecialchars($visitor['country']); ?></span>
                                </td>
                                <td>
                                    <small>
                                        <?php echo htmlspecialchars($visitor['latitude']); ?>, 
                                        <?php echo htmlspecialchars($visitor['longitude']); ?>
                                    </small>
                                </td>
                                <td>
                                    <small>
                                        <div><?php echo htmlspecialchars($visitor['ISP']); ?></div>
                                        <div class="text-muted">AS<?php echo htmlspecialchars($visitor['ASN']); ?></div>
                                    </small>
                                </td>
                                <td>
                                    <?php if ($visitor['is_vpn']): ?>
                                        <span class="badge bg-warning">VPN</span>
                                    <?php endif; ?>
                                    <?php if ($visitor['is_proxy']): ?>
                                        <span class="badge bg-danger">Proxy</span>
                                    <?php endif; ?>
                                    <?php if (!$visitor['is_vpn'] && !$visitor['is_proxy']): ?>
                                        <span class="badge bg-success">Direct</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <small><?php echo date('H:i:s', strtotime($visitor['timestamp'])); ?></small>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <button class="btn btn-outline-info" 
                                                onclick="viewVisitorDetails(<?php echo htmlspecialchars(json_encode($visitor)); ?>)"
                                                title="View Details">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <a href="block-list.php?ip=<?php echo urlencode($visitor['ip']); ?>&website_id=<?php echo $websiteId; ?>" 
                                           class="btn btn-outline-danger" title="Block IP">
                                            <i class="fas fa-ban"></i>
                                        </a>
                                        <a href="https://maps.google.com/?q=<?php echo urlencode($visitor['latitude'] . ',' . $visitor['longitude']); ?>" 
                                           target="_blank" class="btn btn-outline-success" title="View on Google Maps">
                                            <i class="fas fa-external-link-alt"></i>
                                        </a>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="7" class="text-center py-4">
                                    <div class="text-muted">
                                        <i class="fas fa-map-marked-alt fa-lg mb-2"></i>
                                        <div>No geolocated visitor data</div>
                                        <small class="mt-2 d-block">Try adjusting your filters</small>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Visitor Details Modal -->
<div class="modal fade" id="visitorDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title">Visitor Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="visitorDetailsContent">
                <!-- Content will be loaded dynamically -->
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
        <!-- Charts Section -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Visual Analytics</h5>
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-secondary" onclick="refreshData()">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="exportData('json')">
                        <i class="fas fa-download"></i> Export JSON
                    </button>
                    <button class="btn btn-sm btn-outline-success" onclick="exportData('csv')">
                        <i class="fas fa-file-csv"></i> Export CSV
                    </button>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="chart-container">
                        <canvas id="visitorChart"></canvas>
                    </div>
                    <div class="text-center mt-2">
                        <small class="text-muted">Top 10 Countries by Visitor Count</small>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="chart-container">
                        <canvas id="attackChart"></canvas>
                    </div>
                    <div class="text-center mt-2">
                        <small class="text-muted">Top 10 Countries by Attack Count</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bulk Actions Bar (hidden by default, shows when IPs are selected) -->
    <div class="col-12" id="bulkActionsBar" style="display: none;">
        <div class="dashboard-card bulk-actions-bar">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <strong id="selectedCount">0</strong> IP(s) selected
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-danger" onclick="performBulkAction('block')">
                        <i class="fas fa-ban me-1"></i> Block Selected
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="performBulkAction('export')">
                        <i class="fas fa-download me-1"></i> Export Selected
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="$('input[name=\"selected_ips\"]').prop('checked', false); $('#bulkActionsBar').hide();">
                        <i class="fas fa-times me-1"></i> Clear Selection
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// View visitor details
function viewVisitorDetails(visitor) {
    const content = `
        <div class="row">
            <div class="col-md-6">
                <div class="mb-3">
                    <label class="form-label text-muted">IP Address</label>
                    <div class="form-control bg-dark text-light">
                        ${visitor.ip}
                        ${visitor.real_ip && visitor.real_ip !== visitor.ip ? 
                            `<br><small class="text-muted">Real IP: ${visitor.real_ip}</small>` : ''}
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Location</label>
                    <div class="form-control bg-dark text-light">
                        <strong>${visitor.country}</strong><br>
                        Coordinates: ${visitor.latitude}, ${visitor.longitude}
                    </div>
                </div>
                                <div class="mb-3">
                    <label class="form-label text-muted">Network Information</label>
                    <div class="form-control bg-dark text-light">
                        <div>ISP: ${visitor.ISP || 'Unknown'}</div>
                        <div>ASN: ${visitor.ASN || 'Unknown'}</div>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Connection Type</label>
                    <div class="form-control bg-dark text-light">
                        ${visitor.is_vpn ? '<span class="badge bg-warning">VPN</span>' : ''}
                        ${visitor.is_proxy ? '<span class="badge bg-danger">Proxy</span>' : ''}
                        ${!visitor.is_vpn && !visitor.is_proxy ? '<span class="badge bg-success">Direct Connection</span>' : ''}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="mb-3">
                    <label class="form-label text-muted">Device & Browser</label>
                    <div class="form-control bg-dark text-light">
                        ${visitor.user_agent || 'Unknown'}
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Screen Resolution</label>
                    <div class="form-control bg-dark text-light">
                        ${visitor.screen_resolution || 'Not detected'}
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Language & Timezone</label>
                    <div class="form-control bg-dark text-light">
                        <div>Language: ${visitor.language || 'Unknown'}</div>
                        <div>Timezone: ${visitor.timezone || 'Unknown'}</div>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted">Digital DNA</label>
                    <div class="form-control bg-dark text-light" style="font-family: monospace; font-size: 12px;">
                        ${visitor.digital_dna || 'Not available'}
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-3">
            <div class="col-12">
                <div class="alert alert-info">
                    <strong>Timestamp:</strong> ${new Date(visitor.timestamp).toLocaleString()}
                </div>
            </div>
        </div>
        <div class="row mt-3">
            <div class="col-12">
                <div id="visitorMap" style="height: 300px; width: 100%; border-radius: 5px;"></div>
            </div>
        </div>
    `;
    
    $('#visitorDetailsContent').html(content);
    const modal = new bootstrap.Modal(document.getElementById('visitorDetailsModal'));
    modal.show();
    
    // Initialize map after modal is shown
    $('#visitorDetailsModal').on('shown.bs.modal', function() {
        if (visitor.latitude && visitor.longitude) {
            const map = L.map('visitorMap').setView([visitor.latitude, visitor.longitude], 10);
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap'
            }).addTo(map);
            
            L.marker([visitor.latitude, visitor.longitude]).addTo(map)
                .bindPopup(`<strong>${visitor.ip}</strong><br>${visitor.country}<br>${visitor.ISP || ''}`)
                .openPopup();
        }
    });
    
    // Cleanup map on modal close
    $('#visitorDetailsModal').on('hidden.bs.modal', function() {
        const mapDiv = document.getElementById('visitorMap');
        if (mapDiv) {
            mapDiv.innerHTML = '';
        }
    });
}

// Export data functionality
function exportData(format) {
    const params = new URLSearchParams(window.location.search);
    params.set('export', format);
    
    window.location.href = 'api/export-geolocation.php?' + params.toString();
}

// Initialize charts
function initCharts() {
    // Visitor distribution by country chart
    const visitorData = <?php echo json_encode(array_slice($countryData, 0, 10)); ?>;
    const attackData = <?php echo json_encode(array_slice($attackCountryData, 0, 10)); ?>;
    
    if (visitorData.length > 0) {
        const ctx1 = document.getElementById('visitorChart');
        if (ctx1) {
            new Chart(ctx1.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: visitorData.map(c => c.country),
                    datasets: [{
                        label: 'Visitor Count',
                        data: visitorData.map(c => c.total_visits),
                        backgroundColor: 'rgba(54, 162, 235, 0.7)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#888' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { 
                                color: '#888',
                                maxRotation: 45
                            },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    }
                }
            });
        }
    }
    
    if (attackData.length > 0) {
        const ctx2 = document.getElementById('attackChart');
        if (ctx2) {
            new Chart(ctx2.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: attackData.map(c => c.country),
                    datasets: [{
                        label: 'Attack Count',
                        data: attackData.map(c => c.total_attacks),
                        backgroundColor: 'rgba(255, 99, 132, 0.7)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#888' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { 
                                color: '#888',
                                maxRotation: 45
                            },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    }
                }
            });
        }
    }
}

// Refresh page data
function refreshData() {
    window.location.reload();
}

// Real-time updates
function startRealTimeUpdates() {
    // Check for new data every 30 seconds
    setInterval(() => {
        $.ajax({
            url: 'api/check-geo-updates.php',
            data: {
                website_id: <?php echo $websiteId; ?>,
                last_check: new Date().toISOString()
            },
            success: function(response) {
                if (response.has_new_data) {
                    // Show notification
                    showNotification('New geolocation data available', 'info');
                    
                    // Optionally auto-refresh
                    if (response.auto_refresh) {
                        refreshData();
                    }
                }
            }
        });
    }, 30000); // 30 seconds
}

// Show notification
function showNotification(message, type = 'info') {
    const alertClass = {
        'info': 'alert-info',
        'success': 'alert-success',
        'warning': 'alert-warning',
        'danger': 'alert-danger'
    }[type] || 'alert-info';
    
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert" 
             style="position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 300px;">
            ${message}
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('body').append(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alert.alert('close');
    }, 5000);
}

// Bulk actions
function performBulkAction(action) {
    const selectedIps = [];
    $('input[name="selected_ips"]:checked').each(function() {
        selectedIps.push($(this).val());
    });
    
    if (selectedIps.length === 0) {
        showNotification('Please select at least one IP address', 'warning');
        return;
    }
    
    if (action === 'block') {
        if (confirm(`Block ${selectedIps.length} IP address(es)?`)) {
            $.ajax({
                url: 'api/bulk-block.php',
                method: 'POST',
                data: {
                    ips: selectedIps,
                    website_id: <?php echo $websiteId; ?>,
                    reason: 'Bulk block from geolocation page'
                },
                success: function(response) {
                    if (response.success) {
                        showNotification(`${selectedIps.length} IP(s) blocked successfully`, 'success');
                        refreshData();
                    } else {
                        showNotification('Failed to block IPs: ' + response.message, 'danger');
                    }
                },
                error: function() {
                    showNotification('Error blocking IPs', 'danger');
                }
            });
        }
    } else if (action === 'export') {
        // Export selected IPs
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(selectedIps, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", "selected-ips-<?php echo date('Y-m-d'); ?>.json");
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        
        showNotification('IP list exported', 'success');
    }
}

// Initialize when page loads
$(document).ready(function() {
    // Initialize charts
    initCharts();
    
    // Start real-time updates if enabled
    const realTimeEnabled = <?php echo isset($_SESSION['settings']['real_time_updates']) ? 'true' : 'false'; ?>;
    if (realTimeEnabled) {
        startRealTimeUpdates();
    }
    
    // Add select all functionality
    $('#selectAll').change(function() {
        $('input[name="selected_ips"]').prop('checked', $(this).prop('checked'));
    });
    
    // Table row selection
    $('table.table-hover tbody tr').click(function(e) {
        if (!$(e.target).is('input, button, a, .btn, .badge')) {
            $(this).toggleClass('table-active');
            const checkbox = $(this).find('input[name="selected_ips"]');
            checkbox.prop('checked', !checkbox.prop('checked'));
        }
    });
    
    // Initialize tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
    
    // Auto-submit form on filter change
    $('.filter-auto-submit').change(function() {
        $(this).closest('form').submit();
    });
    
    // Load map for the first visitor if available
    <?php if (!empty($visitorData)): ?>
        const firstVisitor = <?php echo json_encode($visitorData[0]); ?>;
        if (firstVisitor.latitude && firstVisitor.longitude) {
            // You could initialize a main map here if needed
        }
    <?php endif; ?>
});
</script>

<?php
require_once '../includes/footer.php';
?>