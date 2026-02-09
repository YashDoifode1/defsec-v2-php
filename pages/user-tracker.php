<?php
// user-tracker.php
require_once '../includes/header.php';

// Check if user is logged in
if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Set default values for userId and websiteId
$userId = $userId ?? 1;
$websiteId = $websiteId ?? 1;

// Handle Search Query
$search = $_GET['search'] ?? '';

// Base SQL with user & website filter
$sql = "SELECT * FROM logs WHERE user_id = :user_id AND website_id = :website_id";

// Add search conditions
$params = [
    ':user_id' => $userId,
    ':website_id' => $websiteId
];

if (!empty($search)) {
    $sql .= " AND (ip LIKE :search OR real_ip LIKE :search2 OR ASN LIKE :search3 OR ISP LIKE :search4 OR user_agent LIKE :search5 OR digital_dna LIKE :search6)";
    $search_param = "%$search%";
    $params[':search'] = $search_param;
    $params[':search2'] = $search_param;
    $params[':search3'] = $search_param;
    $params[':search4'] = $search_param;
    $params[':search5'] = $search_param;
    $params[':search6'] = $search_param;
}

$sql .= " ORDER BY id DESC";

// Prepare and execute statement
try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $logs = $stmt->fetchAll();
} catch (PDOException $e) {
    $logs = [];
    $error = "Database error: " . $e->getMessage();
}

// Get summary statistics
$stats = [
    'total_visitors' => 0,
    'vpn_users' => 0,
    'tor_users' => 0,
    'unique_countries' => [],
    'unique_ips' => []
];

foreach ($logs as $row) {
    $stats['total_visitors']++;
    if ($row['is_vpn']) $stats['vpn_users']++;
    if ($row['is_tor']) $stats['tor_users']++;
    if (!empty($row['country'])) $stats['unique_countries'][$row['country']] = true;
    if (!empty($row['ip'])) $stats['unique_ips'][$row['ip']] = true;
}

$stats['unique_countries_count'] = count($stats['unique_countries']);
$stats['unique_ips_count'] = count($stats['unique_ips']);
?>

<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-user-shield me-2"></i>User Tracking & Fingerprinting</h2>
                <p class="text-muted mb-0">Monitor and analyze user activities with digital fingerprinting</p>
            </div>
            <div>
                <button class="btn btn-outline-primary" onclick="refreshData()">
                    <i class="fas fa-sync-alt me-2"></i>Refresh
                </button>
            </div>
        </div>
    </div>

    <!-- Search Bar -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-search me-2"></i>Search Users</h5>
                <div class="d-flex align-items-center">
                    <span class="badge bg-primary me-3"><?php echo count($logs); ?> Records</span>
                </div>
            </div>
            
            <form method="GET" class="row g-3">
                <div class="col-md-10">
                    <div class="input-group">
                        <span class="input-group-text">
                            <i class="fas fa-search"></i>
                        </span>
                        <input type="text" class="form-control" name="search" 
                               placeholder="Search IP, ISP, User Agent, Country..." 
                               value="<?php echo htmlspecialchars($search); ?>">
                    </div>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-search me-2"></i>Search
                    </button>
                </div>
            </form>
            
            <?php if (!empty($search)): ?>
                <div class="mt-3">
                    <a href="user-tracker.php" class="btn btn-sm btn-outline-danger">
                        <i class="fas fa-times me-1"></i>Clear Search
                    </a>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-primary mb-2">
                <i class="fas fa-users fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['total_visitors']; ?></div>
            <div class="text-muted small">Total Visitors</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-danger mb-2">
                <i class="fas fa-user-secret fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['vpn_users']; ?></div>
            <div class="text-muted small">
                VPN Users
                <?php if ($stats['total_visitors'] > 0): ?>
                    <div class="mt-1">
                        <span class="badge bg-danger">
                            <?php echo round(($stats['vpn_users']/$stats['total_visitors'])*100, 1); ?>%
                        </span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-warning mb-2">
                <i class="fas fa-network-wired fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['tor_users']; ?></div>
            <div class="text-muted small">
                Tor Users
                <?php if ($stats['total_visitors'] > 0): ?>
                    <div class="mt-1">
                        <span class="badge bg-warning">
                            <?php echo round(($stats['tor_users']/$stats['total_visitors'])*100, 1); ?>%
                        </span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-success mb-2">
                <i class="fas fa-globe fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_countries_count']; ?></div>
            <div class="text-muted small">Unique Countries</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-info mb-2">
                <i class="fas fa-desktop fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo $stats['unique_ips_count']; ?></div>
            <div class="text-muted small">Unique IPs</div>
        </div>
    </div>

    <div class="col-xl-2 col-md-4 col-sm-6">
        <div class="dashboard-card text-center">
            <div class="text-purple mb-2">
                <i class="fas fa-fingerprint fa-2x"></i>
            </div>
            <div class="fw-bold fs-4"><?php echo count($logs); ?></div>
            <div class="text-muted small">Digital Fingerprints</div>
        </div>
    </div>

    <!-- Users Table -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2"></i>User Tracking Logs</h5>
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                        <i class="fas fa-download me-1"></i> Export
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="export.php?type=pdf"><i class="fas fa-file-pdf me-2"></i> PDF</a></li>
                        <li><a class="dropdown-item" href="export.php?type=csv"><i class="fas fa-file-csv me-2"></i> CSV</a></li>
                        <li><a class="dropdown-item" href="export.php?type=json"><i class="fas fa-file-code me-2"></i> JSON</a></li>
                    </ul>
                </div>
            </div>
            
            <div class="table-responsive" style="max-height: 600px; overflow-y: auto;">
                <table class="table table-dark table-hover">
                    <thead style="position: sticky; top: 0; background: #2d2d2d; z-index: 1;">
                        <tr>
                            <th>ID</th>
                            <th>IP Route</th>
                            <th>Real IP</th>
                            <th>Country</th>
                            <th>ISP</th>
                            <th>Privacy</th>
                            <th>Screen</th>
                            <th>Browser</th>
                            <th>Fingerprint</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!empty($logs)): ?>
                            <?php foreach ($logs as $row): ?>
                                <?php
                                $privacyBadges = [];
                                if ($row['is_vpn']) $privacyBadges[] = '<span class="badge bg-danger">VPN</span>';
                                if ($row['is_tor']) $privacyBadges[] = '<span class="badge bg-warning">TOR</span>';
                                if ($row['webrtc_ip'] && $row['webrtc_ip'] != $row['ip']) $privacyBadges[] = '<span class="badge bg-info">WebRTC</span>';
                                if ($row['dns_leak_ip']) $privacyBadges[] = '<span class="badge bg-info">DNS Leak</span>';
                                
                                $privacyDisplay = !empty($privacyBadges) ? implode(' ', $privacyBadges) : '<span class="badge bg-success">Clean</span>';
                                
                                // Truncate long text
                                $userAgent = htmlspecialchars($row['user_agent'] ?? '');
                                if (strlen($userAgent) > 50) {
                                    $userAgent = substr($userAgent, 0, 50) . '...';
                                }
                                
                                $fingerprint = $row['digital_dna'] ?? '';
                                if (strlen($fingerprint) > 15) {
                                    $fingerprint = substr($fingerprint, 0, 15) . '...';
                                }
                                ?>
                                <tr>
                                    <td>
                                        <span class="badge bg-dark">#<?php echo htmlspecialchars($row['id'] ?? ''); ?></span>
                                    </td>
                                    <td>
                                        <div>
                                            <code><?php echo htmlspecialchars($row['ip'] ?? ''); ?></code>
                                            <?php if (!empty($row['reverse_dns'])): ?>
                                                <br>
                                                <small class="text-muted"><?php echo htmlspecialchars($row['reverse_dns']); ?></small>
                                            <?php endif; ?>
                                        </div>
                                        <button class="btn btn-sm btn-link p-0 text-info" 
                                                onclick="toggleDetails('details-<?php echo $row['id']; ?>')">
                                            <small><i class="fas fa-chevron-down me-1"></i> Details</small>
                                        </button>
                                        <div id="details-<?php echo $row['id']; ?>" class="mt-2 p-2 bg-dark rounded" style="display: none;">
                                            <div class="row g-2">
                                                <div class="col-md-6">
                                                    <small><strong>ASN:</strong> <?php echo htmlspecialchars($row['ASN'] ?? 'N/A'); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>WebRTC IP:</strong> <?php echo htmlspecialchars($row['webrtc_ip'] ?? 'N/A'); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>DNS Leak IP:</strong> <?php echo htmlspecialchars($row['dns_leak_ip'] ?? 'N/A'); ?></small>
                                                </div>
                                                <div class="col-md-6">
                                                    <small><strong>Port:</strong> <?php echo htmlspecialchars($row['port'] ?? 'N/A'); ?></small>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($row['real_ip'] ?? ''); ?></code>
                                    </td>
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <i class="fas fa-globe me-2 text-muted"></i>
                                            <div>
                                                <div><?php echo htmlspecialchars($row['country'] ?? 'Unknown'); ?></div>
                                                <?php if (!empty($row['city'])): ?>
                                                    <small class="text-muted"><?php echo htmlspecialchars($row['city']); ?></small>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($row['ISP'] ?? 'Unknown'); ?></small>
                                    </td>
                                    <td>
                                        <?php echo $privacyDisplay; ?>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($row['screen_resolution'] ?? 'N/A'); ?></small>
                                    </td>
                                    <td>
                                        <small><?php echo $userAgent; ?></small>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($fingerprint); ?></code>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-outline-info" 
                                                    onclick="fetchWhois('<?php echo htmlspecialchars($row['real_ip'] ?? ''); ?>')"
                                                    title="Whois Lookup">
                                                <i class="fas fa-info-circle"></i>
                                            </button>
                                            <button class="btn btn-outline-success" 
                                                    onclick="fetchLocation('<?php echo htmlspecialchars($row['real_ip'] ?? ''); ?>')"
                                                    title="Location Info">
                                                <i class="fas fa-map-marker-alt"></i>
                                            </button>
                                            <a href="block-list.php?ip=<?php echo urlencode($row['ip'] ?? ''); ?>" 
                                               class="btn btn-outline-danger"
                                               title="Block IP">
                                                <i class="fas fa-ban"></i>
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="10" class="text-center py-5">
                                    <div class="text-muted">
                                        <i class="fas fa-inbox fa-3x mb-3"></i>
                                        <h5>No user tracking data found</h5>
                                        <small>Start collecting user data to see tracking information here.</small>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <?php if (!empty($logs)): ?>
                <div class="mt-3 pt-3 border-top">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-chart-bar text-primary me-2"></i>
                                <div>
                                    <div class="small">Total Records</div>
                                    <div class="fw-bold"><?php echo count($logs); ?></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-clock text-warning me-2"></i>
                                <div>
                                    <div class="small">Last Updated</div>
                                    <div class="fw-bold">Just now</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-database text-info me-2"></i>
                                <div>
                                    <div class="small">Database Size</div>
                                    <div class="fw-bold">Active</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Export Section -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-download me-2"></i>Export Data</h5>
            
            <div class="row g-4">
                <div class="col-md-4">
                    <div class="bg-dark rounded p-3 text-center">
                        <div class="text-danger mb-2">
                            <i class="fas fa-file-pdf fa-2x"></i>
                        </div>
                        <h6>PDF Export</h6>
                        <p class="text-muted small mb-3">Generate detailed PDF reports</p>
                        <a href="export.php?type=pdf&search=<?php echo urlencode($search); ?>" 
                           class="btn btn-danger btn-sm">
                            <i class="fas fa-download me-1"></i> Export PDF
                        </a>
                    </div>
                </div>
                
                <div class="col-md-4">
                    <div class="bg-dark rounded p-3 text-center">
                        <div class="text-success mb-2">
                            <i class="fas fa-file-csv fa-2x"></i>
                        </div>
                        <h6>CSV Export</h6>
                        <p class="text-muted small mb-3">Export data for spreadsheet analysis</p>
                        <a href="export.php?type=csv&search=<?php echo urlencode($search); ?>" 
                           class="btn btn-success btn-sm">
                            <i class="fas fa-download me-1"></i> Export CSV
                        </a>
                    </div>
                </div>
                
                <div class="col-md-4">
                    <div class="bg-dark rounded p-3 text-center">
                        <div class="text-primary mb-2">
                            <i class="fas fa-file-code fa-2x"></i>
                        </div>
                        <h6>JSON Export</h6>
                        <p class="text-muted small mb-3">Export data for API integration</p>
                        <a href="export.php?type=json&search=<?php echo urlencode($search); ?>" 
                           class="btn btn-primary btn-sm">
                            <i class="fas fa-download me-1"></i> Export JSON
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="mt-4 pt-3 border-top">
                <h6 class="mb-3"><i class="fas fa-filter me-2"></i>Advanced Export</h6>
                <form action="export.php" method="GET" class="row g-3">
                    <input type="hidden" name="type" value="custom">
                    <input type="hidden" name="search" value="<?php echo htmlspecialchars($search); ?>">
                    
                    <div class="col-md-3">
                        <label class="form-label">From Date</label>
                        <input type="date" name="from_date" class="form-control" required>
                    </div>
                    
                    <div class="col-md-3">
                        <label class="form-label">To Date</label>
                        <input type="date" name="to_date" class="form-control" required>
                    </div>
                    
                    <div class="col-md-4">
                        <label class="form-label">Format</label>
                        <select name="format" class="form-select">
                            <option value="pdf">PDF Document</option>
                            <option value="csv">CSV Spreadsheet</option>
                            <option value="json">JSON Data</option>
                            <option value="xml">XML Format</option>
                        </select>
                    </div>
                    
                    <div class="col-md-2 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-download me-2"></i>Export
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Information Panel -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-info-circle me-2"></i>About User Tracking</h5>
            
            <div class="row g-4">
                <div class="col-md-6">
                    <div class="alert alert-info">
                        <h6><i class="fas fa-shield-alt me-2"></i>Privacy Detection</h6>
                        <p class="mb-0 small">
                            The system automatically detects VPN, Tor, WebRTC leaks, and DNS leaks to identify 
                            users attempting to hide their identity.
                        </p>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="alert alert-success">
                        <h6><i class="fas fa-fingerprint me-2"></i>Digital Fingerprinting</h6>
                        <p class="mb-0 small">
                            Each visitor is assigned a unique digital fingerprint based on browser characteristics, 
                            screen resolution, installed fonts, and other system information.
                        </p>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="alert alert-warning">
                        <h6><i class="fas fa-map-marker-alt me-2"></i>Geolocation</h6>
                        <p class="mb-0 small">
                            IP addresses are geolocated to provide country and city information, 
                            along with ISP details for better tracking accuracy.
                        </p>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="alert alert-danger">
                        <h6><i class="fas fa-ban me-2"></i>Security Actions</h6>
                        <p class="mb-0 small">
                            Suspicious users can be blocked directly from this interface. 
                            All actions are logged for audit purposes.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- SweetAlert2 -->
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<script>
    // Toggle details visibility
    function toggleDetails(id) {
        const element = document.getElementById(id);
        if (element.style.display === 'block') {
            element.style.display = 'none';
        } else {
            element.style.display = 'block';
        }
    }
    
    // Fetch Whois information
    function fetchWhois(ip) {
        if (!ip) {
            Swal.fire('Error', 'No IP address provided', 'error');
            return;
        }
        
        Swal.fire({
            title: 'Fetching Whois Information...',
            text: 'Please wait while we retrieve Whois data',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        fetch(`api/whois.php?ip=${encodeURIComponent(ip)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                let whoisInfo = '';
                for (const [key, value] of Object.entries(data)) {
                    if (value) {
                        whoisInfo += `<strong>${key}:</strong> ${value}<br>`;
                    }
                }
                
                Swal.fire({
                    title: `Whois Information for ${ip}`,
                    html: `<div style="text-align: left; max-height: 400px; overflow-y: auto;">${whoisInfo}</div>`,
                    width: '700px',
                    confirmButtonText: 'Close',
                    customClass: {
                        popup: 'swal-wide'
                    }
                });
            })
            .catch(error => {
                console.error('Error:', error);
                Swal.fire({
                    title: 'Error',
                    text: 'Could not fetch Whois information. Please try again.',
                    icon: 'error'
                });
            });
    }
    
    // Fetch location information
    function fetchLocation(ip) {
        if (!ip) {
            Swal.fire('Error', 'No IP address provided', 'error');
            return;
        }
        
        Swal.fire({
            title: 'Fetching Location...',
            text: 'Please wait while we retrieve location data',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        // Use a free IP geolocation API
        fetch(`https://ipapi.co/${ip}/json/`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    throw new Error(data.reason || 'Location data not available');
                }
                
                Swal.fire({
                    title: `Location Information for ${ip}`,
                    html: `
                        <div style="text-align: left;">
                            <p><strong>IP Address:</strong> ${data.ip}</p>
                            <p><strong>Country:</strong> ${data.country_name} (${data.country_code})</p>
                            <p><strong>Region:</strong> ${data.region} - ${data.region_code}</p>
                            <p><strong>City:</strong> ${data.city}</p>
                            <p><strong>Postal Code:</strong> ${data.postal}</p>
                            <p><strong>Latitude:</strong> ${data.latitude}</p>
                            <p><strong>Longitude:</strong> ${data.longitude}</p>
                            <p><strong>Timezone:</strong> ${data.timezone}</p>
                            <p><strong>Currency:</strong> ${data.currency}</p>
                            <p><strong>ISP:</strong> ${data.org}</p>
                            <p><strong>ASN:</strong> ${data.asn}</p>
                        </div>
                    `,
                    width: '600px',
                    confirmButtonText: 'Close',
                    showCloseButton: true
                });
            })
            .catch(error => {
                console.error('Error:', error);
                Swal.fire({
                    title: 'Error',
                    text: 'Could not fetch location information. Please try again.',
                    icon: 'error'
                });
            });
    }
    
    // Refresh data
    function refreshData() {
        Swal.fire({
            title: 'Refreshing Data...',
            text: 'Please wait while we refresh the tracking data',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });
        
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    }
    
    // Initialize tooltips
    $(document).ready(function() {
        // Enable Bootstrap tooltips
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[title]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Auto-refresh every 60 seconds
        setInterval(function() {
            // You can implement AJAX refresh here instead of full page reload
            console.log('Auto-refresh triggered');
        }, 60000);
    });
</script>

<style>
    /* Custom styles for this page */
    .swal-wide {
        width: 700px !important;
        max-width: 90vw;
    }
    
    .text-purple {
        color: #6f42c1;
    }
    
    /* Scrollbar styling */
    .table-responsive::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    .table-responsive::-webkit-scrollbar-track {
        background: #1e1e1e;
    }
    
    .table-responsive::-webkit-scrollbar-thumb {
        background: #495057;
        border-radius: 4px;
    }
    
    .table-responsive::-webkit-scrollbar-thumb:hover {
        background: #6c757d;
    }
    
    /* Ensure details panels are properly styled */
    .bg-dark.rounded {
        background-color: #1a1a1a !important;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .btn-group-sm .btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
        }
        
        .dashboard-card {
            padding: 15px;
        }
        
        .stat-number {
            font-size: 1.8rem;
        }
    }
</style>

<?php
require_once '../includes/footer.php';
?>