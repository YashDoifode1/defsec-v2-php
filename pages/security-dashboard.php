<?php
// security-dashboard.php
ob_start(); // Start output buffering
require_once '../includes/header.php';
require_once '../includes/auth.php';

// Check if user is logged in and variables are set
if (!$auth->isLoggedIn()) {
    ob_end_clean(); // Clean the buffer
    header("Location: login.php");
    exit();
}

// Ensure variables are set
$userId = $_SESSION['user_id'] ?? 0;
$websiteId = $_SESSION['website_id'] ?? 0;

/**
 * -------------------------------------------------
 * DASHBOARD DATA FUNCTIONS
 * -------------------------------------------------
 */

/**
 * Map / Geo request data
 * Uses logs (geo) + access_logs (tenant isolation)
 */
function getRequestData($pdo, int $userId, int $websiteId): array
{
    $stmt = $pdo->prepare("
        SELECT 
            l.country,
            l.latitude,
            l.longitude,
            a.ip_address AS ip,
            COUNT(*) AS requests
        FROM access_logs a
        JOIN logs l ON l.ip = a.ip_address
        WHERE a.user_id = :user_id
          AND a.website_id = :website_id
          AND l.latitude IS NOT NULL
          AND l.longitude IS NOT NULL
        GROUP BY l.country, l.latitude, l.longitude, a.ip_address
    ");

    $stmt->execute([
        ':user_id'    => $userId,
        ':website_id' => $websiteId
    ]);

    return $stmt->fetchAll();
}

/**
 * Attack summary (pie chart)
 */
function getAttackSummary($pdo, int $userId, int $websiteId): array
{
    $stmt = $pdo->prepare("
        SELECT attack_type, severity, COUNT(*) AS count
        FROM attack_logs
        WHERE user_id = :user_id
          AND website_id = :website_id
        GROUP BY attack_type, severity
    ");

    $stmt->execute([
        ':user_id'    => $userId,
        ':website_id' => $websiteId
    ]);

    return $stmt->fetchAll();
}

/**
 * Recent attacks table
 * NOTE: uses `timestamp` (NOT created_at)
 */
function getRecentAttacks($pdo, int $userId, int $websiteId): array
{
    $stmt = $pdo->prepare("
        SELECT *
        FROM attack_logs
        WHERE user_id = :user_id
          AND website_id = :website_id
        ORDER BY timestamp DESC
        LIMIT 5
    ");

    $stmt->execute([
        ':user_id'    => $userId,
        ':website_id' => $websiteId
    ]);

    return $stmt->fetchAll();
}

/**
 * Key traffic metrics
 */
function getTrafficMetrics($pdo, int $userId, int $websiteId): array
{
    // Requests per minute
    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM access_logs
        WHERE user_id = :user_id
          AND website_id = :website_id
          AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
    ");
    $stmt->execute([
        ':user_id'    => $userId,
        ':website_id' => $websiteId
    ]);
    $rpm = (int)$stmt->fetchColumn();

    // Threats last hour
    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM attack_logs
        WHERE user_id = :user_id
          AND website_id = :website_id
          AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    ");
    $stmt->execute([
        ':user_id'    => $userId,
        ':website_id' => $websiteId
    ]);
    $threats = (int)$stmt->fetchColumn();

    return [
        'requests_per_minute' => $rpm,
        'threats_detected'    => $threats,
        'traffic_trend'       => $rpm > 100 ? 'HIGH' : 'MEDIUM'
    ];
}

/**
 * -------------------------------------------------
 * FETCH DASHBOARD DATA
 * -------------------------------------------------
 */
$requestData   = getRequestData($pdo, $userId, $websiteId);
$attackSummary = getAttackSummary($pdo, $userId, $websiteId);
$recentAttacks = getRecentAttacks($pdo, $userId, $websiteId);
$metrics       = getTrafficMetrics($pdo, $userId, $websiteId);

/**
 * -------------------------------------------------
 * OPTIONAL: PREPARE CHART DATA (REAL DATA)
 * -------------------------------------------------
 */
$chartLabels = [];
$chartValues = [];

foreach ($attackSummary as $row) {
    $chartLabels[] = $row['attack_type'] . ' (' . $row['severity'] . ')';
    $chartValues[] = (int)$row['count'];
}
?>

<div class="row g-4">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1">Security Dashboard</h2>
                <p class="text-muted mb-0">Real-time monitoring and threat intelligence</p>
            </div>
            <div>
                <span class="badge bg-light text-dark me-3">
                    <i class="fas fa-sync-alt me-1"></i> Last updated: <?php echo date('Y-m-d H:i:s'); ?>
                </span>
                <button class="btn btn-outline-primary" onclick="location.reload()">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
            </div>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="text-muted mb-2">Total Threats</div>
                    <div class="stat-number text-danger"><?php echo $metrics['threats_detected']; ?></div>
                    <div class="text-danger small">
                        <i class="fas fa-skull-crossbones"></i> Last hour
                    </div>
                </div>
                <div class="text-danger">
                    <i class="fas fa-skull-crossbones fa-2x"></i>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="text-muted mb-2">Requests/Minute</div>
                    <div class="stat-number text-warning"><?php echo $metrics['requests_per_minute']; ?></div>
                    <div class="text-success small">
                        <i class="fas fa-chart-line"></i> Live
                    </div>
                </div>
                <div class="text-warning">
                    <i class="fas fa-shield-alt fa-2x"></i>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="text-muted mb-2">System Health</div>
                    <div class="stat-number text-success"><?php echo $metrics['traffic_trend'] == 'HIGH' ? 'Good' : 'Normal'; ?></div>
                    <div class="text-success small">
                        <i class="fas fa-heartbeat"></i> Operational
                    </div>
                </div>
                <div class="text-success">
                    <i class="fas fa-check-circle fa-2x"></i>
                </div>
            </div>
        </div>
    </div>

    <div class="col-xl-3 col-md-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="text-muted mb-2">Active Locations</div>
                    <div class="stat-number text-info"><?php echo count($requestData); ?></div>
                    <div class="text-info small">
                        <i class="fas fa-map-marker-alt"></i> Worldwide
                    </div>
                </div>
                <div class="text-info">
                    <i class="fas fa-globe-americas fa-2x"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Map and Attack Summary Row -->
    <div class="col-xl-8">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-globe-americas me-2"></i>Request Origins Map</h5>
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                        <i class="fas fa-filter me-1"></i> Filter
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="#">Last 24 hours</a></li>
                        <li><a class="dropdown-item" href="#">Last 7 days</a></li>
                        <li><a class="dropdown-item" href="#">All time</a></li>
                    </ul>
                </div>
            </div>
            <div id="map" style="height: 400px; border-radius: 8px;"></div>
        </div>
    </div>

    <div class="col-xl-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-exclamation-triangle me-2"></i>Threat Alerts</h5>
            
            <div class="alert alert-danger mb-3">
                <div class="d-flex align-items-center">
                    <i class="fas fa-fire me-3"></i>
                    <div>
                        <strong>High Priority</strong><br>
                        <small>Suspicious login attempt detected</small>
                        <div class="text-muted x-small mt-1"><i class="fas fa-clock me-1"></i> 10 min ago</div>
                    </div>
                </div>
            </div>
            
            <div class="alert alert-warning mb-3">
                <div class="d-flex align-items-center">
                    <i class="fas fa-exclamation-circle me-3"></i>
                    <div>
                        <strong>Medium Priority</strong><br>
                        <small>Unusual activity detected</small>
                        <div class="text-muted x-small mt-1"><i class="fas fa-clock me-1"></i> 30 min ago</div>
                    </div>
                </div>
            </div>
            
            <div class="alert alert-info">
                <div class="d-flex align-items-center">
                    <i class="fas fa-info-circle me-3"></i>
                    <div>
                        <strong>Low Priority</strong><br>
                        <small>Port scanning detected</small>
                        <div class="text-muted x-small mt-1"><i class="fas fa-clock me-1"></i> 1 hour ago</div>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-3">
                <a href="#" class="btn btn-outline-primary btn-sm">
                    View All Alerts <i class="fas fa-arrow-right ms-1"></i>
                </a>
            </div>
        </div>
    </div>

    <!-- Attack Summary and Recent Activity -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Attack Summary</h5>
                <select class="form-select form-select-sm w-auto" id="chartTimeRange">
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>
            </div>
            <div id="attackChart" style="height: 300px;"></div>
        </div>
    </div>

    <div class="col-xl-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-list me-2"></i>Recent Attacks</h5>
                <a href="web-security.php" class="btn btn-outline-primary btn-sm">
                    View All <i class="fas fa-arrow-right ms-1"></i>
                </a>
            </div>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($recentAttacks as $attack): ?>
                        <tr>
                            <td>
                                <small><?php echo date('H:i', strtotime($attack['timestamp'])); ?></small><br>
                                <small class="text-muted"><?php echo date('M d', strtotime($attack['timestamp'])); ?></small>
                            </td>
                            <td>
                                <span class="badge bg-dark border"><?php echo htmlspecialchars($attack['attack_type']); ?></span>
                            </td>
                            <td>
                                <?php 
                                $severityColor = match(strtolower($attack['severity'])) {
                                    'critical' => 'danger',
                                    'high' => 'warning',
                                    'medium' => 'info',
                                    default => 'secondary'
                                };
                                ?>
                                <span class="badge bg-<?php echo $severityColor; ?>">
                                    <?php echo htmlspecialchars($attack['severity']); ?>
                                </span>
                            </td>
                            <td>
                                <code><?php echo htmlspecialchars($attack['ip_address']); ?></code>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Traffic Analytics -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Traffic Analytics</h5>
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-secondary btn-sm active" data-range="hour">Hour</button>
                    <button type="button" class="btn btn-outline-secondary btn-sm" data-range="day">Day</button>
                    <button type="button" class="btn btn-outline-secondary btn-sm" data-range="week">Week</button>
                </div>
            </div>
            <div id="trafficChart" style="height: 250px;"></div>
        </div>
    </div>

    <!-- Security Status -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Security Status</h5>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <div class="d-flex align-items-center p-3 bg-dark rounded">
                        <div class="me-3">
                            <i class="fas fa-firewall fa-2x text-primary"></i>
                        </div>
                        <div>
                            <div class="fw-bold">Firewall</div>
                            <div class="text-success small">
                                <i class="fas fa-check-circle"></i> Active
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="d-flex align-items-center p-3 bg-dark rounded">
                        <div class="me-3">
                            <i class="fas fa-shield-virus fa-2x text-success"></i>
                        </div>
                        <div>
                            <div class="fw-bold">Malware Protection</div>
                            <div class="text-success small">
                                <i class="fas fa-check-circle"></i> Enabled
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="d-flex align-items-center p-3 bg-dark rounded">
                        <div class="me-3">
                            <i class="fas fa-user-shield fa-2x text-warning"></i>
                        </div>
                        <div>
                            <div class="fw-bold">DDoS Protection</div>
                            <div class="text-warning small">
                                <i class="fas fa-exclamation-triangle"></i> Medium Load
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="d-flex align-items-center p-3 bg-dark rounded">
                        <div class="me-3">
                            <i class="fas fa-database fa-2x text-info"></i>
                        </div>
                        <div>
                            <div class="fw-bold">Backup Status</div>
                            <div class="text-success small">
                                <i class="fas fa-check-circle"></i> Last: 2 hours ago
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Top Threat Sources -->
    <div class="col-xl-6">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-radar me-2"></i>Top Threat Sources</h5>
                <span class="badge bg-danger">Live</span>
            </div>
            
            <div class="table-responsive">
                <table class="table table-dark table-borderless table-hover">
                    <thead>
                        <tr>
                            <th>Country</th>
                            <th>IP Address</th>
                            <th>Threats</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        // Display request data as threat sources
                        foreach ($requestData as $source): 
                            if ($source['requests'] > 0):
                        ?>
                            <tr>
                                <td>
                                    <div class="d-flex align-items-center">
                                        <i class="fas fa-globe me-2 text-muted"></i>
                                        <div>
                                            <div class="fw-bold"><?php echo htmlspecialchars($source['country'] ?? 'Unknown'); ?></div>
                                            <small class="text-muted"><?php echo $source['requests']; ?> requests</small>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <code><?php echo htmlspecialchars($source['ip']); ?></code>
                                </td>
                                <td>
                                    <span class="badge bg-<?php echo $source['requests'] > 10 ? 'danger' : 'warning'; ?>">
                                        <?php echo $source['requests']; ?> threats
                                    </span>
                                </td>
                                <td>
                                    <small>Recent</small><br>
                                    <small class="text-muted">Active</small>
                                </td>
                            </tr>
                        <?php 
                            endif;
                        endforeach; 
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
    $(document).ready(function() {
        // Initialize the map
        var map = L.map('map').setView([20, 0], 2);

        // Add OpenStreetMap tiles with dark theme
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(map);

        // Add request data to the map
        var requestData = <?php echo json_encode($requestData); ?>;
        
        // Create a feature group to store all markers
        var markers = L.layerGroup().addTo(map);
        
        // Add each request location to the map
        requestData.forEach(function(request) {
            var requests = parseInt(request.requests);
            var color = '#007bff';
            
            if (requests >= 50) {
                color = '#dc3545';
            } else if (requests >= 10) {
                color = '#fd7e14';
            }
            
            // Create custom icon
            var icon = L.divIcon({
                html: `<div style="background-color: ${color}; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 10px ${color}80;"></div>`,
                iconSize: [12, 12],
                className: 'map-marker-div'
            });
            
            var marker = L.marker([request.latitude, request.longitude], {icon: icon})
                .addTo(markers)
                .bindPopup(`
                    <div class="map-popup">
                        <h6><i class="fas fa-map-marker-alt me-2"></i>${request.country || 'Unknown'}</h6>
                        <div class="mb-2"><strong>IP:</strong> <code>${request.ip}</code></div>
                        <div class="mb-2"><strong>Requests:</strong> <span class="badge bg-primary">${requests}</span></div>
                        <div class="small text-muted">
                            <i class="fas fa-location-dot me-1"></i>
                            ${parseFloat(request.latitude).toFixed(4)}, ${parseFloat(request.longitude).toFixed(4)}
                        </div>
                    </div>
                `);
            
            // Add pulsating effect for high request areas
            if (requests > 10) {
                L.circle([request.latitude, request.longitude], {
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.2,
                    radius: requests * 2000
                }).addTo(markers);
            }
        });

        // Initialize ApexCharts for attack summary
        var attackChart = new ApexCharts(document.querySelector("#attackChart"), {
            series: <?php echo json_encode($chartValues); ?>,
            chart: {
                type: 'donut',
                height: 300,
                background: 'transparent',
                foreColor: '#e9ecef'
            },
            labels: <?php echo json_encode($chartLabels); ?>,
            colors: ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d'],
            dataLabels: {
                enabled: true,
                formatter: function(val, opts) {
                    return opts.w.config.series[opts.seriesIndex]
                }
            },
            legend: {
                position: 'bottom',
                labels: {
                    colors: '#e9ecef'
                }
            },
            responsive: [{
                breakpoint: 480,
                options: {
                    chart: {
                        width: 200
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }]
        });

        attackChart.render();

        // Traffic chart
        var trafficChart = new ApexCharts(document.querySelector("#trafficChart"), {
            series: [{
                name: 'Requests',
                data: [30, 40, 35, 50, 49, 60, 70, 91, 125, 95, 110, 130]
            }],
            chart: {
                type: 'area',
                height: 250,
                background: 'transparent',
                foreColor: '#e9ecef',
                toolbar: {
                    show: false
                }
            },
            colors: ['#4e54c8'],
            dataLabels: {
                enabled: false
            },
            stroke: {
                curve: 'smooth',
                width: 2
            },
            fill: {
                type: 'gradient',
                gradient: {
                    shadeIntensity: 1,
                    opacityFrom: 0.7,
                    opacityTo: 0.2,
                    stops: [0, 90, 100]
                }
            },
            xaxis: {
                categories: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'],
                labels: {
                    style: {
                        colors: '#6c757d'
                    }
                }
            },
            yaxis: {
                labels: {
                    style: {
                        colors: '#6c757d'
                    }
                }
            },
            grid: {
                borderColor: '#495057',
                strokeDashArray: 4
            },
            tooltip: {
                theme: 'dark'
            }
        });

        trafficChart.render();

        // Time range buttons
        $('[data-range]').click(function() {
            $('[data-range]').removeClass('active');
            $(this).addClass('active');
        });

        // Chart time range selector
        $('#chartTimeRange').change(function() {
            console.log('Time range changed to:', $(this).val());
        });

        // Auto-refresh every 30 seconds
        setInterval(function() {
            // You can implement AJAX calls here to update data without full page reload
            console.log('Auto-refresh triggered');
        }, 30000);
    });
</script>

<style>
    .map-marker-div {
        background: transparent !important;
        border: none !important;
    }
    
    .map-popup {
        color: #212529;
        min-width: 200px;
    }
    
    .map-popup h6 {
        color: #343a40;
        margin-bottom: 10px;
    }
    
    .leaflet-popup-content-wrapper {
        border-radius: 8px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }
    
    .leaflet-popup-tip {
        background: white;
    }
</style>

<?php
require_once '../includes/footer.php';
?>