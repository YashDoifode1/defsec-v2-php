<?php
// view-analysis.php
require_once '../includes/header.php';
require_once 'EmailAnalyzer.php';

if (!$isLoggedIn) {
    header("Location: " . APP_URL . "/auth/login.php");
    exit();
}

$userId = $_SESSION['user_id'] ?? 1;
$analysisId = $_GET['id'] ?? 0;

// Get analysis details
$stmt = $pdo->prepare("SELECT * FROM email_analyses WHERE id = ? AND user_id = ?");
$stmt->execute([$analysisId, $userId]);
$analysis = $stmt->fetch();

if (!$analysis) {
    $_SESSION['error'] = "Analysis not found";
    header("Location: email-analysis.php");
    exit();
}

// Get IPs for this analysis
$ipStmt = $pdo->prepare("SELECT * FROM email_ips WHERE analysis_id = ? ORDER BY hop_number");
$ipStmt->execute([$analysisId]);
$ips = $ipStmt->fetchAll();

// Get attachments if any
$attStmt = $pdo->prepare("SELECT * FROM email_attachments WHERE analysis_id = ?");
$attStmt->execute([$analysisId]);
$attachments = $attStmt->fetchAll();

// Parse raw headers for display
$rawHeaders = $analysis['raw_headers'];
$headerLines = explode("\n", $rawHeaders);
?>

<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-envelope-open-text me-2"></i>Email Analysis Details</h2>
                <p class="text-muted mb-0">Analysis ID: #<?php echo $analysis['id']; ?> | <?php echo date('F j, Y H:i:s', strtotime($analysis['analysis_date'])); ?></p>
            </div>
            <div>
                <a href="export-analysis.php?id=<?php echo $analysis['id']; ?>" class="btn btn-primary me-2">
                    <i class="fas fa-download me-2"></i>Export CSV
                </a>
                <a href="email-analysis.php" class="btn btn-outline-secondary">
                    <i class="fas fa-arrow-left me-2"></i>Back to Analyzer
                </a>
            </div>
        </div>
    </div>

    <!-- Threat Score Overview -->
    <div class="col-12">
        <div class="dashboard-card">
            <div class="row align-items-center">
                <div class="col-md-3 text-center">
                    <div class="position-relative d-inline-block">
                        <div id="threatGauge" style="width: 150px; height: 150px;"></div>
                        <div class="position-absolute top-50 start-50 translate-middle text-center">
                            <div class="h3 mb-0"><?php echo $analysis['spam_score']; ?></div>
                            <small class="text-muted">/100</small>
                        </div>
                    </div>
                    <h5 class="mt-2">Threat Score</h5>
                </div>
                <div class="col-md-9">
                    <div class="row g-3">
                        <div class="col-md-4">
                            <div class="bg-dark p-3 rounded border border-secondary">
                                <small class="text-muted">SPF Result</small>
                                <div class="d-flex align-items-center mt-2">
                                    <?php
                                    $spfClass = 'secondary';
                                    if ($analysis['spf_result'] === 'pass') $spfClass = 'success';
                                    elseif ($analysis['spf_result'] === 'fail') $spfClass = 'danger';
                                    elseif ($analysis['spf_result'] === 'softfail') $spfClass = 'warning';
                                    ?>
                                    <span class="badge bg-<?php echo $spfClass; ?> me-2" style="font-size: 1rem;">
                                        <?php echo strtoupper($analysis['spf_result'] ?: 'N/A'); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="bg-dark p-3 rounded border border-secondary">
                                <small class="text-muted">DKIM Result</small>
                                <div class="d-flex align-items-center mt-2">
                                    <?php
                                    $dkimClass = 'secondary';
                                    if ($analysis['dkim_result'] === 'pass') $dkimClass = 'success';
                                    elseif ($analysis['dkim_result'] === 'fail') $dkimClass = 'danger';
                                    ?>
                                    <span class="badge bg-<?php echo $dkimClass; ?> me-2" style="font-size: 1rem;">
                                        <?php echo strtoupper($analysis['dkim_result'] ?: 'N/A'); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="bg-dark p-3 rounded border border-secondary">
                                <small class="text-muted">DMARC Result</small>
                                <div class="d-flex align-items-center mt-2">
                                    <?php
                                    $dmarcClass = 'secondary';
                                    if ($analysis['dmarc_result'] === 'pass') $dmarcClass = 'success';
                                    elseif ($analysis['dmarc_result'] === 'fail') $dmarcClass = 'danger';
                                    ?>
                                    <span class="badge bg-<?php echo $dmarcClass; ?> me-2" style="font-size: 1rem;">
                                        <?php echo strtoupper($analysis['dmarc_result'] ?: 'N/A'); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Basic Email Information -->
    <div class="col-md-8">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-info-circle me-2"></i>Email Information</h5>
            <table class="table table-dark table-striped">
                <tr>
                    <th style="width: 150px;">From:</th>
                    <td><?php echo htmlspecialchars($analysis['from_address'] ?: 'N/A'); ?></td>
                </tr>
                <tr>
                    <th>From Domain:</th>
                    <td>
                        <?php echo htmlspecialchars($analysis['from_domain'] ?: 'N/A'); ?>
                        <?php if ($analysis['from_domain']): ?>
                            <a href="https://www.virustotal.com/gui/domain/<?php echo urlencode($analysis['from_domain']); ?>" 
                               target="_blank" class="btn btn-sm btn-outline-primary ms-2">
                                <i class="fas fa-search"></i> VT
                            </a>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th>Subject:</th>
                    <td><?php echo htmlspecialchars($analysis['subject'] ?: 'N/A'); ?></td>
                </tr>
                <tr>
                    <th>Date Sent:</th>
                    <td><?php echo $analysis['date_sent'] ? date('F j, Y H:i:s', strtotime($analysis['date_sent'])) : 'N/A'; ?></td>
                </tr>
                <tr>
                    <th>Message-ID:</th>
                    <td><small><?php echo htmlspecialchars($analysis['message_id'] ?: 'N/A'); ?></small></td>
                </tr>
                <tr>
                    <th>Reply-To:</th>
                    <td><?php echo htmlspecialchars($analysis['reply_to'] ?: 'N/A'); ?></td>
                </tr>
                <tr>
                    <th>Return-Path:</th>
                    <td><?php echo htmlspecialchars($analysis['return_path'] ?: 'N/A'); ?></td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Quick Stats -->
    <div class="col-md-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-chart-pie me-2"></i>Quick Stats</h5>
            <div class="text-center mb-4">
                <div class="display-4"><?php echo count($ips); ?></div>
                <small class="text-muted">Total Hops</small>
            </div>
            
            <?php
            $vpnCount = 0;
            $torCount = 0;
            $proxyCount = 0;
            $highRiskCount = 0;
            
            foreach ($ips as $ip) {
                if ($ip['is_vpn']) $vpnCount++;
                if ($ip['is_tor']) $torCount++;
                if ($ip['is_proxy']) $proxyCount++;
                if ($ip['threat_score'] > 50) $highRiskCount++;
            }
            ?>
            
            <div class="list-group list-group-flush bg-transparent">
                <div class="list-group-item bg-transparent text-light d-flex justify-content-between align-items-center">
                    VPN Detected
                    <span class="badge bg-warning rounded-pill"><?php echo $vpnCount; ?></span>
                </div>
                <div class="list-group-item bg-transparent text-light d-flex justify-content-between align-items-center">
                    TOR Exit Nodes
                    <span class="badge bg-danger rounded-pill"><?php echo $torCount; ?></span>
                </div>
                <div class="list-group-item bg-transparent text-light d-flex justify-content-between align-items-center">
                    Proxy Servers
                    <span class="badge bg-info rounded-pill"><?php echo $proxyCount; ?></span>
                </div>
                <div class="list-group-item bg-transparent text-light d-flex justify-content-between align-items-center">
                    High Risk IPs
                    <span class="badge bg-danger rounded-pill"><?php echo $highRiskCount; ?></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Map Visualization -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-map-marked-alt me-2"></i>Email Path Visualization</h5>
            <div id="emailPathMap" style="height: 450px; border-radius: 8px;"></div>
        </div>
    </div>

    <!-- IP Hops Details -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-network-wired me-2"></i>IP Hop Details</h5>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Hop</th>
                            <th>IP Address</th>
                            <th>Hostname / Reverse DNS</th>
                            <th>Location</th>
                            <th>ISP / ASN</th>
                            <th>Security Flags</th>
                            <th>Threat Score</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($ips as $index => $ip): 
                            $threatClass = 'success';
                            if ($ip['threat_score'] > 70) $threatClass = 'danger';
                            elseif ($ip['threat_score'] > 40) $threatClass = 'warning';
                            elseif ($ip['threat_score'] > 20) $threatClass = 'info';
                        ?>
                        <tr>
                            <td><span class="badge bg-secondary">#<?php echo $ip['hop_number']; ?></span></td>
                            <td>
                                <code><?php echo htmlspecialchars($ip['ip_address']); ?></code>
                                <button class="btn btn-sm btn-outline-info ms-1 copy-ip" data-ip="<?php echo $ip['ip_address']; ?>" title="Copy IP">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </td>
                            <td>
                                <small><strong>Host:</strong> <?php echo htmlspecialchars($ip['hostname'] ?: 'N/A'); ?></small><br>
                                <small class="text-muted"><strong>RDNS:</strong> <?php echo htmlspecialchars($ip['reverse_dns'] ?: 'N/A'); ?></small>
                            </td>
                            <td>
                                <?php if ($ip['country']): ?>
                                    <span title="<?php echo htmlspecialchars($ip['country']); ?>">
                                        <img src="https://flagcdn.com/16x12/<?php echo strtolower($ip['country_code']); ?>.png" class="me-1">
                                        <?php echo htmlspecialchars($ip['city'] ? $ip['city'] . ', ' : ''); ?>
                                        <?php echo htmlspecialchars($ip['country']); ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-muted">Unknown</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <small><?php echo htmlspecialchars($ip['isp'] ?: 'N/A'); ?></small><br>
                                <small class="text-muted"><?php echo htmlspecialchars($ip['asn'] ?: ''); ?></small>
                            </td>
                            <td>
                                <?php if ($ip['is_vpn']): ?>
                                    <span class="badge bg-warning me-1" title="VPN Detected"><i class="fas fa-mask"></i> VPN</span>
                                <?php endif; ?>
                                <?php if ($ip['is_tor']): ?>
                                    <span class="badge bg-danger me-1" title="TOR Exit Node"><i class="fas fa-user-secret"></i> TOR</span>
                                <?php endif; ?>
                                <?php if ($ip['is_proxy']): ?>
                                    <span class="badge bg-info me-1" title="Proxy Detected"><i class="fas fa-globe"></i> Proxy</span>
                                <?php endif; ?>
                                <?php if ($ip['is_datacenter']): ?>
                                    <span class="badge bg-secondary me-1" title="Datacenter IP"><i class="fas fa-server"></i> DC</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="progress" style="height: 20px; width: 100px;">
                                    <div class="progress-bar bg-<?php echo $threatClass; ?>" 
                                         style="width: <?php echo $ip['threat_score']; ?>%">
                                        <?php echo $ip['threat_score']; ?>%
                                    </div>
                                </div>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary ip-details-btn" 
                                        data-ip="<?php echo $ip['ip_address']; ?>"
                                        data-rdap='<?php echo htmlspecialchars($ip['rdap_data'] ?? ''); ?>'>
                                    <i class="fas fa-info-circle"></i>
                                </button>
                                <a href="https://www.virustotal.com/gui/ip-address/<?php echo urlencode($ip['ip_address']); ?>" 
                                   target="_blank" class="btn btn-sm btn-outline-danger">
                                    <i class="fas fa-virus"></i>
                                </a>
                                <a href="https://www.abuseipdb.com/check/<?php echo urlencode($ip['ip_address']); ?>" 
                                   target="_blank" class="btn btn-sm btn-outline-warning">
                                    <i class="fas fa-exclamation-triangle"></i>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Authentication Results Details -->
    <?php if ($analysis['authentication_results']): ?>
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Authentication Results</h5>
            <div class="bg-dark p-3 rounded border border-secondary">
                <pre class="mb-0 text-light" style="white-space: pre-wrap; word-wrap: break-word;"><?php echo htmlspecialchars($analysis['authentication_results']); ?></pre>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Attachments Section -->
    <?php if (!empty($attachments)): ?>
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-paperclip me-2"></i>Attachments</h5>
            <div class="table-responsive">
                <table class="table table-dark">
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Type</th>
                            <th>Size</th>
                            <th>MD5 Hash</th>
                            <th>SHA256</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($attachments as $att): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($att['filename']); ?></td>
                            <td><?php echo htmlspecialchars($att['file_type']); ?></td>
                            <td><?php echo round($att['file_size'] / 1024, 2); ?> KB</td>
                            <td><small><?php echo htmlspecialchars($att['md5_hash']); ?></small></td>
                            <td><small><?php echo htmlspecialchars(substr($att['sha256_hash'], 0, 16)) . '...'; ?></small></td>
                            <td>
                                <?php if ($att['is_malicious']): ?>
                                    <span class="badge bg-danger">Malicious</span>
                                <?php else: ?>
                                    <span class="badge bg-success">Clean</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Raw Headers -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4">
                <i class="fas fa-code me-2"></i>Raw Headers
                <button class="btn btn-sm btn-outline-secondary ms-2" onclick="toggleRawHeaders()">
                    <i class="fas fa-eye"></i> Toggle View
                </button>
            </h5>
            <div id="rawHeaders" class="bg-dark p-3 rounded border border-secondary" style="max-height: 400px; overflow-y: auto; display: none;">
                <pre class="mb-0 text-light" style="white-space: pre-wrap; word-wrap: break-word; font-size: 0.85rem;"><?php echo htmlspecialchars($rawHeaders); ?></pre>
            </div>
        </div>
    </div>
</div>

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-info-circle me-2"></i>IP Address Intelligence</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="ipDetailsContent">
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Gathering intelligence data...</p>
                    </div>
                </div>
            </div>
            <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="#" id="rdapLookupBtn" class="btn btn-info" target="_blank">
                    <i class="fas fa-search me-1"></i> RDAP Lookup
                </a>
                <a href="#" id="vtLookupBtn" class="btn btn-primary" target="_blank">
                    <i class="fas fa-virus me-1"></i> VirusTotal
                </a>
                <a href="#" id="abuseLookupBtn" class="btn btn-warning" target="_blank">
                    <i class="fas fa-exclamation-triangle me-1"></i> AbuseIPDB
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Include required libraries -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>

<script>
    let map = null;
    let markers = [];
    let polyline = null;

    <?php if (!empty($ips)): ?>
    // Initialize map
    document.addEventListener('DOMContentLoaded', function() {
        initMap();
        initThreatGauge();
    });

    function initMap() {
        const ipData = <?php echo json_encode($ips); ?>;
        const validLocations = ipData.filter(ip => ip.latitude && ip.longitude && !ip.is_private);
        
        if (validLocations.length === 0) {
            document.getElementById('emailPathMap').innerHTML = '<div class="text-center py-5"><i class="fas fa-map-marked-alt fa-3x text-muted mb-3"></i><p>No geographic data available for visualization</p></div>';
            return;
        }
        
        // Calculate bounds
        const bounds = L.latLngBounds(validLocations.map(ip => [parseFloat(ip.latitude), parseFloat(ip.longitude)]));
        
        // Initialize map
        map = L.map('emailPathMap').fitBounds(bounds);
        
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(map);
        
        // Add markers for each hop
        validLocations.forEach((ip, index) => {
            const threatColor = ip.threat_score > 70 ? '#dc3545' : (ip.threat_score > 40 ? '#ffc107' : '#28a745');
            const iconType = ip.is_vpn ? '🛡️' : (ip.is_tor ? '🌐' : '📧');
            
            const popupContent = `
                <div style="min-width: 250px; background: #212529; color: #fff;">
                    <h6 class="mb-2">Hop #${ip.hop_number}</h6>
                    <table class="table table-sm table-dark">
                        <tr><td>IP:</td><td><code>${ip.ip_address}</code></td></tr>
                        <tr><td>Location:</td><td>${ip.city ? ip.city + ', ' : ''}${ip.country || 'Unknown'}</td></tr>
                        <tr><td>ISP:</td><td>${ip.isp || 'N/A'}</td></tr>
                        <tr><td>ASN:</td><td>${ip.asn || 'N/A'}</td></tr>
                        <tr><td>Threat:</td><td><span class="badge bg-${ip.threat_score > 70 ? 'danger' : (ip.threat_score > 40 ? 'warning' : 'success')}">${ip.threat_score}%</span></td></tr>
                        ${ip.is_vpn ? '<tr><td colspan="2"><span class="badge bg-warning">⚠️ VPN Detected</span></td></tr>' : ''}
                        ${ip.is_tor ? '<tr><td colspan="2"><span class="badge bg-danger">🌐 TOR Exit Node</span></td></tr>' : ''}
                    </table>
                </div>
            `;
            
            const marker = L.marker([parseFloat(ip.latitude), parseFloat(ip.longitude)], {
                icon: L.divIcon({
                    className: 'custom-marker',
                    html: `<div style="background: ${threatColor}; color: white; border-radius: 50%; 
                                 width: 36px; height: 36px; display: flex; align-items: center; 
                                 justify-content: center; border: 3px solid white; font-weight: bold;
                                 box-shadow: 0 2px 5px rgba(0,0,0,0.3);">
                            ${ip.hop_number}
                           </div>`,
                    iconSize: [36, 36]
                })
            }).bindPopup(popupContent);
            
            marker.addTo(map);
            markers.push(marker);
        });
        
        // Draw path with animation
        if (validLocations.length > 1) {
            const points = validLocations.map(ip => [parseFloat(ip.latitude), parseFloat(ip.longitude)]);
            polyline = L.polyline.antPath(points, {
                color: '#4e54c8',
                weight: 4,
                opacity: 0.8,
                pulseColor: '#ffffff',
                delay: 800,
                dashArray: [10, 20],
                pulseRadius: 25
            }).addTo(map);
        }
    }

    function initThreatGauge() {
        const score = <?php echo $analysis['spam_score']; ?>;
        const color = score >= 70 ? '#dc3545' : (score >= 40 ? '#ffc107' : '#28a745');
        
        const options = {
            series: [score],
            chart: {
                type: 'radialBar',
                height: 150,
                sparkline: { enabled: true }
            },
            plotOptions: {
                radialBar: {
                    startAngle: -90,
                    endAngle: 90,
                    track: {
                        background: '#333',
                        strokeWidth: '97%',
                        margin: 5
                    },
                    dataLabels: {
                        name: { show: false },
                        value: { show: false }
                    }
                }
            },
            fill: {
                colors: [color]
            }
        };

        const chart = new ApexCharts(document.querySelector("#threatGauge"), options);
        chart.render();
    }
    <?php endif; ?>

    // IP Details Modal
    async function showIPDetails(ip, rdapData) {
        const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
        
        document.getElementById('ipDetailsContent').innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2">Fetching intelligence data for ${ip}...</p>
            </div>
        `;
        
        modal.show();
        
        try {
            // Fetch multiple data sources
            const [geoData, whoisData, proxyData] = await Promise.all([
                fetch(`https://ipapi.co/${ip}/json/`).then(r => r.json()).catch(() => null),
                fetch(`https://ipwhois.pro/json/${ip}?key=YOUR_KEY`).then(r => r.json()).catch(() => null),
                fetch(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1&risk=1`).then(r => r.json()).catch(() => null)
            ]);
            
            let html = `
                <div class="row">
                    <div class="col-md-6">
                        <div class="card bg-dark border-secondary mb-3">
                            <div class="card-header border-secondary">
                                <h6 class="mb-0"><i class="fas fa-map-marker-alt me-2"></i>Geolocation</h6>
                            </div>
                            <div class="card-body">
                                <table class="table table-dark table-sm">
                                    <tr><th>IP Address</th><td><code>${ip}</code></td></tr>
                                    <tr><th>Country</th><td>${geoData?.country_name || 'N/A'} ${geoData?.country_code ? `<img src="https://flagcdn.com/16x12/${geoData.country_code.toLowerCase()}.png" class="ms-1">` : ''}</td></tr>
                                    <tr><th>Region</th><td>${geoData?.region || 'N/A'}</td></tr>
                                    <tr><th>City</th><td>${geoData?.city || 'N/A'}</td></tr>
                                    <tr><th>Postal Code</th><td>${geoData?.postal || 'N/A'}</td></tr>
                                    <tr><th>Lat/Long</th><td>${geoData?.latitude || 'N/A'}, ${geoData?.longitude || 'N/A'}</td></tr>
                                    <tr><th>Timezone</th><td>${geoData?.timezone || 'N/A'}</td></tr>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card bg-dark border-secondary mb-3">
                            <div class="card-header border-secondary">
                                <h6 class="mb-0"><i class="fas fa-shield-alt me-2"></i>Network & Security</h6>
                            </div>
                            <div class="card-body">
                                <table class="table table-dark table-sm">
                                    <tr><th>ISP</th><td>${geoData?.org || 'N/A'}</td></tr>
                                    <tr><th>ASN</th><td>${proxyData?.[ip]?.asn || geoData?.asn || 'N/A'}</td></tr>
                                    <tr><th>Organization</th><td>${geoData?.org || 'N/A'}</td></tr>
                                    <tr><th>VPN Detected</th><td>${proxyData?.[ip]?.proxy === 'yes' ? '<span class="badge bg-warning">Yes</span>' : '<span class="badge bg-success">No</span>'}</td></tr>
                                    <tr><th>TOR Exit Node</th><td>${proxyData?.[ip]?.type === 'TOR' ? '<span class="badge bg-danger">Yes</span>' : '<span class="badge bg-success">No</span>'}</td></tr>
                                    <tr><th>Proxy Detected</th><td>${proxyData?.[ip]?.proxy === 'yes' && proxyData?.[ip]?.type !== 'TOR' ? '<span class="badge bg-warning">Yes</span>' : '<span class="badge bg-success">No</span>'}</td></tr>
                                    <tr><th>Risk Score</th><td><span class="badge bg-${proxyData?.[ip]?.risk > 50 ? 'danger' : (proxyData?.[ip]?.risk > 25 ? 'warning' : 'success')}">${proxyData?.[ip]?.risk || '0'}%</span></td></tr>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Add WHOIS data if available
            if (whoisData && whoisData.success) {
                html += `
                    <div class="row mt-3">
                        <div class="col-12">
                            <div class="card bg-dark border-secondary">
                                <div class="card-header border-secondary">
                                    <h6 class="mb-0"><i class="fas fa-building me-2"></i>WHOIS Information</h6>
                                </div>
                                <div class="card-body">
                                    <table class="table table-dark table-sm">
                                        <tr><th>Owner</th><td>${whoisData.owner || 'N/A'}</td></tr>
                                        <tr><th>Network</th><td>${whoisData.network || 'N/A'}</td></tr>
                                        <tr><th>Abuse Contact</th><td>${whoisData.abuse || 'N/A'}</td></tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            // Add RDAP data if available
            if (rdapData && rdapData !== 'null') {
                try {
                    const rdap = JSON.parse(rdapData);
                    html += `
                        <div class="row mt-3">
                            <div class="col-12">
                                <div class="card bg-dark border-secondary">
                                    <div class="card-header border-secondary">
                                        <h6 class="mb-0"><i class="fas fa-code me-2"></i>RDAP Data</h6>
                                    </div>
                                    <div class="card-body">
                                        <pre class="bg-black p-2 rounded small text-light" style="max-height: 200px; overflow-y: auto;">${JSON.stringify(rdap, null, 2)}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                } catch (e) {}
            }
            
            document.getElementById('ipDetailsContent').innerHTML = html;
            
            // Update external lookup buttons
            document.getElementById('rdapLookupBtn').href = `https://rdap.db.ripe.net/ip/${ip}`;
            document.getElementById('vtLookupBtn').href = `https://www.virustotal.com/gui/ip-address/${ip}`;
            document.getElementById('abuseLookupBtn').href = `https://www.abuseipdb.com/check/${ip}`;
            
        } catch (error) {
            document.getElementById('ipDetailsContent').innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error fetching IP details: ${error.message}
                </div>
            `;
        }
    }

    // Toggle raw headers
    function toggleRawHeaders() {
        const headers = document.getElementById('rawHeaders');
        if (headers.style.display === 'none') {
            headers.style.display = 'block';
        } else {
            headers.style.display = 'none';
        }
    }

    // Copy IP to clipboard
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.copy-ip').forEach(btn => {
            btn.addEventListener('click', function() {
                const ip = this.dataset.ip;
                navigator.clipboard.writeText(ip).then(() => {
                    // Show temporary tooltip
                    const originalTitle = this.title;
                    this.title = 'Copied!';
                    setTimeout(() => {
                        this.title = originalTitle;
                    }, 2000);
                });
            });
        });
        
        document.querySelectorAll('.ip-details-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const ip = this.dataset.ip;
                const rdap = this.dataset.rdap;
                showIPDetails(ip, rdap);
            });
        });
    });
</script>

<style>
    .custom-marker {
        background: transparent;
        border: none;
    }
    
    #emailPathMap {
        background: #1a1a1a;
        border: 1px solid #495057;
        border-radius: 8px;
        z-index: 1;
    }
    
    .leaflet-container {
        background: #1a1a1a;
    }
    
    .leaflet-popup-content-wrapper {
        background: #212529;
        color: #e9ecef;
        border: 1px solid #495057;
        border-radius: 8px;
    }
    
    .leaflet-popup-tip {
        background: #212529;
        border: 1px solid #495057;
    }
    
    .leaflet-control-attribution {
        background: rgba(0,0,0,0.7);
        color: #adb5bd;
        font-size: 10px;
    }
    
    .leaflet-control-attribution a {
        color: #4e54c8;
    }
    
    /* Modal styling */
    #ipDetailsModal .modal-content {
        border: 1px solid #495057;
    }
    
    #ipDetailsModal .card {
        background: #1a1a1a !important;
    }
    
    #ipDetailsModal .table td, 
    #ipDetailsModal .table th {
        border-color: #495057;
    }
    
    /* Progress bar customization */
    .progress {
        background-color: #333;
        border-radius: 10px;
    }
    
    .progress-bar {
        border-radius: 10px;
    }
    
    /* Raw headers toggle button */
    #rawHeaders {
        transition: all 0.3s ease;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        #threatGauge {
            width: 120px;
            height: 120px;
        }
        
        .btn-group {
            flex-wrap: wrap;
        }
    }
    
    /* Animation for map markers */
    @keyframes pulse {
        0% {
            transform: scale(1);
            opacity: 1;
        }
        50% {
            transform: scale(1.1);
            opacity: 0.8;
        }
        100% {
            transform: scale(1);
            opacity: 1;
        }
    }
    
    .leaflet-marker-icon {
        animation: pulse 2s infinite;
    }
</style>

<?php
require_once '../includes/footer.php';
?>