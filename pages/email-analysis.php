<?php
// email-analysis.php
require_once '../includes/header.php';
require_once 'EmailAnalyzer.php';

if (!$isLoggedIn) {
    header("Location: " . APP_URL . "/auth/login.php");
    exit();
}

$userId = $_SESSION['user_id'] ?? 1;
$message = '';
$analysis = null;

// Load API keys from database or config
$apiKeys = [
    'proxycheck' => 'YOUR_PROXYCHECK_API_KEY', // Get from https://proxycheck.io
    'ip2proxy' => 'YOUR_IP2PROXY_API_KEY',     // Get from https://www.ip2location.com
    'virustotal' => 'YOUR_VT_API_KEY',         // Get from https://www.virustotal.com
    'abuseipdb' => 'YOUR_ABUSEIPDB_API_KEY',   // Get from https://www.abuseipdb.com
    'ipinfo' => 'YOUR_IPINFO_TOKEN'            // Get from https://ipinfo.io
];

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['headers'])) {
    $rawHeaders = $_POST['headers'];
    
    if (!empty($rawHeaders)) {
        $analyzer = new EmailAnalyzer($pdo, $userId, $apiKeys);
        $analysis = $analyzer->analyzeHeaders($rawHeaders);
        $message = '<div class="alert alert-success">Email analysis completed successfully!</div>';
    } else {
        $message = '<div class="alert alert-danger">Please paste email headers.</div>';
    }
}

// Get recent analyses
$recentStmt = $pdo->prepare("SELECT * FROM email_analyses WHERE user_id = ? ORDER BY analysis_date DESC LIMIT 10");
$recentStmt->execute([$userId]);
$recentAnalyses = $recentStmt->fetchAll();
?>

<div class="row g-4 fade-in">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-envelope-open-text me-2"></i>Email Header Analysis</h2>
                <p class="text-muted mb-0">Comprehensive email forensic analysis with IP geolocation, VPN detection, RDAP, and threat intelligence</p>
            </div>
            <div>
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#helpModal">
                    <i class="fas fa-question-circle me-2"></i>How to get headers
                </button>
            </div>
        </div>
    </div>

    <!-- Input Form -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-paste me-2"></i>Paste Email Headers</h5>
            <?php echo $message; ?>
            <form method="post" action="">
                <div class="mb-3">
                    <textarea class="form-control bg-dark text-light" name="headers" rows="10" 
                              placeholder="Paste raw email headers here..."><?php echo isset($_POST['headers']) ? htmlspecialchars($_POST['headers']) : ''; ?></textarea>
                </div>
                <div class="d-flex justify-content-between">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search me-2"></i>Analyze Headers
                    </button>
                    <button type="button" class="btn btn-outline-secondary" onclick="loadSample()">
                        <i class="fas fa-flask me-2"></i>Load Sample
                    </button>
                </div>
            </form>
        </div>
    </div>

    <?php if ($analysis): ?>
    <!-- Analysis Results -->
    <div class="col-12 mt-4">
        <div class="dashboard-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Analysis Results</h5>
                <div>
                    <span class="badge bg-<?php echo $analysis['threat_score'] < 30 ? 'success' : ($analysis['threat_score'] < 60 ? 'warning' : 'danger'); ?> me-2" style="font-size: 1rem;">
                        Threat Score: <?php echo $analysis['threat_score']; ?>/100
                    </span>
                    <a href="export-analysis.php?id=<?php echo $analysis['analysis_id']; ?>" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-download me-1"></i>Export
                    </a>
                </div>
            </div>

            <!-- Basic Info Cards -->
            <div class="row g-3 mb-4">
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">From</small>
                        <div class="fw-bold"><?php echo htmlspecialchars($analysis['basic_info']['from'] ?: 'N/A'); ?></div>
                        <small class="text-info">Domain: <?php echo htmlspecialchars($analysis['basic_info']['from_domain'] ?: 'N/A'); ?></small>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">Subject</small>
                        <div class="fw-bold"><?php echo htmlspecialchars($analysis['basic_info']['subject'] ?: 'N/A'); ?></div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">Date</small>
                        <div class="fw-bold"><?php echo htmlspecialchars($analysis['basic_info']['date_parsed'] ?: 'N/A'); ?></div>
                    </div>
                </div>
            </div>

            <!-- Authentication Results -->
            <div class="row g-3 mb-4">
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">SPF</small>
                        <div class="d-flex align-items-center">
                            <?php
                            $spfClass = 'secondary';
                            if ($analysis['authentication']['spf'] === 'pass') $spfClass = 'success';
                            elseif ($analysis['authentication']['spf'] === 'fail') $spfClass = 'danger';
                            ?>
                            <span class="badge bg-<?php echo $spfClass; ?> me-2"><?php echo strtoupper($analysis['authentication']['spf'] ?: 'N/A'); ?></span>
                            <small class="text-muted"><?php echo $analysis['authentication']['spf'] ? '' : 'No SPF record'; ?></small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">DKIM</small>
                        <div class="d-flex align-items-center">
                            <?php
                            $dkimClass = 'secondary';
                            if ($analysis['authentication']['dkim'] === 'pass') $dkimClass = 'success';
                            elseif ($analysis['authentication']['dkim'] === 'fail') $dkimClass = 'danger';
                            ?>
                            <span class="badge bg-<?php echo $dkimClass; ?> me-2"><?php echo strtoupper($analysis['authentication']['dkim'] ?: 'N/A'); ?></span>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="bg-dark p-3 rounded border border-secondary">
                        <small class="text-muted">DMARC</small>
                        <div class="d-flex align-items-center">
                            <?php
                            $dmarcClass = 'secondary';
                            if ($analysis['authentication']['dmarc'] === 'pass') $dmarcClass = 'success';
                            elseif ($analysis['authentication']['dmarc'] === 'fail') $dmarcClass = 'danger';
                            ?>
                            <span class="badge bg-<?php echo $dmarcClass; ?> me-2"><?php echo strtoupper($analysis['authentication']['dmarc'] ?: 'N/A'); ?></span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Map Visualization -->
            <div class="mb-4">
                <h6 class="mb-3"><i class="fas fa-map-marked-alt me-2"></i>Email Path Visualization</h6>
                <div id="emailPathMap" style="height: 400px; border-radius: 8px;"></div>
            </div>

            <!-- IP Details Table -->
            <h6 class="mb-3"><i class="fas fa-network-wired me-2"></i>IP Hop Details</h6>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Hop</th>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Location</th>
                            <th>ISP/ASN</th>
                            <th>Security</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($analysis['ips'] as $ip): ?>
                        <tr>
                            <td>#<?php echo $ip['hop']; ?></td>
                            <td>
                                <code><?php echo htmlspecialchars($ip['ip']); ?></code>
                                <button class="btn btn-sm btn-outline-info ms-1 copy-ip" data-ip="<?php echo $ip['ip']; ?>" title="Copy IP">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </td>
                            <td>
                                <small><?php echo htmlspecialchars($ip['hostname'] ?: 'N/A'); ?></small><br>
                                <small class="text-muted">RDNS: <?php echo htmlspecialchars($ip['reverse_dns'] ?: 'N/A'); ?></small>
                            </td>
                            <td>
                                <?php if ($ip['country']): ?>
                                    <span title="<?php echo htmlspecialchars($ip['country']); ?>">
                                        <img src="https://flagcdn.com/16x12/<?php echo strtolower($ip['country_code']); ?>.png" class="me-1">
                                        <?php echo htmlspecialchars($ip['city'] ?: $ip['country']); ?>
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
                                <?php if ($ip['threat_score'] > 50): ?>
                                    <span class="badge bg-danger">High Risk</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary ip-details-btn" 
                                        data-ip="<?php echo $ip['ip']; ?>"
                                        data-rdap='<?php echo htmlspecialchars($ip['rdap_data'] ?? ''); ?>'>
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Recent Analyses -->
    <?php if (!empty($recentAnalyses)): ?>
    <div class="col-12 mt-4">
        <div class="dashboard-card">
            <h5 class="mb-4"><i class="fas fa-history me-2"></i>Recent Analyses</h5>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>From</th>
                            <th>Subject</th>
                            <th>SPF/DKIM/DMARC</th>
                            <th>Score</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentAnalyses as $recent): ?>
                        <tr>
                            <td><?php echo date('Y-m-d H:i', strtotime($recent['analysis_date'])); ?></td>
                            <td><?php echo htmlspecialchars($recent['from_address'] ?: 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars(substr($recent['subject'] ?: 'N/A', 0, 50)) . (strlen($recent['subject'] ?? '') > 50 ? '...' : ''); ?></td>
                            <td>
                                <span class="badge bg-<?php echo $recent['spf_result'] === 'pass' ? 'success' : 'secondary'; ?> me-1">SPF</span>
                                <span class="badge bg-<?php echo $recent['dkim_result'] === 'pass' ? 'success' : 'secondary'; ?> me-1">DKIM</span>
                                <span class="badge bg-<?php echo $recent['dmarc_result'] === 'pass' ? 'success' : 'secondary'; ?>">DMARC</span>
                            </td>
                            <td>
                                <span class="badge bg-<?php echo $recent['spam_score'] < 30 ? 'success' : ($recent['spam_score'] < 60 ? 'warning' : 'danger'); ?>">
                                    <?php echo $recent['spam_score']; ?>/100
                                </span>
                            </td>
                            <td>
                                <a href="view-analysis.php?id=<?php echo $recent['id']; ?>" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-eye"></i>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-info-circle me-2"></i>IP Address Details</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="ipDetailsContent">
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Loading IP information...</p>
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
            </div>
        </div>
    </div>
</div>

<!-- Help Modal -->
<div class="modal fade" id="helpModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content bg-dark">
            <div class="modal-header border-secondary">
                <h5 class="modal-title"><i class="fas fa-question-circle me-2"></i>How to Get Email Headers</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <h6>Gmail</h6>
                <ol>
                    <li>Open the email</li>
                    <li>Click the three dots (More) next to Reply</li>
                    <li>Select "Show original"</li>
                    <li>Copy all text from the new window</li>
                </ol>
                
                <h6>Outlook</h6>
                <ol>
                    <li>Open the email</li>
                    <li>Click the three dots (More actions)</li>
                    <li>Select "View" → "View message details"</li>
                    <li>Copy the Internet headers</li>
                </ol>
                
                <h6>Yahoo Mail</h6>
                <ol>
                    <li>Open the email</li>
                    <li>Click "More" (three dots)</li>
                    <li>Select "View raw message"</li>
                    <li>Copy all text</li>
                </ol>
                
                <h6>Apple Mail</h6>
                <ol>
                    <li>Open the email</li>
                    <li>Go to View → Message → Raw Source</li>
                    <li>Copy all text</li>
                </ol>
            </div>
        </div>
    </div>
</div>

<!-- Include Leaflet for maps -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet-ant-path"></script>

<script>
    let map = null;
    let markers = [];
    let polyline = null;
    
    <?php if ($analysis && !empty($analysis['ips'])): ?>
    // Initialize map when page loads
    document.addEventListener('DOMContentLoaded', function() {
        initMap();
    });
    
    function initMap() {
        const ipData = <?php echo json_encode($analysis['ips']); ?>;
        const validLocations = ipData.filter(ip => ip.latitude && ip.longitude && !ip.is_private);
        
        if (validLocations.length === 0) return;
        
        // Calculate bounds
        const bounds = L.latLngBounds(validLocations.map(ip => [ip.latitude, ip.longitude]));
        
        // Initialize map
        map = L.map('emailPathMap').fitBounds(bounds);
        
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);
        
        // Add markers for each hop
        validLocations.forEach((ip, index) => {
            const popupContent = `
                <div style="min-width: 200px;">
                    <strong>Hop #${ip.hop}</strong><br>
                    IP: ${ip.ip}<br>
                    Location: ${ip.city ? ip.city + ', ' : ''}${ip.country}<br>
                    ISP: ${ip.isp || 'N/A'}<br>
                    ${ip.is_vpn ? '<span style="color: orange;">VPN Detected</span><br>' : ''}
                    ${ip.is_tor ? '<span style="color: red;">TOR Exit Node</span><br>' : ''}
                </div>
            `;
            
            const marker = L.marker([ip.latitude, ip.longitude], {
                icon: L.divIcon({
                    className: 'custom-marker',
                    html: `<div style="background: ${ip.is_vpn ? '#ffc107' : (ip.is_tor ? '#dc3545' : '#007bff')}; 
                                 color: white; border-radius: 50%; width: 30px; height: 30px; 
                                 display: flex; align-items: center; justify-content: center; 
                                 border: 2px solid white; font-weight: bold;">
                            ${ip.hop}
                           </div>`,
                    iconSize: [30, 30]
                })
            }).bindPopup(popupContent);
            
            marker.addTo(map);
            markers.push(marker);
        });
        
        // Draw path
        if (validLocations.length > 1) {
            const points = validLocations.map(ip => [ip.latitude, ip.longitude]);
            polyline = L.polyline(points, {
                color: '#4e54c8',
                weight: 3,
                opacity: 0.7,
                dashArray: '5, 10'
            }).addTo(map);
        }
    }
    <?php endif; ?>
    
    // IP Details Modal
    async function showIPDetails(ip, rdapData) {
        const modal = new bootstrap.Modal(document.getElementById('ipDetailsModal'));
        
        document.getElementById('ipDetailsContent').innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2">Fetching detailed IP information...</p>
            </div>
        `;
        
        modal.show();
        
        try {
            // Fetch multiple data sources in parallel
            const [geoData, proxyData, vtData, abuseData] = await Promise.all([
                fetch(`https://ipapi.co/${ip}/json/`).then(r => r.json()).catch(() => null),
                fetch(`https://proxycheck.io/v2/${ip}?key=YOUR_KEY&vpn=1&asn=1`).then(r => r.json()).catch(() => null),
                fetch(`/api/vt-lookup.php?ip=${ip}`).then(r => r.json()).catch(() => null),
                fetch(`/api/abuse-lookup.php?ip=${ip}`).then(r => r.json()).catch(() => null)
            ]);
            
            let html = `
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="mb-3">Geolocation</h6>
                        <table class="table table-dark table-sm">
                            <tr><th>IP</th><td>${ip}</td></tr>
                            <tr><th>Country</th><td>${geoData?.country_name || 'N/A'}</td></tr>
                            <tr><th>Region</th><td>${geoData?.region || 'N/A'}</td></tr>
                            <tr><th>City</th><td>${geoData?.city || 'N/A'}</td></tr>
                            <tr><th>Lat/Long</th><td>${geoData?.latitude || 'N/A'}, ${geoData?.longitude || 'N/A'}</td></tr>
                            <tr><th>ISP</th><td>${geoData?.org || 'N/A'}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6 class="mb-3">Security Analysis</h6>
                        <table class="table table-dark table-sm">
                            <tr><th>VPN</th><td>${proxyData?.[ip]?.proxy === 'yes' ? 'Yes' : 'No'}</td></tr>
                            <tr><th>TOR</th><td>${proxyData?.[ip]?.type === 'TOR' ? 'Yes' : 'No'}</td></tr>
                            <tr><th>Proxy</th><td>${proxyData?.[ip]?.proxy === 'yes' ? 'Yes' : 'No'}</td></tr>
                            <tr><th>Risk Score</th><td>${proxyData?.[ip]?.risk || '0'}/100</td></tr>
                            <tr><th>ASN</th><td>${proxyData?.[ip]?.asn || 'N/A'}</td></tr>
                            <tr><th>Provider</th><td>${proxyData?.[ip]?.provider || 'N/A'}</td></tr>
                        </table>
                    </div>
                </div>
            `;
            
            // Add RDAP data if available
            if (rdapData && rdapData !== 'null') {
                try {
                    const rdap = JSON.parse(rdapData);
                    html += `
                        <div class="mt-3">
                            <h6 class="mb-3">RDAP Information</h6>
                            <pre class="bg-black p-2 rounded small" style="max-height: 200px; overflow-y: auto;">${JSON.stringify(rdap, null, 2)}</pre>
                        </div>
                    `;
                } catch (e) {}
            }
            
            // Add VirusTotal data if available
            if (vtData && vtData.data) {
                const stats = vtData.data.attributes?.last_analysis_stats || {};
                html += `
                    <div class="mt-3">
                        <h6 class="mb-3">VirusTotal Analysis</h6>
                        <div class="row">
                            <div class="col-md-3">
                                <div class="bg-success text-white p-2 rounded text-center">
                                    Harmless: ${stats.harmless || 0}
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="bg-warning text-dark p-2 rounded text-center">
                                    Suspicious: ${stats.suspicious || 0}
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="bg-danger text-white p-2 rounded text-center">
                                    Malicious: ${stats.malicious || 0}
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="bg-secondary text-white p-2 rounded text-center">
                                    Undetected: ${stats.undetected || 0}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            document.getElementById('ipDetailsContent').innerHTML = html;
            
            // Update buttons
            document.getElementById('rdapLookupBtn').href = `https://rdap.db.ripe.net/ip/${ip}`;
            document.getElementById('vtLookupBtn').href = `https://www.virustotal.com/gui/ip-address/${ip}`;
            
        } catch (error) {
            document.getElementById('ipDetailsContent').innerHTML = `
                <div class="alert alert-danger">Error fetching IP details: ${error.message}</div>
            `;
        }
    }
    
    // Load sample headers for testing
    function loadSample() {
        const sample = `Delivered-To: test@example.com
Received: by 2002:a05:6402:228c:b0:0:0:0 with SMTP id abc123;
        Mon, 15 May 2024 10:30:25 -0700 (PDT)
Return-Path: <sender@example.com>
Received: from mail-sender.com (mail.sender.com. [192.0.2.1])
        by mx.google.com with ESMTPS id xyz789;
        Mon, 15 May 2024 10:30:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@example.com;
       dkim=pass header.i=@example.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
         s=selector1; h=from:to:subject:date:message-id;
         bh=abc123; b=def456
From: "John Doe" <sender@example.com>
Date: Mon, 15 May 2024 10:30:15 -0700
Message-ID: <12345@mail.sender.com>
Subject: Sample Email for Analysis
To: recipient@gmail.com
Content-Type: text/plain; charset="UTF-8"

This is a sample email for testing the header analyzer.`;
        
        document.querySelector('textarea[name="headers"]').value = sample;
    }
    
    // Copy IP to clipboard
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.copy-ip').forEach(btn => {
            btn.addEventListener('click', function() {
                const ip = this.dataset.ip;
                navigator.clipboard.writeText(ip).then(() => {
                    alert('IP copied to clipboard!');
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
    }
    
    .leaflet-container {
        background: #1a1a1a;
    }
    
    .leaflet-popup-content-wrapper {
        background: #212529;
        color: #e9ecef;
        border: 1px solid #495057;
    }
    
    .leaflet-popup-tip {
        background: #212529;
        border: 1px solid #495057;
    }
    
    .leaflet-control-attribution {
        background: rgba(0,0,0,0.7);
        color: #adb5bd;
    }
    
    .leaflet-control-attribution a {
        color: #4e54c8;
    }
</style>

<?php
require_once '../includes/footer.php';
?>