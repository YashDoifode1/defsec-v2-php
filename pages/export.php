<?php
// pages/export.php - Complete Export Interface

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if this is an export request (no HTML output)
if (isset($_GET['format']) && in_array($_GET['format'], ['csv', 'pdf', 'json'])) {
    // Handle export without including header.php
    require_once '../includes/db.php'; // Use PDO from db.php
    
    // Get current user and website
    $user_id = $_SESSION['user_id'] ?? 1;
    $website_id = $_SESSION['website_id'] ?? 1;
    
    // Get export parameters
    $format = $_GET['format'];
    $start_date = $_GET['from_date'] ?? '';
    $end_date = $_GET['to_date'] ?? '';
    $ip_filter = $_GET['ip_filter'] ?? '';
    $country_filter = $_GET['country_filter'] ?? '';
    $vpn_filter = $_GET['vpn_filter'] ?? '';
    $tor_filter = $_GET['tor_filter'] ?? '';
    $proxy_filter = $_GET['proxy_filter'] ?? '';
    $sort_column = $_GET['sort'] ?? 'timestamp';
    $sort_order = strtoupper($_GET['order'] ?? 'DESC');
    
    // Validate sort input
    $allowed_columns = ['id', 'timestamp', 'ip', 'real_ip', 'country', 'is_vpn', 'is_tor', 'is_proxy', 'ISP', 'latitude', 'longitude'];
    if (!in_array($sort_column, $allowed_columns)) $sort_column = 'timestamp';
    if (!in_array($sort_order, ['ASC', 'DESC'])) $sort_order = 'DESC';
    
    // Build SQL query
    $sql = "SELECT * FROM logs WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $user_id,
        ':website_id' => $website_id
    ];
    
    // Add date filter
    if (!empty($start_date) && !empty($end_date)) {
        $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
        $params[':start_date'] = $start_date;
        $params[':end_date'] = $end_date . ' 23:59:59';
    }
    
    // Add IP filter
    if (!empty($ip_filter)) {
        $sql .= " AND (ip LIKE :ip OR real_ip LIKE :real_ip)";
        $params[':ip'] = '%' . $ip_filter . '%';
        $params[':real_ip'] = '%' . $ip_filter . '%';
    }
    
    // Add country filter
    if (!empty($country_filter) && $country_filter !== 'all') {
        $sql .= " AND country LIKE :country";
        $params[':country'] = '%' . $country_filter . '%';
    }
    
    // Add VPN filter
    if ($vpn_filter !== '') {
        $sql .= " AND is_vpn = :vpn";
        $params[':vpn'] = (int)$vpn_filter;
    }
    
    // Add Tor filter
    if ($tor_filter !== '') {
        $sql .= " AND is_tor = :tor";
        $params[':tor'] = (int)$tor_filter;
    }
    
    // Add Proxy filter
    if ($proxy_filter !== '') {
        $sql .= " AND is_proxy = :proxy";
        $params[':proxy'] = (int)$proxy_filter;
    }
    
    // Add sorting
    $sql .= " ORDER BY $sort_column $sort_order";
    
    try {
        // Debug: Log the SQL and parameters
        error_log("Export SQL: " . $sql);
        error_log("Export Params: " . print_r($params, true));
        
        // Execute query using PDO
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Handle different export formats
        switch ($format) {
            case 'csv':
                exportCSV($logs);
                break;
            case 'pdf':
                exportPDF($logs, $start_date, $end_date);
                break;
            case 'json':
                exportJSON($logs, $start_date, $end_date);
                break;
        }
        exit;
        
    } catch (PDOException $e) {
        error_log("Database error in export: " . $e->getMessage());
        die("Database error: " . $e->getMessage() . "<br>SQL: " . $sql);
    }
}

// If not an export request, show the filter interface
include '../includes/header.php';

// Get unique countries for filter dropdown
require_once '../includes/db.php';
$user_id = $_SESSION['user_id'] ?? 1;
$website_id = $_SESSION['website_id'] ?? 1;

try {
    $country_stmt = $pdo->prepare("SELECT DISTINCT country FROM logs WHERE user_id = ? AND website_id = ? AND country IS NOT NULL AND country != 'Unknown' ORDER BY country");
    $country_stmt->execute([$user_id, $website_id]);
    $countries = $country_stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $countries = [];
}
?>

<!-- Filter Interface -->
<div class="content-area">
    <div class="row mb-4">
        <div class="col-md-12">
            <div class="dashboard-card">
                <h4><i class="fas fa-download me-2"></i> Export Security Logs</h4>
                <p class="text-muted">Filter and export your security logs in various formats</p>
                
                <form id="exportForm" method="GET" action="export.php" target="_blank">
                    <div class="row">
                        <!-- Date Range -->
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Date Range</label>
                            <div class="input-group">
                                <input type="date" class="form-control" name="from_date" id="from_date" 
                                       value="<?php echo date('Y-m-d', strtotime('-7 days')); ?>">
                                <span class="input-group-text">to</span>
                                <input type="date" class="form-control" name="to_date" id="to_date" 
                                       value="<?php echo date('Y-m-d'); ?>">
                            </div>
                        </div>
                        
                        <!-- IP Filter -->
                        <div class="col-md-6 mb-3">
                            <label class="form-label">IP Address Filter</label>
                            <input type="text" class="form-control" name="ip_filter" id="ip_filter" 
                                   placeholder="Filter by IP address...">
                        </div>
                        
                        <!-- Country Filter -->
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Country</label>
                            <select class="form-control" name="country_filter" id="country_filter">
                                <option value="all">All Countries</option>
                                <?php foreach ($countries as $country): ?>
                                    <option value="<?php echo htmlspecialchars($country); ?>"><?php echo htmlspecialchars($country); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <!-- Security Filters -->
                        <div class="col-md-2 mb-3">
                            <label class="form-label">VPN</label>
                            <select class="form-control" name="vpn_filter" id="vpn_filter">
                                <option value="">All</option>
                                <option value="1">VPN Detected</option>
                                <option value="0">No VPN</option>
                            </select>
                        </div>
                        
                        <div class="col-md-2 mb-3">
                            <label class="form-label">Tor</label>
                            <select class="form-control" name="tor_filter" id="tor_filter">
                                <option value="">All</option>
                                <option value="1">Tor Detected</option>
                                <option value="0">No Tor</option>
                            </select>
                        </div>
                        
                        <div class="col-md-2 mb-3">
                            <label class="form-label">Proxy</label>
                            <select class="form-control" name="proxy_filter" id="proxy_filter">
                                <option value="">All</option>
                                <option value="1">Proxy Detected</option>
                                <option value="0">No Proxy</option>
                            </select>
                        </div>
                        
                        <!-- Sort Options -->
                        <div class="col-md-2 mb-3">
                            <label class="form-label">Sort By</label>
                            <select class="form-control" name="sort" id="sort">
                                <option value="timestamp">Date</option>
                                <option value="id">ID</option>
                                <option value="ip">IP Address</option>
                                <option value="country">Country</option>
                                <option value="ISP">ISP</option>
                                <option value="is_vpn">VPN Status</option>
                                <option value="is_tor">Tor Status</option>
                                <option value="is_proxy">Proxy Status</option>
                            </select>
                        </div>
                    </div>
                    
                    <!-- Export Buttons -->
                    <div class="row mt-4">
                        <div class="col-md-12">
                            <div class="d-flex gap-3 flex-wrap">
                                <button type="button" class="btn btn-success" onclick="exportData('csv')">
                                    <i class="fas fa-file-csv me-2"></i> Export as CSV
                                </button>
                                <button type="button" class="btn btn-danger" onclick="exportData('pdf')">
                                    <i class="fas fa-file-pdf me-2"></i> Export as PDF
                                </button>
                                <button type="button" class="btn btn-info" onclick="exportData('json')">
                                    <i class="fas fa-file-code me-2"></i> Export as JSON
                                </button>
                                <button type="button" class="btn btn-secondary" onclick="resetFilters()">
                                    <i class="fas fa-redo me-2"></i> Reset Filters
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Hidden format field -->
                    <input type="hidden" name="format" id="format" value="csv">
                </form>
            </div>
        </div>
    </div>
    
    <!-- Preview Section -->
    <div class="row">
        <div class="col-md-12">
            <div class="dashboard-card">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-eye me-2"></i> Preview (Last 10 Records)</h5>
                    <div class="text-muted small">Total Records: <span id="totalCount">0</span></div>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-dark table-hover" id="previewTable">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>IP Address</th>
                                <th>Country</th>
                                <th>VPN</th>
                                <th>Tor</th>
                                <th>Proxy</th>
                                <th>ISP</th>
                            </tr>
                        </thead>
                        <tbody id="previewBody">
                            <!-- Preview will be loaded via AJAX -->
                        </tbody>
                    </table>
                </div>
                <div class="text-center mt-3">
                    <button class="btn btn-outline-light btn-sm" onclick="loadPreview()">
                        <i class="fas fa-sync-alt me-1"></i> Refresh Preview
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- JavaScript -->
<script>
function exportData(format) {
    document.getElementById('format').value = format;
    
    // Validate date range
    const fromDate = document.getElementById('from_date').value;
    const toDate = document.getElementById('to_date').value;
    
    if (fromDate && toDate && new Date(fromDate) > new Date(toDate)) {
        alert('End date must be after start date!');
        return;
    }
    
    // Submit form
    document.getElementById('exportForm').submit();
}

function resetFilters() {
    document.getElementById('from_date').value = '<?php echo date('Y-m-d', strtotime('-7 days')); ?>';
    document.getElementById('to_date').value = '<?php echo date('Y-m-d'); ?>';
    document.getElementById('ip_filter').value = '';
    document.getElementById('country_filter').value = 'all';
    document.getElementById('vpn_filter').value = '';
    document.getElementById('tor_filter').value = '';
    document.getElementById('proxy_filter').value = '';
    document.getElementById('sort').value = 'timestamp';
    loadPreview();
}

function loadPreview() {
    const formData = new FormData();
    formData.append('preview', 'true');
    formData.append('from_date', document.getElementById('from_date').value);
    formData.append('to_date', document.getElementById('to_date').value);
    formData.append('ip_filter', document.getElementById('ip_filter').value);
    formData.append('country_filter', document.getElementById('country_filter').value);
    formData.append('vpn_filter', document.getElementById('vpn_filter').value);
    formData.append('tor_filter', document.getElementById('tor_filter').value);
    formData.append('proxy_filter', document.getElementById('proxy_filter').value);
    formData.append('sort', document.getElementById('sort').value);
    
    fetch('export_preview.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const tbody = document.getElementById('previewBody');
        const countSpan = document.getElementById('totalCount');
        
        tbody.innerHTML = '';
        countSpan.textContent = data.total || 0;
        
        if (data.preview && data.preview.length > 0) {
            data.preview.forEach(log => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${log.id}</td>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td><code>${log.ip}</code><br><small class="text-muted">${log.real_ip}</small></td>
                    <td>${log.country || 'Unknown'}</td>
                    <td><span class="badge ${log.is_vpn ? 'bg-danger' : 'bg-success'}">
                        ${log.is_vpn ? 'VPN' : 'No VPN'}
                    </span></td>
                    <td><span class="badge ${log.is_tor ? 'bg-warning' : 'bg-secondary'}">
                        ${log.is_tor ? 'Tor' : 'No Tor'}
                    </span></td>
                    <td><span class="badge ${log.is_proxy ? 'bg-info' : 'bg-secondary'}">
                        ${log.is_proxy ? 'Proxy' : 'No Proxy'}
                    </span></td>
                    <td>${log.ISP || 'Unknown'}</td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center text-muted py-4">
                        <i class="fas fa-database fa-2x mb-3"></i><br>
                        No logs found with current filters
                    </td>
                </tr>
            `;
        }
    })
    .catch(error => {
        console.error('Error loading preview:', error);
    });
}

// Load preview on page load
document.addEventListener('DOMContentLoaded', loadPreview);

// Auto-refresh preview when filters change
document.getElementById('from_date').addEventListener('change', loadPreview);
document.getElementById('to_date').addEventListener('change', loadPreview);
document.getElementById('ip_filter').addEventListener('input', loadPreview);
document.getElementById('country_filter').addEventListener('change', loadPreview);
document.getElementById('vpn_filter').addEventListener('change', loadPreview);
document.getElementById('tor_filter').addEventListener('change', loadPreview);
document.getElementById('proxy_filter').addEventListener('change', loadPreview);
document.getElementById('sort').addEventListener('change', loadPreview);
</script>

<?php
// Export functions
function exportCSV($logs) {
    header("Content-Type: text/csv");
    header("Content-Disposition: attachment; filename=security_logs_" . date('Y-m-d_H-i-s') . ".csv");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    $output = fopen("php://output", "w");
    fwrite($output, "\xEF\xBB\xBF"); // UTF-8 BOM
    
    // Updated CSV headers based on your table structure
    fputcsv($output, [
        "ID", "Timestamp", "IP Address", "Real IP", "Country", 
        "Reverse DNS", "WebRTC IP", "DNS Leak IP", "User Agent",
        "Screen Resolution", "Language", "Timezone", "Cookies Enabled",
        "CPU Cores", "RAM", "GPU", "Battery", "Referrer", "Plugins",
        "Digital DNA", "VPN", "Tor", "Proxy", "ASN", "ISP",
        "Latitude", "Longitude", "User ID", "Website ID"
    ]);
    
    foreach ($logs as $row) {
        fputcsv($output, [
            $row['id'] ?? '',
            $row['timestamp'] ?? '',
            $row['ip'] ?? '',
            $row['real_ip'] ?? '',
            $row['country'] ?? 'Unknown',
            $row['reverse_dns'] ?? 'Unknown',
            $row['webrtc_ip'] ?? 'Unknown',
            $row['dns_leak_ip'] ?? 'Unknown',
            $row['user_agent'] ?? '',
            $row['screen_resolution'] ?? 'Unknown',
            $row['language'] ?? 'Unknown',
            $row['timezone'] ?? 'Unknown',
            $row['cookies_enabled'] ?? '',
            $row['cpu_cores'] ?? 'Unknown',
            $row['ram'] ?? 'Unknown',
            $row['gpu'] ?? 'Unknown',
            $row['battery'] ?? 'Unknown',
            $row['referrer'] ?? '',
            $row['plugins'] ?? '',
            $row['digital_dna'] ?? 'Unknown',
            $row['is_vpn'] ? 'Yes' : 'No',
            $row['is_tor'] ? 'Yes' : 'No',
            $row['is_proxy'] ? 'Yes' : 'No',
            $row['ASN'] ?? 'Unknown',
            $row['ISP'] ?? 'Unknown',
            $row['latitude'] ?? '',
            $row['longitude'] ?? '',
            $row['user_id'] ?? '',
            $row['website_id'] ?? ''
        ]);
    }
    
    fclose($output);
}

function exportPDF($logs, $start_date, $end_date) {
    require_once('../libs/tcpdf/tcpdf.php');
    
    $pdf = new TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);
    $pdf->SetCreator('DefSec Security System');
    $pdf->SetAuthor('DefSec');
    $pdf->SetTitle('Security Logs Report');
    $pdf->setPrintHeader(false);
    $pdf->setPrintFooter(false);
    $pdf->SetMargins(10, 10, 10);
    $pdf->SetAutoPageBreak(TRUE, 15);
    $pdf->AddPage();
    
    // Title
    $pdf->SetFont('helvetica', 'B', 16);
    $pdf->Cell(0, 10, 'DefSec - Security Logs Report', 0, 1, 'C');
    
    // Report info
    $pdf->SetFont('helvetica', '', 10);
    $pdf->Cell(0, 6, 'Generated: ' . date('Y-m-d H:i:s'), 0, 1);
    if (!empty($start_date) && !empty($end_date)) {
        $pdf->Cell(0, 6, 'Date Range: ' . $start_date . ' to ' . $end_date, 0, 1);
    }
    $pdf->Cell(0, 6, 'Total Records: ' . count($logs), 0, 1);
    $pdf->Ln(5);
    
    // Table
    $html = '<style>
        table { border-collapse: collapse; width: 100%; font-size: 7pt; }
        th { background-color: #f2f2f2; font-weight: bold; padding: 3px; border: 1px solid #ddd; }
        td { padding: 2px; border: 1px solid #ddd; }
        .small { font-size: 6pt; }
    </style>';
    
    $html .= '<table>';
    $html .= '<tr>
        <th width="20">ID</th>
        <th width="50">Timestamp</th>
        <th width="60">IP</th>
        <th width="40">Country</th>
        <th width="15">VPN</th>
        <th width="15">Tor</th>
        <th width="15">Proxy</th>
        <th width="50">ISP</th>
        <th width="40">Location</th>
        <th width="40">Browser</th>
    </tr>';
    
    foreach ($logs as $row) {
        $location = '';
        if (!empty($row['latitude']) && !empty($row['longitude'])) {
            $location = round($row['latitude'], 2) . ', ' . round($row['longitude'], 2);
        }
        
        // Extract browser from user agent
        $browser = 'Unknown';
        $ua = $row['user_agent'] ?? '';
        if (stripos($ua, 'chrome') !== false) $browser = 'Chrome';
        elseif (stripos($ua, 'firefox') !== false) $browser = 'Firefox';
        elseif (stripos($ua, 'safari') !== false) $browser = 'Safari';
        elseif (stripos($ua, 'edge') !== false) $browser = 'Edge';
        elseif (stripos($ua, 'opera') !== false) $browser = 'Opera';
        
        $html .= '<tr>';
        $html .= '<td>' . htmlspecialchars($row['id']) . '</td>';
        $html .= '<td>' . htmlspecialchars(substr($row['timestamp'], 0, 16)) . '</td>';
        $html .= '<td class="small">' . htmlspecialchars($row['ip']) . '<br>' . htmlspecialchars($row['real_ip']) . '</td>';
        $html .= '<td>' . htmlspecialchars($row['country'] ?? 'Unknown') . '</td>';
        $html .= '<td align="center">' . ($row['is_vpn'] ? '✓' : '✗') . '</td>';
        $html .= '<td align="center">' . ($row['is_tor'] ? '✓' : '✗') . '</td>';
        $html .= '<td align="center">' . ($row['is_proxy'] ? '✓' : '✗') . '</td>';
        $html .= '<td class="small">' . htmlspecialchars(substr($row['ISP'] ?? 'Unknown', 0, 20)) . '</td>';
        $html .= '<td class="small">' . htmlspecialchars($location) . '</td>';
        $html .= '<td class="small">' . htmlspecialchars($browser) . '</td>';
        $html .= '</tr>';
    }
    
    $html .= '</table>';
    
    $pdf->writeHTML($html, true, false, true, false, '');
    $pdf->Output('security_logs_' . date('Y-m-d_H-i-s') . '.pdf', 'D');
}

function exportJSON($logs, $start_date, $end_date) {
    header("Content-Type: application/json");
    header("Content-Disposition: attachment; filename=security_logs_" . date('Y-m-d_H-i-s') . ".json");
    
    $export_data = [
        'metadata' => [
            'generated_at' => date('Y-m-d H:i:s'),
            'date_range' => ['from' => $start_date, 'to' => $end_date],
            'total_records' => count($logs),
            'columns' => [
                'id', 'timestamp', 'ip', 'real_ip', 'country', 'reverse_dns', 'webrtc_ip',
                'dns_leak_ip', 'user_agent', 'screen_resolution', 'language', 'timezone',
                'cookies_enabled', 'cpu_cores', 'ram', 'gpu', 'battery', 'referrer', 'plugins',
                'digital_dna', 'is_vpn', 'is_tor', 'is_proxy', 'ASN', 'ISP', 'latitude',
                'longitude', 'user_id', 'website_id'
            ]
        ],
        'logs' => $logs
    ];
    
    echo json_encode($export_data, JSON_PRETTY_PRINT);
}

include '../includes/footer.php';
?>