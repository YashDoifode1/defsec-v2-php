<?php
// pages/export.php - Complete Export Interface for All Log Types

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if user is logged in
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'] ?? 1;
$website_id = $_SESSION['website_id'] ?? 1;

// Check if this is an export request (no HTML output)
if (isset($_GET['format']) && in_array($_GET['format'], ['csv', 'pdf', 'json', 'excel'])) {
    // Handle export without including header.php
    require_once '../includes/db.php'; // Use PDO from db.php
    
    // Get export parameters
    $format = $_GET['format'];
    $log_type = $_GET['log_type'] ?? 'visitor'; // visitor, attack, blocked, access, login, settings
    $start_date = $_GET['from_date'] ?? '';
    $end_date = $_GET['to_date'] ?? '';
    $ip_filter = $_GET['ip_filter'] ?? '';
    $country_filter = $_GET['country_filter'] ?? '';
    $vpn_filter = $_GET['vpn_filter'] ?? '';
    $tor_filter = $_GET['tor_filter'] ?? '';
    $proxy_filter = $_GET['proxy_filter'] ?? '';
    $severity_filter = $_GET['severity_filter'] ?? '';
    $attack_type_filter = $_GET['attack_type_filter'] ?? '';
    $sort_column = $_GET['sort'] ?? 'timestamp';
    $sort_order = strtoupper($_GET['order'] ?? 'DESC');
    $limit = intval($_GET['limit'] ?? 10000); // Default limit for exports
    
    // Define allowed columns based on log type
    $allowed_columns = [];
    $default_sort = 'timestamp';
    
    switch ($log_type) {
        case 'visitor':
            $allowed_columns = ['id', 'timestamp', 'ip', 'real_ip', 'country', 'is_vpn', 'is_tor', 'is_proxy', 'ISP', 'latitude', 'longitude', 'user_agent'];
            $default_sort = 'timestamp';
            break;
        case 'attack':
            $allowed_columns = ['id', 'timestamp', 'attack_type', 'severity', 'ip_address', 'user_agent', 'request_url'];
            $default_sort = 'timestamp';
            break;
        case 'blocked':
            $allowed_columns = ['id', 'ip', 'reason', 'created_at', 'expiry_time'];
            $default_sort = 'created_at';
            break;
        case 'access':
            $allowed_columns = ['id', 'timestamp', 'ip_address', 'user_agent', 'request_uri', 'http_method'];
            $default_sort = 'timestamp';
            break;
        case 'login':
            $allowed_columns = ['id', 'created_at', 'ip_address', 'user_agent', 'action_type', 'details'];
            $default_sort = 'created_at';
            break;
        case 'settings':
            $allowed_columns = ['id', 'setting_name', 'setting_value', 'updated_at'];
            $default_sort = 'setting_name';
            break;
    }
    
    // Validate sort input
    if (!in_array($sort_column, $allowed_columns)) $sort_column = $default_sort;
    if (!in_array($sort_order, ['ASC', 'DESC'])) $sort_order = 'DESC';
    
    // Build SQL query based on log type
    $sql = "";
    $params = [];
    
    switch ($log_type) {
        case 'visitor':
            $sql = "SELECT * FROM logs WHERE user_id = :user_id AND website_id = :website_id";
            $params = [':user_id' => $user_id, ':website_id' => $website_id];
            
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
            break;
            
        case 'attack':
            $sql = "SELECT * FROM attack_logs WHERE user_id = :user_id AND website_id = :website_id";
            $params = [':user_id' => $user_id, ':website_id' => $website_id];
            
            // Add date filter
            if (!empty($start_date) && !empty($end_date)) {
                $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }
            
            // Add IP filter
            if (!empty($ip_filter)) {
                $sql .= " AND ip_address LIKE :ip";
                $params[':ip'] = '%' . $ip_filter . '%';
            }
            
            // Add severity filter
            if (!empty($severity_filter) && $severity_filter !== 'all') {
                $sql .= " AND severity = :severity";
                $params[':severity'] = $severity_filter;
            }
            
            // Add attack type filter
            if (!empty($attack_type_filter) && $attack_type_filter !== 'all') {
                $sql .= " AND attack_type LIKE :attack_type";
                $params[':attack_type'] = '%' . $attack_type_filter . '%';
            }
            break;
            
        case 'blocked':
            $sql = "SELECT * FROM blocked_ips WHERE user_id = :user_id AND website_id = :website_id";
            $params = [':user_id' => $user_id, ':website_id' => $website_id];
            
            // Add date filter
            if (!empty($start_date) && !empty($end_date)) {
                $sql .= " AND created_at BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }
            
            // Add IP filter
            if (!empty($ip_filter)) {
                $sql .= " AND ip LIKE :ip";
                $params[':ip'] = '%' . $ip_filter . '%';
            }
            
            // Add status filter
            if (isset($_GET['status_filter']) && $_GET['status_filter'] === 'active') {
                $sql .= " AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())";
            } elseif (isset($_GET['status_filter']) && $_GET['status_filter'] === 'expired') {
                $sql .= " AND expiry_time != '00:00:00' AND DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) <= NOW()";
            }
            break;
            
        case 'access':
            $sql = "SELECT * FROM access_logs WHERE user_id = :user_id AND website_id = :website_id";
            $params = [':user_id' => $user_id, ':website_id' => $website_id];
            
            // Add date filter
            if (!empty($start_date) && !empty($end_date)) {
                $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }
            
            // Add IP filter
            if (!empty($ip_filter)) {
                $sql .= " AND ip_address LIKE :ip";
                $params[':ip'] = '%' . $ip_filter . '%';
            }
            break;
            
        case 'login':
            $sql = "SELECT * FROM login_logs WHERE user_id = :user_id";
            $params = [':user_id' => $user_id];
            
            // Add website filter if provided
            if (!empty($website_id)) {
                $sql .= " AND website_id = :website_id";
                $params[':website_id'] = $website_id;
            }
            
            // Add date filter
            if (!empty($start_date) && !empty($end_date)) {
                $sql .= " AND created_at BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }
            
            // Add IP filter
            if (!empty($ip_filter)) {
                $sql .= " AND ip_address LIKE :ip";
                $params[':ip'] = '%' . $ip_filter . '%';
            }
            break;
            
        case 'settings':
            $sql = "SELECT * FROM settings WHERE user_id = :user_id AND website_id = :website_id";
            $params = [':user_id' => $user_id, ':website_id' => $website_id];
            break;
    }
    
    // Add sorting
    $sql .= " ORDER BY $sort_column $sort_order";
    
    // Add limit for performance
    $sql .= " LIMIT :limit";
    $params[':limit'] = $limit;
    
    try {
        // Debug: Log the SQL and parameters
        error_log("Export SQL: " . $sql);
        error_log("Export Params: " . print_r($params, true));
        
        // Execute query using PDO
        $stmt = $pdo->prepare($sql);
        
        // Bind parameters with proper types
        foreach ($params as $key => $value) {
            if ($key === ':limit') {
                $stmt->bindValue($key, $value, PDO::PARAM_INT);
            } else {
                $stmt->bindValue($key, $value, PDO::PARAM_STR);
            }
        }
        
        $stmt->execute();
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get total count for statistics
        $count_sql = preg_replace('/SELECT \* FROM/', 'SELECT COUNT(*) as total FROM', $sql, 1);
        $count_sql = preg_replace('/ORDER BY .*$/', '', $count_sql);
        $count_sql = preg_replace('/LIMIT :limit$/', '', $count_sql);
        
        $count_stmt = $pdo->prepare($count_sql);
        foreach ($params as $key => $value) {
            if ($key !== ':limit') {
                $count_stmt->bindValue($key, $value, PDO::PARAM_STR);
            }
        }
        $count_stmt->execute();
        $total_count = $count_stmt->fetchColumn();
        
        // Handle different export formats
        switch ($format) {
            case 'csv':
                exportCSV($data, $log_type, $start_date, $end_date, $total_count);
                break;
            case 'pdf':
                exportPDF($data, $log_type, $start_date, $end_date, $total_count);
                break;
            case 'json':
                exportJSON($data, $log_type, $start_date, $end_date, $total_count);
                break;
            case 'excel':
                exportExcel($data, $log_type, $start_date, $end_date, $total_count);
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

// Get unique data for filter dropdowns
require_once '../includes/db.php';

try {
    // Get unique countries
    $country_stmt = $pdo->prepare("SELECT DISTINCT country FROM logs WHERE user_id = ? AND website_id = ? AND country IS NOT NULL AND country != 'Unknown' ORDER BY country");
    $country_stmt->execute([$user_id, $website_id]);
    $countries = $country_stmt->fetchAll(PDO::FETCH_COLUMN);
    
    // Get unique attack types
    $attack_type_stmt = $pdo->prepare("SELECT DISTINCT attack_type FROM attack_logs WHERE user_id = ? AND website_id = ? ORDER BY attack_type");
    $attack_type_stmt->execute([$user_id, $website_id]);
    $attack_types = $attack_type_stmt->fetchAll(PDO::FETCH_COLUMN);
    
    // Get unique severities
    $severity_stmt = $pdo->prepare("SELECT DISTINCT severity FROM attack_logs WHERE user_id = ? AND website_id = ? ORDER BY severity");
    $severity_stmt->execute([$user_id, $website_id]);
    $severities = $severity_stmt->fetchAll(PDO::FETCH_COLUMN);
    
} catch (PDOException $e) {
    $countries = [];
    $attack_types = [];
    $severities = [];
}
?>

<!-- Filter Interface -->
<div class="content-area">
    <div class="row mb-4">
        <div class="col-md-12">
            <div class="dashboard-card">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h4 class="mb-1"><i class="fas fa-download me-2 text-primary"></i> Export Security Data</h4>
                        <p class="text-muted mb-0">Export logs and data in various formats for analysis and reporting</p>
                    </div>
                    <div>
                        <span class="badge bg-info">Multi-Format Export</span>
                    </div>
                </div>
                
                <form id="exportForm" method="GET" action="export.php" target="_blank">
                    <div class="row">
                        <!-- Log Type Selection -->
                        <div class="col-md-3 mb-3">
                            <label class="form-label">Data Type</label>
                            <select class="form-control" name="log_type" id="log_type" onchange="updateFilters()">
                                <option value="visitor" selected>Visitor Logs</option>
                                <option value="attack">Attack Logs</option>
                                <option value="blocked">Blocked IPs</option>
                                <option value="access">Access Logs</option>
                                <option value="login">Login Logs</option>
                                <option value="settings">Settings</option>
                            </select>
                        </div>
                        
                        <!-- Export Format -->
                        <div class="col-md-3 mb-3">
                            <label class="form-label">Export Format</label>
                            <select class="form-control" name="format" id="format">
                                <option value="csv">CSV (Excel)</option>
                                <option value="excel">Excel (XLSX)</option>
                                <option value="pdf">PDF Document</option>
                                <option value="json">JSON Data</option>
                            </select>
                        </div>
                        
                        <!-- Date Range -->
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Date Range</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-calendar"></i></span>
                                <input type="date" class="form-control" name="from_date" id="from_date" 
                                       value="<?php echo date('Y-m-d', strtotime('-7 days')); ?>">
                                <span class="input-group-text">to</span>
                                <input type="date" class="form-control" name="to_date" id="to_date" 
                                       value="<?php echo date('Y-m-d'); ?>">
                            </div>
                        </div>
                        
                        <!-- IP Filter -->
                        <div class="col-md-4 mb-3">
                            <label class="form-label">IP Address Filter</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-network-wired"></i></span>
                                <input type="text" class="form-control" name="ip_filter" id="ip_filter" 
                                       placeholder="Filter by IP address...">
                            </div>
                        </div>
                        
                        <!-- Country Filter (for visitor logs) -->
                        <div class="col-md-4 mb-3" id="countryFilter">
                            <label class="form-label">Country</label>
                            <select class="form-control" name="country_filter" id="country_filter">
                                <option value="all">All Countries</option>
                                <?php foreach ($countries as $country): ?>
                                    <option value="<?php echo htmlspecialchars($country); ?>"><?php echo htmlspecialchars($country); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <!-- Security Filters (for visitor logs) -->
                        <div class="col-md-4 mb-3" id="securityFilters">
                            <label class="form-label">Connection Type</label>
                            <div class="d-flex gap-2">
                                <select class="form-control" name="vpn_filter" id="vpn_filter">
                                    <option value="">VPN: All</option>
                                    <option value="1">VPN Only</option>
                                    <option value="0">No VPN</option>
                                </select>
                                <select class="form-control" name="proxy_filter" id="proxy_filter">
                                    <option value="">Proxy: All</option>
                                    <option value="1">Proxy Only</option>
                                    <option value="0">No Proxy</option>
                                </select>
                            </div>
                        </div>
                        
                        <!-- Attack Specific Filters -->
                        <div class="col-md-6 mb-3" id="attackFilters" style="display: none;">
                            <label class="form-label">Attack Filters</label>
                            <div class="d-flex gap-2">
                                <select class="form-control" name="severity_filter" id="severity_filter">
                                    <option value="all">All Severities</option>
                                    <?php foreach ($severities as $severity): ?>
                                        <option value="<?php echo htmlspecialchars($severity); ?>"><?php echo htmlspecialchars($severity); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <select class="form-control" name="attack_type_filter" id="attack_type_filter">
                                    <option value="all">All Attack Types</option>
                                    <?php foreach ($attack_types as $type): ?>
                                        <option value="<?php echo htmlspecialchars($type); ?>"><?php echo htmlspecialchars($type); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                        
                        <!-- Blocked IPs Specific Filters -->
                        <div class="col-md-4 mb-3" id="blockedFilters" style="display: none;">
                            <label class="form-label">Status Filter</label>
                            <select class="form-control" name="status_filter" id="status_filter">
                                <option value="all">All Status</option>
                                <option value="active">Active Only</option>
                                <option value="expired">Expired Only</option>
                            </select>
                        </div>
                        
                        <!-- Sort Options -->
                        <div class="col-md-3 mb-3">
                            <label class="form-label">Sort By</label>
                            <select class="form-control" name="sort" id="sort">
                                <!-- Options will be populated by JavaScript based on log type -->
                            </select>
                        </div>
                        
                        <!-- Record Limit -->
                        <div class="col-md-3 mb-3">
                            <label class="form-label">Max Records</label>
                            <select class="form-control" name="limit" id="limit">
                                <option value="1000">1,000 records</option>
                                <option value="5000" selected>5,000 records</option>
                                <option value="10000">10,000 records</option>
                                <option value="50000">50,000 records</option>
                                <option value="0">All records</option>
                            </select>
                        </div>
                    </div>
                    
                    <!-- Export Buttons -->
                    <div class="row mt-4">
                        <div class="col-md-12">
                            <div class="d-flex gap-3 flex-wrap">
                                <button type="button" class="btn btn-success" onclick="exportData()">
                                    <i class="fas fa-file-export me-2"></i> Export Data
                                </button>
                                <button type="button" class="btn btn-outline-primary" onclick="loadPreview()">
                                    <i class="fas fa-eye me-2"></i> Preview Data
                                </button>
                                <button type="button" class="btn btn-outline-secondary" onclick="resetFilters()">
                                    <i class="fas fa-redo me-2"></i> Reset Filters
                                </button>
                                <button type="button" class="btn btn-outline-info" onclick="showExportStats()">
                                    <i class="fas fa-chart-bar me-2"></i> View Stats
                                </button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Preview Section -->
    <div class="row">
        <div class="col-md-12">
            <div class="dashboard-card">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-eye me-2 text-info"></i> Data Preview</h5>
                    <div class="d-flex gap-2">
                        <div class="text-muted small">Type: <span id="previewType" class="badge bg-dark">Visitor Logs</span></div>
                        <div class="text-muted small">Records: <span id="totalCount" class="badge bg-primary">0</span></div>
                    </div>
                </div>
                
                <div id="previewContainer">
                    <div class="text-center py-5">
                        <i class="fas fa-database fa-3x text-muted mb-3"></i>
                        <p class="text-muted">Click "Preview Data" to see filtered results</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Statistics Section (Hidden by default) -->
    <div class="row" id="statsSection" style="display: none;">
        <div class="col-md-12">
            <div class="dashboard-card">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-chart-bar me-2 text-warning"></i> Export Statistics</h5>
                    <button class="btn btn-sm btn-outline-secondary" onclick="hideStats()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="statsContent">
                    <!-- Statistics will be loaded here -->
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Export Functions -->
<script>
// Define sort options for each log type
const sortOptions = {
    'visitor': [
        {value: 'timestamp', text: 'Date'},
        {value: 'id', text: 'ID'},
        {value: 'ip', text: 'IP Address'},
        {value: 'country', text: 'Country'},
        {value: 'ISP', text: 'ISP'},
        {value: 'is_vpn', text: 'VPN Status'},
        {value: 'is_proxy', text: 'Proxy Status'},
        {value: 'user_agent', text: 'User Agent'}
    ],
    'attack': [
        {value: 'timestamp', text: 'Date'},
        {value: 'id', text: 'ID'},
        {value: 'ip_address', text: 'IP Address'},
        {value: 'attack_type', text: 'Attack Type'},
        {value: 'severity', text: 'Severity'},
        {value: 'request_url', text: 'Request URL'}
    ],
    'blocked': [
        {value: 'created_at', text: 'Date Blocked'},
        {value: 'id', text: 'ID'},
        {value: 'ip', text: 'IP Address'},
        {value: 'reason', text: 'Reason'},
        {value: 'expiry_time', text: 'Expiry Time'}
    ],
    'access': [
        {value: 'timestamp', text: 'Date'},
        {value: 'id', text: 'ID'},
        {value: 'ip_address', text: 'IP Address'},
        {value: 'request_uri', text: 'Request URI'},
        {value: 'http_method', text: 'HTTP Method'}
    ],
    'login': [
        {value: 'created_at', text: 'Date'},
        {value: 'id', text: 'ID'},
        {value: 'ip_address', text: 'IP Address'},
        {value: 'action_type', text: 'Action Type'},
        {value: 'details', text: 'Details'}
    ],
    'settings': [
        {value: 'setting_name', text: 'Setting Name'},
        {value: 'updated_at', text: 'Last Updated'},
        {value: 'id', text: 'ID'}
    ]
};

// Define preview columns for each log type
const previewColumns = {
    'visitor': ['id', 'timestamp', 'ip', 'country', 'is_vpn', 'is_proxy', 'ISP'],
    'attack': ['id', 'timestamp', 'ip_address', 'attack_type', 'severity', 'request_url'],
    'blocked': ['id', 'ip', 'reason', 'created_at', 'expiry_time'],
    'access': ['id', 'timestamp', 'ip_address', 'user_agent', 'request_uri'],
    'login': ['id', 'created_at', 'ip_address', 'action_type', 'details'],
    'settings': ['id', 'setting_name', 'setting_value']
};

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    updateFilters();
    loadStats(); // Load initial statistics
});

// Update filters based on selected log type
function updateFilters() {
    const logType = document.getElementById('log_type').value;
    const sortSelect = document.getElementById('sort');
    const previewType = document.getElementById('previewType');
    
    // Update preview type display
    const typeNames = {
        'visitor': 'Visitor Logs',
        'attack': 'Attack Logs',
        'blocked': 'Blocked IPs',
        'access': 'Access Logs',
        'login': 'Login Logs',
        'settings': 'Settings'
    };
    previewType.textContent = typeNames[logType];
    
    // Update sort options
    sortSelect.innerHTML = '';
    sortOptions[logType].forEach(option => {
        const opt = document.createElement('option');
        opt.value = option.value;
        opt.textContent = option.text;
        sortSelect.appendChild(opt);
    });
    
    // Show/hide specific filters
    document.getElementById('countryFilter').style.display = logType === 'visitor' ? 'block' : 'none';
    document.getElementById('securityFilters').style.display = logType === 'visitor' ? 'block' : 'none';
    document.getElementById('attackFilters').style.display = logType === 'attack' ? 'flex' : 'none';
    document.getElementById('blockedFilters').style.display = logType === 'blocked' ? 'block' : 'none';
    
    // Clear preview
    document.getElementById('previewContainer').innerHTML = `
        <div class="text-center py-5">
            <i class="fas fa-database fa-3x text-muted mb-3"></i>
            <p class="text-muted">Click "Preview Data" to see filtered results</p>
        </div>
    `;
    document.getElementById('totalCount').textContent = '0';
}

// Export data
function exportData() {
    const form = document.getElementById('exportForm');
    
    // Validate date range
    const fromDate = document.getElementById('from_date').value;
    const toDate = document.getElementById('to_date').value;
    
    if (fromDate && toDate && new Date(fromDate) > new Date(toDate)) {
        showAlert('End date must be after start date!', 'danger');
        return;
    }
    
    // Submit form
    form.submit();
}

// Load preview data
function loadPreview() {
    const formData = new FormData();
    formData.append('preview', 'true');
    formData.append('log_type', document.getElementById('log_type').value);
    formData.append('from_date', document.getElementById('from_date').value);
    formData.append('to_date', document.getElementById('to_date').value);
    formData.append('ip_filter', document.getElementById('ip_filter').value);
    formData.append('country_filter', document.getElementById('country_filter').value);
    formData.append('vpn_filter', document.getElementById('vpn_filter').value);
    formData.append('proxy_filter', document.getElementById('proxy_filter').value);
    formData.append('severity_filter', document.getElementById('severity_filter').value);
    formData.append('attack_type_filter', document.getElementById('attack_type_filter').value);
    formData.append('status_filter', document.getElementById('status_filter').value);
    formData.append('sort', document.getElementById('sort').value);
    formData.append('limit', document.getElementById('limit').value);
    
    // Show loading
    document.getElementById('previewContainer').innerHTML = `
        <div class="text-center py-5">
            <div class="spinner-border text-primary" role="status"></div>
            <p class="mt-2 text-muted">Loading preview data...</p>
        </div>
    `;
    
    fetch('api/export-preview.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('previewContainer');
        const countSpan = document.getElementById('totalCount');
        
        countSpan.textContent = data.total || 0;
        
        if (data.preview && data.preview.length > 0) {
            const logType = document.getElementById('log_type').value;
            const columns = previewColumns[logType];
            
            let html = `<div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>`;
            
            // Create table headers
            columns.forEach(col => {
                html += `<th>${formatColumnName(col)}</th>`;
            });
            
            html += `</tr>
                    </thead>
                    <tbody>`;
            
            // Create table rows
            data.preview.forEach(row => {
                html += '<tr>';
                columns.forEach(col => {
                    let value = row[col];
                    if (value === null || value === undefined) value = '';
                    
                    // Format specific columns
                    if (col === 'timestamp' || col === 'created_at') {
                        value = new Date(value).toLocaleString();
                    } else if (col === 'is_vpn' || col === 'is_proxy' || col === 'is_tor') {
                        value = value ? '<span class="badge bg-danger">Yes</span>' : '<span class="badge bg-success">No</span>';
                    } else if (col === 'severity') {
                        const color = value === 'Critical' ? 'danger' : 
                                    value === 'High' ? 'warning' : 
                                    value === 'Medium' ? 'info' : 'secondary';
                        value = `<span class="badge bg-${color}">${value}</span>`;
                    } else if (col === 'ip' || col === 'ip_address') {
                        value = `<code class="small">${value}</code>`;
                    } else if (col === 'expiry_time') {
                        if (value === '00:00:00') {
                            value = '<span class="badge bg-warning">Permanent</span>';
                        } else if (value) {
                            value = value;
                        }
                    }
                    
                    html += `<td>${value}</td>`;
                });
                html += '</tr>';
            });
            
            html += `</tbody>
                </table>
            </div>
            <div class="mt-3 text-center">
                <small class="text-muted">Showing ${data.preview.length} of ${data.total} records</small>
            </div>`;
            
            container.innerHTML = html;
        } else {
            container.innerHTML = `
                <div class="text-center py-5">
                    <i class="fas fa-database fa-3x text-muted mb-3"></i>
                    <h5>No data found</h5>
                    <p class="text-muted">Try adjusting your filters</p>
                </div>
            `;
        }
    })
    .catch(error => {
        console.error('Error loading preview:', error);
        document.getElementById('previewContainer').innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                Error loading preview data. Please try again.
            </div>
        `;
    });
}

// Format column name for display
function formatColumnName(col) {
    return col.replace(/_/g, ' ')
              .replace(/\b\w/g, l => l.toUpperCase());
}

// Reset all filters
function resetFilters() {
    document.getElementById('from_date').value = '<?php echo date('Y-m-d', strtotime('-7 days')); ?>';
    document.getElementById('to_date').value = '<?php echo date('Y-m-d'); ?>';
    document.getElementById('ip_filter').value = '';
    document.getElementById('country_filter').value = 'all';
    document.getElementById('vpn_filter').value = '';
    document.getElementById('proxy_filter').value = '';
    document.getElementById('severity_filter').value = 'all';
    document.getElementById('attack_type_filter').value = 'all';
    document.getElementById('status_filter').value = 'all';
    document.getElementById('sort').value = 'timestamp';
    document.getElementById('limit').value = '5000';
    
    updateFilters();
    showAlert('Filters have been reset', 'success');
}

// Show export statistics
function showExportStats() {
    document.getElementById('statsSection').style.display = 'block';
    loadStats();
}

// Hide statistics
function hideStats() {
    document.getElementById('statsSection').style.display = 'none';
}

// Load statistics
function loadStats() {
    const statsContent = document.getElementById('statsContent');
    statsContent.innerHTML = `
        <div class="text-center py-3">
            <div class="spinner-border spinner-border-sm" role="status"></div>
            <p class="mt-2 small text-muted">Loading statistics...</p>
        </div>
    `;
    
    fetch('api/export-stats.php')
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            let html = `<div class="row">`;
            
            // Total records card
            html += `
                <div class="col-md-4 mb-3">
                    <div class="card bg-dark border-success">
                        <div class="card-body text-center">
                            <div class="h2 mb-0 text-success">${data.stats.total_records.toLocaleString()}</div>
                            <small class="text-muted">Total Records</small>
                        </div>
                    </div>
                </div>
            `;
            
            // Log types breakdown
            html += `
                <div class="col-md-8 mb-3">
                    <div class="card bg-dark border-info">
                        <div class="card-body">
                            <h6 class="mb-3"><i class="fas fa-chart-pie me-2"></i> Log Distribution</h6>
                            <div class="row small">
            `;
            
            Object.entries(data.stats.log_types).forEach(([type, count]) => {
                const percentage = ((count / data.stats.total_records) * 100).toFixed(1);
                html += `
                    <div class="col-6 mb-2">
                        <div class="d-flex justify-content-between">
                            <span>${formatColumnName(type)}</span>
                            <span>${count.toLocaleString()} (${percentage}%)</span>
                        </div>
                        <div class="progress" style="height: 5px;">
                            <div class="progress-bar bg-info" style="width: ${percentage}%"></div>
                        </div>
                    </div>
                `;
            });
            
            html += `</div></div></div></div>`;
            
            // Recent activity
            html += `
                <div class="col-md-12">
                    <div class="card bg-dark border-warning">
                        <div class="card-body">
                            <h6 class="mb-3"><i class="fas fa-history me-2"></i> Recent Activity</h6>
                            <div class="row small">
            `;
            
            if (data.stats.recent_activity && data.stats.recent_activity.length > 0) {
                data.stats.recent_activity.forEach(activity => {
                    html += `
                        <div class="col-md-6 mb-2">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <strong>${formatColumnName(activity.type)}</strong>
                                    <div class="text-muted">${activity.date}</div>
                                </div>
                                <span class="badge bg-primary">${activity.count.toLocaleString()}</span>
                            </div>
                        </div>
                    `;
                });
            } else {
                html += `<div class="col-12 text-center text-muted">No recent activity</div>`;
            }
            
            html += `</div></div></div></div>`;
            
            html += `</div>`;
            
            statsContent.innerHTML = html;
        } else {
            statsContent.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    ${data.message || 'Error loading statistics'}
                </div>
            `;
        }
    })
    .catch(error => {
        console.error('Error loading stats:', error);
        statsContent.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                Error loading statistics
            </div>
        `;
    });
}

// Show alert message
function showAlert(message, type = 'info') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.content-area');
    container.insertBefore(alert, container.firstChild);
    
    setTimeout(() => {
        if (alert.parentNode) {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 150);
        }
    }, 5000);
}

// Add event listeners for auto-preview on filter change
['from_date', 'to_date', 'log_type', 'ip_filter', 'country_filter', 'vpn_filter', 'proxy_filter', 
 'severity_filter', 'attack_type_filter', 'status_filter', 'sort', 'limit'].forEach(id => {
    document.getElementById(id).addEventListener('change', () => {
        // Debounce preview loading
        clearTimeout(window.previewTimeout);
        window.previewTimeout = setTimeout(loadPreview, 500);
    });
});

// Auto-refresh stats every 30 seconds
setInterval(loadStats, 30000);
</script>

<?php
// Export functions
function exportCSV($data, $log_type, $start_date, $end_date, $total_count) {
    $filename = "{$log_type}_logs_" . date('Y-m-d_H-i-s') . ".csv";
    
    header("Content-Type: text/csv");
    header("Content-Disposition: attachment; filename={$filename}");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    $output = fopen("php://output", "w");
    fwrite($output, "\xEF\xBB\xBF"); // UTF-8 BOM
    
    if (!empty($data)) {
        // Write headers
        fputcsv($output, array_keys($data[0]));
        
        // Write data
        foreach ($data as $row) {
            // Clean up any line breaks in CSV fields
            $clean_row = array_map(function($value) {
                if (is_string($value)) {
                    // Remove line breaks and trim
                    return str_replace(["\r", "\n"], ' ', trim($value));
                }
                return $value;
            }, $row);
            fputcsv($output, $clean_row);
        }
    }
    
    fclose($output);
}

function exportPDF($data, $log_type, $start_date, $end_date, $total_count) {
    require_once('../libs/tcpdf/tcpdf.php');
    
    $pdf = new TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);
    $pdf->SetCreator('Security Monitoring System');
    $pdf->SetAuthor('Security System');
    $pdf->SetTitle(ucfirst($log_type) . ' Logs Report');
    $pdf->setPrintHeader(true);
    $pdf->setPrintFooter(true);
    $pdf->SetMargins(15, 25, 15);
    $pdf->SetAutoPageBreak(TRUE, 15);
    $pdf->AddPage();
    
    // Header
    $pdf->SetFont('helvetica', 'B', 16);
    $pdf->Cell(0, 10, ucfirst($log_type) . ' Logs Report', 0, 1, 'C');
    
    // Report info
    $pdf->SetFont('helvetica', '', 10);
    $pdf->Cell(0, 6, 'Generated: ' . date('Y-m-d H:i:s'), 0, 1);
    $pdf->Cell(0, 6, 'Report Type: ' . ucfirst($log_type) . ' Logs', 0, 1);
    if (!empty($start_date) && !empty($end_date)) {
        $pdf->Cell(0, 6, 'Date Range: ' . $start_date . ' to ' . $end_date, 0, 1);
    }
    $pdf->Cell(0, 6, 'Total Records: ' . number_format($total_count), 0, 1);
    $pdf->Ln(5);
    
    if (!empty($data)) {
        // Determine columns to display (limit to 8 for PDF readability)
        $columns = array_keys($data[0]);
        $display_columns = array_slice($columns, 0, 8);
        
        // Create table
        $html = '<style>
            table { border-collapse: collapse; width: 100%; font-size: 8pt; }
            th { background-color: #f2f2f2; font-weight: bold; padding: 4px; border: 1px solid #ddd; }
            td { padding: 3px; border: 1px solid #ddd; word-wrap: break-word; }
            .small { font-size: 7pt; }
            .center { text-align: center; }
        </style>';
        
        $html .= '<table>';
        $html .= '<tr>';
        foreach ($display_columns as $col) {
            $html .= '<th width="' . (100/count($display_columns)) . '%">' . ucfirst(str_replace('_', ' ', $col)) . '</th>';
        }
        $html .= '</tr>';
        
        $count = 0;
        foreach ($data as $row) {
            if ($count++ >= 100) { // Limit PDF to 100 rows
                $html .= '<tr><td colspan="' . count($display_columns) . '" class="center small">... and ' . ($total_count - 100) . ' more records</td></tr>';
                break;
            }
            
            $html .= '<tr>';
            foreach ($display_columns as $col) {
                $value = isset($row[$col]) ? $row[$col] : '';
                if (is_string($value)) {
                    $value = htmlspecialchars(substr($value, 0, 50));
                }
                $html .= '<td class="small">' . $value . '</td>';
            }
            $html .= '</tr>';
        }
        
        $html .= '</table>';
        
        $pdf->writeHTML($html, true, false, true, false, '');
    } else {
        $pdf->Cell(0, 10, 'No data available for the selected filters', 0, 1, 'C');
    }
    
    $filename = "{$log_type}_logs_" . date('Y-m-d_H-i-s') . ".pdf";
    $pdf->Output($filename, 'D');
}

function exportJSON($data, $log_type, $start_date, $end_date, $total_count) {
    $filename = "{$log_type}_logs_" . date('Y-m-d_H-i-s') . ".json";
    
    header("Content-Type: application/json");
    header("Content-Disposition: attachment; filename={$filename}");
    
    $export_data = [
        'metadata' => [
            'export_type' => $log_type,
            'generated_at' => date('Y-m-d H:i:s'),
            'date_range' => ['from' => $start_date, 'to' => $end_date],
            'total_records' => $total_count,
            'exported_records' => count($data)
        ],
        'data' => $data
    ];
    
    echo json_encode($export_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}

function exportExcel($data, $log_type, $start_date, $end_date, $total_count) {
    // For Excel export, we'll use CSV with .xls extension
    $filename = "{$log_type}_logs_" . date('Y-m-d_H-i-s') . ".xls";
    
    header("Content-Type: application/vnd.ms-excel");
    header("Content-Disposition: attachment; filename={$filename}");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    echo "<html><head><meta charset='UTF-8'></head><body>";
    echo "<table border='1'>";
    
    if (!empty($data)) {
        // Headers
        echo "<tr>";
        foreach (array_keys($data[0]) as $header) {
            echo "<th>" . htmlspecialchars($header) . "</th>";
        }
        echo "</tr>";
        
        // Data
        foreach ($data as $row) {
            echo "<tr>";
            foreach ($row as $cell) {
                echo "<td>" . htmlspecialchars($cell) . "</td>";
            }
            echo "</tr>";
        }
    }
    
    echo "</table></body></html>";
}

include '../includes/footer.php';
?>