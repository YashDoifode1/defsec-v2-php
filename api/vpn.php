<?php
header('Content-Type: application/json');

// Constants for tracking
define('USER_ID', 1);
define('WEBSITE_ID', 1);

// Database Configuration
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'mailfor';

$db = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($db->connect_error) {
    http_response_code(500);
    exit(json_encode(['status'=>'error','message'=>"Database connection failed: ".$db->connect_error]));
}

// Get client IP (consider Cloudflare headers)
$clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

// For local testing
if ($clientIp === '127.0.0.1' || $clientIp === '::1') {
    $clientIp = '8.8.8.8'; // Example IP
}

// Load settings from DB
$settings = [];
$result = $db->query("SELECT setting_name, setting_value FROM settings");
while ($row = $result->fetch_assoc()) {
    $settings[$row['setting_name']] = $row['setting_value'];
}

// Fetch geo info
$geoApiUrl = "http://ip-api.com/json/{$clientIp}?fields=status,message,country,countryCode,proxy";
$response = file_get_contents($geoApiUrl);
$geoData = json_decode($response, true);

if (!$geoData || $geoData['status'] !== 'success') {
    http_response_code(400);
    exit(json_encode([
        'status'=>'error',
        'message'=>'Could not determine your location',
        'details'=>$geoData['message'] ?? 'Unknown error'
    ]));
}

$countryCode = $geoData['countryCode'];
$isProxy = $geoData['proxy'] ?? false;

// Check VPN/proxy blocking
if (!empty($settings['block_vpn']) && $settings['block_vpn'] == '1' && $isProxy) {
    http_response_code(403);
    exit(json_encode([
        'status'=>'error',
        'message'=>'VPN/Proxy access is not allowed',
        'country'=>$geoData['country'],
        'countryCode'=>$countryCode,
        'isProxy'=>true
    ]));
}

// Check country whitelist/allowed countries
$stmt = $db->prepare("SELECT is_allowed FROM allowed_countries WHERE country_code = ?");
$stmt->bind_param("s", $countryCode);
$stmt->execute();
$result = $stmt->get_result();

$blocked = false;
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    if (!$row['is_allowed']) $blocked = true;
} elseif (!empty($settings['strict_mode']) && $settings['strict_mode'] == '1') {
    $blocked = true;
}

if ($blocked) {
    http_response_code(403);
    exit(json_encode([
        'status'=>'error',
        'message'=>'Access denied for your country',
        'country'=>$geoData['country'],
        'countryCode'=>$countryCode
    ]));
}

// If access is allowed, log it (optional)
$stmtLog = $db->prepare("INSERT INTO access_logs (user_id, website_id, ip, country, country_code, is_proxy, timestamp) VALUES (?, ?, ?, ?, ?, ?, NOW())");
$stmtLog->bind_param("iisssi", USER_ID, WEBSITE_ID, $clientIp, $geoData['country'], $countryCode, $isProxy);
$stmtLog->execute();
$stmtLog->close();

// Access granted
echo json_encode([
    'status'=>'success',
    'message'=>'Access granted',
    'country'=>$geoData['country'],
    'countryCode'=>$countryCode,
    'isProxy'=>$isProxy
]);

$db->close();
?>

