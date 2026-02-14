<?php
// header('Content-Type: application/json');
// header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

// ==========================
// TEMP TESTING VALUES
// ==========================
$userId = 1;
$websiteId = 1;

// ==========================
// DB CONNECTION
// ==========================
$db = new mysqli("localhost", "root", "", "mailfor");

if ($db->connect_error) {
    http_response_code(500);
    exit(json_encode([
        'status' => 'error',
        'message' => 'Database connection failed'
    ]));
}

// ==========================
// GET CLIENT IP
// ==========================
$clientIp = $_SERVER['HTTP_CF_CONNECTING_IP']
    ?? $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR'];

// For local testing
if ($clientIp === '127.0.0.1' || $clientIp === '::1') {
    $clientIp = '8.8.8.8';
}

// ==========================
// CHECK BLOCKED IPS
// ==========================
$stmt = $db->prepare("
    SELECT id FROM blocked_ips 
    WHERE ip = ? 
    AND user_id = ? 
    AND website_id = ?
");
$stmt->bind_param("sii", $clientIp, $userId, $websiteId);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    http_response_code(403);
    exit(json_encode([
        'status' => 'error',
        'message' => 'Your IP is blocked'
    ]));
}
$stmt->close();

// ==========================
// LOAD SETTINGS (SCOPED)
// ==========================
$settings = [];
$stmt = $db->prepare("
    SELECT setting_name, setting_value 
    FROM settings 
    WHERE user_id = ? 
    AND website_id = ?
");
$stmt->bind_param("ii", $userId, $websiteId);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    $settings[$row['setting_name']] = $row['setting_value'];
}
$stmt->close();

// ==========================
// GEO LOOKUP
// ==========================
$geoApiUrl = "http://ip-api.com/json/{$clientIp}?fields=status,message,country,countryCode,proxy";
$response = @file_get_contents($geoApiUrl);
$geoData = json_decode($response, true);

if (!$geoData || $geoData['status'] !== 'success') {
    http_response_code(400);
    exit(json_encode([
        'status' => 'error',
        'message' => 'Could not determine location'
    ]));
}

$countryCode = $geoData['countryCode'];
$isProxy = $geoData['proxy'] ?? false;

// ==========================
// VPN BLOCK CHECK
// ==========================
if (!empty($settings['block_vpn']) && $settings['block_vpn'] == '1' && $isProxy) {
    http_response_code(403);
    exit(json_encode([
        'status' => 'error',
        'message' => 'VPN/Proxy access is not allowed',
        'country' => $geoData['country'],
        'countryCode' => $countryCode,
        'isProxy' => true
    ]));
}

// ==========================
// COUNTRY CHECK
// ==========================
$stmt = $db->prepare("
    SELECT is_allowed 
    FROM allowed_countries 
    WHERE country_code = ?
    AND user_id = ?
    AND website_id = ?
");
$stmt->bind_param("sii", $countryCode, $userId, $websiteId);
$stmt->execute();
$result = $stmt->get_result();

$blocked = false;

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    if (!$row['is_allowed']) {
        $blocked = true;
    }
} elseif (!empty($settings['strict_mode']) && $settings['strict_mode'] == '1') {
    $blocked = true;
}

$stmt->close();

if ($blocked) {
    http_response_code(403);
    exit(json_encode([
        'status' => 'error',
        'message' => 'Access denied for your country',
        'country' => $geoData['country'],
        'countryCode' => $countryCode
    ]));
}

// ==========================
// LOG ACCESS
// ==========================
$stmt = $db->prepare("
    INSERT INTO access_logs 
    (user_id, website_id, ip_address, user_agent, referrer, request_uri, http_method, query_string) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
");

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
$requestUri = $_SERVER['REQUEST_URI'] ?? '';
$httpMethod = $_SERVER['REQUEST_METHOD'] ?? '';
$queryString = $_SERVER['QUERY_STRING'] ?? '';

$stmt->bind_param(
    "iissssss",
    $userId,
    $websiteId,
    $clientIp,
    $userAgent,
    $referrer,
    $requestUri,
    $httpMethod,
    $queryString
);

$stmt->execute();
$stmt->close();

// ==========================
// SUCCESS RESPONSE
// ==========================
echo json_encode([
    'status' => 'success',
    'message' => 'Access granted',
    'country' => $geoData['country'],
    'countryCode' => $countryCode,
    'isProxy' => $isProxy
]);

$db->close();
