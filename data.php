<?php
// Allow only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(403);
    exit('Direct access not allowed');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

define('USER_ID', 1);
define('WEBSITE_ID', 1);

// ---------------- DATABASE ----------------
$conn = new mysqli("localhost", "root", "", "mailfor");

if ($conn->connect_error) {
    http_response_code(500);
    exit("Database connection failed");
}

$conn->set_charset("utf8mb4");

// ---------------- GET JSON INPUT ----------------
$input = json_decode(file_get_contents("php://input"), true);

if (!$input || json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    exit("Invalid JSON input");
}

// ---------------- HELPERS ----------------
function sanitize_string($value) {
    return htmlspecialchars(strip_tags((string)$value), ENT_QUOTES, 'UTF-8');
}

function sanitize_int($value) {
    return filter_var($value, FILTER_VALIDATE_INT) ?: 0;
}

function sanitize_float($value) {
    return filter_var($value, FILTER_VALIDATE_FLOAT) ?: 0.0;
}

function sanitize_bool($value) {
    return filter_var($value, FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
}

function get_reverse_dns($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Invalid IP";
    return @gethostbyaddr($ip) ?: "Lookup failed";
}

// ---------------- IP HANDLING ----------------
$ip = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP) ?: 'Unknown';
$real_ip = filter_var($input['ip'] ?? $ip, FILTER_VALIDATE_IP) ?: $ip;

// ---------------- TRACKING DATA ----------------
$tracking = [
    'user_id' => USER_ID,
    'website_id' => WEBSITE_ID,
    'ip' => $ip,
    'real_ip' => $real_ip,
    'hostname' => get_reverse_dns($real_ip),
    'webrtc_ip' => sanitize_string($input['webrtcIP'] ?? 'Unknown'),
    'dns_leak_ip' => sanitize_string($input['dnsLeakIP'] ?? 'Unknown'),
    'user_agent' => sanitize_string($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
    'screen_resolution' => sanitize_string($input['screenResolution'] ?? 'Unknown'),
    'language' => sanitize_string($input['language'] ?? 'Unknown'),
    'timezone' => sanitize_string($input['timezone'] ?? 'Unknown'),
    'cookies_enabled' => sanitize_bool($input['cookiesEnabled'] ?? 0),
    'cpu_cores' => sanitize_int($input['cpuCores'] ?? 0),
    'ram' => sanitize_string($input['ram'] ?? 'Unknown'),
    'gpu' => sanitize_string($input['gpu'] ?? 'Unknown'),
    'battery' => sanitize_string($input['battery'] ?? 'Unknown'),
    'referrer' => sanitize_string($input['referrer'] ?? 'None'),
    'plugins' => sanitize_string($input['plugins'] ?? 'None'),
    'digital_dna' => sanitize_string($input['digitalDNA'] ?? 'Unknown')
];

// ---------------- IP REPUTATION ----------------
function check_ip_reputation($ip) {

    $default = [
        'is_vpn'=>0,
        'is_tor'=>0,
        'is_proxy'=>0,
        'ASN'=>'Unknown',
        'ISP'=>'Unknown',
        'country'=>'Unknown',
        'latitude'=>0.0,
        'longitude'=>0.0
    ];

    if (!filter_var($ip, FILTER_VALIDATE_IP)) return $default;

    $api_key = "UIBQsNrKKJy9yOjGx4JLNPSJSE6XGxQy";
    $url = "https://ipqualityscore.com/api/json/ip/$api_key/$ip";

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true
    ]);

    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code !== 200 || !$response) return $default;

    $data = json_decode($response, true);
    if (!$data) return $default;

    return [
        'is_vpn' => isset($data['vpn']) ? (int)$data['vpn'] : 0,
        'is_tor' => isset($data['tor']) ? (int)$data['tor'] : 0,
        'is_proxy' => isset($data['proxy']) ? (int)$data['proxy'] : 0,
        'ASN' => sanitize_string($data['ASN'] ?? 'Unknown'),
        'ISP' => sanitize_string($data['ISP'] ?? 'Unknown'),
        'country' => sanitize_string($data['country_name'] ?? 'Unknown'),
        'latitude' => sanitize_float($data['latitude'] ?? 0),
        'longitude' => sanitize_float($data['longitude'] ?? 0)
    ];
}

$rep = check_ip_reputation($real_ip);

// ---------------- INSERT ----------------
$conn->autocommit(false);

$stmt = $conn->prepare("
    INSERT INTO logs
    (user_id, website_id, ip, real_ip, reverse_dns, webrtc_ip, dns_leak_ip,
     user_agent, screen_resolution, language, timezone, cookies_enabled,
     cpu_cores, ram, gpu, battery, referrer, plugins, digital_dna,
     is_vpn, is_tor, is_proxy, ASN, ISP, country, latitude, longitude, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
");

if (!$stmt) {
    http_response_code(500);
    exit("Prepare failed: " . $conn->error);
}

/*
27 parameters exactly
*/
$stmt->bind_param(
    "iisssssssssiiissssssiiisssdd",
    $tracking['user_id'],
    $tracking['website_id'],
    $tracking['ip'],
    $tracking['real_ip'],
    $tracking['hostname'],
    $tracking['webrtc_ip'],
    $tracking['dns_leak_ip'],
    $tracking['user_agent'],
    $tracking['screen_resolution'],
    $tracking['language'],
    $tracking['timezone'],
    $tracking['cookies_enabled'],
    $tracking['cpu_cores'],
    $tracking['ram'],
    $tracking['gpu'],
    $tracking['battery'],
    $tracking['referrer'],
    $tracking['plugins'],
    $tracking['digital_dna'],
    $rep['is_vpn'],
    $rep['is_tor'],
    $rep['is_proxy'],
    $rep['ASN'],
    $rep['ISP'],
    $rep['country'],
    $rep['latitude'],
    $rep['longitude']
);

if (!$stmt->execute()) {
    $conn->rollback();
    http_response_code(500);
    exit("Execute failed: " . $stmt->error);
}

$conn->commit();
$stmt->close();
$conn->close();

header('Content-Type: application/json');
echo json_encode([
    'status' => 'success',
    'message' => 'Tracking data saved'
]);