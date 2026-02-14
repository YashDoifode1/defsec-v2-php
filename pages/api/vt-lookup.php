<?php
// api/vt-lookup.php
header('Content-Type: application/json');

require_once '../../includes/db.php';

$ip = $_GET['ip'] ?? '';

if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['error' => 'Invalid IP']);
    exit;
}

// Check cache first
$stmt = $pdo->prepare("SELECT response_data FROM api_cache WHERE api_name = 'vt' AND query_key = ? AND expires_at > NOW()");
$stmt->execute([$ip]);
$cached = $stmt->fetchColumn();

if ($cached) {
    echo $cached;
    exit;
}

// Your VirusTotal API key
$apiKey = 'YOUR_VT_API_KEY';

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/{$ip}");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "x-apikey: {$apiKey}"
]);

$response = curl_exec($ch);
curl_close($ch);

// Cache the response
if ($response) {
    $stmt = $pdo->prepare("INSERT INTO api_cache (api_name, query_key, response_data, expires_at) 
                           VALUES ('vt', ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))
                           ON DUPLICATE KEY UPDATE response_data = ?, expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR)");
    $stmt->execute([$ip, $response, $response]);
}

echo $response ?: json_encode(['error' => 'Failed to fetch data']);
?>