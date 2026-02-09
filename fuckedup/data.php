<?php
// Database Configuration
$host = "localhost";
$user = "root";
$password = "";
$database = "mailfor";

// Secure Database Connection
$conn = new mysqli($host, $user, $password, $database);
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    exit;
}

// Get Data Sent from JavaScript
$data = json_decode(file_get_contents("php://input"), true);
if (!$data) {
    error_log("Invalid JSON input received.");
    exit;
}

// Get Visitor's IP Address Securely
$ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
$real_ip = filter_var($data['ip'] ?? $ip, FILTER_VALIDATE_IP) ?: 'Unknown';

// Function to Get Reverse DNS (PTR Record)
function get_reverse_dns($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) ? gethostbyaddr($ip) : "Invalid IP";
}

$hostname = get_reverse_dns($real_ip);

// Function to Sanitize Input
function sanitize_input($value) {
    return htmlspecialchars(strip_tags($value));
}

// Extract and Sanitize Data
$webrtc_ip = sanitize_input($data['webrtcIP'] ?? 'Unknown');
$dns_leak_ip = sanitize_input($data['dnsLeakIP'] ?? 'Unknown');
$user_agent = sanitize_input($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
$screen_resolution = sanitize_input($data['screenResolution'] ?? 'Unknown');
$language = sanitize_input($data['language'] ?? 'Unknown');
$timezone = sanitize_input($data['timezone'] ?? 'Unknown');
$cookies_enabled = sanitize_input($data['cookiesEnabled'] ?? 'Unknown');
$cpu_cores = sanitize_input($data['cpuCores'] ?? 'Unknown');
$ram = sanitize_input($data['ram'] ?? 'Unknown');
$gpu = sanitize_input($data['gpu'] ?? 'Unknown');
$battery = sanitize_input($data['battery'] ?? 'Unknown');
$referrer = sanitize_input($data['referrer'] ?? 'Unknown');
$plugins = sanitize_input($data['plugins'] ?? 'Unknown');
$digital_dna = sanitize_input($data['digitalDNA'] ?? 'Unknown'); // New field

// Function to Check VPN, Tor, Proxy Using IPQualityScore API
function check_ip_reputation($ip) {
    $api_key = "UIBQsNrKKJy9yOjGx4JLNPSJSE6XGxQy"; // Replace with your actual API key
    $url = "https://ipqualityscore.com/api/json/ip/$api_key/$ip";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200 || !$response) {
        error_log("Failed to fetch IP reputation data.");
        return ["is_vpn" => 0, "is_tor" => 0, "is_proxy" => 0, "ASN" => "Unknown", "ISP" => "Unknown"];
    }

    $data = json_decode($response, true);
    return [
    "is_vpn" => isset($data['vpn']) ? (int)$data['vpn'] : 0,
    "is_tor" => isset($data['tor']) ? (int)$data['tor'] : 0,
    "is_proxy" => isset($data['proxy']) ? (int)$data['proxy'] : 0,
    "ASN" => sanitize_input($data['ASN'] ?? "Unknown"),
    "ISP" => sanitize_input($data['ISP'] ?? "Unknown"),
    "country" => sanitize_input($data['country_name'] ?? "Unknown"),
    "latitude" => isset($data['latitude']) ? floatval($data['latitude']) : 0.0,
    "longitude" => isset($data['longitude']) ? floatval($data['longitude']) : 0.0
];

}

// Check if the IP is using VPN/Tor/Proxy
$status = check_ip_reputation($real_ip);

// Insert Data into Database Securely
$stmt = $conn->prepare("
    INSERT INTO logs 
    (ip, real_ip, reverse_dns, webrtc_ip, dns_leak_ip, user_agent, screen_resolution, language, timezone, cookies_enabled, 
     cpu_cores, ram, gpu, battery, referrer, plugins, digital_dna, is_vpn, is_tor, is_proxy, ASN, ISP, country, latitude, longitude) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
");


if ($stmt) {
    // Corrected bind_param: 22 placeholders = 22 variables
$stmt->bind_param("sssssssssssssssssiissssdd", 
    $ip, $real_ip, $hostname, $webrtc_ip, $dns_leak_ip,
    $user_agent, $screen_resolution, $language, $timezone, 
    $cookies_enabled, $cpu_cores, $ram, $gpu, $battery, 
    $referrer, $plugins, $digital_dna, 
    $status["is_vpn"], $status["is_tor"], $status["is_proxy"],
    $status["ASN"], $status["ISP"], $status["country"], 
    $status["latitude"], $status["longitude"]
);



    if (!$stmt->execute()) {
        error_log("Database insert error: " . $stmt->error);
    }

    $stmt->close();
} else {
    error_log("Database statement preparation failed: " . $conn->error);
}

$conn->close();
?>
