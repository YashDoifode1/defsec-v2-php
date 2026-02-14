<?php
// ENSURE THIS SCRIPT IS ACCESSABLE BY TRACK [API] USERS IN FETCH JQUERY 
// Ensure this script is accessed only via POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('HTTP/1.1 403 Forbidden');
    exit('Direct access not allowed');
}

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database Configuration - Consider moving to config file
$db_config = [
    'host' => "localhost",
    'user' => "root",
    'password' => "",
    'database' => "mailfor",
    'charset' => "utf8mb4"
];

// Secure Database Connection with error handling
try {
    $conn = new mysqli($db_config['host'], $db_config['user'], 
                      $db_config['password'], $db_config['database']);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    $conn->set_charset($db_config['charset']);
} catch (Exception $e) {
    error_log($e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    exit('Database connection error');
}

// Validate and process JSON input
$input = json_decode(file_get_contents("php://input"), true);
if (!$input || json_last_error() !== JSON_ERROR_NONE) {
    header('HTTP/1.1 400 Bad Request');
    exit('Invalid JSON input');
}

// IP Address Handling
$ip = filter_var($_SERVER['REMOTE_ADDR'] ?? 'Unknown', FILTER_VALIDATE_IP) ?: 'Unknown';
$real_ip = filter_var($input['ip'] ?? $ip, FILTER_VALIDATE_IP) ?: 'Unknown';

// Enhanced Reverse DNS Lookup with caching
function get_reverse_dns($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Invalid IP";
    
    // Cache results for 1 hour to reduce DNS queries
    $cache_key = 'dns_'.md5($ip);
    if (function_exists('apcu_fetch') && $cached = apcu_fetch($cache_key)) {
        return $cached;
    }
    
    $hostname = gethostbyaddr($ip) ?: "Lookup failed";
    
    if (function_exists('apcu_store')) {
        apcu_store($cache_key, $hostname, 3600);
    }
    
    return $hostname;
}

// Data Sanitization with type preservation
function sanitize_input($value, $type = 'string') {
    if (is_null($value)) return null;
    
    switch ($type) {
        case 'int':
            return filter_var($value, FILTER_VALIDATE_INT) ?: 0;
        case 'float':
            return filter_var($value, FILTER_VALIDATE_FLOAT) ?: 0.0;
        case 'bool':
            return filter_var($value, FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
        default:
            return htmlspecialchars(strip_tags($value), ENT_QUOTES, 'UTF-8');
    }
}

// Extract and sanitize all data fields
$tracking_data = [
    'user_id' => sanitize_input($input['user_id'] ?? 0, 'int'),
    'website_id' => sanitize_input($input['website_id'] ?? 0, 'int'),
    'ip' => $ip,
    'real_ip' => $real_ip,
    'reverse_dns' => get_reverse_dns($real_ip),
    'webrtc_ip' => sanitize_input($input['webrtcIP'] ?? 'Unknown'),
    'dns_leak_ip' => sanitize_input($input['dnsLeakIP'] ?? 'Unknown'),
    'user_agent' => sanitize_input($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
    'screen_resolution' => sanitize_input($input['screenResolution'] ?? 'Unknown'),
    'language' => sanitize_input($input['language'] ?? 'Unknown'),
    'timezone' => sanitize_input($input['timezone'] ?? 'Unknown'),
    'cookies_enabled' => sanitize_input($input['cookiesEnabled'] ?? 'Unknown'),
    'cpu_cores' => sanitize_input($input['cpuCores'] ?? 'Unknown'),
    'ram' => sanitize_input($input['ram'] ?? 'Unknown'),
    'gpu' => sanitize_input($input['gpu'] ?? 'Unknown'),
    'battery' => sanitize_input($input['battery'] ?? 'Unknown'),
    'referrer' => sanitize_input($input['referrer'] ?? 'None'),
    'plugins' => sanitize_input($input['plugins'] ?? 'None'),
    'digital_dna' => sanitize_input($input['digitalDNA'] ?? 'Unknown'),
    'country' => sanitize_input($input['country'] ?? 'Unknown'),
    'city' => sanitize_input($input['city'] ?? 'Unknown'),
    'ISP' => sanitize_input($input['ISP'] ?? 'Unknown'),
    'ASN' => sanitize_input($input['ASN'] ?? 'Unknown'),
    'latitude' => isset($input['latitude']) ? sanitize_input($input['latitude'], 'float') : null,
    'longitude' => isset($input['longitude']) ? sanitize_input($input['longitude'], 'float') : null
];

// Enhanced IP Reputation Check with caching and fallback
function check_ip_reputation($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return [
            'is_vpn' => 0,
            'is_tor' => 0,
            'is_proxy' => 0
        ];
    }

    $cache_key = 'iprep_'.md5($ip);
    if (function_exists('apcu_fetch') && $cached = apcu_fetch($cache_key)) {
        return $cached;
    }

    $api_key = "UIBQsNrKKJy9yOjGx4JLNPSJSE6XGxQy";
    $url = "https://ipqualityscore.com/api/json/ip/$api_key/$ip";

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $default_result = [
        'is_vpn' => 0,
        'is_tor' => 0,
        'is_proxy' => 0
    ];

    if ($http_code !== 200 || !$response) {
        return $default_result;
    }

    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return $default_result;
    }

    $result = [
        'is_vpn' => isset($data['vpn']) ? (int)$data['vpn'] : 0,
        'is_tor' => isset($data['tor']) ? (int)$data['tor'] : 0,
        'is_proxy' => isset($data['proxy']) ? (int)$data['proxy'] : 0
    ];

    if (function_exists('apcu_store')) {
        apcu_store($cache_key, $result, 3600); // Cache for 1 hour
    }

    return $result;
}

$ip_reputation = check_ip_reputation($real_ip);

// Prepare and execute database insert with transaction
try {
    $conn->autocommit(false); // Start transaction
    
    $stmt = $conn->prepare("
        INSERT INTO logs 
        (user_id, website_id, ip, real_ip, reverse_dns, webrtc_ip, dns_leak_ip, 
         user_agent, screen_resolution, language, timezone, cookies_enabled, 
         cpu_cores, ram, gpu, battery, referrer, plugins, digital_dna, 
         is_vpn, is_tor, is_proxy, ASN, ISP, country, city, latitude, longitude) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    
    if (!$stmt) {
        throw new Exception("Prepare failed: " . $conn->error);
    }
    
    $bind_result = $stmt->bind_param(
        "iisssssssssssssssssiiissssdd",
        $tracking_data['user_id'],
        $tracking_data['website_id'],
        $tracking_data['ip'],
        $tracking_data['real_ip'],
        $tracking_data['reverse_dns'],
        $tracking_data['webrtc_ip'],
        $tracking_data['dns_leak_ip'],
        $tracking_data['user_agent'],
        $tracking_data['screen_resolution'],
        $tracking_data['language'],
        $tracking_data['timezone'],
        $tracking_data['cookies_enabled'],
        $tracking_data['cpu_cores'],
        $tracking_data['ram'],
        $tracking_data['gpu'],
        $tracking_data['battery'],
        $tracking_data['referrer'],
        $tracking_data['plugins'],
        $tracking_data['digital_dna'],
        $ip_reputation['is_vpn'],
        $ip_reputation['is_tor'],
        $ip_reputation['is_proxy'],
        $tracking_data['ASN'],
        $tracking_data['ISP'],
        $tracking_data['country'],
        $tracking_data['city'],
        $tracking_data['latitude'],
        $tracking_data['longitude']
    );
    
    if (!$bind_result) {
        throw new Exception("Bind failed: " . $stmt->error);
    }
    
    if (!$stmt->execute()) {
        throw new Exception("Execute failed: " . $stmt->error);
    }
    
    $conn->commit();
    header('Content-Type: application/json');
    echo json_encode(['status' => 'success', 'message' => 'Tracking data saved']);
    
} catch (Exception $e) {
    $conn->rollback();
    error_log("Tracking error: " . $e->getMessage());
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
} finally {
    if (isset($stmt)) $stmt->close();
    $conn->autocommit(true);
    $conn->close();
}