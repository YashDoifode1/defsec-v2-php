<?php
// ==============================
// collect.php - Multi-Tenant API Gateway with Advanced Fingerprint Processing
// ==============================

// ✅ CORS headers for API endpoint
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With, X-Session-ID, X-Security-Version');
header('Access-Control-Max-Age: 86400');
header('X-Content-Type-Options: nosniff');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit();
}

try {
    // Get JSON input with error handling
    $inputRaw = file_get_contents('php://input');
    if (!$inputRaw) {
        throw new Exception('Empty request body');
    }
    
    $input = json_decode($inputRaw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON: ' . json_last_error_msg());
    }
    
    if (!$input || !isset($input['api_key']) || !isset($input['payload'])) {
        throw new Exception('Invalid request format: missing api_key or payload');
    }
    
    $apiKey = $input['api_key'];
    $payload = $input['payload'];
    $sessionId = $input['payload']['session']['id'] ?? $_SERVER['HTTP_X_SESSION_ID'] ?? bin2hex(random_bytes(16));
    
    // Validate API key format (32 char hex)
    if (!preg_match('/^[a-f0-9]{32}$/', $apiKey)) {
        throw new Exception('Invalid API key format');
    }
    
    // Database connection with persistent connection for performance
    $pdo = new PDO(
        'mysql:host=sql110.infinityfree.com;dbname=if0_41139861_defsec;charset=utf8mb4',
        'if0_41139861',
        'PmPCYvBP79RP',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => true
        ]
    );
    
    // Validate API key and resolve tenant
    $stmt = $pdo->prepare("
        SELECT 
            w.id as website_id, 
            w.user_id, 
            w.domain,
            w.name as website_name,
            w.security_level,
            w.settings as website_settings,
            u.email as user_email,
            u.api_key as user_api_key,
            u.plan as user_plan
        FROM websites w
        INNER JOIN users u ON w.user_id = u.id
        WHERE w.api_key = :api_key 
        AND w.is_active = 1 
        AND u.is_active = 1
        LIMIT 1
    ");
    $stmt->execute([':api_key' => $apiKey]);
    $tenant = $stmt->fetch();
    
    if (!$tenant) {
        error_log("Failed API key attempt: " . substr($apiKey, 0, 8) . "...");
        throw new Exception('Invalid or inactive API key');
    }
    
    // Initialize security logger with tenant context
    require_once __DIR__ . '/backend/AdvancedSecurityLogger.php';
    
    $logger = new AdvancedSecurityLogger(
        $pdo,
        (int)$tenant['user_id'],
        (int)$tenant['website_id']
    );
    
    // Extract client IP from multiple sources
    $clientIP = $payload['server']['ip_address'] ?? 
                $payload['server']['remote_addr'] ?? 
                $payload['client']['webrtcIP'] ??
                $payload['client']['serverIp'] ??
                $_SERVER['HTTP_CF_CONNECTING_IP'] ?? 
                $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
                $_SERVER['REMOTE_ADDR'] ?? 
                '0.0.0.0';
    
    // Clean IP (handle comma-separated lists)
    if (strpos($clientIP, ',') !== false) {
        $clientIP = trim(explode(',', $clientIP)[0]);
    }
    
    // Quick block check before full processing
    if ($logger->isIPBlocked($clientIP)) {
        echo json_encode([
            'success' => true,
            'blocked' => true,
            'reason' => 'IP blocked',
            'action' => 'block',
            'session_id' => $sessionId
        ]);
        exit();
    }
    
    // Process fingerprint and threat detection
    $result = $logger->processAdvancedRequest($payload, $tenant);
    
    // Store fingerprint data for future recognition
    if (isset($payload['client']['digitalDNA'])) {
        $logger->storeFingerprint($clientIP, $payload['client'], $sessionId);
    }
    
    // Check for fingerprint-based blocking
    if (isset($payload['client']['digitalDNA'])) {
        $fingerprintBlocked = $logger->isFingerprintBlocked($payload['client']['digitalDNA']);
        if ($fingerprintBlocked) {
            $logger->blockIP($clientIP, 'Fingerprint blocked');
            echo json_encode([
                'success' => true,
                'blocked' => true,
                'reason' => 'Device fingerprint blocked',
                'action' => 'block',
                'session_id' => $sessionId
            ]);
            exit();
        }
    }
    
    // Log the visit with all fingerprint data
    $logger->logAdvancedVisit($clientIP, $payload, $tenant, $sessionId);
    
    // Prepare comprehensive response
    $response = [
        'success' => true,
        'timestamp' => time(),
        'session_id' => $sessionId,
        'request_id' => bin2hex(random_bytes(8))
    ];
    
    // Add security action results
    if (isset($result['action'])) {
        $response['action'] = $result['action'];
    }
    
    if (isset($result['blocked'])) {
        $response['blocked'] = $result['blocked'];
    }
    
    // Add threat detection results
    if (isset($result['threats']) && !empty($result['threats'])) {
        $response['threats_detected'] = count($result['threats']);
        $response['threat_level'] = $result['threat_level'] ?? 'low';
        $response['threats'] = array_map(function($threat) {
            return [
                'type' => $threat['type'],
                'severity' => $threat['severity']
            ];
        }, array_slice($result['threats'], 0, 5)); // Limit to 5 threats in response
    }
    
    // Add tenant info (non-sensitive)
    $response['tenant'] = [
        'website_id' => $tenant['website_id'],
        'website_name' => $tenant['website_name'] ?? null,
        'domain' => $tenant['domain'] ?? null
    ];
    
    // Add fingerprint status
    if (isset($payload['client']['digitalDNA'])) {
        $response['fingerprint'] = [
            'registered' => true,
            'hash' => substr($payload['client']['digitalDNA'], 0, 8) . '...'
        ];
    }
    
    echo json_encode($response);
    
} catch (PDOException $e) {
    error_log("Collect.php DB Error: " . $e->getMessage() . " [Code: " . $e->getCode() . "]");
    http_response_code(503);
    echo json_encode([
        'success' => false,
        'error' => 'Database service unavailable',
        'code' => 'DB_ERROR'
    ]);
    
} catch (Exception $e) {
    error_log("Collect.php Error: " . $e->getMessage());
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'Security service unavailable',
        'code' => 'SERVICE_ERROR'
    ]);
}