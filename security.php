<?php
// ==============================
// CONFIGURATION
// ==============================
define('USER_ID', 1);       // Current user ID
define('WEBSITE_ID', 1);    // Current website ID

class AdvancedSecurityLogger {
    private $db;
    private $threatLevels = [
        'SQLi' => 'Critical',
        'XSS' => 'High',
        'DoS' => 'Critical',
        'LFI' => 'High',
        'RFI' => 'Critical',
        'RCE' => 'Critical',
        'BruteForce' => 'Medium',
        'SuspiciousInput' => 'Low'
    ];
    
    // Known attack patterns
    private $attackPatterns = [
        'SQLi' => ['/(union[\s\+]+select)|(select.+from)|(insert.+into)|(drop.+table)|(\d+\s*=\s*\d+)/i'],
        'XSS' => ['/<script|<iframe|javascript:|onload\s*=|onerror\s*=/i'],
        'LFI' => ['/\.\.\/|\.\.\\|etc\/passwd|proc\/self/i'],
        'RFI' => ['/https?:\/\/|ftp:\/\/|php:\/\/input/i'],
        'RCE' => ['/(system|shell_exec|exec|passthru|eval|assert)\s*\(/i']
    ];

    public function __construct() {
        $this->connectDB();
        register_shutdown_function([$this, 'logShutdown']);
    }
    
    private function connectDB() {
        try {
            $this->db = new PDO(
                'mysql:host=localhost;dbname=mailfor;charset=utf8mb4', 
                'root', 
                '',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
        } catch (PDOException $e) {
            error_log("Security Logger DB Error: " . $e->getMessage());
        }
    }
    
    public function monitorRequest() {
        $this->detectInputThreats();
        $this->detectBruteForce();
        $this->detectTrafficAnomalies();
        $this->checkBlockedIPs();
    }

    // ==============================
    // BLOCKED IP CHECK
    // ==============================
    private function checkBlockedIPs() {
        $ip = $this->getClientIP();

        $stmt = $this->db->prepare("
            SELECT * FROM blocked_ips 
            WHERE ip = :ip AND 
                  ((user_id = 0 AND website_id = 0) OR 
                   (user_id = :uid AND website_id = :wid))
            LIMIT 1
        ");
        $stmt->execute([
            ':ip'  => $ip,
            ':uid' => USER_ID,
            ':wid' => WEBSITE_ID
        ]);
        $blocked = $stmt->fetch();

        if ($blocked) {
            http_response_code(403);
            echo "Access denied. Your IP has been blocked.";
            exit;
        }
    }
    
    // ==============================
    // INPUT THREAT DETECTION
    // ==============================
    private function detectInputThreats() {
        $inputs = array_merge($_GET, $_POST, $_COOKIE);
        
        foreach ($inputs as $key => $value) {
            if (is_array($value)) continue;
            
            foreach ($this->attackPatterns as $type => $patterns) {
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $this->logAttack(
                            $type, 
                            $this->threatLevels[$type] ?? 'Medium',
                            "$key=" . substr($value, 0, 100)
                        );
                        $this->takeAction($type);
                        break 2;
                    }
                }
            }
        }
    }
    
    // ==============================
    // BRUTE FORCE DETECTION
    // ==============================
    private function detectBruteForce() {
        $ip = $this->getClientIP();
        $attempts = $this->countRecentEvents($ip, 'login_attempt');

        if ($attempts > 5) {
            $this->logAttack(
                'BruteForce', 
                'Medium', 
                "Multiple login attempts ($attempts)"
            );
        }
    }
    
    // ==============================
    // TRAFFIC ANOMALY DETECTION
    // ==============================
    private function detectTrafficAnomalies() {
        $ip = $this->getClientIP();
        $reqRate = $this->getRequestRate($ip);
        
        if ($reqRate > 100) {
            $this->logAttack(
                'DoS', 
                'Critical', 
                "High request rate ($reqRate/min)"
            );
            $this->takeAction('DoS');
        }
    }
    
    // ==============================
    // LOG ATTACKS TO DATABASE
    // ==============================
    private function logAttack($type, $severity, $payload = '') {
        try {
            $ip = $this->getClientIP();
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $url = $_SERVER['REQUEST_URI'] ?? '';

            // Insert into attack_logs
            $stmt = $this->db->prepare("
                INSERT INTO attack_logs 
                (timestamp, attack_type, severity, ip_address, user_agent, attack_payload, request_url, user_id, website_id) 
                VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([$type, $severity, $ip, $ua, $payload, $url, USER_ID, WEBSITE_ID]);

            // Block IP if critical
            if (in_array($severity, ['Critical'])) {
                $this->blockIP($ip);
            }

        } catch (Exception $e) {
            error_log("Security Logger Error: " . $e->getMessage());
        }
    }
    
    // ==============================
    // TAKE ACTION ON THREAT
    // ==============================
    private function takeAction($threatType) {
        switch ($threatType) {
            case 'SQLi':
            case 'RCE':
                $this->blockIP($this->getClientIP());
                break;
            case 'DoS':
                usleep(500000);
                break;
            case 'XSS':
                header("X-XSS-Protection: 1; mode=block");
                break;
        }
    }

    // ==============================
    // BLOCK IP IN DATABASE
    // ==============================
    private function blockIP($ip) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO blocked_ips (ip, user_id, website_id, timestamp)
                VALUES (?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE timestamp = NOW()
            ");
            $stmt->execute([$ip, USER_ID, WEBSITE_ID]);
        } catch (Exception $e) {
            error_log("Failed to block IP $ip: " . $e->getMessage());
        }
    }

    // ==============================
    // UTILITIES
    // ==============================
    private function getClientIP() {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (!empty($_SERVER[$key])) {
                return is_array($_SERVER[$key]) ? $_SERVER[$key][0] : $_SERVER[$key];
            }
        }
        return '0.0.0.0';
    }

    private function countRecentEvents($ip, $eventType, $seconds = 300) {
        static $eventCount = [];
        $key = "$ip-$eventType-".floor(time()/$seconds);

        if (!isset($eventCount[$key])) {
            $eventCount[$key] = 0;
        }

        return ++$eventCount[$key];
    }

    private function getRequestRate($ip) {
        return $this->countRecentEvents($ip, 'request', 60);
    }

    // ==============================
    // LOG PHP ERRORS ON SHUTDOWN
    // ==============================
    public function logShutdown() {
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_WARNING, E_PARSE])) {
            $this->logAttack(
                'PHP_Error', 
                'Medium', 
                "{$error['message']} in {$error['file']}:{$error['line']}"
            );
        }
    }
}

// ==============================
// USAGE
// ==============================
$securityLogger = new AdvancedSecurityLogger();
$securityLogger->monitorRequest();
?>