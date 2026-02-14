<?php
// ==============================
// AdvancedSecurityLogger.php - Multi-Tenant Core
// ==============================

class AdvancedSecurityLogger {
    private PDO $db;
    private int $userId;
    private int $websiteId;
    private array $threatLevels;
    private array $attackPatterns;
    private array $requestData;
    
    public function __construct(PDO $pdo, int $userId, int $websiteId) {
        $this->db = $pdo;
        $this->userId = $userId;
        $this->websiteId = $websiteId;
        $this->threatLevels = [
            'SQLi' => 'Critical',
            'XSS' => 'High',
            'DoS' => 'Critical',
            'LFI' => 'High',
            'RFI' => 'Critical',
            'RCE' => 'Critical',
            'BruteForce' => 'Medium',
            'SuspiciousInput' => 'Low',
            'Client_XSS' => 'High'
        ];
        
        $this->attackPatterns = [
            'SQLi' => ['/(union[\s\+]+select)|(select.+from)|(insert.+into)|(drop.+table)|(\d+\s*=\s*\d+)/i'],
            'XSS' => ['/<script|<iframe|javascript:|onload\s*=|onerror\s*=/i'],
            'LFI' => ['/\.\.\/|\.\.\\|etc\/passwd|proc\/self/i'],
            'RFI' => ['/https?:\/\/|ftp:\/\/|php:\/\/input/i'],
            'RCE' => ['/(system|shell_exec|exec|passthru|eval|assert)\s*\(/i']
        ];
    }
    
    public function processRequest(array $payload): array {
        $this->requestData = $payload;
        $blocked = false;
        $action = 'monitor';
        
        // Check if IP is already blocked
        if ($this->isIPBlocked($this->getClientIP())) {
            return ['action' => 'blocked', 'blocked' => true];
        }
        
        // Run threat detection
        $threats = $this->detectAllThreats($payload);
        
        foreach ($threats as $threat) {
            $this->logAttack(
                $threat['type'],
                $threat['severity'],
                $threat['payload']
            );
            
            $action = $this->takeAction($threat['type'], $threat['severity']);
            if ($action === 'block') {
                $blocked = true;
            }
        }
        
        // Log normal request if no threats
        if (empty($threats)) {
            $this->logNormalRequest();
        }
        
        // Monitor for brute force attempts
        $this->detectBruteForce();
        
        return ['action' => $action, 'blocked' => $blocked];
    }
    
    private function detectAllThreats(array $data): array {
        $threats = [];
        
        // Check server-side input threats
        if (isset($data['request']['parameters'])) {
            foreach ($data['request']['parameters'] as $key => $value) {
                if (is_array($value)) continue;
                
                foreach ($this->attackPatterns as $type => $patterns) {
                    foreach ($patterns as $pattern) {
                        if (preg_match($pattern, $value)) {
                            $threats[] = [
                                'type' => $type,
                                'severity' => $this->threatLevels[$type] ?? 'Medium',
                                'payload' => "$key=" . substr($value, 0, 100)
                            ];
                            break 2;
                        }
                    }
                }
            }
        }
        
        // Check client-side XSS
        if (isset($data['type']) && $data['type'] === 'client_xss') {
            $threats[] = [
                'type' => 'Client_XSS',
                'severity' => 'High',
                'payload' => $data['details'] ?? 'Client-side XSS detected'
            ];
        }
        
        // Check request rate
        $requestRate = $this->getRequestRate($this->getClientIP());
        if ($requestRate > 100) {
            $threats[] = [
                'type' => 'DoS',
                'severity' => 'Critical',
                'payload' => "High request rate ($requestRate/min)"
            ];
        }
        
        return $threats;
    }
    
    private function logAttack(string $type, string $severity, string $payload = ''): void {
        try {
            $ip = $this->getClientIP();
            $ua = $this->requestData['server']['user_agent'] ?? 'Unknown';
            $url = $this->requestData['request']['url'] ?? '';
            
            $stmt = $this->db->prepare("
                INSERT INTO attack_logs 
                (timestamp, attack_type, severity, ip_address, user_agent, attack_payload, 
                 request_url, user_id, website_id, metadata) 
                VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $type,
                $severity,
                $ip,
                $ua,
                $payload,
                $url,
                $this->userId,
                $this->websiteId,
                json_encode([
                    'screen' => $this->requestData['client']['screen_resolution'] ?? null,
                    'timezone' => $this->requestData['client']['timezone'] ?? null,
                    'referrer' => $this->requestData['client']['referrer'] ?? null
                ])
            ]);
            
            // Block IP if critical
            if (in_array($severity, ['Critical'])) {
                $this->blockIP($ip, $type);
            }
            
        } catch (Exception $e) {
            error_log("Security Logger Error (Tenant {$this->websiteId}): " . $e->getMessage());
        }
    }
    
    private function logNormalRequest(): void {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO logs 
                (timestamp, ip_address, user_agent, request_url, user_id, website_id, metadata) 
                VALUES (NOW(), ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $this->getClientIP(),
                $this->requestData['server']['user_agent'] ?? 'Unknown',
                $this->requestData['request']['url'] ?? '',
                $this->userId,
                $this->websiteId,
                json_encode([
                    'load_time' => $this->requestData['client']['load_time'] ?? null,
                    'dom_time' => $this->requestData['client']['dom_loaded'] ?? null,
                    'screen' => $this->requestData['client']['screen_resolution'] ?? null
                ])
            ]);
        } catch (Exception $e) {
            error_log("Failed to log normal request: " . $e->getMessage());
        }
    }
    
    private function detectBruteForce(): void {
        $ip = $this->getClientIP();
        
        // Check login attempts in last 5 minutes
        $stmt = $this->db->prepare("
            SELECT COUNT(*) as attempt_count 
            FROM attack_logs 
            WHERE ip_address = :ip 
                AND attack_type = 'BruteForce' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
                AND user_id = :user_id 
                AND website_id = :website_id
        ");
        
        $stmt->execute([
            ':ip' => $ip,
            ':user_id' => $this->userId,
            ':website_id' => $this->websiteId
        ]);
        
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result['attempt_count'] > 5) {
            $this->blockIP($ip, 'BruteForce');
        }
    }
    
    private function isIPBlocked(string $ip): bool {
        $stmt = $this->db->prepare("
            SELECT id FROM blocked_ips 
            WHERE ip = :ip AND user_id = :user_id AND website_id = :website_id
            LIMIT 1
        ");
        
        $stmt->execute([
            ':ip' => $ip,
            ':user_id' => $this->userId,
            ':website_id' => $this->websiteId
        ]);
        
        return (bool)$stmt->fetch();
    }
    
    private function blockIP(string $ip, string $reason = ''): void {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO blocked_ips (ip, user_id, website_id, reason, timestamp)
                VALUES (?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                    timestamp = NOW(),
                    reason = VALUES(reason)
            ");
            
            $stmt->execute([$ip, $this->userId, $this->websiteId, $reason]);
        } catch (Exception $e) {
            error_log("Failed to block IP $ip for tenant {$this->websiteId}: " . $e->getMessage());
        }
    }
    
    private function takeAction(string $threatType, string $severity): string {
        if ($severity === 'Critical') {
            return 'block';
        }
        
        switch ($threatType) {
            case 'SQLi':
            case 'RCE':
                return 'block';
            case 'DoS':
                return 'delay';
            case 'XSS':
            case 'Client_XSS':
                return 'filter';
            default:
                return 'monitor';
        }
    }
    
    private function getClientIP(): string {
        return $this->requestData['server']['REMOTE_ADDR'] ?? 
               $this->requestData['server']['HTTP_X_FORWARDED_FOR'] ?? 
               $this->requestData['server']['HTTP_CF_CONNECTING_IP'] ?? 
               '0.0.0.0';
    }
    
    private function getRequestRate(string $ip): int {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) as request_count 
            FROM logs 
            WHERE ip_address = :ip 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
                AND user_id = :user_id 
                AND website_id = :website_id
        ");
        
        $stmt->execute([
            ':ip' => $ip,
            ':user_id' => $this->userId,
            ':website_id' => $this->websiteId
        ]);
        
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return (int)($result['request_count'] ?? 0);
    }
}