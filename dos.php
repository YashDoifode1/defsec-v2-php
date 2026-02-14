<?php

class DDoSProtector {

    private $db;
    private $clientIP;

    // 🔒 Hardcoded values
    private $user_id = 1;
    private $website_id = 1;

    private $config = [
        'requests_per_minute' => 100,
        'block_duration'      => 300
    ];

    public function __construct($mysqli, $customConfig = []) {

        $this->db = $mysqli;
        $this->config = array_merge($this->config, $customConfig);
        $this->clientIP = $this->getRealIP();

        $this->runProtection();
    }

    private function getRealIP() {

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Check if blocked
     */
    private function isBlocked() {

        $stmt = $this->db->prepare("
            SELECT id FROM blocked_ips
            WHERE ip = ?
            AND user_id = ?
            AND website_id = ?
            AND (expiry_time IS NULL OR expiry_time > NOW())
            LIMIT 1
        ");

        $stmt->bind_param("sii", $this->clientIP, $this->user_id, $this->website_id);
        $stmt->execute();
        $stmt->store_result();

        return $stmt->num_rows > 0;
    }

    /**
     * Block IP
     */
    private function blockIP($reason = 'Rate limit exceeded') {

        $stmt = $this->db->prepare("
            INSERT INTO blocked_ips
            (user_id, ip, website_id, reason, created_at, expiry_time)
            VALUES (?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND))
        ");

        $stmt->bind_param(
            "iissi",
            $this->user_id,
            $this->clientIP,
            $this->website_id,
            $reason,
            $this->config['block_duration']
        );

        $stmt->execute();
    }

    /**
     * Check rate limit from logs table
     */
    private function checkRateLimit() {

        $stmt = $this->db->prepare("
            SELECT COUNT(*) as total
            FROM logs
            WHERE ip = ?
            AND user_id = ?
            AND website_id = ?
            AND timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        ");

        $stmt->bind_param("sii", $this->clientIP, $this->user_id, $this->website_id);
        $stmt->execute();

        $result = $stmt->get_result()->fetch_assoc();

        return (int)$result['total'];
    }

    private function deny() {

        http_response_code(429);
        header("Retry-After: " . $this->config['block_duration']);

        exit("<h1>Too Many Requests</h1><p>Please try again later.</p>");
    }

    private function runProtection() {

        if ($this->isBlocked()) {
            $this->deny();
        }

        $count = $this->checkRateLimit();

        if ($count > $this->config['requests_per_minute']) {

            $this->blockIP("Exceeded {$this->config['requests_per_minute']} req/min");
            $this->deny();
        }
    }
}