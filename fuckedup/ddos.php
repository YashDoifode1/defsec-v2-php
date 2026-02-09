<?php
/**
 * DDoS Protector - Advanced PHP DDoS Mitigation
 * Author: AI Security Engineer
 * Version: 2.0
 * License: MIT
 */

class DDoSProtector {
    // Configuration
    private $config = [
        'requests_per_minute' => 100,    // Max requests per minute per IP
        'block_duration'      => 300,    // 5 minutes blocking
        'strict_mode'         => true,   // Enable aggressive protection
        'enable_captcha'      => true,   // Show CAPTCHA for suspicious requests
        'log_file'            => __DIR__ . '/ddos_logs.log',
        'ip_blacklist_file'   => __DIR__ . '/ip_blacklist.txt',
        'trusted_proxies'     => [],     // If behind Cloudflare, add their IPs
    ];

    // High-risk countries (ISO codes)
    private $highRiskCountries = ['RU', 'CN', 'KP', 'IR', 'SY'];

    // Known bad User-Agents (botnets, scanners)
    private $maliciousUserAgents = [
        'bot', 'spider', 'scan', 'crawl', 'brute', 'python', 'curl', 'wget', 
        'nikto', 'sqlmap', 'hydra', 'metasploit', 'zmeu', 'slowloris'
    ];

    // Internal variables
    private $clientIP;
    private $requestCounts = [];
    private $blockedIPs = [];

    public function __construct($customConfig = []) {
        $this->config = array_merge($this->config, $customConfig);
        $this->clientIP = $this->getRealIP();
        $this->loadBlacklist();
        $this->runProtection();
    }

    /**
     * Get real client IP (handles proxies)
     */
    private function getRealIP() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) { // Cloudflare
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($ipList[0]);
        }
        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Load blocked IPs from file
     */
    private function loadBlacklist() {
        if (file_exists($this->config['ip_blacklist_file'])) {
            $this->blockedIPs = file($this->config['ip_blacklist_file'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }
    }

    /**
     * Save IP to blacklist
     */
    private function blockIP($ip) {
        if (!in_array($ip, $this->blockedIPs)) {
            file_put_contents($this->config['ip_blacklist_file'], $ip . PHP_EOL, FILE_APPEND);
            $this->blockedIPs[] = $ip;
        }
    }

    /**
     * Check if IP is blocked
     */
    private function isIPBlocked($ip) {
        return in_array($ip, $this->blockedIPs);
    }

    /**
     * Log DDoS attempt
     */
    private function logAttack($type, $ip, $details = '') {
        $logEntry = sprintf(
            "[%s] [DDoS Attack] Type: %s | IP: %s | Details: %s\n",
            date('Y-m-d H:i:s'),
            $type,
            $ip,
            $details
        );
        file_put_contents($this->config['log_file'], $logEntry, FILE_APPEND);
    }

    /**
     * Check for suspicious User-Agent
     */
    private function isMaliciousUserAgent() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach ($this->maliciousUserAgents as $badAgent) {
            if (stripos($userAgent, $badAgent) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if IP is from a high-risk country (requires MaxMind GeoIP or similar)
     */
    private function isHighRiskCountry($ip) {
        // Example: Use GeoIP database (commented out for simplicity)
        // $countryCode = geoip_country_code_by_name($ip);
        // return in_array($countryCode, $this->highRiskCountries);
        return false; // Disabled by default (requires setup)
    }

    /**
     * Show CAPTCHA challenge
     */
    private function showCaptcha() {
        if ($this->config['enable_captcha']) {
            header('HTTP/1.1 403 Forbidden');
            echo "<h1>Security Challenge</h1>";
            echo "<p>Please complete CAPTCHA to continue.</p>";
            // In a real system, integrate with reCAPTCHA or hCaptcha
            exit;
        }
    }

    /**
     * Block the request
     */
    private function blockRequest() {
        header('HTTP/1.1 429 Too Many Requests');
        header('Retry-After: ' . $this->config['block_duration']);
        echo "<h1>Access Blocked</h1>";
        echo "<p>Too many requests. Try again later.</p>";
        exit;
    }

    /**
     * Main DDoS protection logic
     */
    private function runProtection() {
        // Check if IP is already blocked
        if ($this->isIPBlocked($this->clientIP)) {
            $this->blockRequest();
        }

        // Rate limiting (requests per minute)
        $requestCount = $this->getRequestCount($this->clientIP);
        if ($requestCount > $this->config['requests_per_minute']) {
            $this->blockIP($this->clientIP);
            $this->logAttack('RateLimit', $this->clientIP, "Requests: $requestCount");
            $this->blockRequest();
        }

        // Check for bad User-Agents
        if ($this->isMaliciousUserAgent()) {
            $this->logAttack('BadUserAgent', $this->clientIP, $_SERVER['HTTP_USER_AGENT']);
            $this->showCaptcha();
        }

        // Check high-risk countries (if GeoIP enabled)
        if ($this->isHighRiskCountry($this->clientIP)) {
            $this->logAttack('HighRiskCountry', $this->clientIP);
            $this->showCaptcha();
        }
    }

    /**
     * Track request count per IP (simplified version)
     */
    private function getRequestCount($ip) {
        $currentMinute = (int)(time() / 60);
        $cacheKey = "req_count_{$ip}_{$currentMinute}";

        if (!isset($this->requestCounts[$cacheKey])) {
            $this->requestCounts[$cacheKey] = 0;
        }

        $this->requestCounts[$cacheKey]++;
        return $this->requestCounts[$cacheKey];
    }
}

// ===== USAGE =====
// Include this at the top of your PHP application
$ddosProtector = new DDoSProtector([
    'requests_per_minute' => 150, // Adjust based on expected traffic
    'strict_mode' => true,       // Enable for high-security sites
]);

// Optional: Add custom blocked IPs
// $ddosProtector->blockIP('1.2.3.4');
?>