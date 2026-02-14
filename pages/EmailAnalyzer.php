<?php
// EmailAnalyzer.php
require_once '../includes/db.php';

class EmailAnalyzer {
    private $pdo;
    private $userId;
    private $analysisId = null;
    private $apiKeys;
    private $cacheTime = 86400; // 24 hours cache
    
    // Free APIs for enrichment
    private $apis = [
        'ipapi' => 'http://ip-api.com/json/%s?fields=66846719', // Free, no key needed
        'proxycheck' => 'https://proxycheck.io/v2/%s?key=%s&vpn=1&asn=1&time=1&risk=1&port=1&seen=1&days=1',
        'ip2proxy' => 'https://api.ip2proxy.com/?key=%s&ip=%s&package=PX11',
        'rdap' => 'https://rdap.db.ripe.net/ip/%s',
        'virustotal' => 'https://www.virustotal.com/api/v3/ip_addresses/%s',
        'abuseipdb' => 'https://api.abuseipdb.com/api/v2/check',
        'ipinfo' => 'https://ipinfo.io/%s?token=%s'
    ];
    
    public function __construct($pdo, $userId, $apiKeys = []) {
        $this->pdo = $pdo;
        $this->userId = $userId;
        $this->apiKeys = $apiKeys;
    }
    
    /**
     * Parse raw email headers and extract all information
     */
    public function analyzeHeaders($rawHeaders) {
        // Parse headers into array
        $headers = $this->parseHeaders($rawHeaders);
        
        // Extract basic information
        $basicInfo = $this->extractBasicInfo($headers);
        
        // Extract authentication results (SPF, DKIM, DMARC)
        $authResults = $this->extractAuthResults($headers);
        
        // Extract all IPs from Received headers
        $ips = $this->extractIPsFromHeaders($headers);
        
        // Enrich each IP with geolocation and threat data
        $enrichedIPs = $this->enrichIPs($ips);
        
        // Calculate threat score
        $threatScore = $this->calculateThreatScore($enrichedIPs, $authResults);
        
        // Save to database
        $this->saveAnalysis($basicInfo, $authResults, $enrichedIPs, $threatScore, $rawHeaders);
        
        return [
            'basic_info' => $basicInfo,
            'authentication' => $authResults,
            'ips' => $enrichedIPs,
            'threat_score' => $threatScore,
            'analysis_id' => $this->analysisId
        ];
    }
    
    /**
     * Parse raw headers into associative array
     */
    private function parseHeaders($rawHeaders) {
        $headers = [];
        $lines = explode("\n", $rawHeaders);
        $currentHeader = '';
        
        foreach ($lines as $line) {
            $line = rtrim($line);
            if (preg_match('/^([a-zA-Z0-9\-]+):\s*(.*)$/', $line, $matches)) {
                $currentHeader = strtolower($matches[1]);
                $headers[$currentHeader][] = $matches[2];
            } elseif (preg_match('/^\s+(.*)$/', $line, $matches) && $currentHeader) {
                // Continuation line
                $lastIndex = count($headers[$currentHeader]) - 1;
                $headers[$currentHeader][$lastIndex] .= ' ' . $matches[1];
            }
        }
        
        return $headers;
    }
    
    /**
     * Extract basic email information from headers
     */
    private function extractBasicInfo($headers) {
        $info = [
            'message_id' => $this->getHeaderFirst($headers, 'message-id'),
            'subject' => $this->getHeaderFirst($headers, 'subject'),
            'from' => $this->getHeaderFirst($headers, 'from'),
            'reply_to' => $this->getHeaderFirst($headers, 'reply-to'),
            'return_path' => $this->getHeaderFirst($headers, 'return-path'),
            'date' => $this->getHeaderFirst($headers, 'date'),
            'to' => $this->getHeaderFirst($headers, 'to'),
            'cc' => $this->getHeaderFirst($headers, 'cc'),
            'bcc' => $this->getHeaderFirst($headers, 'bcc'),
            'content_type' => $this->getHeaderFirst($headers, 'content-type')
        ];
        
        // Extract domain from From address
        if ($info['from'] && preg_match('/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/', $info['from'], $matches)) {
            $info['from_domain'] = $matches[1];
        }
        
        // Parse date
        if ($info['date']) {
            $info['date_parsed'] = date('Y-m-d H:i:s', strtotime($info['date']));
        }
        
        return $info;
    }
    
    /**
     * Extract authentication results (SPF, DKIM, DMARC)
     */
    private function extractAuthResults($headers) {
        $results = [
            'spf' => null,
            'dkim' => null,
            'dmarc' => null,
            'authentication_results' => $this->getHeaderFirst($headers, 'authentication-results')
        ];
        
        // Parse Authentication-Results header
        if ($results['authentication_results']) {
            $authHeader = $results['authentication_results'];
            
            // Extract SPF
            if (preg_match('/spf=(\w+)/i', $authHeader, $matches)) {
                $results['spf'] = $matches[1];
            }
            
            // Extract DKIM
            if (preg_match('/dkim=(\w+)/i', $authHeader, $matches)) {
                $results['dkim'] = $matches[1];
            }
            
            // Extract DMARC
            if (preg_match('/dmarc=(\w+)/i', $authHeader, $matches)) {
                $results['dmarc'] = $matches[1];
            }
        }
        
        // Also check for specific SPF/DKIM/DMARC headers
        if (!$results['spf'] && isset($headers['received-spf'])) {
            $results['spf'] = implode(' ', $headers['received-spf']);
        }
        
        return $results;
    }
    
    /**
     * Extract all IP addresses from Received headers
     */
    private function extractIPsFromHeaders($headers) {
        $ips = [];
        $hopNumber = 0;
        
        if (!isset($headers['received'])) {
            return $ips;
        }
        
        // Process Received headers in reverse order (oldest first)
        $receivedHeaders = array_reverse($headers['received']);
        
        foreach ($receivedHeaders as $received) {
            $hopNumber++;
            $hopData = [
                'hop' => $hopNumber,
                'raw' => $received,
                'ip' => null,
                'hostname' => null,
                'by' => null,
                'from' => null,
                'with' => null,
                'timestamp' => null
            ];
            
            // Extract IP address - multiple patterns
            $patterns = [
                '/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/',
                '/from\s+([a-zA-Z0-9.-]+)\s+\(([^)]+)\[([0-9.]+)\]\)/',
                '/from\s+([a-zA-Z0-9.-]+)\s*\(\[([0-9.]+)\]/',
                '/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/'
            ];
            
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $received, $matches)) {
                    // Extract the IP (usually the last match with digits)
                    foreach ($matches as $match) {
                        if (filter_var($match, FILTER_VALIDATE_IP)) {
                            $hopData['ip'] = $match;
                            break 2;
                        }
                    }
                }
            }
            
            // Extract hostname
            if (preg_match('/from\s+([a-zA-Z0-9.-]+)\s*\(/', $received, $matches)) {
                $hopData['hostname'] = $matches[1];
            }
            
            // Extract server that received it
            if (preg_match('/by\s+([a-zA-Z0-9.-]+)/', $received, $matches)) {
                $hopData['by'] = $matches[1];
            }
            
            // Extract protocol
            if (preg_match('/with\s+([a-zA-Z0-9-]+)/', $received, $matches)) {
                $hopData['with'] = $matches[1];
            }
            
            // Extract timestamp
            if (preg_match('/;\s*(.+)$/', $received, $matches)) {
                $hopData['timestamp'] = trim($matches[1]);
            }
            
            if ($hopData['ip']) {
                $ips[] = $hopData;
            }
        }
        
        return $ips;
    }
    
    /**
     * Enrich IPs with geolocation, threat data, RDAP, etc.
     */
    private function enrichIPs($ips) {
        $enriched = [];
        
        foreach ($ips as $index => $ipData) {
            $ip = $ipData['ip'];
            
            // Skip private/local IPs
            if ($this->isPrivateIP($ip)) {
                $ipData['is_private'] = true;
                $ipData['country'] = 'Local/Private';
                $ipData['threat_score'] = 0;
                $enriched[] = $ipData;
                continue;
            }
            
            // Get geolocation from cache or API
            $geo = $this->getCachedOrFetch('geo', $ip, function($ip) {
                return $this->fetchGeoData($ip);
            });
            
            // Get proxy/VPN detection
            $proxyCheck = $this->getCachedOrFetch('proxy', $ip, function($ip) {
                return $this->fetchProxyCheck($ip);
            });
            
            // Get RDAP data
            $rdap = $this->getCachedOrFetch('rdap', $ip, function($ip) {
                return $this->fetchRDAP($ip);
            });
            
            // Get reverse DNS
            $reverseDNS = gethostbyaddr($ip);
            
            // Combine all data
            $ipData = array_merge($ipData, [
                'reverse_dns' => $reverseDNS ?: null,
                'country' => $geo['country'] ?? null,
                'country_code' => $geo['countryCode'] ?? null,
                'region' => $geo['region'] ?? $geo['regionName'] ?? null,
                'city' => $geo['city'] ?? null,
                'latitude' => $geo['lat'] ?? $geo['latitude'] ?? null,
                'longitude' => $geo['lon'] ?? $geo['longitude'] ?? null,
                'isp' => $geo['isp'] ?? $geo['org'] ?? null,
                'asn' => $proxyCheck['asn'] ?? $geo['as'] ?? null,
                'as_org' => $proxyCheck['asn_name'] ?? $geo['org'] ?? null,
                'is_vpn' => $proxyCheck['proxy'] === 'yes' || $proxyCheck['type'] === 'VPN' ? 1 : 0,
                'is_tor' => $proxyCheck['type'] === 'TOR' ? 1 : 0,
                'is_proxy' => $proxyCheck['proxy'] === 'yes' ? 1 : 0,
                'is_datacenter' => $proxyCheck['type'] === 'HOSTING' ? 1 : 0,
                'threat_score' => $proxyCheck['risk'] ?? 0,
                'rdap_data' => $rdap ? json_encode($rdap) : null
            ]);
            
            $enriched[] = $ipData;
        }
        
        return $enriched;
    }
    
    /**
     * Fetch geolocation data from ip-api.com (free, no key)
     */
    private function fetchGeoData($ip) {
        $url = sprintf($this->apis['ipapi'], $ip);
        $response = $this->makeRequest($url);
        return json_decode($response, true);
    }
    
    /**
     * Fetch proxy/VPN detection from proxycheck.io
     */
    private function fetchProxyCheck($ip) {
        $apiKey = $this->apiKeys['proxycheck'] ?? '';
        $url = sprintf($this->apis['proxycheck'], $ip, $apiKey);
        $response = $this->makeRequest($url);
        $data = json_decode($response, true);
        
        if (isset($data[$ip])) {
            return $data[$ip];
        }
        
        return [];
    }
    
    /**
     * Fetch RDAP data
     */
    private function fetchRDAP($ip) {
        $url = sprintf($this->apis['rdap'], $ip);
        $response = $this->makeRequest($url);
        return json_decode($response, true);
    }
    
    /**
     * Make HTTP request with timeout
     */
    private function makeRequest($url, $headers = []) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'EmailAnalyzer/1.0');
        
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return $response;
    }
    
    /**
     * Check if IP is private/local
     */
    private function isPrivateIP($ip) {
        $privateRanges = [
            '10.0.0.0|10.255.255.255',
            '172.16.0.0|172.31.255.255',
            '192.168.0.0|192.168.255.255',
            '127.0.0.0|127.255.255.255',
            '169.254.0.0|169.254.255.255'
        ];
        
        $ipLong = ip2long($ip);
        if ($ipLong === false) return true;
        
        foreach ($privateRanges as $range) {
            list($start, $end) = explode('|', $range);
            if ($ipLong >= ip2long($start) && $ipLong <= ip2long($end)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get cached data or fetch fresh
     */
    private function getCachedOrFetch($type, $key, $fetchCallback) {
        // Check cache first
        $stmt = $this->pdo->prepare("SELECT response_data FROM api_cache 
                                      WHERE api_name = ? AND query_key = ? AND expires_at > NOW()");
        $stmt->execute([$type, $key]);
        $cached = $stmt->fetchColumn();
        
        if ($cached) {
            return json_decode($cached, true);
        }
        
        // Fetch fresh data
        $data = $fetchCallback($key);
        
        if ($data) {
            // Store in cache
            $stmt = $this->pdo->prepare("INSERT INTO api_cache (api_name, query_key, response_data, expires_at) 
                                          VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))
                                          ON DUPLICATE KEY UPDATE response_data = ?, expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND)");
            $stmt->execute([$type, $key, json_encode($data), $this->cacheTime, json_encode($data), $this->cacheTime]);
        }
        
        return $data;
    }
    
    /**
     * Calculate overall threat score
     */
    private function calculateThreatScore($ips, $authResults) {
        $score = 0;
        
        // Check authentication failures
        if ($authResults['spf'] === 'fail' || $authResults['spf'] === 'softfail') $score += 20;
        if ($authResults['dkim'] === 'fail') $score += 20;
        if ($authResults['dmarc'] === 'fail') $score += 30;
        
        // Check IP threats
        foreach ($ips as $ip) {
            if (isset($ip['is_vpn']) && $ip['is_vpn']) $score += 15;
            if (isset($ip['is_tor']) && $ip['is_tor']) $score += 25;
            if (isset($ip['is_proxy']) && $ip['is_proxy']) $score += 10;
            if (isset($ip['is_datacenter']) && $ip['is_datacenter']) $score += 5;
            if (isset($ip['threat_score']) && $ip['threat_score'] > 50) $score += 20;
        }
        
        return min(100, $score);
    }
    
    /**
     * Save analysis to database
     */
    private function saveAnalysis($basicInfo, $authResults, $ips, $threatScore, $rawHeaders) {
        // Insert main analysis
        $stmt = $this->pdo->prepare("INSERT INTO email_analyses 
            (user_id, raw_headers, message_id, subject, from_address, from_domain, 
             reply_to, return_path, date_sent, spf_result, dkim_result, dmarc_result, 
             authentication_results, spam_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        
        $stmt->execute([
            $this->userId,
            $rawHeaders,
            $basicInfo['message_id'],
            $basicInfo['subject'],
            $basicInfo['from'],
            $basicInfo['from_domain'] ?? null,
            $basicInfo['reply_to'],
            $basicInfo['return_path'],
            $basicInfo['date_parsed'] ?? null,
            $authResults['spf'],
            $authResults['dkim'],
            $authResults['dmarc'],
            $authResults['authentication_results'],
            $threatScore
        ]);
        
        $this->analysisId = $this->pdo->lastInsertId();
        
        // Insert IPs
        foreach ($ips as $ip) {
            $stmt = $this->pdo->prepare("INSERT INTO email_ips 
                (analysis_id, hop_number, ip_address, hostname, reverse_dns, country, 
                 country_code, region, city, latitude, longitude, isp, asn, as_org, 
                 is_vpn, is_tor, is_proxy, is_datacenter, threat_score, rdap_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            
            $stmt->execute([
                $this->analysisId,
                $ip['hop'] ?? null,
                $ip['ip'] ?? null,
                $ip['hostname'] ?? null,
                $ip['reverse_dns'] ?? null,
                $ip['country'] ?? null,
                $ip['country_code'] ?? null,
                $ip['region'] ?? null,
                $ip['city'] ?? null,
                $ip['latitude'] ?? null,
                $ip['longitude'] ?? null,
                $ip['isp'] ?? null,
                $ip['asn'] ?? null,
                $ip['as_org'] ?? null,
                $ip['is_vpn'] ?? 0,
                $ip['is_tor'] ?? 0,
                $ip['is_proxy'] ?? 0,
                $ip['is_datacenter'] ?? 0,
                $ip['threat_score'] ?? 0,
                $ip['rdap_data'] ?? null
            ]);
        }
    }
    
    /**
     * Get header first value
     */
    private function getHeaderFirst($headers, $key) {
        return isset($headers[$key]) ? $headers[$key][0] : null;
    }
}
?>