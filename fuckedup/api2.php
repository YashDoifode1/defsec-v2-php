<?php
// api.php - Must be included before any output

// Check if DVWA environment is loaded
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
   die('DVWA environment not loaded');
}
 Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
  @session_start();
}

/**
 * Securely fetch visitor's IP address
 */
function getIpAddress() {
    // Try external service first
    if (function_exists('curl_init')) {
        $ch = curl_init("https://api64.ipify.org?format=text");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $ip = curl_exec($ch);
        curl_close($ch);
        
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    
    // Fallback to server variables
    $ipSources = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    
    foreach ($ipSources as $key) {
        if (isset($_SERVER[$key])) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }
    
    return 'Unknown';
}

/**
 * Get reverse DNS (PTR Record)
 */
function get_reverse_dns($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return "Invalid IP";
    }
    
    // Use DNS-over-HTTPS for better privacy
    if (function_exists('curl_init')) {
        $ch = curl_init("https://dns.google/resolve?name=" . urlencode($ip) . "&type=PTR");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);
        $response = curl_exec($ch);
        curl_close($ch);
        
        if ($response) {
            $data = json_decode($response, true);
            if (isset($data['Answer'][0]['data'])) {
                return rtrim($data['Answer'][0]['data'], '.');
            }
        }
    }
    
    // Fallback to traditional method
    return gethostbyaddr($ip) ?: "Lookup failed";
}

// Get visitor data
$visitorData = [
    'ip' => getIpAddress(),
    'hostname' => null,
    'timestamp' => date('Y-m-d H:i:s'),
    'dvwa_user_id' => isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null
];

$visitorData['hostname'] = get_reverse_dns($visitorData['ip']);

// Prepare data for JavaScript
$jsVisitorData = json_encode($visitorData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);

// Store in session for later use
$_SESSION['visitor_data'] = $visitorData;

// No output here - data will be used by JavaScript later
?>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Get data from PHP
    const visitorData = <?php echo $jsVisitorData; ?>;
    
    async function collectBrowserData() {
        try {
            const data = {
                ...visitorData,
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                languages: navigator.languages,
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                cookies: navigator.cookieEnabled,
                hardware: {
                    cores: navigator.hardwareConcurrency,
                    memory: navigator.deviceMemory
                },
                webRTC: await detectWebRTC(),
                dns: await checkDNS(),
                country: await getCountry(),
                gpu: await getGPUInfo(),
                battery: await getBatteryInfo()
            };
            
            // Generate fingerprint
            data.fingerprint = await generateFingerprint(data);
            
            // Send to server
            sendToDVWA(data);
        } catch (error) {
            console.error('Tracking error:', error);
        }
    }
    
    // Detection functions
    async function detectWebRTC() {
        try {
            const rtc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
            rtc.createDataChannel("");
            const offer = await rtc.createOffer();
            await rtc.setLocalDescription(offer);
            
            return new Promise(resolve => {
                rtc.onicecandidate = (e) => {
                    if (e.candidate && e.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/)) {
                        resolve(e.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/)[0]);
                    }
                };
                setTimeout(() => resolve("Not detected"), 3000);
            });
        } catch {
            return "Blocked";
        }
    }
    
    async function checkDNS() {
        try {
            const response = await fetch("https://cloudflare-dns.com/dns-query?name=example.com", {
                headers: { "Accept": "application/dns-json" }
            });
            const data = await response.json();
            return data.Answer?.[0]?.data || "Unknown";
        } catch {
            return "Error";
        }
    }
    
    async function getCountry() {
        try {
            const response = await fetch(`https://ipapi.co/${visitorData.ip}/json/`);
            const data = await response.json();
            return data.country_name || "Unknown";
        } catch {
            return "Unknown";
        }
    }
    
    async function getGPUInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return "None";
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "Unknown";
        } catch {
            return "Error";
        }
    }
    
    async function getBatteryInfo() {
        try {
            if (!navigator.getBattery) return "Unsupported";
            const battery = await navigator.getBattery();
            return {
                level: Math.round(battery.level * 100),
                charging: battery.charging
            };
        } catch {
            return "Error";
        }
    }
    
    async function generateFingerprint(data) {
        // Exclude volatile fields
        const { ip, timestamp, battery, ...fingerprintData } = data;
        const str = JSON.stringify(fingerprintData);
        
        // Generate hash
        const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        const hashArray = Array.from(new Uint8Array(buffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    function sendToDVWA(data) {
        fetch('dvwa/includes/data.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(data)
        }).catch(e => console.error('Tracking save failed:', e));
    }
    
    // Start collection
    collectBrowserData();
});
</script>