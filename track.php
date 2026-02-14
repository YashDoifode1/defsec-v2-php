<?php
// Get real visitor IP safely (no external API)
function getIpAddress() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

$ip = getIpAddress();

// Reverse DNS
function get_reverse_dns($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) ? @gethostbyaddr($ip) : "Invalid IP";
}

$hostname = get_reverse_dns($ip);

// Server-side country detection
function getCountryFromIP($ip) {
    $json = @file_get_contents("http://ip-api.com/json/{$ip}?fields=country");
    if ($json) {
        $data = json_decode($json, true);
        return $data['country'] ?? "Unknown";
    }
    return "Unknown";
}

$country = getCountryFromIP($ip);

// Start output buffering if not already started
if (ob_get_level() == 0) {
    ob_start();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Visitor Information</title>
<style>
    .tracking-info {
        display: none; /* Hide tracking info from users */
    }
</style>
</head>

<body>
<!-- Hidden tracking container -->
<div class="tracking-info" 
     data-ip="<?= htmlspecialchars($ip) ?>" 
     data-hostname="<?= htmlspecialchars($hostname) ?>" 
     data-country="<?= htmlspecialchars($country) ?>">
</div>

<script>
// Immediately invoke tracking function
(async function trackVisitor() {
    try {
        // Get server-side data from hidden div
        const trackingDiv = document.querySelector('.tracking-info');
        const serverIP = trackingDiv?.dataset.ip || 'Unknown';
        
        // Collect browser data
        let deviceInfo = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            screenResolution: screen.width + "x" + screen.height,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            cookiesEnabled: navigator.cookieEnabled ? "Yes" : "No",
            cpuCores: navigator.hardwareConcurrency || "Unknown",
            ram: navigator.deviceMemory ? navigator.deviceMemory + " GB" : "Unknown",
            referrer: document.referrer || "None",
            ip: serverIP, // Include server IP
            website_id: 1, // Default website ID
            user_id: generateUserId() // Generate or get user ID
        };

        // Collect additional info
        deviceInfo.gpu = await getGPUInfo();
        deviceInfo.battery = await getBatteryInfo();
        deviceInfo.webrtcIP = await detectWebRTCLeak();

        // Generate Digital DNA
        try {
            let dnaInput = { ...deviceInfo };
            delete dnaInput.webrtcIP;
            delete dnaInput.battery;
            delete dnaInput.user_id;
            delete dnaInput.website_id;
            
            deviceInfo.digitalDNA = await generateSHA256(JSON.stringify(dnaInput));
        } catch (e) {
            console.warn("Hashing failed:", e);
            deviceInfo.digitalDNA = "Unavailable";
        }

        // Send data to server
        await sendData(deviceInfo);
        
    } catch (error) {
        console.error('Tracking error:', error);
    }
})();

// Helper function to generate or get user ID
function generateUserId() {
    // Try to get existing user ID from localStorage
    let userId = localStorage.getItem('visitor_id');
    if (!userId) {
        // Generate new UUID v4
        userId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
        localStorage.setItem('visitor_id', userId);
    }
    return userId;
}

async function getGPUInfo() {
    try {
        let canvas = document.createElement('canvas');
        let gl = canvas.getContext('webgl');
        if (!gl) return "Not supported";
        let debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        return debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "Unknown";
    } catch {
        return "Unavailable";
    }
}

async function getBatteryInfo() {
    try {
        if (!navigator.getBattery) return "Not supported";
        let battery = await navigator.getBattery();
        return Math.round(battery.level * 100) + "%";
    } catch {
        return "Unavailable";
    }
}

async function generateSHA256(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function detectWebRTCLeak() {
    return new Promise(resolve => {
        try {
            let rtc = new RTCPeerConnection({ iceServers: [] });
            rtc.createDataChannel("");
            rtc.createOffer().then(o => rtc.setLocalDescription(o));

            rtc.onicecandidate = e => {
                if (e && e.candidate) {
                    let ipMatch = e.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/);
                    if (ipMatch) {
                        resolve(ipMatch[0]);
                        rtc.close();
                    }
                }
            };

            setTimeout(() => {
                resolve("Not detected");
                if (rtc) rtc.close();
            }, 2000);
        } catch {
            resolve("Blocked");
        }
    });
}

async function sendData(data) {
    try {
        const response = await fetch("data.php", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            const text = await response.text();
            console.warn('Server response:', text);
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Tracking data saved:', result);
    } catch (err) {
        console.warn("Send failed:", err);
    }
}
</script>

</body>
</html>