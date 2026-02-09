<?php
// Constants for simplicity
define('USER_ID', 1);
define('WEBSITE_ID', 1);

// Database connection
$host = 'localhost';
$db   = 'mailfor';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// --- Fetch visitor IP ---
function getIpAddress() {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $ch = curl_init("https://api64.ipify.org?format=text");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $ip = curl_exec($ch);
        curl_close($ch);
    }

    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'Unknown';
}

// Reverse DNS lookup
function get_reverse_dns($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) ? gethostbyaddr($ip) : "Invalid IP";
}

$ip = getIpAddress();
$hostname = get_reverse_dns($ip);

// --- Check if IP is blocked ---
$stmt = $pdo->prepare("SELECT * FROM blocked_ips WHERE ip = ? AND user_id = ? AND website_id = ?");
$stmt->execute([$ip, USER_ID, WEBSITE_ID]);
$blocked = $stmt->fetch();

if ($blocked) {
    http_response_code(403);
    echo "Access denied. Your IP has been blocked.";
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visitor Info</title>
</head>
<body onload="collectBrowserData()" style="display:none">
<h2>Visitor Information</h2>
<p><strong>Your IP Address:</strong> <?php echo htmlspecialchars($ip); ?></p>
<p><strong>Reverse DNS:</strong> <?php echo htmlspecialchars($hostname); ?></p>
<p><strong>WebRTC IP:</strong> <span id="webrtc-ip">Checking...</span></p>
<p><strong>DNS Leak:</strong> <span id="dns-leak">Checking...</span></p>
<p><strong>User Agent:</strong> <span id="user-agent"></span></p>
<p><strong>Platform:</strong> <span id="platform"></span></p>
<p><strong>Language:</strong> <span id="language"></span></p>
<p><strong>Screen Resolution:</strong> <span id="screen-resolution"></span></p>
<p><strong>CPU Cores:</strong> <span id="cpu-cores"></span></p>
<p><strong>RAM:</strong> <span id="ram"></span></p>
<p><strong>GPU:</strong> <span id="gpu"></span></p>
<p><strong>Battery:</strong> <span id="battery"></span></p>
<p><strong>Timezone:</strong> <span id="timezone"></span></p>
<p><strong>Cookies Enabled:</strong> <span id="cookies"></span></p>
<p><strong>Digital DNA:</strong> <span id="digital-dna"></span></p>
<p><strong>Country:</strong> <span id="country">Checking...</span></p>

<script>
async function collectBrowserData() {
    const serverIp = "<?php echo $ip; ?>";
    const deviceInfo = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        screenResolution: screen.width + "x" + screen.height,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        cookiesEnabled: navigator.cookieEnabled ? "Yes" : "No",
        cpuCores: navigator.hardwareConcurrency || "Unknown",
        ram: navigator.deviceMemory ? navigator.deviceMemory + " GB" : "Unknown",
        ip: serverIp,
        referrer: document.referrer || "None",
        plugins: Array.from(navigator.plugins).map(p => p.name).join(", ") || "No plugins found"
    };

    const [gpu, battery, webrtcIP, dnsLeakIP, country] = await Promise.all([
        getGPUInfo(),
        getBatteryInfo(),
        detectWebRTCLeak(),
        checkDNSLeak(),
        getCountry()
    ]);

    deviceInfo.gpu = gpu;
    deviceInfo.battery = battery;
    deviceInfo.webrtcIP = webrtcIP;
    deviceInfo.dnsLeakIP = dnsLeakIP;
    deviceInfo.country = country;

    // Generate digital DNA hash
    const dnaInput = {...deviceInfo};
    delete dnaInput.ip;
    delete dnaInput.webrtcIP;
    delete dnaInput.dnsLeakIP;
    delete dnaInput.battery;
    deviceInfo.digitalDNA = await generateSHA256(JSON.stringify(dnaInput));

    // Display
    document.getElementById('user-agent').innerText = deviceInfo.userAgent;
    document.getElementById('platform').innerText = deviceInfo.platform;
    document.getElementById('language').innerText = deviceInfo.language;
    document.getElementById('screen-resolution').innerText = deviceInfo.screenResolution;
    document.getElementById('timezone').innerText = deviceInfo.timezone;
    document.getElementById('cookies').innerText = deviceInfo.cookiesEnabled;
    document.getElementById('cpu-cores').innerText = deviceInfo.cpuCores;
    document.getElementById('ram').innerText = deviceInfo.ram;
    document.getElementById('gpu').innerText = deviceInfo.gpu;
    document.getElementById('battery').innerText = deviceInfo.battery;
    document.getElementById('webrtc-ip').innerText = webrtcIP;
    document.getElementById('dns-leak').innerText = dnsLeakIP;
    document.getElementById('digital-dna').innerText = deviceInfo.digitalDNA;
    document.getElementById('country').innerText = country;

    // Send to server
    fetch("data.php", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(deviceInfo)
    }).then(res => res.text()).then(console.log).catch(console.error);
}

async function getGPUInfo() {
    let canvas = document.createElement('canvas');
    let gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return "WebGL not supported";
    let debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    return debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "Unknown GPU";
}

async function getBatteryInfo() {
    if (!navigator.getBattery) return "Battery API not supported";
    let battery = await navigator.getBattery();
    return Math.round(battery.level * 100) + "%";
}

async function detectWebRTCLeak() {
    return new Promise(resolve => {
        let rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
        rtc.createDataChannel("");
        rtc.createOffer().then(offer => rtc.setLocalDescription(offer));
        rtc.onicecandidate = event => {
            if (event?.candidate?.candidate) {
                let match = event.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/);
                if (match) resolve(match[0]);
            }
        };
        setTimeout(() => resolve("Not detected"), 3000);
    });
}

async function checkDNSLeak() {
    try {
        const resp = await fetch("https://cloudflare-dns.com/dns-query?name=example.com", {headers: {"accept":"application/dns-json"}});
        const data = await resp.json();
        return data.Answer ? data.Answer[0].data : "Unknown";
    } catch { return "Unknown"; }
}

async function getCountry() {
    try {
        const resp = await fetch('https://ipapi.co/json/');
        const data = await resp.json();
        return data.country_name || 'Unknown';
    } catch { return 'Unknown'; }
}

async function generateSHA256(input) {
    const buf = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hashBuffer)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
</script>
</body>
</html>
