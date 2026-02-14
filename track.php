<?php
// Constants
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
    http_response_code(500);
    die("Database connection failed.");
}

// ---------------- IP Detection ----------------
function getIpAddress() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ipList[0]);
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    }

    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'Unknown';
}

function getReverseDNS($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP)
        ? @gethostbyaddr($ip) ?: "Lookup failed"
        : "Invalid IP";
}

$ip = getIpAddress();
$hostname = getReverseDNS($ip);

// ---------------- Block Check ----------------
try {
    $stmt = $pdo->prepare("
        SELECT 1 FROM blocked_ips 
        WHERE ip = ? AND user_id = ? AND website_id = ?
        LIMIT 1
    ");
    $stmt->execute([$ip, USER_ID, WEBSITE_ID]);
    $blocked = $stmt->fetchColumn();

    if ($blocked) {
        http_response_code(403);
        exit("Access denied.");
    }
} catch (Exception $e) {
    // Fail open instead of breaking tracking page
}

// Optional: you can log the visit here if needed
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Visitor Info</title>
</head>
<body onload="collectBrowserData()" style="display:none">

<script>
async function collectBrowserData() {

    try {

        const serverIp = "<?php echo htmlspecialchars($ip, ENT_QUOTES); ?>";

        const deviceInfo = {
            userAgent: navigator.userAgent || "Unknown",
            platform: navigator.platform || "Unknown",
            language: navigator.language || "Unknown",
            screenResolution: screen.width + "x" + screen.height,
            timezone: safeTimezone(),
            cookiesEnabled: navigator.cookieEnabled ? 1 : 0,
            cpuCores: navigator.hardwareConcurrency || 0,
            ram: navigator.deviceMemory ? navigator.deviceMemory + " GB" : "Unknown",
            ip: serverIp,
            referrer: document.referrer || "None",
            plugins: safePlugins()
        };

        const gpu = await safeAsync(getGPUInfo);
        const battery = await safeAsync(getBatteryInfo);
        const webrtcIP = await safeAsync(detectWebRTCLeak);
        const dnsLeakIP = await safeAsync(checkDNSLeak);
        const country = await safeAsync(getCountry);

        deviceInfo.gpu = gpu;
        deviceInfo.battery = battery;
        deviceInfo.webrtcIP = webrtcIP;
        deviceInfo.dnsLeakIP = dnsLeakIP;
        deviceInfo.country = country;

        // Generate fingerprint safely
        deviceInfo.digitalDNA = await safeAsync(() =>
            generateSHA256(JSON.stringify({
                ...deviceInfo,
                ip: undefined,
                webrtcIP: undefined,
                dnsLeakIP: undefined,
                battery: undefined
            }))
        );

        // Send to server safely
        await fetch("data.php", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(deviceInfo)
        }).catch(() => {});

    } catch (err) {
        console.warn("Tracking failed silently:", err);
    }
}

/* ---------------- SAFE WRAPPERS ---------------- */

async function safeAsync(fn) {
    try {
        return await fn();
    } catch {
        return "Unavailable";
    }
}

function safeTimezone() {
    try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
        return "Unknown";
    }
}

function safePlugins() {
    try {
        return Array.from(navigator.plugins || [])
            .map(p => p.name)
            .join(", ") || "None";
    } catch {
        return "None";
    }
}

/* ---------------- HARDENED FUNCTIONS ---------------- */

async function getGPUInfo() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        if (!gl) return "WebGL not supported";
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        return debugInfo
            ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
            : "Unknown GPU";
    } catch {
        return "Unknown GPU";
    }
}

async function getBatteryInfo() {
    try {
        if (!navigator.getBattery) return "Unsupported";
        const battery = await navigator.getBattery();
        return Math.round(battery.level * 100) + "%";
    } catch {
        return "Unknown";
    }
}

async function detectWebRTCLeak() {
    return new Promise(resolve => {
        try {
            const rtc = new RTCPeerConnection({
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
            });

            rtc.createDataChannel("");
            rtc.createOffer()
                .then(o => rtc.setLocalDescription(o))
                .catch(() => resolve("Not detected"));

            rtc.onicecandidate = e => {
                if (e?.candidate?.candidate) {
                    const match = e.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/);
                    if (match) resolve(match[0]);
                }
            };

            setTimeout(() => resolve("Not detected"), 2000);
        } catch {
            resolve("Not detected");
        }
    });
}

async function checkDNSLeak() {
    try {
        const resp = await fetch(
            "https://cloudflare-dns.com/dns-query?name=example.com",
            { headers: { "accept": "application/dns-json" } }
        );
        const data = await resp.json();
        return data?.Answer?.[0]?.data || "Unknown";
    } catch {
        return "Unknown";
    }
}

async function getCountry() {
    try {
        const resp = await fetch("https://ipapi.co/json/");
        const data = await resp.json();
        return data?.country_name || "Unknown";
    } catch {
        return "Unknown";
    }
}

async function generateSHA256(input) {
    try {
        const buf = new TextEncoder().encode(input);
        const hash = await crypto.subtle.digest("SHA-256", buf);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    } catch {
        return "hash_failed";
    }
}

/* Prevent ANY unhandled promise rejection */
window.addEventListener("unhandledrejection", function (event) {
    event.preventDefault();
});
</script>

</body>
</html>