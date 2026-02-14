<?php
ob_start();
// Securely fetch the visitor's IP address
function getIpAddress() {
    $ch = curl_init("https://api64.ipify.org?format=text");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $ip = curl_exec($ch);
    curl_close($ch);

    return $ip ?: ($_SERVER['REMOTE_ADDR'] ?? "Unknown"); // Fallback to REMOTE_ADDR if API fails
}

$ip = getIpAddress();

// Function to get Reverse DNS (PTR Record) securely
function get_reverse_dns($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) ? gethostbyaddr($ip) : "Invalid IP";
}

$hostname = get_reverse_dns($ip);
ob_end_flush();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <style>.body{display: none}</style>
</head>
<div class="body">
<body onload="collectBrowserData()">
    <h2>Visitor Information</h2>
    <p><strong>Your IP Address:</strong> <?php echo htmlspecialchars($ip); ?></p>
    <p><strong>Reverse DNS (PTR Record):</strong> <?php echo htmlspecialchars($hostname); ?></p>
    <p><strong>WebRTC Detected IP:</strong> <span id="webrtc-ip">Checking...</span></p>
    <p><strong>DNS Leak Detected IP:</strong> <span id="dns-leak">Checking...</span></p>
    <p><strong>User Agent:</strong> <span id="user-agent"></span></p>
    <p><strong>Your Language:</strong> <span id="language"></span></p>
    <p><strong>Platform:</strong> <span id="platform"></span></p>
    <p><strong>Screen Resolution:</strong> <span id="screen-resolution"></span></p>
    <p><strong>CPU Cores:</strong> <span id="cpu-cores"></span></p>
    <p><strong>RAM (Approximate):</strong> <span id="ram"></span></p>
    <p><strong>GPU:</strong> <span id="gpu"></span></p>
    <p><strong>Battery:</strong> <span id="battery"></span></p>
    <p><strong>Timezone:</strong> <span id="timezone"></span></p>
    <p><strong>Cookies Enabled:</strong> <span id="cookies"></span></p>
    <p><strong>DNA:</strong> <span id="digital-dna"></span></p>
    <p><strong>Country:</strong> <span id="country">Checking...</span></p>

    <script>
      async function collectBrowserData() {
          let real_ip = "<?php echo $ip; ?>";

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
              plugins: Array.from(navigator.plugins).map(p => p.name).join(", ") || "No plugins found",
              ip: real_ip
          };

          let [gpu, battery, webrtcIP, dnsLeakIP] = await Promise.all([
              getGPUInfo(),
              getBatteryInfo(),
              detectWebRTCLeak(),
              checkDNSLeak()
          ]);

          deviceInfo.gpu = gpu;
          deviceInfo.battery = battery;
          deviceInfo.webrtcIP = webrtcIP;
          deviceInfo.dnsLeakIP = dnsLeakIP;

          // Exclude IPs from hashing
          let dnaInput = { ...deviceInfo };
          delete dnaInput.ip;
          delete dnaInput.webrtcIP;
          delete dnaInput.dnsLeakIP;
          delete dnaInput.battery;

          let digitalDNA = await generateSHA256(JSON.stringify(dnaInput));
          deviceInfo.digitalDNA = digitalDNA;

          // Display Data
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
          document.getElementById('digital-dna').innerText = digitalDNA;
          document.getElementById('country').innerText = deviceInfo.country;
          deviceInfo.country = await getCountry();

          sendData(deviceInfo);
      }
      async function getCountry() {
        try {
            const response = await fetch('https://ipapi.co/json/');
            if (!response.ok) throw new Error('Rate limited');
            const data = await response.json();
            return data.country_name || 'Unknown';
        } catch {
            return 'Unknown'; // Fallback to server-side detection
        }
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

      async function generateSHA256(input) {
    console.log("Hashing Input:", input); // Debugging
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hash = Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, '0')).join('');
    console.log("Generated SHA-256 Hash:", hash); // Debugging
    return hash;
}


      function detectWebRTCLeak() {
          return new Promise((resolve) => {
              let rtc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
              rtc.createDataChannel("");
              rtc.createOffer().then(offer => rtc.setLocalDescription(offer));

              rtc.onicecandidate = event => {
                  if (event && event.candidate && event.candidate.candidate) {
                      let match = event.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/);
                      if (match) resolve(match[0]);
                  }
              };

              setTimeout(() => resolve("Not detected"), 3000);
          });
      }

      function checkDNSLeak() {
          return fetch("https://cloudflare-dns.com/dns-query?name=example.com", {
              method: "GET",
              headers: { "accept": "application/dns-json" }
          })
          .then(response => response.json())
          .then(data => (data.Answer ? data.Answer[0].data : "Unknown"))
          .catch(() => "Error fetching DNS data");
      }

      function sendData(data) {
    console.log("Sending Data to Server:", data); // Debugging

    fetch("data.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    })
    .then(response => response.text())
    .then(result => console.log("Server Response:", result)) // Debugging
    .catch(error => console.error("Error sending data:", error));
}

    </script>
</body>
</div>
</html>