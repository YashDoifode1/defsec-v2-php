<?php
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

// You should set these dynamically based on your application
$user_id = 1; // This should come from your session/auth system
$website_id = 1; // This should be set based on the current website

// Generate a consistent browser fingerprint on server side as fallback
function generateServerFingerprint($ip, $userAgent) {
    $fingerprintData = $ip . $userAgent . $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'en';
    return hash('sha256', $fingerprintData);
}

$serverFingerprint = generateServerFingerprint($ip, $_SERVER['HTTP_USER_AGENT'] ?? '');
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
    <p><strong>Digital Fingerprint:</strong> <span id="digital-dna">Generating...</span></p>
    <p><strong>Server Fingerprint:</strong> <?php echo $serverFingerprint; ?></p>
    <p><strong>Country:</strong> <span id="country">Checking...</span></p>
    <p><strong>City:</strong> <span id="city">Checking...</span></p>
    <p><strong>ISP:</strong> <span id="isp">Checking...</span></p>
    <p><strong>ASN:</strong> <span id="asn">Checking...</span></p>
    <p><strong>VPN/Proxy Status:</strong> <span id="vpn-status">Checking...</span></p>

    <script>
      // Store fingerprint in sessionStorage to maintain consistency across page loads
      let consistentFingerprint = sessionStorage.getItem('visitor_fingerprint');
      
      async function collectBrowserData() {
          let real_ip = "<?php echo $ip; ?>";
          let user_id = <?php echo $user_id; ?>;
          let website_id = <?php echo $website_id; ?>;

          // Get country and additional geo info
          let geoInfo = await getGeoInfo();

          // Normalize values for consistent fingerprinting
          let normalizedData = {
              userAgent: normalizeUserAgent(navigator.userAgent),
              platform: navigator.platform || 'Unknown',
              language: navigator.language || 'en-US',
              screenResolution: screen.width + "x" + screen.height,
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              cookiesEnabled: navigator.cookieEnabled ? "Yes" : "No",
              cpuCores: navigator.hardwareConcurrency || "Unknown",
              // Use standardized values
              colorDepth: screen.colorDepth || 24,
              pixelRatio: window.devicePixelRatio || 1,
              touchSupport: 'ontouchstart' in window ? 'Yes' : 'No',
              doNotTrack: navigator.doNotTrack || 'Unknown'
          };

          let deviceInfo = {
              user_id: user_id,
              website_id: website_id,
              ip: real_ip,
              real_ip: real_ip,
              reverse_dns: "<?php echo $hostname; ?>",
              country: geoInfo.country_name || 'Unknown',
              city: geoInfo.city || 'Unknown',
              ISP: geoInfo.org || 'Unknown',
              ASN: geoInfo.asn || 'Unknown',
              latitude: geoInfo.latitude || null,
              longitude: geoInfo.longitude || null,
              is_vpn: 0,
              is_proxy: 0,
              is_tor: 0,
              ...normalizedData
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

          // Generate consistent fingerprint
          let digitalDNA = await generateConsistentFingerprint(deviceInfo);
          deviceInfo.digitalDNA = digitalDNA;

          // Store fingerprint for future use
          sessionStorage.setItem('visitor_fingerprint', digitalDNA);
          localStorage.setItem('visitor_fingerprint_' + digitalDNA.substring(0, 8), Date.now());

          // Display Data
          document.getElementById('user-agent').innerText = deviceInfo.userAgent;
          document.getElementById('platform').innerText = deviceInfo.platform;
          document.getElementById('language').innerText = deviceInfo.language;
          document.getElementById('screen-resolution').innerText = deviceInfo.screenResolution;
          document.getElementById('timezone').innerText = deviceInfo.timezone;
          document.getElementById('cookies').innerText = deviceInfo.cookiesEnabled;
          document.getElementById('cpu-cores').innerText = deviceInfo.cpuCores;
          document.getElementById('ram').innerText = deviceInfo.ram || 'Unknown';
          document.getElementById('gpu').innerText = deviceInfo.gpu;
          document.getElementById('battery').innerText = deviceInfo.battery;
          document.getElementById('webrtc-ip').innerText = webrtcIP;
          document.getElementById('dns-leak').innerText = dnsLeakIP;
          document.getElementById('digital-dna').innerText = digitalDNA;
          document.getElementById('country').innerText = deviceInfo.country;
          document.getElementById('city').innerText = deviceInfo.city;
          document.getElementById('isp').innerText = deviceInfo.ISP;
          document.getElementById('asn').innerText = deviceInfo.ASN;
          document.getElementById('vpn-status').innerText = deviceInfo.is_vpn ? 'Yes' : 'No';

          sendData(deviceInfo);
      }

      // Normalize user agent to remove version-specific details that might change
      function normalizeUserAgent(ua) {
          // Remove version numbers from browser names for consistency
          return ua
              .replace(/(Chrome\/)[0-9.]+/g, '$1XX')
              .replace(/(Firefox\/)[0-9.]+/g, '$1XX')
              .replace(/(Safari\/)[0-9.]+/g, '$1XX')
              .replace(/(Edge\/)[0-9.]+/g, '$1XX')
              .replace(/(OPR\/)[0-9.]+/g, '$1XX');
      }

      async function generateConsistentFingerprint(data) {
          // If we already have a fingerprint stored, use it
          if (consistentFingerprint) {
              console.log('Using stored fingerprint:', consistentFingerprint);
              return consistentFingerprint;
          }

          // Create a consistent string for hashing
          const fingerprintParts = [
              data.userAgent,
              data.platform,
              data.language,
              data.screenResolution,
              data.timezone,
              data.cookiesEnabled,
              data.cpuCores,
              data.colorDepth,
              data.pixelRatio,
              data.touchSupport,
              data.doNotTrack
          ];

          // Add WebGL fingerprint if available (more stable)
          let canvas = document.createElement('canvas');
          let gl = canvas.getContext('webgl');
          if (gl) {
              let debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
              if (debugInfo) {
                  fingerprintParts.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
                  fingerprintParts.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
              }
          }

          // Add canvas fingerprint
          let canvasFingerprint = await getCanvasFingerprint();
          fingerprintParts.push(canvasFingerprint);

          // Add installed fonts fingerprint
          let fontsFingerprint = await getFontsFingerprint();
          fingerprintParts.push(fontsFingerprint);

          // Sort to ensure consistent order
          fingerprintParts.sort();
          
          const fingerprintString = fingerprintParts.join('|');
          console.log('Fingerprint string:', fingerprintString);

          // Generate SHA-256 hash
          const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(fingerprintString));
          const hash = Array.from(new Uint8Array(hashBuffer))
              .map(byte => byte.toString(16).padStart(2, '0'))
              .join('');
          
          consistentFingerprint = hash;
          return hash;
      }

      // Canvas fingerprinting for more stability
      async function getCanvasFingerprint() {
          let canvas = document.createElement('canvas');
          canvas.width = 200;
          canvas.height = 50;
          let ctx = canvas.getContext('2d');
          ctx.textBaseline = 'top';
          ctx.font = '14px Arial';
          ctx.fillStyle = '#f60';
          ctx.fillRect(0, 0, 100, 50);
          ctx.fillStyle = '#069';
          ctx.fillText('Fingerprint', 2, 15);
          ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
          ctx.fillText('Test', 2, 30);
          
          return canvas.toDataURL();
      }

      // Fonts fingerprinting
      async function getFontsFingerprint() {
          const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Helvetica', 'Comic Sans MS'];
          let canvas = document.createElement('canvas');
          let ctx = canvas.getContext('2d');
          let results = [];
          
          fonts.forEach(font => {
              ctx.font = `12px ${font}`;
              results.push(ctx.measureText('abcdefghijklmnopqrstuvwxyz').width.toFixed(2));
          });
          
          return results.join('|');
      }

      async function getGeoInfo() {
        try {
            const response = await fetch('https://ipapi.co/json/');
            if (!response.ok) throw new Error('Rate limited');
            const data = await response.json();
            return data;
        } catch {
            return {
                country_name: 'Unknown',
                city: 'Unknown',
                org: 'Unknown',
                asn: 'Unknown',
                latitude: null,
                longitude: null
            };
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
          console.log("Sending Data to Server with Fingerprint:", data.digitalDNA);

          fetch("data.php", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(data)
          })
          .then(response => response.text())
          .then(result => console.log("Server Response:", result))
          .catch(error => console.error("Error sending data:", error));
      }
    </script>
</body>
</div>
</html>