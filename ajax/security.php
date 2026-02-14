<?php
// ==============================
// security.php - SaaS Multi-Tenant Client
// ==============================
header('Content-Type: application/javascript');

// Get API key from request
$apiKey = $_GET['api_key'] ?? '';
if (empty($apiKey)) {
    die('console.error("Security: Missing API key");');
}

// Collect browser metadata
$browserData = [
    'url' => $_SERVER['HTTP_REFERER'] ?? ($_SERVER['REQUEST_URI'] ?? ''),
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
    'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
    'connection' => $_SERVER['HTTP_CONNECTION'] ?? '',
    'cache_control' => $_SERVER['HTTP_CACHE_CONTROL'] ?? '',
    'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? '',
    'sec_ch_ua_mobile' => $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '',
    'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
    'timestamp' => time(),
    'screen_resolution' => '', // Will be captured client-side
    'timezone' => '', // Will be captured client-side
    'cookies_enabled' => '' // Will be captured client-side
];

// Output JavaScript that collects metadata and sends to collect.php
?>
(function() {
    'use strict';
    
    const apiKey = <?php echo json_encode($apiKey); ?>;
    const serverData = <?php echo json_encode($browserData); ?>;
    
    // Collect client-side metadata
    function getClientMetadata() {
        return {
            screen_resolution: window.screen.width + 'x' + window.screen.height,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            cookies_enabled: navigator.cookieEnabled,
            referrer: document.referrer,
            page_title: document.title,
            dom_loaded: performance.timing ? 
                (performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart) : 0,
            load_time: performance.timing ? 
                (performance.timing.loadEventEnd - performance.timing.navigationStart) : 0
        };
    }

    // Collect request parameters (GET and POST)
    function getRequestData() {
        const urlParams = new URLSearchParams(window.location.search);
        const params = {};
        urlParams.forEach((value, key) => {
            if (key !== 'api_key') { // Don't send API key in payload
                params[key] = value;
            }
        });
        
        return {
            url: window.location.href,
            pathname: window.location.pathname,
            query_string: window.location.search,
            parameters: params
        };
    }

    // Send security data to collector
    function sendSecurityData() {
        const payload = {
            api_key: apiKey,
            payload: {
                server: serverData,
                client: getClientMetadata(),
                request: getRequestData(),
                headers: {
                    cookie: document.cookie,
                    origin: window.location.origin
                }
            }
        };

        // Use sendBeacon for page unload, fallback to fetch
        if (navigator.sendBeacon) {
            const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
            navigator.sendBeacon('/collect.php', blob);
        } else {
            fetch('/collect.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            }).catch(error => {
                console.error('Security logger error:', error);
            });
        }
    }

    // Send data when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', sendSecurityData);
    } else {
        sendSecurityData();
    }

    // Monitor for XSS attempts in DOM
    function monitorDOMForXSS() {
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes.length) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeType === 1 && node.innerHTML) { // Element node
                            const xssPatterns = [
                                /<script|<iframe|javascript:|onload\s*=|onerror\s*=/i,
                                /eval\s*\(|document\.write|innerHTML\s*=/
                            ];
                            
                            xssPatterns.forEach(pattern => {
                                if (pattern.test(node.outerHTML || '')) {
                                    fetch('/collect.php', {
                                        method: 'POST',
                                        headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({
                                            api_key: apiKey,
                                            payload: {
                                                type: 'client_xss',
                                                details: node.outerHTML.substring(0, 200),
                                                url: window.location.href
                                            }
                                        })
                                    });
                                }
                            });
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    if (document.body) {
        monitorDOMForXSS();
    } else {
        document.addEventListener('DOMContentLoaded', monitorDOMForXSS);
    }
})();