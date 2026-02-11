<?php
define('DEFSEC_API_KEY', '1279632cf873f05ff4721424285e47c0');

if (!defined('DEFSEC_API_KEY')) {
    return; // do nothing if not configured
}

if (php_sapi_name() === 'cli') {
    return; // ignore CLI
}

function defsec_run() {

    $endpoint = "http://localhost/defsec/v2/inspect.php";

    $payload = [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'get' => $_GET,
        'post' => $_POST
    ];

    $ch = curl_init($endpoint);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-KEY: ' . DEFSEC_API_KEY
        ],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_TIMEOUT => 2,
        CURLOPT_CONNECTTIMEOUT => 1
    ]);

    $response = curl_exec($ch);

    if ($response === false) {
        curl_close($ch);
        return; // fail open (don't break site)
    }

    curl_close($ch);

    $result = json_decode($response, true);

    if (!empty($result['block'])) {
        http_response_code(403);
        exit("Access Denied");
    }
}

// Run safely
defsec_run();
