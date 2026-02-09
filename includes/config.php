<?php
// includes/config.php

// Application settings
define('APP_NAME', 'Defsec Cybersecurity Dashboard');
define('APP_VERSION', '1.0.0');
define('BASE_URL', 'http://localhost/Defsec/v2');

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'mailfor');

// Security settings
define('PASSWORD_HASH_COST', 12);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_ATTEMPTS_TIMEFRAME', 300);
define('SESSION_TIMEOUT', 1800);
define('CSRF_TOKEN_LIFETIME', 3600);

// Dashboard settings
define('ITEMS_PER_PAGE', 20);
define('AUTO_REFRESH_INTERVAL', 30000);

// Start session with security settings
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'name' => 'DefsecSession',
        'cookie_lifetime' => SESSION_TIMEOUT,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
        'use_only_cookies' => 1
    ]);
}
?>