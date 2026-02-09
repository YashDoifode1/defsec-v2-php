<?php
// includes/config.php

// Load .env file
function loadEnv($path)
{
    if (!file_exists($path)) {
        throw new Exception('.env file not found');
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        list($name, $value) = array_map('trim', explode('=', $line, 2));

        // Remove surrounding quotes
        $value = trim($value, "\"'");

        putenv("$name=$value");
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

// Load environment variables
loadEnv(__DIR__ . '/../.env');

// Application settings
define('APP_NAME', getenv('APP_NAME'));
define('APP_VERSION', getenv('APP_VERSION'));
define('BASE_URL', getenv('BASE_URL'));

// Database configuration
define('DB_HOST', getenv('DB_HOST'));
define('DB_USER', getenv('DB_USER'));
define('DB_PASS', getenv('DB_PASS'));
define('DB_NAME', getenv('DB_NAME'));

// Security settings
define('PASSWORD_HASH_COST', (int) getenv('PASSWORD_HASH_COST'));
define('MAX_LOGIN_ATTEMPTS', (int) getenv('MAX_LOGIN_ATTEMPTS'));
define('LOGIN_ATTEMPTS_TIMEFRAME', (int) getenv('LOGIN_ATTEMPTS_TIMEFRAME'));
define('SESSION_TIMEOUT', (int) getenv('SESSION_TIMEOUT'));
define('CSRF_TOKEN_LIFETIME', (int) getenv('CSRF_TOKEN_LIFETIME'));

// Dashboard settings
define('ITEMS_PER_PAGE', (int) getenv('ITEMS_PER_PAGE'));
define('AUTO_REFRESH_INTERVAL', (int) getenv('AUTO_REFRESH_INTERVAL'));

// Start session with security settings
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'name' => 'DefsecSession',
        'cookie_lifetime' => SESSION_TIMEOUT,
        'cookie_secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
        'use_only_cookies' => 1
    ]);
}
?>
