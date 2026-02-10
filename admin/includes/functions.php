<?php
// includes/functions.php

/**
 * Generate CSRF token
 */
function generateCSRFToken($form_name = 'default') {
    if (!isset($_SESSION['csrf_tokens'])) {
        $_SESSION['csrf_tokens'] = [];
    }
    
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_tokens'][$form_name] = [
        'token' => $token,
        'expires' => time() + 3600 // 1 hour
    ];
    
    return $token;
}

/**
 * Validate CSRF token
 */
function validateCSRFToken($form_name, $token) {
    if (!isset($_SESSION['csrf_tokens'][$form_name])) {
        return false;
    }
    
    $stored_token = $_SESSION['csrf_tokens'][$form_name];
    
    // Remove expired tokens
    if (time() > $stored_token['expires']) {
        unset($_SESSION['csrf_tokens'][$form_name]);
        return false;
    }
    
    // Validate token
    if (hash_equals($stored_token['token'], $token)) {
        unset($_SESSION['csrf_tokens'][$form_name]);
        return true;
    }
    
    return false;
}

/**
 * Sanitize input
 */
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Format date
 */
function formatDate($date, $format = 'F j, Y H:i:s') {
    if (empty($date) || $date === '0000-00-00 00:00:00') {
        return 'Never';
    }
    return date($format, strtotime($date));
}

/**
 * Get severity badge class
 */
function getSeverityBadge($severity) {
    switch (strtolower($severity)) {
        case 'critical':
            return 'danger';
        case 'high':
            return 'warning';
        case 'medium':
            return 'info';
        case 'low':
            return 'secondary';
        default:
            return 'dark';
    }
}

/**
 * Get status badge class
 */
function getStatusBadge($status) {
    switch (strtolower($status)) {
        case 'active':
            return 'success';
        case 'paused':
        case 'suspended':
            return 'warning';
        case 'inactive':
        case 'blocked':
            return 'danger';
        default:
            return 'secondary';
    }
}

/**
 * Get role badge class
 */
function getRoleBadge($role) {
    switch (strtolower($role)) {
        case 'superadmin':
            return 'danger';
        case 'admin':
            return 'info';
        case 'analyst':
            return 'success';
        case 'viewer':
            return 'secondary';
        default:
            return 'dark';
    }
}

/**
 * Truncate text
 */
function truncateText($text, $length = 100) {
    if (strlen($text) <= $length) {
        return $text;
    }
    return substr($text, 0, $length) . '...';
}

/**
 * Get IP information (mock for now)
 */
function getIPInfo($ip) {
    return [
        'country' => 'Unknown',
        'isp' => 'Unknown',
        'asn' => 'Unknown',
        'threat_level' => 'low'
    ];
}

/**
 * Generate random string
 */
function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

/**
 * Log admin action
 */
function logAdminAction($pdo, $admin_id, $action, $details = '') {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO admin_logs (admin_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $admin_id,
            $action,
            $details,
            $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
    } catch (PDOException $e) {
        error_log("Failed to log admin action: " . $e->getMessage());
    }
}
?>