<?php
// api/get-quick-stats.php
require_once '../includes/config.php';
require_once '../includes/db.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

// Check authentication
if (!$auth->isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

// Get website ID from session
$websiteId = $_SESSION['CONTEXT']['WEBSITE_ID'] ?? 0;

try {
    // Get threat count (last 24 hours)
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM attack_logs 
        WHERE website_id = ? 
        AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stmt->execute([$websiteId]);
    $threats = $stmt->fetchColumn();
    
    // Get blocked IP count
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE website_id = ? 
        AND is_active = 1
    ");
    $stmt->execute([$websiteId]);
    $blocked = $stmt->fetchColumn();
    
    // Get online users (last 5 minutes)
    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT ip_address) as count 
        FROM user_sessions 
        WHERE website_id = ? 
        AND last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    ");
    $stmt->execute([$websiteId]);
    $online = $stmt->fetchColumn();
    
    // Get attack count for sidebar
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM attack_logs 
        WHERE website_id = ? 
        AND resolved = 0
    ");
    $stmt->execute([$websiteId]);
    $attacks = $stmt->fetchColumn();
    
    // Get blocked IPs count for sidebar
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM blocked_ips 
        WHERE website_id = ? 
        AND is_active = 1
    ");
    $stmt->execute([$websiteId]);
    $blockedIps = $stmt->fetchColumn();
    
    // Get alert count for sidebar
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as count 
        FROM alerts 
        WHERE website_id = ? 
        AND status = 'unread'
    ");
    $stmt->execute([$websiteId]);
    $alerts = $stmt->fetchColumn();
    
    echo json_encode([
        'success' => true,
        'threats' => (int)$threats,
        'blocked' => (int)$blocked,
        'online' => (int)$online,
        'attacks' => (int)$attacks,
        'blocked_ips' => (int)$blockedIps,
        'alerts' => (int)$alerts
    ]);
    
} catch (PDOException $e) {
    error_log("Quick stats error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'Failed to load statistics'
    ]);
}
?>