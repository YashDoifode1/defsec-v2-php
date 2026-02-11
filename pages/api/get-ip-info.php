<?php
require_once '../../includes/db.php';
require_once '../../includes/auth.php';

header('Content-Type: application/json');

if (!$auth->isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

if (!isset($_GET['ip']) || empty($_GET['ip'])) {
    echo json_encode(['success' => false, 'message' => 'IP address required']);
    exit();
}

$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if (!$ip) {
    echo json_encode(['success' => false, 'message' => 'Invalid IP address']);
    exit();
}

$userId = $_SESSION['user_id'];
$websiteId = $_SESSION['website_id'] ?? 1;

try {
    // Get IP information from logs
    $stmt = $pdo->prepare("
        SELECT 
            ip,
            real_ip,
            country,
            ISP as isp,
            ASN as asn,
            is_vpn,
            is_proxy,
            COUNT(*) as visit_count,
            MAX(timestamp) as last_seen
        FROM logs 
        WHERE (ip = ? OR real_ip = ?) AND user_id = ? AND website_id = ?
        GROUP BY ip
        ORDER BY last_seen DESC
        LIMIT 1
    ");
    
    $stmt->execute([$ip, $ip, $userId, $websiteId]);
    $ipInfo = $stmt->fetch();
    
    // Check if IP is blocked
    $blockStmt = $pdo->prepare("
        SELECT COUNT(*) as is_blocked 
        FROM blocked_ips 
        WHERE ip = ? AND user_id = ? AND website_id = ?
        AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
    ");
    
    $blockStmt->execute([$ip, $userId, $websiteId]);
    $blockInfo = $blockStmt->fetch();
    
    // Get attack count
    $attackStmt = $pdo->prepare("
        SELECT COUNT(*) as attack_count
        FROM attack_logs
        WHERE ip_address = ? AND user_id = ? AND website_id = ?
    ");
    
    $attackStmt->execute([$ip, $userId, $websiteId]);
    $attackInfo = $attackStmt->fetch();
    
    $result = [
        'success' => true,
        'data' => [
            'ip' => $ip,
            'country' => $ipInfo['country'] ?? 'Unknown',
            'isp' => $ipInfo['isp'] ?? 'Unknown',
            'asn' => $ipInfo['asn'] ?? 'Unknown',
            'is_vpn' => $ipInfo['is_vpn'] ?? false,
            'is_proxy' => $ipInfo['is_proxy'] ?? false,
            'visit_count' => $ipInfo['visit_count'] ?? 0,
            'last_seen' => $ipInfo['last_seen'] ?? null,
            'is_blocked' => $blockInfo['is_blocked'] > 0,
            'attack_count' => $attackInfo['attack_count'] ?? 0
        ]
    ];
    
    echo json_encode($result);
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error']);
}
?>