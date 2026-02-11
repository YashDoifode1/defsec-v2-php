<?php
require_once '../../includes/db.php';
require_once '../../includes/auth.php';

header('Content-Type: application/json');

if (!$auth->isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$userId = $_SESSION['user_id'];
$websiteId = $_SESSION['website_id'] ?? 1;

try {
    // Get most recent attacker from attack logs
    $stmt = $pdo->prepare("
        SELECT ip_address, attack_type, severity, MAX(timestamp) as last_attack
        FROM attack_logs
        WHERE user_id = ? AND website_id = ? 
        AND ip_address NOT IN (
            SELECT ip FROM blocked_ips 
            WHERE user_id = ? AND website_id = ?
            AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
        )
        GROUP BY ip_address
        ORDER BY last_attack DESC
        LIMIT 1
    ");
    
    $stmt->execute([$userId, $websiteId, $userId, $websiteId]);
    $attacker = $stmt->fetch();
    
    if ($attacker) {
        echo json_encode([
            'success' => true,
            'ip' => $attacker['ip_address'],
            'reason' => $attacker['attack_type'] . ' attack (' . $attacker['severity'] . ')',
            'last_attack' => $attacker['last_attack']
        ]);
    } else {
        // If no attacks, get recent VPN user
        $vpnStmt = $pdo->prepare("
            SELECT ip, country, ISP as isp
            FROM logs
            WHERE user_id = ? AND website_id = ? AND is_vpn = 1
            AND ip NOT IN (
                SELECT ip FROM blocked_ips 
                WHERE user_id = ? AND website_id = ?
                AND (expiry_time = '00:00:00' OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())
            )
            ORDER BY timestamp DESC
            LIMIT 1
        ");
        
        $vpnStmt->execute([$userId, $websiteId, $userId, $websiteId]);
        $vpnUser = $vpnStmt->fetch();
        
        if ($vpnUser) {
            echo json_encode([
                'success' => true,
                'ip' => $vpnUser['ip'],
                'reason' => 'VPN user from ' . $vpnUser['country'],
                'country' => $vpnUser['country'],
                'isp' => $vpnUser['isp']
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'No suggestions available']);
        }
    }
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error']);
}
?>