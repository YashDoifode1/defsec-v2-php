<?php
// pages/export_preview.php - AJAX Preview Handler

session_start();
require_once '../includes/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['preview'])) {
    $user_id = $_SESSION['user_id'] ?? 1;
    $website_id = $_SESSION['website_id'] ?? 1;
    
    // Get filter parameters
    $start_date = $_POST['from_date'] ?? '';
    $end_date = $_POST['to_date'] ?? '';
    $ip_filter = $_POST['ip_filter'] ?? '';
    $country_filter = $_POST['country_filter'] ?? '';
    $vpn_filter = $_POST['vpn_filter'] ?? '';
    $tor_filter = $_POST['tor_filter'] ?? '';
    $proxy_filter = $_POST['proxy_filter'] ?? '';
    $sort_column = $_POST['sort'] ?? 'timestamp';
    $sort_order = 'DESC';
    
    // Build SQL query
    $sql = "SELECT id, timestamp, ip, real_ip, country, is_vpn, is_tor, is_proxy, ISP 
            FROM logs WHERE user_id = :user_id AND website_id = :website_id";
    $params = [
        ':user_id' => $user_id,
        ':website_id' => $website_id
    ];
    
    if (!empty($start_date) && !empty($end_date)) {
        $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
        $params[':start_date'] = $start_date;
        $params[':end_date'] = $end_date . ' 23:59:59';
    }
    
    if (!empty($ip_filter)) {
        $sql .= " AND (ip LIKE :ip OR real_ip LIKE :real_ip)";
        $params[':ip'] = '%' . $ip_filter . '%';
        $params[':real_ip'] = '%' . $ip_filter . '%';
    }
    
    if (!empty($country_filter) && $country_filter !== 'all') {
        $sql .= " AND country LIKE :country";
        $params[':country'] = '%' . $country_filter . '%';
    }
    
    if ($vpn_filter !== '') {
        $sql .= " AND is_vpn = :vpn";
        $params[':vpn'] = (int)$vpn_filter;
    }
    
    if ($tor_filter !== '') {
        $sql .= " AND is_tor = :tor";
        $params[':tor'] = (int)$tor_filter;
    }
    
    if ($proxy_filter !== '') {
        $sql .= " AND is_proxy = :proxy";
        $params[':proxy'] = (int)$proxy_filter;
    }
    
    $sql .= " ORDER BY $sort_column $sort_order LIMIT 10";
    
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $preview = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Get total count with separate query
        $count_sql = "SELECT COUNT(*) as total FROM logs WHERE user_id = :user_id AND website_id = :website_id";
        $count_params = [
            ':user_id' => $user_id,
            ':website_id' => $website_id
        ];
        
        if (!empty($start_date) && !empty($end_date)) {
            $count_sql .= " AND timestamp BETWEEN :start_date AND :end_date";
            $count_params[':start_date'] = $start_date;
            $count_params[':end_date'] = $end_date . ' 23:59:59';
        }
        
        if (!empty($ip_filter)) {
            $count_sql .= " AND (ip LIKE :ip OR real_ip LIKE :real_ip)";
            $count_params[':ip'] = '%' . $ip_filter . '%';
            $count_params[':real_ip'] = '%' . $ip_filter . '%';
        }
        
        if (!empty($country_filter) && $country_filter !== 'all') {
            $count_sql .= " AND country LIKE :country";
            $count_params[':country'] = '%' . $country_filter . '%';
        }
        
        if ($vpn_filter !== '') {
            $count_sql .= " AND is_vpn = :vpn";
            $count_params[':vpn'] = (int)$vpn_filter;
        }
        
        if ($tor_filter !== '') {
            $count_sql .= " AND is_tor = :tor";
            $count_params[':tor'] = (int)$tor_filter;
        }
        
        if ($proxy_filter !== '') {
            $count_sql .= " AND is_proxy = :proxy";
            $count_params[':proxy'] = (int)$proxy_filter;
        }
        
        $count_stmt = $pdo->prepare($count_sql);
        $count_stmt->execute($count_params);
        $total = $count_stmt->fetch()['total'];
        
        header('Content-Type: application/json');
        echo json_encode([
            'preview' => $preview,
            'total' => $total
        ]);
        
    } catch (PDOException $e) {
        error_log("Preview error: " . $e->getMessage());
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}
?>