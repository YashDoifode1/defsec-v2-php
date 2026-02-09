<?php
// api/export-preview.php

session_start();
header('Content-Type: application/json');

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/db.php';

// Only allow POST preview requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['preview'])) {
    echo json_encode([
        'success' => false,
        'error' => 'Invalid request',
        'preview' => [],
        'total' => 0
    ]);
    exit;
}

// Auth check
if (!isset($_SESSION['user_id'])) {
    echo json_encode([
        'success' => false,
        'error' => 'Unauthorized',
        'preview' => [],
        'total' => 0
    ]);
    exit;
}

$user_id = $_SESSION['user_id'];
$website_id = $_SESSION['website_id'] ?? 1;

/*
|--------------------------------------------------------------------------
| Input Parameters
|--------------------------------------------------------------------------
*/

$log_type = $_POST['log_type'] ?? 'visitor';
$start_date = $_POST['from_date'] ?? '';
$end_date = $_POST['to_date'] ?? '';
$ip_filter = $_POST['ip_filter'] ?? '';
$country_filter = $_POST['country_filter'] ?? '';
$vpn_filter = $_POST['vpn_filter'] ?? '';
$proxy_filter = $_POST['proxy_filter'] ?? '';
$severity_filter = $_POST['severity_filter'] ?? '';
$attack_type_filter = $_POST['attack_type_filter'] ?? '';
$status_filter = $_POST['status_filter'] ?? '';
$sort_column = $_POST['sort'] ?? 'timestamp';
$sort_order = strtoupper($_POST['order'] ?? 'DESC');
$limit = max(1, min(100, (int)($_POST['limit'] ?? 10))); // limit between 1–100

// Force sort order safety
$sort_order = $sort_order === 'ASC' ? 'ASC' : 'DESC';

try {

    switch ($log_type) {

        case 'visitor':

            $allowed_sort_columns = [
                'id', 'timestamp', 'ip', 'real_ip',
                'country', 'is_vpn', 'is_proxy'
            ];

            $sql = "SELECT id, timestamp, ip, real_ip, country, is_vpn, is_proxy, ISP, user_agent
                    FROM logs
                    WHERE user_id = :user_id AND website_id = :website_id";

            $params = [
                ':user_id' => $user_id,
                ':website_id' => $website_id
            ];

            if ($start_date && $end_date) {
                $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }

            if ($ip_filter) {
                $sql .= " AND (ip LIKE :ip OR real_ip LIKE :real_ip)";
                $params[':ip'] = "%$ip_filter%";
                $params[':real_ip'] = "%$ip_filter%";
            }

            if ($country_filter && $country_filter !== 'all') {
                $sql .= " AND country LIKE :country";
                $params[':country'] = "%$country_filter%";
            }

            if ($vpn_filter !== '') {
                $sql .= " AND is_vpn = :vpn";
                $params[':vpn'] = (int)$vpn_filter;
            }

            if ($proxy_filter !== '') {
                $sql .= " AND is_proxy = :proxy";
                $params[':proxy'] = (int)$proxy_filter;
            }

            break;

        case 'attack':

            $allowed_sort_columns = [
                'id', 'timestamp', 'ip_address',
                'attack_type', 'severity'
            ];

            $sql = "SELECT id, timestamp, ip_address, attack_type, severity, request_url
                    FROM attack_logs
                    WHERE user_id = :user_id AND website_id = :website_id";

            $params = [
                ':user_id' => $user_id,
                ':website_id' => $website_id
            ];

            if ($start_date && $end_date) {
                $sql .= " AND timestamp BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }

            if ($ip_filter) {
                $sql .= " AND ip_address LIKE :ip";
                $params[':ip'] = "%$ip_filter%";
            }

            if ($severity_filter && $severity_filter !== 'all') {
                $sql .= " AND severity = :severity";
                $params[':severity'] = $severity_filter;
            }

            if ($attack_type_filter && $attack_type_filter !== 'all') {
                $sql .= " AND attack_type LIKE :attack_type";
                $params[':attack_type'] = "%$attack_type_filter%";
            }

            break;

        case 'blocked':

            $allowed_sort_columns = [
                'id', 'ip', 'created_at', 'expiry_time'
            ];

            $sql = "SELECT id, ip, reason, created_at, expiry_time
                    FROM blocked_ips
                    WHERE user_id = :user_id AND website_id = :website_id";

            $params = [
                ':user_id' => $user_id,
                ':website_id' => $website_id
            ];

            if ($start_date && $end_date) {
                $sql .= " AND created_at BETWEEN :start_date AND :end_date";
                $params[':start_date'] = $start_date;
                $params[':end_date'] = $end_date . ' 23:59:59';
            }

            if ($ip_filter) {
                $sql .= " AND ip LIKE :ip";
                $params[':ip'] = "%$ip_filter%";
            }

            if ($status_filter === 'active') {
                $sql .= " AND (expiry_time = '00:00:00'
                        OR DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) > NOW())";
            } elseif ($status_filter === 'expired') {
                $sql .= " AND expiry_time != '00:00:00'
                        AND DATE_ADD(created_at, INTERVAL TIME_TO_SEC(expiry_time) SECOND) <= NOW()";
            }

            break;

        default:
            echo json_encode([
                'success' => true,
                'preview' => [],
                'total' => 0
            ]);
            exit;
    }

    // Validate sort column
    if (!in_array($sort_column, $allowed_sort_columns)) {
        $sort_column = 'id';
    }

    /*
    |--------------------------------------------------------------------------
    | Count Query
    |--------------------------------------------------------------------------
    */

    $count_stmt = $pdo->prepare("SELECT COUNT(*) FROM ($sql) as count_query");
    foreach ($params as $key => $value) {
        $count_stmt->bindValue($key, $value);
    }
    $count_stmt->execute();
    $total = (int)$count_stmt->fetchColumn();

    /*
    |--------------------------------------------------------------------------
    | Preview Query
    |--------------------------------------------------------------------------
    */

    $sql .= " ORDER BY $sort_column $sort_order LIMIT :limit";

    $stmt = $pdo->prepare($sql);

    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }

    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);

    $stmt->execute();
    $preview = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'success' => true,
        'preview' => $preview,
        'total' => $total
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {

    error_log('Export Preview Error: ' . $e->getMessage());

    echo json_encode([
        'success' => false,
        'error' => 'Database error occurred',
        'preview' => [],
        'total' => 0
    ]);
}

exit;
