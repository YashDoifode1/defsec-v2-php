<?php
// api/export-geolocation.php

session_start();

ini_set('display_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/../../includes/db.php';

// Auth check
if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    exit('Forbidden');
}

$userId = $_SESSION['user_id'];
$websiteId = intval($_GET['website_id'] ?? $_SESSION['website_id'] ?? 0);

if ($websiteId <= 0) {
    http_response_code(400);
    exit('Invalid website ID');
}

$exportFormat = strtolower($_GET['export'] ?? 'json');

// Validate dates
$startDateInput = $_GET['start_date'] ?? date('Y-m-d', strtotime('-7 days'));
$endDateInput   = $_GET['end_date'] ?? date('Y-m-d');

$startDate = strtotime($startDateInput) ? date('Y-m-d', strtotime($startDateInput)) : date('Y-m-d', strtotime('-7 days'));
$endDate   = strtotime($endDateInput)   ? date('Y-m-d', strtotime($endDateInput))   : date('Y-m-d');

$country = $_GET['country'] ?? '';
$ipSearch = $_GET['ip'] ?? '';

try {

    /*
    |--------------------------------------------------------------------------
    | Build Query
    |--------------------------------------------------------------------------
    */

    $conditions = ["user_id = ?", "website_id = ?"];
    $params = [$userId, $websiteId];

    $conditions[] = "DATE(timestamp) >= ?";
    $params[] = $startDate;

    $conditions[] = "DATE(timestamp) <= ?";
    $params[] = $endDate;

    if (!empty($country) && $country !== 'all') {
        $conditions[] = "country = ?";
        $params[] = $country;
    }

    if (!empty($ipSearch)) {
        $conditions[] = "(ip LIKE ? OR real_ip LIKE ?)";
        $params[] = "%$ipSearch%";
        $params[] = "%$ipSearch%";
    }

    $whereClause = implode(' AND ', $conditions);

    $query = $pdo->prepare("
        SELECT 
            ip,
            real_ip,
            country,
            latitude,
            longitude,
            user_agent,
            timestamp,
            is_vpn,
            is_proxy,
            ASN,
            ISP,
            screen_resolution,
            language,
            timezone,
            digital_dna
        FROM logs
        WHERE $whereClause
        ORDER BY timestamp DESC
    ");

    $query->execute($params);
    $data = $query->fetchAll(PDO::FETCH_ASSOC);

    /*
    |--------------------------------------------------------------------------
    | Export Handling
    |--------------------------------------------------------------------------
    */

    $filename = "geolocation-export-" . date('Y-m-d');

    // Clear any previous output buffer (critical)
    if (ob_get_length()) {
        ob_end_clean();
    }

    if ($exportFormat === 'csv') {

        header('Content-Type: text/csv');
        header("Content-Disposition: attachment; filename=\"$filename.csv\"");
        header('Pragma: no-cache');
        header('Expires: 0');

        $output = fopen('php://output', 'w');

        if (!empty($data)) {
            fputcsv($output, array_keys($data[0]));
            foreach ($data as $row) {
                fputcsv($output, $row);
            }
        }

        fclose($output);

    } else {

        header('Content-Type: application/json');
        header("Content-Disposition: attachment; filename=\"$filename.json\"");
        header('Pragma: no-cache');
        header('Expires: 0');

        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }

} catch (Exception $e) {

    error_log('Geolocation Export Error: ' . $e->getMessage());

    http_response_code(500);

    if ($exportFormat === 'csv') {
        header('Content-Type: text/plain');
        echo "Export failed.";
    } else {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Export failed.']);
    }
}

exit;
