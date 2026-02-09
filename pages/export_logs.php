<?php
session_start();
include '../includes/header.php';

// Connect to Database
$conn = new mysqli("localhost", "root", "", "mailfor");
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

// Get current user and website
$user_id = $_SESSION['user_id'] ?? 1;
$website_id = $_SESSION['website_id'] ?? 1;

// Get export format, date range, and optional sorting
$format = $_GET['format'] ?? 'csv';
$start_date = $_GET['from_date'] ?? '';
$end_date = $_GET['to_date'] ?? '';
$sort_column = $_GET['sort'] ?? 'id';
$sort_order = strtoupper($_GET['order'] ?? 'DESC');

// Validate sort input to prevent SQL injection
$allowed_columns = ['id','ip','real_ip','ISP','is_vpn','is_tor','webrtc_ip','dns_leak_ip','created_at'];
if (!in_array($sort_column, $allowed_columns)) $sort_column = 'id';
if (!in_array($sort_order, ['ASC','DESC'])) $sort_order = 'DESC';

// Base SQL query with user and website filter
$sql = "SELECT * FROM logs WHERE user_id = ? AND website_id = ?";
$params = [$user_id, $website_id];
$types = "ii";

// Date filtering
if (!empty($start_date) && !empty($end_date)) {
    $sql .= " AND created_at BETWEEN ? AND ?";
    $params[] = $start_date;
    $params[] = $end_date;
    $types .= "ss";
}

// Add sorting
$sql .= " ORDER BY $sort_column $sort_order";

// Prepare and execute
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$result = $stmt->get_result();

// CSV Export
if ($format == 'csv') {
    header("Content-Type: text/csv");
    header("Content-Disposition: attachment; filename=logs.csv");
    
    $output = fopen("php://output", "w");
    fputcsv($output, ["ID","IP Route","Reverse DNS","Real IP","ISP","VPN","Tor","WebRTC","DNS","User Agent","Screen Resolution","Language","Timezone","Cookies Enabled","Referrer","Plugins"]);
    
    while ($row = $result->fetch_assoc()) {
        fputcsv($output, [
            $row['id'],
            $row['ip'],
            $row['reverse_dns'],
            $row['real_ip'],
            $row['ISP'],
            $row['is_vpn'] ? '✅' : '✕',
            $row['is_tor'] ? '✅' : '✕',
            $row['webrtc_ip'],
            $row['dns_leak_ip'],
            $row['user_agent'],
            $row['screen_resolution'],
            $row['language'],
            $row['timezone'],
            $row['cookies_enabled'],
            $row['referrer'],
            $row['plugins']
        ]);
    }
    fclose($output);
    exit;
}

// PDF Export
if ($format == 'pdf') {
    require_once('libs/tcpdf.php');
    $pdf = new TCPDF();
    $pdf->AddPage();
    $pdf->SetFont('helvetica', '', 10);
    
    $html = '<h2>User Tracking Logs</h2><table border="1" cellpadding="5">
        <tr>
            <th>ID</th><th>IP Route</th><th>Reverse DNS</th><th>Real IP</th><th>ISP</th>
            <th>VPN</th><th>Tor</th><th>WebRTC</th><th>DNS</th><th>User Agent</th>
            <th>Screen Resolution</th><th>Language</th><th>Timezone</th><th>Cookies Enabled</th>
            <th>Referrer</th><th>Plugins</th>
        </tr>';
    
    while ($row = $result->fetch_assoc()) {
        $html .= "<tr>
            <td>{$row['id']}</td>
            <td>{$row['ip']}</td>
            <td>{$row['reverse_dns']}</td>
            <td>{$row['real_ip']}</td>
            <td>{$row['ISP']}</td>
            <td>" . ($row['is_vpn'] ? '✅' : '✕') . "</td>
            <td>" . ($row['is_tor'] ? '✅' : '✕') . "</td>
            <td>{$row['webrtc_ip']}</td>
            <td>{$row['dns_leak_ip']}</td>
            <td>{$row['user_agent']}</td>
            <td>{$row['screen_resolution']}</td>
            <td>{$row['language']}</td>
            <td>{$row['timezone']}</td>
            <td>{$row['cookies_enabled']}</td>
            <td>{$row['referrer']}</td>
            <td>{$row['plugins']}</td>
        </tr>";
    }
    
    $html .= '</table>';
    $pdf->writeHTML($html);
    $pdf->Output('logs.pdf', 'D');
    exit;
}

$conn->close();
?>
