<?php
// export-analysis.php
require_once '../includes/db_connect.php';

session_start();
$userId = $_SESSION['user_id'] ?? 1;
$analysisId = $_GET['id'] ?? 0;

// Get analysis
$stmt = $pdo->prepare("SELECT * FROM email_analyses WHERE id = ? AND user_id = ?");
$stmt->execute([$analysisId, $userId]);
$analysis = $stmt->fetch();

if (!$analysis) {
    die('Analysis not found');
}

// Get IPs
$ipStmt = $pdo->prepare("SELECT * FROM email_ips WHERE analysis_id = ? ORDER BY hop_number");
$ipStmt->execute([$analysisId]);
$ips = $ipStmt->fetchAll();

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="email_analysis_' . $analysisId . '_' . date('Y-m-d') . '.csv"');

$output = fopen('php://output', 'w');

// Basic info
fputcsv($output, ['Email Analysis Report']);
fputcsv($output, ['Analysis ID', $analysis['id']]);
fputcsv($output, ['Date', $analysis['analysis_date']]);
fputcsv($output, ['From', $analysis['from_address']]);
fputcsv($output, ['Subject', $analysis['subject']]);
fputcsv($output, ['SPF', $analysis['spf_result']]);
fputcsv($output, ['DKIM', $analysis['dkim_result']]);
fputcsv($output, ['DMARC', $analysis['dmarc_result']]);
fputcsv($output, ['Threat Score', $analysis['spam_score']]);
fputcsv($output, []);

// IP details
fputcsv($output, ['Hop', 'IP Address', 'Hostname', 'Reverse DNS', 'Country', 'City', 
                   'ISP', 'ASN', 'VPN', 'TOR', 'Proxy', 'Threat Score']);

foreach ($ips as $ip) {
    fputcsv($output, [
        $ip['hop_number'],
        $ip['ip_address'],
        $ip['hostname'],
        $ip['reverse_dns'],
        $ip['country'],
        $ip['city'],
        $ip['isp'],
        $ip['asn'],
        $ip['is_vpn'] ? 'Yes' : 'No',
        $ip['is_tor'] ? 'Yes' : 'No',
        $ip['is_proxy'] ? 'Yes' : 'No',
        $ip['threat_score']
    ]);
}

fclose($output);
?>