<?php
header('Content-Type: application/json');

// Check if 'ip' parameter exists
if (!isset($_GET['ip'])) {
    echo json_encode(["error" => "No IP address provided."]);
    exit;
}

$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if (!$ip) {
    echo json_encode(["error" => "Invalid IP address."]);
    exit;
}

// Fetch Whois data
$whoisUrl = "https://rdap.org/ip/" . urlencode($ip);

$whoisData = @file_get_contents($whoisUrl);
if (!$whoisData) {
    echo json_encode(["error" => "Whois data not found or service unavailable."]);
    exit;
}

$whoisJson = json_decode($whoisData, true);
if (!$whoisJson) {
    echo json_encode(["error" => "Failed to decode Whois JSON data."]);
    exit;
}

// Extract details
$output = [
    "ip" => $ip,
    "country" => $whoisJson["country"] ?? "N/A",
    "handle" => $whoisJson["handle"] ?? "N/A",
    "events" => isset($whoisJson["events"]) ? array_column($whoisJson["events"], "eventAction") : [],
    "email" => [],
    "tel" => [],
    "adr" => []
];

// Extract emails, phones, addresses
if (!empty($whoisJson["entities"])) {
    foreach ($whoisJson["entities"] as $entity) {
        if (!empty($entity["vcardArray"][1])) {
            foreach ($entity["vcardArray"][1] as $vcard) {
                switch ($vcard[0] ?? '') {
                    case 'email':
                        $output["email"][] = htmlspecialchars($vcard[3] ?? '');
                        break;
                    case 'tel':
                        $output["tel"][] = htmlspecialchars($vcard[3] ?? '');
                        break;
                    case 'adr':
                        $output["adr"][] = htmlspecialchars(implode(", ", array_filter($vcard[3] ?? [])));
                        break;
                }
            }
        }
    }
}

// Return JSON response
echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
