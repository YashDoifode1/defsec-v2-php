<?php
header('Content-Type: application/json');

// Allow CORS if needed (for SaaS/external use)
// header("Access-Control-Allow-Origin: *");

// Validate IP parameter
if (!isset($_GET['ip'])) {
    http_response_code(400);
    echo json_encode(["error" => "No IP address provided."]);
    exit;
}

$ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
if (!$ip) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid IP address."]);
    exit;
}

// Reject private/reserved ranges (optional but recommended)
if (
    filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
) {
    http_response_code(400);
    echo json_encode(["error" => "Private or reserved IP addresses are not allowed."]);
    exit;
}

// RDAP URL
$rdapUrl = "https://rdap.org/ip/" . urlencode($ip);

// Initialize cURL
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $rdapUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_USERAGENT => "Mailfor-Security-Panel/1.0"
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    $error = curl_error($ch);
    curl_close($ch);
    http_response_code(500);
    echo json_encode(["error" => "cURL Error: " . $error]);
    exit;
}

curl_close($ch);

if ($httpCode !== 200 || !$response) {
    http_response_code(404);
    echo json_encode(["error" => "Whois data not found or service unavailable."]);
    exit;
}

// Decode JSON
$data = json_decode($response, true);
if (!$data) {
    http_response_code(500);
    echo json_encode(["error" => "Failed to decode RDAP response."]);
    exit;
}

// Extract useful info
$output = [
    "ip" => $ip,
    "country" => $data["country"] ?? "N/A",
    "handle" => $data["handle"] ?? "N/A",
    "startAddress" => $data["startAddress"] ?? "N/A",
    "endAddress" => $data["endAddress"] ?? "N/A",
    "name" => $data["name"] ?? "N/A",
    "type" => $data["type"] ?? "N/A",
    "org" => [],
    "abuse_email" => [],
    "abuse_phone" => [],
    "events" => [],
];

// Extract events
if (!empty($data["events"])) {
    foreach ($data["events"] as $event) {
        if (isset($event["eventAction"], $event["eventDate"])) {
            $output["events"][] = $event["eventAction"] . " (" . $event["eventDate"] . ")";
        }
    }
}

// Extract entity information
if (!empty($data["entities"])) {
    foreach ($data["entities"] as $entity) {

        // Extract organization name
        if (!empty($entity["vcardArray"][1])) {
            foreach ($entity["vcardArray"][1] as $vcard) {

                switch ($vcard[0]) {
                    case "fn":
                        $output["org"][] = $vcard[3] ?? '';
                        break;

                    case "email":
                        if (!empty($vcard[3])) {
                            $output["abuse_email"][] = $vcard[3];
                        }
                        break;

                    case "tel":
                        if (!empty($vcard[3])) {
                            $output["abuse_phone"][] = $vcard[3];
                        }
                        break;
                }
            }
        }
    }
}

// Remove duplicates
$output["org"] = array_unique(array_filter($output["org"]));
$output["abuse_email"] = array_unique(array_filter($output["abuse_email"]));
$output["abuse_phone"] = array_unique(array_filter($output["abuse_phone"]));

// Return final JSON
echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
