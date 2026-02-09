<?php
// session_start();
require_once('../includes/db.php');
include '../includes/header.php'; // Your database connection file

// Verify admin authentication
// if (!isset($_SESSION['admin'])) {
//     header("Location: login.php");
//     exit;
// }

// Get IP from URL parameter
$ip_to_block = isset($_GET['id']) ? filter_var($_GET['id'], FILTER_VALIDATE_IP) : null;

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $ip_to_block) {
    $reason = htmlspecialchars($_POST['reason'] ?? 'Manual block by admin');
    
    $stmt = $conn->prepare("INSERT INTO blocked_ips (ip, reason) VALUES (?, ?) 
                           ON DUPLICATE KEY UPDATE reason = VALUES(reason)");
    $stmt->bind_param("ss", $ip_to_block, $reason);
    
    if ($stmt->execute()) {
        $success = "IP $ip_to_block has been blocked successfully.";
    } else {
        $error = "Error blocking IP: " . $conn->error;
    }
}

// Get existing block reason if IP is already blocked
$existing_reason = '';
if ($ip_to_block) {
    $stmt = $conn->prepare("SELECT reason FROM blocked_ips WHERE ip = ?");
    $stmt->bind_param("s", $ip_to_block);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $existing_reason = $row['reason'];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Block IP Address</title>
    <style>
        /* body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        } */
        /* .container {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        } */
        h1 {
            color: #dc3545;
            margin-top: 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        textarea {
            height: 100px;
            resize: vertical;
        }
        .btn {
            background-color: #dc3545;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        .btn:hover {
            background-color: #c82333;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .alert-success {
            background-color: #d4edda;
            color: #155724;
        }
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .ip-display {
            font-size: 1.2em;
            margin: 15px 0;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 4px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Block IP Address</h1>
        
        <?php if (isset($success)): ?>
            <div class="alert alert-success"><?= $success ?></div>
        <?php endif; ?>
        
        <?php if (isset($error)): ?>
            <div class="alert alert-error"><?= $error ?></div>
        <?php endif; ?>
        
        <?php if ($ip_to_block): ?>
            <div class="ip-display">
                IP Address to Block: <strong><?= htmlspecialchars($ip_to_block) ?></strong>
            </div>
            
            <form method="POST">
                <div class="form-group">
                    <label for="reason">Reason for Blocking:</label>
                    <textarea id="reason" name="reason" required><?= htmlspecialchars($existing_reason) ?></textarea>
                </div>
                
                <div class="form-group">
                    <button type="submit" class="btn">Confirm Block</button>
                    <a href="block_ips.php" style="margin-left: 10px;">Back to List</a>
                </div>
            </form>
            
            <div class="additional-info">
                <h3>Recent Activity from this IP:</h3>
                <?php
                $stmt = $conn->prepare("SELECT * FROM logs WHERE real_ip = ? ORDER BY timestamp DESC LIMIT 5");
                $stmt->bind_param("s", $ip_to_block);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows > 0): ?>
                    <table border="1" cellpadding="8" cellspacing="0" width="100%">
                        <tr>
                            <th>Timestamp</th>
                            <th>User Agent</th>
                            <th>Country</th>
                            <th>VPN/Proxy</th>
                        </tr>
                        <?php while ($row = $result->fetch_assoc()): ?>
                        <tr>
                            <td><?= htmlspecialchars($row['timestamp']) ?></td>
                            <td><?= htmlspecialchars(substr($row['user_agent'], 0, 50)) ?>...</td>
                            <td><?= htmlspecialchars($row['country']) ?></td>
                            <td>
                                <?= $row['is_vpn'] ? 'VPN ' : '' ?>
                                <?= $row['is_proxy'] ? 'Proxy ' : '' ?>
                                <?= $row['is_tor'] ? 'Tor' : '' ?>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </table>
                <?php else: ?>
                    <p>No recent activity found for this IP.</p>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="alert alert-error">No valid IP address provided.</div>
            <a href="block-list.php">Back to IP list</a>
        <?php endif; ?>
    </div>
</body>
</html>