<?php
http_response_code(404);
require_once __DIR__ . '/../includes/config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>404 Not Found | <?= APP_NAME ?></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #ffffff;
            text-align: center;
            padding: 100px 20px;
        }
        .logo {
            width: 120px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 80px;
            margin: 0;
            color: #ef4444;
        }
        p {
            font-size: 18px;
            opacity: 0.8;
        }
        a {
            display: inline-block;
            margin-top: 30px;
            padding: 12px 25px;
            background: #3b82f6;
            color: #fff;
            text-decoration: none;
            border-radius: 6px;
        }
        a:hover {
            background: #2563eb;
        }
    </style>
</head>
<body>

    <img src="<?= BASE_URL ?>/assets/logo.png" class="logo" alt="Logo">

    <h1>500</h1>
    <p>The page you're looking for doesn't exist.</p>

    <a href="<?= BASE_URL ?>">Return to Dashboard</a>

</body>
</html>
