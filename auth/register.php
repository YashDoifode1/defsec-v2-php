<?php
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username   = trim($_POST['username'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $password   = $_POST['password'] ?? '';
    $site_name  = trim($_POST['site_name'] ?? '');
    $domain     = strtolower(trim($_POST['domain'] ?? ''));

    if (strlen($username) < 3) $errors[] = "Username must be at least 3 characters.";
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email address.";
    if (strlen($password) < 6) $errors[] = "Password must be at least 6 characters.";
    if (empty($site_name)) $errors[] = "Website name required.";
    if (!preg_match('/^[a-z0-9.-]+$/', $domain)) $errors[] = "Invalid domain format.";

    if (empty($errors)) {
        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare("SELECT id FROM users WHERE username=? OR email=?");
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) throw new Exception("Username or email already exists.");

            $stmt = $pdo->prepare("SELECT id FROM websites WHERE domain=?");
            $stmt->execute([$domain]);
            if ($stmt->fetch()) throw new Exception("Domain already registered.");

            $passwordHash = password_hash($password, PASSWORD_DEFAULT, [
                'cost' => PASSWORD_HASH_COST
            ]);

            $stmt = $pdo->prepare("
                INSERT INTO users (username,email,password_hash,role,status,created_at)
                VALUES (?, ?, ?, 'admin','active',NOW())
            ");
            $stmt->execute([$username,$email,$passwordHash]);
            $userId = $pdo->lastInsertId();

            $stmt = $pdo->prepare("
                INSERT INTO websites (user_id,site_name,domain,status,created_at)
                VALUES (?, ?, ?, 'active',NOW())
            ");
            $stmt->execute([$userId,$site_name,$domain]);
            $websiteId = $pdo->lastInsertId();

            $pdo->commit();

            session_regenerate_id(true);
            $_SESSION['user_id'] = $userId;
            $_SESSION['website_id'] = $websiteId;

            header("Location: login.php");
            exit;

        } catch (Exception $e) {
            $pdo->rollBack();
            $errors[] = $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Register - <?= APP_NAME ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
body {
    margin:0;
    font-family: 'Segoe UI', sans-serif;
    background: linear-gradient(135deg,#0f2027,#203a43,#2c5364);
    display:flex;
    align-items:center;
    justify-content:center;
    height:100vh;
}

.container {
    background:#fff;
    padding:40px;
    border-radius:14px;
    width:100%;
    max-width:420px;
    box-shadow:0 15px 40px rgba(0,0,0,0.3);
}

h2 {
    margin-bottom:25px;
    text-align:center;
}

input {
    width:100%;
    padding:12px;
    margin-bottom:15px;
    border:1px solid #ddd;
    border-radius:8px;
    font-size:14px;
}

input:focus {
    border-color:#2c5364;
    outline:none;
}

button {
    width:100%;
    padding:12px;
    border:none;
    border-radius:8px;
    background:#2c5364;
    color:#fff;
    font-size:15px;
    cursor:pointer;
    transition:0.3s;
}

button:hover {
    background:#1e3c50;
}

.error {
    background:#ffdddd;
    padding:10px;
    border-radius:6px;
    margin-bottom:15px;
    font-size:13px;
    color:#b30000;
}

.strength {
    font-size:12px;
    margin-bottom:15px;
}
</style>
</head>

<body>

<div class="container">
    <h2>Create Account</h2>

    <?php if (!empty($errors)): ?>
        <div class="error">
            <?= implode("<br>", array_map('htmlspecialchars', $errors)) ?>
        </div>
    <?php endif; ?>

    <form method="POST" id="registerForm">
        <input type="text" name="username" placeholder="Username" required>
        <input type="email" name="email" placeholder="Email Address" required>
        <input type="password" name="password" id="password" placeholder="Password" required>
        <div class="strength" id="strengthText"></div>
        <input type="text" name="site_name" placeholder="Website Name" required>
        <input type="text" name="domain" placeholder="example.com" required>
        <button type="submit">Create Account</button>
    </form>
</div>

<script>
const passwordInput = document.getElementById("password");
const strengthText = document.getElementById("strengthText");

passwordInput.addEventListener("input", function() {
    const val = passwordInput.value;
    let strength = 0;

    if (val.length >= 6) strength++;
    if (/[A-Z]/.test(val)) strength++;
    if (/[0-9]/.test(val)) strength++;
    if (/[^A-Za-z0-9]/.test(val)) strength++;

    let message = "";
    let color = "red";

    if (strength <= 1) {
        message = "Weak password";
        color = "red";
    } else if (strength == 2) {
        message = "Medium strength";
        color = "orange";
    } else if (strength >= 3) {
        message = "Strong password";
        color = "green";
    }

    strengthText.textContent = message;
    strengthText.style.color = color;
});
</script>

</body>
</html>
