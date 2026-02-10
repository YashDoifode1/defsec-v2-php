<?php
// admin_login.php

// DEBUG MODE (TURN OFF IN PRODUCTION)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Log errors to file
ini_set("log_errors", 1);
ini_set("error_log", __DIR__ . "/debug.log");

require_once 'includes/config.php';
require_once 'includes/admin_auth.php';

// session_start(); // Make sure session starts

$error_msg = '';
$success_msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    error_log("Login attempt started");

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    error_log("Email entered: " . $email);

    if (empty($email) || empty($password)) {
        $error_msg = "Email and password are required.";
        error_log("Validation failed: Empty fields");
    } else {

        if (!isset($admin_auth)) {
            error_log("ERROR: \$admin_auth is not set!");
            $error_msg = "System error. Contact administrator.";
        } else {

            error_log("Calling admin_auth->login()");

            $login_result = $admin_auth->login($email, $password);

            error_log("Login result: " . var_export($login_result, true));

            if ($login_result) {
                error_log("Login successful. Redirecting...");
                header("Location: admin_dashboard.php");
                exit();
            } else {
                error_log("Login failed.");
                $error_msg = "Invalid email or password, or you don't have admin privileges.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefSec Admin | Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --dark-bg: #121212;
            --darker-bg: #0a0a0a;
            --card-bg: #1e1e1e;
            --border-color: #2d2d2d;
        }
        
        body {
            background: linear-gradient(135deg, var(--darker-bg) 0%, var(--dark-bg) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding: 20px;
        }
        
        .login-container {
            max-width: 400px;
            margin: 0 auto;
            width: 100%;
        }
        
        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            padding: 2rem;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .login-header h2 {
            color: var(--primary-color);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .login-header p {
            color: var(--secondary-color);
            font-size: 0.9rem;
        }
        
        .form-control {
            background: var(--dark-bg);
            border: 1px solid var(--border-color);
            color: white;
            padding: 0.75rem 1rem;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            background: var(--dark-bg);
            border-color: var(--primary-color);
            color: white;
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color) 0%, #0b5ed7 100%);
            border: none;
            padding: 0.75rem;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(13, 110, 253, 0.4);
        }
        
        .alert {
            border: none;
            border-radius: 5px;
            padding: 0.75rem 1rem;
        }
        
        .login-footer {
            text-align: center;
            margin-top: 1.5rem;
            color: var(--secondary-color);
            font-size: 0.9rem;
        }
        
        .login-footer a {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        .login-footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <h2><i class="bi bi-shield-lock me-2"></i>DefSec Admin</h2>
                <p>Secure Administration Panel</p>
            </div>
            
            <?php if ($error_msg): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    <?= htmlspecialchars($error_msg) ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if ($success_msg): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="bi bi-check-circle-fill me-2"></i>
                    <?= htmlspecialchars($success_msg) ?>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="mb-3">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" class="form-control" id="email" name="email" required 
                           placeholder="admin@example.com">
                </div>
                
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-group">
                        <input type="password" class="form-control" id="password" name="password" required
                               placeholder="Enter your password">
                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword()">
                            <i class="bi bi-eye"></i>
                        </button>
                    </div>
                </div>
                
                <div class="d-grid mb-3">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                    </button>
                </div>
                
                <div class="form-check mb-3">
                    <input class="form-check-input" type="checkbox" id="remember" name="remember">
                    <label class="form-check-label" for="remember">
                        Remember me
                    </label>
                </div>
            </form>
            
            <div class="login-footer">
                <p class="mb-2">
                    <a href="../index.php"><i class="bi bi-arrow-left me-1"></i>Back to Main Site</a>
                </p>
                <p class="mb-0 text-muted small">
                    &copy; <?= date('Y') ?> DefSec. All rights reserved.
                </p>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleButton = document.querySelector('.btn-outline-secondary i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleButton.classList.remove('bi-eye');
                toggleButton.classList.add('bi-eye-slash');
            } else {
                passwordInput.type = 'password';
                toggleButton.classList.remove('bi-eye-slash');
                toggleButton.classList.add('bi-eye');
            }
        }
        
        // Focus on email field on page load
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('email').focus();
        });
    </script>
</body>
</html>