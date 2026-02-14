<?php
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

$errors = [];

// Function to generate a unique API key
function generateApiKey($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

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

            // Check if username or email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username=? OR email=?");
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) throw new Exception("Username or email already exists.");

            // Check if domain already registered
            $stmt = $pdo->prepare("SELECT id FROM websites WHERE domain=?");
            $stmt->execute([$domain]);
            if ($stmt->fetch()) throw new Exception("Domain already registered.");

            // Generate unique API key
            $apiKey = generateApiKey(64);
            
            // Make sure API key is unique
            $stmt = $pdo->prepare("SELECT id FROM users WHERE api_key = ?");
            $stmt->execute([$apiKey]);
            while ($stmt->fetch()) {
                $apiKey = generateApiKey(64);
                $stmt->execute([$apiKey]);
            }

            $passwordHash = password_hash($password, PASSWORD_DEFAULT, [
                'cost' => PASSWORD_HASH_COST
            ]);

            // Insert user with all fields including api_key
            $stmt = $pdo->prepare("
                INSERT INTO users (
                    username, 
                    email, 
                    password_hash, 
                    api_key,
                    full_name,
                    role, 
                    status, 
                    login_attempts,
                    is_locked,
                    created_at,
                    updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    'admin', 'active', 0, 0,
                    NOW(), NOW()
                )
            ");
            $stmt->execute([
                $username,
                $email,
                $passwordHash,
                $apiKey,
                $username // Using username as full_name initially, can be updated later
            ]);
            $userId = $pdo->lastInsertId();

            // Insert website
            $stmt = $pdo->prepare("
                INSERT INTO websites (user_id, site_name, domain, status, created_at)
                VALUES (?, ?, ?, 'active', NOW())
            ");
            $stmt->execute([$userId, $site_name, $domain]);
            $websiteId = $pdo->lastInsertId();

            $pdo->commit();

            // Set session variables
            session_regenerate_id(true);
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $username;
            $_SESSION['email'] = $email;
            $_SESSION['role'] = 'admin';
            $_SESSION['website_id'] = $websiteId;
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();

            // Optional: Store API key in session if needed for API calls
            $_SESSION['api_key'] = $apiKey;

            // Redirect to dashboard
            header("Location: ../Pages/security-dashboard.php");
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
    <title>Register - <?= htmlspecialchars(APP_NAME) ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #6c757d;
            --dark-color: #121212;
            --light-color: #f8f9fa;
        }
        
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #141e30, #243b55);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .register-container {
            background: rgba(30, 30, 30, 0.95);
            padding: 40px;
            border-radius: 14px;
            width: 100%;
            max-width: 450px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }
        
        .register-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .register-header h2 {
            color: #ffffff;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .register-header p {
            color: #adb5bd;
            font-size: 0.9rem;
        }
        
        .brand-logo {
            font-size: 2.5rem;
            color: var(--primary-color);
            margin-bottom: 15px;
        }
        
        .form-control {
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #ffffff;
            padding: 12px 15px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            background-color: rgba(255, 255, 255, 0.1);
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
            color: #ffffff;
        }
        
        .form-control::placeholder {
            color: #6c757d;
        }
        
        .input-group-text {
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #6c757d;
            border-right: none;
        }
        
        .password-toggle {
            background-color: transparent;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-left: none;
            color: #6c757d;
            cursor: pointer;
            transition: color 0.3s;
        }
        
        .password-toggle:hover {
            color: var(--primary-color);
        }
        
        .btn-register {
            background: linear-gradient(135deg, var(--primary-color), #0b5ed7);
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            width: 100%;
            color: white;
        }
        
        .btn-register:hover {
            background: linear-gradient(135deg, #0b5ed7, #0a58ca);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(13, 110, 253, 0.4);
        }
        
        .alert-danger {
            background-color: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.2);
            color: #f8d7da;
            border-radius: 8px;
        }
        
        .alert-success {
            background-color: rgba(25, 135, 84, 0.1);
            border: 1px solid rgba(25, 135, 84, 0.2);
            color: #d1e7dd;
            border-radius: 8px;
        }
        
        .alert-info {
            background-color: rgba(13, 110, 253, 0.1);
            border: 1px solid rgba(13, 110, 253, 0.2);
            color: #cfe2ff;
            border-radius: 8px;
        }
        
        .register-footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .register-footer a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .register-footer a:hover {
            color: #0b5ed7;
            text-decoration: underline;
        }
        
        .form-label {
            color: #adb5bd;
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .strength-meter {
            font-size: 0.8rem;
            margin-top: 5px;
            padding: 5px;
            border-radius: 4px;
            transition: all 0.3s;
        }
        
        .strength-weak {
            color: #dc3545;
        }
        
        .strength-medium {
            color: #ffc107;
        }
        
        .strength-strong {
            color: #28a745;
        }
        
        .strength-very-strong {
            color: #20c997;
        }
        
        .password-requirements {
            font-size: 0.75rem;
            color: #6c757d;
            margin-top: 5px;
            padding-left: 5px;
        }
        
        .requirement-met {
            color: #28a745;
        }
        
        .requirement-unmet {
            color: #6c757d;
        }
        
        /* Animation */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease-out;
        }
        
        /* Domain input helper */
        .domain-helper {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
            font-size: 0.8rem;
            pointer-events: none;
        }
        
        .position-relative {
            position: relative;
        }
        
        /* API Key preview (hidden) */
        .api-key-preview {
            background-color: rgba(0, 0, 0, 0.3);
            border: 1px dashed var(--primary-color);
            border-radius: 8px;
            padding: 10px;
            margin-top: 10px;
            display: none;
        }
        
        .api-key-preview.show {
            display: block;
        }
        
        .api-key-value {
            font-family: monospace;
            font-size: 0.8rem;
            word-break: break-all;
            background-color: rgba(255, 255, 255, 0.05);
            padding: 8px;
            border-radius: 4px;
            color: #0d6efd;
        }
    </style>
</head>
<body>
    <div class="register-container fade-in">
        <div class="register-header">
            <div class="brand-logo">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h2>Create Account</h2>
            <p>Join DefSec Security Platform</p>
        </div>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger mb-4">
                <i class="fas fa-exclamation-circle me-2"></i>
                <?= implode("<br>", array_map('htmlspecialchars', $errors)) ?>
            </div>
        <?php endif; ?>
        
        <div class="alert alert-info mb-4">
            <i class="fas fa-key me-2"></i>
            <small>Your API key will be automatically generated upon registration.</small>
        </div>
        
        <form method="POST" id="registerForm">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-user"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        id="username" 
                        name="username" 
                        placeholder="Choose a username"
                        value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                        required
                        minlength="3"
                        autofocus
                    >
                </div>
                <small class="text-muted">Minimum 3 characters</small>
            </div>
            
            <div class="mb-3">
                <label for="email" class="form-label">Email Address</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-envelope"></i>
                    </span>
                    <input 
                        type="email" 
                        class="form-control" 
                        id="email" 
                        name="email" 
                        placeholder="Enter your email"
                        value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                        required
                    >
                </div>
            </div>
            
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-lock"></i>
                    </span>
                    <input 
                        type="password" 
                        class="form-control" 
                        id="password" 
                        name="password" 
                        placeholder="Create a password"
                        required
                        minlength="6"
                    >
                    <button type="button" class="input-group-text password-toggle" id="togglePassword">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <div id="strengthText" class="strength-meter"></div>
                <div class="password-requirements">
                    <div id="lengthCheck"><i class="fas fa-circle me-1"></i> At least 6 characters</div>
                    <div id="uppercaseCheck"><i class="fas fa-circle me-1"></i> At least 1 uppercase letter</div>
                    <div id="numberCheck"><i class="fas fa-circle me-1"></i> At least 1 number</div>
                    <div id="specialCheck"><i class="fas fa-circle me-1"></i> At least 1 special character</div>
                </div>
            </div>
            
            <div class="mb-3">
                <label for="site_name" class="form-label">Website Name</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-globe"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        id="site_name" 
                        name="site_name" 
                        placeholder="e.g., My Business Website"
                        value="<?= htmlspecialchars($_POST['site_name'] ?? '') ?>"
                        required
                    >
                </div>
            </div>
            
            <div class="mb-4">
                <label for="domain" class="form-label">Domain</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-link"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        id="domain" 
                        name="domain" 
                        placeholder="example.com"
                        value="<?= htmlspecialchars($_POST['domain'] ?? '') ?>"
                        required
                        pattern="[a-z0-9.-]+"
                        title="Only lowercase letters, numbers, dots, and hyphens"
                    >
                </div>
                <small class="text-muted">Enter your domain (e.g., example.com)</small>
            </div>
            
            <div class="mb-4">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="termsAgree" name="terms_agree" required>
                    <label class="form-check-label" for="termsAgree">
                        I agree to the <a href="#" class="text-primary">Terms of Service</a> and 
                        <a href="#" class="text-primary">Privacy Policy</a>
                    </label>
                </div>
            </div>
            
            <!-- Hidden API Key Preview (for demonstration, will be generated server-side) -->
            <div class="api-key-preview" id="apiKeyPreview">
                <small class="text-muted d-block mb-2">
                    <i class="fas fa-key me-1"></i>Your API key will be:
                </small>
                <div class="api-key-value" id="demoApiKey">
                    [Generated on server]
                </div>
                <small class="text-muted mt-2 d-block">
                    This key will be used for API authentication. Keep it secure!
                </small>
            </div>
            
            <button type="submit" class="btn btn-register mb-3" id="submitBtn">
                <i class="fas fa-user-plus me-2"></i> Create Account
            </button>
        </form>
        
        <div class="register-footer">
            Already have an account? 
            <a href="login.php" class="ms-1">Sign in</a>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Password visibility toggle
        document.getElementById('togglePassword').addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });

        // Password strength checker and requirements
        const passwordInput = document.getElementById("password");
        const strengthText = document.getElementById("strengthText");
        const lengthCheck = document.getElementById("lengthCheck");
        const uppercaseCheck = document.getElementById("uppercaseCheck");
        const numberCheck = document.getElementById("numberCheck");
        const specialCheck = document.getElementById("specialCheck");
        const submitBtn = document.getElementById("submitBtn");
        const apiKeyPreview = document.getElementById("apiKeyPreview");

        function checkPasswordStrength() {
            const val = passwordInput.value;
            
            // Check requirements
            const hasLength = val.length >= 6;
            const hasUppercase = /[A-Z]/.test(val);
            const hasNumber = /[0-9]/.test(val);
            const hasSpecial = /[^A-Za-z0-9]/.test(val);
            
            // Update requirement indicators
            lengthCheck.innerHTML = hasLength ? 
                '<i class="fas fa-check-circle me-1 text-success"></i> At least 6 characters' : 
                '<i class="fas fa-circle me-1"></i> At least 6 characters';
            
            uppercaseCheck.innerHTML = hasUppercase ? 
                '<i class="fas fa-check-circle me-1 text-success"></i> At least 1 uppercase letter' : 
                '<i class="fas fa-circle me-1"></i> At least 1 uppercase letter';
            
            numberCheck.innerHTML = hasNumber ? 
                '<i class="fas fa-check-circle me-1 text-success"></i> At least 1 number' : 
                '<i class="fas fa-circle me-1"></i> At least 1 number';
            
            specialCheck.innerHTML = hasSpecial ? 
                '<i class="fas fa-check-circle me-1 text-success"></i> At least 1 special character' : 
                '<i class="fas fa-circle me-1"></i> At least 1 special character';
            
            // Calculate strength
            let strength = 0;
            if (hasLength) strength++;
            if (hasUppercase) strength++;
            if (hasNumber) strength++;
            if (hasSpecial) strength++;

            let message = "";
            let className = "";

            if (val.length === 0) {
                message = "";
                className = "";
            } else if (strength <= 1) {
                message = "Weak password";
                className = "strength-weak";
            } else if (strength == 2) {
                message = "Medium password";
                className = "strength-medium";
            } else if (strength == 3) {
                message = "Strong password";
                className = "strength-strong";
            } else if (strength >= 4) {
                message = "Very strong password";
                className = "strength-very-strong";
            }

            strengthText.textContent = message;
            strengthText.className = "strength-meter " + className;
        }

        passwordInput.addEventListener("input", checkPasswordStrength);

        // Show API key preview on form interaction
        function showApiKeyPreview() {
            apiKeyPreview.classList.add('show');
        }

        // Show preview when user focuses on any important field
        document.getElementById('username').addEventListener('focus', showApiKeyPreview);
        document.getElementById('email').addEventListener('focus', showApiKeyPreview);
        document.getElementById('password').addEventListener('focus', showApiKeyPreview);

        // Form validation
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const siteName = document.getElementById('site_name').value.trim();
            const domain = document.getElementById('domain').value.trim();
            const termsAgree = document.getElementById('termsAgree').checked;
            
            let errors = [];
            
            if (username.length < 3) {
                errors.push("Username must be at least 3 characters");
            }
            
            if (!email.includes('@') || !email.includes('.')) {
                errors.push("Please enter a valid email address");
            }
            
            if (password.length < 6) {
                errors.push("Password must be at least 6 characters");
            }
            
            if (!siteName) {
                errors.push("Website name is required");
            }
            
            if (!domain.match(/^[a-z0-9.-]+$/)) {
                errors.push("Domain contains invalid characters");
            }
            
            if (!termsAgree) {
                errors.push("You must agree to the Terms of Service");
            }
            
            if (errors.length > 0) {
                e.preventDefault();
                alert('Please fix the following errors:\n\n' + errors.join('\n'));
            }
        });

        // Focus on first input field
        document.getElementById('username').focus();

        // Enter key submits form
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
                const focused = document.activeElement;
                if (focused && focused.type !== 'submit') {
                    e.preventDefault();
                    document.querySelector('form').submit();
                }
            }
        });

        // Domain input formatting
        document.getElementById('domain').addEventListener('input', function() {
            this.value = this.value.toLowerCase().replace(/[^a-z0-9.-]/g, '');
        });

        // Password match with login page theme
        const style = document.createElement('style');
        style.textContent = `
            .text-primary {
                color: var(--primary-color) !important;
            }
            .text-primary:hover {
                color: #0b5ed7 !important;
            }
            .form-check-input:checked {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
            }
            .form-check-input:focus {
                border-color: var(--primary-color);
                box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
            }
            .btn-register:disabled {
                opacity: 0.65;
                cursor: not-allowed;
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>