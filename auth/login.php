<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identifier = trim($_POST['identifier'] ?? '');
    $password   = $_POST['password'] ?? '';

    if (empty($identifier) || empty($password)) {
        $errors[] = "Please enter your username/email and password.";
    } else {
        try {
            // Check if user exists
            $stmt = $pdo->prepare("
                SELECT * FROM users 
                WHERE username = ? OR email = ?
                LIMIT 1
            ");
            $stmt->execute([$identifier, $identifier]);
            $user = $stmt->fetch();

            if (!$user) {
                throw new Exception("Invalid credentials.");
            }

            // Check account status - note: using correct column names
            // Adjust based on your actual database schema
            if (isset($user['status']) && $user['status'] !== 'active') {
                throw new Exception("Account is not active.");
            }
            
            if (isset($user['is_locked']) && $user['is_locked']) {
                throw new Exception("Account is locked.");
            }

            // Verify password - check column name
            $password_column = isset($user['password_hash']) ? 'password_hash' : 'password';
            if (!password_verify($password, $user[$password_column])) {
                throw new Exception("Invalid credentials.");
            }

            // Get website for this user
            $stmt = $pdo->prepare("
                SELECT id FROM websites 
                WHERE user_id = ?
                LIMIT 1
            ");
            $stmt->execute([$user['id']]);
            $website = $stmt->fetch();

            // If no website found, create a default one or use fallback
            $website_id = 1; // Default fallback
            if ($website && isset($website['id'])) {
                $website_id = $website['id'];
            }

            // Regenerate session ID for security
            session_regenerate_id(true);

            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'] ?? $identifier;
            $_SESSION['email'] = $user['email'] ?? '';
            $_SESSION['role'] = $user['role'] ?? 'user';
            $_SESSION['website_id'] = $website_id;
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();

            // Update last login
            $updateStmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $updateStmt->execute([$user['id']]);

            // Redirect to dashboard
            header("Location: ../Pages/security-dashboard.php");
            exit();

        } catch (Exception $e) {
            $errors[] = htmlspecialchars($e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - <?= htmlspecialchars(APP_NAME) ?></title>
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
        
        .login-container {
            background: rgba(30, 30, 30, 0.95);
            padding: 40px;
            border-radius: 14px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h2 {
            color: #ffffff;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .login-header p {
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
        
        .btn-login {
            background: linear-gradient(135deg, var(--primary-color), #0b5ed7);
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            width: 100%;
        }
        
        .btn-login:hover {
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
        
        .login-footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .login-footer a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .login-footer a:hover {
            color: #0b5ed7;
            text-decoration: underline;
        }
        
        .form-label {
            color: #adb5bd;
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .form-check-label {
            color: #adb5bd;
            font-size: 0.9rem;
        }
        
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
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
    </style>
</head>
<body>
    <div class="login-container fade-in">
        <div class="login-header">
            <div class="brand-logo">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h2>DefSec Security</h2>
            <p>Sign in to your security dashboard</p>
        </div>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger mb-4">
                <i class="fas fa-exclamation-circle me-2"></i>
                <?= implode("<br>", $errors) ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
            <div class="mb-3">
                <label for="identifier" class="form-label">Username or Email</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-user"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        id="identifier" 
                        name="identifier" 
                        placeholder="Enter username or email"
                        value="<?= htmlspecialchars($_POST['identifier'] ?? '') ?>"
                        required
                        autofocus
                    >
                </div>
            </div>
            
            <div class="mb-4">
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
                        placeholder="Enter password"
                        required
                    >
                    <button type="button" class="input-group-text password-toggle" id="togglePassword">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <div class="mb-4">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="rememberMe" name="remember_me">
                    <label class="form-check-label" for="rememberMe">
                        Remember me
                    </label>
                </div>
            </div>
            
            <button type="submit" class="btn btn-login mb-3">
                <i class="fas fa-sign-in-alt me-2"></i> Sign In
            </button>
            
            <div class="text-center mb-3">
                <a href="forgot-password.php" class="text-decoration-none">
                    <small>Forgot password?</small>
                </a>
            </div>
        </form>
        
        <div class="login-footer">
            Don't have an account? 
            <a href="register.php" class="ms-1">Create one now</a>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Toggle password visibility
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
        
        // Focus on first input field
        document.getElementById('identifier').focus();
        
        // Form validation
        document.querySelector('form').addEventListener('submit', function(e) {
            const identifier = document.getElementById('identifier').value.trim();
            const password = document.getElementById('password').value.trim();
            
            if (!identifier || !password) {
                e.preventDefault();
                alert('Please fill in all required fields.');
            }
        });
        
        // Enter key submits form
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
                const focused = document.activeElement;
                if (focused && (focused.type === 'text' || focused.type === 'password')) {
                    document.querySelector('form').submit();
                }
            }
        });
    </script>
</body>
</html>