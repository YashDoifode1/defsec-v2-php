<?php
// includes/auth.php

class Auth {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
        // session_start();
    }
    
    // Check if user is logged in
    public function isLoggedIn() {
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    // Login user
    public function login($username, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password'])) {
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'] ?? 'user';
                $_SESSION['website_id'] = $user['default_website_id'] ?? 1;
                
                // Update last login
                $updateStmt = $this->pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $updateStmt->execute([$user['id']]);
                
                return true;
            }
            return false;
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return false;
        }
    }
    
    // Logout user
    public function logout() {
        session_destroy();
        return true;
    }
    
    // Get current user ID
    public function getUserId() {
        return $_SESSION['user_id'] ?? null;
    }
    
    // Get current username
    public function getUsername() {
        return $_SESSION['username'] ?? null;
    }
    
    // Get current role
    public function getRole() {
        return $_SESSION['role'] ?? 'user';
    }
    
    // Check if user has permission
    public function hasPermission($permission) {
        $role = $this->getRole();
        
        // Define role permissions (you can expand this)
        $permissions = [
            'admin' => ['view_logs', 'manage_settings', 'block_ips', 'manage_users'],
            'user' => ['view_logs', 'block_ips']
        ];
        
        return isset($permissions[$role]) && in_array($permission, $permissions[$role]);
    }
    
    // Register new user
    public function register($username, $email, $password, $website_id = 1) {
        try {
            // Check if user already exists
            $checkStmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $checkStmt->execute([$username, $email]);
            
            if ($checkStmt->fetch()) {
                return ['success' => false, 'message' => 'Username or email already exists'];
            }
            
            // Hash password
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Insert new user
            $stmt = $this->pdo->prepare("
                INSERT INTO users (username, email, password, role, default_website_id, created_at)
                VALUES (?, ?, ?, 'user', ?, NOW())
            ");
            
            $stmt->execute([$username, $email, $hashedPassword, $website_id]);
            
            return ['success' => true, 'message' => 'Registration successful'];
        } catch (PDOException $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed'];
        }
    }
    
    // Update user profile
    public function updateProfile($userId, $data) {
        try {
            $updates = [];
            $params = [];
            
            if (isset($data['email'])) {
                $updates[] = "email = ?";
                $params[] = $data['email'];
            }
            
            if (isset($data['password']) && !empty($data['password'])) {
                $updates[] = "password = ?";
                $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
            }
            
            if (empty($updates)) {
                return false;
            }
            
            $params[] = $userId;
            $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
            $stmt = $this->pdo->prepare($sql);
            return $stmt->execute($params);
        } catch (PDOException $e) {
            error_log("Update profile error: " . $e->getMessage());
            return false;
        }
    }
}

// Initialize auth object
$auth = new Auth($pdo);
?>