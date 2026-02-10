<?php
// includes/admin_auth.php
session_start();

class AdminAuth {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    public function isAdminLoggedIn() {
        return isset($_SESSION['admin_id']) && isset($_SESSION['admin_role']) && $_SESSION['admin_role'] === 'superadmin';
    }
    
    public function requireAdminLogin() {
        if (!$this->isAdminLoggedIn()) {
            header("Location: admin_login.php");
            exit();
        }
    }
    
    public function login($email, $password) {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ? AND role IN ('admin', 'superadmin') AND status = 'active'");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password_hash'])) {
                $_SESSION['admin_id'] = $user['id'];
                $_SESSION['admin_email'] = $user['email'];
                $_SESSION['admin_role'] = $user['role'];
                $_SESSION['admin_name'] = $user['full_name'] ?? $user['username'];
                
                // Update last login
                $stmt = $this->pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $stmt->execute([$user['id']]);
                
                return true;
            }
            return false;
        } catch (PDOException $e) {
            error_log("Admin login error: " . $e->getMessage());
            return false;
        }
    }
    
    public function logout() {
        session_destroy();
        header("Location: admin_login.php");
        exit();
    }
    
    public function getAdminId() {
        return $_SESSION['admin_id'] ?? null;
    }
    
    public function getAdminRole() {
        return $_SESSION['admin_role'] ?? null;
    }
    
    public function isSuperAdmin() {
        return $this->getAdminRole() === 'superadmin';
    }
}

// Create admin_auth instance
require_once 'config.php';
$admin_auth = new AdminAuth($pdo);
?>