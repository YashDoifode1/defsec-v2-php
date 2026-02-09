<?php
// includes/db.php

require_once __DIR__ . '/config.php';

class Database {
    private $pdo;
    
    public function __construct() {
        try {
            $dsn = 'mysql:host=' . DB_HOST . 
                   ';dbname=' . DB_NAME . 
                   ';charset=utf8mb4';

            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_TIMEOUT => 5
            ]);

        } catch (PDOException $e) {
            error_log("Database connection error: " . $e->getMessage());
            die("Service temporarily unavailable.");
        }
    }
    
    public function getConnection() {
        return $this->pdo;
    }
    
    public function query($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
    
    public function fetch($sql, $params = []) {
        return $this->query($sql, $params)->fetch();
    }
    
    public function fetchAll($sql, $params = []) {
        return $this->query($sql, $params)->fetchAll();
    }
    
    public function insert($table, $data) {
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));

        $sql = "INSERT INTO {$table} ({$columns}) VALUES ({$placeholders})";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($data);

        return $this->pdo->lastInsertId();
    }
    
    public function update($table, $data, $where, $whereParams = []) {
        $set = [];
        foreach ($data as $column => $value) {
            $set[] = "{$column} = :{$column}";
        }

        $sql = "UPDATE {$table} SET " . implode(', ', $set) . " WHERE {$where}";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute(array_merge($data, $whereParams));
    }
    
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }
}

// Create database instance
$database = new Database();
$pdo = $database->getConnection();
