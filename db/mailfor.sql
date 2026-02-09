-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jan 28, 2026 at 12:54 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `mailfor`
--

-- --------------------------------------------------------

--
-- Table structure for table `access_logs`
--

CREATE TABLE `access_logs` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `referrer` text DEFAULT NULL,
  `request_uri` text DEFAULT NULL,
  `http_method` varchar(10) DEFAULT NULL,
  `query_string` text DEFAULT NULL,
  `session_id` varchar(128) DEFAULT NULL,
  `username` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `access_logs`
--

INSERT INTO `access_logs` (`id`, `ip_address`, `user_agent`, `referrer`, `request_uri`, `http_method`, `query_string`, `session_id`, `username`, `timestamp`) VALUES
(1, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/', 'GET', '', '', NULL, '2025-06-12 14:35:59'),
(2, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/', 'GET', '', '', NULL, '2025-06-12 14:37:42'),
(3, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/xss.php', 'GET', '', '', NULL, '2025-06-12 14:38:32'),
(4, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/xss.php', 'GET', '', '', NULL, '2025-06-12 14:40:55'),
(5, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/xss.php', 'GET', '', NULL, NULL, '2025-06-12 14:41:53'),
(6, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/', 'GET', '', NULL, NULL, '2025-06-12 21:52:46'),
(7, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', NULL, '/Defsec/sql.php', 'GET', '', NULL, NULL, '2025-06-12 21:53:35'),
(8, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/xss.php', 'GET', '', NULL, NULL, '2025-06-12 21:54:15'),
(9, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', NULL, '/Defsec/test.php', 'GET', '', NULL, NULL, '2025-06-12 21:54:25'),
(10, '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0', NULL, '/Defsec/test.php', 'GET', '', NULL, NULL, '2025-06-12 21:54:33'),

-- --------------------------------------------------------

--
-- Table structure for table `allowed_countries`
--

CREATE TABLE `allowed_countries` (
  `id` int(11) NOT NULL,
  `country_code` varchar(2) DEFAULT NULL,
  `country_name` varchar(100) DEFAULT NULL,
  `is_allowed` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `allowed_countries`
--

INSERT INTO `allowed_countries` (`id`, `country_code`, `country_name`, `is_allowed`) VALUES
(1, 'US', 'United States', 1),
(2, 'GB', 'United Kingdom', 0),
(3, 'CA', 'Canada', 0),
(4, 'DE', 'Germany', 0),
(5, 'CN', 'China', 0),
(6, 'RU', 'Russia', 0),
(7, 'IN', 'India', 1);

-- --------------------------------------------------------

--
-- Table structure for table `attack_logs`
--

CREATE TABLE `attack_logs` (
  `id` int(11) NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `attack_type` varchar(50) DEFAULT NULL,
  `severity` enum('Critical','High','Medium','Info') DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `attack_payload` text DEFAULT NULL,
  `request_url` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `attack_logs`
--

INSERT INTO `attack_logs` (`id`, `timestamp`, `attack_type`, `severity`, `ip_address`, `user_agent`, `attack_payload`, `request_url`) VALUES
(1, '2025-06-01 17:23:22', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'xss=<script>alert(\'hacked\')</script>', '/cyberhack/demo.php?xss=%3Cscript%3Ealert(%27hacked%27)%3C/script%3E'),
(2, '2025-06-01 17:39:27', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'xss=<script>alert(\'hacked\')</script>', '/Defsec/index.php?xss=%3Cscript%3Ealert(%27hacked%27)%3C/script%3E'),
(3, '2025-06-01 17:39:27', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api.php:53) in C:\\xampp\\htdocs\\Defsec\\security.php:133', '/Defsec/index.php?xss=%3Cscript%3Ealert(%27hacked%27)%3C/script%3E'),
(4, '2025-06-01 17:52:31', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'xss=<script>alert(\'hacked\')</script>', '/cyberhack/demo.php?xss=%3Cscript%3Ealert(%27hacked%27)%3C/script%3E'),
(5, '2025-06-01 18:29:26', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/Defsec/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(6, '2025-06-02 11:53:59', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:53) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/vulnerabilities/brute/'),
(7, '2025-06-02 11:57:00', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:53) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/index.php'),
(8, '2025-06-02 11:57:38', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:53) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/index.php'),
(9, '2025-06-02 12:01:31', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:193) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/index.php'),
(10, '2025-06-02 12:01:49', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:193) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/index.php'),
(11, '2025-06-02 12:02:49', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:693) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:607', '/dvwa/index.php'),
(12, '2025-06-02 12:06:13', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'ip=<script> alert(\'xss\')</script>', '/dvwa/vulnerabilities/exec/'),
(13, '2025-06-02 12:06:55', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'ip=<script> alert(\'xss\')</script>', '/dvwa/vulnerabilities/exec/'),
(14, '2025-06-02 12:08:20', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:193) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/vulnerabilities/exec/index.php'),
(15, '2025-06-02 12:08:34', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:193) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/vulnerabilities/exec/index.php'),
(16, '2025-06-02 12:12:27', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/vulnerabilities/exec/index.php'),
(17, '2025-06-02 12:12:36', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/vulnerabilities/exec/'),
(18, '2025-06-02 12:12:39', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:606', '/dvwa/index.php'),
(19, '2025-06-02 12:20:43', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:388', '/dvwa/index.php'),
(20, '2025-06-02 12:21:06', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:388', '/dvwa/index.php'),
(21, '2025-06-02 12:21:55', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:388', '/dvwa/index.php'),
(22, '2025-06-02 12:23:53', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/index.php'),
(23, '2025-06-02 12:24:24', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/vulnerabilities/brute/'),
(24, '2025-06-02 12:24:38', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(25, '2025-06-02 12:30:05', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(26, '2025-06-02 12:31:47', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(27, '2025-06-02 12:34:12', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(28, '2025-06-02 12:39:23', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(29, '2025-06-02 12:39:47', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(30, '2025-06-02 12:40:11', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(31, '2025-06-02 12:40:33', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(32, '2025-06-02 12:44:49', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:107) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:395', '/dvwa/'),
(33, '2025-06-02 14:33:51', 'XSS', 'High', '::1', 'Unknown', 'name=<script>alert(1)</script>', '/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>'),
(34, '2025-06-02 14:36:21', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/dvwa/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(35, '2025-06-02 14:37:21', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(36, '2025-06-02 14:46:38', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(37, '2025-06-02 14:48:19', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(38, '2025-06-02 14:48:50', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(39, '2025-06-02 15:48:46', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/dvwa/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(40, '2025-06-02 15:55:30', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/dvwa/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(41, '2025-06-02 15:57:02', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/dvwa/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(42, '2025-06-02 15:57:11', 'SQLi', 'Critical', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'user=\'UNION SELECT username,password FROM users--\"', '/dvwa/index.php?user=%27UNION%20SELECT%20username,password%20FROM%20users--%22'),
(43, '2025-06-02 18:18:27', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(44, '2025-06-02 18:18:38', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/vulnerabilities/brute/'),
(45, '2025-06-02 18:20:00', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(46, '2025-06-02 18:20:24', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(47, '2025-06-02 18:20:28', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(48, '2025-06-02 18:20:54', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:617', '/dvwa/'),
(49, '2025-06-02 18:21:26', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:617', '/dvwa/'),
(50, '2025-06-02 18:21:42', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:617', '/dvwa/logout.php'),
(51, '2025-06-02 18:21:59', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:617', '/dvwa/logout.php'),
(52, '2025-06-02 18:22:41', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(53, '2025-06-02 18:23:18', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(54, '2025-06-02 18:28:06', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/'),
(55, '2025-06-02 18:30:37', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(56, '2025-06-02 18:30:37', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(57, '2025-06-02 18:32:19', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(58, '2025-06-02 18:32:19', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\security.php:133', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(59, '2025-06-02 18:32:34', 'XSS', 'High', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'search=<script>alert(1)</script>\"', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(60, '2025-06-02 18:32:34', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\api.php:51) in C:\\xampp\\htdocs\\DVWA\\dvwa\\includes\\dvwaPage.inc.php:399', '/dvwa/index.php?search=%3Cscript%3Ealert(1)%3C/script%3E%22'),
(61, '2025-06-07 16:07:01', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Undefined array key \"block_vpn\" in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:42', '/Defsec/'),
(62, '2025-06-07 16:07:38', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Undefined array key \"block_vpn\" in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:42', '/Defsec/'),
(63, '2025-06-07 16:08:06', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Undefined array key \"block_vpn\" in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:42', '/Defsec/'),
(64, '2025-06-07 16:10:17', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api\\track.php:53) in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:5', '/Defsec/'),
(65, '2025-06-07 16:10:37', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api\\track.php:53) in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:5', '/Defsec/'),
(66, '2025-06-07 16:10:46', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api\\track.php:53) in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:5', '/Defsec/'),
(67, '2025-06-07 16:10:54', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api\\track.php:53) in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:5', '/Defsec/index.php'),
(68, '2025-06-07 16:16:02', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Cannot modify header information - headers already sent by (output started at C:\\xampp\\htdocs\\Defsec\\api\\track.php:53) in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:5', '/Defsec/index.php'),
(69, '2025-06-07 16:16:21', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Undefined array key \"block_vpn\" in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:42', '/Defsec/index.php'),
(70, '2025-06-07 16:17:43', 'PHP_Error', 'Medium', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', 'Undefined array key \"block_vpn\" in C:\\xampp\\htdocs\\Defsec\\api\\vpn.php:42', '/Defsec/index.php'),

-- --------------------------------------------------------

--
-- Table structure for table `blocked_ips`
--

CREATE TABLE `blocked_ips` (
  `id` int(11) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `reason` varchar(255) DEFAULT 'Abuse',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expiry_time` time NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `cases`
--

-- Dumping data for table `email_analysis`
--

 --------------------------------------------------------

--
-- Table structure for table `email_breaches`
--

--
-- Dumping data for table `email_breaches`
--
- --------------------------------------------------------

--
-- Table structure for table `email_osint`
--


--
-- Dumping data for table `email_osint`
--


-- --------------------------------------------------------

--
-- Table structure for table `exif_data`
--


CREATE TABLE `logs` (
  `id` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip` varchar(45) NOT NULL,
  `real_ip` varchar(45) NOT NULL,
  `country` varchar(100) DEFAULT 'Unknown',
  `reverse_dns` varchar(255) DEFAULT 'Unknown',
  `webrtc_ip` varchar(45) DEFAULT 'Unknown',
  `dns_leak_ip` varchar(45) DEFAULT 'Unknown',
  `user_agent` text DEFAULT NULL,
  `screen_resolution` varchar(20) DEFAULT 'Unknown',
  `language` varchar(20) DEFAULT 'Unknown',
  `timezone` varchar(50) DEFAULT 'Unknown',
  `cookies_enabled` varchar(5) DEFAULT NULL,
  `cpu_cores` varchar(10) DEFAULT 'Unknown',
  `ram` varchar(10) DEFAULT 'Unknown',
  `gpu` varchar(100) DEFAULT 'Unknown',
  `battery` varchar(10) DEFAULT 'Unknown',
  `referrer` text DEFAULT NULL,
  `plugins` text DEFAULT NULL,
  `digital_dna` varchar(64) DEFAULT 'Unknown',
  `is_vpn` tinyint(1) DEFAULT 0,
  `is_tor` tinyint(1) DEFAULT 0,
  `is_proxy` tinyint(1) DEFAULT 0,
  `ASN` varchar(50) DEFAULT 'Unknown',
  `ISP` varchar(100) DEFAULT 'Unknown',
  `latitude` double DEFAULT NULL,
  `longitude` double DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `logs`
--

INSERT INTO `logs` (`id`, `timestamp`, `ip`, `real_ip`, `country`, `reverse_dns`, `webrtc_ip`, `dns_leak_ip`, `user_agent`, `screen_resolution`, `language`, `timezone`, `cookies_enabled`, `cpu_cores`, `ram`, `gpu`, `battery`, `referrer`, `plugins`, `digital_dna`, `is_vpn`, `is_tor`, `is_proxy`, `ASN`, `ISP`, `latitude`, `longitude`) VALUES
(1, '2025-05-30 10:05:54', '::1', '2401:4900:52f6:8edd:8597:3450:747:8c6e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.3.45', '96.7.128.175', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '52%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(2, '2025-05-30 10:31:27', '::1', '106.195.3.45', 'India', '106.195.3.45', '106.195.3.45', '23.192.228.84', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '44%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(3, '2025-05-30 10:36:17', '::1', '2401:4900:52f6:8edd:8597:3450:747:8c6e', 'India', 'LAPTOP-M124ARSB', '106.195.3.45', '96.7.128.198', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11-30.0.101.2079)', '43%', 'None', 'Microsoft Edge PDF Plugin, Microsoft Edge PDF Viewer, Native Client', '7136cd5fa0a9f5780c4a9bac29628a36da3f690a9624e6e47935af2039a37319', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(4, '2025-05-30 11:29:29', '::1', '2401:4900:52f6:8edd:8597:3450:747:8c6e', 'India', 'LAPTOP-M124ARSB', '106.195.3.45', '96.7.128.198', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '43%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(5, '2025-05-30 11:29:32', '::1', '2401:4900:52f6:8edd:8597:3450:747:8c6e', 'India', 'LAPTOP-M124ARSB', '106.195.3.45', '96.7.128.198', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '43%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(6, '2025-05-30 04:45:20', '::1', '92.184.105.0', 'France', 'pc-fra.fr', '92.184.105.0', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'fr-FR', 'Europe/Paris', '1', '8', '16 GB', 'NVIDIA GeForce GTX 1650', '89%', 'https://google.fr', 'PDF Viewer', 'abc123', 0, 0, 0, '12345', 'Orange', NULL, NULL),
(7, '2025-05-30 05:52:45', '::1', '45.33.32.156', 'USA', 'host-us.linode.com', '45.33.32.156', '1.1.1.1', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', '2560x1440', 'en-US', 'America/New_York', '1', '4', '8 GB', 'AMD Radeon Pro 560X', '67%', 'https://cnn.com', 'PDF Viewer, Flash', 'def456', 0, 1, 0, '63949', 'Linode', NULL, NULL),
(8, '2025-05-30 07:35:10', '::1', '103.21.244.0', 'India', 'broadband.airtel.in', '103.21.244.0', '8.8.4.4', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1366x768', 'en-IN', 'Asia/Kolkata', '1', '4', '8 GB', 'Intel HD Graphics 620', '42%', '', 'PDF Viewer', 'ghi789', 1, 0, 0, '45609', 'Airtel', NULL, NULL),
(9, '2025-05-30 09:03:17', '::1', '185.107.56.200', 'Germany', 'vpn-ger.de', '185.107.56.200', '9.9.9.9', 'Mozilla/5.0 (Linux; Android 11)', '1080x2340', 'de-DE', 'Europe/Berlin', '1', '8', '6 GB', 'Adreno 640', '35%', 'https://heise.de', 'Chrome PDF Viewer', 'jkl012', 1, 0, 1, '51167', 'Contabo', NULL, NULL),
(10, '2025-05-30 10:20:31', '::1', '202.40.130.0', 'Australia', 'adsl.oz.net', '202.40.130.0', '208.67.222.222', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'en-AU', 'Australia/Sydney', '1', '8', '16 GB', 'NVIDIA RTX 3060', '61%', 'https://abc.net.au', 'Chrome PDF Viewer', 'mno345', 0, 0, 0, '4809', 'Telstra', NULL, NULL),
(11, '2025-05-30 11:14:12', '::1', '200.89.75.20', 'Argentina', 'host.ar.com', '200.89.75.20', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1440x900', 'es-AR', 'America/Argentina/Buenos_Aires', '1', '2', '4 GB', 'Intel HD Graphics', '53%', '', 'PDF Viewer', 'pqr678', 0, 0, 0, '27885', 'Telecom Argentina', NULL, NULL),
(12, '2025-05-30 11:50:50', '::1', '203.0.113.5', 'Japan', 'ntt.jp', '203.0.113.5', '1.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'ja-JP', 'Asia/Tokyo', '1', '4', '8 GB', 'Intel UHD Graphics 620', '76%', 'https://yahoo.co.jp', 'PDF Viewer', 'stu901', 0, 0, 0, '7524', 'NTT', NULL, NULL),
(13, '2025-05-30 12:33:22', '::1', '41.74.178.130', 'South Africa', 'dsl.sa.co.za', '41.74.178.130', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1366x768', 'en-ZA', 'Africa/Johannesburg', '1', '2', '4 GB', 'Intel Graphics', '34%', '', 'PDF Viewer', 'vwx234', 1, 0, 1, '36953', 'MTN', NULL, NULL),
(14, '2025-05-30 13:30:00', '::1', '82.165.200.10', 'United Kingdom', 'dsl.uk.co', '82.165.200.10', '9.9.9.9', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1280x1024', 'en-GB', 'Europe/London', '1', '4', '8 GB', 'AMD Vega 8', '49%', '', 'PDF Viewer', 'yz1234', 0, 0, 0, '8560', 'BT Group', NULL, NULL),
(15, '2025-05-30 15:00:15', '::1', '190.15.30.15', 'Brazil', 'dsl.br.net', '190.15.30.15', '208.67.220.220', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1600x900', 'pt-BR', 'America/Sao_Paulo', '1', '4', '8 GB', 'Intel Iris Plus Graphics', '59%', 'https://globo.com', 'PDF Viewer', 'abc567', 0, 0, 0, '53112', 'Claro', NULL, NULL),
(16, '2025-05-30 04:45:20', '::1', '92.184.105.0', 'France', 'pc-fra.fr', '92.184.105.0', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'fr-FR', 'Europe/Paris', '1', '8', '16 GB', 'NVIDIA GeForce GTX 1650', '89%', 'https://google.fr', 'PDF Viewer', 'abc123', 0, 0, 0, '12345', 'Orange', NULL, NULL),
(17, '2025-05-30 05:52:45', '::1', '45.33.32.156', 'USA', 'host-us.linode.com', '45.33.32.156', '1.1.1.1', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', '2560x1440', 'en-US', 'America/New_York', '1', '4', '8 GB', 'AMD Radeon Pro 560X', '67%', 'https://cnn.com', 'PDF Viewer, Flash', 'def456', 0, 1, 0, '63949', 'Linode', NULL, NULL),
(18, '2025-05-30 07:35:10', '::1', '103.21.244.0', 'India', 'broadband.airtel.in', '103.21.244.0', '8.8.4.4', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1366x768', 'en-IN', 'Asia/Kolkata', '1', '4', '8 GB', 'Intel HD Graphics 620', '42%', '', 'PDF Viewer', 'ghi789', 1, 0, 0, '45609', 'Airtel', NULL, NULL),
(19, '2025-05-30 09:03:17', '::1', '185.107.56.200', 'Germany', 'vpn-ger.de', '185.107.56.200', '9.9.9.9', 'Mozilla/5.0 (Linux; Android 11)', '1080x2340', 'de-DE', 'Europe/Berlin', '1', '8', '6 GB', 'Adreno 640', '35%', 'https://heise.de', 'Chrome PDF Viewer', 'jkl012', 1, 0, 1, '51167', 'Contabo', NULL, NULL),
(20, '2025-05-30 10:20:31', '::1', '202.40.130.0', 'Australia', 'adsl.oz.net', '202.40.130.0', '208.67.222.222', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'en-AU', 'Australia/Sydney', '1', '8', '16 GB', 'NVIDIA RTX 3060', '61%', 'https://abc.net.au', 'Chrome PDF Viewer', 'mno345', 0, 0, 0, '4809', 'Telstra', NULL, NULL),
(21, '2025-05-30 11:14:12', '::1', '200.89.75.20', 'Argentina', 'host.ar.com', '200.89.75.20', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1440x900', 'es-AR', 'America/Argentina/Buenos_Aires', '1', '2', '4 GB', 'Intel HD Graphics', '53%', '', 'PDF Viewer', 'pqr678', 0, 0, 0, '27885', 'Telecom Argentina', NULL, NULL),
(22, '2025-05-30 11:50:50', '::1', '203.0.113.5', 'Japan', 'ntt.jp', '203.0.113.5', '1.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1920x1080', 'ja-JP', 'Asia/Tokyo', '1', '4', '8 GB', 'Intel UHD Graphics 620', '76%', 'https://yahoo.co.jp', 'PDF Viewer', 'stu901', 0, 0, 0, '7524', 'NTT', NULL, NULL),
(23, '2025-05-30 12:33:22', '::1', '41.74.178.130', 'South Africa', 'dsl.sa.co.za', '41.74.178.130', '8.8.8.8', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1366x768', 'en-ZA', 'Africa/Johannesburg', '1', '2', '4 GB', 'Intel Graphics', '34%', '', 'PDF Viewer', 'vwx234', 1, 0, 1, '36953', 'MTN', NULL, NULL),
(24, '2025-05-30 13:30:00', '::1', '82.165.200.10', 'United Kingdom', 'dsl.uk.co', '82.165.200.10', '9.9.9.9', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1280x1024', 'en-GB', 'Europe/London', '1', '4', '8 GB', 'AMD Vega 8', '49%', '', 'PDF Viewer', 'yz1234', 0, 0, 0, '8560', 'BT Group', NULL, NULL),
(25, '2025-05-30 15:00:15', '::1', '190.15.30.15', 'Brazil', 'dsl.br.net', '190.15.30.15', '208.67.220.220', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '1600x900', 'pt-BR', 'America/Sao_Paulo', '1', '4', '8 GB', 'Intel Iris Plus Graphics', '59%', 'https://globo.com', 'PDF Viewer', 'abc567', 0, 0, 0, '53112', 'Claro', NULL, NULL),
(26, '2025-06-01 06:51:49', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '23.215.0.136', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '38%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(27, '2025-06-01 06:53:12', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.175', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '38%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(28, '2025-06-01 06:54:07', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.198', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '37%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(29, '2025-06-01 06:54:10', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '23.192.228.84', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '37%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(30, '2025-06-01 06:56:36', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.175', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '37%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(31, '2025-06-01 06:57:42', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '23.192.228.84', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '36%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(32, '2025-06-01 06:58:04', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.198', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '36%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(33, '2025-06-01 06:58:36', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.175', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '36%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),
(34, '2025-06-01 07:13:39', '::1', '2401:4900:52f0:57ab:584:de30:56e1:b25e', 'Unknown', 'LAPTOP-M124ARSB', '106.195.11.164', '96.7.128.175', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '1536x864', 'en-US', 'Asia/Calcutta', 'Yes', '4', '8 GB', 'ANGLE (Intel, Intel(R) UHD Graphics (0x00008A56) Direct3D11 vs_5_0 ps_5_0, D3D11)', '38%', 'None', 'PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF', '006ce45425ffb26a9ac9be0ba4638ccab31a9359e77c10b965ed0c3f7b741ae7', 0, 0, 0, '45609', 'Airtel', NULL, NULL),

-- --------------------------------------------------------

--
-- Table structure for table `osint_results`
--


--
-- Table structure for table `settings`
--

CREATE TABLE `settings` (
  `id` int(11) NOT NULL,
  `setting_name` varchar(50) DEFAULT NULL,
  `setting_value` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `settings`
--

INSERT INTO `settings` (`id`, `setting_name`, `setting_value`) VALUES
(1, 'block_vpn', '0'),
(2, 'strict_mode', '0');

-- --------------------------------------------------------

--
-- Table structure for table `user2`
--

CREATE TABLE `user2` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `full_name` varchar(100) DEFAULT NULL,
  `role` enum('admin','analyst','viewer') DEFAULT 'viewer',
  `last_login` datetime DEFAULT NULL,
  `login_attempts` int(11) DEFAULT 0,
  `last_attempt` datetime DEFAULT NULL,
  `is_locked` tinyint(1) DEFAULT 0,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user2`
--

INSERT INTO `user2` (`id`, `username`, `email`, `password_hash`, `full_name`, `role`, `last_login`, `login_attempts`, `last_attempt`, `is_locked`, `created_at`, `updated_at`) VALUES
(1, 'admin', 'admin@defsec.local', '$2y$10$vJ9HEmEvq/W0ME8kaUp2XO22iBS08YloH/SchhoUw/cHfaAdPznw.', 'Administrator', 'admin', NULL, 0, NULL, 0, '2025-06-06 14:40:35', '2025-09-22 14:44:27'),
(2, 'yashdoifode', 'skidde7@gmail.com', '$2y$12$EjyXtL9O/GFsDR9/ILjGfOBKqACx1ULfBQPAUl0tZexyZUnS8JafK', 'Yash DOIFODE', 'admin', '2025-09-27 16:26:51', 0, NULL, 0, '2025-06-06 14:50:34', '2025-09-27 16:26:51');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--


-- Indexes for dumped tables
--

--
-- Indexes for table `access_logs`
--
ALTER TABLE `access_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `allowed_countries`
--
ALTER TABLE `allowed_countries`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `country_code` (`country_code`);

--
-- Indexes for table `attack_logs`
--
ALTER TABLE `attack_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `blocked_ips`
--
ALTER TABLE `blocked_ips`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_ip` (`ip`);

--
-- Indexes for table `cases`
--

--
-- Indexes for table `logs`
--
ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `ip` (`ip`),
  ADD KEY `real_ip` (`real_ip`),
  ADD KEY `country` (`country`),
  ADD KEY `digital_dna` (`digital_dna`),
  ADD KEY `timestamp` (`timestamp`);

--
-- Indexes for table `osint_results`

--
-- Indexes for table `settings`
--
ALTER TABLE `settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_name` (`setting_name`);

--
-- Indexes for table `user2`
--
ALTER TABLE `user2`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `users`
--

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `access_logs`
--
ALTER TABLE `access_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `allowed_countries`
--
ALTER TABLE `allowed_countries`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `attack_logs`
--
ALTER TABLE `attack_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=192;

--
-- AUTO_INCREMENT for table `blocked_ips`
--
ALTER TABLE `blocked_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=31;

--
-- AUTO_INCREMENT for table `cases`
--

-- AUTO_INCREMENT for table `logs`
--
ALTER TABLE `logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=238;

--
-- AUTO_INCREMENT for table `osint_results`
--

--
-- AUTO_INCREMENT for table `settings`
--
ALTER TABLE `settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `user2`
--
ALTER TABLE `user2`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `users`
--

--
