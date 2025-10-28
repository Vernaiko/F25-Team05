-- ============================================================================
-- FAILED LOGIN ATTEMPTS TABLE
-- ============================================================================
-- This table logs all failed login attempts for security monitoring
-- Admins can view this data to identify potential security threats
-- ============================================================================

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    failure_reason VARCHAR(255),
    account_type VARCHAR(50),
    
    -- Indexes for performance
    INDEX idx_username (username),
    INDEX idx_attempted_at (attempted_at),
    INDEX idx_ip_address (ip_address)
);

-- Optional: Create a view for recent failed attempts
CREATE OR REPLACE VIEW recent_failed_logins AS
SELECT 
    attempt_id,
    username,
    attempted_at,
    ip_address,
    failure_reason,
    account_type,
    CASE 
        WHEN attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 'Last Hour'
        WHEN attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 'Last 24 Hours'
        WHEN attempted_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 'Last 7 Days'
        ELSE 'Older'
    END AS time_category
FROM failed_login_attempts
ORDER BY attempted_at DESC;

-- Optional: Create a view for suspicious activity (multiple failures)
CREATE OR REPLACE VIEW suspicious_login_activity AS
SELECT 
    username,
    COUNT(*) as attempt_count,
    MAX(attempted_at) as last_attempt,
    MIN(attempted_at) as first_attempt,
    GROUP_CONCAT(DISTINCT ip_address) as ip_addresses
FROM failed_login_attempts
WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY username
HAVING COUNT(*) >= 3
ORDER BY attempt_count DESC, last_attempt DESC;
