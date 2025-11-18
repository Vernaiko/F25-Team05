-- ============================================================================
-- AUDIT LOG TABLE FOR SAFE DRIVER PROGRAM
-- ============================================================================
-- This table tracks all significant system events for compliance and reporting
-- Supports sponsor-specific and admin-wide audit reporting requirements
-- ============================================================================

CREATE TABLE audit_logs (
    audit_id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Event identification
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type ENUM('user_action', 'system_action', 'data_change', 'security_event', 'transaction', 'report_generation') NOT NULL,
    event_category VARCHAR(50) NOT NULL, -- 'point_change', 'purchase', 'login', 'account_modification', etc.
    
    -- User/Actor information
    actor_user_id INT,
    actor_type ENUM('admin', 'sponsor', 'driver', 'system') NOT NULL,
    actor_username VARCHAR(50),
    
    -- Target/Affected entities
    target_user_id INT, -- User being affected by the action
    target_type ENUM('admin', 'sponsor', 'driver') NULL,
    target_username VARCHAR(50),
    
    -- Sponsor relationship (for filtering sponsor-specific logs)
    related_sponsor_id INT, -- Links to sponsor for driver actions
    
    -- Event details
    action_performed VARCHAR(100) NOT NULL, -- 'points_awarded', 'product_purchased', 'account_created', etc.
    description TEXT NOT NULL,
    
    -- Data changes (for point tracking)
    old_value VARCHAR(255),
    new_value VARCHAR(255),
    points_amount INT DEFAULT NULL, -- For point-related transactions
    
    -- Reference information
    reference_id VARCHAR(100), -- Transaction ID, Order ID, etc.
    reference_type VARCHAR(50), -- 'wallet_transaction', 'order', 'user_account', etc.
    
    -- Additional context
    reason VARCHAR(255),
    notes TEXT,
    
    -- Technical details
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(100),
    
    -- Status and metadata
    status ENUM('success', 'failed', 'pending', 'reversed') DEFAULT 'success',
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    
    -- Indexes for performance
    INDEX idx_event_timestamp (event_timestamp),
    INDEX idx_event_type_category (event_type, event_category),
    INDEX idx_actor_user_id (actor_user_id),
    INDEX idx_target_user_id (target_user_id),
    INDEX idx_related_sponsor_id (related_sponsor_id),
    INDEX idx_reference_id (reference_id),
    INDEX idx_status (status),
    
    -- Composite indexes for common queries
    INDEX idx_sponsor_date_category (related_sponsor_id, event_timestamp, event_category),
    INDEX idx_actor_date (actor_user_id, event_timestamp),
    INDEX idx_target_date (target_user_id, event_timestamp),
    
    -- Foreign key constraints
    FOREIGN KEY (actor_user_id) REFERENCES users(userID) ON DELETE SET NULL,
    FOREIGN KEY (target_user_id) REFERENCES users(userID) ON DELETE SET NULL,
    FOREIGN KEY (related_sponsor_id) REFERENCES users(userID) ON DELETE SET NULL
);

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC AUDIT LOGGING
-- ============================================================================

-- 1. TRIGGER FOR WALLET TRANSACTIONS (Point Changes)
DELIMITER //
CREATE TRIGGER audit_wallet_transactions
AFTER INSERT ON wallet_transaction_history
FOR EACH ROW
BEGIN
    DECLARE sponsor_id INT DEFAULT NULL;
    DECLARE actor_username VARCHAR(100) DEFAULT '';
    DECLARE target_username VARCHAR(100) DEFAULT '';
    DECLARE actor_type_val VARCHAR(20) DEFAULT 'system';

    -- get active sponsor for driver (if any)
    SELECT sponsor_user_id INTO sponsor_id
    FROM sponsor_driver_relationships
    WHERE driver_user_id = NEW.driver_id
      AND relationship_status = 'active'
    LIMIT 1;

    IF NEW.sponsor_id IS NOT NULL THEN
        SET actor_type_val = 'sponsor';
        SELECT username INTO actor_username FROM users WHERE userID = NEW.sponsor_id LIMIT 1;
    ELSEIF NEW.admin_id IS NOT NULL THEN
        SET actor_type_val = 'admin';
        SELECT username INTO actor_username FROM users WHERE userID = NEW.admin_id LIMIT 1;
    ELSE
        SET actor_type_val = 'system';
        SET actor_username = 'system';
    END IF;

    SELECT username INTO target_username FROM users WHERE userID = NEW.driver_id LIMIT 1;

    INSERT INTO audit_logs (
        event_type,
        event_category,
        actor_user_id,
        actor_type,
        actor_username,
        target_user_id,
        target_type,
        target_username,
        related_sponsor_id,
        action_performed,
        description,
        old_value,
        new_value,
        points_amount,
        reference_id,
        reference_type,
        reason,
        notes,
        status,
        severity
    ) VALUES (
        'transaction',
        'point_change',
        COALESCE(NEW.sponsor_id, NEW.admin_id),
        actor_type_val,
        actor_username,
        NEW.driver_id,
        'driver',
        target_username,
        COALESCE(sponsor_id, NEW.sponsor_id),
        CONCAT('points_', COALESCE(NEW.transaction_type, 'unknown')),
        CONCAT('Point ', COALESCE(NEW.transaction_type, 'transaction'), ' for driver ', target_username, ': ', COALESCE(NEW.description, 'No description')),
        -- ensure these column names exist in your wallet table; replace if necessary
        CAST(NEW.points_before AS CHAR),
        CAST(NEW.points_after AS CHAR),
        NEW.points_amount,
        COALESCE(NEW.reference_id, CONCAT('WALLET-', NEW.transaction_id)),
        COALESCE(NEW.reference_type, 'wallet_transaction'),
        COALESCE(NEW.description, NULL),
        COALESCE(NEW.notes, NULL),
        COALESCE(NEW.status, 'success'),
        CASE 
            WHEN ABS(NEW.points_amount) >= 1000 THEN 'high'
            WHEN ABS(NEW.points_amount) >= 100 THEN 'medium'
            ELSE 'low'
        END
    );
END//
DELIMITER ;

-- 2. TRIGGER FOR DRIVER APPLICATION STATUS CHANGES
DROP TRIGGER IF EXISTS audit_driver_application_status;
DELIMITER //

CREATE TRIGGER audit_driver_application_status
AFTER INSERT ON driver_application_status_history
FOR EACH ROW
BEGIN
    DECLARE sponsor_id_val INT DEFAULT NULL;
    DECLARE driver_id_val INT DEFAULT NULL;
    DECLARE sponsor_username VARCHAR(50) DEFAULT '';
    DECLARE driver_username VARCHAR(50) DEFAULT '';
    DECLARE status_description TEXT DEFAULT '';
    
    -- Get sponsor_id and driver_id from driver_applications table
    SELECT sponsor_id, driver_id INTO sponsor_id_val, driver_id_val
    FROM driver_applications 
    WHERE application_id = NEW.application_id LIMIT 1;
    
    -- Get usernames (with NULL checks)
    IF sponsor_id_val IS NOT NULL THEN
        SELECT username INTO sponsor_username FROM users WHERE userID = sponsor_id_val LIMIT 1;
    END IF;
    
    IF driver_id_val IS NOT NULL THEN
        SELECT username INTO driver_username FROM users WHERE userID = driver_id_val LIMIT 1;
    END IF;
    
    -- Create status description using NEW.new_status (from DDL)
    SET status_description = CONCAT(
        'Driver application status changed from "', COALESCE(NEW.old_status, 'N/A'), 
        '" to "', NEW.new_status, '" for driver ', 
        COALESCE(driver_username, CONCAT('ID:', driver_id_val)), 
        ' by user ', 
        COALESCE(sponsor_username, CONCAT('ID:', NEW.changed_by_user_id))
    );
    
    -- Add reason if provided (using change_reason from DDL)
    IF NEW.change_reason IS NOT NULL AND NEW.change_reason != '' THEN
        SET status_description = CONCAT(status_description, '. Reason: ', NEW.change_reason);
    END IF;
    
    -- Add admin comments if provided
    IF NEW.admin_comments IS NOT NULL AND NEW.admin_comments != '' THEN
        SET status_description = CONCAT(status_description, '. Comments: ', NEW.admin_comments);
    END IF;
    
    INSERT INTO audit_logs (
        event_type,
        event_category,
        actor_user_id,
        actor_type,
        actor_username,
        target_user_id,
        target_type,
        target_username,
        related_sponsor_id,
        action_performed,
        description,
        old_value,
        new_value,
        reference_id,
        reference_type,
        reason,
        status,
        severity
    ) VALUES (
        'user_action',
        'application_status',
        NEW.changed_by_user_id,  -- Use changed_by_user_id from DDL
        'sponsor',
        sponsor_username,
        driver_id_val,
        'driver',
        driver_username,
        sponsor_id_val,
        CONCAT('application_', NEW.new_status),
        status_description,
        NEW.old_status,
        NEW.new_status,
        CONCAT('APP-', NEW.application_id, '-', NEW.history_id),  -- Use history_id from DDL
        'driver_application',
        NEW.change_reason,  -- Use change_reason from DDL
        'success',
        CASE 
            WHEN NEW.new_status = 'rejected' THEN 'medium'
            WHEN NEW.new_status = 'approved' THEN 'medium'
            ELSE 'low'
        END
    );
END//

DELIMITER ;

-- 3. TRIGGER FOR DRIVER APPLICATION UPDATES (Status Changes)
DROP TRIGGER IF EXISTS audit_driver_application_updates;
DELIMITER //

CREATE TRIGGER audit_driver_application_updates
AFTER UPDATE ON driver_applications
FOR EACH ROW
BEGIN
    DECLARE sponsor_username VARCHAR(50) DEFAULT '';
    DECLARE driver_username VARCHAR(50) DEFAULT '';
    DECLARE status_description TEXT DEFAULT '';
    
    -- Only log if application_status actually changed
    IF OLD.application_status != NEW.application_status THEN
        -- Get usernames (with NULL checks)
        IF NEW.sponsor_user_id IS NOT NULL THEN
            SELECT username INTO sponsor_username FROM users WHERE userID = NEW.sponsor_user_id LIMIT 1;
        END IF;
        
        IF NEW.driver_user_id IS NOT NULL THEN
            SELECT username INTO driver_username FROM users WHERE userID = NEW.driver_user_id LIMIT 1;
        END IF;
        
        -- Create status description
        SET status_description = CONCAT(
            'Driver application status updated from "', OLD.application_status, '" to "', NEW.application_status, 
            '" for driver ', COALESCE(driver_username, CONCAT('ID:', NEW.driver_user_id))
        );
        
        -- Add sponsor info if available
        IF sponsor_username != '' THEN
            SET status_description = CONCAT(status_description, ' by sponsor ', sponsor_username);
        END IF;
        
        -- Add admin notes if provided
        IF NEW.admin_notes IS NOT NULL AND NEW.admin_notes != '' THEN
            SET status_description = CONCAT(status_description, '. Admin notes: ', NEW.admin_notes);
        END IF;
        
        INSERT INTO audit_logs (
            event_type,
            event_category,
            actor_user_id,
            actor_type,
            actor_username,
            target_user_id,
            target_type,
            target_username,
            related_sponsor_id,
            action_performed,
            description,
            old_value,
            new_value,
            reference_id,
            reference_type,
            status,
            severity
        ) VALUES (
            'data_change',
            'application_status',
            COALESCE(NEW.reviewed_by_admin_id, NEW.sponsor_user_id),  -- Could be admin or sponsor
            CASE 
                WHEN NEW.reviewed_by_admin_id IS NOT NULL THEN 'admin'
                WHEN NEW.sponsor_user_id IS NOT NULL THEN 'sponsor'
                ELSE 'system'
            END,
            COALESCE(sponsor_username, 'system'),
            NEW.driver_user_id,
            'driver',
            driver_username,
            NEW.sponsor_user_id,
            CONCAT('status_change_', NEW.application_status),
            status_description,
            OLD.application_status,
            NEW.application_status,
            CONCAT('APP-', NEW.application_id),
            'driver_application',
            'success',
            CASE 
                WHEN NEW.application_status IN ('rejected', 'withdrawn') THEN 'high'
                WHEN NEW.application_status = 'approved' THEN 'medium'
                ELSE 'low'
            END
        );
    END IF;
END//

DELIMITER ;


-- 4. TRIGGER FOR PASSWORD CHANGES
DELIMITER //

CREATE TRIGGER audit_password_changes
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    DECLARE change_type VARCHAR(50) DEFAULT 'password_update';
    DECLARE change_description TEXT DEFAULT '';
    
    -- Only log if password actually changed
    IF OLD.password_hash != NEW.password_hash THEN
        -- Determine change type
        IF OLD.updated_at IS NULL OR OLD.updated_at = OLD.created_at THEN
            SET change_type = 'initial_password_set';
            SET change_description = CONCAT('Initial password set for user ', NEW.username);
        ELSE
            SET change_type = 'password_changed';
            SET change_description = CONCAT('Password changed for user ', NEW.username);
        END IF;
        
        INSERT INTO audit_logs (
            event_type,
            event_category,
            actor_user_id,
            actor_type,
            actor_username,
            target_user_id,
            target_type,
            target_username,
            action_performed,
            description,
            reference_id,
            reference_type,
            status,
            severity
        ) VALUES (
            'security_event',
            'password_change',
            NEW.userID,
            NEW.account_type,
            NEW.username,
            NEW.userID,
            NEW.account_type,
            NEW.username,
            change_type,
            change_description,
            CONCAT('USER-', NEW.userID, '-PWD'),
            'user_account',
            'success',
            'medium'
        );
    END IF;
END//

DELIMITER ;

-- 5. TRIGGER FOR LOGIN ATTEMPTS (Success)
DELIMITER //

CREATE TRIGGER audit_successful_logins
AFTER INSERT ON failed_login_attempts
FOR EACH ROW
BEGIN
    DECLARE user_id_val INT DEFAULT NULL;
    DECLARE user_type VARCHAR(20) DEFAULT 'unknown';
    DECLARE login_description TEXT DEFAULT '';
    
    -- Only log successful attempts (success = 1)
    IF NEW.success = 1 THEN
        -- Get user ID and type
        SELECT userID, account_type INTO user_id_val, user_type 
        FROM users WHERE username = NEW.username LIMIT 1;
        
        SET login_description = CONCAT('Successful login for user ', NEW.username);
        
        IF NEW.notes IS NOT NULL AND NEW.notes != '' THEN
            SET login_description = CONCAT(login_description, '. Notes: ', NEW.notes);
        END IF;
        
        INSERT INTO audit_logs (
            event_type,
            event_category,
            actor_user_id,
            actor_type,
            actor_username,
            target_user_id,
            target_type,
            target_username,
            action_performed,
            description,
            reference_id,
            reference_type,
            ip_address,
            user_agent,
            status,
            severity
        ) VALUES (
            'security_event',
            'login',
            user_id_val,
            COALESCE(user_type, 'unknown'),
            NEW.username,
            user_id_val,
            COALESCE(user_type, 'unknown'),
            NEW.username,
            'login_success',
            login_description,
            CONCAT('LOGIN-', NEW.attempt_id),
            'login_attempt',
            NEW.ip_address,
            NEW.user_agent,
            'success',
            'low'
        );
    END IF;
END//

DELIMITER ;

-- 6. TRIGGER FOR FAILED LOGIN ATTEMPTS
DELIMITER //

CREATE TRIGGER audit_failed_logins
AFTER INSERT ON failed_login_attempts
FOR EACH ROW
BEGIN
    DECLARE user_id_val INT DEFAULT NULL;
    DECLARE user_type VARCHAR(20) DEFAULT 'unknown';
    DECLARE login_description TEXT DEFAULT '';
    
    -- Only log failed attempts (success = 0)
    IF NEW.success = 0 THEN
        -- Try to get user ID and type (might not exist for invalid usernames)
        SELECT userID, account_type INTO user_id_val, user_type 
        FROM users WHERE username = NEW.username LIMIT 1;
        
        SET login_description = CONCAT('Failed login attempt for username ', NEW.username);
        
        IF NEW.notes IS NOT NULL AND NEW.notes != '' THEN
            SET login_description = CONCAT(login_description, '. Notes: ', NEW.notes);
        END IF;
        
        INSERT INTO audit_logs (
            event_type,
            event_category,
            actor_user_id,
            actor_type,
            actor_username,
            target_user_id,
            target_type,
            target_username,
            action_performed,
            description,
            reference_id,
            reference_type,
            ip_address,
            user_agent,
            status,
            severity
        ) VALUES (
            'security_event',
            'login',
            user_id_val,
            COALESCE(user_type, 'unknown'),
            NEW.username,
            user_id_val,
            COALESCE(user_type, 'unknown'),
            NEW.username,
            'login_failed',
            login_description,
            CONCAT('LOGIN-FAIL-', NEW.attempt_id),
            'login_attempt',
            NEW.ip_address,
            NEW.user_agent,
            'failed',
            CASE 
                WHEN user_id_val IS NULL THEN 'high'  -- Invalid username
                ELSE 'medium'  -- Valid username, wrong password
            END
        );
    END IF;
END//

DELIMITER ;

-- ============================================================================
-- SAMPLE QUERIES FOR REPORTING REQUIREMENTS
-- ============================================================================

-- Sponsor Report: Driver Point Tracking
-- SELECT a.event_timestamp as date_of_change,
--        CONCAT(tu.first_name, ' ', tu.last_name) as driver_name,
--        a.points_amount as point_change,
--        a.new_value as total_points_after,
--        CONCAT(au.first_name, ' ', au.last_name) as sponsor_name,
--        a.reason
-- FROM audit_logs a
-- JOIN users tu ON a.target_user_id = tu.userID
-- LEFT JOIN users au ON a.actor_user_id = au.userID
-- WHERE a.related_sponsor_id = ? 
--   AND a.event_category = 'point_change'
--   AND a.event_timestamp BETWEEN ? AND ?
-- ORDER BY a.event_timestamp DESC;

-- Admin Report: Driver Application Status Changes
-- SELECT a.event_timestamp as date_changed,
--        CONCAT(s.first_name, ' ', s.last_name) as sponsor_name,
--        CONCAT(d.first_name, ' ', d.last_name) as driver_name,
--        a.new_value as status,
--        CASE WHEN a.new_value = 'approved' THEN 'accept' ELSE 'reject' END as action,
--        a.reason
-- FROM audit_logs a
-- JOIN users s ON a.actor_user_id = s.userID
-- JOIN users d ON a.target_user_id = d.userID
-- WHERE a.event_category = 'application_status'
--   AND a.event_timestamp BETWEEN ? AND ?
-- ORDER BY a.event_timestamp DESC;

-- Admin Report: Password Changes
-- SELECT a.event_timestamp as date_changed,
--        a.target_username as username,
--        a.action_performed as change_type
-- FROM audit_logs a
-- WHERE a.event_category = 'password_change'
--   AND a.event_timestamp BETWEEN ? AND ?
-- ORDER BY a.event_timestamp DESC;

-- Admin Report: Login Attempts
-- SELECT a.event_timestamp as attempt_date,
--        a.actor_username as username,
--        CASE WHEN a.status = 'success' THEN 'success' ELSE 'failure' END as result,
--        a.ip_address
-- FROM audit_logs a
-- WHERE a.event_category = 'login'
--   AND a.event_timestamp BETWEEN ? AND ?
-- ORDER BY a.event_timestamp DESC;

-- ============================================================================
-- TEST DATA FOR AUDIT LOGS
-- ============================================================================

-- Manual audit log entries for testing (these would normally be auto-generated)
INSERT INTO audit_logs (
    event_type, event_category, actor_user_id, actor_type, actor_username,
    target_user_id, target_type, target_username, related_sponsor_id,
    action_performed, description, points_amount, reference_id, reference_type,
    reason, status, severity
) VALUES 
-- Admin creates new driver account
('user_action', 'account_creation', 1, 'admin', 'admin_user', 
 50, 'driver', 'driver50', 3,
 'account_created', 'New driver account created by admin', NULL, 'USER-50', 'user_account',
 'New driver registration approved', 'success', 'medium'),

-- Sponsor awards points to driver  
('transaction', 'point_change', 3, 'sponsor', 'sponsor_abc', 
 50, 'driver', 'driver50', 3,
 'points_reward', 'Welcome bonus awarded to new driver', 100, 'WELCOME-50', 'sponsor_reward',
 'New driver welcome bonus', 'success', 'medium'),

-- System processes purchase
('system_action', 'point_change', NULL, 'system', 'system', 
 50, 'driver', 'driver50', 3,
 'points_purchase', 'Driver redeemed points for gas card', -75, 'ORDER-1001', 'order',
 'Product redemption processed', 'success', 'low'),

-- Admin applies penalty
('user_action', 'point_change', 1, 'admin', 'admin_user', 
 54, 'driver', 'driver54', 3,
 'points_penalty', 'Late report submission penalty', -10, 'PENALTY-54-AUG', 'penalty',
 'Monthly report submitted 5 days late', 'success', 'medium'),

-- Driver application approved
('user_action', 'application_status', 3, 'sponsor', 'sponsor_abc',
 52, 'driver', 'driver52', 3,
 'application_approved', 'Driver application approved by sponsor', NULL, 'APP-52-APPROVED', 'driver_application',
 'Driver met all safety requirements', 'success', 'medium'),

-- Password change
('security_event', 'password_change', 50, 'driver', 'driver50',
 50, 'driver', 'driver50', NULL,
 'password_changed', 'Driver changed their password', NULL, 'USER-50-PWD', 'user_account',
 'User-initiated password change', 'success', 'medium'),

-- Successful login
('security_event', 'login', 3, 'sponsor', 'sponsor_abc',
 3, 'sponsor', 'sponsor_abc', NULL,
 'login_success', 'Successful login for sponsor', NULL, 'LOGIN-SUCCESS-001', 'login_attempt',
 'Regular login', 'success', 'low'),

-- Failed login attempt
('security_event', 'login', NULL, 'unknown', 'invalid_user',
 NULL, 'unknown', 'invalid_user', NULL,
 'login_failed', 'Failed login attempt with invalid username', NULL, 'LOGIN-FAIL-002', 'login_attempt',
 'Invalid username attempted', 'failed', 'high');