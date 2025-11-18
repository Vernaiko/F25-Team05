CREATE TABLE driver_application_status_history (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    
    -- Status Change Information
    old_status ENUM('pending', 'under_review', 'approved', 'rejected', 'withdrawn'),
    new_status ENUM('pending', 'under_review', 'approved', 'rejected', 'withdrawn') NOT NULL,
    
    -- Change Details
    changed_by_user_id INT NOT NULL,
    change_reason TEXT NULL,
    admin_comments TEXT NULL,
    
    -- Timestamp
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign Key Constraints
    FOREIGN KEY (application_id) REFERENCES driver_applications(application_id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(userID) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_application_id (application_id),
    INDEX idx_changed_by_user_id (changed_by_user_id),
    INDEX idx_changed_at (changed_at)
);
-- ============================================================================
-- TRIGGERS FOR DRIVER APPLICATION STATUS HISTORY TRACKING
-- ============================================================================
-- These triggers automatically log all application status changes
-- Tracks creation, updates, approvals, rejections, and withdrawals
-- ============================================================================

-- 1. TRIGGER FOR NEW APPLICATION CREATION
DROP TRIGGER IF EXISTS log_application_creation;
DELIMITER //

CREATE TRIGGER log_application_creation
AFTER INSERT ON driver_applications
FOR EACH ROW
BEGIN
    -- Log the initial application creation
    INSERT INTO driver_application_status_history (
        application_id,
        old_status,
        new_status,
        changed_by_user_id,
        change_reason,
        admin_comments,
        changed_at
    ) VALUES (
        NEW.application_id,
        NULL,  -- No previous status
        NEW.application_status,
        NEW.driver_user_id,  -- Driver created the application
        'Application submitted by driver',
        NULL,
        NEW.application_date
    );
END//

DELIMITER ;

-- 2. TRIGGER FOR APPLICATION STATUS CHANGES
DROP TRIGGER IF EXISTS log_application_status_change;
DELIMITER //

CREATE TRIGGER log_application_status_change
AFTER UPDATE ON driver_applications
FOR EACH ROW
BEGIN
    DECLARE change_reason_text TEXT;
    DECLARE admin_comments_text TEXT;
    DECLARE changed_by_id INT;
    
    -- Only log if application_status actually changed
    IF OLD.application_status != NEW.application_status THEN
        
        -- Determine who made the change and why
        IF NEW.reviewed_by_admin_id IS NOT NULL THEN
            SET changed_by_id = NEW.reviewed_by_admin_id;
            SET admin_comments_text = NEW.admin_notes;
            
            -- Determine reason based on new status
            CASE NEW.application_status
                WHEN 'approved' THEN
                    SET change_reason_text = 'Application approved by admin';
                WHEN 'rejected' THEN
                    SET change_reason_text = CONCAT('Application rejected: ', COALESCE(NEW.rejection_reason, 'No reason provided'));
                WHEN 'under_review' THEN
                    SET change_reason_text = 'Application moved to review by admin';
                ELSE
                    SET change_reason_text = 'Status changed by admin';
            END CASE;
            
        ELSEIF NEW.sponsor_user_id IS NOT NULL AND OLD.sponsor_user_id IS NULL THEN
            -- Sponsor assigned
            SET changed_by_id = NEW.sponsor_user_id;
            SET change_reason_text = 'Application assigned to sponsor';
            SET admin_comments_text = NULL;
            
        ELSEIF NEW.application_status = 'withdrawn' THEN
            -- Driver withdrew application
            SET changed_by_id = NEW.driver_user_id;
            SET change_reason_text = 'Application withdrawn by driver';
            SET admin_comments_text = NULL;
            
        ELSE
            -- System or other change
            SET changed_by_id = COALESCE(NEW.reviewed_by_admin_id, NEW.driver_user_id);
            SET change_reason_text = CONCAT('Status changed from ', OLD.application_status, ' to ', NEW.application_status);
            SET admin_comments_text = NEW.admin_notes;
        END IF;
        
        -- Insert history record
        INSERT INTO driver_application_status_history (
            application_id,
            old_status,
            new_status,
            changed_by_user_id,
            change_reason,
            admin_comments,
            changed_at
        ) VALUES (
            NEW.application_id,
            OLD.application_status,
            NEW.application_status,
            changed_by_id,
            change_reason_text,
            admin_comments_text,
            NOW()
        );
    END IF;
END//

DELIMITER ;

-- 3. TRIGGER FOR SPONSOR ASSIGNMENT CHANGES
DROP TRIGGER IF EXISTS log_sponsor_assignment_change;
DELIMITER //

CREATE TRIGGER log_sponsor_assignment_change
AFTER UPDATE ON driver_applications
FOR EACH ROW
BEGIN
    DECLARE change_reason_text TEXT;
    
    -- Log when sponsor assignment changes (not status change)
    IF OLD.sponsor_user_id != NEW.sponsor_user_id 
       AND OLD.application_status = NEW.application_status THEN
        
        IF OLD.sponsor_user_id IS NULL AND NEW.sponsor_user_id IS NOT NULL THEN
            SET change_reason_text = CONCAT('Sponsor assigned (ID: ', NEW.sponsor_user_id, ')');
        ELSEIF OLD.sponsor_user_id IS NOT NULL AND NEW.sponsor_user_id IS NULL THEN
            SET change_reason_text = CONCAT('Sponsor removed (was ID: ', OLD.sponsor_user_id, ')');
        ELSE
            SET change_reason_text = CONCAT('Sponsor changed from ID:', OLD.sponsor_user_id, ' to ID:', NEW.sponsor_user_id);
        END IF;
        
        INSERT INTO driver_application_status_history (
            application_id,
            old_status,
            new_status,
            changed_by_user_id,
            change_reason,
            admin_comments,
            changed_at
        ) VALUES (
            NEW.application_id,
            OLD.application_status,
            NEW.application_status,  -- Status unchanged
            COALESCE(NEW.reviewed_by_admin_id, NEW.sponsor_user_id, NEW.driver_user_id),
            change_reason_text,
            'Sponsor assignment modified',
            NOW()
        );
    END IF;
END//

DELIMITER ;

-- 4. TRIGGER FOR ADMIN REVIEW ASSIGNMENT
DROP TRIGGER IF EXISTS log_admin_review_assignment;
DELIMITER //

CREATE TRIGGER log_admin_review_assignment
AFTER UPDATE ON driver_applications
FOR EACH ROW
BEGIN
    -- Log when admin is assigned to review (without status change)
    IF OLD.reviewed_by_admin_id IS NULL 
       AND NEW.reviewed_by_admin_id IS NOT NULL
       AND OLD.application_status = NEW.application_status THEN
        
        INSERT INTO driver_application_status_history (
            application_id,
            old_status,
            new_status,
            changed_by_user_id,
            change_reason,
            admin_comments,
            changed_at
        ) VALUES (
            NEW.application_id,
            OLD.application_status,
            NEW.application_status,
            NEW.reviewed_by_admin_id,
            CONCAT('Application assigned to admin for review (Admin ID: ', NEW.reviewed_by_admin_id, ')'),
            'Admin review assigned',
            NOW()
        );
    END IF;
    
    -- Log when admin reviewer changes
    IF OLD.reviewed_by_admin_id IS NOT NULL 
       AND NEW.reviewed_by_admin_id IS NOT NULL
       AND OLD.reviewed_by_admin_id != NEW.reviewed_by_admin_id
       AND OLD.application_status = NEW.application_status THEN
        
        INSERT INTO driver_application_status_history (
            application_id,
            old_status,
            new_status,
            changed_by_user_id,
            change_reason,
            admin_comments,
            changed_at
        ) VALUES (
            NEW.application_id,
            OLD.application_status,
            NEW.application_status,
            NEW.reviewed_by_admin_id,
            CONCAT('Reviewing admin changed from ID:', OLD.reviewed_by_admin_id, ' to ID:', NEW.reviewed_by_admin_id),
            'Admin reviewer reassigned',
            NOW()
        );
    END IF;
END//

DELIMITER ;

-- 5. TRIGGER FOR SIGNIFICANT APPLICATION DATA CHANGES
DROP TRIGGER IF EXISTS log_application_data_changes;
DELIMITER //

CREATE TRIGGER log_application_data_changes
AFTER UPDATE ON driver_applications
FOR EACH ROW
BEGIN
    DECLARE changes_detected BOOLEAN DEFAULT FALSE;
    DECLARE change_summary TEXT DEFAULT '';
    
    -- Only log if status hasn't changed (to avoid duplicate logging)
    IF OLD.application_status = NEW.application_status THEN
        
        -- Check for significant field changes
        IF OLD.driver_license_number != NEW.driver_license_number THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'License number updated; ');
        END IF;
        
        IF OLD.license_expiry_date != NEW.license_expiry_date THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'License expiry date updated; ');
        END IF;
        
        IF OLD.years_of_experience != NEW.years_of_experience THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Years of experience updated; ');
        END IF;
        
        IF OLD.accidents_last_3_years != NEW.accidents_last_3_years THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Accident count updated; ');
        END IF;
        
        IF OLD.violations_last_3_years != NEW.violations_last_3_years THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Violation count updated; ');
        END IF;
        
        IF OLD.dui_history != NEW.dui_history THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'DUI history updated; ');
        END IF;
        
        IF COALESCE(OLD.vehicle_vin, '') != COALESCE(NEW.vehicle_vin, '') THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Vehicle VIN updated; ');
        END IF;
        
        IF COALESCE(OLD.insurance_policy_number, '') != COALESCE(NEW.insurance_policy_number, '') THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Insurance policy updated; ');
        END IF;
        
        IF COALESCE(OLD.insurance_expiry_date, '1900-01-01') != COALESCE(NEW.insurance_expiry_date, '1900-01-01') THEN
            SET changes_detected = TRUE;
            SET change_summary = CONCAT(change_summary, 'Insurance expiry updated; ');
        END IF;
        
        -- Log if changes detected
        IF changes_detected THEN
            INSERT INTO driver_application_status_history (
                application_id,
                old_status,
                new_status,
                changed_by_user_id,
                change_reason,
                admin_comments,
                changed_at
            ) VALUES (
                NEW.application_id,
                OLD.application_status,
                NEW.application_status,
                COALESCE(NEW.reviewed_by_admin_id, NEW.driver_user_id),
                CONCAT('Application data modified: ', TRIM(TRAILING '; ' FROM change_summary)),
                'Application information updated',
                NOW()
            );
        END IF;
    END IF;
END//

DELIMITER ;

-- 6. TRIGGER FOR APPLICATION DELETION
DROP TRIGGER IF EXISTS log_application_deletion;
DELIMITER //

CREATE TRIGGER log_application_deletion
BEFORE DELETE ON driver_applications
FOR EACH ROW
BEGIN
    -- Log application deletion before it's removed
    INSERT INTO driver_application_status_history (
        application_id,
        old_status,
        new_status,
        changed_by_user_id,
        change_reason,
        admin_comments,
        changed_at
    ) VALUES (
        OLD.application_id,
        OLD.application_status,
        'withdrawn',  -- Treat deletion as withdrawal
        OLD.driver_user_id,
        'Application deleted/removed from system',
        CONCAT('Application deleted. Last status: ', OLD.application_status, 
               '. Last updated: ', OLD.updated_at),
        NOW()
    );
END//

DELIMITER ;

-- ============================================================================
-- SAMPLE QUERIES FOR VIEWING APPLICATION HISTORY
-- ============================================================================

/*
-- View complete history for a specific application
SELECT 
    h.history_id,
    h.application_id,
    h.old_status,
    h.new_status,
    u.username as changed_by,
    u.account_type as changer_type,
    h.change_reason,
    h.admin_comments,
    h.changed_at
FROM driver_application_status_history h
LEFT JOIN users u ON h.changed_by_user_id = u.userID
WHERE h.application_id = ?
ORDER BY h.changed_at DESC;

-- View all status changes for a driver
SELECT 
    da.application_id,
    da.application_date,
    h.old_status,
    h.new_status,
    h.change_reason,
    h.changed_at,
    u.username as changed_by
FROM driver_applications da
JOIN driver_application_status_history h ON da.application_id = h.application_id
LEFT JOIN users u ON h.changed_by_user_id = u.userID
WHERE da.driver_user_id = ?
ORDER BY h.changed_at DESC;

-- View all recent application status changes (admin view)
SELECT 
    da.application_id,
    CONCAT(du.first_name, ' ', du.last_name) as driver_name,
    h.old_status,
    h.new_status,
    h.change_reason,
    h.changed_at,
    CONCAT(cu.first_name, ' ', cu.last_name) as changed_by,
    cu.account_type as changer_role
FROM driver_application_status_history h
JOIN driver_applications da ON h.application_id = da.application_id
JOIN users du ON da.driver_user_id = du.userID
LEFT JOIN users cu ON h.changed_by_user_id = cu.userID
WHERE h.changed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
ORDER BY h.changed_at DESC;

-- View applications by sponsor with status history
SELECT 
    da.application_id,
    CONCAT(du.first_name, ' ', du.last_name) as driver_name,
    da.application_status as current_status,
    COUNT(h.history_id) as status_changes,
    MAX(h.changed_at) as last_change_date
FROM driver_applications da
JOIN users du ON da.driver_user_id = du.userID
LEFT JOIN driver_application_status_history h ON da.application_id = h.application_id
WHERE da.sponsor_user_id = ?
GROUP BY da.application_id, driver_name, da.application_status
ORDER BY last_change_date DESC;
*/