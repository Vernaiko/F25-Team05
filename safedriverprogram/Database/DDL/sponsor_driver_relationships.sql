CREATE TABLE sponsor_driver_relationships (
    relationship_id INT AUTO_INCREMENT PRIMARY KEY,
    sponsor_user_id INT NOT NULL,
    driver_user_id INT NOT NULL,
    application_id INT NOT NULL,  -- Reference to the approved application
    
    -- Relationship Status
    relationship_status ENUM('active', 'paused', 'terminated', 'completed') DEFAULT 'active',
    
    -- Important Dates
    relationship_start_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    relationship_end_date DATETIME NULL,
    last_activity_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Relationship Metrics
    safe_driving_streak_days INT DEFAULT 0,
    total_trips_logged INT DEFAULT 0,
    total_miles_driven DECIMAL(10,2) DEFAULT 0.00,
    
    -- Communication Preferences
    communication_frequency ENUM('daily', 'weekly', 'monthly', 'as_needed') DEFAULT 'weekly',
    preferred_contact_method ENUM('email', 'phone', 'app_notification') DEFAULT 'email',
    
    -- Performance Tracking
    performance_rating DECIMAL(3,2) NULL,  -- 0.00 to 5.00
    sponsor_satisfaction_rating DECIMAL(3,2) NULL,
    driver_satisfaction_rating DECIMAL(3,2) NULL,
    
    -- Notes and Comments
    sponsor_notes TEXT NULL,
    relationship_notes TEXT NULL,
    termination_reason TEXT NULL,
    
    -- Admin Information
    approved_by_admin_id INT NULL,
    terminated_by_user_id INT NULL,  -- Who terminated the relationship
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign Key Constraints
    FOREIGN KEY (sponsor_user_id) REFERENCES users(userID) ON DELETE CASCADE,
    FOREIGN KEY (driver_user_id) REFERENCES users(userID) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES driver_applications(application_id) ON DELETE CASCADE,
    FOREIGN KEY (approved_by_admin_id) REFERENCES users(userID) ON DELETE SET NULL,
    FOREIGN KEY (terminated_by_user_id) REFERENCES users(userID) ON DELETE SET NULL,
    
    -- Indexes
    INDEX idx_sponsor_user_id (sponsor_user_id),
    INDEX idx_driver_user_id (driver_user_id),
    INDEX idx_application_id (application_id),
    INDEX idx_relationship_status (relationship_status),
    INDEX idx_relationship_start_date (relationship_start_date),
    INDEX idx_last_activity_date (last_activity_date),
    
    -- Unique constraint - one active relationship per driver-sponsor pair
    UNIQUE KEY unique_active_relationship (sponsor_user_id, driver_user_id, relationship_status)
);