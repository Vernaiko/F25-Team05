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