CREATE TABLE driver_applications (
    application_id INT AUTO_INCREMENT PRIMARY KEY,
    driver_user_id INT NOT NULL,
    sponsor_user_id INT NULL,  -- NULL when not yet assigned to sponsor
    
    -- Application Details
    application_status ENUM('pending', 'under_review', 'approved', 'rejected', 'withdrawn') DEFAULT 'pending',
    application_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    review_date DATETIME NULL,
    approval_date DATETIME NULL,
    
    -- Driver Information
    driver_license_number VARCHAR(50) NOT NULL,
    license_state VARCHAR(2) NOT NULL,
    license_expiry_date DATE NOT NULL,
    years_of_experience INT NOT NULL,
    
    -- Driving Record
    accidents_last_3_years INT DEFAULT 0,
    violations_last_3_years INT DEFAULT 0,
    dui_history BOOLEAN DEFAULT FALSE,
    clean_record_years INT DEFAULT 0,
    
    -- Personal Information
    date_of_birth DATE NOT NULL,
    emergency_contact_name VARCHAR(100),
    emergency_contact_phone VARCHAR(20),
    
    -- Vehicle Information
    vehicle_make VARCHAR(50),
    vehicle_model VARCHAR(50),
    vehicle_year YEAR,
    vehicle_vin VARCHAR(17),
    insurance_company VARCHAR(100),
    insurance_policy_number VARCHAR(50),
    insurance_expiry_date DATE,
    
    -- Application Essay/Motivation
    motivation_essay TEXT,
    goals_description TEXT,
    
    -- Review Information
    reviewed_by_admin_id INT NULL,
    admin_notes TEXT NULL,
    rejection_reason TEXT NULL,
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign Key Constraints
    FOREIGN KEY (driver_user_id) REFERENCES users(userID) ON DELETE CASCADE,
    FOREIGN KEY (sponsor_user_id) REFERENCES users(userID) ON DELETE SET NULL,
    FOREIGN KEY (reviewed_by_admin_id) REFERENCES users(userID) ON DELETE SET NULL,
    
    -- Indexes
    INDEX idx_driver_user_id (driver_user_id),
    INDEX idx_sponsor_user_id (sponsor_user_id),
    INDEX idx_application_status (application_status),
    INDEX idx_application_date (application_date),
    INDEX idx_review_date (review_date),
    
    -- Unique constraint - one active application per driver
    UNIQUE KEY unique_active_application (driver_user_id, application_status)
);