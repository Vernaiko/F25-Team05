CREATE TABLE wallet_transaction_history (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    wallet_id INT NOT NULL,
    driver_id INT NOT NULL,
    
    -- Transaction details (using integer points)
    transaction_type ENUM('adjustment', 'refund', 'purchase', 'reward', 'penalty') NOT NULL,
    points_amount INT NOT NULL,
    points_before INT NOT NULL,
    points_after INT NOT NULL,
    
    -- Transaction metadata
    description VARCHAR(500),
    reference_id VARCHAR(100), -- Order ID, sponsor ID, etc.
    reference_type ENUM('order', 'sponsor_reward', 'admin_adjustment', 'point_conversion', 'refund', 'penalty', 'bonus', 'other'),
    
    -- Sponsor relationship (if applicable)
    sponsor_id INT NULL,
    
    -- Admin who performed action (if applicable)
    admin_id INT NULL,
    
    -- Status and timestamps
    status ENUM('pending', 'completed', 'failed', 'cancelled') DEFAULT 'completed',
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_by VARCHAR(100), -- System user or admin username
    
    -- Additional info
    notes TEXT,
    ip_address VARCHAR(45),
    
    -- Foreign keys
    CONSTRAINT fk_transaction_wallet 
        FOREIGN KEY (wallet_id) 
        REFERENCES driver_wallets(wallet_id) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_transaction_driver 
        FOREIGN KEY (driver_id) 
        REFERENCES users(userID) 
        ON DELETE CASCADE,
    
    CONSTRAINT fk_transaction_sponsor 
        FOREIGN KEY (sponsor_id) 
        REFERENCES users(userID) 
        ON DELETE SET NULL,
    
    CONSTRAINT fk_transaction_admin 
        FOREIGN KEY (admin_id) 
        REFERENCES users(userID) 
        ON DELETE SET NULL,
    
    -- Ensure points amount is not zero
    CONSTRAINT chk_transaction_points 
        CHECK (points_amount != 0)
);

-- Indexes for better query performance
CREATE INDEX idx_transaction_wallet ON wallet_transaction_history(wallet_id);
CREATE INDEX idx_transaction_driver ON wallet_transaction_history(driver_id);
CREATE INDEX idx_transaction_date ON wallet_transaction_history(transaction_date);
CREATE INDEX idx_transaction_type ON wallet_transaction_history(transaction_type);
CREATE INDEX idx_transaction_status ON wallet_transaction_history(status);
CREATE INDEX idx_transaction_reference ON wallet_transaction_history(reference_id, reference_type);
CREATE INDEX idx_transaction_sponsor ON wallet_transaction_history(sponsor_id);