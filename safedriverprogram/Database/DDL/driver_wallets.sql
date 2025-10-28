CREATE TABLE driver_wallets (
    wallet_id INT AUTO_INCREMENT PRIMARY KEY,
    driver_id INT NOT NULL,
    points_balance INT NOT NULL DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_transaction_date TIMESTAMP NULL,
    
    -- Foreign key to users table
    CONSTRAINT fk_wallet_driver 
        FOREIGN KEY (driver_id) 
        REFERENCES users(userID) 
        ON DELETE CASCADE,
    
    -- Ensure non-negative points
    CONSTRAINT chk_positive_points 
        CHECK (points_balance >= 0),
    
    -- One wallet per driver
    CONSTRAINT unique_driver_wallet 
        UNIQUE (driver_id)
);

-- Index for faster lookups
CREATE INDEX idx_driver_wallet_active ON driver_wallets(driver_id, is_active);
CREATE INDEX idx_wallet_points ON driver_wallets(points_balance);