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

-- ============================================================================
-- TRIGGERS FOR DRIVER WALLET HISTORY TRACKING
-- ============================================================================
-- These triggers automatically log all wallet balance changes to the history table
-- Supports transactions, corrections, rebates, and administrative adjustments
-- ============================================================================

-- 1. TRIGGER FOR WALLET BALANCE UPDATES
DROP TRIGGER IF EXISTS log_wallet_balance_change;
DELIMITER //

CREATE TRIGGER log_wallet_balance_change
AFTER UPDATE ON driver_wallets
FOR EACH ROW
BEGIN
    DECLARE points_diff INT;
    DECLARE trans_type VARCHAR(50);
    DECLARE trans_description TEXT;
    
    -- Only log if points_balance actually changed
    IF OLD.points_balance != NEW.points_balance THEN
        -- Calculate the difference
        SET points_diff = NEW.points_balance - OLD.points_balance;
        
        -- Determine transaction type based on the change
        IF points_diff > 0 THEN
            SET trans_type = 'credit';
            SET trans_description = CONCAT('Points added: +', points_diff);
        ELSE
            SET trans_type = 'debit';
            SET trans_description = CONCAT('Points deducted: ', points_diff);
        END IF;
        
        -- Insert into wallet history
        INSERT INTO wallet_transaction_history (
            driver_id,
            transaction_type,
            points_amount,
            points_before,
            points_after,
            description,
            transaction_date,
            status
        ) VALUES (
            NEW.driver_id,
            trans_type,
            points_diff,
            OLD.points_balance,
            NEW.points_balance,
            trans_description,
            NOW(),
            'completed'
        );
    END IF;
END//

DELIMITER ;

-- 2. TRIGGER FOR NEW WALLET CREATION
DROP TRIGGER IF EXISTS log_wallet_creation;
DELIMITER //

CREATE TRIGGER log_wallet_creation
AFTER INSERT ON driver_wallets
FOR EACH ROW
BEGIN
    -- Log the initial wallet creation
    INSERT INTO wallet_transaction_history (
        driver_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        transaction_date,
        status
    ) VALUES (
        NEW.driver_id,
        'creation',
        NEW.points_balance,
        0,
        NEW.points_balance,
        CONCAT('Wallet created with initial balance: ', NEW.points_balance, ' points'),
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- 3. TRIGGER FOR WALLET DEACTIVATION
DROP TRIGGER IF EXISTS log_wallet_deactivation;
DELIMITER //

CREATE TRIGGER log_wallet_deactivation
AFTER UPDATE ON driver_wallets
FOR EACH ROW
BEGIN
    -- Log when wallet is deactivated
    IF OLD.is_active = TRUE AND NEW.is_active = FALSE THEN
        INSERT INTO wallet_transaction_history (
            driver_id,
            transaction_type,
            points_amount,
            points_before,
            points_after,
            description,
            transaction_date,
            status
        ) VALUES (
            NEW.driver_id,
            'deactivation',
            0,
            NEW.points_balance,
            NEW.points_balance,
            CONCAT('Wallet deactivated. Final balance: ', NEW.points_balance, ' points'),
            NOW(),
            'completed'
        );
    END IF;
    
    -- Log when wallet is reactivated
    IF OLD.is_active = FALSE AND NEW.is_active = TRUE THEN
        INSERT INTO wallet_transaction_history (
            driver_id,
            transaction_type,
            points_amount,
            points_before,
            points_after,
            description,
            transaction_date,
            status
        ) VALUES (
            NEW.driver_id,
            'reactivation',
            0,
            NEW.points_balance,
            NEW.points_balance,
            CONCAT('Wallet reactivated. Current balance: ', NEW.points_balance, ' points'),
            NOW(),
            'completed'
        );
    END IF;
END//

DELIMITER ;

-- ============================================================================
-- STORED PROCEDURES FOR COMMON WALLET OPERATIONS
-- ============================================================================
-- These procedures ensure proper history logging for all transaction types
-- ============================================================================

-- Procedure: Award points (by sponsor)
DROP PROCEDURE IF EXISTS award_points_to_driver;
DELIMITER //

CREATE PROCEDURE award_points_to_driver(
    IN p_driver_id INT,
    IN p_sponsor_id INT,
    IN p_points INT,
    IN p_reason VARCHAR(255),
    IN p_reference_id VARCHAR(100)
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id AND is_active = TRUE
    FOR UPDATE;
    
    -- Calculate new balance
    SET new_balance = current_balance + p_points;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history with sponsor info
    INSERT INTO wallet_transaction_history (
        driver_id,
        sponsor_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        p_sponsor_id,
        'reward',
        p_points,
        current_balance,
        new_balance,
        COALESCE(p_reason, 'Points awarded by sponsor'),
        p_reference_id,
        'sponsor_award',
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- Procedure: Deduct points (purchase)
DROP PROCEDURE IF EXISTS deduct_points_from_driver;
DELIMITER //

CREATE PROCEDURE deduct_points_from_driver(
    IN p_driver_id INT,
    IN p_points INT,
    IN p_order_id INT,
    IN p_description VARCHAR(255)
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id AND is_active = TRUE
    FOR UPDATE;
    
    -- Check sufficient balance
    IF current_balance < p_points THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Insufficient points balance';
    END IF;
    
    -- Calculate new balance
    SET new_balance = current_balance - p_points;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history
    INSERT INTO wallet_transaction_history (
        driver_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        'purchase',
        -p_points,
        current_balance,
        new_balance,
        COALESCE(p_description, 'Points redeemed for purchase'),
        CONCAT('ORDER-', p_order_id),
        'order',
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- Procedure: Admin correction/adjustment
DROP PROCEDURE IF EXISTS adjust_driver_points;
DELIMITER //

CREATE PROCEDURE adjust_driver_points(
    IN p_driver_id INT,
    IN p_admin_id INT,
    IN p_points_adjustment INT,
    IN p_reason VARCHAR(255),
    IN p_notes TEXT
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    DECLARE adj_type VARCHAR(50);
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id
    FOR UPDATE;
    
    -- Calculate new balance
    SET new_balance = current_balance + p_points_adjustment;
    
    -- Ensure non-negative balance
    IF new_balance < 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Adjustment would result in negative balance';
    END IF;
    
    -- Determine adjustment type
    IF p_points_adjustment > 0 THEN
        SET adj_type = 'adjustment_credit';
    ELSE
        SET adj_type = 'adjustment_debit';
    END IF;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history with admin info
    INSERT INTO wallet_transaction_history (
        driver_id,
        admin_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        notes,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        p_admin_id,
        adj_type,
        p_points_adjustment,
        current_balance,
        new_balance,
        COALESCE(p_reason, 'Administrative points adjustment'),
        CONCAT('ADMIN-ADJ-', p_admin_id, '-', UNIX_TIMESTAMP()),
        'admin_adjustment',
        p_notes,
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- Procedure: Process rebate
DROP PROCEDURE IF EXISTS process_driver_rebate;
DELIMITER //

CREATE PROCEDURE process_driver_rebate(
    IN p_driver_id INT,
    IN p_sponsor_id INT,
    IN p_rebate_points INT,
    IN p_reason VARCHAR(255),
    IN p_reference_id VARCHAR(100)
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id AND is_active = TRUE
    FOR UPDATE;
    
    -- Calculate new balance
    SET new_balance = current_balance + p_rebate_points;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history
    INSERT INTO wallet_transaction_history (
        driver_id,
        sponsor_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        p_sponsor_id,
        'rebate',
        p_rebate_points,
        current_balance,
        new_balance,
        COALESCE(p_reason, 'Rebate processed'),
        p_reference_id,
        'rebate',
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- Procedure: Apply penalty
DROP PROCEDURE IF EXISTS apply_driver_penalty;
DELIMITER //

CREATE PROCEDURE apply_driver_penalty(
    IN p_driver_id INT,
    IN p_sponsor_id INT,
    IN p_penalty_points INT,
    IN p_reason VARCHAR(255),
    IN p_notes TEXT
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id AND is_active = TRUE
    FOR UPDATE;
    
    -- Calculate new balance (penalty is negative)
    SET new_balance = current_balance - p_penalty_points;
    
    -- Ensure non-negative balance
    IF new_balance < 0 THEN
        SET new_balance = 0;
    END IF;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history
    INSERT INTO wallet_transaction_history (
        driver_id,
        sponsor_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        notes,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        p_sponsor_id,
        'penalty',
        -p_penalty_points,
        current_balance,
        new_balance,
        COALESCE(p_reason, 'Penalty applied'),
        CONCAT('PENALTY-', p_driver_id, '-', UNIX_TIMESTAMP()),
        'penalty',
        p_notes,
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- Procedure: Refund points
DROP PROCEDURE IF EXISTS refund_driver_points;
DELIMITER //

CREATE PROCEDURE refund_driver_points(
    IN p_driver_id INT,
    IN p_points INT,
    IN p_original_transaction_id INT,
    IN p_reason VARCHAR(255),
    IN p_admin_id INT
)
BEGIN
    DECLARE current_balance INT;
    DECLARE new_balance INT;
    
    -- Get current balance
    SELECT points_balance INTO current_balance
    FROM driver_wallets
    WHERE driver_id = p_driver_id
    FOR UPDATE;
    
    -- Calculate new balance
    SET new_balance = current_balance + p_points;
    
    -- Update wallet
    UPDATE driver_wallets
    SET points_balance = new_balance,
        last_transaction_date = NOW()
    WHERE driver_id = p_driver_id;
    
    -- Log to history
    INSERT INTO wallet_transaction_history (
        driver_id,
        admin_id,
        transaction_type,
        points_amount,
        points_before,
        points_after,
        description,
        reference_id,
        reference_type,
        transaction_date,
        status
    ) VALUES (
        p_driver_id,
        p_admin_id,
        'refund',
        p_points,
        current_balance,
        new_balance,
        COALESCE(p_reason, 'Points refunded'),
        CONCAT('REFUND-TXN-', p_original_transaction_id),
        'refund',
        NOW(),
        'completed'
    );
END//

DELIMITER ;

-- ============================================================================
-- USAGE EXAMPLES
-- ============================================================================

/*
-- Award points to driver
CALL award_points_to_driver(50, 3, 100, 'Safe driving bonus', 'BONUS-2024-11');

-- Deduct points for purchase
CALL deduct_points_from_driver(50, 75, 1001, 'Gas card purchase');

-- Admin correction
CALL adjust_driver_points(50, 1, 50, 'Correction for missed award', 'Driver completed challenge but points not awarded');

-- Process rebate
CALL process_driver_rebate(50, 3, 25, 'Quarterly rebate program', 'REBATE-Q4-2024');

-- Apply penalty
CALL apply_driver_penalty(54, 3, 10, 'Late report submission', 'Report submitted 5 days late');

-- Refund points
CALL refund_driver_points(50, 75, 123, 'Order cancelled', 1);
*/