-- ============================================================================
-- TEST WALLET DATA FOR DRIVERS 50, 52, 54
-- ============================================================================
-- This file contains INSERT statements to populate test data for the driver
-- wallet system with realistic transaction histories.
-- ============================================================================

-- ============================================================================
-- STEP 1: INSERT DRIVER WALLETS
-- ============================================================================

-- Driver 50: Moderate balance (250 points)
INSERT INTO driver_wallets (driver_id, points_balance, is_active, created_at, updated_at, last_transaction_date)
VALUES (50, 250, TRUE, '2024-01-15 10:00:00', '2024-10-20 14:30:00', '2024-10-20 14:30:00');

-- Driver 52: High balance (500 points)
INSERT INTO driver_wallets (driver_id, points_balance, is_active, created_at, updated_at, last_transaction_date)
VALUES (52, 500, TRUE, '2024-02-01 09:00:00', '2024-10-22 16:45:00', '2024-10-22 16:45:00');

-- Driver 54: Low balance (75 points)
INSERT INTO driver_wallets (driver_id, points_balance, is_active, created_at, updated_at, last_transaction_date)
VALUES (54, 75, TRUE, '2024-03-10 11:30:00', '2024-10-18 10:15:00', '2024-10-18 10:15:00');


-- ============================================================================
-- STEP 2: INSERT TRANSACTION HISTORY
-- ============================================================================

-- ----------------------------------------------------------------------------
-- DRIVER 50 TRANSACTIONS (Balance: 250 points)
-- ----------------------------------------------------------------------------

-- Transaction 1: Welcome bonus
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    1, 50, 'reward', 100, 0, 100,
    'Welcome bonus for joining the program', 'WELCOME-50', 'sponsor_reward', 3,
    'completed', '2024-01-15 10:15:00', 'sponsor_user'
);

-- Transaction 2: Safe driving streak
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    1, 50, 'reward', 50, 100, 150,
    '30 days safe driving streak', 'STREAK-30-50', 'sponsor_reward', 3,
    'completed', '2024-02-14 09:30:00', 'sponsor_user'
);

-- Transaction 3: Product purchase
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, status, transaction_date, processed_by
) VALUES (
    1, 50, 'purchase', -75, 150, 75,
    'Redeemed: $25 Gas Card', 'ORDER-1001', 'order',
    'completed', '2024-05-20 15:45:00', 'system'
);

-- Transaction 4: Monthly safety award
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    1, 50, 'reward', 100, 75, 175,
    'Monthly safety award - August', 'MONTHLY-AUG-50', 'sponsor_reward', 3,
    'completed', '2024-08-31 17:00:00', 'sponsor_user'
);

-- Transaction 5: Referral bonus
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, admin_id, status, transaction_date, processed_by, notes
) VALUES (
    1, 50, 'adjustment', 50, 175, 225,
    'Referral bonus - new driver signup', 'REF-BONUS-50', 'bonus', 1,
    'completed', '2024-09-15 11:20:00', 'admin', 'Referred driver ID 54'
);

-- Transaction 6: Training completion
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    1, 50, 'reward', 25, 225, 250,
    'Defensive driving course completed', 'TRAINING-50', 'sponsor_reward', 3,
    'completed', '2024-10-20 14:30:00', 'sponsor_user'
);


-- ----------------------------------------------------------------------------
-- DRIVER 52 TRANSACTIONS (Balance: 500 points)
-- ----------------------------------------------------------------------------

-- Transaction 1: Welcome bonus
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    2, 52, 'reward', 100, 0, 100,
    'Welcome to Safe Driver Program', 'WELCOME-52', 'sponsor_reward', 3,
    'completed', '2024-02-01 09:15:00', 'sponsor_user'
);

-- Transaction 2: Quarterly excellence award
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by, notes
) VALUES (
    2, 52, 'reward', 200, 100, 300,
    'Q1 Excellence Award - Top performer', 'Q1-AWARD-52', 'sponsor_reward', 3,
    'completed', '2024-03-31 16:00:00', 'sponsor_user', 'Highest safety score in Q1'
);

-- Transaction 3: Product purchase
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, status, transaction_date, processed_by
) VALUES (
    2, 52, 'purchase', -50, 300, 250,
    'Redeemed: Car Care Kit', 'ORDER-1025', 'order',
    'completed', '2024-04-15 10:20:00', 'system'
);

-- Transaction 4: Milestone achievement
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by, notes
) VALUES (
    2, 52, 'reward', 150, 250, 400,
    '100 safe trips milestone', 'MILESTONE-100-52', 'sponsor_reward', 3,
    'completed', '2024-06-20 13:45:00', 'sponsor_user', '100 consecutive safe trips'
);

-- Transaction 5: Penalty applied
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, admin_id, status, transaction_date, processed_by, notes
) VALUES (
    2, 52, 'penalty', -25, 400, 375,
    'Late monthly report submission', 'PENALTY-52-JUL', 'penalty', 1,
    'completed', '2024-07-10 09:00:00', 'admin', 'Report submitted 3 days late'
);

-- Transaction 6: Refund of penalty
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, admin_id, status, transaction_date, processed_by, notes
) VALUES (
    2, 52, 'refund', 25, 375, 400,
    'Penalty reversed - system error', 'REFUND-52-JUL', 'refund', 1,
    'completed', '2024-07-12 14:00:00', 'admin', 'Applied in error due to system date issue'
);

-- Transaction 7: Mentoring bonus
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    2, 52, 'reward', 75, 400, 475,
    'Mentoring new driver', 'MENTOR-52', 'bonus', 3,
    'completed', '2024-09-25 11:30:00', 'sponsor_user'
);

-- Transaction 8: Weekly perfect score
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    2, 52, 'reward', 25, 475, 500,
    'Perfect safety week', 'WEEKLY-52-OCT3', 'sponsor_reward', 3,
    'completed', '2024-10-22 16:45:00', 'sponsor_user'
);


-- ----------------------------------------------------------------------------
-- DRIVER 54 TRANSACTIONS (Balance: 75 points)
-- ----------------------------------------------------------------------------

-- Transaction 1: Welcome bonus
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by, notes
) VALUES (
    3, 54, 'reward', 50, 0, 50,
    'New driver welcome bonus', 'WELCOME-54', 'sponsor_reward', 3,
    'completed', '2024-03-10 11:45:00', 'sponsor_user', 'Referred by driver 50'
);

-- Transaction 2: First achievement
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    3, 54, 'reward', 30, 50, 80,
    'First 10 safe trips', 'FIRST10-54', 'sponsor_reward', 3,
    'completed', '2024-04-05 15:20:00', 'sponsor_user'
);

-- Transaction 3: Small purchase
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, status, transaction_date, processed_by
) VALUES (
    3, 54, 'purchase', -40, 80, 40,
    'Redeemed: Coffee shop gift card', 'ORDER-1102', 'order',
    'completed', '2024-06-12 13:10:00', 'system'
);

-- Transaction 4: Monthly reward
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    3, 54, 'reward', 20, 40, 60,
    'Safe driving month - July', 'MONTHLY-JUL-54', 'sponsor_reward', 3,
    'completed', '2024-07-31 18:00:00', 'sponsor_user'
);

-- Transaction 5: Penalty for late report
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, admin_id, status, transaction_date, processed_by, notes
) VALUES (
    3, 54, 'penalty', -10, 60, 50,
    'Late monthly report', 'PENALTY-54-AUG', 'penalty', 1,
    'completed', '2024-08-15 09:30:00', 'admin', 'Report 5 days late'
);

-- Transaction 6: Admin adjustment
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, admin_id, status, transaction_date, processed_by, notes
) VALUES (
    3, 54, 'adjustment', 5, 50, 55,
    'Correction - missed training bonus', 'ADJ-54-SEP', 'admin_adjustment', 1,
    'completed', '2024-09-20 10:00:00', 'admin', 'Training bonus not applied automatically'
);

-- Transaction 7: Recent reward
INSERT INTO wallet_transaction_history (
    wallet_id, driver_id, transaction_type, points_amount, points_before, points_after,
    description, reference_id, reference_type, sponsor_id, status, transaction_date, processed_by
) VALUES (
    3, 54, 'reward', 20, 55, 75,
    'Safe driving week', 'WEEKLY-54-OCT2', 'sponsor_reward', 3,
    'completed', '2024-10-18 10:15:00', 'sponsor_user'
);


-- ============================================================================
-- VERIFICATION QUERIES (uncomment to run)
-- ============================================================================

-- Check wallet balances:
-- SELECT driver_id, points_balance, is_active, last_transaction_date 
-- FROM driver_wallets 
-- WHERE driver_id IN (50, 52, 54);

-- Check transaction counts and totals:
-- SELECT driver_id, COUNT(*) as tx_count, SUM(points_amount) as total_change
-- FROM wallet_transaction_history
-- WHERE driver_id IN (50, 52, 54)
-- GROUP BY driver_id;

-- View all transactions:
-- SELECT driver_id, transaction_type, points_amount, points_after, 
--        description, transaction_date, status
-- FROM wallet_transaction_history
-- WHERE driver_id IN (50, 52, 54)
-- ORDER BY driver_id, transaction_date;

-- ============================================================================
-- NOTES:
-- ============================================================================
-- 1. wallet_id values (1, 2, 3) assume auto_increment starts at 1
--    Adjust if your database has different wallet_id values
--
-- 2. sponsor_id = 3 and admin_id = 1 must exist in users table
--    Change these to match actual user IDs in your database
--
-- 3. Transaction patterns:
--    - Driver 50: 6 transactions, balanced activity (250 pts)
--    - Driver 52: 8 transactions, high performer (500 pts)
--    - Driver 54: 7 transactions, newer driver (75 pts)
--
-- 4. All transaction types represented:
--    - reward: Points earned for achievements
--    - purchase: Points spent on products
--    - penalty: Points deducted for violations
--    - refund: Points returned for errors
--    - adjustment: Manual admin corrections
-- ============================================================================
