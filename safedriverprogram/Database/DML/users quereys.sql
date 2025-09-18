-- ==============================================
-- USER AUTHENTICATION QUERIES FOR DJANGO
-- ==============================================

-- 1. USER LOGIN QUERIES
-- Check user credentials (username/email and password)
-- Query for login by username:

SELECT userID, username, email, password_hash, first_name, last_name, 
       account_type, is_active, is_email_verified, last_login_at
FROM users 
WHERE username = %s AND is_active = true;


-- Query for login by email:

SELECT userID, username, email, password_hash, first_name, last_name, 
       account_type, is_active, is_email_verified, last_login_at
FROM users 
WHERE email = %s AND is_active = true;


-- Update last login timestamp after successful login:

UPDATE users 
SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s;


-- 2. USER LOGOUT QUERIES
-- No specific SQL query needed for logout in Django (handled by session management)
-- Optional: Log logout activity (if you want to track logout times)

UPDATE users 
SET updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s;


-- 3. ACCOUNT CREATION QUERIES
-- Insert new user account:
INSERT INTO users (username, email, password_hash, first_name, last_name, 
                   phone_number, address, account_type, DOB, is_active, is_email_verified)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, true, false);
*/

-- Check if username already exists:

SELECT COUNT(*) as count 
FROM users 
WHERE username = %s;


-- Check if email already exists:

SELECT COUNT(*) as count 
FROM users 
WHERE email = %s;


-- Get newly created user:

SELECT userID, username, email, first_name, last_name, account_type, 
       is_active, is_email_verified, created_at
FROM users 
WHERE userID = LAST_INSERT_ID();


-- 4. FORGOT PASSWORD QUERIES
-- Create password reset token:

INSERT INTO password_reset_tokens (userID, token, expires_at)
VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 1 HOUR));


-- Verify password reset token:

SELECT prt.token_id, prt.userID, prt.expires_at, prt.used, u.email, u.username
FROM password_reset_tokens prt
JOIN users u ON prt.userID = u.userID
WHERE prt.token = %s 
  AND prt.expires_at > NOW() 
  AND prt.used = false 
  AND u.is_active = true;


-- Update password with reset token:

UPDATE users 
SET password_hash = %s, updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s AND is_active = true;


-- Mark reset token as used:

UPDATE password_reset_tokens 
SET used = true, updated_at = CURRENT_TIMESTAMP 
WHERE token = %s;


-- Get user by email for password reset:

SELECT userID, username, email, first_name, last_name 
FROM users 
WHERE email = %s AND is_active = true;


-- Clean up expired tokens (optional maintenance query):

DELETE FROM password_reset_tokens 
WHERE expires_at < NOW() OR used = true;


-- 5. ADDITIONAL UTILITY QUERIES
-- Activate user account (for email verification):

UPDATE users 
SET is_email_verified = true, updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s;

-- Deactivate user account:

UPDATE users 
SET is_active = false, updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s;


-- Get user profile by ID:

SELECT userID, username, email, first_name, last_name, phone_number, 
       address, avatar_image, account_type, DOB, is_active, 
       is_email_verified, last_login_at, created_at, updated_at
FROM users 
WHERE userID = %s AND is_active = true;


-- Update user profile:

UPDATE users 
SET first_name = %s, last_name = %s, phone_number = %s, 
    address = %s, avatar_image = %s, updated_at = CURRENT_TIMESTAMP 
WHERE userID = %s AND is_active = true;