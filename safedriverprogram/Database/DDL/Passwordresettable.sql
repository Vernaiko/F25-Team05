
-- Password reset tokens table for forgot password functionality
-- Essentially logs the password isn't stored and updated in this table
CREATE TABLE password_reset_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    userID INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userID) REFERENCES users(userID)
);