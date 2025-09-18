-- Users table to store user information
-- Note: Passwords are hashed and need to be hashed by backend before storing in MySQL
CREATE TABLE users (
    userID int(6) AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(30) NOT NULL UNIQUE,
    email VARCHAR(50) NOT NULL UNIQUE,
    password_hash varchar(256) NOT NULL,
    first_name varchar(50),
    last_name varchar(50), 
    phone_number varchar(20),
    address varchar(200),
    avatar_image varchar(200),
    account_type ENUM('driver', 'sponsor', 'admin') DEFAULT 'driver',
    DOB DATE,
    is_active BOOLEAN DEFAULT true,
    is_email_verified BOOLEAN DEFAULT false,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
);
