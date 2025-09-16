Create table users {
	PRIMARY KEY userID int(6) AUTO_INCREMENT,
	username Varchar(30) NOT NULL UNIQUE,
	email VARCHAR(50) NOT NULL UNIQUE,
	password_hash varchar(50) NOT NULL,
    first_name varchar(50),
	last_name varchar(50), 
	phone_number varchar(20),
    address varchar(200),
	DOB DATE,
	is_active BOOLEAN DEFAULT true,
	is_email_verified BOOLEAN DEFAULT false,
	last_login_at TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	INDEX idx_username (username),
    INDEX idx_email (email)
};