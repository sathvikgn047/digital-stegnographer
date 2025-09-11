CREATE DATABASE IF NOT EXISTS steganography_db;

USE steganography_db;

CREATE TABLE IF NOT EXISTS operations_log (
    operation_id INT AUTO_INCREMENT PRIMARY KEY,
    operation_type VARCHAR(10) NOT NULL,
    original_image_path VARCHAR(255) NOT NULL,
    stego_image_path VARCHAR(255),
    message_length INT,
    timestamp DATETIME NOT NULL
);

-- Note: Before running the Java application, you need to create a database user
-- and grant permissions. Replace 'your_db_user' and 'your_db_password' with your credentials.
-- Example:
-- CREATE USER 'your_db_user'@'localhost' IDENTIFIED BY 'your_db_password';
-- GRANT ALL PRIVILEGES ON steganography_db.* TO 'your_db_user'@'localhost';
-- FLUSH PRIVILEGES;
