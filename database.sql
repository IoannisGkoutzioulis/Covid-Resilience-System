DROP DATABASE IF EXISTS PRS_System;
CREATE DATABASE IF NOT EXISTS PRS_System;
USE PRS_System;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    prs_id VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    national_id VARCHAR(20) UNIQUE NOT NULL,
    dob DATE NOT NULL,
    role ENUM('Admin', 'Official', 'Merchant', 'Citizen', 'Doctor') NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    city VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_prs_id (prs_id),
    INDEX idx_role (role),
    INDEX idx_national_id (national_id)
);

DROP TABLE IF EXISTS doctors;
CREATE TABLE doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    age INT,
    email VARCHAR(100),
    specialty VARCHAR(100),
    contact_phone VARCHAR(20),
    clinic_hospital VARCHAR(150),
    license_number VARCHAR(50),
    city VARCHAR(50),
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_name (name),
    INDEX idx_specialty (specialty),
    INDEX idx_city (city),
    INDEX idx_email (email)
);

DROP TABLE IF EXISTS government_officials;
CREATE TABLE government_officials (
    official_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    role VARCHAR(100) NOT NULL,
    contact_phone VARCHAR(20),
    contact_email VARCHAR(100),
    authorized_area VARCHAR(100),
    user_id INT,
    status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
    approved_by INT DEFAULT NULL,
    approved_at TIMESTAMP NULL DEFAULT NULL,
    rejection_reason TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (approved_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_name (first_name, last_name),
    INDEX idx_role (role),
    INDEX idx_status (status),
    INDEX idx_approved_by (approved_by),
    INDEX idx_authorized_area (authorized_area)
);

DROP TABLE IF EXISTS merchants;
CREATE TABLE merchants (
    merchant_id INT AUTO_INCREMENT PRIMARY KEY,
    prs_id VARCHAR(20) UNIQUE NOT NULL,
    merchant_name VARCHAR(100) NOT NULL,
    contact_email VARCHAR(100),
    contact_phone VARCHAR(20),
    city VARCHAR(50),
    business_license VARCHAR(100),
    user_id INT,
    status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
    approved_by INT DEFAULT NULL,
    approved_at TIMESTAMP NULL DEFAULT NULL,
    rejection_reason TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (approved_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_merchant_name (merchant_name),
    INDEX idx_prs_id (prs_id),
    INDEX idx_city (city),
    INDEX idx_status (status),
    INDEX idx_approved_by (approved_by)
);

DROP TABLE IF EXISTS stock;
CREATE TABLE stock (
    stock_id INT AUTO_INCREMENT PRIMARY KEY,
    merchant_id INT NOT NULL,
    item_name VARCHAR(100) NOT NULL,
    category ENUM('Medical', 'Grocery', 'Essential', 'Other') NOT NULL,
    unit_price DECIMAL(10, 2),
    quantity_available INT NOT NULL DEFAULT 0,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_updated TIMESTAMP GENERATED ALWAYS AS (updated_at) STORED,
    FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_merchant_id (merchant_id),
    INDEX idx_item_name (item_name),
    INDEX idx_category (category),
    INDEX idx_quantity (quantity_available)
);

DROP TABLE IF EXISTS vaccination_records;
CREATE TABLE vaccination_records (
    vaccination_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    vaccine_type VARCHAR(100) NOT NULL,
    dose_number INT NOT NULL,
    date_administered DATE NOT NULL,
    administered_by VARCHAR(100),
    batch_number VARCHAR(50),
    expiry_date DATE,
    side_effects TEXT,
    next_dose_due DATE,
    traveler_flag BOOLEAN DEFAULT FALSE,
    certification VARCHAR(255) DEFAULT NULL,
    notes TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_vaccine_type (vaccine_type),
    INDEX idx_date_administered (date_administered),
    INDEX idx_administered_by (administered_by),
    INDEX idx_traveler_flag (traveler_flag)
);

DROP TABLE IF EXISTS purchases;
CREATE TABLE purchases (
    purchase_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    merchant_id INT NOT NULL,
    item_name VARCHAR(100) NOT NULL,
    item_quantity INT NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL,
    total_price DECIMAL(10, 2) NOT NULL,
    purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    eligible_purchase BOOLEAN DEFAULT TRUE,
    stock_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (stock_id) REFERENCES stock(stock_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_merchant_id (merchant_id),
    INDEX idx_purchase_date (purchase_date),
    INDEX idx_item_name (item_name)
);

DROP TABLE IF EXISTS documents;
CREATE TABLE documents (
    document_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    document_name VARCHAR(150) NOT NULL,
    document_type ENUM('Vaccination Certificate', 'ID Document', 'Medical Report', 'Other') NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100),
    file_size BIGINT,
    hash_value VARCHAR(64),
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_verified BOOLEAN DEFAULT FALSE,
    verified_by INT,
    verified_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (verified_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_document_type (document_type),
    INDEX idx_is_verified (is_verified),
    INDEX idx_verified_by (verified_by),
    INDEX idx_hash_value (hash_value)
);

DROP TABLE IF EXISTS encryption_keys;
CREATE TABLE encryption_keys (
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    key_value TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INT,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_is_active (is_active)
);

DROP TABLE IF EXISTS critical_items;
CREATE TABLE critical_items (
    critical_item_id INT AUTO_INCREMENT PRIMARY KEY,
    merchant_id INT NOT NULL,
    stock_id INT NOT NULL,
    suggested_reason TEXT,
    status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
    reviewed_by INT,
    reviewed_at TIMESTAMP NULL,
    review_notes TEXT,
    suggested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (stock_id) REFERENCES stock(stock_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_merchant_id (merchant_id),
    INDEX idx_stock_id (stock_id),
    INDEX idx_status (status),
    INDEX idx_reviewed_by (reviewed_by)
);

DROP TABLE IF EXISTS access_logs;
CREATE TABLE access_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    access_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    location VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    additional_info TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_access_type (access_type),
    INDEX idx_success (success)
);

DROP TABLE IF EXISTS migrations;
CREATE TABLE migrations (
    migration_id INT AUTO_INCREMENT PRIMARY KEY,
    version VARCHAR(20) NOT NULL,
    description TEXT,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    applied_by INT,
    FOREIGN KEY (applied_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE,
    INDEX idx_version (version),
    INDEX idx_applied_at (applied_at)
);

INSERT INTO users (prs_id, full_name, national_id, dob, role, username, password, email, city, created_at) VALUES
('ADM0001', 'System Administrator', '0000000001', '1980-01-01', 'Admin', 'admin', 'TEMP_PLACEHOLDER', 'admin@covid-system.com', 'System', NOW()),
('PRS1001', 'Nikos Papadopoulos', '1234567890', '1990-05-15', 'Citizen', 'nikos_p', 'TEMP_PLACEHOLDER', 'nikos@example.com', 'Athens', NOW()),
('PRS1002', 'Maria Konstantinou', '2345678901', '1985-08-22', 'Citizen', 'maria_k', 'TEMP_PLACEHOLDER', 'maria@example.com', 'Thessaloniki', NOW()),
('DOC1001', 'Dr. Andreas Dimitriou', '3456789012', '1975-03-10', 'Doctor', 'dr_andreas', 'TEMP_PLACEHOLDER', 'andreas@hospital.gr', 'Athens', NOW()),
('OFF1001', 'Sofia Georgiou', '4567890123', '1982-12-01', 'Official', 'sofia_g', 'TEMP_PLACEHOLDER', 'sofia.g@gov.gr', 'Athens', NOW()),
('MER1001', 'Dimitris Ioannou', '5678901234', '1988-07-14', 'Merchant', 'dimitris_i', 'TEMP_PLACEHOLDER', 'dimitris@pharmacy.gr', 'Patras', NOW()),
('DOC1002', 'Dr. Elena Petrou', '6789012345', '1978-11-25', 'Doctor', 'dr_elena', 'TEMP_PLACEHOLDER', 'elena@medical.gr', 'Thessaloniki', NOW()),
('MER1002', 'Yannis Stavrou', '7890123456', '1983-04-30', 'Merchant', 'yannis_s', 'TEMP_PLACEHOLDER', 'yannis@market.gr', 'Larissa', NOW()),
('OFF1002', 'Katerina Michailidou', '8901234567', '1979-09-18', 'Official', 'katerina_m', 'TEMP_PLACEHOLDER', 'katerina@gov.gr', 'Patras', NOW()),
('PRS1003', 'Alexandros Kostas', '9012345678', '1992-12-03', 'Citizen', 'alex_k', 'TEMP_PLACEHOLDER', 'alex@example.com', 'Volos', NOW()),
('PRS1004', 'Christina Nikolaou', '0123456789', '1987-06-14', 'Citizen', 'christina_n', 'TEMP_PLACEHOLDER', 'christina@example.com', 'Rhodes', NOW()),
('DOC1003', 'Dr. Panagiotis Athanasiou', '1357924680', '1973-02-28', 'Doctor', 'dr_panagiotis', 'TEMP_PLACEHOLDER', 'panagiotis@clinic.gr', 'Heraklion', NOW());

INSERT INTO doctors (name, age, email, specialty, contact_phone, clinic_hospital, license_number, city, user_id) VALUES
('Dr. Andreas Dimitriou', 49, 'andreas@hospital.gr', 'General Medicine', '210-1234567', 'Athens General Hospital', 'MD12345', 'Athens', 4),
('Dr. Elena Petrou', 46, 'elena@medical.gr', 'Pediatrics', '2310-987654', 'Thessaloniki Medical Center', 'MD23456', 'Thessaloniki', 7),
('Dr. Panagiotis Athanasiou', 51, 'panagiotis@clinic.gr', 'Cardiology', '2810-555123', 'Heraklion Heart Clinic', 'MD34567', 'Heraklion', 12),
('Dr. Vasilis Karagiannis', 44, 'vasilis@hospital.gr', 'Internal Medicine', '2610-444567', 'Patras General Hospital', 'MD45678', 'Patras', NULL),
('Dr. Ioanna Theodorou', 38, 'ioanna@medical.gr', 'Dermatology', '22410-333789', 'Rhodes Medical Center', 'MD56789', 'Rhodes', NULL),
('Dr. Michalis Papanikolaou', 52, 'michalis@clinic.gr', 'Orthopedics', '24210-222456', 'Volos Orthopedic Clinic', 'MD67890', 'Volos', NULL);

INSERT INTO government_officials (first_name, last_name, role, contact_phone, contact_email, authorized_area, user_id, status, approved_by, approved_at) VALUES
('Sofia', 'Georgiou', 'Health Department Coordinator', '210-9876543', 'sofia.g@gov.gr', 'Athens Health Department', 5, 'Approved', 1, NOW()),
('Katerina', 'Michailidou', 'Supply Chain Officer', '2610-456789', 'katerina@gov.gr', 'Patras Regional Office', 9, 'Approved', 1, NOW()),
('Dimitris', 'Kostopoulos', 'Health Inspector', '2310-999888', 'dimitris.k@gov.gr', 'Thessaloniki Health Department', NULL, 'Pending', NULL, NULL),
('Maria', 'Angelopoulou', 'Emergency Coordinator', '210-111222', 'maria.a@gov.gr', 'Crisis Management Unit', NULL, 'Pending', NULL, NULL),
('Nikos', 'Vlachos', 'Public Safety Officer', '2810-777333', 'nikos.v@gov.gr', 'Heraklion Safety Department', NULL, 'Rejected', 1, NOW()),
('Anna', 'Papadaki', 'Administrative Officer', '22410-888444', 'anna.p@gov.gr', 'Rhodes Administrative Office', NULL, 'Approved', 1, NOW());

INSERT INTO merchants (prs_id, merchant_name, contact_email, contact_phone, city, business_license, user_id, status, approved_by, approved_at) VALUES
('MER1001', 'Dimitris Pharmacy', 'dimitris@pharmacy.gr', '2610-123456', 'Patras', 'BL12345', 6, 'Approved', 1, NOW()),
('MER1002', 'Yannis Market', 'yannis@market.gr', '2410-555666', 'Larissa', 'BL23456', 8, 'Approved', 1, NOW()),
('MER1003', 'Athens Medical Supplies', 'info@athensmedical.gr', '210-987654', 'Athens', 'BL34567', NULL, 'Pending', NULL, NULL),
('MER1004', 'Thessaloniki Health Store', 'contact@thesshealth.gr', '2310-777888', 'Thessaloniki', 'BL45678', NULL, 'Pending', NULL, NULL),
('MER1005', 'Crete Essentials', 'sales@creteessentials.gr', '2810-666999', 'Heraklion', 'BL56789', NULL, 'Rejected', 1, NOW()),
('MER1006', 'Rhodes Pharmacy Plus', 'info@rhodespharmacy.gr', '22410-333555', 'Rhodes', 'BL67890', NULL, 'Approved', 1, NOW());

INSERT INTO stock (merchant_id, item_name, category, unit_price, quantity_available, description) VALUES
(1, 'Surgical Face Masks', 'Medical', 0.50, 1000, 'Disposable 3-layer surgical masks'),
(1, '95% Alcohol Sanitizer', 'Medical', 3.50, 200, 'Hand sanitizer 500ml bottle'),
(2, 'N95 Respirator Masks', 'Medical', 2.50, 500, 'N95 filtering facepiece respirator'),
(2, 'Digital Thermometer', 'Medical', 15.00, 50, 'Non-contact infrared thermometer'),
(1, 'Latex Gloves', 'Medical', 0.25, 2000, 'Disposable latex examination gloves'),
(2, 'Vitamin C Tablets', 'Medical', 8.90, 75, '1000mg Vitamin C supplement');

INSERT INTO vaccination_records (user_id, vaccine_type, dose_number, date_administered, administered_by, batch_number, expiry_date, traveler_flag, certification, notes) VALUES
(2, 'Pfizer-BioNTech COVID-19', 1, '2023-03-15', 'Dr. Andreas Dimitriou', 'PF001', '2024-03-15', TRUE, 'WHO International Certificate', 'Cleared for international travel'),
(2, 'Pfizer-BioNTech COVID-19', 2, '2023-06-15', 'Dr. Andreas Dimitriou', 'PF002', '2024-06-15', TRUE, 'WHO International Certificate', 'Booster dose completed'),
(3, 'Moderna COVID-19', 1, '2023-04-10', 'Dr. Elena Petrou', 'MD001', '2024-04-10', TRUE, 'EU Digital COVID Certificate', 'Valid for EU travel'),
(10, 'Johnson & Johnson COVID-19', 1, '2023-05-20', 'Dr. Panagiotis Athanasiou', 'JJ001', '2024-05-20', FALSE, 'National Certificate', 'Single dose vaccine'),
(11, 'AstraZeneca COVID-19', 1, '2023-02-28', 'Dr. Andreas Dimitriou', 'AZ001', '2024-02-28', FALSE, NULL, 'First dose administered'),
(11, 'AstraZeneca COVID-19', 2, '2023-05-28', 'Dr. Andreas Dimitriou', 'AZ002', '2024-05-28', TRUE, 'National Certificate', 'Completed vaccination series');

INSERT INTO purchases (user_id, merchant_id, item_name, item_quantity, unit_price, total_price, stock_id, eligible_purchase) VALUES
(2, 1, 'Surgical Face Masks', 10, 0.50, 5.00, 1, TRUE),
(3, 1, '95% Alcohol Sanitizer', 2, 3.50, 7.00, 2, TRUE),
(10, 2, 'N95 Respirator Masks', 5, 2.50, 12.50, 3, TRUE),
(11, 1, 'Digital Thermometer', 1, 15.00, 15.00, 4, TRUE),
(2, 2, 'Latex Gloves', 20, 0.25, 5.00, 5, TRUE),
(3, 2, 'Vitamin C Tablets', 3, 8.90, 26.70, 6, TRUE);

INSERT INTO documents (user_id, document_name, document_type, file_path, mime_type, file_size, hash_value, is_verified, verified_by, verified_at) VALUES
(2, 'COVID-19 Vaccination Certificate', 'Vaccination Certificate', '/uploads/nikos_vaccine_cert.pdf', 'application/pdf', 245760, 'abc123def456', TRUE, 5, NOW()),
(3, 'National ID Copy', 'ID Document', '/uploads/maria_id.pdf', 'application/pdf', 189440, 'def456ghi789', TRUE, 5, NOW()),
(10, 'Medical History Report', 'Medical Report', '/uploads/alex_medical.pdf', 'application/pdf', 334566, 'ghi789jkl012', FALSE, NULL, NULL),
(11, 'Vaccination Certificate', 'Vaccination Certificate', '/uploads/christina_vaccine.pdf', 'application/pdf', 278543, 'jkl012mno345', TRUE, 9, NOW()),
(6, 'Business Registration Certificate', 'Other', '/uploads/dimitris_business.pdf', 'application/pdf', 156789, 'mno345pqr678', TRUE, 5, NOW()),
(8, 'Health Permit', 'Other', '/uploads/yannis_permit.pdf', 'application/pdf', 198765, 'pqr678stu901', FALSE, NULL, NULL);

INSERT INTO encryption_keys (key_value, is_active, created_by) VALUES
('base64encoded_key_001_' + MD5(RAND()), TRUE, 1),
('base64encoded_key_002_' + MD5(RAND()), TRUE, 1),
('base64encoded_key_003_' + MD5(RAND()), FALSE, 1),
('base64encoded_key_004_' + MD5(RAND()), TRUE, 5),
('base64encoded_key_005_' + MD5(RAND()), TRUE, 9),
('base64encoded_key_006_' + MD5(RAND()), FALSE, 5);

INSERT INTO critical_items (merchant_id, stock_id, suggested_reason, status, reviewed_by, reviewed_at, review_notes) VALUES
(1, 1, 'High demand for surgical masks due to flu season', 'Approved', 5, NOW(), 'Approved as essential medical supply'),
(2, 3, 'N95 masks are critical for healthcare workers', 'Approved', 5, NOW(), 'Priority item for medical professionals'),
(1, 2, 'Hand sanitizer shortage reported in local area', 'Pending', NULL, NULL, NULL),
(2, 4, 'Digital thermometers needed for temperature screening', 'Approved', 9, NOW(), 'Essential for health monitoring'),
(1, 5, 'Latex gloves shortage in medical facilities', 'Rejected', 5, NOW(), 'Sufficient stock available from other suppliers'),
(2, 6, 'Vitamin supplements boost immunity during pandemic', 'Pending', NULL, NULL, NULL);

INSERT INTO access_logs (user_id, access_type, ip_address, location, success, additional_info) VALUES
(1, 'Login', '192.168.1.100', 'Web Application', TRUE, 'Admin login successful'),
(2, 'Login', '192.168.1.101', 'Web Application', TRUE, 'Citizen login successful'),
(5, 'Merchant Approval', '192.168.1.100', 'Web Application', TRUE, 'Approved merchant ID: 1'),
(1, 'Official Approval', '192.168.1.100', 'Web Application', TRUE, 'Approved official ID: 1'),
(3, 'Document Upload', '192.168.1.102', 'Web Application', TRUE, 'Uploaded vaccination certificate'),
(6, 'Stock Update', '192.168.1.103', 'Web Application', TRUE, 'Updated inventory quantities');

INSERT INTO migrations (version, description, applied_by) VALUES
('1.0.0', 'Initial database structure created', 1),
('1.1.0', 'Added merchant approval system', 1),
('1.2.0', 'Enhanced vaccination tracking', 1),
('1.3.0', 'Added document management system', 1),
('1.4.0', 'Implemented critical items workflow', 1),
('1.5.0', 'Added official approval system with status tracking', 1);

SET FOREIGN_KEY_CHECKS = 1;