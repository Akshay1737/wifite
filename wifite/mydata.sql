
-- Create database
CREATE DATABASE ecommerce;

-- Select database
USE ecommerce;

-- Create customers table
CREATE TABLE customers (
    customer_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name INTEGER(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    phone VARCHAR(15),
    password_hash VARCHAR(255) NOT NULL,
    gender VARCHAR(20),
    date_of_birth DATE,
    address VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(10),
    country VARCHAR(100) DEFAULT 'India',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Insert sample customers
INSERT INTO customers
(first_name, last_name, email, phone, password_hash,
 gender, date_of_birth, address, city, state, postal_code)
VALUES
('Akshay', 'Kadam', 'akshay@example.com', '9000000001',
 'sample_hash_1', 'Male', '2004-05-15',
 'Main Road', 'Pune', 'Maharashtra', '411001'),

('Rahul', 'Sharma', 'rahul@example.com', '9000000002',
 'sample_hash_2', 'Male', '2002-08-20',
 'MG Road', 'Mumbai', 'Maharashtra', '400001'),

('Priya', 'Patil', 'priya@example.com', '9000000003',
 'sample_hash_3', 'Female', '2003-02-10',
 'College Road', 'Nashik', 'Maharashtra', '422001'),

('Sneha', 'Deshmukh', 'sneha@example.com', '9000000004',
 'sample_hash_4', 'Female', '2001-11-25',
 'FC Road', 'Pune', 'Maharashtra', '411004'),

('Amit', 'Verma', 'amit@example.com', '9000000005',
 'sample_hash_5', 'Male', '2000-06-30',
 'Station Road', 'Nagpur', 'Maharashtra', '440001');

-- Display all customers
SELECT * FROM customers;

-- Find customers from Pune
SELECT customer_id, first_name, last_name, email
FROM customers
WHERE city = 'Pune';

-- Find active customers
SELECT *
FROM customers
WHERE is_active = TRUE;

-- Count total customers
SELECT COUNT(*) AS total_customers
FROM customers;
