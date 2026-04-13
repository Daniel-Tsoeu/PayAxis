-- ============================================================
-- Payroll Management System — Database Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS payroll_db;
USE payroll_db;

-- Person (base contact info)
CREATE TABLE IF NOT EXISTS person (
  person_id  INT PRIMARY KEY AUTO_INCREMENT,
  first_name VARCHAR(50)  NOT NULL,
  last_name  VARCHAR(50)  NOT NULL,
  phone      VARCHAR(15),
  email      VARCHAR(100) UNIQUE
);

-- Users (login accounts)
CREATE TABLE IF NOT EXISTS users (
  user_id   INT PRIMARY KEY AUTO_INCREMENT,
  person_id INT NOT NULL,
  username  VARCHAR(50) UNIQUE NOT NULL,
  FOREIGN KEY (person_id) REFERENCES person(person_id) ON DELETE CASCADE
);

-- Authentication
CREATE TABLE IF NOT EXISTS authentication (
  auth_id       INT PRIMARY KEY AUTO_INCREMENT,
  user_id       INT NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  last_login    DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Employee
CREATE TABLE IF NOT EXISTS employee (
  employee_id INT PRIMARY KEY AUTO_INCREMENT,
  user_id     INT NOT NULL UNIQUE,
  position    VARCHAR(50),
  hire_date   DATE,
  hourly_rate DECIMAL(10,2) DEFAULT 0.00,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Admin
CREATE TABLE IF NOT EXISTS admin (
  admin_id    INT PRIMARY KEY AUTO_INCREMENT,
  user_id     INT NOT NULL UNIQUE,
  admin_level INT DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Attendance
CREATE TABLE IF NOT EXISTS attendance (
  attendance_id INT PRIMARY KEY AUTO_INCREMENT,
  employee_id   INT NOT NULL,
  clock_in      DATETIME NOT NULL,
  clock_out     DATETIME,
  FOREIGN KEY (employee_id) REFERENCES employee(employee_id) ON DELETE CASCADE
);

-- Work Hours
CREATE TABLE IF NOT EXISTS workhours (
  work_id       INT PRIMARY KEY AUTO_INCREMENT,
  attendance_id INT NOT NULL UNIQUE,
  hours_worked  DECIMAL(5,2) NOT NULL,
  FOREIGN KEY (attendance_id) REFERENCES attendance(attendance_id) ON DELETE CASCADE
);

-- Payroll
CREATE TABLE IF NOT EXISTS payroll (
  payroll_id   INT PRIMARY KEY AUTO_INCREMENT,
  employee_id  INT NOT NULL,
  period_start DATE NOT NULL,
  period_end   DATE NOT NULL,
  total_hours  DECIMAL(10,2) DEFAULT 0,
  gross_pay    DECIMAL(10,2) DEFAULT 0,
  FOREIGN KEY (employee_id) REFERENCES employee(employee_id) ON DELETE CASCADE
);

-- Payroll Details (line items: bonuses, deductions)
CREATE TABLE IF NOT EXISTS payrolldetails (
  detail_id   INT PRIMARY KEY AUTO_INCREMENT,
  payroll_id  INT NOT NULL,
  description VARCHAR(100),
  amount      DECIMAL(10,2),
  FOREIGN KEY (payroll_id) REFERENCES payroll(payroll_id) ON DELETE CASCADE
);

-- Seed admin user (password: Admin@123)
INSERT IGNORE INTO person (person_id, first_name, last_name, email) VALUES (1, 'System', 'Admin', 'admin@company.com');
INSERT IGNORE INTO users (user_id, person_id, username) VALUES (1, 1, 'admin');
INSERT IGNORE INTO authentication (user_id, password_hash) VALUES (1, '$2b$10$Wm7l5MXvDUBIAeFzJHFLpOIggn2z7l4nmDJ0kp1a/e7dQwFNkSxEe');
INSERT IGNORE INTO admin (user_id, admin_level) VALUES (1, 1);
