-- Create the database
CREATE DATABASE IF NOT EXISTS mydb;
USE mydb;

-- Create the 'alunos' table
CREATE TABLE IF NOT EXISTS alunos (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nome VARCHAR(255) NOT NULL,
    foto VARCHAR(255),
    userId INT,
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- Create the 'eventos' table
CREATE TABLE IF NOT EXISTS eventos (
    id INT PRIMARY KEY AUTO_INCREMENT,
    titulo VARCHAR(255) NOT NULL,
    descricao TEXT,
    data DATE,
    userId INT,
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- Create the 'gallery' table
CREATE TABLE IF NOT EXISTS gallery (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255) NOT NULL,
    filepath VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the 'students' table
CREATE TABLE IF NOT EXISTS students (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    photo VARCHAR(255)
);

-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'student', 'visitor') NOT NULL
);
