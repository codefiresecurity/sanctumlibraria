-- database/schema.sql
CREATE DATABASE IF NOT EXISTS sanctumlibraria;
USE sanctumlibraria;

-- Users table for authentication
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Central books table for metadata (shared across users)
CREATE TABLE books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    isbn VARCHAR(20) UNIQUE,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    description TEXT,
    pages INT,
    cover_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- User-specific book entries
CREATE TABLE user_books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    book_id INT NOT NULL,
    status ENUM('to_read', 'in_progress', 'read') DEFAULT 'to_read',
    media_type ENUM('physical', 'electronic', 'audiobook') NOT NULL,
    link VARCHAR(255),
    duration_minutes INT,
    rating INT CHECK (rating BETWEEN 1 AND 5),
    notes TEXT,
    progress INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
    UNIQUE KEY (user_id, book_id)
) ENGINE=InnoDB;

-- Tags table (shared, for autofill)
CREATE TABLE tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
) ENGINE=InnoDB;

-- Junction for many-to-many tags per user_book
CREATE TABLE user_book_tags (
    user_book_id INT NOT NULL,
    tag_id INT NOT NULL,
    PRIMARY KEY (user_book_id, tag_id),
    FOREIGN KEY (user_book_id) REFERENCES user_books(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Relationships table (graph edges, per user, redundant for easy queries)
CREATE TABLE user_book_relationships (
    user_book_id INT NOT NULL,
    related_user_book_id INT NOT NULL,
    relation ENUM('before', 'same', 'after') NOT NULL,
    PRIMARY KEY (user_book_id, related_user_book_id, relation),
    FOREIGN KEY (user_book_id) REFERENCES user_books(id) ON DELETE CASCADE,
    FOREIGN KEY (related_user_book_id) REFERENCES user_books(id) ON DELETE CASCADE
) ENGINE=InnoDB;