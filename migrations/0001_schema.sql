-- Migration number: 0001 	 2025-03-31T01:11:41.706Z

CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ulid TEXT NOT NULL,
    name TEXT NOT NULL,
    picture TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ulid)
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_ulid TEXT,
    email TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    picture TEXT,
    auth_code TEXT,
    auth_code_expires_at TIMESTAMP,
    auth_code_verified_at TIMESTAMP,
    refresh_token TEXT NOT NULL,
    access_token TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email, provider)
);

CREATE INDEX IF NOT EXISTS idx_users_account_ulid ON users (account_ulid);
CREATE INDEX IF NOT EXISTS idx_users_auth_code ON users (auth_code);
CREATE INDEX IF NOT EXISTS idx_users_refresh_token ON users (refresh_token);

CREATE TABLE system_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_ulid TEXT,
    title TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE context_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ulid TEXT NOT NULL,
    account_ulid TEXT,
    title TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ulid)
);