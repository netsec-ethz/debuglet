-- +goose up
DROP TABLE debuglet_logs;
DROP TABLE debuglets;

CREATE TABLE debuglets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    usage INTEGER NOT NULL,
    executor_id TEXT NOT NULL,
    addresses TEXT,
    state INTEGER NOT NULL,
    error TEXT
);
CREATE INDEX debuglets_uuid_idx ON debuglets(uuid);

CREATE TABLE debuglet_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debuglet_id INTEGER NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    output BLOB NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL
);
CREATE INDEX users_uuid_idx ON users(uuid);

CREATE TABLE debuglet_users (
    debuglet_id INTEGER NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

-- +goose down
DROP TABLE debuglet_users;
DROP INDEX users_uuid_idx;
DROP TABLE users;

DROP TABLE debuglet_logs;
DROP INDEX debuglets_uuid_idx;
DROP TABLE debuglets;

CREATE TABLE debuglets (
    id TEXT PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    usage INTEGER NOT NULL,
    executor_id TEXT NOT NULL,
    addresses TEXT, -- comma-separated list of addresses
    state INTEGER NOT NULL
);

CREATE TABLE debuglet_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debuglet_id TEXT NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    output BLOB NOT NULL
);
