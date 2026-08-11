-- +goose up
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

CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY NOT NULL,
    auth_key TEXT NOT NULL,
    price INTEGER NOT NULL,
    method TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    paid BOOLEAN NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transaction_states (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- +goose down
-- reverse order of creation to prevent foreign key constraint issues
DROP TABLE debuglet_logs;
DROP TABLE debuglets;

DROP TABLE transaction_states;
DROP TABLE transactions;
