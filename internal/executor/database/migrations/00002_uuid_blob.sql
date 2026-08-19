-- +goose up
DROP TABLE debuglet_logs;
DROP TABLE debuglets;

CREATE TABLE debuglets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    start_time TIMESTAMP,
    args TEXT, -- comma-separated list of base64 encoded arguments
    wasm BLOB NOT NULL,
    transaction_id TEXT NOT NULL,
    -- policy
    floor_bw INTEGER NOT NULL,
    ceil_bw INTEGER NOT NULL,
    timeout_ms INTEGER NOT NULL,
    addresses TEXT, -- comma-separated list of addresses
    require_icmp BOOLEAN NOT NULL,
    listen_udp BOOLEAN NOT NULL,
    listen_tcp BOOLEAN NOT NULL,
    listen_icmp BOOLEAN NOT NULL,
    listen_scion BOOLEAN NOT NULL,

    started_at TIMESTAMP
);
CREATE INDEX debuglets_uuid_idx ON debuglets(uuid);

CREATE TABLE debuglet_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debuglet_id INTEGER NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    output BLOB NOT NULL
);

-- +goose down
DROP TABLE debuglet_logs;
DROP INDEX debuglets_uuid_idx;
DROP TABLE debuglets;

CREATE TABLE debuglets (
    id TEXT PRIMARY KEY,
    start_time TIMESTAMP,
    args TEXT, -- comma-separated list of base64 encoded arguments
    wasm BLOB NOT NULL,
    transaction_id TEXT NOT NULL,
    -- policy
    floor_bw INTEGER NOT NULL,
    ceil_bw INTEGER NOT NULL,
    timeout_ms INTEGER NOT NULL,
    addresses TEXT, -- comma-separated list of addresses
    require_icmp BOOLEAN NOT NULL,
    listen_udp BOOLEAN NOT NULL,
    listen_tcp BOOLEAN NOT NULL,
    listen_icmp BOOLEAN NOT NULL,
    listen_scion BOOLEAN NOT NULL,

    started_at TIMESTAMP
);

CREATE TABLE debuglet_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    debuglet_id TEXT NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    output BLOB NOT NULL
);
