-- +goose up
CREATE TABLE debuglets (
    id TEXT PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    usage INTEGER NOT NULL,
    executor_id TEXT NOT NULL,
    addresses TEXT -- comma-separated list of addresses
);

CREATE TABLE IF NOT EXISTS transactions (
	transaction_id 	TEXT	PRIMARY KEY NOT NULL,
	auth_key		TEXT	NOT NULL,
	price			INTEGER NOT NULL,
	method			TEXT	NOT NULL,
	expires_at		TIMESTAMP	NOT NULL,
	paid			BOOLEAN	NOT NULL,
	hash			TEXT	NOT NULL
);

CREATE TABLE IF NOT EXISTS transaction_state (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- +goose down
DROP TABLE debuglets;
