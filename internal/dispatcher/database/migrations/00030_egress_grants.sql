-- +goose up
CREATE TABLE egress_clock (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    observed_at INTEGER NOT NULL
);
INSERT INTO egress_clock(id, observed_at) VALUES(1, 0);
-- Grants outlive measurement deletion and terminal results until their window ends.
CREATE TABLE egress_grants (
    run_uuid TEXT PRIMARY KEY NOT NULL,
    policy_hash TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    window_end INTEGER NOT NULL,
    grant_json BLOB NOT NULL
);
CREATE INDEX egress_grants_expiry ON egress_grants(window_end);
CREATE TABLE egress_reservations (
    run_uuid TEXT NOT NULL REFERENCES egress_grants(run_uuid) ON DELETE CASCADE,
    bucket TEXT NOT NULL,
    bits_per_second INTEGER NOT NULL CHECK(bits_per_second >= 0),
    burst_bytes INTEGER NOT NULL CHECK(burst_bytes >= 0),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    attempts_per_second INTEGER NOT NULL CHECK(attempts_per_second >= 0),
    attempt_burst INTEGER NOT NULL CHECK(attempt_burst >= 0),
    attempts INTEGER NOT NULL CHECK(attempts >= 0),
    targets INTEGER NOT NULL CHECK(targets >= 0),
    PRIMARY KEY(run_uuid, bucket)
);
-- +goose down
DROP TABLE egress_reservations;
DROP TABLE egress_grants;
DROP TABLE egress_clock;
