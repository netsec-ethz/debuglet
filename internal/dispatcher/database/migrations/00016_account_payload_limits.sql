-- +goose up
-- Identity-keyed reservations survive request cancellation, reconnect and
-- dispatcher restart. Terminal state alone does not prove executor retirement.
-- Account zero is the explicit local-development / historical ownerless bucket.
CREATE TABLE account_run_reservations (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    account_id INTEGER NOT NULL,
    queued_bytes INTEGER NOT NULL CHECK (queued_bytes >= 0),
    retired_at INTEGER,
    last_retirement_check INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX account_run_reservations_live ON account_run_reservations(account_id)
WHERE retired_at IS NULL;

-- Earlier dispatchers did not retain the uploaded module size. Charge the
-- maximum stored run size rather than assume that it costs nothing. Historical
-- work is retired only after an authenticated inspection confirms absence.
INSERT INTO account_run_reservations(debuglet_id, account_id, queued_bytes)
SELECT d.id, COALESCE((SELECT MIN(user_id) FROM debuglet_users WHERE debuglet_id = d.id), 0),
       33554432
FROM debuglets d;

CREATE TABLE payload_tombstones (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    deleted_at INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('owner_requested', 'retention_expired')),
    workload_sha256 TEXT,
    certificate_sha256 TEXT
);
-- +goose StatementBegin
CREATE TRIGGER payload_tombstones_immutable BEFORE UPDATE ON payload_tombstones
BEGIN
    SELECT RAISE(ABORT, 'payload deletion reference is immutable');
END;
-- +goose StatementEnd

-- +goose down
DROP TRIGGER payload_tombstones_immutable;
DROP TABLE payload_tombstones;
DROP INDEX account_run_reservations_live;
DROP TABLE account_run_reservations;
