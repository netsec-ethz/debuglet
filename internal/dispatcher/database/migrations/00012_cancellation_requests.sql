-- +goose up
CREATE TABLE debuglet_cancellations (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    request_id TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    attempted_at INTEGER,
    acknowledged_at INTEGER,
    failure TEXT NOT NULL DEFAULT ''
);

-- +goose down
DROP TABLE debuglet_cancellations;
