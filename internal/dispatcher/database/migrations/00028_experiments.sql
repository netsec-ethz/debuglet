-- +goose up
CREATE TABLE experiment_barriers (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    deadline_ns INTEGER NOT NULL,
    start_time_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE experiment_readiness (
    debuglet_id INTEGER PRIMARY KEY NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    metadata BLOB NOT NULL CHECK(length(metadata) <= 4096),
    ready_at_ns INTEGER NOT NULL
);
-- +goose down
DROP TABLE experiment_readiness;
DROP TABLE experiment_barriers;
