-- +goose up
-- A terminal result is retained under the run's immutable identity and its
-- original control binding until the executor knows the dispatcher accepted it.
-- The row therefore outlives the execution row it describes. A result the
-- dispatcher will never accept is kept as evidence and marked rejected.
CREATE TABLE debuglet_exits (
    debuglet_id TEXT NOT NULL PRIMARY KEY,
    dispatcher_incarnation TEXT NOT NULL,
    session_id TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    error_message TEXT,
    recorded_at TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP,
    last_error TEXT NOT NULL DEFAULT '',
    rejected BOOLEAN NOT NULL DEFAULT FALSE
);

-- A session reconciles only the results it accepted itself, oldest first.
CREATE INDEX debuglet_exits_binding_idx
    ON debuglet_exits(dispatcher_incarnation, session_id, recorded_at);

-- +goose down
DROP TABLE debuglet_exits;
