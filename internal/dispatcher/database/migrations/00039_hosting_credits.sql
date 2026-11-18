-- +goose Up
-- Server-observed hosting time and the last accounted authenticated session.
-- Grants remain in allowance_grants; this cursor prevents replay and carries
-- sub-unit rewards between observations without rounding each minute down.
CREATE TABLE allowance_hosting (
    executor_id TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    incarnation TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    observed_at INTEGER NOT NULL DEFAULT 0 CHECK (observed_at >= 0),
    observed_seconds INTEGER NOT NULL DEFAULT 0 CHECK (observed_seconds >= 0),
    credited INTEGER NOT NULL DEFAULT 0 CHECK (credited >= 0),
    remainder INTEGER NOT NULL DEFAULT 0 CHECK (remainder >= 0 AND remainder < 3600),
    PRIMARY KEY (executor_id, user_id)
);

-- +goose Down
DROP TABLE allowance_hosting;
