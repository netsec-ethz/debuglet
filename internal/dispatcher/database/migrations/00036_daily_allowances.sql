-- +goose Up
-- Approval belongs to an account, never to an executor's reported identity.
CREATE TABLE allowance_eligibility (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    researcher INTEGER NOT NULL CHECK (researcher IN (0, 1)),
    approved_by INTEGER NOT NULL REFERENCES users(id),
    updated_at INTEGER NOT NULL
);
CREATE TABLE hosting_approvals (
    executor_id TEXT PRIMARY KEY REFERENCES owned_executors(executor_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    approved_by INTEGER NOT NULL REFERENCES users(id),
    updated_at INTEGER NOT NULL
);
-- Record even a zero refill: spending later must not issue a second grant.
CREATE TABLE allowance_periods (
    user_id INTEGER NOT NULL REFERENCES users(id),
    period TEXT NOT NULL,
    researcher INTEGER NOT NULL CHECK (researcher IN (0, 1)),
    eligible_nodes INTEGER NOT NULL CHECK (eligible_nodes >= 0),
    ceiling INTEGER NOT NULL CHECK (ceiling >= 0),
    hosting_bonus INTEGER NOT NULL CHECK (hosting_bonus >= 0),
    granted INTEGER NOT NULL DEFAULT 0 CHECK (granted >= 0),
    decided_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, period)
);

-- +goose Down
DROP TABLE allowance_periods;
DROP TABLE hosting_approvals;
DROP TABLE allowance_eligibility;
