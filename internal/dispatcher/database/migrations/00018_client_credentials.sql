-- +goose up
ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser';
ALTER TABLE sessions ADD COLUMN audience TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN label TEXT NOT NULL DEFAULT '';

CREATE TABLE device_logins (
    selector TEXT PRIMARY KEY,
    verifier_hash BLOB NOT NULL,
    user_code_hash BLOB NOT NULL UNIQUE,
    audience TEXT NOT NULL,
    scopes TEXT NOT NULL,
    label TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    next_poll_at INTEGER NOT NULL,
    poll_interval INTEGER NOT NULL DEFAULT 5,
    state TEXT NOT NULL DEFAULT 'pending',
    approver_session TEXT NOT NULL DEFAULT '',
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX device_logins_expiry ON device_logins(expires_at);

-- +goose down
DROP TABLE device_logins;
DELETE FROM sessions WHERE kind = 'api';
ALTER TABLE sessions DROP COLUMN label;
ALTER TABLE sessions DROP COLUMN scopes;
ALTER TABLE sessions DROP COLUMN audience;
ALTER TABLE sessions DROP COLUMN kind;
