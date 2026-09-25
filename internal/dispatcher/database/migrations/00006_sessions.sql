-- +goose up
-- Server-issued credentials replace the UUID cookie identity. Every credential
-- is a public selector plus a secret verifier. Only the verifier's SHA-256
-- digest is stored, so the database never holds a usable credential. Rows that
-- existed before this migration keep no credential and no owner, and are not
-- adopted by anyone.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

CREATE TABLE user_credentials (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    selector TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, kind)
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    selector TEXT NOT NULL UNIQUE,
    verifier_hash BLOB NOT NULL,
    csrf_hash BLOB NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE transaction_users (
    transaction_id TEXT NOT NULL PRIMARY KEY REFERENCES transactions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

-- +goose down
DROP TABLE transaction_users;
DROP INDEX sessions_user_idx;
DROP TABLE sessions;
DROP TABLE user_credentials;
ALTER TABLE users DROP COLUMN role;
