-- +goose up
ALTER TABLE oauth_identities ADD COLUMN issuer TEXT NOT NULL DEFAULT 'https://github.com';
CREATE UNIQUE INDEX oauth_identity_issuer_subject ON oauth_identities (issuer, subject);

CREATE TABLE oauth_login_attempts (
    state_hash BLOB PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link')),
    session_selector TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX oauth_login_expiry ON oauth_login_attempts (expires_at);

CREATE TABLE pending_identity_links (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    login TEXT NOT NULL,
    session_selector TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, provider)
);

-- +goose down
DROP TABLE pending_identity_links;
DROP TABLE oauth_login_attempts;
DROP INDEX oauth_identity_issuer_subject;
ALTER TABLE oauth_identities DROP COLUMN issuer;
