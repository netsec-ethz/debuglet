-- +goose up
ALTER TABLE oauth_identities RENAME TO oauth_identities_previous;
CREATE TABLE oauth_identities (
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL DEFAULT 'https://github.com',
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (issuer, subject),
    UNIQUE (provider, user_id)
);
INSERT INTO oauth_identities (provider, subject, user_id, login, created_at, updated_at)
SELECT provider, subject, user_id, login, created_at, updated_at FROM oauth_identities_previous;
DROP TABLE oauth_identities_previous;

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
ALTER TABLE oauth_identities RENAME TO oauth_identities_current;
CREATE TABLE oauth_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (provider, subject),
    UNIQUE (provider, user_id)
);
INSERT INTO oauth_identities SELECT provider, subject, user_id, login, created_at, updated_at FROM oauth_identities_current;
DROP TABLE oauth_identities_current;
