-- +goose up
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

-- +goose down
DROP TABLE oauth_identities;
