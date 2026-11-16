-- +goose Up
CREATE TABLE assistant_keys (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key BLOB NOT NULL CHECK(length(encrypted_key) BETWEEN 30 AND 8256)
);

-- +goose Down
DROP TABLE assistant_keys;
