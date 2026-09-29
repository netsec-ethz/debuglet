-- +goose up
CREATE TABLE owned_executors (
    executor_id TEXT NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX owned_executors_user_idx ON owned_executors(user_id);

-- +goose down
DROP TABLE owned_executors;
