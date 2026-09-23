-- +goose up
-- An enrolled executor ID is bound to the SHA-256 fingerprint of the client
-- certificate its node presents on both control channels. That binding is the
-- node identity, and control sessions, their generations and their leases all
-- stay separate from it.
CREATE TABLE executor_enrollments (
    executor_id TEXT NOT NULL PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    enrolled_at TIMESTAMP NOT NULL
);

-- A token bootstraps one binding and is then spent. Only the SHA-256 digest of
-- its secret half is stored, so the database never holds a usable token.
CREATE TABLE executor_enrollment_tokens (
    selector TEXT NOT NULL PRIMARY KEY,
    executor_id TEXT NOT NULL,
    secret_hash BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX executor_enrollment_tokens_executor_idx ON executor_enrollment_tokens(executor_id);

-- +goose down
DROP INDEX executor_enrollment_tokens_executor_idx;
DROP TABLE executor_enrollment_tokens;
DROP TABLE executor_enrollments;
