-- +goose up
-- Usage allowances: grants of TEST units an operator issued to an account,
-- each with the operator, a reason and the idempotency key that makes a
-- repeated request issue it once. An account's ceiling is the sum of its
-- grants; what it reserved and consumed is read from its orders. Rows are
-- never changed or removed.
CREATE TABLE allowance_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL,
    granted_by INTEGER NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    UNIQUE (user_id, idempotency_key)
);
-- +goose StatementBegin
CREATE TRIGGER allowance_grants_immutable BEFORE UPDATE ON allowance_grants
BEGIN
    SELECT RAISE(ABORT, 'allowance grant is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER allowance_grants_retained BEFORE DELETE ON allowance_grants
BEGIN
    SELECT RAISE(ABORT, 'allowance grant is immutable');
END;
-- +goose StatementEnd

-- +goose down
DROP TRIGGER allowance_grants_retained;
DROP TRIGGER allowance_grants_immutable;
DROP TABLE allowance_grants;
