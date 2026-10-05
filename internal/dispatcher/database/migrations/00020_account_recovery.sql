-- +goose up
-- Host administrators may restore access to credentialless historical accounts.
-- Keep the approval reference and outcome, never the recovery code itself.
CREATE TABLE account_recovery_audit (
    selector TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    case_reference TEXT NOT NULL UNIQUE,
    issued_by_uid INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER NOT NULL DEFAULT 0,
    revoked_by_uid INTEGER,
    revocation_reference TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX account_recovery_pending ON account_recovery_audit(user_id)
    WHERE consumed_at = 0 AND revoked_at = 0;

-- +goose down
DELETE FROM user_credentials WHERE selector IN (SELECT selector FROM account_recovery_audit);
DROP TABLE account_recovery_audit;
