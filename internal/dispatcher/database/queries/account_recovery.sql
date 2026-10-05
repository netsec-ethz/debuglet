-- name: LockAccountForRecovery :execrows
UPDATE users SET name = name WHERE uuid = ?;

-- name: GetUnmappedAccountForRecovery :one
SELECT users.* FROM users WHERE uuid = ?
  AND NOT EXISTS (SELECT 1 FROM user_credentials WHERE user_id = users.id)
  AND NOT EXISTS (SELECT 1 FROM oauth_identities WHERE user_id = users.id)
  AND NOT EXISTS (SELECT 1 FROM account_recovery_audit WHERE user_id = users.id
                  AND consumed_at = 0 AND revoked_at = 0);

-- name: RecordAdminAccountRecovery :exec
INSERT INTO account_recovery_audit (selector, user_id, case_reference, issued_by_uid, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ConsumeAdminAccountRecovery :exec
UPDATE account_recovery_audit SET consumed_at = unixepoch() WHERE selector = ?;

-- name: RevokeAdminAccountRecovery :one
UPDATE account_recovery_audit SET revoked_at = unixepoch(), revoked_by_uid = ?, revocation_reference = ?
WHERE user_id = (SELECT id FROM users WHERE uuid = ?) AND consumed_at = 0 AND revoked_at = 0
RETURNING selector;

-- name: DeleteAdminRecoveryCredential :exec
DELETE FROM user_credentials WHERE kind = 'recovery' AND selector = ?;
