-- name: CreateAPICredential :exec
INSERT INTO sessions (selector, verifier_hash, csrf_hash, user_id, created_at, expires_at, revoked, kind, audience, scopes, label)
VALUES (?, ?, X'', ?, ?, ?, 0, 'api', ?, ?, ?);

-- name: ListAccountCredentials :many
SELECT selector, kind, audience, scopes, label, created_at, expires_at
FROM sessions WHERE user_id = (SELECT id FROM users WHERE uuid = sqlc.arg(uuid))
  AND revoked = 0 AND expires_at > sqlc.arg(now)
ORDER BY created_at DESC LIMIT 100;

-- name: RevokeAccountCredential :execrows
UPDATE sessions SET revoked = 1
WHERE selector = sqlc.arg(selector) AND user_id = (SELECT id FROM users WHERE uuid = sqlc.arg(uuid));

-- name: CountAccountCredentials :one
SELECT COUNT(*) FROM sessions WHERE user_id = sqlc.arg(user_id)
  AND revoked = 0 AND expires_at > sqlc.arg(now);

-- name: CreateDeviceLogin :exec
INSERT INTO device_logins (selector, verifier_hash, user_code_hash, audience, scopes, label, expires_at, next_poll_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDeviceLogin :one
SELECT * FROM device_logins WHERE selector = ?;

-- name: GetDeviceLoginByUserCode :one
SELECT * FROM device_logins WHERE user_code_hash = ?;

-- name: UpdateDeviceLoginPoll :execrows
UPDATE device_logins SET next_poll_at = sqlc.arg(next_poll_at), poll_interval = sqlc.arg(poll_interval)
WHERE selector = sqlc.arg(selector) AND state IN ('pending', 'approved');

-- name: ApproveDeviceLogin :execrows
UPDATE device_logins SET state = 'approved', user_id = sqlc.arg(user_id)
WHERE selector = sqlc.arg(selector) AND state = 'pending' AND expires_at > sqlc.arg(now);

-- name: DenyDeviceLogin :execrows
UPDATE device_logins SET state = 'denied'
WHERE selector = sqlc.arg(selector) AND state = 'pending' AND expires_at > sqlc.arg(now);

-- name: CancelDeviceLogin :exec
UPDATE device_logins SET state = 'cancelled' WHERE selector = ? AND state IN ('pending', 'approved');

-- name: ConsumeDeviceLogin :execrows
UPDATE device_logins SET state = 'consumed'
WHERE selector = sqlc.arg(selector) AND state = 'approved' AND expires_at > sqlc.arg(now);

-- name: DeleteExpiredDeviceLogins :exec
DELETE FROM device_logins WHERE expires_at <= ?;

-- name: CountDeviceLogins :one
SELECT COUNT(*) FROM device_logins;
