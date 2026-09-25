/*

CREDENTIALS

*/

-- name: UpsertUserCredential :exec
INSERT OR REPLACE INTO user_credentials (user_id, kind, selector, secret_hash, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetUserCredential :one
SELECT user_credentials.user_id, user_credentials.secret_hash,
       users.uuid, users.name, users.role
FROM user_credentials
INNER JOIN users ON users.id = user_credentials.user_id
WHERE user_credentials.selector = sqlc.arg(selector)
  AND user_credentials.kind = sqlc.arg(kind);

/*

SESSIONS

*/

-- name: CreateSession :exec
INSERT INTO sessions (selector, verifier_hash, csrf_hash, user_id, created_at, expires_at, revoked)
VALUES (?, ?, ?, ?, ?, ?, 0);

-- name: GetSessionBySelector :one
SELECT sessions.verifier_hash, sessions.csrf_hash, sessions.expires_at, sessions.revoked,
       users.uuid, users.name, users.role
FROM sessions
INNER JOIN users ON users.id = sessions.user_id
WHERE sessions.selector = ?;

-- name: RevokeSessionBySelector :exec
UPDATE sessions SET revoked = 1 WHERE selector = ?;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked = 1
WHERE user_id = (SELECT id FROM users WHERE users.uuid = sqlc.arg(uuid));

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < sqlc.arg(before);

/*

OWNERSHIP

*/

-- name: SetTransactionOwner :exec
INSERT OR REPLACE INTO transaction_users (transaction_id, user_id)
VALUES (sqlc.arg(transaction_id), (SELECT id FROM users WHERE users.uuid = sqlc.arg(uuid)));

-- name: GetTransactionOwnerUUID :one
SELECT users.uuid
FROM transaction_users
INNER JOIN users ON users.id = transaction_users.user_id
WHERE transaction_users.transaction_id = ?;

-- name: GetDebugletOwnerUUID :one
SELECT users.uuid
FROM debuglet_users
INNER JOIN users ON users.id = debuglet_users.user_id
INNER JOIN debuglets ON debuglets.id = debuglet_users.debuglet_id
WHERE debuglets.uuid = ?;

-- name: SetUserRole :execrows
UPDATE users SET role = sqlc.arg(role) WHERE uuid = sqlc.arg(uuid);
