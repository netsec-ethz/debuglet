-- name: FindExternalIdentity :one
SELECT user_id FROM oauth_identities WHERE issuer = ? AND subject = ?;

-- name: CreateExternalIdentity :exec
INSERT INTO oauth_identities (provider, issuer, subject, user_id, login, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: RefreshExternalIdentity :exec
UPDATE oauth_identities SET login = ?, updated_at = ? WHERE issuer = ? AND subject = ?;

-- name: ListExternalIdentities :many
SELECT provider, issuer, login, created_at FROM oauth_identities
WHERE user_id = (SELECT id FROM users WHERE uuid = ?) ORDER BY provider;

-- name: DeleteExternalIdentity :execrows
DELETE FROM oauth_identities WHERE provider = ? AND user_id = ?;

-- name: CountRecoveryCredentials :one
SELECT COUNT(*) FROM user_credentials WHERE user_id = ? AND kind IN ('account', 'recovery');

-- name: GetIdentitySession :one
SELECT sessions.user_id, sessions.created_at, sessions.authenticated_at, sessions.expires_at, sessions.revoked, users.uuid
FROM sessions INNER JOIN users ON users.id = sessions.user_id WHERE selector = ?;

-- name: CreateOAuthAttempt :execrows
INSERT INTO oauth_login_attempts (state_hash, provider, verifier, nonce, purpose, session_selector, expires_at)
SELECT sqlc.arg(state_hash), sqlc.arg(provider), sqlc.arg(verifier), sqlc.arg(nonce), sqlc.arg(purpose), sqlc.arg(session_selector), sqlc.arg(expires_at) WHERE (SELECT COUNT(*) FROM oauth_login_attempts) < 4096;

-- name: ConsumeOAuthAttempt :one
DELETE FROM oauth_login_attempts WHERE state_hash = ? AND provider = ? AND expires_at > ?
RETURNING verifier, nonce, purpose, session_selector;

-- name: DeleteExpiredOAuthAttempts :exec
DELETE FROM oauth_login_attempts WHERE expires_at <= ?;

-- name: StorePendingIdentityLink :exec
INSERT INTO pending_identity_links (user_id, provider, issuer, subject, login, session_selector, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (user_id, provider) DO UPDATE SET issuer = excluded.issuer, subject = excluded.subject,
    login = excluded.login, session_selector = excluded.session_selector, expires_at = excluded.expires_at;

-- name: ListPendingIdentityLinks :many
SELECT provider, login, expires_at FROM pending_identity_links
WHERE user_id = ? AND session_selector = ? AND expires_at > ? ORDER BY provider;

-- name: ConsumePendingIdentityLink :one
DELETE FROM pending_identity_links WHERE user_id = ? AND provider = ? AND session_selector = ? AND expires_at > ?
RETURNING issuer, subject, login;

-- name: DeleteExpiredIdentityLinks :exec
DELETE FROM pending_identity_links WHERE expires_at <= ?;
