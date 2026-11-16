-- name: GetAssistantKey :one
SELECT encrypted_key FROM assistant_keys
WHERE user_id = (SELECT id FROM users WHERE uuid = sqlc.arg(uuid));

-- name: SetAssistantKey :exec
INSERT INTO assistant_keys (user_id, encrypted_key)
VALUES ((SELECT id FROM users WHERE uuid = sqlc.arg(uuid)), sqlc.arg(encrypted_key))
ON CONFLICT(user_id) DO UPDATE SET encrypted_key = excluded.encrypted_key;

-- name: DeleteAssistantKey :exec
DELETE FROM assistant_keys
WHERE user_id = (SELECT id FROM users WHERE uuid = sqlc.arg(uuid));
