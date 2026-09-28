-- name: CreateTerminalCleanup :exec
INSERT INTO debuglet_terminal_cleanup (debuglet_id) VALUES (?);

-- name: GetTerminalCleanup :one
SELECT d.* FROM debuglets d
JOIN debuglet_terminal_cleanup c ON c.debuglet_id = d.id
WHERE d.uuid = ?;

-- name: ListTerminalCleanup :many
SELECT d.* FROM debuglets d
JOIN debuglet_terminal_cleanup c ON c.debuglet_id = d.id
ORDER BY d.id LIMIT ?;

-- name: DeleteTerminalCleanup :exec
DELETE FROM debuglet_terminal_cleanup WHERE debuglet_id = ?;
