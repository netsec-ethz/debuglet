/*

DEBUGLET

*/

-- name: ListDebuglets :many
SELECT * FROM debuglets
LIMIT ?
OFFSET ?;

-- name: ListDebugletsEndAfter :many
SELECT * FROM debuglets
WHERE end_time > ?;

-- name: GetDebugletByID :one
SELECT * FROM debuglets
WHERE id = ?;

-- name: CreateDebuglet :one
INSERT INTO debuglets (id, start_time, end_time, usage, executor_id, addresses, state)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateDebugletState :one
UPDATE debuglets
SET state = ?
WHERE id = ?
RETURNING *;

/*

LOGS

*/

-- name: CreateDebugletLog :one
INSERT INTO debuglet_logs (debuglet_id, timestamp, output)
VALUES (?, ?, ?)
RETURNING *;

-- name: ListDebugletLogs :many
SELECT id, debuglet_id, timestamp, output
FROM debuglet_logs
WHERE debuglet_id = ? AND id > ?
ORDER BY id ASC
LIMIT ?;
