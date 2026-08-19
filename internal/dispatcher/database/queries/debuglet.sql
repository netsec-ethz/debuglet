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

-- name: GetDebugletByUUID :one
SELECT * FROM debuglets
WHERE uuid = ?;

-- name: CreateDebuglet :one
INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateDebugletState :one
UPDATE debuglets
SET state = ?
WHERE uuid = ?
RETURNING *;

-- name: SetDebugletError :exec
UPDATE debuglets
SET error = ?
WHERE uuid = ?;

/*

LOGS

*/

-- name: CreateDebugletLog :one
INSERT INTO debuglet_logs (debuglet_id, timestamp, output)
VALUES (
    (SELECT id FROM debuglets WHERE uuid = ?), ?, ?
)
RETURNING *;

-- name: ListDebugletLogs :many
SELECT debuglet_logs.*
FROM debuglet_logs
INNER JOIN debuglets ON debuglet_logs.debuglet_id = debuglets.id
WHERE uuid = ? AND debuglet_logs.id > :after
ORDER BY debuglet_logs.id ASC
LIMIT ?;
