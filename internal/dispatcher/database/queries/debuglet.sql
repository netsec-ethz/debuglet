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

-- name: GetDebugletIdentityByUUID :one
SELECT executor_id, dispatcher_incarnation, session_id
FROM debuglets
WHERE uuid = ?;

-- name: GetOwnedDebugletByUUID :one
SELECT * FROM debuglets
WHERE uuid = sqlc.arg(uuid)
  AND executor_id = sqlc.arg(executor_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> '';

-- name: CreateDebuglet :one
INSERT INTO debuglets (uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, transaction_id, order_id, dispatcher_incarnation, session_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: CompleteDebuglet :one
UPDATE debuglets
SET state = sqlc.arg(exited_state), error = sqlc.narg(error)
WHERE uuid = sqlc.arg(uuid) AND state <> sqlc.arg(exited_state)
  AND executor_id = sqlc.arg(executor_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> ''
RETURNING *;

-- name: UpdateDebugletState :one
UPDATE debuglets SET state = sqlc.arg(state)
WHERE uuid = sqlc.arg(uuid) AND state <> sqlc.arg(exited_state)
  AND CASE state
    WHEN 0 THEN 0
    WHEN 3 THEN 1
    WHEN 4 THEN 2
    WHEN 1 THEN 3
    WHEN 2 THEN 4
    WHEN 5 THEN 5
    ELSE 999
  END < sqlc.arg(state_rank)
  AND executor_id = sqlc.arg(executor_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> ''
RETURNING *;

/*

LOGS

*/

-- name: CreateDebugletLog :one
INSERT INTO debuglet_logs (debuglet_id, timestamp, output)
SELECT id, sqlc.arg(timestamp), sqlc.arg(output)
FROM debuglets
WHERE uuid = sqlc.arg(uuid)
  AND executor_id = sqlc.arg(executor_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> ''
RETURNING *;

-- name: ListDebugletLogs :many
SELECT debuglet_logs.*
FROM debuglet_logs
INNER JOIN debuglets ON debuglet_logs.debuglet_id = debuglets.id
WHERE uuid = ? AND debuglet_logs.id > :after
ORDER BY debuglet_logs.id ASC
LIMIT ?;
