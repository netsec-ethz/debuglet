-- name: ListDebuglets :many
SELECT * FROM debuglets
LIMIT ?
OFFSET ?;

-- name: GetDebugletByUUID :one
SELECT * FROM debuglets
WHERE uuid = ?;

-- name: GetOwnedDebugletByUUID :one
SELECT * FROM debuglets
WHERE uuid = sqlc.arg(uuid)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> '';

-- name: UpdateDebugletStarted :one
UPDATE debuglets
SET started_at = ?
WHERE uuid = ?
RETURNING *;

-- name: DeleteDebuglet :exec
DELETE FROM debuglets
WHERE uuid = ?;

-- name: CreateDebuglet :exec
INSERT INTO debuglets (
    uuid,
    start_time,
    args,
    wasm,
    transaction_id,
    floor_bw,
    ceil_bw,
    timeout_ms,
    addresses,
    require_icmp,
    listen_udp,
    listen_tcp,
    listen_scion,
    dispatcher_incarnation,
    session_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDebugletIdentity :one
-- Identity, original binding and start marker only: inspection never reads the
-- stored WASM blob or arguments.
SELECT uuid, dispatcher_incarnation, session_id, transaction_id, start_time, started_at
FROM debuglets
WHERE uuid = ?;

-- name: GetDebugletStarted :one
SELECT started_at FROM debuglets
WHERE uuid = ?;
