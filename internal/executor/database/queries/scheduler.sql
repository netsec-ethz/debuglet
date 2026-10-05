-- name: ListDebuglets :many
SELECT * FROM debuglets
WHERE NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid)
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
  AND dispatcher_incarnation <> '' AND session_id <> ''
  AND NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid);

-- name: UpdateDebugletStarted :one
UPDATE debuglets
SET started_at = ?
WHERE uuid = ? AND NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid)
RETURNING *;

-- name: DeleteDebuglet :exec
DELETE FROM debuglets
WHERE uuid = ? AND NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid);

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

-- name: CreateBoundedDebuglet :execrows
-- The durable rows are the reservations. Keeping the quota predicate inside
-- this INSERT makes concurrent admission and crash recovery use the same
-- accounting, without a separate counter that can drift from retained work.
-- Existing UUIDs still reach the UNIQUE constraint even when the queue is full.
INSERT INTO debuglets (
    uuid, start_time, args, wasm, transaction_id, floor_bw, ceil_bw, timeout_ms,
    addresses, require_icmp, listen_udp, listen_tcp, listen_scion,
    dispatcher_incarnation, session_id
)
SELECT sqlc.arg(uuid), sqlc.narg(start_time), sqlc.narg(args), sqlc.arg(wasm),
       sqlc.arg(transaction_id), sqlc.arg(floor_bw), sqlc.arg(ceil_bw),
       sqlc.arg(timeout_ms), sqlc.narg(addresses), sqlc.arg(require_icmp),
       sqlc.arg(listen_udp), sqlc.arg(listen_tcp), sqlc.arg(listen_scion),
       sqlc.arg(dispatcher_incarnation), sqlc.arg(session_id)
WHERE EXISTS (SELECT 1 FROM debuglets WHERE uuid = sqlc.arg(uuid))
   OR ((SELECT COUNT(*) FROM debuglets
        WHERE NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid)) < CAST(sqlc.arg(max_queued_runs) AS INTEGER)
       AND (SELECT COALESCE(SUM(
           length(wasm) + COALESCE(length(CAST(args AS BLOB)), 0)
           + COALESCE(length(CAST(addresses AS BLOB)), 0)
           + length(CAST(transaction_id AS BLOB))
           + length(CAST(dispatcher_incarnation AS BLOB))
           + length(CAST(session_id AS BLOB)) + 512), 0) FROM debuglets
           WHERE NOT EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = debuglets.uuid))
           <= CAST(sqlc.arg(max_queued_bytes) AS INTEGER) - CAST(sqlc.arg(queue_bytes) AS INTEGER));
