-- name: ListDebuglets :many
SELECT * FROM debuglets
LIMIT ?
OFFSET ?;

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
    listen_icmp,
    listen_scion
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDebugletStarted :one
SELECT started_at FROM debuglets
WHERE uuid = ?;
