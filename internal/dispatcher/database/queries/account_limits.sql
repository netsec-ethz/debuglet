-- name: ListAccountReservations :many
SELECT r.debuglet_id, r.queued_bytes, d.start_time, d.end_time
FROM account_run_reservations r JOIN debuglets d ON d.id = r.debuglet_id
WHERE r.account_id = ? AND r.retired_at IS NULL LIMIT 100001;

-- name: ReserveAccountRun :exec
INSERT INTO account_run_reservations(debuglet_id, account_id, queued_bytes)
VALUES (?, ?, ?);

-- name: RetireAccountRun :execrows
UPDATE account_run_reservations SET retired_at = ?
WHERE debuglet_id = ? AND retired_at IS NULL;

-- name: MarkRetirementCheck :exec
UPDATE account_run_reservations SET last_retirement_check = ? WHERE debuglet_id = ?;

-- name: ListRetirementCandidates :many
SELECT d.uuid FROM account_run_reservations r JOIN debuglets d ON d.id = r.debuglet_id
WHERE r.retired_at IS NULL AND d.state = 5
ORDER BY r.last_retirement_check, d.id LIMIT 4;

-- name: GetAccountRunReservation :one
SELECT * FROM account_run_reservations WHERE debuglet_id = ?;

-- name: GetPayloadTombstone :one
SELECT t.* FROM payload_tombstones t JOIN debuglets d ON d.id = t.debuglet_id
WHERE d.uuid = ?;

-- name: CreatePayloadTombstone :exec
INSERT INTO payload_tombstones(debuglet_id, deleted_at, reason, workload_sha256, certificate_sha256)
SELECT d.id, sqlc.arg(deleted_at), sqlc.arg(reason),
       json_extract(p.document, '$.workload_sha256'), json_extract(p.document, '$.certificate_sha256')
FROM debuglets d LEFT JOIN debuglet_provenance p ON p.debuglet_id = d.id
WHERE d.id = sqlc.arg(debuglet_id);

-- name: DeleteMeasurementLogs :exec
DELETE FROM debuglet_logs WHERE debuglet_id = ?;

-- name: DeleteMeasurementProvenance :exec
DELETE FROM debuglet_provenance WHERE debuglet_id = ?;

-- name: DeleteMeasurementTargets :exec
UPDATE debuglets SET addresses = NULL, error = sqlc.narg(public_error) WHERE id = sqlc.arg(debuglet_id);

-- name: ListExpiredPayloads :many
SELECT d.uuid FROM debuglets d
JOIN account_run_reservations r ON r.debuglet_id = d.id
JOIN debuglet_output o ON o.debuglet_id = d.id
LEFT JOIN payload_tombstones t ON t.debuglet_id = d.id
WHERE r.retired_at < sqlc.arg(before) AND d.state = 5
  AND o.final_sequence IS NOT NULL AND t.debuglet_id IS NULL
ORDER BY r.retired_at LIMIT 100;
