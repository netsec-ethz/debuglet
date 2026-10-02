-- name: ListUnreclaimedAllocations :many
SELECT d.* FROM debuglets d
WHERE d.state <> sqlc.arg(exited_state) AND d.end_time < sqlc.arg(end_time)
  AND d.dispatcher_incarnation <> '' AND d.session_id <> ''
  AND NOT EXISTS (SELECT 1 FROM allocation_reclamations r WHERE r.debuglet_id = d.id)
ORDER BY d.end_time, d.id LIMIT 100;

-- name: ReclaimAllocation :exec
INSERT INTO allocation_reclamations (debuglet_id, reclaimed_at)
SELECT id, sqlc.arg(reclaimed_at) FROM debuglets
WHERE uuid = sqlc.arg(uuid) AND state <> sqlc.arg(exited_state)
  AND executor_id = sqlc.arg(executor_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> ''
ON CONFLICT (debuglet_id) DO NOTHING;

-- name: GetAllocationReclamation :one
SELECT r.reclaimed_at FROM allocation_reclamations r JOIN debuglets d ON d.id = r.debuglet_id
WHERE d.uuid = ?;

-- name: GetReclaimedDebuglet :one
SELECT d.* FROM debuglets d JOIN allocation_reclamations r ON r.debuglet_id = d.id
WHERE d.uuid = ?;
