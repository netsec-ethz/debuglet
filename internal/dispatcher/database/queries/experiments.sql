-- name: GetExperimentBarrier :one
SELECT * FROM experiment_barriers WHERE transaction_id = ?;

-- name: CreateExperimentBarrier :exec
INSERT INTO experiment_barriers(transaction_id, deadline_ns) VALUES (?, ?)
ON CONFLICT(transaction_id) DO NOTHING;

-- name: ReleaseExperiment :exec
UPDATE experiment_barriers SET start_time_ns = ?
WHERE transaction_id = ? AND start_time_ns = 0;

-- name: RecordExperimentReady :exec
INSERT INTO experiment_readiness(debuglet_id, metadata, ready_at_ns) VALUES (?, ?, ?)
ON CONFLICT(debuglet_id) DO NOTHING;

-- name: CountExperimentOrders :one
SELECT count(*) FROM debuglet_order WHERE transaction_id = ?;

-- name: GetExperimentMembers :many
SELECT sqlc.embed(d), r.metadata, r.ready_at_ns,
 EXISTS(SELECT 1 FROM debuglet_cancellations c WHERE c.debuglet_id = d.id) AS cancelled,
 EXISTS(SELECT 1 FROM allocation_reclamations a WHERE a.debuglet_id = d.id) AS reclaimed
FROM debuglet_order o JOIN debuglets d ON d.id = o.debuglet_id
 AND d.transaction_id = o.transaction_id AND d.order_id = o.order_id
LEFT JOIN experiment_readiness r ON r.debuglet_id = d.id
WHERE o.transaction_id = ? ORDER BY o.order_id LIMIT 129;

-- name: PruneExperimentMetadata :exec
DELETE FROM experiment_readiness WHERE debuglet_id IN (
 SELECT r.debuglet_id FROM experiment_readiness r
 JOIN debuglets d ON d.id = r.debuglet_id
 JOIN experiment_barriers b ON b.transaction_id = d.transaction_id
 WHERE b.deadline_ns <= ? LIMIT 512
);
