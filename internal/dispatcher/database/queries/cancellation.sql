-- name: CreateCancellation :exec
INSERT INTO debuglet_cancellations (debuglet_id, request_id, reason, requested_at)
VALUES (?, ?, ?, ?) ON CONFLICT(debuglet_id) DO NOTHING;

-- name: GetCancellation :one
SELECT * FROM debuglet_cancellations WHERE debuglet_id = ?;

-- name: AttemptCancellation :exec
UPDATE debuglet_cancellations SET attempted_at = COALESCE(attempted_at, ?), failure = ''
WHERE debuglet_id = ? AND acknowledged_at IS NULL;

-- name: AcknowledgeCancellation :exec
UPDATE debuglet_cancellations SET acknowledged_at = COALESCE(acknowledged_at, ?), failure = ''
WHERE debuglet_id = ?;

-- name: FailCancellation :exec
UPDATE debuglet_cancellations SET failure = ?
WHERE debuglet_id = ? AND acknowledged_at IS NULL;
