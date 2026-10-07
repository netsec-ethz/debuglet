-- name: LatestDestinationPolicyRevision :one
SELECT CAST(COALESCE(MAX(revision), 0) AS INTEGER) FROM destination_policy_events
WHERE destination = ?;

-- name: RecordDestinationPolicy :one
INSERT INTO destination_policy_events (destination, kind, limit_bps, reason, actor, requested_at_ns, expires_at_ns, revision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListCurrentDestinationPolicies :many
SELECT e.* FROM destination_policy_events e
WHERE e.revision = (SELECT MAX(l.revision) FROM destination_policy_events l WHERE l.destination = e.destination)
ORDER BY e.destination;
