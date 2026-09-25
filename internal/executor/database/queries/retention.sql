-- name: RecordDebugletExit :exec
-- The first write wins: a duplicate report never rewrites the chosen result.
INSERT INTO debuglet_exits (
    debuglet_id,
    dispatcher_incarnation,
    session_id,
    exit_code,
    error_message,
    recorded_at
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (debuglet_id) DO NOTHING;

-- name: NoteDebugletExitFailure :execrows
UPDATE debuglet_exits
SET attempts = attempts + sqlc.arg(attempts),
    last_attempt_at = sqlc.arg(last_attempt_at),
    last_error = sqlc.arg(last_error),
    rejected = sqlc.arg(rejected)
WHERE debuglet_id = sqlc.arg(debuglet_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> '';

-- name: ReleaseDebugletExit :execrows
DELETE FROM debuglet_exits
WHERE debuglet_id = sqlc.arg(debuglet_id)
  AND dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> '';

-- name: GetDebugletExit :one
SELECT * FROM debuglet_exits
WHERE debuglet_id = ?;

-- name: ListDebugletExits :many
SELECT * FROM debuglet_exits
ORDER BY recorded_at, debuglet_id
LIMIT ?;

-- name: ListDebugletExitsForBinding :many
-- Only a session's own deliverable results, so results no session can deliver
-- cannot crowd out the ones that can be.
SELECT * FROM debuglet_exits
WHERE dispatcher_incarnation = sqlc.arg(dispatcher_incarnation)
  AND session_id = sqlc.arg(session_id)
  AND dispatcher_incarnation <> '' AND session_id <> ''
  AND rejected = FALSE
ORDER BY recorded_at, debuglet_id
LIMIT sqlc.arg(limit);

-- name: CountDebugletExits :one
SELECT count(*) FROM debuglet_exits;
