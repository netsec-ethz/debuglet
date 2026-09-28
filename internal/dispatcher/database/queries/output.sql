-- name: CreateDebugletOutput :exec
INSERT INTO debuglet_output (debuglet_id, output_version, owner_fingerprint, account_id, byte_count, frame_count, last_log_id)
SELECT d.id, sqlc.arg(output_version), sqlc.arg(owner_fingerprint),
    COALESCE((SELECT MIN(user_id) FROM debuglet_users WHERE debuglet_id = d.id), 0),
    COALESCE((SELECT SUM(length(output)) FROM debuglet_logs WHERE debuglet_id = d.id), 0),
    (SELECT COUNT(*) FROM debuglet_logs WHERE debuglet_id = d.id),
    COALESCE((SELECT MAX(id) FROM debuglet_logs WHERE debuglet_id = d.id), 0)
FROM debuglets d WHERE d.uuid = sqlc.arg(uuid);

-- name: GetDebugletOutput :one
SELECT o.*, d.uuid, d.executor_id, d.dispatcher_incarnation, d.session_id
FROM debuglet_output o JOIN debuglets d ON d.id = o.debuglet_id WHERE d.uuid = ?;

-- name: GetSequencedDebugletLog :one
SELECT * FROM debuglet_logs WHERE debuglet_id = ? AND source_sequence = ?;

-- name: CreateSequencedDebugletLog :one
INSERT INTO debuglet_logs (debuglet_id, timestamp, output, source_sequence) VALUES (?, ?, ?, ?)
RETURNING *;

-- name: EnsureOutputAccountUsage :exec
INSERT INTO output_account_usage (account_id, charged_bytes, frame_count) VALUES (?, 0, 0)
ON CONFLICT (account_id) DO NOTHING;

-- name: GetOutputAccountUsage :one
SELECT * FROM output_account_usage WHERE account_id = sqlc.arg(account_id);

-- name: GetOutputNodeUsage :one
SELECT * FROM output_node_usage WHERE singleton = 1;

-- name: AddOutputAccountUsage :exec
UPDATE output_account_usage SET charged_bytes = charged_bytes + sqlc.arg(bytes),
    frame_count = frame_count + sqlc.arg(frames) WHERE account_id = sqlc.arg(account_id);

-- name: AddOutputNodeUsage :exec
UPDATE output_node_usage SET charged_bytes = charged_bytes + sqlc.arg(bytes),
    frame_count = frame_count + sqlc.arg(frames) WHERE singleton = 1;

-- name: AdvanceDebugletOutput :execrows
UPDATE debuglet_output SET committed_sequence = sqlc.arg(sequence),
    byte_count = byte_count + sqlc.arg(bytes), frame_count = frame_count + 1,
    last_log_id = sqlc.arg(log_id)
WHERE debuglet_id = sqlc.arg(debuglet_id) AND final_sequence IS NULL AND committed_sequence = sqlc.arg(sequence) - 1;

-- name: FinishDebugletOutput :execrows
UPDATE debuglet_output SET final_sequence = committed_sequence, final_cursor = last_log_id,
    status = sqlc.arg(status), reason = sqlc.arg(reason)
WHERE debuglet_id = sqlc.arg(debuglet_id) AND final_sequence IS NULL AND committed_sequence = sqlc.arg(sequence);

-- name: AdvanceLegacyDebugletOutput :execrows
UPDATE debuglet_output SET byte_count = byte_count + sqlc.arg(bytes), frame_count = frame_count + 1,
    last_log_id = sqlc.arg(log_id)
WHERE debuglet_id = sqlc.arg(debuglet_id) AND output_version = 0 AND final_sequence IS NULL;
