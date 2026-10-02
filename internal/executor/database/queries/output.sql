-- name: CreateOutputRun :exec
INSERT INTO output_runs (run_id, dispatcher_incarnation, session_id, output_version)
VALUES (?, ?, ?, ?);

-- name: GetOutputRun :one
SELECT * FROM output_runs WHERE run_id = sqlc.arg(run_id);

-- name: ListPendingOutputRuns :many
SELECT * FROM output_runs WHERE NOT end_acknowledged AND output_runs.run_id > ?
AND NOT EXISTS (SELECT 1 FROM operator_dispositions d WHERE d.run_id = output_runs.run_id)
ORDER BY output_runs.run_id LIMIT ?;

-- name: CountOutputRuns :one
-- A run whose end the dispatcher acknowledged holds no further spool capacity.
SELECT COUNT(*) FROM output_runs WHERE NOT end_acknowledged;

-- name: GetOutputUsage :one
SELECT charged_bytes FROM output_usage WHERE singleton = 1;

-- name: AddOutputUsage :exec
UPDATE output_usage SET charged_bytes = charged_bytes + ? WHERE singleton = 1;

-- name: CreateOutputFrame :exec
INSERT INTO output_frames (run_id, sequence, timestamp_ns, output) VALUES (?, ?, ?, ?);

-- name: ListOutputFrames :many
SELECT * FROM output_frames WHERE run_id = ? AND sequence > ? ORDER BY sequence LIMIT ?;

-- name: AdvanceOutputRun :exec
UPDATE output_runs SET last_sequence = last_sequence + 1,
    emitted_bytes = emitted_bytes + sqlc.arg(bytes), queued_bytes = queued_bytes + sqlc.arg(bytes),
    queued_frames = queued_frames + 1 WHERE run_id = sqlc.arg(run_id);

-- name: FinishOutputRun :exec
UPDATE output_runs SET status = ?, reason = ? WHERE run_id = ? AND status = 'open';

-- name: InterruptOpenOutputRuns :exec
UPDATE output_runs SET status = 'truncated', reason = 'executor_interrupted' WHERE status = 'open'
AND NOT EXISTS (SELECT 1 FROM operator_dispositions d WHERE d.run_id = output_runs.run_id);

-- name: SumAcknowledgedOutput :one
SELECT CAST(COALESCE(SUM(length(output)), 0) AS INTEGER) AS byte_count, COUNT(*) AS frame_count
FROM output_frames WHERE run_id = ? AND sequence <= ?;

-- name: DeleteAcknowledgedOutput :exec
DELETE FROM output_frames WHERE run_id = ? AND sequence <= ?;

-- name: AcknowledgeOutputRun :exec
UPDATE output_runs SET acknowledged_sequence = sqlc.arg(acknowledged_sequence),
    queued_bytes = queued_bytes - sqlc.arg(bytes), queued_frames = queued_frames - sqlc.arg(frames),
    end_acknowledged = sqlc.arg(end_acknowledged) WHERE run_id = sqlc.arg(run_id);

-- name: AcceptOutputTruncation :exec
UPDATE output_runs SET receipt_sequence = sqlc.arg(sequence), receipt_reason = sqlc.arg(reason),
    acknowledged_sequence = sqlc.arg(sequence), queued_bytes = 0, queued_frames = 0,
    end_acknowledged = TRUE WHERE run_id = sqlc.arg(run_id);

-- name: AbandonOutputRun :exec
UPDATE output_runs SET queued_bytes = 0, queued_frames = 0, end_acknowledged = TRUE
WHERE run_id = ? AND NOT end_acknowledged;
