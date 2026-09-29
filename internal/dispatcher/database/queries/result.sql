-- name: CreateDebugletProvenance :exec
INSERT INTO debuglet_provenance (debuglet_id, document) VALUES (?, ?);

-- name: GetDebugletProvenance :one
SELECT p.document FROM debuglet_provenance p JOIN debuglets d ON d.id = p.debuglet_id
WHERE d.uuid = ?;

-- name: GetResultOutputSize :one
SELECT COUNT(*) AS frames, CAST(COALESCE(SUM(length(output)), 0) AS INTEGER) AS bytes
FROM debuglet_logs WHERE debuglet_id = ?;

-- name: GetResultLogs :many
SELECT id, debuglet_id, timestamp, output, source_sequence FROM debuglet_logs
WHERE debuglet_id = ? ORDER BY id;

-- name: GetDebugletProvenanceSize :one
SELECT length(CAST(document AS BLOB)) FROM debuglet_provenance WHERE debuglet_id = ?;
