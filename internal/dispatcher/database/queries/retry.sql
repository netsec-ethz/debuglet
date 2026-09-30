-- name: GetRetryRequest :one
SELECT * FROM retry_requests WHERE caller_scope = ? AND request_id = ?;

-- name: CreateRetryRequest :exec
INSERT INTO retry_requests (caller_scope, request_id, parent_run_id, transaction_id, request_hash, intent_metadata)
VALUES (?, ?, ?, ?, ?, ?);
