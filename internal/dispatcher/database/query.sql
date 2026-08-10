/*

DEBUGLET

*/

-- name: ListDebuglets :many
SELECT * FROM debuglets;

-- name: ListDebugletsEndBefore :many
SELECT * FROM debuglets
WHERE end_time < ?;

-- name: ListDebugletsEndAfter :many
SELECT * FROM debuglets
WHERE end_time > ?;

-- name: GetDebugletByID :one
SELECT * FROM debuglets
WHERE id = ?;

-- name: CreateDebuglet :one
INSERT INTO debuglets (id, start_time, end_time, usage, executor_id, addresses)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: DeleteDebugletByID :exec
DELETE FROM debuglets
WHERE id = ?;


/*

TRANSACTION

*/

-- name: GetTransactionState :one
SELECT * FROM transaction_state
WHERE key = ?;

-- name: UpdateTransactionState :one
INSERT OR REPLACE INTO transaction_state (key, value)
VALUES (?, ?)
RETURNING *;

-- name: GetTransactionByID :one
SELECT * FROM transactions
WHERE transaction_id = ?;

-- name: CreateTransaction :one
INSERT INTO transactions (transaction_id, auth_key, price, method, expires_at, paid, hash)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateTransactionPaid :one
UPDATE transactions
SET paid = ?
WHERE transaction_id = ?
RETURNING *;
