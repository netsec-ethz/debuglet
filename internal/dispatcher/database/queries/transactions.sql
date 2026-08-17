-- name: GetTransactionByID :one
SELECT * FROM transactions
WHERE id = ?;

-- name: CreateTransaction :one
INSERT INTO transactions (id, auth_key, price, currency, method, expires_at, status, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateTransactionStatus :one
UPDATE transactions
SET status = ?
WHERE id = ?
RETURNING *;

-- name: GetTransactionState :one
SELECT * FROM transaction_states
WHERE key = ?;

-- name: UpdateTransactionState :one
INSERT OR REPLACE INTO transaction_states (key, value)
VALUES (?, ?)
RETURNING *;

/*

DEBUGLET_ORDER

*/

-- name: GetDebugletOrder :one
SELECT * FROM debuglet_order
WHERE transaction_id = ? AND order_id = ?;

-- name: GetTransactionOrders :many
SELECT * FROM debuglet_order
WHERE transaction_id = ?;

-- name: CreateDebugletOrder :one
INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency )
VALUES (?,?,?,?,?)
RETURNING *;


/*

EARNINGS

*/

-- name: GetEarnings :many
SELECT * FROM earnings
WHERE executor_id = ?;

-- name: GetEarningsIn :one
SELECT * FROM earnings
WHERE executor_id = ? AND currency = ?;

-- name: CreateEarnings :one
INSERT INTO earnings (executor_id, currency, total_income, current_balance)
VALUES (?,?,0,0)
RETURNING *;

-- name: AddEarnings :one
UPDATE earnings
SET total_income = total_income + sqlc.arg(amount),
    current_balance = current_balance + sqlc.arg(amount)
WHERE executor_id = sqlc.arg(executor_id) AND currency = sqlc.arg(currency)
RETURNING *;
