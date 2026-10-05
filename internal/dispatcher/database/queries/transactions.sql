-- name: GetTransactionByID :one
SELECT * FROM transactions
WHERE id = ?;

-- name: CreateTransaction :one
INSERT INTO transactions (id, auth_key, price, currency, method, expires_at, status, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: SetTransactionPricingRule :exec
UPDATE transactions
SET pricing_rule = ?
WHERE id = ?;

-- name: UpdateTransactionStatus :exec
UPDATE transactions
SET status = ?
WHERE id = ?;

-- name: RefundUnadmittedTransaction :execrows
UPDATE transactions
SET status = sqlc.arg(refunded_status)
WHERE id = sqlc.arg(transaction_id) AND status = sqlc.arg(paid_status)
  AND NOT EXISTS (
    SELECT 1 FROM debuglet_order
    WHERE debuglet_order.transaction_id = transactions.id AND debuglet_id IS NOT NULL
  );

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
INSERT INTO debuglet_order (transaction_id, order_id, executor_id, price, currency, refund_address, state )
VALUES (?,?,?,?,?,?,?)
RETURNING *;

-- name: UpdateDebugletOrderState :one
UPDATE debuglet_order
SET state = ? 
WHERE transaction_id = ? AND order_id = ?
RETURNING *;

-- name: TransitionDebugletOrder :execrows
UPDATE debuglet_order
SET state = sqlc.arg(to_state)
WHERE transaction_id = sqlc.arg(transaction_id) AND order_id = sqlc.arg(order_id)
  AND state = sqlc.arg(from_state);

-- name: InsertOrderSettlement :exec
INSERT INTO order_settlements (transaction_id, order_id, kind, amount, currency, executor_id, debuglet_id, recorded_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOrderSettlement :one
SELECT * FROM order_settlements
WHERE transaction_id = ? AND order_id = ?;

-- name: ListPendingSettlements :many
-- An order covered by a refund transfer in any state is never listed: the
-- transfer's own reconciliation resolves it, so a pass cannot send it twice.
SELECT sqlc.embed(d), e.exit_code, o.currency FROM debuglet_order o
JOIN debuglets d ON d.id = o.debuglet_id
  AND d.transaction_id = o.transaction_id AND d.order_id = o.order_id
JOIN measurement_execution e ON e.debuglet_id = d.id
WHERE o.state = sqlc.arg(outstanding_state) AND d.state = sqlc.arg(exited_state)
  AND e.exit_code IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM chain_transfers t
    WHERE t.kind = 'refund' AND t.transaction_id = o.transaction_id
      AND (t.order_id IS NULL OR t.order_id = o.order_id)
  )
  AND d.id > sqlc.arg(after_id)
ORDER BY d.id
LIMIT sqlc.arg(row_limit);

-- name: ClaimDebugletOrder :execrows
UPDATE debuglet_order
SET debuglet_id = sqlc.narg(debuglet_id)
WHERE transaction_id = sqlc.arg(transaction_id) AND order_id = sqlc.arg(order_id)
  AND debuglet_id IS NULL AND state = sqlc.arg(outstanding_state)
  AND EXISTS (
    SELECT 1 FROM transactions
    WHERE transactions.id = debuglet_order.transaction_id
      AND transactions.status = sqlc.arg(paid_status)
  );

-- name: GetAdmittedRuns :many
SELECT o.order_id, d.uuid FROM debuglet_order o
JOIN debuglets d ON d.id = o.debuglet_id
WHERE o.transaction_id = ?
ORDER BY o.order_id;

-- name: SetRefundAddress :exec
UPDATE debuglet_order
SET refund_address = ?
WHERE transaction_id = ? AND order_id = ?; 

/*

EARNINGS

*/

-- name: GetEarnings :many
SELECT * FROM earnings;

-- name: GetEarningsOf :many
SELECT * FROM earnings
WHERE executor_id = ?;

-- name: GetEarningsIn :one
SELECT * FROM earnings
WHERE executor_id = ? AND currency = ?;

-- name: CreateEarnings :one
INSERT INTO earnings (executor_id, currency, sui_wallet_address, total_income, current_balance)
VALUES (?,?,?,0,0)
RETURNING *;

-- name: AddEarnings :exec
UPDATE earnings
SET total_income = total_income + sqlc.arg(amount),
    current_balance = current_balance + sqlc.arg(amount)
WHERE executor_id = sqlc.arg(executor_id) AND currency = sqlc.arg(currency);

-- name: SettleEarning :exec
UPDATE earnings 
SET current_balance = 0
WHERE executor_id = ? AND currency = ?
